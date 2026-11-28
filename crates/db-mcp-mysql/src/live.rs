//! Live MySQL 8 backend (mysql_async over plain TCP): DSN parsing, pooled read-only sessions,
//! bounded execution, value mapping, cancellation (`KILL QUERY`) and `check-connection`.
//!
//! A live connection never falls back to the embedded simulation: an unreachable server is
//! reported as `CONNECTION_UNAVAILABLE` with a `next_action`, and the DSN password never appears
//! in any message.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use db_mcp_core::{
    AuthorizedQuery, ColumnMetadata, DatabaseCapabilities, DatabaseEngine, DbMcpError, DbMcpResult,
    ExecutionId, QueryResult,
};
use db_mcp_secrets::{redact_sensitive_text, SecretString};
use db_mcp_sql::split_sql_statements;
use mysql_async::consts::{ColumnFlags, ColumnType};
use mysql_async::prelude::*;
use mysql_async::{
    Conn, Opts, OptsBuilder, Params, Pool, PoolConstraints, PoolOpts, Value as MyValue,
};
use percent_encoding::percent_decode_str;
use url::Url;

/// Default TCP connect timeout for live MySQL connections (DSN `connect_timeout` overrides it).
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3_000;

/// Error code returned when a live server cannot be reached or refuses the login.
pub const CODE_CONNECTION_UNAVAILABLE: &str = "CONNECTION_UNAVAILABLE";

/// Parsed `mysql://user:pass@host[:port][/database][?connect_timeout=ms]` DSN.
#[derive(Clone)]
pub struct MySqlDsn {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: SecretString,
    pub database: Option<String>,
    pub connect_timeout_ms: u64,
}

impl std::fmt::Debug for MySqlDsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlDsn")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"***")
            .field("database", &self.database)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .finish()
    }
}

impl MySqlDsn {
    /// `host:port` for messages (never includes credentials).
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn decode(component: &str, what: &str, connection_id: &str) -> DbMcpResult<String> {
    percent_decode_str(component)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| {
            DbMcpError::ConfigurationError(format!(
                "Connection '{connection_id}': the MySQL DSN {what} is not valid percent-encoded UTF-8"
            ))
        })
}

/// Parse a live MySQL DSN. User and password are percent-decoded (`%40` -> `@`, `%29` -> `)`,
/// `%24` -> `$`). Errors name the problem, never the password.
pub fn parse_mysql_dsn(connection_id: &str, dsn: &str) -> DbMcpResult<MySqlDsn> {
    let invalid = |why: &str| {
        DbMcpError::ConfigurationError(format!(
            "Connection '{connection_id}': invalid MySQL DSN ({why}); expected mysql://user:password@host[:port][/database]"
        ))
    };
    let url = Url::parse(dsn.trim()).map_err(|_| invalid("not a URL"))?;
    if !matches!(url.scheme(), "mysql" | "mariadb") {
        return Err(invalid("scheme must be mysql:// or mariadb://"));
    }
    let host = url
        .host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| invalid("missing host"))?;
    let port = url.port().unwrap_or(3306);
    let user = decode(url.username(), "user", connection_id)?;
    if user.is_empty() {
        return Err(invalid("missing user"));
    }
    let password = match url.password() {
        Some(p) => decode(p, "password", connection_id)?,
        None => String::new(),
    };
    let database = {
        let raw = url.path().trim_start_matches('/');
        if raw.is_empty() {
            None
        } else {
            Some(decode(raw, "database", connection_id)?)
        }
    };
    let mut connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "connect_timeout" | "connect_timeout_ms" => {
                connect_timeout_ms =
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|v| *v > 0)
                        .ok_or_else(|| {
                            invalid("connect_timeout must be a positive number of milliseconds")
                        })?;
            }
            "ssl-mode" | "ssl_mode" | "sslmode" => {
                if !value.eq_ignore_ascii_case("disabled") {
                    return Err(invalid(
                        "TLS is not supported by this build (plain TCP only); remove ssl-mode or set ssl-mode=disabled",
                    ));
                }
            }
            other => {
                return Err(invalid(&format!("unsupported DSN parameter '{other}'")));
            }
        }
    }
    Ok(MySqlDsn {
        host,
        port,
        user,
        password: SecretString::new(password),
        database,
        connect_timeout_ms,
    })
}

/// Build the fail-closed `CONNECTION_UNAVAILABLE` error for a live connection.
pub fn connection_unavailable(connection_id: &str, dsn: &MySqlDsn, reason: &str) -> DbMcpError {
    DbMcpError::PolicyDenied {
        code: CODE_CONNECTION_UNAVAILABLE.to_string(),
        message: format!(
            "Live MySQL connection '{connection_id}' ({}) is unavailable: {reason}. No simulated data is returned for a live backend.",
            dsn.address()
        ),
        next_action: Some(format!(
            "Check the server address, port, network and credentials, then run `db-mcp check-connection --config <file> --connection {connection_id}`"
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Code for a statement the server refused because the session is READ ONLY (defence in depth
/// behind policy and the adapter guard).
pub const CODE_SERVER_READ_ONLY: &str = "READONLY_VIOLATION";
/// Code for a statement the server refused because the login lacks a privilege.
pub const CODE_DATABASE_PERMISSION_DENIED: &str = "DATABASE_PERMISSION_DENIED";

fn server_reason(e: &mysql_async::Error) -> String {
    redact_sensitive_text(&match e {
        mysql_async::Error::Server(se) => {
            format!("MySQL error {} ({}): {}", se.code, se.state, se.message)
        }
        mysql_async::Error::Io(io) => format!("I/O error: {io}"),
        mysql_async::Error::Driver(d) => format!("driver error: {d}"),
        mysql_async::Error::Other(o) => format!("error: {o}"),
        mysql_async::Error::Url(_) => "invalid connection options".to_string(),
    })
}

/// Map an error raised while opening a connection (always fail closed, never simulated).
pub(crate) fn map_connect_error(
    connection_id: &str,
    dsn: &MySqlDsn,
    e: &mysql_async::Error,
) -> DbMcpError {
    let reason = match e {
        mysql_async::Error::Server(se) if se.code == 1045 => {
            format!(
                "authentication failed for user '{}' (MySQL error 1045)",
                dsn.user
            )
        }
        mysql_async::Error::Server(se) if se.code == 1049 => format!(
            "database '{}' does not exist or is not visible to user '{}' (MySQL error 1049)",
            dsn.database.as_deref().unwrap_or(""),
            dsn.user
        ),
        _ => server_reason(e),
    };
    connection_unavailable(connection_id, dsn, &reason)
}

/// Map an error raised while running a statement.
pub(crate) fn map_exec_error(
    connection_id: &str,
    dsn: &MySqlDsn,
    timeout_ms: u64,
    e: &mysql_async::Error,
) -> DbMcpError {
    match e {
        mysql_async::Error::Server(se) => match se.code {
            3024 => DbMcpError::ExecutionTimeout { timeout_ms },
            1317 => DbMcpError::ExecutionCancelled(format!("MySQL query on '{connection_id}' was interrupted (KILL QUERY)")),
            1792 => DbMcpError::PolicyDenied {
                code: CODE_SERVER_READ_ONLY.to_string(),
                message: format!(
                    "MySQL refused the statement on '{connection_id}': the session is READ ONLY (error 1792)"
                ),
                next_action: Some("propose_change".to_string()),
            },
            1142 | 1143 | 1227 | 1370 | 1044 => DbMcpError::PolicyDenied {
                code: CODE_DATABASE_PERMISSION_DENIED.to_string(),
                message: format!(
                    "MySQL denied the statement on '{connection_id}' for user '{}': {}",
                    dsn.user,
                    redact_sensitive_text(&se.message)
                ),
                next_action: Some("Ask the DBA for the missing GRANT, or query objects the read-only login can read".to_string()),
            },
            _ => DbMcpError::AdapterError(server_reason(e)),
        },
        mysql_async::Error::Io(_) => connection_unavailable(connection_id, dsn, &format!("connection lost: {}", server_reason(e))),
        _ => DbMcpError::AdapterError(server_reason(e)),
    }
}

/// Capabilities of a live MySQL 8 connection.
pub fn live_capabilities() -> DatabaseCapabilities {
    let mut caps = DatabaseCapabilities::for_mysql();
    caps.supports_health_diagnostics = true;
    caps.supports_workload_analysis = true;
    caps.supports_index_advisor = true;
    caps.supports_analyze_explain = true;
    caps.supports_cancellation = true;
    caps.unavailable_reasons.insert(
        "analyze_explain".to_string(),
        "EXPLAIN ANALYZE executes the statement; it needs MySQL 8.0.18+ and allow_explain_analyze = true".to_string(),
    );
    caps
}

/// `SET SESSION ...` statement run on every checkout: READ ONLY (when the connection or request
/// is read-only) plus the server-side `max_execution_time` budget.
pub fn build_mysql_session_setup(read_only: bool, max_execution_time_ms: u64) -> String {
    format!(
        "SET SESSION transaction_read_only = {}, SESSION max_execution_time = {}",
        u8::from(read_only),
        max_execution_time_ms
    )
}

// ---------------------------------------------------------------------------------------------
// Live backend
// ---------------------------------------------------------------------------------------------

/// Maximum pooled connections per live MySQL connection.
pub const MAX_POOL_CONNECTIONS: usize = 4;

/// Live MySQL backend (plain TCP, pooled, read-only sessions).
pub struct LiveMySql {
    pub connection_id: String,
    pub dsn: MySqlDsn,
    read_only: bool,
    pool: Pool,
    active: DashMap<ExecutionId, u32>,
    server_version: std::sync::Mutex<Option<String>>,
    catalog_cache: std::sync::Mutex<Option<crate::catalog::CachedCatalog>>,
}

impl std::fmt::Debug for LiveMySql {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveMySql")
            .field("connection_id", &self.connection_id)
            .field("dsn", &self.dsn)
            .field("read_only", &self.read_only)
            .finish()
    }
}

/// Outcome of running one statement.
pub(crate) struct StatementOutcome {
    pub columns: Vec<ColumnMetadata>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub rows_affected: Option<u64>,
    pub truncated: bool,
    pub bytes_used: usize,
    pub warnings: Vec<String>,
}

impl LiveMySql {
    pub fn new(connection_id: &str, dsn: &str, read_only: bool) -> DbMcpResult<Self> {
        let parsed = parse_mysql_dsn(connection_id, dsn)?;
        let mut setup: Vec<String> = Vec::new();
        if read_only {
            setup.push("SET SESSION transaction_read_only = 1".to_string());
        }
        let constraints = PoolConstraints::new(0, MAX_POOL_CONNECTIONS).ok_or_else(|| {
            DbMcpError::InternalError("invalid MySQL pool constraints".to_string())
        })?;
        let opts = OptsBuilder::default()
            .ip_or_hostname(parsed.host.clone())
            .tcp_port(parsed.port)
            .user(Some(parsed.user.clone()))
            .pass(Some(parsed.password.expose_secret().to_string()))
            .db_name(parsed.database.clone())
            .prefer_socket(false)
            .setup(setup)
            .pool_opts(
                PoolOpts::default()
                    .with_constraints(constraints)
                    .with_inactive_connection_ttl(Duration::from_secs(60)),
            );
        Ok(Self {
            connection_id: connection_id.to_string(),
            dsn: parsed,
            read_only,
            pool: Pool::new(Opts::from(opts)),
            active: DashMap::new(),
            server_version: std::sync::Mutex::new(None),
            catalog_cache: std::sync::Mutex::new(None),
        })
    }

    pub(crate) fn cached_catalog(&self) -> Option<crate::catalog::CachedCatalog> {
        self.catalog_cache.lock().ok().and_then(|c| c.clone())
    }

    pub(crate) fn store_catalog(&self, catalog: crate::catalog::CachedCatalog) {
        if let Ok(mut c) = self.catalog_cache.lock() {
            *c = Some(catalog);
        }
    }

    /// Forget the cached catalog (after DDL, or before capture/diff/drift checks).
    pub fn invalidate_catalog(&self) {
        if let Ok(mut c) = self.catalog_cache.lock() {
            *c = None;
        }
    }

    /// Schema version of the cached catalog, when one was read recently.
    pub fn cached_schema_version(&self) -> Option<String> {
        self.cached_catalog()
            .filter(|c| c.at.elapsed() < crate::catalog::CATALOG_CACHE_TTL)
            .map(|c| c.schema_version)
    }

    /// Visibility warnings (missing optional grants) of the last catalog read.
    pub fn catalog_warnings(&self) -> Vec<String> {
        self.cached_catalog()
            .map(|c| c.warnings)
            .unwrap_or_default()
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Server version reported by the last successful connection (e.g. `8.0.46`).
    pub fn server_version(&self) -> Option<String> {
        self.server_version.lock().ok().and_then(|v| v.clone())
    }

    /// `(major, minor, patch)` of the server, when known.
    pub fn server_version_tuple(&self) -> Option<(u16, u16, u16)> {
        let v = self.server_version()?;
        let mut parts = v
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u16>().unwrap_or(0));
        Some((
            parts.next()?,
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        ))
    }

    /// Check a connection out of the pool within the connect timeout (fail closed).
    pub(crate) async fn checkout(&self) -> DbMcpResult<Conn> {
        let budget = Duration::from_millis(self.dsn.connect_timeout_ms);
        match tokio::time::timeout(budget, self.pool.get_conn()).await {
            Ok(Ok(conn)) => {
                let (a, b, c) = conn.server_version();
                if let Ok(mut v) = self.server_version.lock() {
                    *v = Some(format!("{a}.{b}.{c}"));
                }
                Ok(conn)
            }
            Ok(Err(e)) => Err(map_connect_error(&self.connection_id, &self.dsn, &e)),
            Err(_) => Err(connection_unavailable(
                &self.connection_id,
                &self.dsn,
                &format!(
                    "no connection could be opened within {} ms",
                    self.dsn.connect_timeout_ms
                ),
            )),
        }
    }

    /// Checkout + session setup (READ ONLY when required, `max_execution_time`).
    pub(crate) async fn session(&self, read_only: bool, timeout_ms: u64) -> DbMcpResult<Conn> {
        let mut conn = self.checkout().await?;
        let ro = read_only || self.read_only;
        conn.query_drop(build_mysql_session_setup(ro, timeout_ms))
            .await
            .map_err(|e| map_exec_error(&self.connection_id, &self.dsn, timeout_ms, &e))?;
        Ok(conn)
    }

    /// Run an internal read-only query (text protocol) and map every row to JSON.
    pub(crate) async fn query_json(
        &self,
        conn: &mut Conn,
        sql: &str,
        timeout_ms: u64,
    ) -> DbMcpResult<(Vec<String>, Vec<Vec<serde_json::Value>>)> {
        let mut result = conn
            .query_iter(sql)
            .await
            .map_err(|e| map_exec_error(&self.connection_id, &self.dsn, timeout_ms, &e))?;
        let columns = result.columns().map(|c| c.to_vec()).unwrap_or_default();
        let names = columns.iter().map(|c| c.name_str().to_string()).collect();
        let mut rows = Vec::new();
        while let Some(row) = result
            .next()
            .await
            .map_err(|e| map_exec_error(&self.connection_id, &self.dsn, timeout_ms, &e))?
        {
            let values = row.unwrap();
            rows.push(
                values
                    .iter()
                    .zip(columns.iter())
                    .map(|(v, c)| {
                        mysql_value_to_json(v, c.column_type(), c.flags(), c.character_set())
                    })
                    .collect(),
            );
        }
        drop(result);
        Ok((names, rows))
    }

    /// Execute an authorized statement on the server with row/byte budgets.
    pub async fn execute(
        &self,
        request: &AuthorizedQuery,
        read_only: bool,
        timeout_ms: u64,
    ) -> DbMcpResult<QueryResult> {
        let started = Instant::now();
        let statements = split_sql_statements(DatabaseEngine::MySql, &request.sql);
        let statements: Vec<String> = statements
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if statements.is_empty() {
            return Err(DbMcpError::InvalidArgument(
                "empty SQL statement".to_string(),
            ));
        }
        if statements.len() > 1 && !request.params.is_empty() {
            return Err(DbMcpError::InvalidArgument(
                "parameters are only supported for a single MySQL statement".to_string(),
            ));
        }
        let mut conn = self.session(read_only, timeout_ms).await?;
        let thread_id = conn.id();
        self.active.insert(request.execution_id.clone(), thread_id);
        let mut warnings = Vec::new();
        let mut outcome: Option<StatementOutcome> = None;
        let mut needs_kill = false;
        for (idx, stmt) in statements.iter().enumerate() {
            let last = idx + 1 == statements.len();
            let (sql, params) = bind_mysql_placeholders(stmt, &request.params)?;
            let params: Vec<MyValue> = params.iter().map(json_to_mysql_param).collect();
            let result = run_prepared(
                &mut conn,
                &sql,
                params,
                if last { request.max_rows } else { 0 },
                if last { request.max_bytes } else { 0 },
                last,
            )
            .await;
            match result {
                Ok((out, kill)) => {
                    needs_kill |= kill;
                    if last {
                        outcome = Some(out);
                    }
                }
                Err(e) => {
                    self.active.remove(&request.execution_id);
                    return Err(map_exec_error(
                        &self.connection_id,
                        &self.dsn,
                        timeout_ms,
                        &e,
                    ));
                }
            }
        }
        self.active.remove(&request.execution_id);
        drop(conn);
        if needs_kill {
            // A truncated result still streaming: stop the server instead of draining it.
            let _ = self.kill_query(thread_id).await;
        }
        let out = outcome.expect("at least one statement");
        warnings.extend(out.warnings);
        if statements.len() > 1 {
            warnings.push(format!(
                "{} statements were executed; only the last result is returned",
                statements.len()
            ));
        }
        Ok(QueryResult {
            execution_id: request.execution_id.clone(),
            returned_rows: out.rows.len(),
            columns: out.columns,
            rows: out.rows,
            rows_affected: out.rows_affected,
            truncated: out.truncated,
            bytes_used: out.bytes_used,
            execution_time_ms: started.elapsed().as_millis() as u64,
            warnings,
            schema_version: None,
        })
    }

    /// `KILL QUERY <thread>` on a fresh pooled connection (a login may always kill its own threads).
    pub async fn kill_query(&self, thread_id: u32) -> DbMcpResult<()> {
        let mut conn = self.checkout().await?;
        conn.query_drop(crate::build_mysql_kill_query(u64::from(thread_id)))
            .await
            .map_err(|e| map_exec_error(&self.connection_id, &self.dsn, 0, &e))
    }

    /// Cancel an in-flight execution; `Ok(false)` when it is not running.
    pub async fn cancel(&self, execution: &ExecutionId) -> DbMcpResult<Option<u32>> {
        let Some((_, thread_id)) = self.active.remove(execution) else {
            return Ok(None);
        };
        self.kill_query(thread_id).await?;
        Ok(Some(thread_id))
    }

    /// Thread id of an in-flight execution (tests, observability).
    pub fn active_thread(&self, execution: &ExecutionId) -> Option<u32> {
        self.active.get(execution).map(|v| *v)
    }
}

/// Run one statement through the binary protocol (prepared statements cannot carry a second
/// statement, so nothing can be smuggled past the single-statement policy). Returns the outcome
/// and whether the server may still be streaming rows (truncated before the end).
async fn run_prepared(
    conn: &mut Conn,
    sql: &str,
    params: Vec<MyValue>,
    max_rows: usize,
    max_bytes: usize,
    collect: bool,
) -> Result<(StatementOutcome, bool), mysql_async::Error> {
    let params = if params.is_empty() {
        Params::Empty
    } else {
        Params::Positional(params)
    };
    let mut result = conn.exec_iter(sql, params).await?;
    let cols = result.columns().map(|c| c.to_vec()).unwrap_or_default();
    let mut out = StatementOutcome {
        columns: cols
            .iter()
            .map(|c| {
                let mut m = ColumnMetadata::new(
                    c.name_str().to_string(),
                    mysql_column_type_name(c.column_type(), c.flags(), c.character_set()),
                );
                m.nullable = Some(!c.flags().contains(ColumnFlags::NOT_NULL_FLAG));
                m
            })
            .collect(),
        rows: Vec::new(),
        rows_affected: None,
        truncated: false,
        bytes_used: 0,
        warnings: Vec::new(),
    };
    if cols.is_empty() {
        out.rows_affected = Some(result.affected_rows());
        result.drop_result().await?;
        return Ok((out, false));
    }
    let max_rows = if max_rows == 0 { usize::MAX } else { max_rows };
    let mut still_streaming = false;
    while let Some(row) = result.next().await? {
        if !collect {
            continue;
        }
        if out.rows.len() >= max_rows {
            out.truncated = true;
            out.warnings
                .push(format!("Result truncated at max_rows={max_rows}"));
            still_streaming = true;
            break;
        }
        let values = row.unwrap();
        let mapped: Vec<serde_json::Value> = values
            .iter()
            .zip(cols.iter())
            .map(|(v, c)| mysql_value_to_json(v, c.column_type(), c.flags(), c.character_set()))
            .collect();
        let row_bytes: usize = mapped.iter().map(json_size).sum();
        if max_bytes > 0 && out.bytes_used + row_bytes > max_bytes && !out.rows.is_empty() {
            out.truncated = true;
            out.warnings
                .push(format!("Result truncated at max_bytes={max_bytes}"));
            still_streaming = true;
            break;
        }
        out.bytes_used += row_bytes;
        out.rows.push(mapped);
    }
    if still_streaming {
        // Drain briefly; a large remainder is stopped with KILL QUERY by the caller.
        match tokio::time::timeout(Duration::from_millis(250), result.drop_result()).await {
            Ok(Ok(())) => return Ok((out, false)),
            Ok(Err(_)) | Err(_) => return Ok((out, true)),
        }
    }
    drop(result);
    Ok((out, false))
}

// ---------------------------------------------------------------------------------------------
// Value mapping
// ---------------------------------------------------------------------------------------------

const BINARY_CHARSET: u16 = 63;

fn is_integer_type(t: ColumnType) -> bool {
    matches!(
        t,
        ColumnType::MYSQL_TYPE_TINY
            | ColumnType::MYSQL_TYPE_SHORT
            | ColumnType::MYSQL_TYPE_LONG
            | ColumnType::MYSQL_TYPE_LONGLONG
            | ColumnType::MYSQL_TYPE_INT24
            | ColumnType::MYSQL_TYPE_YEAR
    )
}

/// SQL type name reported in result-set column metadata.
pub fn mysql_column_type_name(t: ColumnType, flags: ColumnFlags, charset: u16) -> String {
    let binary = charset == BINARY_CHARSET;
    let base = match t {
        ColumnType::MYSQL_TYPE_TINY => "tinyint",
        ColumnType::MYSQL_TYPE_SHORT => "smallint",
        ColumnType::MYSQL_TYPE_INT24 => "mediumint",
        ColumnType::MYSQL_TYPE_LONG => "int",
        ColumnType::MYSQL_TYPE_LONGLONG => "bigint",
        ColumnType::MYSQL_TYPE_YEAR => "year",
        ColumnType::MYSQL_TYPE_DECIMAL | ColumnType::MYSQL_TYPE_NEWDECIMAL => "decimal",
        ColumnType::MYSQL_TYPE_FLOAT => "float",
        ColumnType::MYSQL_TYPE_DOUBLE => "double",
        ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE => "date",
        ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_DATETIME2 => "datetime",
        ColumnType::MYSQL_TYPE_TIMESTAMP | ColumnType::MYSQL_TYPE_TIMESTAMP2 => "timestamp",
        ColumnType::MYSQL_TYPE_TIME | ColumnType::MYSQL_TYPE_TIME2 => "time",
        ColumnType::MYSQL_TYPE_BIT => "bit",
        ColumnType::MYSQL_TYPE_JSON => "json",
        ColumnType::MYSQL_TYPE_ENUM => "enum",
        ColumnType::MYSQL_TYPE_SET => "set",
        ColumnType::MYSQL_TYPE_GEOMETRY => "geometry",
        ColumnType::MYSQL_TYPE_NULL => "null",
        ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB
        | ColumnType::MYSQL_TYPE_BLOB => {
            if binary {
                "blob"
            } else {
                "text"
            }
        }
        ColumnType::MYSQL_TYPE_STRING => {
            if flags.contains(ColumnFlags::ENUM_FLAG) {
                "enum"
            } else if flags.contains(ColumnFlags::SET_FLAG) {
                "set"
            } else if binary {
                "binary"
            } else {
                "char"
            }
        }
        ColumnType::MYSQL_TYPE_VAR_STRING | ColumnType::MYSQL_TYPE_VARCHAR => {
            if binary {
                "varbinary"
            } else {
                "varchar"
            }
        }
        _ => "unknown",
    };
    if is_integer_type(t)
        && t != ColumnType::MYSQL_TYPE_YEAR
        && flags.contains(ColumnFlags::UNSIGNED_FLAG)
    {
        format!("{base} unsigned")
    } else {
        base.to_string()
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn fraction(us: u32) -> String {
    if us == 0 {
        String::new()
    } else {
        format!(".{us:06}")
    }
}

/// Map one MySQL value (text or binary protocol) to JSON: integers as numbers, DECIMAL as a
/// string (no precision loss), DATE/DATETIME/TIMESTAMP as ISO-8601 (`T` separator), TIME as
/// `[-]HH:MM:SS[.ffffff]`, BIT as an unsigned number, binary-collation bytes as `0x..` hex, text
/// as UTF-8 (hex if not valid UTF-8), JSON as its text.
pub fn mysql_value_to_json(
    value: &MyValue,
    t: ColumnType,
    flags: ColumnFlags,
    charset: u16,
) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        MyValue::NULL => J::Null,
        MyValue::Int(i) => J::from(*i),
        MyValue::UInt(u) => J::from(*u),
        MyValue::Float(f) => serde_json::Number::from_f64(f64::from(*f))
            .map(J::Number)
            .unwrap_or_else(|| J::String(f.to_string())),
        MyValue::Double(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .unwrap_or_else(|| J::String(f.to_string())),
        MyValue::Date(y, m, d, h, mi, s, us) => {
            if matches!(
                t,
                ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE
            ) {
                J::String(format!("{y:04}-{m:02}-{d:02}"))
            } else {
                J::String(format!(
                    "{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}{}",
                    fraction(*us)
                ))
            }
        }
        MyValue::Time(neg, days, h, mi, s, us) => {
            let hours = u64::from(*days) * 24 + u64::from(*h);
            J::String(format!(
                "{}{hours:02}:{mi:02}:{s:02}{}",
                if *neg { "-" } else { "" },
                fraction(*us)
            ))
        }
        MyValue::Bytes(bytes) => bytes_to_json(bytes, t, flags, charset),
    }
}

fn bytes_to_json(
    bytes: &[u8],
    t: ColumnType,
    flags: ColumnFlags,
    charset: u16,
) -> serde_json::Value {
    use serde_json::Value as J;
    let text = std::str::from_utf8(bytes).ok();
    if is_integer_type(t) {
        if let Some(s) = text {
            if let Ok(i) = s.parse::<i64>() {
                return J::from(i);
            }
            if let Ok(u) = s.parse::<u64>() {
                return J::from(u);
            }
        }
    }
    match t {
        ColumnType::MYSQL_TYPE_FLOAT | ColumnType::MYSQL_TYPE_DOUBLE => {
            if let Some(n) = text
                .and_then(|s| s.parse::<f64>().ok())
                .and_then(serde_json::Number::from_f64)
            {
                return J::Number(n);
            }
        }
        ColumnType::MYSQL_TYPE_BIT => {
            if bytes.len() <= 8 {
                let v = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
                return J::from(v);
            }
            return J::String(hex_string(bytes));
        }
        ColumnType::MYSQL_TYPE_DATETIME
        | ColumnType::MYSQL_TYPE_DATETIME2
        | ColumnType::MYSQL_TYPE_TIMESTAMP
        | ColumnType::MYSQL_TYPE_TIMESTAMP2 => {
            if let Some(s) = text {
                return J::String(s.replacen(' ', "T", 1));
            }
        }
        ColumnType::MYSQL_TYPE_DECIMAL
        | ColumnType::MYSQL_TYPE_NEWDECIMAL
        | ColumnType::MYSQL_TYPE_DATE
        | ColumnType::MYSQL_TYPE_NEWDATE
        | ColumnType::MYSQL_TYPE_TIME
        | ColumnType::MYSQL_TYPE_TIME2
        | ColumnType::MYSQL_TYPE_JSON
        | ColumnType::MYSQL_TYPE_ENUM
        | ColumnType::MYSQL_TYPE_SET => {
            if let Some(s) = text {
                return J::String(s.to_string());
            }
        }
        _ => {}
    }
    let binary_column = charset == BINARY_CHARSET
        && !flags.contains(ColumnFlags::ENUM_FLAG)
        && !flags.contains(ColumnFlags::SET_FLAG)
        && matches!(
            t,
            ColumnType::MYSQL_TYPE_STRING
                | ColumnType::MYSQL_TYPE_VAR_STRING
                | ColumnType::MYSQL_TYPE_VARCHAR
                | ColumnType::MYSQL_TYPE_TINY_BLOB
                | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
                | ColumnType::MYSQL_TYPE_LONG_BLOB
                | ColumnType::MYSQL_TYPE_BLOB
                | ColumnType::MYSQL_TYPE_GEOMETRY
        );
    match text {
        Some(s) if !binary_column => J::String(s.to_string()),
        _ => J::String(hex_string(bytes)),
    }
}

/// JSON parameter -> MySQL value (booleans as 0/1, arrays/objects as JSON text).
pub fn json_to_mysql_param(value: &serde_json::Value) -> MyValue {
    match value {
        serde_json::Value::Null => MyValue::NULL,
        serde_json::Value::Bool(b) => MyValue::Int(i64::from(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                MyValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                MyValue::UInt(u)
            } else {
                MyValue::Double(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => MyValue::Bytes(s.as_bytes().to_vec()),
        other => MyValue::Bytes(other.to_string().into_bytes()),
    }
}

fn json_size(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Null => 4,
        serde_json::Value::String(s) => s.len().max(1),
        other => other.to_string().len(),
    }
}

/// Rewrite numbered placeholders (`?1`, `$1`) to MySQL's positional `?`, reordering the
/// parameters. Quotes, backticks and comments are skipped. Mixing styles is rejected.
pub fn bind_mysql_placeholders(
    sql: &str,
    params: &[serde_json::Value],
) -> DbMcpResult<(String, Vec<serde_json::Value>)> {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut numbered: Vec<usize> = Vec::new();
    let mut bare = 0usize;
    let mut i = 0usize;
    let mut last = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\'' | b'"' | b'`' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && c != b'`' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == c {
                        if i + 1 < bytes.len() && bytes[i + 1] == c {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'?' | b'$' => {
                let prev_ident = i > 0
                    && (bytes[i - 1].is_ascii_alphanumeric()
                        || bytes[i - 1] == b'_'
                        || bytes[i - 1] == b'$');
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if c == b'?' && j == i + 1 {
                    bare += 1;
                    i += 1;
                } else if j > i + 1 && !prev_ident {
                    let n: usize = sql[i + 1..j].parse().unwrap_or(0);
                    out.push_str(&sql[last..i]);
                    out.push('?');
                    numbered.push(n);
                    i = j;
                    last = j;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    if numbered.is_empty() {
        return Ok((sql.to_string(), params.to_vec()));
    }
    if bare > 0 {
        return Err(DbMcpError::InvalidArgument(
            "SQL mixes positional '?' and numbered ('?1' / '$1') placeholders".to_string(),
        ));
    }
    out.push_str(&sql[last.min(sql.len())..]);
    let mut bound = Vec::with_capacity(numbered.len());
    for n in numbered {
        let v = n
            .checked_sub(1)
            .and_then(|idx| params.get(idx))
            .ok_or_else(|| {
                DbMcpError::InvalidArgument(format!(
                    "placeholder {n} has no matching parameter ({} given)",
                    params.len()
                ))
            })?;
        bound.push(v.clone());
    }
    Ok((out, bound))
}

// ---------------------------------------------------------------------------------------------
// Grants and check-connection
// ---------------------------------------------------------------------------------------------

/// Privileges that let an account change data, schema or server state.
const WRITE_PRIVILEGES: &[&str] = &[
    "ALL",
    "ALL PRIVILEGES",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "ALTER",
    "INDEX",
    "CREATE VIEW",
    "CREATE ROUTINE",
    "ALTER ROUTINE",
    "EXECUTE",
    "TRIGGER",
    "EVENT",
    "FILE",
    "SUPER",
    "GRANT OPTION",
    "CREATE USER",
    "CREATE ROLE",
    "DROP ROLE",
    "RELOAD",
    "SHUTDOWN",
    "CREATE TABLESPACE",
    "REFERENCES",
    "LOCK TABLES",
];

/// What the account's `SHOW GRANTS` lines allow, for warnings and feature notes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantSummary {
    pub write_privileges: Vec<String>,
    pub has_process: bool,
    pub can_read_routine_definitions: bool,
    pub has_trigger: bool,
    pub has_show_view: bool,
    pub has_performance_schema: bool,
    pub role_grants: bool,
}

/// Summarize `SHOW GRANTS` output (`GRANT <privs> ON <scope> TO <user>` lines).
pub fn summarize_grants(grants: &[String]) -> GrantSummary {
    let mut out = GrantSummary::default();
    for line in grants {
        let upper = line.trim().to_ascii_uppercase();
        let Some(rest) = upper.strip_prefix("GRANT ") else {
            continue;
        };
        let Some((privs, after_on)) = rest.split_once(" ON ") else {
            out.role_grants = true;
            continue;
        };
        let scope = after_on
            .split(" TO ")
            .next()
            .unwrap_or("")
            .replace('`', "")
            .trim()
            .to_string();
        let global = scope == "*.*";
        for raw in privs.split(',') {
            let p = raw.split('(').next().unwrap_or("").trim().to_string();
            if p.is_empty() || p == "USAGE" {
                continue;
            }
            let all = p == "ALL" || p == "ALL PRIVILEGES";
            if WRITE_PRIVILEGES.contains(&p.as_str()) || p.ends_with("_ADMIN") {
                let label = format!("{p} ON {scope}");
                if !out.write_privileges.contains(&label) {
                    out.write_privileges.push(label);
                }
            }
            if p == "PROCESS" || (all && global) {
                out.has_process = true;
            }
            if p == "SHOW_ROUTINE" || (global && (p == "SELECT" || all)) {
                out.can_read_routine_definitions = true;
            }
            if p == "TRIGGER" || all {
                out.has_trigger = true;
            }
            if p == "SHOW VIEW" || all {
                out.has_show_view = true;
            }
            if (scope.starts_with("PERFORMANCE_SCHEMA.") || global) && (p == "SELECT" || all) {
                out.has_performance_schema = true;
            }
        }
        if line.to_ascii_uppercase().contains("WITH GRANT OPTION") {
            out.write_privileges
                .push(format!("GRANT OPTION ON {scope}"));
        }
    }
    out
}

impl LiveMySql {
    /// `SHOW GRANTS` for the current login (no passwords are ever part of the output).
    pub(crate) async fn grants(&self, conn: &mut Conn) -> DbMcpResult<Vec<String>> {
        let (_, rows) = self.query_json(conn, "SHOW GRANTS", 5_000).await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.into_iter().next())
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect())
    }

    /// Read-only `check-connection` report. Never contains the DSN or the password.
    pub async fn check(&self) -> serde_json::Value {
        let report = |can_connect: bool,
                      version: serde_json::Value,
                      select_1: bool,
                      objects: serde_json::Value,
                      perms: Vec<String>,
                      can_write: serde_json::Value,
                      warnings: Vec<String>| {
            serde_json::json!({
                "connection": self.connection_id,
                "engine": "mysql",
                "backend": "live",
                "server_version": version,
                "can_connect": can_connect,
                "select_1": select_1,
                "object_count": objects,
                "permissions": perms,
                "can_write": can_write,
                "warnings": warnings,
            })
        };
        let mut conn = match self.session(true, 10_000).await {
            Ok(c) => c,
            Err(e) => {
                return report(
                    false,
                    serde_json::Value::Null,
                    false,
                    serde_json::Value::Null,
                    Vec::new(),
                    serde_json::Value::Null,
                    vec![e.to_string()],
                )
            }
        };
        let mut warnings = Vec::new();
        let first = |rows: &[Vec<serde_json::Value>], i: usize| {
            rows.first()
                .and_then(|r| r.get(i))
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        };
        let version = match self.query_json(&mut conn, "SELECT VERSION()", 5_000).await {
            Ok((_, rows)) => first(&rows, 0),
            Err(e) => {
                warnings.push(format!("SELECT VERSION() failed: {e}"));
                serde_json::Value::Null
            }
        };
        let select_1 = matches!(self.query_json(&mut conn, "SELECT 1", 5_000).await, Ok((_, rows)) if first(&rows, 0) == serde_json::json!(1));
        let session = self
            .query_json(&mut conn, "SELECT CURRENT_USER(), DATABASE(), @@session.transaction_read_only, @@global.read_only, @@global.super_read_only", 5_000)
            .await
            .map(|(_, rows)| rows)
            .unwrap_or_default();
        if first(&session, 2) != serde_json::json!(1) {
            warnings.push("the session could not be switched to READ ONLY (SET SESSION transaction_read_only = 1)".to_string());
        }
        if first(&session, 1).is_null() {
            warnings.push(
                "the DSN names no database; unqualified table names will not resolve".to_string(),
            );
        }
        let server_read_only = first(&session, 3) == serde_json::json!(1)
            || first(&session, 4) == serde_json::json!(1);
        let grants = match self.grants(&mut conn).await {
            Ok(g) => g,
            Err(e) => {
                warnings.push(format!("SHOW GRANTS failed: {e}"));
                Vec::new()
            }
        };
        let summary = summarize_grants(&grants);
        let object_count = self
            .query_json(
                &mut conn,
                "SELECT (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','sys')) + \
                 (SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','sys'))",
                10_000,
            )
            .await
            .map(|(_, rows)| first(&rows, 0))
            .unwrap_or(serde_json::Value::Null);
        let digest_readable = self
            .query_json(
                &mut conn,
                "SELECT 1 FROM performance_schema.events_statements_summary_by_digest LIMIT 1",
                5_000,
            )
            .await
            .is_ok();
        drop(conn);

        let can_write = !summary.write_privileges.is_empty();
        if can_write {
            warnings.push(format!(
                "this account can write ({}); use a read-only login (GRANT SELECT, SHOW VIEW only){}",
                summary.write_privileges.join(", "),
                if server_read_only { " - the server itself is read_only, which blocks most writes" } else { "" }
            ));
        }
        if summary.role_grants {
            warnings.push(
                "role grants are present; effective privileges depend on the activated roles"
                    .to_string(),
            );
        }
        if !summary.has_show_view {
            warnings.push(
                "SHOW VIEW is not granted: view definitions (lineage through views) are hidden"
                    .to_string(),
            );
        }
        if !summary.can_read_routine_definitions {
            warnings.push(format!(
                "routines are not visible: procedures/functions and the call graph need GRANT SHOW_ROUTINE ON *.* TO {} (optional)",
                first(&session, 0).as_str().unwrap_or(&self.dsn.user)
            ));
        }
        if !summary.has_trigger {
            warnings.push("triggers are not listed (information_schema.TRIGGERS needs the TRIGGER privilege, which can also create triggers; not recommended for a read-only login)".to_string());
        }
        if !digest_readable {
            warnings.push("performance_schema digests are not readable: analyze_workload uses session history (optional: GRANT SELECT ON performance_schema.*)".to_string());
        }
        if !summary.has_process {
            warnings.push("PROCESS is not granted: database_health sees only this login's own sessions (optional)".to_string());
        }
        if let Some((major, minor, patch)) = self.server_version_tuple() {
            if (major, minor, patch) < (8, 0, 18) {
                warnings.push("EXPLAIN ANALYZE needs MySQL 8.0.18 or later".to_string());
            }
        }
        report(
            true,
            version,
            select_1,
            object_count,
            grants,
            serde_json::json!(can_write),
            warnings,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{CallerIdentity, ExecutionLimits};

    #[test]
    fn dsn_percent_decoding_and_defaults() {
        let d = parse_mysql_dsn("m", "mysql://ro%40corp:p%40ss%29w%24rd@10.0.0.5/appdb").unwrap();
        assert_eq!(d.user, "ro@corp");
        assert_eq!(d.password.expose_secret(), "p@ss)w$rd");
        assert_eq!(d.host, "10.0.0.5");
        assert_eq!(d.port, 3306);
        assert_eq!(d.database.as_deref(), Some("appdb"));
        assert_eq!(d.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
        assert!(!format!("{d:?}").contains("p@ss"));

        let d = parse_mysql_dsn("m", "mariadb://u:p@db.local:3307?connect_timeout=500").unwrap();
        assert_eq!(
            (d.port, d.database.clone(), d.connect_timeout_ms),
            (3307, None, 500)
        );
        assert_eq!(d.address(), "db.local:3307");
    }

    #[test]
    fn dsn_errors_never_echo_password() {
        for bad in [
            "postgres://u:topsecret@h/db",
            "mysql://:topsecret@h/db",
            "mysql://u:topsecret@h/db?ssl-mode=REQUIRED",
            "mysql://u:topsecret@h/db?bogus=1",
            "mysql://u:topsecret@h/db?connect_timeout=0",
        ] {
            let e = parse_mysql_dsn("m", bad).unwrap_err().to_string();
            assert!(!e.contains("topsecret"), "{e}");
            assert!(e.contains("'m'"), "{e}");
        }
        parse_mysql_dsn("m", "mysql://u:p@h/db?ssl-mode=DISABLED").unwrap();
    }

    #[tokio::test]
    async fn unreachable_server_fails_closed_with_next_action() {
        let live = LiveMySql::new(
            "m",
            "mysql://u:topsecret@127.0.0.1:1/db?connect_timeout=500",
            true,
        )
        .unwrap();
        let e = live.checkout().await.unwrap_err();
        assert_eq!(e.code(), CODE_CONNECTION_UNAVAILABLE);
        assert!(e.next_action().unwrap().contains("check-connection"));
        assert!(!e.to_string().contains("topsecret"));
        let report = live.check().await;
        assert_eq!(report["can_connect"], serde_json::json!(false));
        assert!(!report.to_string().contains("topsecret"));
    }

    #[test]
    fn value_mapping_text_and_binary_protocol() {
        let f = ColumnFlags::empty();
        let utf8 = 255u16;
        let j = |v: MyValue, t: ColumnType, cs: u16| mysql_value_to_json(&v, t, f, cs);
        assert_eq!(
            j(
                MyValue::Bytes(b"-7".to_vec()),
                ColumnType::MYSQL_TYPE_TINY,
                63
            ),
            serde_json::json!(-7)
        );
        assert_eq!(
            j(
                MyValue::Bytes(b"18446744073709551615".to_vec()),
                ColumnType::MYSQL_TYPE_LONGLONG,
                63
            ),
            serde_json::json!(u64::MAX)
        );
        assert_eq!(
            j(
                MyValue::Bytes(b"12345.678900".to_vec()),
                ColumnType::MYSQL_TYPE_NEWDECIMAL,
                63
            ),
            serde_json::json!("12345.678900")
        );
        assert_eq!(
            j(
                MyValue::Bytes(b"3.5".to_vec()),
                ColumnType::MYSQL_TYPE_DOUBLE,
                63
            ),
            serde_json::json!(3.5)
        );
        assert_eq!(
            j(
                MyValue::Bytes(b"2025-01-03 10:00:00.123".to_vec()),
                ColumnType::MYSQL_TYPE_DATETIME,
                63
            ),
            serde_json::json!("2025-01-03T10:00:00.123")
        );
        assert_eq!(
            j(
                MyValue::Date(2025, 1, 3, 10, 0, 0, 123000),
                ColumnType::MYSQL_TYPE_DATETIME,
                63
            ),
            serde_json::json!("2025-01-03T10:00:00.123000")
        );
        assert_eq!(
            j(
                MyValue::Date(2025, 1, 3, 0, 0, 0, 0),
                ColumnType::MYSQL_TYPE_DATE,
                63
            ),
            serde_json::json!("2025-01-03")
        );
        assert_eq!(
            j(
                MyValue::Time(true, 1, 2, 3, 4, 0),
                ColumnType::MYSQL_TYPE_TIME,
                63
            ),
            serde_json::json!("-26:03:04")
        );
        assert_eq!(
            j(
                MyValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
                ColumnType::MYSQL_TYPE_VAR_STRING,
                63
            ),
            serde_json::json!("0xdeadbeef")
        );
        assert_eq!(
            j(
                MyValue::Bytes(vec![0b1010_0101]),
                ColumnType::MYSQL_TYPE_BIT,
                63
            ),
            serde_json::json!(165)
        );
        assert_eq!(
            j(
                MyValue::Bytes("héllo".as_bytes().to_vec()),
                ColumnType::MYSQL_TYPE_BLOB,
                utf8
            ),
            serde_json::json!("héllo")
        );
        assert_eq!(
            j(
                MyValue::Bytes(vec![0xff, 0xfe]),
                ColumnType::MYSQL_TYPE_VAR_STRING,
                utf8
            ),
            serde_json::json!("0xfffe")
        );
        assert_eq!(
            j(MyValue::NULL, ColumnType::MYSQL_TYPE_VAR_STRING, utf8),
            serde_json::Value::Null
        );
        assert_eq!(
            j(MyValue::UInt(7), ColumnType::MYSQL_TYPE_LONGLONG, 63),
            serde_json::json!(7)
        );
        assert_eq!(
            mysql_column_type_name(
                ColumnType::MYSQL_TYPE_LONGLONG,
                ColumnFlags::UNSIGNED_FLAG,
                63
            ),
            "bigint unsigned"
        );
        assert_eq!(
            mysql_column_type_name(ColumnType::MYSQL_TYPE_BLOB, f, utf8),
            "text"
        );
        assert_eq!(
            mysql_column_type_name(ColumnType::MYSQL_TYPE_STRING, ColumnFlags::ENUM_FLAG, utf8),
            "enum"
        );
    }

    #[test]
    fn numbered_placeholders_are_rewritten() {
        let p = vec![serde_json::json!(1), serde_json::json!("x")];
        let (sql, bound) =
            bind_mysql_placeholders("SELECT ?2, ?1, '?3', `$1` FROM t WHERE a = $1 -- ?9", &p)
                .unwrap();
        assert_eq!(sql, "SELECT ?, ?, '?3', `$1` FROM t WHERE a = ? -- ?9");
        assert_eq!(
            bound,
            vec![
                serde_json::json!("x"),
                serde_json::json!(1),
                serde_json::json!(1)
            ]
        );
        let (sql, bound) = bind_mysql_placeholders("SELECT ? , ?", &p).unwrap();
        assert_eq!((sql.as_str(), bound.len()), ("SELECT ? , ?", 2));
        assert!(bind_mysql_placeholders("SELECT ?, ?1", &p).is_err());
        assert!(bind_mysql_placeholders("SELECT ?3", &p).is_err());
    }

    #[test]
    fn grant_summary_flags_writers_and_optional_grants() {
        let ro = summarize_grants(&[
            "GRANT USAGE ON *.* TO `dbmcp_ro`@`%`".to_string(),
            "GRANT SELECT, SHOW VIEW ON `appdb`.* TO `dbmcp_ro`@`%`".to_string(),
        ]);
        assert!(ro.write_privileges.is_empty());
        assert!(
            ro.has_show_view
                && !ro.has_process
                && !ro.can_read_routine_definitions
                && !ro.has_performance_schema
        );
        let diag = summarize_grants(&[
            "GRANT PROCESS ON *.* TO `d`@`%`".to_string(),
            "GRANT SHOW_ROUTINE ON *.* TO `d`@`%`".to_string(),
            "GRANT SELECT ON `performance_schema`.* TO `d`@`%`".to_string(),
        ]);
        assert!(
            diag.write_privileges.is_empty()
                && diag.has_process
                && diag.can_read_routine_definitions
                && diag.has_performance_schema
        );
        let rw = summarize_grants(&[
            "GRANT SELECT, INSERT, UPDATE, DELETE ON `appdb`.* TO `rw`@`%`".to_string(),
        ]);
        assert_eq!(
            rw.write_privileges,
            vec![
                "INSERT ON APPDB.*",
                "UPDATE ON APPDB.*",
                "DELETE ON APPDB.*"
            ]
        );
        assert!(summarize_grants(&["GRANT `app_reader`@`%` TO `u`@`%`".to_string()]).role_grants);
    }

    #[test]
    fn session_setup_statement() {
        assert_eq!(
            build_mysql_session_setup(true, 1500),
            "SET SESSION transaction_read_only = 1, SESSION max_execution_time = 1500"
        );
        assert_eq!(
            build_mysql_session_setup(false, 10),
            "SET SESSION transaction_read_only = 0, SESSION max_execution_time = 10"
        );
    }

    // ---- live integration tests (skipped unless DB_MCP_MYSQL_TEST_DSN* point at the fixture) ----

    fn env_dsn(var: &str) -> Option<String> {
        match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => {
                eprintln!(
                    "skipped: {var} not set (run `eval \"$(bash scripts/live-db-up.sh mysql)\"`)"
                );
                None
            }
        }
    }

    fn query(sql: &str, params: Vec<serde_json::Value>) -> AuthorizedQuery {
        AuthorizedQuery::new_read(
            "req_live",
            "m",
            CallerIdentity::local_agent("t"),
            sql,
            params,
            &ExecutionLimits::default(),
        )
    }

    #[tokio::test]
    async fn live_select_types_params_and_truncation() {
        let Some(dsn) = env_dsn("DB_MCP_MYSQL_TEST_DSN") else {
            return;
        };
        let live = LiveMySql::new("m", &dsn, true).unwrap();
        let r = live
            .execute(
                &query(
                    "SELECT * FROM type_samples WHERE id = ?1",
                    vec![serde_json::json!(1)],
                ),
                true,
                5_000,
            )
            .await
            .unwrap();
        let row = &r.rows[0];
        let col = |n: &str| r.columns.iter().position(|c| c.name == n).unwrap();
        assert_eq!(row[col("i_tiny")], serde_json::json!(-7));
        assert_eq!(row[col("i_big_u")], serde_json::json!(u64::MAX));
        assert_eq!(row[col("d_dec")], serde_json::json!("12345.678900"));
        assert_eq!(row[col("f_double")], serde_json::json!(3.5));
        assert_eq!(
            row[col("dt")],
            serde_json::json!("2025-01-03T10:00:00.123000")
        );
        assert_eq!(row[col("d")], serde_json::json!("2025-01-03"));
        assert_eq!(row[col("t")], serde_json::json!("13:14:15"));
        assert_eq!(row[col("y")], serde_json::json!(2025));
        assert_eq!(row[col("b_bin")], serde_json::json!("0xdeadbeef"));
        assert_eq!(row[col("e")], serde_json::json!("large"));
        assert_eq!(row[col("bits")], serde_json::json!(165));
        assert_eq!(row[col("txt")], serde_json::json!("héllo 日本"));
        assert_eq!(row[col("n_null")], serde_json::Value::Null);
        assert_eq!(r.columns[col("i_big_u")].data_type, "bigint unsigned");

        let mut q = query("SELECT n FROM numbers ORDER BY n", vec![]);
        q.max_rows = 5;
        let r = live.execute(&q, true, 5_000).await.unwrap();
        assert!(r.truncated && r.rows.len() == 5, "{r:?}");
        // The pool connection is reusable after a truncated stream.
        let r = live
            .execute(
                &query("SELECT COUNT(*) AS c FROM numbers", vec![]),
                true,
                5_000,
            )
            .await
            .unwrap();
        assert_eq!(r.rows[0][0], serde_json::json!(1000));
    }

    #[tokio::test]
    async fn live_read_only_session_refuses_writes_even_for_a_writer() {
        let Some(dsn) = env_dsn("DB_MCP_MYSQL_TEST_DSN_RW") else {
            return;
        };
        let live = LiveMySql::new("m", &dsn, true).unwrap();
        let e = live
            .execute(
                &query(
                    "INSERT INTO event_log_nopk (event_time, message) VALUES (NOW(), 'x')",
                    vec![],
                ),
                true,
                5_000,
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), CODE_SERVER_READ_ONLY, "{e}");
        let Some(ro) = env_dsn("DB_MCP_MYSQL_TEST_DSN") else {
            return;
        };
        // A read-only login is refused by the server's privilege system even without READ ONLY.
        let live = LiveMySql::new("m", &ro, false).unwrap();
        let e = live
            .execute(
                &query(
                    "INSERT INTO event_log_nopk (event_time, message) VALUES (NOW(), 'x')",
                    vec![],
                ),
                false,
                5_000,
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), CODE_DATABASE_PERMISSION_DENIED, "{e}");
    }

    #[tokio::test]
    async fn live_timeout_and_cancel() {
        let Some(dsn) = env_dsn("DB_MCP_MYSQL_TEST_DSN") else {
            return;
        };
        let live = std::sync::Arc::new(LiveMySql::new("m", &dsn, true).unwrap());
        let slow = "SELECT SUM(a.n + b.n + c.n) FROM numbers a, numbers b, numbers c";
        let started = Instant::now();
        let e = live
            .execute(&query(slow, vec![]), true, 800)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "EXECUTION_TIMEOUT", "{e}");
        assert!(started.elapsed() < Duration::from_secs(5));

        let q = query(slow, vec![]);
        let exec_id = q.execution_id.clone();
        let runner = {
            let live = live.clone();
            tokio::spawn(async move { live.execute(&q, true, 60_000).await })
        };
        let mut thread = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if live.active_thread(&exec_id).is_some() {
                thread = live.cancel(&exec_id).await.unwrap();
                break;
            }
        }
        assert!(thread.is_some(), "query never became active");
        let e = runner.await.unwrap().unwrap_err();
        assert_eq!(e.code(), "EXECUTION_CANCELLED", "{e}");
    }

    #[tokio::test]
    async fn live_check_connection_reports_permissions() {
        let Some(dsn) = env_dsn("DB_MCP_MYSQL_TEST_DSN") else {
            return;
        };
        let report = LiveMySql::new("m", &dsn, true).unwrap().check().await;
        let pw = parse_mysql_dsn("m", &dsn)
            .unwrap()
            .password
            .expose_secret()
            .to_string();
        assert!(!report.to_string().contains(&pw));
        assert_eq!(report["can_connect"], serde_json::json!(true));
        assert_eq!(report["select_1"], serde_json::json!(true));
        assert_eq!(report["can_write"], serde_json::json!(false));
        assert!(report["server_version"].as_str().unwrap().starts_with('8'));
        assert!(report["object_count"].as_u64().unwrap() >= 8);
        assert!(report["warnings"].to_string().contains("SHOW_ROUTINE"));
        if let Some(rw) = env_dsn("DB_MCP_MYSQL_TEST_DSN_RW") {
            let report = LiveMySql::new("m", &rw, true).unwrap().check().await;
            assert_eq!(report["can_write"], serde_json::json!(true));
            assert!(report["warnings"].to_string().contains("can write"));
        }
    }
}
