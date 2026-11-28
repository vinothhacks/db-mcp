//! Microsoft SQL Server adapter: live TDS connections (tiberius + rustls), read-only defence in
//! depth, catalog discovery from `sys.*`, estimated plans (SHOWPLAN_XML) and diagnostics.
//!
//! Read-only defence in depth, in order: the policy engine (ReadOnly mode), this adapter's own
//! read guard (re-classifies the SQL and refuses anything that is not a read on a read-only
//! connection), every read runs inside `BEGIN TRANSACTION ... ROLLBACK`, and finally the login's
//! own permissions (`db_datareader`). There is no simulated SQL Server backend: an unreachable
//! server fails closed with `CONNECTION_UNAVAILABLE`.

pub mod catalog;
pub mod diagnostics;
pub mod dsn;
pub mod showplan;
pub mod values;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use db_mcp_catalog::{
    capture_schema, compute_schema_version, diff_schema, filter_and_paginate_objects,
};
use db_mcp_core::{
    AuthorizedQuery, CatalogObject, CatalogRequest, CatalogResponse, ColumnMetadata,
    DatabaseAdapter, DatabaseCapabilities, DatabaseEngine, DbMcpError, DbMcpResult, ExecutionId,
    ExplainFormat, ExplainPlan, ExplainRequest, QueryResult, SchemaDiff, SchemaDiffProvider,
    SchemaSnapshot, SqlStatementClass,
};
use db_mcp_secrets::SecretString;
use db_mcp_sql::parse_and_analyze_sql;
use futures_util::TryStreamExt;
use serde::Serialize;
use serde_json::Value;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, QueryItem, SqlBrowser};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use tokio_util::sync::CancellationToken;

pub use dsn::{SqlServerDsn, SqlServerEncryption};
pub use values::{column_data_to_json, rewrite_placeholders, SqlParam};

/// Live TDS client type.
pub type TdsClient = Client<Compat<TcpStream>>;

/// Denial code for an unreachable server or a failed login (never falls back to simulation).
pub const CODE_CONNECTION_UNAVAILABLE: &str = "CONNECTION_UNAVAILABLE";
/// Denial code for statements the server refused because the login lacks a permission.
pub const CODE_SERVER_PERMISSION_DENIED: &str = "SERVER_PERMISSION_DENIED";
const CHECK_CONNECTION_HINT: &str = "db-mcp check-connection --config <file> --connection <id>";

/// SQL Server connection configuration.
#[derive(Clone)]
pub struct SqlServerConfig {
    pub connection_id: String,
    pub dsn: SecretString,
    pub read_only: bool,
    pub default_schema: String,
    pub pool_size: usize,
    /// How long cached catalog metadata is reused before it is read again.
    pub catalog_ttl: Duration,
}

impl std::fmt::Debug for SqlServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlServerConfig")
            .field("connection_id", &self.connection_id)
            .field("dsn", &"<redacted>")
            .field("read_only", &self.read_only)
            .field("default_schema", &self.default_schema)
            .finish()
    }
}

impl SqlServerConfig {
    pub fn new(connection_id: impl Into<String>, dsn: impl Into<SecretString>) -> Self {
        Self {
            connection_id: connection_id.into(),
            dsn: dsn.into(),
            read_only: true,
            default_schema: "dbo".to_string(),
            pool_size: 4,
            catalog_ttl: Duration::from_secs(10),
        }
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn with_default_schema(mut self, schema: impl Into<String>) -> Self {
        let s = schema.into();
        if !s.trim().is_empty() {
            self.default_schema = s;
        }
        self
    }
}

/// Server identity and the effective permissions of the login, detected at first connect.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServerInfo {
    pub product_version: String,
    pub major_version: u32,
    pub edition: String,
    pub product_level: String,
    pub instance_name: Option<String>,
    pub database: String,
    pub login: String,
    pub database_user: String,
    pub database_permissions: Vec<String>,
    pub server_permissions: Vec<String>,
    pub roles: Vec<String>,
    pub is_sysadmin: bool,
}

impl ServerInfo {
    fn has_db(&self, perm: &str) -> bool {
        self.is_sysadmin
            || self
                .database_permissions
                .iter()
                .any(|p| p.eq_ignore_ascii_case(perm) || p.eq_ignore_ascii_case("CONTROL"))
            || self
                .roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case("db_owner"))
    }
    fn has_server(&self, perm: &str) -> bool {
        self.is_sysadmin
            || self
                .server_permissions
                .iter()
                .any(|p| p.eq_ignore_ascii_case(perm) || p.eq_ignore_ascii_case("CONTROL SERVER"))
    }
    pub fn can_view_definition(&self) -> bool {
        self.has_db("VIEW DEFINITION") || self.has_server("VIEW ANY DEFINITION")
    }
    pub fn can_showplan(&self) -> bool {
        self.has_db("SHOWPLAN")
    }
    pub fn can_view_database_state(&self) -> bool {
        self.has_db("VIEW DATABASE STATE") || self.has_server("VIEW SERVER STATE")
    }
    pub fn can_view_server_state(&self) -> bool {
        self.has_server("VIEW SERVER STATE")
    }
    /// Query Store exists from SQL Server 2016 (major version 13).
    pub fn has_query_store(&self) -> bool {
        self.major_version >= 13
    }
    /// Write-capable permissions or roles held by the login (empty for a read-only account).
    pub fn write_capabilities(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.is_sysadmin {
            out.push("server role sysadmin".to_string());
        }
        for r in &self.roles {
            if [
                "db_owner",
                "db_datawriter",
                "db_ddladmin",
                "db_securityadmin",
                "db_accessadmin",
            ]
            .iter()
            .any(|w| r.eq_ignore_ascii_case(w))
            {
                out.push(format!("database role {r}"));
            }
        }
        for p in &self.database_permissions {
            let up = p.to_ascii_uppercase();
            if matches!(
                up.as_str(),
                "INSERT" | "UPDATE" | "DELETE" | "ALTER" | "CONTROL" | "EXECUTE" | "TAKE OWNERSHIP"
            ) || up.starts_with("CREATE ")
                || up.starts_with("ALTER ANY")
            {
                out.push(format!("database permission {up}"));
            }
        }
        out.sort();
        out.dedup();
        out
    }
    /// Optional grants that are missing, keyed by feature, with the statement to run.
    pub fn missing_grants(&self) -> Vec<(String, String)> {
        let user = if self.database_user.is_empty() {
            "<user>".to_string()
        } else {
            self.database_user.clone()
        };
        let login = if self.login.is_empty() {
            "<login>".to_string()
        } else {
            self.login.clone()
        };
        let mut out = Vec::new();
        if !self.can_view_definition() {
            out.push((
                "routine_definitions".to_string(),
                format!("procedures, functions, triggers and view definitions are hidden; GRANT VIEW DEFINITION TO [{user}]"),
            ));
        }
        if !self.can_showplan() {
            out.push((
                "explain".to_string(),
                format!("estimated plans need GRANT SHOWPLAN TO [{user}]"),
            ));
        }
        if !self.can_view_database_state() {
            out.push((
                "query_store".to_string(),
                format!("Query Store workload and table sizes need GRANT VIEW DATABASE STATE TO [{user}]"),
            ));
        }
        if !self.can_view_server_state() {
            out.push((
                "server_state".to_string(),
                format!("server counters, plan cache and missing-index DMVs need GRANT VIEW SERVER STATE TO [{login}] (in master)"),
            ));
        }
        out
    }
}

#[derive(Clone)]
struct CatalogCache {
    loaded_at: Instant,
    objects: Vec<CatalogObject>,
}

/// One fetched result set.
#[derive(Debug, Clone, Default)]
pub struct FetchedRows {
    pub columns: Vec<ColumnMetadata>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
    pub bytes_used: usize,
    pub extra_result_sets: usize,
}

/// SQL Server implementation of `DatabaseAdapter` and `SchemaDiffProvider`.
#[derive(Clone)]
pub struct SqlServerAdapter {
    config: SqlServerConfig,
    dsn: Arc<SqlServerDsn>,
    pool: Arc<Mutex<Vec<TdsClient>>>,
    permits: Arc<Semaphore>,
    server_info: Arc<RwLock<Option<ServerInfo>>>,
    catalog_cache: Arc<StdMutex<Option<CatalogCache>>>,
    catalog_warnings: Arc<StdMutex<Vec<String>>>,
    inflight: Arc<StdMutex<BTreeMap<ExecutionId, CancellationToken>>>,
}

impl std::fmt::Debug for SqlServerAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlServerAdapter")
            .field("connection_id", &self.config.connection_id)
            .field("target", &self.dsn.display_target())
            .finish()
    }
}

fn unavailable(dsn: &SqlServerDsn, why: impl std::fmt::Display) -> DbMcpError {
    DbMcpError::PolicyDenied {
        code: CODE_CONNECTION_UNAVAILABLE.to_string(),
        message: format!(
            "SQL Server at {} is unreachable: {}",
            dsn.display_target(),
            dsn.scrub(&why.to_string())
        ),
        next_action: Some(CHECK_CONNECTION_HINT.to_string()),
    }
}

/// Map a driver error to a fail-closed `DbMcpError` with the password scrubbed.
pub(crate) fn map_tds_error(
    dsn: &SqlServerDsn,
    context: &str,
    err: tiberius::error::Error,
) -> DbMcpError {
    use tiberius::error::Error as E;
    match &err {
        E::Server(token) => {
            let code = token.code();
            let msg = dsn.scrub(token.message());
            match code {
                18456 | 18452 | 18470 | 18488 | 4060 | 4064 => DbMcpError::PolicyDenied {
                    code: CODE_CONNECTION_UNAVAILABLE.to_string(),
                    message: format!("SQL Server login failed ({context}, error {code}): {msg}"),
                    next_action: Some(CHECK_CONNECTION_HINT.to_string()),
                },
                229 | 230 | 262 | 297 | 300 | 916 | 15247 | 8189 => DbMcpError::PolicyDenied {
                    code: CODE_SERVER_PERMISSION_DENIED.to_string(),
                    message: format!(
                        "SQL Server refused the statement because the login lacks a permission (error {code}): {msg}"
                    ),
                    next_action: Some(
                        "list_connections (capabilities.unavailable_reasons names the grants to request)".to_string(),
                    ),
                },
                1222 => DbMcpError::AdapterError(format!("SQL Server lock request timed out ({context}): {msg}")),
                _ => DbMcpError::AdapterError(format!("SQL Server error {code} ({context}): {msg}")),
            }
        }
        E::Io { .. } | E::Tls(_) | E::Routing { .. } | E::Protocol(_) => {
            unavailable(dsn, format!("{context}: {err}"))
        }
        _ => DbMcpError::AdapterError(format!(
            "SQL Server driver error ({context}): {}",
            dsn.scrub(&err.to_string())
        )),
    }
}

async fn run_simple(
    client: &mut TdsClient,
    dsn: &SqlServerDsn,
    sql: &str,
    context: &str,
) -> DbMcpResult<()> {
    client
        .simple_query(sql)
        .await
        .map_err(|e| map_tds_error(dsn, context, e))?
        .into_results()
        .await
        .map_err(|e| map_tds_error(dsn, context, e))?;
    Ok(())
}

/// Execute `sql` with `params`, optionally inside `BEGIN TRANSACTION ... ROLLBACK`, and return
/// every result set plus whether the connection is clean (reusable). When the row/byte budget
/// truncates the result the stream is abandoned: the caller must drop the connection, and the
/// server then rolls the open transaction back.
pub(crate) async fn run_read(
    client: &mut TdsClient,
    dsn: &SqlServerDsn,
    sql: &str,
    params: &[SqlParam],
    max_rows: usize,
    max_bytes: usize,
    in_transaction: bool,
) -> DbMcpResult<(Vec<FetchedRows>, bool)> {
    if in_transaction {
        run_simple(
            client,
            dsn,
            "SET XACT_ABORT ON; SET IMPLICIT_TRANSACTIONS OFF; BEGIN TRANSACTION;",
            "begin transaction",
        )
        .await?;
    }
    let refs: Vec<&dyn tiberius::ToSql> = params.iter().map(|p| p.as_tosql()).collect();
    let mut sets: Vec<FetchedRows> = Vec::new();
    let mut truncated = false;
    {
        let stream = if params.is_empty() {
            client.simple_query(sql).await
        } else {
            client.query(sql, &refs).await
        };
        let mut stream = stream.map_err(|e| map_tds_error(dsn, "query", e))?;
        while let Some(item) = stream
            .try_next()
            .await
            .map_err(|e| map_tds_error(dsn, "query", e))?
        {
            match item {
                QueryItem::Metadata(meta) => sets.push(FetchedRows {
                    columns: meta
                        .columns()
                        .iter()
                        .map(|c| {
                            ColumnMetadata::new(c.name(), values::column_type_name(c.column_type()))
                        })
                        .collect(),
                    ..FetchedRows::default()
                }),
                QueryItem::Row(row) => {
                    let Some(set) = sets.last_mut() else { continue };
                    if set.rows.len() >= max_rows {
                        set.truncated = true;
                        truncated = true;
                        break;
                    }
                    let vals: Vec<Value> =
                        row.cells().map(|(_, d)| column_data_to_json(d)).collect();
                    let size: usize =
                        vals.iter().map(values::json_size).sum::<usize>() + vals.len();
                    if set.bytes_used + size > max_bytes {
                        set.truncated = true;
                        truncated = true;
                        break;
                    }
                    set.bytes_used += size;
                    set.rows.push(vals);
                }
            }
        }
    }
    if truncated {
        return Ok((sets, false));
    }
    if in_transaction {
        run_simple(
            client,
            dsn,
            "IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;",
            "rollback",
        )
        .await?;
    }
    Ok((sets, true))
}

/// Probe version, database, login and effective permissions.
pub(crate) async fn probe_server_info(
    client: &mut TdsClient,
    dsn: &SqlServerDsn,
) -> DbMcpResult<ServerInfo> {
    let sql = "SELECT /* db-mcp:internal */ CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), CAST(SERVERPROPERTY('Edition') AS nvarchar(128)), \
        CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)), CAST(SERVERPROPERTY('InstanceName') AS nvarchar(128)), \
        DB_NAME(), SUSER_SNAME(), USER_NAME(), CAST(IS_SRVROLEMEMBER('sysadmin') AS int); \
        SELECT /* db-mcp:internal */ permission_name FROM fn_my_permissions(NULL, 'DATABASE'); \
        SELECT /* db-mcp:internal */ permission_name FROM fn_my_permissions(NULL, 'SERVER'); \
        SELECT /* db-mcp:internal */ r.name FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID();";
    let (sets, _) = run_read(client, dsn, sql, &[], 1000, usize::MAX, false).await?;
    let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let mut info = ServerInfo::default();
    if let Some(row) = sets.first().and_then(|r| r.rows.first()) {
        info.product_version = s(&row[0]);
        info.major_version = info
            .product_version
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or(0);
        info.edition = s(&row[1]);
        info.product_level = s(&row[2]);
        info.instance_name = row[3].as_str().map(ToOwned::to_owned);
        info.database = s(&row[4]);
        info.login = s(&row[5]);
        info.database_user = s(&row[6]);
        info.is_sysadmin = row[7].as_i64() == Some(1);
    }
    let col = |i: usize| -> Vec<String> {
        sets.get(i)
            .map(|r| {
                r.rows
                    .iter()
                    .filter_map(|row| row.first().and_then(|v| v.as_str()).map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    info.database_permissions = col(1);
    info.server_permissions = col(2);
    info.roles = col(3);
    Ok(info)
}

impl SqlServerAdapter {
    /// Create an adapter. The DSN is parsed here (configuration errors fail at startup); the
    /// first connection is opened lazily by the first tool call.
    pub fn new(config: SqlServerConfig) -> DbMcpResult<Self> {
        let dsn = SqlServerDsn::parse(config.dsn.expose_secret()).map_err(|e| match e {
            DbMcpError::ConfigurationError(m) => DbMcpError::ConfigurationError(format!(
                "Connection '{}': {m}",
                config.connection_id
            )),
            other => other,
        })?;
        if dsn.encryption == SqlServerEncryption::Strict {
            return Err(DbMcpError::ConfigurationError(format!(
                "Connection '{}': encrypt=strict (TDS 8.0) is not supported by this build; use encrypt=true",
                config.connection_id
            )));
        }
        let pool_size = config.pool_size.max(1);
        Ok(Self {
            dsn: Arc::new(dsn),
            pool: Arc::new(Mutex::new(Vec::new())),
            permits: Arc::new(Semaphore::new(pool_size)),
            server_info: Arc::new(RwLock::new(None)),
            catalog_cache: Arc::new(StdMutex::new(None)),
            catalog_warnings: Arc::new(StdMutex::new(Vec::new())),
            inflight: Arc::new(StdMutex::new(BTreeMap::new())),
            config,
        })
    }

    pub fn config(&self) -> &SqlServerConfig {
        &self.config
    }

    pub fn dsn(&self) -> &SqlServerDsn {
        &self.dsn
    }

    /// Credential-free description of the target.
    pub fn display_target(&self) -> String {
        self.dsn.display_target()
    }

    fn tds_config(&self) -> Config {
        let d = &self.dsn;
        let mut cfg = Config::new();
        cfg.host(&d.host);
        match (d.port, &d.instance) {
            (Some(p), _) => cfg.port(p),
            (None, Some(inst)) => cfg.instance_name(inst),
            (None, None) => cfg.port(1433),
        }
        if let Some(db) = &d.database {
            cfg.database(db);
        }
        cfg.application_name(&d.application_name);
        cfg.authentication(AuthMethod::sql_server(&d.user, d.password()));
        cfg.encryption(match d.encryption {
            SqlServerEncryption::Optional => EncryptionLevel::Off,
            SqlServerEncryption::Required | SqlServerEncryption::Strict => {
                EncryptionLevel::Required
            }
            SqlServerEncryption::Disabled => EncryptionLevel::NotSupported,
        });
        if d.trust_server_certificate {
            cfg.trust_cert();
        }
        cfg
    }

    /// Open a new authenticated TDS connection (bounded by `connectTimeout`).
    pub async fn connect(&self) -> DbMcpResult<TdsClient> {
        let cfg = self.tds_config();
        let dsn = self.dsn.clone();
        let by_browser = dsn.port.is_none() && dsn.instance.is_some();
        let connect = async move {
            let tcp = if by_browser {
                TcpStream::connect_named(&cfg)
                    .await
                    .map_err(|e| map_tds_error(&dsn, "SQL Browser lookup", e))?
            } else {
                let port = dsn.port.unwrap_or(1433);
                TcpStream::connect((dsn.host.as_str(), port))
                    .await
                    .map_err(|e| unavailable(&dsn, e))?
            };
            let _ = tcp.set_nodelay(true);
            Client::connect(cfg, tcp.compat_write())
                .await
                .map_err(|e| map_tds_error(&dsn, "login", e))
        };
        match tokio::time::timeout(Duration::from_secs(self.dsn.connect_timeout_secs), connect)
            .await
        {
            Ok(r) => r,
            Err(_) => Err(unavailable(
                &self.dsn,
                format!("connect timed out after {}s", self.dsn.connect_timeout_secs),
            )),
        }
    }

    async fn checkout(&self) -> DbMcpResult<TdsClient> {
        if let Some(c) = self.pool.lock().await.pop() {
            return Ok(c);
        }
        let mut client = self.connect().await?;
        if self.server_info.read().map(|g| g.is_none()).unwrap_or(true) {
            if let Ok(info) = probe_server_info(&mut client, &self.dsn).await {
                if let Ok(mut g) = self.server_info.write() {
                    *g = Some(info);
                }
            }
        }
        Ok(client)
    }

    async fn checkin(&self, client: TdsClient) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.config.pool_size.max(1) {
            pool.push(client);
        }
    }

    /// Check out a connection; a pooled connection that died is replaced once.
    async fn checkout_live(&self) -> DbMcpResult<TdsClient> {
        let mut client = self.checkout().await?;
        if run_simple(
            &mut client,
            &self.dsn,
            "SELECT /* db-mcp:internal */ 1;",
            "ping",
        )
        .await
        .is_ok()
        {
            return Ok(client);
        }
        drop(client);
        let mut fresh = self.connect().await?;
        run_simple(
            &mut fresh,
            &self.dsn,
            "SELECT /* db-mcp:internal */ 1;",
            "ping",
        )
        .await?;
        Ok(fresh)
    }

    /// Server identity and login permissions (connects once if not yet known).
    pub async fn server_info(&self) -> DbMcpResult<ServerInfo> {
        if let Some(info) = self.cached_server_info() {
            return Ok(info);
        }
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| DbMcpError::InternalError(e.to_string()))?;
        let mut client = self.checkout().await?;
        let info = probe_server_info(&mut client, &self.dsn).await?;
        if let Ok(mut g) = self.server_info.write() {
            *g = Some(info.clone());
        }
        self.checkin(client).await;
        Ok(info)
    }

    /// Cached server info without connecting.
    pub fn cached_server_info(&self) -> Option<ServerInfo> {
        self.server_info.read().ok().and_then(|g| g.clone())
    }

    /// Run an internal read-only metadata/diagnostic batch (no parameters) inside
    /// BEGIN TRAN ... ROLLBACK and return every result set.
    pub async fn query_internal(
        &self,
        sql: &str,
        max_rows: usize,
    ) -> DbMcpResult<Vec<FetchedRows>> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| DbMcpError::InternalError(e.to_string()))?;
        let mut client = self.checkout_live().await?;
        let (sets, clean) =
            run_read(&mut client, &self.dsn, sql, &[], max_rows, usize::MAX, true).await?;
        if clean {
            self.checkin(client).await;
        }
        Ok(sets)
    }

    /// First result set of an internal query.
    pub async fn query_rows(&self, sql: &str, max_rows: usize) -> DbMcpResult<FetchedRows> {
        Ok(self
            .query_internal(sql, max_rows)
            .await?
            .into_iter()
            .next()
            .unwrap_or_default())
    }

    /// Catalog objects of the current database, cached for `catalog_ttl`.
    pub async fn catalog_objects(&self) -> DbMcpResult<Vec<CatalogObject>> {
        if let Some(c) = self.catalog_cache.lock().ok().and_then(|g| g.clone()) {
            if c.loaded_at.elapsed() < self.config.catalog_ttl {
                return Ok(c.objects);
            }
        }
        let (objects, warnings) = catalog::load_catalog(self).await?;
        if let Ok(mut g) = self.catalog_cache.lock() {
            *g = Some(CatalogCache {
                loaded_at: Instant::now(),
                objects: objects.clone(),
            });
        }
        if let Ok(mut w) = self.catalog_warnings.lock() {
            *w = warnings;
        }
        Ok(objects)
    }

    /// Warnings from the last catalog load (e.g. definitions hidden without VIEW DEFINITION).
    pub fn catalog_warnings(&self) -> Vec<String> {
        self.catalog_warnings
            .lock()
            .map(|w| w.clone())
            .unwrap_or_default()
    }

    fn invalidate_catalog(&self) {
        if let Ok(mut g) = self.catalog_cache.lock() {
            *g = None;
        }
    }

    /// The adapter's own read guard: re-classify the SQL and refuse non-reads on a read-only
    /// connection or request, independent of the policy engine. Returns true for a read.
    pub fn guard(&self, sql: &str, read_only_request: bool) -> DbMcpResult<bool> {
        let analysis = parse_and_analyze_sql(DatabaseEngine::SqlServer, sql)?;
        let is_read = analysis.overall_class == SqlStatementClass::Read && !analysis.has_cte_write;
        if analysis.overall_class == SqlStatementClass::Transaction {
            return Err(DbMcpError::PolicyDenied {
                code: "TRANSACTION_CONTROL_NOT_ALLOWED".to_string(),
                message: "Transaction and session statements (BEGIN/COMMIT/ROLLBACK/SET/DECLARE) are managed by DB-MCP and are not sent to SQL Server".to_string(),
                next_action: None,
            });
        }
        if analysis.overall_class == SqlStatementClass::Unknown {
            return Err(DbMcpError::PolicyDenied {
                code: "UNKNOWN_SQL_CONSTRUCT".to_string(),
                message: "SQL Server adapter refuses statements it cannot classify".to_string(),
                next_action: None,
            });
        }
        if !is_read && (self.config.read_only || read_only_request) {
            return Err(DbMcpError::PolicyDenied {
                code: "MUTATION_NOT_ALLOWED_IN_READ_ONLY".to_string(),
                message: format!(
                    "SQL Server adapter read guard: '{}' statement refused on read-only connection '{}'",
                    analysis.overall_class, self.config.connection_id
                ),
                next_action: Some("list_connections".to_string()),
            });
        }
        Ok(is_read)
    }

    async fn execute_inner(
        &self,
        request: &AuthorizedQuery,
        sql: &str,
        params: &[SqlParam],
        is_read: bool,
    ) -> DbMcpResult<(FetchedRows, Option<u64>)> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| DbMcpError::InternalError(e.to_string()))?;
        let mut client = self.checkout_live().await?;
        let lock_ms = request.timeout_ms.clamp(1, 30_000);
        run_simple(
            &mut client,
            &self.dsn,
            &format!("SET LOCK_TIMEOUT {lock_ms};"),
            "session setup",
        )
        .await?;
        if is_read {
            let (sets, clean) = run_read(
                &mut client,
                &self.dsn,
                sql,
                params,
                request.max_rows,
                request.max_bytes,
                true,
            )
            .await?;
            if clean {
                self.checkin(client).await;
            }
            let extra = sets.len().saturating_sub(1);
            let mut first = sets.into_iter().next().unwrap_or_default();
            first.extra_result_sets = extra;
            return Ok((first, None));
        }
        // Write path: only reachable on a non-read-only connection (Development mode or an
        // approved change). Runs in a transaction and commits.
        run_simple(
            &mut client,
            &self.dsn,
            "SET XACT_ABORT ON; BEGIN TRANSACTION;",
            "begin transaction",
        )
        .await?;
        let refs: Vec<&dyn tiberius::ToSql> = params.iter().map(|p| p.as_tosql()).collect();
        let res = client
            .execute(sql, &refs)
            .await
            .map_err(|e| map_tds_error(&self.dsn, "execute", e))?;
        let affected: u64 = res.rows_affected().iter().sum();
        run_simple(&mut client, &self.dsn, "COMMIT TRANSACTION;", "commit").await?;
        self.checkin(client).await;
        self.invalidate_catalog();
        Ok((FetchedRows::default(), Some(affected)))
    }

    fn capabilities_with_probe(&self) -> DatabaseCapabilities {
        let mut caps = DatabaseCapabilities::for_sqlserver();
        match self.cached_server_info() {
            Some(info) => {
                for (k, v) in info.missing_grants() {
                    caps.unavailable_reasons.insert(k, v);
                }
                if !info.has_query_store() {
                    caps.unavailable_reasons.insert(
                        "query_store".to_string(),
                        format!(
                            "Query Store needs SQL Server 2016+ (server is {})",
                            info.product_version
                        ),
                    );
                }
            }
            None => {
                caps.unavailable_reasons.insert(
                    "permissions".to_string(),
                    "not yet connected: optional grants (VIEW DEFINITION, SHOWPLAN, VIEW DATABASE STATE, VIEW SERVER STATE) are checked at first use".to_string(),
                );
            }
        }
        caps
    }
}

#[async_trait]
impl DatabaseAdapter for SqlServerAdapter {
    fn connection_id(&self) -> &str {
        &self.config.connection_id
    }

    fn capabilities(&self) -> DatabaseCapabilities {
        self.capabilities_with_probe()
    }

    async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
        let objects = self.catalog_objects().await?;
        let mut resp = filter_and_paginate_objects(&objects, &request);
        resp.schema_version = Some(compute_schema_version(&objects));
        Ok(resp)
    }

    async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        let started = Instant::now();
        let is_read = self.guard(&request.sql, request.read_only)?;
        let params: Vec<SqlParam> = request.params.iter().map(SqlParam::from_json).collect();
        let sql = rewrite_placeholders(&request.sql, params.len());
        let token = CancellationToken::new();
        if let Ok(mut m) = self.inflight.lock() {
            m.insert(request.execution_id.clone(), token.clone());
        }
        // Cancellation and timeouts drop this future, which drops the TDS connection: the
        // server notices the closed session and rolls the open transaction back.
        let outcome = tokio::select! {
            _ = token.cancelled() => Err(DbMcpError::ExecutionCancelled(format!(
                "Execution '{}' was cancelled; the SQL Server connection was closed", request.execution_id
            ))),
            r = self.execute_inner(&request, &sql, &params, is_read) => r,
        };
        if let Ok(mut m) = self.inflight.lock() {
            m.remove(&request.execution_id);
        }
        let (fetched, rows_affected) = outcome?;
        let mut warnings = Vec::new();
        if fetched.extra_result_sets > 0 {
            warnings.push(format!(
                "{} additional result set(s) were discarded",
                fetched.extra_result_sets
            ));
        }
        Ok(QueryResult {
            execution_id: request.execution_id,
            returned_rows: fetched.rows.len(),
            columns: fetched.columns,
            rows: fetched.rows,
            rows_affected,
            truncated: fetched.truncated,
            bytes_used: fetched.bytes_used,
            execution_time_ms: started.elapsed().as_millis() as u64,
            warnings,
            schema_version: None,
        })
    }

    async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
        self.explain_estimated(request).await
    }

    async fn cancel(&self, execution: ExecutionId) -> DbMcpResult<bool> {
        // KILL needs ALTER ANY CONNECTION, which a read-only login lacks: cancellation drops the
        // in-flight request and its connection instead (the server rolls the transaction back).
        let token = self
            .inflight
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&execution));
        Ok(match token {
            Some(t) => {
                t.cancel();
                true
            }
            None => false,
        })
    }
}

fn count_named_params(sql: &str) -> usize {
    let re = regex::Regex::new(r"(?i)@P(\d+)\b").expect("valid param regex");
    re.captures_iter(sql)
        .filter_map(|c| c[1].parse::<usize>().ok())
        .max()
        .unwrap_or(0)
}

fn showplan_denied(user: &str) -> DbMcpError {
    let user = if user.is_empty() { "<user>" } else { user };
    DbMcpError::UnsupportedCapability(format!(
        "explain_query on SQL Server needs the SHOWPLAN permission; ask an administrator to run: GRANT SHOWPLAN TO [{user}]"
    ))
}

impl SqlServerAdapter {
    /// Estimated plan via `SET SHOWPLAN_XML ON` (the statement is compiled, never executed).
    pub async fn explain_estimated(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
        if request.analyze {
            return Err(DbMcpError::UnsupportedCapability(
                "explain analyze is not supported on SQL Server: an actual execution plan runs the statement; use analyze=false for the estimated plan".to_string(),
            ));
        }
        if !self.guard(&request.sql, true)? {
            return Err(DbMcpError::PolicyDenied {
                code: "MUTATION_NOT_ALLOWED_IN_READ_ONLY".to_string(),
                message: "SQL Server explain only accepts read statements".to_string(),
                next_action: None,
            });
        }
        let info = self.server_info().await?;
        if !info.can_showplan() {
            return Err(showplan_denied(&info.database_user));
        }
        let params: Vec<SqlParam> = request.params.iter().map(SqlParam::from_json).collect();
        let body = rewrite_placeholders(&request.sql, params.len());
        let n = params.len().max(count_named_params(&body));
        // Parameters are declared without values so the batch compiles; the optimizer then
        // estimates with average selectivity.
        let declares: Vec<String> = (1..=n)
            .map(|i| {
                format!(
                    "DECLARE @P{i} {};",
                    params
                        .get(i - 1)
                        .map(|p| p.declared_type())
                        .unwrap_or("nvarchar(4000)")
                )
            })
            .collect();
        let batch = format!("{}\n{}", declares.join(" "), body);
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| DbMcpError::InternalError(e.to_string()))?;
        let mut client = self.checkout_live().await?;
        run_simple(&mut client, &self.dsn, "SET SHOWPLAN_XML ON;", "showplan")
            .await
            .map_err(|e| match &e {
                DbMcpError::PolicyDenied { code, .. } if code == CODE_SERVER_PERMISSION_DENIED => {
                    showplan_denied(&info.database_user)
                }
                _ => e,
            })?;
        let fetched = async {
            client
                .simple_query(batch.as_str())
                .await
                .map_err(|e| map_tds_error(&self.dsn, "showplan", e))?
                .into_results()
                .await
                .map_err(|e| map_tds_error(&self.dsn, "showplan", e))
        }
        .await;
        if run_simple(&mut client, &self.dsn, "SET SHOWPLAN_XML OFF;", "showplan")
            .await
            .is_ok()
        {
            self.checkin(client).await;
        }
        let sets = fetched?;
        // Each compiled statement returns one plan document; the last one is the user statement.
        let xml = sets
            .iter()
            .flatten()
            .filter_map(|r| r.get::<&str, _>(0).map(ToOwned::to_owned))
            .next_back()
            .ok_or_else(|| {
                DbMcpError::AdapterError("SQL Server returned no estimated plan".to_string())
            })?;
        let parsed = showplan::parse_showplan_xml(&xml)?;
        let raw_plan = match request.format {
            ExplainFormat::Json => xml,
            ExplainFormat::Text => parsed.text_tree.clone(),
        };
        let mut warnings = vec![
            "SQL Server estimated plan (SHOWPLAN_XML); the statement was compiled, not executed"
                .to_string(),
        ];
        warnings.extend(parsed.warnings.clone());
        Ok(ExplainPlan {
            connection: request.connection,
            sql: request.sql,
            analyze: false,
            format: request.format,
            raw_plan,
            structured_plan: Some(parsed.structured),
            estimated_cost: parsed.estimated_cost,
            estimated_rows: parsed.estimated_rows,
            seq_scans: parsed.scans,
            index_scans: parsed.seeks,
            warnings,
        })
    }
}

#[async_trait]
impl SchemaDiffProvider for SqlServerAdapter {
    async fn capture_schema(
        &self,
        connection: &str,
        schema_pattern: Option<String>,
    ) -> DbMcpResult<SchemaSnapshot> {
        let mut req = CatalogRequest::new(connection);
        req.schema_pattern = schema_pattern;
        req.detail_level = db_mcp_core::CatalogDetailLevel::Full;
        req.limit = 10_000;
        let resp = self.discover(req).await?;
        Ok(capture_schema(
            connection,
            DatabaseEngine::SqlServer,
            resp.objects,
        ))
    }

    async fn diff_schema(
        &self,
        base: &SchemaSnapshot,
        target: &SchemaSnapshot,
    ) -> DbMcpResult<SchemaDiff> {
        Ok(diff_schema(base, target))
    }
}

/// Read-only connection check used by `db-mcp check-connection`. Never contains the password.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionCheck {
    pub target: String,
    pub server_version: Option<String>,
    pub database: Option<String>,
    pub login: Option<String>,
    pub can_connect: bool,
    pub select_1: bool,
    pub object_count: Option<usize>,
    pub permissions: Vec<String>,
    pub can_write: bool,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

impl SqlServerAdapter {
    /// Connect, read version and permissions, run `SELECT 1` and count catalog objects.
    pub async fn check_connection(&self) -> ConnectionCheck {
        let mut check = ConnectionCheck {
            target: self.display_target(),
            server_version: None,
            database: None,
            login: None,
            can_connect: false,
            select_1: false,
            object_count: None,
            permissions: Vec::new(),
            can_write: false,
            warnings: Vec::new(),
            error_code: None,
        };
        let info = match self.server_info().await {
            Ok(i) => i,
            Err(e) => {
                check.error_code = Some(e.code().to_string());
                check.warnings.push(self.dsn.scrub(&e.to_string()));
                return check;
            }
        };
        check.can_connect = true;
        check.server_version = Some(format!(
            "Microsoft SQL Server {} {} ({})",
            info.product_version, info.product_level, info.edition
        ));
        check.database = Some(info.database.clone());
        check.login = Some(info.login.clone());
        let mut perms: Vec<String> = info
            .database_permissions
            .iter()
            .map(|p| format!("database:{p}"))
            .collect();
        perms.extend(
            info.server_permissions
                .iter()
                .map(|p| format!("server:{p}")),
        );
        perms.extend(info.roles.iter().map(|r| format!("role:{r}")));
        check.permissions = perms;
        let writes = info.write_capabilities();
        check.can_write = !writes.is_empty();
        if check.can_write {
            check.warnings.push(format!(
                "this login can write ({}); DB-MCP still keeps read-only connections read-only, but use a dedicated db_datareader login",
                writes.join(", ")
            ));
        }
        for (_, why) in info.missing_grants() {
            check.warnings.push(format!("optional: {why}"));
        }
        match self
            .query_rows("SELECT /* db-mcp:internal */ 1 AS ok", 1)
            .await
        {
            Ok(r) => {
                check.select_1 = r
                    .rows
                    .first()
                    .and_then(|row| row.first())
                    .and_then(|v| v.as_i64())
                    == Some(1)
            }
            Err(e) => check.warnings.push(format!(
                "SELECT 1 failed: {}",
                self.dsn.scrub(&e.to_string())
            )),
        }
        match self.catalog_objects().await {
            Ok(objs) => check.object_count = Some(objs.len()),
            Err(e) => check.warnings.push(format!(
                "catalog discovery failed: {}",
                self.dsn.scrub(&e.to_string())
            )),
        }
        check.warnings.extend(self.catalog_warnings());
        check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(dsn: &str) -> SqlServerAdapter {
        SqlServerAdapter::new(SqlServerConfig::new("mssql", dsn)).unwrap()
    }

    #[test]
    fn construction_parses_dsn_without_connecting_and_never_leaks_password() {
        let a = adapter("sqlserver://ro:P%40ss%29w%24rd@127.0.0.1:1?instance=X");
        assert!(!format!("{a:?}").contains("P@ss"));
        assert!(!a.display_target().contains("P@ss"));
        let e = SqlServerAdapter::new(SqlServerConfig::new("bad", "sqlserver://ro:Secr3tPw@h:x"))
            .unwrap_err();
        assert!(
            e.to_string().contains("'bad'") && !e.to_string().contains("Secr3tPw"),
            "{e}"
        );
        let caps = a.capabilities();
        assert_eq!(caps.engine, DatabaseEngine::SqlServer);
        assert!(!caps.supports_analyze_explain);
        assert!(caps.unavailable_reasons.contains_key("permissions"));
    }

    #[test]
    fn read_guard_refuses_writes_and_session_statements() {
        let a = adapter("sqlserver://ro:pw@127.0.0.1:1");
        assert!(a.guard("SELECT TOP 1 id FROM dbo.users", true).unwrap());
        for sql in [
            "DELETE FROM dbo.users",
            "SELECT 1 DELETE FROM dbo.users",
            "EXEC sp_who",
            "BEGIN TRAN",
            "SELECT id INTO dbo.x FROM dbo.users",
            "UPDATE dbo.users SET role = 'x'",
        ] {
            assert!(a.guard(sql, false).is_err(), "{sql}");
        }
        let rw = SqlServerAdapter::new(
            SqlServerConfig::new("rw", "sqlserver://u:pw@127.0.0.1:1").with_read_only(false),
        )
        .unwrap();
        assert!(!rw.guard("UPDATE dbo.users SET role = 'x'", false).unwrap());
        assert!(rw.guard("UPDATE dbo.users SET role = 'x'", true).is_err());
    }

    #[tokio::test]
    async fn unreachable_server_fails_closed_with_connection_unavailable() {
        let mut cfg = SqlServerConfig::new(
            "mssql",
            "sqlserver://ro:Secr3tPw@127.0.0.1:1?connectTimeout=2",
        );
        cfg.catalog_ttl = Duration::from_secs(0);
        let a = SqlServerAdapter::new(cfg).unwrap();
        let err = a.discover(CatalogRequest::new("mssql")).await.unwrap_err();
        assert_eq!(err.code(), CODE_CONNECTION_UNAVAILABLE, "{err}");
        assert!(err.next_action().unwrap_or("").contains("check-connection"));
        assert!(!err.to_string().contains("Secr3tPw"));
        let check = a.check_connection().await;
        assert!(!check.can_connect && !check.select_1);
        assert_eq!(
            check.error_code.as_deref(),
            Some(CODE_CONNECTION_UNAVAILABLE)
        );
        assert!(!serde_json::to_string(&check).unwrap().contains("Secr3tPw"));
    }

    #[test]
    fn write_capabilities_and_missing_grants() {
        let ro = ServerInfo {
            database_permissions: vec!["CONNECT".into(), "SELECT".into()],
            roles: vec!["db_datareader".into()],
            database_user: "dbmcp_ro".into(),
            login: "dbmcp_ro".into(),
            major_version: 16,
            ..Default::default()
        };
        assert!(ro.write_capabilities().is_empty());
        let missing: Vec<String> = ro.missing_grants().into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            missing,
            vec![
                "routine_definitions",
                "explain",
                "query_store",
                "server_state"
            ]
        );
        let rw = ServerInfo {
            roles: vec!["db_datawriter".into()],
            database_permissions: vec!["INSERT".into()],
            ..Default::default()
        };
        assert_eq!(rw.write_capabilities().len(), 2);
        let full = ServerInfo {
            database_permissions: vec![
                "VIEW DEFINITION".into(),
                "SHOWPLAN".into(),
                "VIEW DATABASE STATE".into(),
            ],
            server_permissions: vec!["VIEW SERVER STATE".into()],
            ..Default::default()
        };
        assert!(full.missing_grants().is_empty());
    }

    #[test]
    fn named_param_counting() {
        assert_eq!(count_named_params("SELECT @P1, @p3 FROM t"), 3);
        assert_eq!(count_named_params("SELECT 1"), 0);
    }
}
