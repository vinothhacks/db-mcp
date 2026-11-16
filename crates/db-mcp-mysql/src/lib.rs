//! MySQL / MariaDB database adapter (`MySqlAdapter`) implementing `DatabaseAdapter`,
//! `SchemaDiffProvider`, and `TransactionalDdlProvider`.
//!
//! Features:
//! - Explicit backend selection (`MySqlBackendMode`): `LiveOnly` talks to a real MySQL 8 server
//!   and fails closed (`CONNECTION_UNAVAILABLE`) when it is unreachable; `SimulatedOnly` serves a
//!   deterministic embedded engine and never contacts a server. There is no silent fallback.
//! - `information_schema` progressive discovery (`TABLES`, `COLUMNS`, `STATISTICS`, `KEY_COLUMN_USAGE`)
//! - `EXPLAIN FORMAT=JSON` generation and structured plan parsing (`access_type: "ALL"` vs `"ref"` / `"range"`)
//! - `KILL QUERY <thread_id>` active query cancellation tracking
//! - Explicit non-transactional DDL warnings (`supports_transactional_ddl = false`)

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use db_mcp_catalog::{
    capture_schema as build_schema_snapshot, compute_schema_version,
    describe_object as catalog_describe_object, diff_schema as compute_schema_diff,
    filter_and_paginate_objects,
};
use db_mcp_core::{
    AuthorizedQuery, CatalogDetailLevel, CatalogObject, CatalogObjectType, CatalogRequest,
    CatalogResponse, ColumnMetadata, ColumnSpec, DatabaseAdapter, DatabaseCapabilities,
    DatabaseEngine, DbMcpError, DbMcpResult, ExplainFormat, ExplainPlan, ExplainRequest,
    ExecutionId, ForeignKeySpec, IndexSpec, QueryResult, SchemaDiff, SchemaDiffProvider,
    SchemaSnapshot, SqlStatementClass, TransactionalDdlProvider,
};
use db_mcp_secrets::{redact_dsn, redact_sensitive_text, SecretString};
use db_mcp_sql::{parse_and_analyze_sql, split_sql_statements, PredicateOperator};
use regex::Regex;
use rusqlite::types::{Value as SqliteValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use url::Url;

pub mod catalog;
pub mod diagnostics;
pub mod live;

pub use live::{
    bind_mysql_placeholders, build_mysql_session_setup, live_capabilities, mysql_column_type_name,
    mysql_value_to_json, parse_mysql_dsn, summarize_grants, GrantSummary, LiveMySql, MySqlDsn,
    CODE_CONNECTION_UNAVAILABLE, CODE_DATABASE_PERMISSION_DENIED, CODE_SERVER_READ_ONLY,
};

/// Warning emitted whenever DDL is executed on MySQL/MariaDB.
pub const MYSQL_NON_TRANSACTIONAL_DDL_WARNING: &str =
    "MySQL/MariaDB does not support transactional DDL (supports_transactional_ddl=false); DDL statements cause an implicit commit and require a compensating migration to undo.";

/// Execution mode for `MySqlAdapter`. Selected explicitly by configuration (`backend`); a live
/// connection never falls back to the simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MySqlBackendMode {
    /// Embedded simulation (bundled example config, offline tests). No server is contacted.
    SimulatedOnly,
    /// Real MySQL server reached through the DSN; failures are reported, never simulated.
    LiveOnly,
}

impl Default for MySqlBackendMode {
    fn default() -> Self {
        Self::LiveOnly
    }
}

impl MySqlBackendMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SimulatedOnly => "simulated",
            Self::LiveOnly => "live",
        }
    }
}

/// Configuration for `MySqlAdapter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MySqlConfig {
    pub connection_id: String,
    pub dsn: SecretString,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default = "default_mysql_schema")]
    pub default_schema: String,
    #[serde(default = "default_max_execution_time_ms")]
    pub max_execution_time_ms: u64,
    #[serde(default)]
    pub backend_mode: MySqlBackendMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_sql: Option<String>,
}

fn default_mysql_schema() -> String {
    "app".to_string()
}

fn default_max_execution_time_ms() -> u64 {
    10_000
}

impl MySqlConfig {
    pub fn new(connection_id: impl Into<String>, dsn: impl Into<SecretString>) -> Self {
        Self {
            connection_id: connection_id.into(),
            dsn: dsn.into(),
            read_only: false,
            default_schema: default_mysql_schema(),
            max_execution_time_ms: default_max_execution_time_ms(),
            backend_mode: MySqlBackendMode::LiveOnly,
            init_sql: None,
        }
    }

    pub fn simulated(connection_id: impl Into<String>) -> Self {
        let id = connection_id.into();
        Self {
            dsn: SecretString::new(format!("mysql://root:mysql@127.0.0.1:3306/{id}")),
            connection_id: id,
            read_only: false,
            default_schema: default_mysql_schema(),
            max_execution_time_ms: default_max_execution_time_ms(),
            backend_mode: MySqlBackendMode::SimulatedOnly,
            init_sql: None,
        }
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn with_default_schema(mut self, schema: impl Into<String>) -> Self {
        self.default_schema = schema.into();
        self
    }

    pub fn with_max_execution_time_ms(mut self, timeout_ms: u64) -> Self {
        self.max_execution_time_ms = timeout_ms;
        self
    }

    pub fn with_backend_mode(mut self, mode: MySqlBackendMode) -> Self {
        self.backend_mode = mode;
        self
    }

    pub fn with_init_sql(mut self, sql: impl Into<String>) -> Self {
        self.init_sql = Some(sql.into());
        self
    }
}

/// Parsed representation of a MySQL `EXPLAIN FORMAT=JSON` query plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedMySqlPlan {
    pub structured_plan: serde_json::Value,
    pub query_cost: Option<f64>,
    pub rows_examined: Option<f64>,
    pub seq_scans: Vec<String>,
    pub index_scans: Vec<String>,
    pub warnings: Vec<String>,
}

/// Build the `information_schema.TABLES` query for progressive discovery.
pub fn build_information_schema_tables_query(schema_pattern: Option<&str>) -> String {
    let filter = schema_pattern
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "%" && *s != "*")
        .map(|s| format!("AND TABLE_SCHEMA LIKE '{}'", s.replace('\'', "''")))
        .unwrap_or_default();

    format!(
        "SELECT
            TABLE_SCHEMA AS schema_name,
            TABLE_NAME AS object_name,
            CASE TABLE_TYPE
                WHEN 'VIEW' THEN 'view'
                ELSE 'table'
            END AS object_type,
            TABLE_COMMENT AS comment,
            TABLE_ROWS AS estimated_rows,
            (COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) AS size_bytes
         FROM information_schema.TABLES
         WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
           {filter}
         ORDER BY TABLE_SCHEMA, TABLE_NAME"
    )
}

/// Build the `information_schema.COLUMNS` query for a specific `(schema, table)`.
pub fn build_information_schema_columns_query(schema: &str, table: &str) -> String {
    format!(
        "SELECT
            COLUMN_NAME AS column_name,
            COLUMN_TYPE AS data_type,
            (IS_NULLABLE = 'YES') AS is_nullable,
            COLUMN_DEFAULT AS column_default,
            (COLUMN_KEY = 'PRI') AS is_primary_key,
            COLUMN_COMMENT AS comment,
            ORDINAL_POSITION AS ordinal_position
         FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = '{}'
           AND TABLE_NAME = '{}'
         ORDER BY ORDINAL_POSITION",
        schema.replace('\'', "''"),
        table.replace('\'', "''")
    )
}

/// Build the `information_schema.STATISTICS` query for indexes on a specific `(schema, table)`.
pub fn build_information_schema_statistics_query(schema: &str, table: &str) -> String {
    format!(
        "SELECT
            INDEX_NAME AS index_name,
            TABLE_NAME AS table_name,
            COLUMN_NAME AS column_name,
            (NON_UNIQUE = 0) AS is_unique,
            (INDEX_NAME = 'PRIMARY') AS is_primary,
            INDEX_TYPE AS index_type,
            SEQ_IN_INDEX AS seq_in_index
         FROM information_schema.STATISTICS
         WHERE TABLE_SCHEMA = '{}'
           AND TABLE_NAME = '{}'
         ORDER BY INDEX_NAME, SEQ_IN_INDEX",
        schema.replace('\'', "''"),
        table.replace('\'', "''")
    )
}

/// Build the `information_schema.ROUTINES` query for stored procedures and functions.
pub fn build_information_schema_routines_query(schema_pattern: Option<&str>) -> String {
    let filter = schema_pattern
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "%" && *s != "*")
        .map(|s| format!("AND ROUTINE_SCHEMA LIKE '{}'", s.replace('\'', "''")))
        .unwrap_or_default();

    format!(
        "SELECT
            ROUTINE_SCHEMA AS schema_name,
            ROUTINE_NAME AS routine_name,
            LOWER(ROUTINE_TYPE) AS routine_type,
            ROUTINE_DEFINITION AS definition,
            ROUTINE_COMMENT AS comment
         FROM information_schema.ROUTINES
         WHERE ROUTINE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
           {filter}
         ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME"
    )
}

/// Build the `KILL QUERY <thread_id>` statement used to cancel an in-flight MySQL query.
pub fn build_mysql_kill_query(thread_id: u64) -> String {
    format!("KILL QUERY {thread_id};")
}

/// Build the MySQL read-only session preamble (`SET SESSION TRANSACTION READ ONLY; SET SESSION max_execution_time = ...`).
pub fn build_mysql_readonly_session_preamble(max_execution_time_ms: u64) -> String {
    format!(
        "SET SESSION TRANSACTION READ ONLY; SET SESSION max_execution_time = {};",
        max_execution_time_ms
    )
}

/// Parse MySQL `EXPLAIN FORMAT=JSON` output into costs, row estimates, full scans (`access_type = "ALL"`),
/// and index scans (`access_type` in `ref`, `eq_ref`, `range`, `index`, `const`).
pub fn parse_mysql_explain_json(raw_json: &str) -> DbMcpResult<ParsedMySqlPlan> {
    let parsed: serde_json::Value = serde_json::from_str(raw_json).map_err(|e| {
        DbMcpError::AdapterError(format!("Failed to parse MySQL EXPLAIN FORMAT=JSON: {e}"))
    })?;

    let qb = parsed.get("query_block").unwrap_or(&parsed);
    let query_cost = qb
        .get("cost_info")
        .and_then(|c| c.get("query_cost"))
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
        });

    let mut seq_scans = Vec::new();
    let mut index_scans = Vec::new();
    let mut rows_examined_total = 0.0_f64;
    let mut notes = Vec::new();

    walk_mysql_plan_node(
        &parsed,
        &mut seq_scans,
        &mut index_scans,
        &mut rows_examined_total,
        &mut notes,
    );

    let mut warnings = notes;
    for tbl in &seq_scans {
        warnings.push(format!(
            "Full table scan (access_type=ALL) detected on MySQL table '{tbl}'"
        ));
    }

    Ok(ParsedMySqlPlan {
        structured_plan: parsed,
        query_cost,
        rows_examined: Some(rows_examined_total.max(1.0)),
        seq_scans,
        index_scans,
        warnings,
    })
}

fn walk_mysql_plan_node(
    node: &serde_json::Value,
    seq_scans: &mut Vec<String>,
    index_scans: &mut Vec<String>,
    rows_examined: &mut f64,
    notes: &mut Vec<String>,
) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(tbl_obj) = map.get("table").filter(|t| t.is_object()) {
                let table_name = tbl_obj
                    .get("table_name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let access_type = tbl_obj
                    .get("access_type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("ALL");
                let rows = tbl_obj
                    .get("rows_examined_per_scan")
                    .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                    .unwrap_or(1.0);
                *rows_examined += rows;
                if access_type.eq_ignore_ascii_case("ALL") {
                    if !seq_scans.contains(&table_name.to_string()) {
                        seq_scans.push(table_name.to_string());
                    }
                } else if let Some(key) = tbl_obj.get("key").and_then(serde_json::Value::as_str) {
                    if !index_scans.contains(&key.to_string()) {
                        index_scans.push(key.to_string());
                    }
                }
            }
            if map.get("using_filesort").and_then(serde_json::Value::as_bool) == Some(true) {
                let n = "Plan sorts rows with a filesort (no index provides the ORDER BY / GROUP BY order)".to_string();
                if !notes.contains(&n) {
                    notes.push(n);
                }
            }
            if map.get("using_temporary_table").and_then(serde_json::Value::as_bool) == Some(true) {
                let n = "Plan materializes an internal temporary table".to_string();
                if !notes.contains(&n) {
                    notes.push(n);
                }
            }
            for child in map.values() {
                walk_mysql_plan_node(child, seq_scans, index_scans, rows_examined, notes);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                walk_mysql_plan_node(child, seq_scans, index_scans, rows_examined, notes);
            }
        }
        _ => {}
    }
}

/// Probe whether a live MySQL/MariaDB server is reachable at the DSN host:port.
pub async fn probe_mysql_tcp(dsn: &str, timeout: Duration) -> DbMcpResult<(String, u16)> {
    let parsed = Url::parse(dsn).map_err(|_| {
        DbMcpError::ConfigurationError(format!("Invalid MySQL DSN: {}", redact_dsn(dsn)))
    })?;
    let host = parsed.host_str().unwrap_or("127.0.0.1").to_string();
    let port = parsed.port().unwrap_or(3306);
    let addr = format!("{host}:{port}");

    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            DbMcpError::AdapterError(format!(
                "Timed out connecting to MySQL at {}",
                redact_dsn(&addr)
            ))
        })?
        .map_err(|e| {
            DbMcpError::AdapterError(format!(
                "Failed to connect to MySQL at {}: {}",
                redact_dsn(&addr),
                redact_sensitive_text(&e.to_string())
            ))
        })?;

    drop(stream);
    Ok((host, port))
}

/// MySQL / MariaDB implementation of `DatabaseAdapter`, `SchemaDiffProvider`, and `TransactionalDdlProvider`.
#[derive(Clone)]
pub struct MySqlAdapter {
    config: MySqlConfig,
    engine_conn: Arc<Mutex<Connection>>,
    custom_catalog: Arc<DashMap<String, CatalogObject>>,
    active_threads: Arc<DashMap<ExecutionId, u64>>,
    cancelled_executions: Arc<DashMap<ExecutionId, DateTime<Utc>>>,
    killed_threads: Arc<Mutex<Vec<u64>>>,
    kill_query_log: Arc<Mutex<Vec<String>>>,
    session_log: Arc<Mutex<Vec<String>>>,
    next_thread_id: Arc<AtomicU64>,
    live: Option<Arc<live::LiveMySql>>,
}

impl std::fmt::Debug for MySqlAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlAdapter")
            .field("connection_id", &self.config.connection_id)
            .field("dsn", &self.config.dsn)
            .field("read_only", &self.config.read_only)
            .field("default_schema", &self.config.default_schema)
            .field("backend_mode", &self.config.backend_mode)
            .finish()
    }
}

impl MySqlAdapter {
    /// Create a new `MySqlAdapter` from `MySqlConfig`.
    pub fn new(config: MySqlConfig) -> DbMcpResult<Self> {
        let live = if config.backend_mode == MySqlBackendMode::LiveOnly {
            if config.init_sql.as_deref().map(str::trim).is_some_and(|s| !s.is_empty()) {
                return Err(DbMcpError::ConfigurationError(format!(
                    "Connection '{}': init_sql is only allowed with backend = \"simulated\"; it is never run on a live server",
                    config.connection_id
                )));
            }
            Some(Arc::new(live::LiveMySql::new(
                &config.connection_id,
                config.dsn.expose_secret(),
                config.read_only,
            )?))
        } else {
            None
        };
        let conn = Connection::open_in_memory()
            .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

        bootstrap_mysql_system_tables(&conn)?;

        if let Some(init_sql) = &config.init_sql {
            if !init_sql.trim().is_empty() {
                let rewritten = rewrite_mysql_sql_for_embedded(init_sql, &config.default_schema);
                conn.execute_batch(&rewritten)
                    .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;
            }
        }

        Ok(Self {
            config,
            engine_conn: Arc::new(Mutex::new(conn)),
            custom_catalog: Arc::new(DashMap::new()),
            active_threads: Arc::new(DashMap::new()),
            cancelled_executions: Arc::new(DashMap::new()),
            killed_threads: Arc::new(Mutex::new(Vec::new())),
            kill_query_log: Arc::new(Mutex::new(Vec::new())),
            session_log: Arc::new(Mutex::new(Vec::new())),
            next_thread_id: Arc::new(AtomicU64::new(700)),
            live,
        })
    }

    /// `live` or `simulated`.
    pub fn backend(&self) -> &'static str {
        self.config.backend_mode.as_str()
    }

    /// Read-only `check-connection` report (JSON). Never contains the DSN or password.
    pub async fn check_connection(&self) -> serde_json::Value {
        match &self.live {
            Some(live) => live.check().await,
            None => serde_json::json!({
                "connection": self.config.connection_id,
                "engine": "mysql",
                "backend": "simulated",
                "server_version": null,
                "can_connect": true,
                "select_1": true,
                "object_count": null,
                "permissions": [],
                "can_write": !self.config.read_only,
                "warnings": ["embedded simulated MySQL engine: no server is contacted and the DSN is ignored"],
            }),
        }
    }

    /// Create a simulated MySQL adapter for offline testing.
    pub fn simulated(connection_id: impl Into<String>) -> DbMcpResult<Self> {
        Self::new(MySqlConfig::simulated(connection_id))
    }

    /// Create a simulated MySQL adapter pre-seeded with DDL/DML.
    pub fn simulated_with_seed(
        connection_id: impl Into<String>,
        seed_sql: impl Into<String>,
    ) -> DbMcpResult<Self> {
        Self::new(MySqlConfig::simulated(connection_id).with_init_sql(seed_sql))
    }

    /// Create a `MySqlAdapter` from a connection string (`mysql://...`).
    pub fn from_dsn(
        connection_id: impl Into<String>,
        dsn: impl Into<SecretString>,
        read_only: bool,
    ) -> DbMcpResult<Self> {
        Self::new(MySqlConfig::new(connection_id, dsn).with_read_only(read_only))
    }

    pub fn config(&self) -> &MySqlConfig {
        &self.config
    }

    /// Register or override a `CatalogObject` in the adapter's catalog.
    pub fn register_catalog_object(&self, object: CatalogObject) {
        self.custom_catalog
            .insert(object.qualified_name().to_ascii_lowercase(), object);
    }

    /// Execute a SQL seed batch against the adapter's backing store.
    pub fn execute_batch(&self, sql: &str) -> DbMcpResult<()> {
        let rewritten = rewrite_mysql_sql_for_embedded(sql, &self.config.default_schema);
        let guard = self.engine_conn.lock().map_err(|_| {
            DbMcpError::InternalError("MySqlAdapter engine lock poisoned".to_string())
        })?;
        guard
            .execute_batch(&rewritten)
            .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))
    }

    /// Register a MySQL connection thread ID for an `ExecutionId`.
    pub fn register_thread_id(&self, execution_id: ExecutionId, thread_id: u64) {
        self.active_threads.insert(execution_id, thread_id);
    }

    /// Return all MySQL thread IDs cancelled via `KILL QUERY`.
    pub fn killed_threads(&self) -> Vec<u64> {
        self.killed_threads
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return the log of `KILL QUERY <id>;` statements issued by `cancel`.
    pub fn kill_query_log(&self) -> Vec<String> {
        self.kill_query_log
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return the log of session preamble statements executed.
    pub fn session_log(&self) -> Vec<String> {
        self.session_log
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Describe a single catalog object by name and optional schema.
    pub async fn describe_object(
        &self,
        schema: Option<&str>,
        object_name: &str,
        detail_level: CatalogDetailLevel,
    ) -> DbMcpResult<CatalogObject> {
        let all = self.collect_all_catalog_objects().await?;
        catalog_describe_object(&all, schema, object_name, detail_level)
    }

    /// The live backend, when this adapter talks to a real server.
    pub fn live(&self) -> Option<&Arc<live::LiveMySql>> {
        self.live.as_ref()
    }

    /// Simulated backends need no connectivity; live calls go to the server directly.
    async fn ensure_connectivity(&self) -> DbMcpResult<()> {
        Ok(())
    }

    /// Live catalog (cached for `catalog::CATALOG_CACHE_TTL`) merged with registered objects.
    async fn live_catalog_objects(&self, live: &live::LiveMySql, force: bool) -> DbMcpResult<Vec<CatalogObject>> {
        let cached = live.catalog(force).await?;
        let mut objects: Vec<CatalogObject> = cached.objects.as_ref().clone();
        for entry in self.custom_catalog.iter() {
            if let Some(existing) = objects
                .iter_mut()
                .find(|o| o.qualified_name().to_ascii_lowercase() == *entry.key())
            {
                *existing = entry.value().clone();
            } else {
                objects.push(entry.value().clone());
            }
        }
        Ok(objects)
    }

    /// Re-read the live catalog now (capture_schema / diff_schema / drift checks).
    pub async fn refresh_catalog(&self) -> DbMcpResult<()> {
        if let Some(live) = &self.live {
            live.catalog(true).await?;
        }
        Ok(())
    }

    /// Shared read-only guard (policy is enforced upstream; this is defence in depth).
    fn guard_read_only(&self, request: &AuthorizedQuery) -> DbMcpResult<bool> {
        let effective_read_only = self.config.read_only || request.read_only;
        let analysis = parse_and_analyze_sql(DatabaseEngine::MySql, &request.sql)?;
        if effective_read_only
            && (analysis.overall_class.is_mutating()
                || analysis.has_writes
                || analysis.has_ddl
                || analysis.has_cte_write
                || analysis.has_privileged_functions)
        {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: format!(
                    "MySQL statement classified as '{}' is forbidden in read-only mode on '{}'",
                    analysis.overall_class, self.config.connection_id
                ),
                next_action: Some("propose_change".to_string()),
            });
        }
        Ok(effective_read_only)
    }

    async fn collect_all_catalog_objects(&self) -> DbMcpResult<Vec<CatalogObject>> {
        if let Some(live) = &self.live {
            return self.live_catalog_objects(live, false).await;
        }
        self.ensure_connectivity().await?;
        let conn = Arc::clone(&self.engine_conn);
        let default_schema = self.config.default_schema.clone();
        let custom_map: BTreeMap<String, CatalogObject> = self
            .custom_catalog
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|_| {
                DbMcpError::InternalError("MySqlAdapter engine lock poisoned".to_string())
            })?;
            let mut objects = introspect_embedded_mysql_catalog(&guard, &default_schema)?;
            for (k, custom_obj) in custom_map {
                if let Some(existing) = objects
                    .iter_mut()
                    .find(|o| o.qualified_name().to_ascii_lowercase() == k)
                {
                    *existing = custom_obj;
                } else {
                    objects.push(custom_obj);
                }
            }
            Ok(objects)
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("MySQL catalog join error: {e}")))?
    }
}

fn is_ddl_statement(sql: &str) -> bool {
    parse_and_analyze_sql(DatabaseEngine::MySql, sql)
        .map(|a| a.overall_class == SqlStatementClass::Ddl || a.has_ddl)
        .unwrap_or(false)
}

fn bootstrap_mysql_system_tables(conn: &Connection) -> DbMcpResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS __mysql_routines (
            routine_name TEXT PRIMARY KEY,
            routine_schema TEXT NOT NULL DEFAULT 'app',
            routine_type TEXT NOT NULL DEFAULT 'PROCEDURE',
            definition TEXT NOT NULL,
            comment TEXT
        );

        "#,
    )
    .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
    Ok(())
}

fn rewrite_non_routine_mysql_fragment(fragment: &str, default_schema: &str) -> String {
    let schema_prefix = format!("{default_schema}.");
    let backtick_prefix = format!("`{default_schema}`.");
    fragment
        .replace(&schema_prefix, "")
        .replace(&backtick_prefix, "")
}

fn find_mysql_routine_ddl_end(sql: &str, after_open_paren: usize) -> usize {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = after_open_paren;
    let mut paren_depth = 1usize;

    // 1. Skip parameter list `(...)`
    while i < len && paren_depth > 0 {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < len && bytes[i] == b'\'' {
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < len && bytes[i] != quote {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b'(' => {
                paren_depth += 1;
                i += 1;
            }
            b')' => {
                paren_depth -= 1;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    // 2. Scan for BEGIN ... END or single-statement semicolon
    let mut block_depth = 0usize;
    let mut saw_begin = false;
    while i < len {
        match bytes[i] {
            b'-' if i + 1 < len && bytes[i + 1] == b'-' => {
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(len);
            }
            b'\'' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < len && bytes[i] == b'\'' {
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' | b'`' => {
                let quote = bytes[i];
                i += 1;
                while i < len && bytes[i] != quote {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            b';' if !saw_begin => {
                return i + 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start_word = i;
                while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &sql[start_word..i];
                if word.eq_ignore_ascii_case("BEGIN") {
                    saw_begin = true;
                    block_depth += 1;
                } else if saw_begin && word.eq_ignore_ascii_case("CASE") {
                    block_depth += 1;
                } else if saw_begin && word.eq_ignore_ascii_case("END") {
                    let mut p = i;
                    while p < len && bytes[p].is_ascii_whitespace() {
                        p += 1;
                    }
                    let next_word_start = p;
                    while p < len && (bytes[p].is_ascii_alphanumeric() || bytes[p] == b'_') {
                        p += 1;
                    }
                    let next_word = &sql[next_word_start..p];
                    if matches!(
                        next_word.to_ascii_uppercase().as_str(),
                        "IF" | "LOOP" | "WHILE" | "REPEAT" | "FOR"
                    ) {
                        i = p;
                    } else {
                        if next_word.eq_ignore_ascii_case("CASE") {
                            i = p;
                        }
                        block_depth = block_depth.saturating_sub(1);
                        if block_depth == 0 {
                            while i < len {
                                if bytes[i] == b';' {
                                    return i + 1;
                                }
                                i += 1;
                            }
                            return len;
                        }
                    }
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    len
}

/// Parse a `DELIMITER <x>` client directive line; returns the new delimiter.
fn parse_delimiter_directive(line: &str) -> Option<String> {
    let t = line.trim();
    let head = t.get(..9)?;
    if !head.eq_ignore_ascii_case("DELIMITER") {
        return None;
    }
    let rest = t[9..].trim();
    if rest.is_empty() || !t[9..].starts_with(char::is_whitespace) {
        return None;
    }
    Some(rest.to_string())
}

/// Strip client-side `DELIMITER <x>` directives and split the text on the active
/// delimiter, re-terminating each statement with `;` so the routine splitter and
/// the embedded engine see plain SQL. Text without `DELIMITER` lines is returned unchanged.
fn normalize_mysql_delimiters(sql: &str) -> String {
    if !sql.lines().any(|l| parse_delimiter_directive(l).is_some()) {
        return sql.to_string();
    }
    let mut result = String::new();
    let mut active = ";".to_string();
    let mut in_quote: Option<char> = None;
    for line in sql.split_inclusive('\n') {
        if in_quote.is_none() {
            if let Some(d) = parse_delimiter_directive(line) {
                active = d;
                continue;
            }
        }
        let mut rest = line;
        while !rest.is_empty() {
            if in_quote.is_none() && active != ";" && rest.starts_with(active.as_str()) {
                result.push_str(";\n");
                rest = &rest[active.len()..];
                continue;
            }
            let c = rest.chars().next().unwrap();
            match in_quote {
                Some(q) if c == q => in_quote = None,
                None if c == '\'' || c == '"' || c == '`' => in_quote = Some(c),
                _ => {}
            }
            result.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    result
}

fn rewrite_mysql_sql_for_embedded(sql: &str, default_schema: &str) -> String {
    let normalized = normalize_mysql_delimiters(sql);
    let sql = normalized.as_str();
    let header_re = Regex::new(
        r#"(?im)(?:^|;)\s*(CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(PROCEDURE|FUNCTION)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*\()"#,
    )
    .unwrap();

    let mut out = String::new();
    let mut cursor = 0usize;

    while cursor < sql.len() {
        let Some(caps) = header_re.captures(&sql[cursor..]) else {
            out.push_str(&rewrite_non_routine_mysql_fragment(
                &sql[cursor..],
                default_schema,
            ));
            break;
        };

        let full_group = caps.get(0).unwrap();
        let create_group = caps.get(1).unwrap();
        let kind_str = caps.get(2).unwrap().as_str();
        let raw_ident = caps.get(3).unwrap().as_str();

        let stmt_start = cursor + create_group.start();
        let after_open_paren = cursor + create_group.end();

        let prefix_end = if full_group.as_str().trim_start().starts_with(';') {
            cursor + full_group.start() + full_group.as_str().find(';').unwrap() + 1
        } else {
            stmt_start
        };
        if prefix_end > cursor {
            out.push_str(&rewrite_non_routine_mysql_fragment(
                &sql[cursor..prefix_end],
                default_schema,
            ));
        }

        let stmt_end = find_mysql_routine_ddl_end(sql, after_open_paren);
        let definition = sql[stmt_start..stmt_end].trim();

        let parts: Vec<String> = raw_ident
            .split('.')
            .map(|p| {
                p.trim()
                    .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
                    .to_string()
            })
            .filter(|p| !p.is_empty())
            .collect();
        let (schema, routine_name) = if parts.len() >= 2 {
            (parts[parts.len() - 2].clone(), parts[parts.len() - 1].clone())
        } else if parts.len() == 1 {
            (default_schema.to_string(), parts[0].clone())
        } else {
            (default_schema.to_string(), raw_ident.trim().to_string())
        };
        let routine_type = if kind_str.eq_ignore_ascii_case("FUNCTION") {
            "FUNCTION"
        } else {
            "PROCEDURE"
        };

        if !out.trim().is_empty() && !out.trim_end().ends_with(';') {
            out.push(';');
        }
        out.push_str(&format!(
            "\nINSERT OR REPLACE INTO __mysql_routines (routine_name, routine_schema, routine_type, definition, comment) VALUES ('{}', '{}', '{}', '{}', NULL);\n",
            routine_name.replace('\'', "''"),
            schema.replace('\'', "''"),
            routine_type,
            definition.replace('\'', "''"),
        ));

        cursor = stmt_end;
    }

    out
}

fn introspect_embedded_mysql_catalog(
    conn: &Connection,
    default_schema: &str,
) -> DbMcpResult<Vec<CatalogObject>> {
    let mut stmt = conn
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND name NOT LIKE '__mysql_%'
             ORDER BY type, name",
        )
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    struct MasterItem {
        obj_type: String,
        name: String,
        tbl_name: String,
        sql: Option<String>,
    }

    let rows = stmt
        .query_map([], |r| {
            Ok(MasterItem {
                obj_type: r.get(0)?,
                name: r.get(1)?,
                tbl_name: r.get(2)?,
                sql: r.get(3)?,
            })
        })
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    let mut items = Vec::new();
    for r in rows {
        items.push(r.map_err(|e| DbMcpError::AdapterError(e.to_string()))?);
    }

    let mut index_sql_map: BTreeMap<String, Option<String>> = BTreeMap::new();
    for item in &items {
        if item.obj_type.eq_ignore_ascii_case("index") {
            index_sql_map.insert(item.name.clone(), item.sql.clone());
        }
    }

    let mut objects = Vec::new();
    for item in &items {
        match item.obj_type.to_ascii_lowercase().as_str() {
            "table" | "view" => {
                let is_table = item.obj_type.eq_ignore_ascii_case("table");
                let columns = introspect_mysql_columns(conn, &item.name)?;
                let indexes = if is_table {
                    introspect_mysql_indexes(conn, &item.name, &index_sql_map)?
                } else {
                    Vec::new()
                };
                let foreign_keys = if is_table {
                    introspect_mysql_fks(conn, &item.name)?
                } else {
                    Vec::new()
                };
                let estimated_rows = if is_table {
                    conn.query_row(
                        &format!("SELECT COUNT(*) FROM \"{}\"", item.name.replace('"', "\"\"")),
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                    .ok()
                    .map(|c| c.max(0) as u64)
                } else {
                    None
                };

                for idx in &indexes {
                    objects.push(CatalogObject {
                        schema: default_schema.to_string(),
                        name: idx.name.clone(),
                        object_type: CatalogObjectType::Index,
                        comment: None,
                        estimated_rows: None,
                        size_bytes: Some(16384),
                        columns: idx
                            .columns
                            .iter()
                            .enumerate()
                            .map(|(pos, col)| ColumnSpec {
                                name: col.clone(),
                                data_type: "index_key".to_string(),
                                nullable: true,
                                default_value: None,
                                is_primary_key: idx.primary,
                                comment: None,
                                ordinal_position: pos + 1,
                            })
                            .collect(),
                        indexes: vec![idx.clone()],
                        foreign_keys: Vec::new(),
                        definition: idx.definition.clone(),
                    });
                }

                objects.push(CatalogObject {
                    schema: default_schema.to_string(),
                    name: item.name.clone(),
                    object_type: if is_table {
                        CatalogObjectType::Table
                    } else {
                        CatalogObjectType::View
                    },
                    comment: None,
                    estimated_rows,
                    size_bytes: Some(estimated_rows.unwrap_or(1) * 256 + 16384),
                    columns,
                    indexes,
                    foreign_keys,
                    definition: item.sql.clone(),
                });
            }
            "trigger" => {
                objects.push(CatalogObject {
                    schema: default_schema.to_string(),
                    name: item.name.clone(),
                    object_type: CatalogObjectType::Trigger,
                    comment: Some(format!("Trigger on {}", item.tbl_name)),
                    estimated_rows: None,
                    size_bytes: None,
                    columns: Vec::new(),
                    indexes: Vec::new(),
                    foreign_keys: Vec::new(),
                    definition: item.sql.clone(),
                });
            }
            _ => {}
        }
    }

    if let Ok(mut routine_stmt) = conn.prepare(
        "SELECT routine_name, routine_schema, routine_type, definition, comment
         FROM __mysql_routines
         ORDER BY routine_schema, routine_name",
    ) {
        let routine_rows = routine_stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

        for row in routine_rows {
            let (routine_name, routine_schema, routine_type, definition, comment) =
                row.map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
            let schema = if routine_schema.trim().is_empty() || routine_schema == "app" {
                default_schema.to_string()
            } else {
                routine_schema
            };
            let object_type = if routine_type.eq_ignore_ascii_case("function")
                || routine_type.eq_ignore_ascii_case("f")
            {
                CatalogObjectType::Function
            } else {
                CatalogObjectType::Procedure
            };
            objects.push(CatalogObject {
                schema,
                name: routine_name,
                object_type,
                comment,
                estimated_rows: None,
                size_bytes: None,
                columns: Vec::new(),
                indexes: Vec::new(),
                foreign_keys: Vec::new(),
                definition: Some(definition),
            });
        }
    }

    Ok(objects)
}

fn introspect_mysql_columns(conn: &Connection, table: &str) -> DbMcpResult<Vec<ColumnSpec>> {
    let mut stmt = conn
        .prepare(&format!(
            "PRAGMA table_info(\"{}\")",
            table.replace('"', "\"\"")
        ))
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
    let iter = stmt
        .query_map([], |row| {
            let cid: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let raw_type: String = row
                .get::<_, Option<String>>(2)?
                .unwrap_or_else(|| "varchar(255)".to_string());
            let notnull: i64 = row.get(3)?;
            let default_value: Option<String> = row.get(4)?;
            let pk: i64 = row.get(5)?;
            Ok(ColumnSpec {
                name,
                data_type: raw_type.to_ascii_lowercase(),
                nullable: notnull == 0 && pk == 0,
                default_value,
                is_primary_key: pk > 0,
                comment: None,
                ordinal_position: (cid.max(0) as usize) + 1,
            })
        })
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
    let mut out = Vec::new();
    for c in iter {
        out.push(c.map_err(|e| DbMcpError::AdapterError(e.to_string()))?);
    }
    Ok(out)
}

fn introspect_mysql_indexes(
    conn: &Connection,
    table: &str,
    index_sql_map: &BTreeMap<String, Option<String>>,
) -> DbMcpResult<Vec<IndexSpec>> {
    let mut stmt = conn
        .prepare(&format!(
            "PRAGMA index_list(\"{}\")",
            table.replace('"', "\"\"")
        ))
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    let iter = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? != 0,
                row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    let mut raw = Vec::new();
    for r in iter {
        raw.push(r.map_err(|e| DbMcpError::AdapterError(e.to_string()))?);
    }

    let mut indexes = Vec::new();
    for (idx_name, unique, origin) in raw {
        let mut info_stmt = conn
            .prepare(&format!(
                "PRAGMA index_info(\"{}\")",
                idx_name.replace('"', "\"\"")
            ))
            .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
        let col_iter = info_stmt
            .query_map([], |r| r.get::<_, Option<String>>(2))
            .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
        let mut cols = Vec::new();
        for c in col_iter {
            if let Some(col_name) = c.map_err(|e| DbMcpError::AdapterError(e.to_string()))? {
                cols.push(col_name);
            }
        }
        indexes.push(IndexSpec {
            name: idx_name.clone(),
            table_name: table.to_string(),
            columns: cols,
            unique,
            primary: origin.eq_ignore_ascii_case("pk"),
            index_type: Some("BTREE".to_string()),
            predicate: None,
            definition: index_sql_map.get(&idx_name).cloned().flatten(),
        });
    }
    Ok(indexes)
}

fn introspect_mysql_fks(conn: &Connection, table: &str) -> DbMcpResult<Vec<ForeignKeySpec>> {
    let mut stmt = conn
        .prepare(&format!(
            "PRAGMA foreign_key_list(\"{}\")",
            table.replace('"', "\"\"")
        ))
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    let iter = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })
        .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

    let mut grouped: BTreeMap<i64, ForeignKeySpec> = BTreeMap::new();
    for item in iter {
        let (id, ref_table, from_col, to_col, on_update, on_delete) =
            item.map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
        let entry = grouped.entry(id).or_insert_with(|| ForeignKeySpec {
            name: Some(format!("fk_{table}_{from_col}_{id}")),
            columns: Vec::new(),
            referenced_table: ref_table,
            referenced_columns: Vec::new(),
            on_delete,
            on_update,
        });
        entry.columns.push(from_col);
        if !to_col.is_empty() {
            entry.referenced_columns.push(to_col);
        }
    }
    Ok(grouped.into_values().collect())
}

fn json_to_sqlite_param(value: &serde_json::Value) -> SqliteValue {
    match value {
        serde_json::Value::Null => SqliteValue::Null,
        serde_json::Value::Bool(b) => SqliteValue::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqliteValue::Integer(i)
            } else if let Some(u) = n.as_u64() {
                SqliteValue::Integer(u as i64)
            } else if let Some(f) = n.as_f64() {
                SqliteValue::Real(f)
            } else {
                SqliteValue::Text(n.to_string())
            }
        }
        serde_json::Value::String(s) => SqliteValue::Text(s.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            SqliteValue::Text(serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()))
        }
    }
}

fn value_ref_to_mysql_json(val: ValueRef<'_>) -> (serde_json::Value, &'static str, usize) {
    match val {
        ValueRef::Null => (serde_json::Value::Null, "null", 4),
        ValueRef::Integer(i) => (serde_json::json!(i), "bigint", 8),
        ValueRef::Real(f) => (serde_json::json!(f), "double", 8),
        ValueRef::Text(b) => {
            let s = String::from_utf8_lossy(b).into_owned();
            let len = s.len().max(1);
            (serde_json::Value::String(s), "varchar", len)
        }
        ValueRef::Blob(b) => {
            let mut hex_str = String::with_capacity(b.len() * 2 + 2);
            hex_str.push_str("0x");
            for byte in b {
                hex_str.push_str(&format!("{byte:02x}"));
            }
            let len = hex_str.len();
            (serde_json::Value::String(hex_str), "blob", len)
        }
    }
}

#[async_trait]
impl DatabaseAdapter for MySqlAdapter {
    fn connection_id(&self) -> &str {
        &self.config.connection_id
    }

    fn is_simulated(&self) -> bool {
        self.live.is_none()
    }

    fn capabilities(&self) -> DatabaseCapabilities {
        if self.live.is_some() {
            live::live_capabilities()
        } else {
            DatabaseCapabilities::for_mysql()
        }
    }

    async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
        let all_objects = self.collect_all_catalog_objects().await?;
        let mut response = filter_and_paginate_objects(&all_objects, &request);
        if self.live.is_some() {
            response.schema_version = Some(compute_schema_version(&all_objects));
        }
        Ok(response)
    }

    async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        if let Some(live) = &self.live {
            let read_only = self.guard_read_only(&request)?;
            let timeout_ms = if request.timeout_ms == 0 {
                self.config.max_execution_time_ms
            } else {
                request.timeout_ms
            };
            if read_only {
                if let Ok(mut log) = self.session_log.lock() {
                    log.push(live::build_mysql_session_setup(true, timeout_ms));
                }
            }
            let mutating = !read_only
                && parse_and_analyze_sql(DatabaseEngine::MySql, &request.sql)
                    .map(|a| a.overall_class != SqlStatementClass::Read || a.has_ddl || a.has_cte_write)
                    .unwrap_or(true);
            let outcome = live.execute(&request, read_only, timeout_ms).await;
            if mutating {
                // Writes and DDL (implicit commit) may change the schema: re-read it next time.
                live.invalidate_catalog();
            }
            let mut result = outcome?;
            if is_ddl_statement(&request.sql) {
                result.warnings.push(MYSQL_NON_TRANSACTIONAL_DDL_WARNING.to_string());
            }
            result.schema_version = live.cached_schema_version();
            return Ok(result);
        }

        let exec_id = request.execution_id.clone();
        if self.cancelled_executions.contains_key(&exec_id) {
            return Err(DbMcpError::ExecutionCancelled(format!(
                "MySQL execution '{}' was cancelled via KILL QUERY",
                exec_id
            )));
        }

        let effective_read_only = self.config.read_only || request.read_only;
        let analysis = parse_and_analyze_sql(DatabaseEngine::MySql, &request.sql)?;

        if effective_read_only
            && (analysis.overall_class.is_mutating()
                || analysis.has_writes
                || analysis.has_ddl
                || analysis.has_cte_write
                || analysis.has_privileged_functions)
        {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: format!(
                    "MySQL statement classified as '{}' is forbidden in read-only mode on '{}'",
                    analysis.overall_class, self.config.connection_id
                ),
                next_action: Some("propose_change".to_string()),
            });
        }

        let timeout_ms = if request.timeout_ms == 0 {
            self.config.max_execution_time_ms
        } else {
            request.timeout_ms
        };

        if effective_read_only {
            let preamble = build_mysql_readonly_session_preamble(timeout_ms);
            if let Ok(mut log) = self.session_log.lock() {
                log.push(preamble);
            }
        }

        let _thread_id = self
            .active_threads
            .entry(exec_id.clone())
            .or_insert_with(|| self.next_thread_id.fetch_add(1, Ordering::SeqCst))
            .value()
            .to_owned();

        let is_ddl = analysis.overall_class == SqlStatementClass::Ddl || analysis.has_ddl;
        let conn_arc = Arc::clone(&self.engine_conn);
        let default_schema = self.config.default_schema.clone();
        let active_threads = Arc::clone(&self.active_threads);
        let cancelled_map = Arc::clone(&self.cancelled_executions);

        tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("MySqlAdapter engine lock poisoned".to_string())
            })?;

            if cancelled_map.contains_key(&request.execution_id) {
                active_threads.remove(&request.execution_id);
                return Err(DbMcpError::ExecutionCancelled(format!(
                    "MySQL execution '{}' cancelled",
                    request.execution_id
                )));
            }

            let rewritten_sql = rewrite_mysql_sql_for_embedded(&request.sql, &default_schema);
            let params: Vec<SqliteValue> = request.params.iter().map(json_to_sqlite_param).collect();
            let max_rows = if request.max_rows == 0 {
                usize::MAX
            } else {
                request.max_rows
            };
            let max_bytes = request.max_bytes;

            let mut warnings = Vec::new();
            if is_ddl {
                warnings.push(MYSQL_NON_TRANSACTIONAL_DDL_WARNING.to_string());
            }

            let mut stmt = guard.prepare(&rewritten_sql).map_err(|e| {
                DbMcpError::AdapterError(redact_sensitive_text(&e.to_string()))
            })?;
            let col_count = stmt.column_count();

            let outcome = if col_count > 0 {
                let mut columns: Vec<ColumnMetadata> = stmt
                    .column_names()
                    .into_iter()
                    .map(|n| ColumnMetadata::new(n, "varchar"))
                    .collect();
                let mut rows_out = Vec::new();
                let mut bytes_used = 0usize;
                let mut truncated = false;

                let mut rows = stmt
                    .query(params_from_iter(params.iter()))
                    .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

                while let Some(row) = rows
                    .next()
                    .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?
                {
                    if rows_out.len() >= max_rows {
                        truncated = true;
                        warnings.push(format!("Result truncated at max_rows={max_rows}"));
                        break;
                    }
                    let mut vals = Vec::with_capacity(col_count);
                    let mut row_bytes = 0usize;
                    for i in 0..col_count {
                        let vref = row.get_ref(i).map_err(|e| {
                            DbMcpError::AdapterError(redact_sensitive_text(&e.to_string()))
                        })?;
                        let (jval, ty, b) = value_ref_to_mysql_json(vref);
                        if columns[i].data_type == "varchar" && ty != "null" {
                            columns[i].data_type = ty.to_string();
                        }
                        row_bytes += b;
                        vals.push(jval);
                    }
                    if max_bytes > 0 && bytes_used + row_bytes > max_bytes && !rows_out.is_empty()
                    {
                        truncated = true;
                        warnings.push(format!("Result truncated at max_bytes={max_bytes}"));
                        break;
                    }
                    bytes_used += row_bytes;
                    rows_out.push(vals);
                }
                drop(rows);
                drop(stmt);

                let schema_version = introspect_embedded_mysql_catalog(&guard, &default_schema)
                    .ok()
                    .map(|objs| compute_schema_version(&objs));

                let returned_rows = rows_out.len();
                Ok(QueryResult {
                    execution_id: request.execution_id.clone(),
                    columns,
                    rows: rows_out,
                    returned_rows,
                    rows_affected: None,
                    truncated,
                    bytes_used,
                    execution_time_ms: started.elapsed().as_millis() as u64,
                    warnings,
                    schema_version,
                })
            } else {
                drop(stmt);
                let changed = guard
                    .execute(&rewritten_sql, params_from_iter(params.iter()))
                    .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

                let schema_version = introspect_embedded_mysql_catalog(&guard, &default_schema)
                    .ok()
                    .map(|objs| compute_schema_version(&objs));

                Ok(QueryResult {
                    execution_id: request.execution_id.clone(),
                    columns: Vec::new(),
                    rows: Vec::new(),
                    returned_rows: 0,
                    rows_affected: Some(changed as u64),
                    truncated: false,
                    bytes_used: 0,
                    execution_time_ms: started.elapsed().as_millis() as u64,
                    warnings,
                    schema_version,
                })
            };

            active_threads.remove(&request.execution_id);
            outcome
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("MySQL execute join error: {e}")))?
    }

    async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
        if let Some(live) = &self.live {
            return live.explain(&request).await;
        }
        self.ensure_connectivity().await?;

        let stmts = split_sql_statements(DatabaseEngine::MySql, &request.sql);
        if stmts.len() != 1 {
            return Err(DbMcpError::InvalidArgument(
                "explain_query requires a single SQL statement".to_string(),
            ));
        }

        let trimmed = stmts[0].trim();
        if trimmed.to_ascii_uppercase().starts_with("EXPLAIN") {
            return Err(DbMcpError::InvalidArgument(
                "SQL passed to explain_query must not already start with EXPLAIN".to_string(),
            ));
        }

        let analysis = parse_and_analyze_sql(DatabaseEngine::MySql, trimmed)?;
        if analysis.overall_class.is_mutating() || analysis.has_privileged_functions {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "explain_query only permits read-only SQL statements".to_string(),
                next_action: None,
            });
        }

        let all_objects = self.collect_all_catalog_objects().await?;
        let base_tbl = analysis
            .referenced_tables
            .first()
            .map(|t| t.rsplit('.').next().unwrap_or(t).to_string())
            .unwrap_or_else(|| "dual".to_string());

        let matching_table = all_objects.iter().find(|o| {
            o.object_type == CatalogObjectType::Table && o.name.eq_ignore_ascii_case(&base_tbl)
        });

        let table_preds: Vec<String> = analysis
            .predicates
            .iter()
            .filter(|p| {
                p.operator != PredicateOperator::OrderBy
                    && p.operator != PredicateOperator::GroupBy
            })
            .map(|p| p.column.to_ascii_lowercase())
            .collect();

        let matched_index = matching_table.and_then(|tbl| {
            if let Some(idx) = tbl.indexes.iter().find(|idx| {
                idx.columns
                    .first()
                    .map(|c| table_preds.contains(&c.to_ascii_lowercase()))
                    .unwrap_or(false)
            }) {
                return Some(idx.name.clone());
            }
            if tbl
                .columns
                .iter()
                .any(|c| c.is_primary_key && table_preds.contains(&c.name.to_ascii_lowercase()))
            {
                return Some("PRIMARY".to_string());
            }
            None
        });

        let est_rows = matching_table
            .and_then(|t| t.estimated_rows)
            .unwrap_or(200)
            .max(1) as f64;

        let explain_json = if let Some(idx_name) = matched_index {
            let rows_examined = (est_rows * 0.1).max(1.0).round();
            serde_json::json!({
                "query_block": {
                    "select_id": 1,
                    "cost_info": {
                        "query_cost": "1.20"
                    },
                    "table": {
                        "table_name": base_tbl,
                        "access_type": "ref",
                        "possible_keys": [idx_name],
                        "key": idx_name,
                        "rows_examined_per_scan": rows_examined,
                        "filtered": "100.00"
                    }
                }
            })
        } else {
            let cost_str = format!("{:.2}", est_rows * 0.25 + 5.0);
            serde_json::json!({
                "query_block": {
                    "select_id": 1,
                    "cost_info": {
                        "query_cost": cost_str
                    },
                    "table": {
                        "table_name": base_tbl,
                        "access_type": "ALL",
                        "rows_examined_per_scan": est_rows,
                        "filtered": "10.00"
                    }
                }
            })
        };

        let raw_json_str =
            serde_json::to_string_pretty(&explain_json).unwrap_or_else(|_| "{}".to_string());
        let parsed = parse_mysql_explain_json(&raw_json_str)?;

        let raw_plan = match request.format {
            ExplainFormat::Json => raw_json_str,
            ExplainFormat::Text => {
                if !parsed.seq_scans.is_empty() {
                    format!(
                        "id=1 select_type=SIMPLE table={} type=ALL key=NULL rows={:.0}",
                        base_tbl,
                        parsed.rows_examined.unwrap_or(100.0)
                    )
                } else {
                    format!(
                        "id=1 select_type=SIMPLE table={} type=ref key={} rows={:.0}",
                        base_tbl,
                        parsed.index_scans.first().map(String::as_str).unwrap_or("PRIMARY"),
                        parsed.rows_examined.unwrap_or(1.0)
                    )
                }
            }
        };

        Ok(ExplainPlan {
            connection: request.connection,
            sql: request.sql,
            analyze: request.analyze,
            format: request.format,
            raw_plan,
            structured_plan: Some(parsed.structured_plan),
            estimated_cost: parsed.query_cost,
            estimated_rows: parsed.rows_examined,
            seq_scans: parsed.seq_scans,
            index_scans: parsed.index_scans,
            warnings: parsed.warnings,
        })
    }

    async fn cancel(&self, execution: ExecutionId) -> DbMcpResult<bool> {
        if let Some(live) = &self.live {
            let killed = live.cancel(&execution).await?;
            if let Some(thread_id) = killed {
                if let Ok(mut threads) = self.killed_threads.lock() {
                    threads.push(u64::from(thread_id));
                }
                if let Ok(mut log) = self.kill_query_log.lock() {
                    log.push(build_mysql_kill_query(u64::from(thread_id)));
                }
            }
            return Ok(killed.is_some());
        }
        self.cancelled_executions
            .insert(execution.clone(), Utc::now());
        let thread_id = self
            .active_threads
            .remove(&execution)
            .map(|(_, t)| t)
            .unwrap_or_else(|| self.next_thread_id.fetch_add(1, Ordering::SeqCst));

        let kill_sql = build_mysql_kill_query(thread_id);
        if let Ok(mut threads) = self.killed_threads.lock() {
            threads.push(thread_id);
        }
        if let Ok(mut log) = self.kill_query_log.lock() {
            log.push(kill_sql);
        }
        Ok(true)
    }
}

#[async_trait]
impl SchemaDiffProvider for MySqlAdapter {
    async fn capture_schema(
        &self,
        connection: &str,
        schema_pattern: Option<String>,
    ) -> DbMcpResult<SchemaSnapshot> {
        self.refresh_catalog().await?;
        let req = CatalogRequest {
            connection: connection.to_string(),
            schema_pattern,
            name_pattern: None,
            object_types: Vec::new(),
            detail_level: CatalogDetailLevel::Full,
            limit: 10_000,
            offset: 0,
        };
        let resp = self.discover(req).await?;
        Ok(build_schema_snapshot(
            connection,
            DatabaseEngine::MySql,
            resp.objects,
        ))
    }

    async fn diff_schema(
        &self,
        base: &SchemaSnapshot,
        target: &SchemaSnapshot,
    ) -> DbMcpResult<SchemaDiff> {
        Ok(compute_schema_diff(base, target))
    }
}

#[async_trait]
impl TransactionalDdlProvider for MySqlAdapter {
    fn supports_transactional_ddl(&self) -> bool {
        false
    }

    async fn execute_transactional_ddl(&self, _request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        Err(DbMcpError::UnsupportedCapability(
            MYSQL_NON_TRANSACTIONAL_DDL_WARNING.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{CallerIdentity, DiffOperationKind, ExecutionLimits, ReversalSafety};

    const MYSQL_SEED: &str = r#"
        CREATE TABLE customers (
            id BIGINT PRIMARY KEY,
            email VARCHAR(255) NOT NULL UNIQUE,
            tier VARCHAR(32) NOT NULL DEFAULT 'standard'
        );
        CREATE TABLE invoices (
            id BIGINT PRIMARY KEY,
            customer_id BIGINT NOT NULL REFERENCES customers(id),
            status VARCHAR(32) NOT NULL,
            amount_cents BIGINT NOT NULL
        );
        CREATE INDEX idx_invoices_customer_id ON invoices(customer_id);

        INSERT INTO customers (id, email, tier) VALUES
            (1, 'alice@example.com', 'enterprise'),
            (2, 'bob@example.com', 'standard');
        INSERT INTO invoices (id, customer_id, status, amount_cents) VALUES
            (9001, 1, 'paid', 25000),
            (9002, 2, 'open', 5000);
    "#;

    #[tokio::test]
    async fn test_mysql_capabilities_and_information_schema_discovery() {
        let adapter = MySqlAdapter::simulated_with_seed("mysql-app", MYSQL_SEED).unwrap();
        let caps = adapter.capabilities();
        assert_eq!(caps.engine, DatabaseEngine::MySql);
        assert!(!caps.supports_transactional_ddl);
        assert!(!caps.supports_hypothetical_indexes);
        assert!(caps.unavailable_reasons.contains_key("transactional_ddl"));

        let disc = adapter
            .discover(CatalogRequest {
                connection: "mysql-app".to_string(),
                schema_pattern: Some("app".to_string()),
                name_pattern: None,
                object_types: vec![CatalogObjectType::Table],
                detail_level: CatalogDetailLevel::Full,
                limit: 10,
                offset: 0,
            })
            .await
            .unwrap();
        assert_eq!(disc.total_count, 2);

        let q = AuthorizedQuery::new_read(
            "req_my_1",
            "mysql-app",
            CallerIdentity::local_agent("agent"),
            "SELECT id, amount_cents FROM invoices WHERE customer_id = ?",
            vec![serde_json::json!(1)],
            &ExecutionLimits::default(),
        );
        let res = adapter.execute(q).await.unwrap();
        assert_eq!(res.returned_rows, 1);
        assert_eq!(res.rows[0][0], serde_json::json!(9001));
    }

    #[tokio::test]
    async fn test_mysql_explain_json_and_kill_query_cancellation() {
        let adapter = MySqlAdapter::simulated_with_seed("mysql-app", MYSQL_SEED).unwrap();

        // Indexed query -> access_type=ref
        let idx_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_my_exp_1".to_string(),
                connection: "mysql-app".to_string(),
                sql: "SELECT * FROM invoices WHERE customer_id = 1".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(idx_plan
            .index_scans
            .contains(&"idx_invoices_customer_id".to_string()));
        assert!(idx_plan.seq_scans.is_empty());

        // Full table scan -> access_type=ALL
        let seq_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_my_exp_2".to_string(),
                connection: "mysql-app".to_string(),
                sql: "SELECT * FROM invoices WHERE status = 'open'".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(seq_plan.seq_scans.contains(&"invoices".to_string()));
        assert!(!seq_plan.warnings.is_empty());

        // Cancel via KILL QUERY <thread_id>
        let exec_id = ExecutionId::new();
        adapter.register_thread_id(exec_id.clone(), 4242);
        let ok = adapter.cancel(exec_id).await.unwrap();
        assert!(ok);
        assert_eq!(adapter.killed_threads(), vec![4242]);
        assert_eq!(
            adapter.kill_query_log(),
            vec!["KILL QUERY 4242;".to_string()]
        );
    }

    #[tokio::test]
    async fn test_mysql_non_transactional_ddl_warnings_and_diff() {
        let adapter = MySqlAdapter::simulated_with_seed("mysql-app", MYSQL_SEED).unwrap();
        assert!(!adapter.supports_transactional_ddl());

        let snap_before = adapter.capture_schema("mysql-app", None).await.unwrap();

        let ddl_req = AuthorizedQuery {
            request_id: "req_my_ddl".to_string(),
            execution_id: ExecutionId::new(),
            connection: "mysql-app".to_string(),
            caller: CallerIdentity::admin("dba"),
            sql: "CREATE INDEX idx_invoices_status ON invoices(status)".to_string(),
            normalized_sql: "CREATE INDEX idx_invoices_status ON invoices(status)".to_string(),
            sql_hash: "h".to_string(),
            params: vec![],
            statement_class: SqlStatementClass::Ddl,
            read_only: false,
            timeout_ms: 5_000,
            max_rows: 100,
            max_bytes: 102400,
            change_id: Some("chg_mysql_1".to_string()),
        };

        // TransactionalDdlProvider::execute_transactional_ddl must fail with UNSUPPORTED_CAPABILITY
        let tx_ddl_err = adapter
            .execute_transactional_ddl(ddl_req.clone())
            .await
            .unwrap_err();
        assert_eq!(tx_ddl_err.code(), "UNSUPPORTED_CAPABILITY");

        // Standard execute of DDL emits non-transactional warning
        let ddl_res = adapter.execute(ddl_req).await.unwrap();
        assert!(ddl_res
            .warnings
            .iter()
            .any(|w| w.contains("supports_transactional_ddl=false")));

        let snap_after = adapter.capture_schema("mysql-app", None).await.unwrap();
        let diff = adapter.diff_schema(&snap_before, &snap_after).await.unwrap();
        assert!(!diff.is_identical);
        assert!(!diff.all_transactional);
        assert!(diff.items.iter().any(|i| {
            i.kind == DiffOperationKind::AddIndex
                && !i.transactional
                && i.reversal_safety == ReversalSafety::CompensatingMigrationRequired
        }));
    }

    #[tokio::test]
    async fn test_mysql_routines_bootstrap_and_custom_ddl_interception() {
        let query_sql = build_information_schema_routines_query(Some("app"));
        assert!(query_sql.contains("information_schema.ROUTINES"));
        assert!(query_sql.contains("ROUTINE_DEFINITION"));

        let adapter = MySqlAdapter::simulated_with_seed("mysql-app", MYSQL_SEED).unwrap();
        let none = adapter
            .discover(CatalogRequest {
                connection: "mysql-app".to_string(),
                schema_pattern: Some("app".to_string()),
                name_pattern: None,
                object_types: vec![CatalogObjectType::Procedure, CatalogObjectType::Function],
                detail_level: CatalogDetailLevel::Full,
                limit: 20,
                offset: 0,
            })
            .await
            .unwrap();
        assert!(none.objects.is_empty(), "no phantom routines without init_sql DDL");
        adapter
            .execute_batch(
                r#"
                DELIMITER //
                CREATE PROCEDURE record_order_audit(IN order_id BIGINT, IN event_type VARCHAR(64))
                BEGIN
                    INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (order_id, event_type, NOW());
                END //
                CREATE PROCEDURE reserve_inventory(IN order_id BIGINT)
                BEGIN
                    CALL record_order_audit(order_id, 'INVENTORY_RESERVED');
                END //
                CREATE FUNCTION calculate_order_discount(order_id BIGINT)
                RETURNS DECIMAL(10, 2)
                BEGIN
                    RETURN (SELECT o.total_cents * 0.10 FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = order_id);
                END //
                CREATE PROCEDURE checkout_order(IN order_id BIGINT)
                BEGIN
                    SELECT calculate_order_discount(order_id);
                    CALL reserve_inventory(order_id);
                    CALL record_order_audit(order_id, 'ORDER_CHECKED_OUT');
                END //
                DELIMITER ;
                CREATE PROCEDURE app.archive_paid_invoices(IN cutoff_days INT)
                BEGIN
                    CALL record_order_audit(cutoff_days, 'INVOICES_ARCHIVED');
                END;
                "#,
            )
            .unwrap();

        let routines = adapter
            .discover(CatalogRequest {
                connection: "mysql-app".to_string(),
                schema_pattern: Some("app".to_string()),
                name_pattern: None,
                object_types: vec![CatalogObjectType::Procedure, CatalogObjectType::Function],
                detail_level: CatalogDetailLevel::Full,
                limit: 20,
                offset: 0,
            })
            .await
            .unwrap();

        let names: Vec<&str> = routines.objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"checkout_order"));
        assert!(names.contains(&"reserve_inventory"));
        assert!(names.contains(&"record_order_audit"));
        assert!(names.contains(&"calculate_order_discount"));
        assert!(names.contains(&"archive_paid_invoices"));

        let discount_fn = routines
            .objects
            .iter()
            .find(|o| o.name == "calculate_order_discount")
            .unwrap();
        assert_eq!(discount_fn.object_type, CatalogObjectType::Function);
        assert!(discount_fn.definition.as_deref().unwrap().contains("JOIN users"));

        let checkout_proc = routines
            .objects
            .iter()
            .find(|o| o.name == "checkout_order")
            .unwrap();
        assert_eq!(checkout_proc.object_type, CatalogObjectType::Procedure);
        let def = checkout_proc.definition.as_deref().unwrap();
        assert!(def.contains("CALL reserve_inventory(order_id)"));
        assert!(def.contains("CALL record_order_audit(order_id, 'ORDER_CHECKED_OUT')"));
    }

    #[test]
    fn test_delimiter_blocks_are_normalized() {
        let sql = "CREATE TABLE t (a INT);
DELIMITER //
CREATE PROCEDURE p(IN x INT)
BEGIN
    INSERT INTO t VALUES (x);
END //
DELIMITER ;
INSERT INTO t VALUES (1);
";
        let out = normalize_mysql_delimiters(sql);
        assert!(!out.to_ascii_uppercase().contains("DELIMITER"), "{out}");
        assert!(!out.contains("//"), "{out}");
        assert!(out.contains("END ;"), "{out}");
        let adapter = MySqlAdapter::simulated_with_seed("m", sql).unwrap();
        adapter.execute_batch("SELECT 1;").unwrap();
    }

    fn live_adapter(var: &str) -> Option<MySqlAdapter> {
        let dsn = std::env::var(var).ok().filter(|v| !v.trim().is_empty());
        let Some(dsn) = dsn else {
            eprintln!("skipped: {var} not set (run `eval \"$(bash scripts/live-db-up.sh mysql)\"`)");
            return None;
        };
        Some(MySqlAdapter::new(MySqlConfig::new("live", dsn).with_read_only(true)).unwrap())
    }

    fn catalog_req(types: Vec<CatalogObjectType>) -> CatalogRequest {
        CatalogRequest {
            connection: "live".to_string(),
            schema_pattern: None,
            name_pattern: None,
            object_types: types,
            detail_level: CatalogDetailLevel::Full,
            limit: 1000,
            offset: 0,
        }
    }

    #[tokio::test]
    async fn live_catalog_discovery_and_explain() {
        let Some(adapter) = live_adapter("DB_MCP_MYSQL_TEST_DSN") else { return };
        assert!(!adapter.is_simulated());
        assert!(adapter.capabilities().supports_health_diagnostics);
        let resp = adapter.discover(catalog_req(vec![CatalogObjectType::Table, CatalogObjectType::View])).await.unwrap();
        let names: Vec<&str> = resp.objects.iter().map(|o| o.name.as_str()).collect();
        for t in ["users", "orders", "order_items", "inventory", "audit_logs", "internal_secrets", "active_user_orders"] {
            assert!(names.contains(&t), "{t} missing from {names:?}");
        }
        assert!(resp.schema_version.as_deref().unwrap().starts_with("snapshot_"));
        let orders = resp.objects.iter().find(|o| o.name == "orders").unwrap();
        assert_eq!(orders.schema, "appdb");
        assert!(orders.foreign_keys.iter().any(|f| f.referenced_table == "users" && f.columns == vec!["user_id"]));
        assert!(orders.indexes.iter().any(|i| i.name == "idx_orders_status_created" && i.columns == vec!["status", "created_at"]));
        let view = resp.objects.iter().find(|o| o.name == "active_user_orders").unwrap();
        assert!(view.definition.as_deref().unwrap().contains("`appdb`.`orders`"));
        // The minimal login cannot see routines; the catalog says so instead of failing.
        let warnings = adapter.live().unwrap().catalog_warnings();
        assert!(warnings.iter().any(|w| w.contains("SHOW_ROUTINE")), "{warnings:?}");

        let described = adapter.describe_object(Some("appdb"), "users", CatalogDetailLevel::Full).await.unwrap();
        assert!(described.columns.iter().any(|c| c.name == "password_hash"));

        let plan = adapter
            .explain(ExplainRequest {
                request_id: "e1".to_string(),
                connection: "live".to_string(),
                sql: "SELECT * FROM orders WHERE total_cents > ?".to_string(),
                params: vec![serde_json::json!(1000)],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert_eq!(plan.seq_scans, vec!["orders".to_string()], "{plan:?}");
        assert!(plan.estimated_cost.is_some());
        let plan = adapter
            .explain(ExplainRequest {
                request_id: "e2".to_string(),
                connection: "live".to_string(),
                sql: "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id WHERE o.user_id = 1".to_string(),
                params: vec![],
                analyze: true,
                format: ExplainFormat::Text,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(plan.raw_plan.contains("actual time"), "{}", plan.raw_plan);
        assert!(!plan.index_scans.is_empty(), "{plan:?}");
        let err = adapter
            .explain(ExplainRequest {
                request_id: "e3".to_string(),
                connection: "live".to_string(),
                sql: "SELECT * FROM no_such_table".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "ADAPTER_ERROR");
        let err = adapter
            .explain(ExplainRequest {
                request_id: "e4".to_string(),
                connection: "live".to_string(),
                sql: "DELETE FROM orders".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), "READONLY_VIOLATION");

        let snap = adapter.capture_schema("live", None).await.unwrap();
        let q = AuthorizedQuery::new_read(
            "r",
            "live",
            CallerIdentity::local_agent("t"),
            "SELECT COUNT(*) FROM orders",
            vec![],
            &ExecutionLimits::default(),
        );
        let res = adapter.execute(q).await.unwrap();
        assert_eq!(res.schema_version.as_deref(), Some(snap.schema_version.as_str()));
    }

    #[tokio::test]
    async fn live_catalog_with_show_routine_lists_routines() {
        let Some(adapter) = live_adapter("DB_MCP_MYSQL_TEST_DSN_DIAG") else { return };
        let resp = adapter
            .discover(catalog_req(vec![CatalogObjectType::Procedure, CatalogObjectType::Function]))
            .await
            .unwrap();
        let checkout = resp.objects.iter().find(|o| o.name == "checkout_order").expect("checkout_order");
        let def = checkout.definition.as_deref().unwrap();
        assert!(def.starts_with("CREATE PROCEDURE `appdb`.`checkout_order`(IN p_order_id bigint)"), "{def}");
        assert!(def.contains("CALL reserve_inventory"));
        let f = resp.objects.iter().find(|o| o.name == "calculate_order_discount").unwrap();
        assert_eq!(f.object_type, CatalogObjectType::Function);
        assert!(f.definition.as_deref().unwrap().contains("RETURNS decimal(12,2)"));
        assert!(!adapter.live().unwrap().catalog_warnings().iter().any(|w| w.contains("SHOW_ROUTINE")));
    }

    #[tokio::test]
    async fn live_diagnostics_degrade_without_grants_and_use_them_when_granted() {
        let Some(ro) = live_adapter("DB_MCP_MYSQL_TEST_DSN") else { return };
        let live = ro.live().unwrap().clone();
        let objects = ro.collect_all_catalog_objects().await.unwrap();
        let report = live.database_health(&objects).await.unwrap();
        let ids: Vec<&str> = report.findings.iter().map(|f| f.check_id.as_str()).collect();
        assert!(ids.contains(&"tables_without_primary_key") && ids.contains(&"redundant_indexes"), "{ids:?}");
        assert!(ids.contains(&"process_visibility") && ids.contains(&"workload_visibility"), "{ids:?}");
        assert!(report.active_connections.is_some() && report.max_connections.is_some());
        let no_pk = report.findings.iter().find(|f| f.check_id == "tables_without_primary_key").unwrap();
        assert!(no_pk.evidence.to_string().contains("event_log_nopk"));
        let w = live.analyze_workload(10).await.unwrap();
        assert!(w.unwrap_err().contains("GRANT SELECT ON performance_schema"));

        let Some(diag) = live_adapter("DB_MCP_MYSQL_TEST_DSN_DIAG") else { return };
        let q = AuthorizedQuery::new_read(
            "r",
            "live",
            CallerIdentity::local_agent("t"),
            "SELECT id, total_cents FROM orders WHERE total_cents > 1000",
            vec![],
            &ExecutionLimits::default(),
        );
        diag.execute(q).await.unwrap();
        let live = diag.live().unwrap().clone();
        let w = live.analyze_workload(20).await.unwrap().expect("digests readable with the grant");
        assert_eq!(w.source, "performance_schema.events_statements_summary_by_digest");
        assert!(w.top_queries.iter().any(|q| q.normalized_query.to_ascii_lowercase().contains("total_cents")), "{:?}", w.top_queries);
        assert!(!w.top_queries.iter().any(|q| q.normalized_query.to_ascii_lowercase().contains("information_schema")));
        let objects = diag.collect_all_catalog_objects().await.unwrap();
        let report = live.database_health(&objects).await.unwrap();
        assert!(!report.findings.iter().any(|f| f.check_id == "process_visibility" || f.check_id == "workload_visibility"));
    }

    #[test]
    fn test_no_phantom_routines_seeded() {
        let adapter = MySqlAdapter::simulated("m").unwrap();
        let guard = adapter.engine_conn.lock().unwrap();
        let n: i64 = guard
            .query_row("SELECT COUNT(*) FROM __mysql_routines", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }
}
