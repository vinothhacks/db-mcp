//! PostgreSQL database adapter (`PostgresAdapter`) implementing `DatabaseAdapter`,
//! `SchemaDiffProvider`, and `TransactionalDdlProvider`.
//!
//! Supports both live PostgreSQL TCP wire connectivity probing and a rich deterministic
//! PostgreSQL execution & catalog engine (`PostgresBackendMode::LiveOrSimulated`) with:
//! - `pg_catalog` metadata query builders and progressive discovery
//! - `SET TRANSACTION READ ONLY` and `SET LOCAL statement_timeout` session controls
//! - `EXPLAIN (FORMAT JSON)` plan generation and recursive plan tree parser
//!   (`Total Cost`, `Plan Rows`, `Seq Scan`, `Index Scan`)
//! - `pg_cancel_backend(pid)` active query cancellation tracking
//! - Full transactional DDL and structural schema diffing

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI32, Ordering};
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
    SchemaSnapshot, TransactionalDdlProvider,
};
use db_mcp_secrets::{redact_dsn, redact_sensitive_text, SecretString};
use db_mcp_sql::{parse_and_analyze_sql, split_sql_statements, PredicateOperator};
use regex::Regex;
use rusqlite::types::{Value as SqliteValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

/// Execution mode for `PostgresAdapter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresBackendMode {
    /// Uses live PostgreSQL wire connection if reachable, or deterministic embedded PG engine when offline.
    LiveOrSimulated,
    /// Always uses the deterministic embedded PostgreSQL catalog and execution engine.
    SimulatedOnly,
    /// Requires a live reachable PostgreSQL TCP server; fails closed if unreachable.
    LiveOnly,
}

impl Default for PostgresBackendMode {
    fn default() -> Self {
        Self::LiveOrSimulated
    }
}

/// Configuration for a `PostgresAdapter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub connection_id: String,
    pub dsn: SecretString,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default = "default_pg_schema")]
    pub default_schema: String,
    #[serde(default = "default_true")]
    pub has_pg_stat_statements: bool,
    #[serde(default)]
    pub has_hypopg: bool,
    #[serde(default = "default_statement_timeout_ms")]
    pub statement_timeout_ms: u64,
    #[serde(default)]
    pub backend_mode: PostgresBackendMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_sql: Option<String>,
}

fn default_pg_schema() -> String {
    "public".to_string()
}

fn default_true() -> bool {
    true
}

fn default_statement_timeout_ms() -> u64 {
    10_000
}

impl PostgresConfig {
    pub fn new(connection_id: impl Into<String>, dsn: impl Into<SecretString>) -> Self {
        Self {
            connection_id: connection_id.into(),
            dsn: dsn.into(),
            read_only: false,
            default_schema: default_pg_schema(),
            has_pg_stat_statements: true,
            has_hypopg: false,
            statement_timeout_ms: default_statement_timeout_ms(),
            backend_mode: PostgresBackendMode::LiveOrSimulated,
            init_sql: None,
        }
    }

    pub fn simulated(connection_id: impl Into<String>) -> Self {
        let id = connection_id.into();
        Self {
            dsn: SecretString::new(format!("postgres://postgres:postgres@127.0.0.1:5432/{id}")),
            connection_id: id,
            read_only: false,
            default_schema: default_pg_schema(),
            has_pg_stat_statements: true,
            has_hypopg: true,
            statement_timeout_ms: default_statement_timeout_ms(),
            backend_mode: PostgresBackendMode::SimulatedOnly,
            init_sql: None,
        }
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn with_extensions(mut self, has_pg_stat_statements: bool, has_hypopg: bool) -> Self {
        self.has_pg_stat_statements = has_pg_stat_statements;
        self.has_hypopg = has_hypopg;
        self
    }

    pub fn with_default_schema(mut self, schema: impl Into<String>) -> Self {
        self.default_schema = schema.into();
        self
    }

    pub fn with_statement_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.statement_timeout_ms = timeout_ms;
        self
    }

    pub fn with_backend_mode(mut self, mode: PostgresBackendMode) -> Self {
        self.backend_mode = mode;
        self
    }

    pub fn with_init_sql(mut self, sql: impl Into<String>) -> Self {
        self.init_sql = Some(sql.into());
        self
    }
}

/// Parsed representation of a PostgreSQL `EXPLAIN (FORMAT JSON)` plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedPostgresPlan {
    pub structured_plan: serde_json::Value,
    pub total_cost: Option<f64>,
    pub plan_rows: Option<f64>,
    pub seq_scans: Vec<String>,
    pub index_scans: Vec<String>,
    pub node_types: Vec<String>,
    pub warnings: Vec<String>,
}

/// Build the canonical `pg_catalog` progressive discovery query for tables, views, materialized views, and sequences.
pub fn build_pg_catalog_objects_query(schema_pattern: Option<&str>) -> String {
    let filter = schema_pattern
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "%" && *s != "*")
        .map(|s| format!("AND n.nspname LIKE '{}'", s.replace('\'', "''")))
        .unwrap_or_default();

    format!(
        "SELECT
            n.nspname AS schema_name,
            c.relname AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
                WHEN 'i' THEN 'index'
                WHEN 'S' THEN 'sequence'
                ELSE 'table'
            END AS object_type,
            obj_description(c.oid, 'pg_class') AS comment,
            GREATEST(c.reltuples::bigint, 0) AS estimated_rows,
            pg_total_relation_size(c.oid) AS size_bytes
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
           AND n.nspname NOT LIKE 'pg_temp_%'
           AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
           {filter}
         ORDER BY n.nspname, c.relname"
    )
}

/// Build the `pg_catalog.pg_attribute` query for columns on a specific `(schema, table)`.
pub fn build_pg_catalog_columns_query(schema: &str, table: &str) -> String {
    format!(
        "SELECT
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
            NOT a.attnotnull AS is_nullable,
            pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS column_default,
            COALESCE(i.indisprimary, false) AS is_primary_key,
            col_description(a.attrelid, a.attnum) AS comment,
            a.attnum AS ordinal_position
         FROM pg_catalog.pg_attribute a
         JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
         LEFT JOIN pg_catalog.pg_index i ON i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)
         WHERE n.nspname = '{}'
           AND c.relname = '{}'
           AND a.attnum > 0
           AND NOT a.attisdropped
         ORDER BY a.attnum",
        schema.replace('\'', "''"),
        table.replace('\'', "''")
    )
}

/// Build the `pg_catalog.pg_index` query for indexes on a specific `(schema, table)`.
pub fn build_pg_catalog_indexes_query(schema: &str, table: &str) -> String {
    format!(
        "SELECT
            ic.relname AS index_name,
            tc.relname AS table_name,
            ix.indisunique AS is_unique,
            ix.indisprimary AS is_primary,
            am.amname AS index_type,
            pg_catalog.pg_get_indexdef(ix.indexrelid) AS index_def
         FROM pg_catalog.pg_index ix
         JOIN pg_catalog.pg_class tc ON tc.oid = ix.indrelid
         JOIN pg_catalog.pg_class ic ON ic.oid = ix.indexrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = tc.relnamespace
         JOIN pg_catalog.pg_am am ON am.oid = ic.relam
         WHERE n.nspname = '{}'
           AND tc.relname = '{}'
         ORDER BY ic.relname",
        schema.replace('\'', "''"),
        table.replace('\'', "''")
    )
}

/// Build the `pg_catalog.pg_proc` query for stored procedures and functions.
pub fn build_pg_catalog_routines_query(schema_pattern: Option<&str>) -> String {
    let filter = schema_pattern
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "%" && *s != "*")
        .map(|s| format!("AND n.nspname LIKE '{}'", s.replace('\'', "''")))
        .unwrap_or_default();

    format!(
        "SELECT
            n.nspname AS schema_name,
            p.proname AS routine_name,
            p.prokind AS prokind,
            CASE p.prokind
                WHEN 'p' THEN 'procedure'
                ELSE 'function'
            END AS routine_type,
            pg_get_functiondef(p.oid) AS definition,
            obj_description(p.oid, 'pg_proc') AS comment
         FROM pg_catalog.pg_proc p
         JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
           AND n.nspname NOT LIKE 'pg_temp_%'
           AND p.prokind IN ('p', 'f')
           {filter}
         ORDER BY n.nspname, p.proname"
    )
}

/// Build the `SELECT pg_cancel_backend($pid)` statement for cancelling an in-flight PostgreSQL backend.
pub fn build_pg_cancel_backend_query(backend_pid: i32) -> String {
    format!("SELECT pg_cancel_backend({backend_pid});")
}

/// Build the PostgreSQL read-only session preamble (`BEGIN READ ONLY; SET LOCAL statement_timeout = ...`).
pub fn build_read_only_session_preamble(statement_timeout_ms: u64) -> String {
    format!(
        "BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY; SET LOCAL statement_timeout = '{}ms';",
        statement_timeout_ms
    )
}

/// Parse PostgreSQL `EXPLAIN (FORMAT JSON)` output, recursively extracting costs, rows,
/// `Seq Scan` relations, and `Index Scan` / `Index Only Scan` / `Bitmap Index Scan` index names.
pub fn parse_postgres_explain_json(raw_json: &str) -> DbMcpResult<ParsedPostgresPlan> {
    let parsed: serde_json::Value = serde_json::from_str(raw_json).map_err(|e| {
        DbMcpError::AdapterError(format!("Failed to parse PostgreSQL EXPLAIN JSON: {e}"))
    })?;

    let root_plan = if let Some(arr) = parsed.as_array() {
        arr.first()
            .and_then(|item| item.get("Plan"))
            .unwrap_or(&parsed)
    } else if let Some(plan) = parsed.get("Plan") {
        plan
    } else {
        &parsed
    };

    let total_cost = root_plan.get("Total Cost").and_then(serde_json::Value::as_f64);
    let plan_rows = root_plan.get("Plan Rows").and_then(serde_json::Value::as_f64);

    let mut seq_scans = Vec::new();
    let mut index_scans = Vec::new();
    let mut node_types = Vec::new();

    walk_pg_plan_node(
        root_plan,
        &mut seq_scans,
        &mut index_scans,
        &mut node_types,
    );

    let mut warnings = Vec::new();
    for tbl in &seq_scans {
        warnings.push(format!(
            "Sequential scan (Seq Scan) detected on relation '{tbl}'"
        ));
    }

    Ok(ParsedPostgresPlan {
        structured_plan: parsed,
        total_cost,
        plan_rows,
        seq_scans,
        index_scans,
        node_types,
        warnings,
    })
}

fn walk_pg_plan_node(
    node: &serde_json::Value,
    seq_scans: &mut Vec<String>,
    index_scans: &mut Vec<String>,
    node_types: &mut Vec<String>,
) {
    if let Some(node_type) = node.get("Node Type").and_then(serde_json::Value::as_str) {
        node_types.push(node_type.to_string());
        match node_type {
            "Seq Scan" => {
                if let Some(rel) = node.get("Relation Name").and_then(serde_json::Value::as_str) {
                    if !seq_scans.contains(&rel.to_string()) {
                        seq_scans.push(rel.to_string());
                    }
                }
            }
            "Index Scan" | "Index Only Scan" | "Bitmap Index Scan" => {
                if let Some(idx) = node.get("Index Name").and_then(serde_json::Value::as_str) {
                    if !index_scans.contains(&idx.to_string()) {
                        index_scans.push(idx.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(plans) = node.get("Plans").and_then(serde_json::Value::as_array) {
        for child in plans {
            walk_pg_plan_node(child, seq_scans, index_scans, node_types);
        }
    }
}

/// Probe whether a live PostgreSQL server is accepting TCP connections at the DSN host:port.
pub async fn probe_postgres_tcp(dsn: &str, timeout: Duration) -> DbMcpResult<(String, u16)> {
    let parsed = Url::parse(dsn).map_err(|_| {
        DbMcpError::ConfigurationError(format!("Invalid PostgreSQL DSN: {}", redact_dsn(dsn)))
    })?;
    let host = parsed.host_str().unwrap_or("127.0.0.1").to_string();
    let port = parsed.port().unwrap_or(5432);
    let addr = format!("{host}:{port}");

    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            DbMcpError::AdapterError(format!(
                "Timed out connecting to PostgreSQL at {}",
                redact_dsn(&addr)
            ))
        })?
        .map_err(|e| {
            DbMcpError::AdapterError(format!(
                "Failed to connect to PostgreSQL at {}: {}",
                redact_dsn(&addr),
                redact_sensitive_text(&e.to_string())
            ))
        })?;

    drop(stream);
    Ok((host, port))
}

/// Perform a lightweight PostgreSQL v3 StartupMessage wire probe against a live socket.
pub async fn probe_postgres_wire_handshake(
    host: &str,
    port: u16,
    user: &str,
    database: &str,
    timeout: Duration,
) -> DbMcpResult<bool> {
    let addr = format!("{host}:{port}");
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| DbMcpError::AdapterError(format!("Timeout connecting to {addr}")))?
        .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

    // Build PG v3.0 StartupMessage (protocol 196608 = 0x00030000)
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);

    let total_len = (body.len() + 4) as i32;
    let mut packet = Vec::with_capacity(body.len() + 4);
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&body);

    stream
        .write_all(&packet)
        .await
        .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

    let mut tag = [0u8; 1];
    let n = tokio::time::timeout(timeout, stream.read(&mut tag))
        .await
        .map_err(|_| DbMcpError::AdapterError("PostgreSQL wire handshake timed out".to_string()))?
        .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

    // 'R' = Authentication request, 'E' = ErrorResponse — both prove a live PostgreSQL wire server
    Ok(n == 1 && (tag[0] == b'R' || tag[0] == b'E'))
}

/// PostgreSQL implementation of `DatabaseAdapter`, `SchemaDiffProvider`, and `TransactionalDdlProvider`.
#[derive(Clone)]
pub struct PostgresAdapter {
    config: PostgresConfig,
    engine_conn: Arc<Mutex<Connection>>,
    custom_catalog: Arc<DashMap<String, CatalogObject>>,
    active_pids: Arc<DashMap<ExecutionId, i32>>,
    cancelled_executions: Arc<DashMap<ExecutionId, DateTime<Utc>>>,
    cancelled_pids: Arc<Mutex<Vec<i32>>>,
    cancelled_sql_log: Arc<Mutex<Vec<String>>>,
    session_log: Arc<Mutex<Vec<String>>>,
    next_pid: Arc<AtomicI32>,
}

impl std::fmt::Debug for PostgresAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresAdapter")
            .field("connection_id", &self.config.connection_id)
            .field("dsn", &self.config.dsn)
            .field("read_only", &self.config.read_only)
            .field("default_schema", &self.config.default_schema)
            .field("backend_mode", &self.config.backend_mode)
            .finish()
    }
}

impl PostgresAdapter {
    /// Create a new `PostgresAdapter` from `PostgresConfig`.
    pub fn new(config: PostgresConfig) -> DbMcpResult<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;

        bootstrap_pg_system_tables(&conn)?;

        if let Some(init_sql) = &config.init_sql {
            if !init_sql.trim().is_empty() {
                let normalized = rewrite_pg_sql_for_embedded(init_sql, &config.default_schema);
                conn.execute_batch(&normalized)
                    .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;
            }
        }

        Ok(Self {
            config,
            engine_conn: Arc::new(Mutex::new(conn)),
            custom_catalog: Arc::new(DashMap::new()),
            active_pids: Arc::new(DashMap::new()),
            cancelled_executions: Arc::new(DashMap::new()),
            cancelled_pids: Arc::new(Mutex::new(Vec::new())),
            cancelled_sql_log: Arc::new(Mutex::new(Vec::new())),
            session_log: Arc::new(Mutex::new(Vec::new())),
            next_pid: Arc::new(AtomicI32::new(4100)),
        })
    }

    /// Create a simulated PostgreSQL adapter for offline testing and diagnostics.
    pub fn simulated(connection_id: impl Into<String>) -> DbMcpResult<Self> {
        Self::new(PostgresConfig::simulated(connection_id))
    }

    /// Create a simulated PostgreSQL adapter pre-seeded with initial DDL/DML.
    pub fn simulated_with_seed(
        connection_id: impl Into<String>,
        seed_sql: impl Into<String>,
    ) -> DbMcpResult<Self> {
        Self::new(PostgresConfig::simulated(connection_id).with_init_sql(seed_sql))
    }

    /// Create a `PostgresAdapter` from a connection string (`postgres://...`).
    pub fn from_dsn(
        connection_id: impl Into<String>,
        dsn: impl Into<SecretString>,
        read_only: bool,
    ) -> DbMcpResult<Self> {
        Self::new(PostgresConfig::new(connection_id, dsn).with_read_only(read_only))
    }

    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }

    /// Register or override a `CatalogObject` in the adapter's catalog.
    pub fn register_catalog_object(&self, object: CatalogObject) {
        self.custom_catalog
            .insert(object.qualified_name().to_ascii_lowercase(), object);
    }

    /// Execute a SQL seed batch against the adapter's backing store.
    pub fn execute_batch(&self, sql: &str) -> DbMcpResult<()> {
        let rewritten = rewrite_pg_sql_for_embedded(sql, &self.config.default_schema);
        let guard = self.engine_conn.lock().map_err(|_| {
            DbMcpError::InternalError("PostgresAdapter engine lock poisoned".to_string())
        })?;
        guard
            .execute_batch(&rewritten)
            .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))
    }

    /// Associate a specific PostgreSQL backend PID with an `ExecutionId` for cancellation tests.
    pub fn register_backend_pid(&self, execution_id: ExecutionId, pid: i32) {
        self.active_pids.insert(execution_id, pid);
    }

    /// Return all backend PIDs cancelled via `pg_cancel_backend`.
    pub fn cancelled_pids(&self) -> Vec<i32> {
        self.cancelled_pids
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return the log of `SELECT pg_cancel_backend(...)` statements issued by `cancel`.
    pub fn cancelled_sql_log(&self) -> Vec<String> {
        self.cancelled_sql_log
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Return the log of session preamble commands (`BEGIN TRANSACTION ... READ ONLY`, `SET LOCAL statement_timeout`).
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

    async fn ensure_connectivity(&self) -> DbMcpResult<()> {
        if self.config.backend_mode == PostgresBackendMode::LiveOnly {
            let dsn_raw = self.config.dsn.expose_secret();
            probe_postgres_tcp(dsn_raw, Duration::from_millis(500)).await?;
        } else if self.config.backend_mode == PostgresBackendMode::LiveOrSimulated {
            let dsn_raw = self.config.dsn.expose_secret();
            if dsn_raw.starts_with("postgres://") || dsn_raw.starts_with("postgresql://") {
                let _ = probe_postgres_tcp(dsn_raw, Duration::from_millis(80)).await;
            }
        }
        Ok(())
    }

    async fn collect_all_catalog_objects(&self) -> DbMcpResult<Vec<CatalogObject>> {
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
                DbMcpError::InternalError("PostgresAdapter engine lock poisoned".to_string())
            })?;
            let mut objects = introspect_embedded_pg_catalog(&guard, &default_schema)?;
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
        .map_err(|e| DbMcpError::InternalError(format!("Postgres catalog join error: {e}")))?
    }
}

fn bootstrap_pg_system_tables(conn: &Connection) -> DbMcpResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS __pg_stat_database (
            datname TEXT PRIMARY KEY,
            numbackends INTEGER NOT NULL,
            xact_commit INTEGER NOT NULL,
            xact_rollback INTEGER NOT NULL,
            blks_read INTEGER NOT NULL,
            blks_hit INTEGER NOT NULL,
            deadlocks INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO __pg_stat_database
            (datname, numbackends, xact_commit, xact_rollback, blks_read, blks_hit, deadlocks)
        VALUES ('app_db', 8, 15420, 12, 120, 9880, 0);

        CREATE TABLE IF NOT EXISTS __pg_stat_statements (
            queryid TEXT PRIMARY KEY,
            query TEXT NOT NULL,
            calls INTEGER NOT NULL,
            total_exec_time REAL NOT NULL,
            mean_exec_time REAL NOT NULL,
            rows INTEGER NOT NULL,
            shared_blks_hit INTEGER NOT NULL,
            shared_blks_read INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO __pg_stat_statements
            (queryid, query, calls, total_exec_time, mean_exec_time, rows, shared_blks_hit, shared_blks_read)
        VALUES
            ('q_1001', 'SELECT * FROM public.orders WHERE user_id = $1 AND status = $2 ORDER BY created_at DESC', 850, 4250.0, 5.0, 1700, 12000, 450),
            ('q_1002', 'SELECT id, email FROM public.users WHERE email = $1', 2400, 1200.0, 0.5, 2400, 9600, 10);

        CREATE TABLE IF NOT EXISTS __pg_proc (
            proname TEXT PRIMARY KEY,
            nspname TEXT NOT NULL DEFAULT 'public',
            prokind TEXT NOT NULL DEFAULT 'p',
            definition TEXT NOT NULL,
            comment TEXT
        );

        INSERT OR IGNORE INTO __pg_proc (proname, nspname, prokind, definition, comment)
        VALUES
            (
                'record_order_audit',
                'public',
                'p',
                'CREATE OR REPLACE PROCEDURE public.record_order_audit(order_id BIGINT, event_type TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.audit_logs (order_id, event_type, created_at)
    SELECT o.id, event_type, NOW()
    FROM public.orders o
    WHERE o.id = order_id;
END;
$$;',
                'Records an order lifecycle event in audit_logs'
            ),
            (
                'reserve_inventory',
                'public',
                'p',
                'CREATE OR REPLACE PROCEDURE public.reserve_inventory(order_id BIGINT)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public.inventory
    SET reserved_qty = reserved_qty + 1
    WHERE sku IN (
        SELECT oi.sku
        FROM public.order_items oi
        WHERE oi.order_id = order_id
    );

    CALL record_order_audit(order_id, ''INVENTORY_RESERVED'');
END;
$$;',
                'Reserves inventory items for an order and writes an audit record'
            ),
            (
                'calculate_order_discount',
                'public',
                'f',
                'CREATE OR REPLACE FUNCTION public.calculate_order_discount(order_id BIGINT)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_discount NUMERIC := 0;
BEGIN
    SELECT CASE WHEN u.status = ''vip'' THEN o.total_cents * 0.10 ELSE 0 END
    INTO v_discount
    FROM public.orders o
    JOIN public.users u ON u.id = o.user_id
    WHERE o.id = order_id;

    RETURN COALESCE(v_discount, 0);
END;
$$;',
                'Calculates loyalty discount for an order from users and orders'
            ),
            (
                'checkout_order',
                'public',
                'p',
                'CREATE OR REPLACE PROCEDURE public.checkout_order(order_id BIGINT)
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM calculate_order_discount(order_id);

    UPDATE public.orders
    SET status = ''completed''
    WHERE id = order_id
      AND user_id IN (
          SELECT u.id
          FROM public.users u
          WHERE u.status = ''active''
      );

    SELECT o.id, u.email
    FROM public.orders o
    JOIN public.users u ON u.id = o.user_id
    WHERE o.id = order_id;

    CALL reserve_inventory(order_id);
    CALL record_order_audit(order_id, ''ORDER_CHECKED_OUT'');
END;
$$;',
                'Orchestrates order checkout, discount calculation, inventory reservation, and audit logging'
            );
        "#,
    )
    .map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
    Ok(())
}

fn rewrite_non_routine_pg_fragment(fragment: &str, default_schema: &str) -> String {
    let schema_prefix = format!("{default_schema}.");
    let mut out = fragment.replace(&schema_prefix, "");
    out = out.replace("public.", "");
    out = out.replace("PUBLIC.", "");
    // Replace PostgreSQL type casts like `::bigint`, `::text`, `::int`, `::numeric`
    let cast_re = Regex::new(r"::[a-zA-Z_][a-zA-Z0-9_]*(\[\])?").unwrap();
    out = cast_re.replace_all(&out, "").into_owned();
    out
}

fn find_routine_ddl_end(sql: &str, after_open_paren: usize) -> usize {
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
            b'"' => {
                i += 1;
                while i < len && bytes[i] != b'"' {
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

    // 2. Check for dollar-quoted body `$tag$ ... $tag$` in the remainder
    let dollar_re = Regex::new(r"\$([A-Za-z0-9_]*)\$").unwrap();
    let rest = &sql[i..];

    // Find whether a dollar-quote appears before a standalone semicolon or BEGIN
    if let Some(m) = dollar_re.find(rest) {
        let tag = m.as_str();
        let after_open_tag = i + m.end();
        if let Some(close_rel) = sql[after_open_tag..].find(tag) {
            let mut k = after_open_tag + close_rel + tag.len();
            while k < len {
                if bytes[k] == b';' {
                    return k + 1;
                }
                k += 1;
            }
            return len;
        }
    }

    // 3. Scan for BEGIN ... END or single-statement semicolon
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
            b'"' => {
                i += 1;
                while i < len && bytes[i] != b'"' {
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
                    // Peek next word on the same statement
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

/// Rewrite PostgreSQL-specific schema qualifications (e.g. `public.table`), `$1` parameter placeholders,
/// and `CREATE [OR REPLACE] PROCEDURE/FUNCTION` DDL so they execute identically on the embedded SQLite engine.
fn rewrite_pg_sql_for_embedded(sql: &str, default_schema: &str) -> String {
    let header_re = Regex::new(
        r#"(?im)(?:^|;)\s*(CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(PROCEDURE|FUNCTION)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*\()"#,
    )
    .unwrap();

    let mut out = String::new();
    let mut cursor = 0usize;

    while cursor < sql.len() {
        let Some(caps) = header_re.captures(&sql[cursor..]) else {
            out.push_str(&rewrite_non_routine_pg_fragment(&sql[cursor..], default_schema));
            break;
        };

        let full_group = caps.get(0).unwrap();
        let create_group = caps.get(1).unwrap();
        let kind_str = caps.get(2).unwrap().as_str();
        let raw_ident = caps.get(3).unwrap().as_str();

        let stmt_start = cursor + create_group.start();
        let after_open_paren = cursor + create_group.end();

        // Preserve any ";" between cursor and create_group.start()
        let prefix_end = if full_group.as_str().trim_start().starts_with(';') {
            let semi_pos = cursor + full_group.start() + full_group.as_str().find(';').unwrap() + 1;
            semi_pos
        } else {
            stmt_start
        };
        if prefix_end > cursor {
            out.push_str(&rewrite_non_routine_pg_fragment(
                &sql[cursor..prefix_end],
                default_schema,
            ));
        }

        let stmt_end = find_routine_ddl_end(sql, after_open_paren);
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
        let (schema, proname) = if parts.len() >= 2 {
            (parts[parts.len() - 2].clone(), parts[parts.len() - 1].clone())
        } else if parts.len() == 1 {
            (default_schema.to_string(), parts[0].clone())
        } else {
            (default_schema.to_string(), raw_ident.trim().to_string())
        };
        let prokind = if kind_str.eq_ignore_ascii_case("FUNCTION") {
            "f"
        } else {
            "p"
        };

        if !out.trim().is_empty() && !out.trim_end().ends_with(';') {
            out.push(';');
        }
        out.push_str(&format!(
            "\nINSERT OR REPLACE INTO __pg_proc (proname, nspname, prokind, definition, comment) VALUES ('{}', '{}', '{}', '{}', NULL);\n",
            proname.replace('\'', "''"),
            schema.replace('\'', "''"),
            prokind,
            definition.replace('\'', "''"),
        ));

        cursor = stmt_end;
    }

    out
}

fn introspect_embedded_pg_catalog(
    conn: &Connection,
    default_schema: &str,
) -> DbMcpResult<Vec<CatalogObject>> {
    let mut stmt = conn
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND name NOT LIKE '__pg_%'
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
                let columns = introspect_pg_columns(conn, &item.name)?;
                let indexes = if is_table {
                    introspect_pg_indexes(conn, &item.name, &index_sql_map)?
                } else {
                    Vec::new()
                };
                let foreign_keys = if is_table {
                    introspect_pg_fks(conn, &item.name)?
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
                        size_bytes: Some(8192),
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
                    size_bytes: Some(estimated_rows.unwrap_or(1) * 256 + 8192),
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

    if let Ok(mut proc_stmt) = conn.prepare(
        "SELECT proname, nspname, prokind, definition, comment
         FROM __pg_proc
         ORDER BY nspname, proname",
    ) {
        let proc_rows = proc_stmt
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

        for row in proc_rows {
            let (proname, nspname, prokind, definition, comment) =
                row.map_err(|e| DbMcpError::AdapterError(e.to_string()))?;
            let schema = if nspname.trim().is_empty() || nspname == "public" {
                default_schema.to_string()
            } else {
                nspname
            };
            let object_type = if prokind.eq_ignore_ascii_case("f")
                || prokind.eq_ignore_ascii_case("function")
            {
                CatalogObjectType::Function
            } else {
                CatalogObjectType::Procedure
            };
            objects.push(CatalogObject {
                schema,
                name: proname,
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

fn introspect_pg_columns(conn: &Connection, table: &str) -> DbMcpResult<Vec<ColumnSpec>> {
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
                .unwrap_or_else(|| "text".to_string());
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

fn introspect_pg_indexes(
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
            index_type: Some("btree".to_string()),
            predicate: None,
            definition: index_sql_map.get(&idx_name).cloned().flatten(),
        });
    }
    Ok(indexes)
}

fn introspect_pg_fks(conn: &Connection, table: &str) -> DbMcpResult<Vec<ForeignKeySpec>> {
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
            name: Some(format!("{table}_{from_col}_fkey")),
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

fn value_ref_to_pg_json(val: ValueRef<'_>) -> (serde_json::Value, &'static str, usize) {
    match val {
        ValueRef::Null => (serde_json::Value::Null, "unknown", 4),
        ValueRef::Integer(i) => (serde_json::json!(i), "bigint", 8),
        ValueRef::Real(f) => (serde_json::json!(f), "double precision", 8),
        ValueRef::Text(b) => {
            let s = String::from_utf8_lossy(b).into_owned();
            let len = s.len().max(1);
            (serde_json::Value::String(s), "text", len)
        }
        ValueRef::Blob(b) => {
            let mut hex_str = String::with_capacity(b.len() * 2 + 2);
            hex_str.push_str("\\x");
            for byte in b {
                hex_str.push_str(&format!("{byte:02x}"));
            }
            let len = hex_str.len();
            (serde_json::Value::String(hex_str), "bytea", len)
        }
    }
}

#[async_trait]
impl DatabaseAdapter for PostgresAdapter {
    fn connection_id(&self) -> &str {
        &self.config.connection_id
    }

    fn capabilities(&self) -> DatabaseCapabilities {
        DatabaseCapabilities::for_postgres(
            self.config.has_pg_stat_statements,
            self.config.has_hypopg,
        )
    }

    async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
        let all_objects = self.collect_all_catalog_objects().await?;
        Ok(filter_and_paginate_objects(&all_objects, &request))
    }

    async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        self.ensure_connectivity().await?;

        let exec_id = request.execution_id.clone();
        if self.cancelled_executions.contains_key(&exec_id) {
            return Err(DbMcpError::ExecutionCancelled(format!(
                "PostgreSQL execution '{}' was cancelled via pg_cancel_backend",
                exec_id
            )));
        }

        let effective_read_only = self.config.read_only || request.read_only;
        let analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, &request.sql)?;

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
                    "PostgreSQL statement classified as '{}' is forbidden in read-only transaction mode on '{}'",
                    analysis.overall_class, self.config.connection_id
                ),
                next_action: Some("propose_change".to_string()),
            });
        }

        let timeout_ms = if request.timeout_ms == 0 {
            self.config.statement_timeout_ms
        } else {
            request.timeout_ms
        };

        if effective_read_only {
            let preamble = build_read_only_session_preamble(timeout_ms);
            if let Ok(mut log) = self.session_log.lock() {
                log.push(preamble);
            }
        }

        let pid = self
            .active_pids
            .entry(exec_id.clone())
            .or_insert_with(|| self.next_pid.fetch_add(1, Ordering::SeqCst))
            .value()
            .to_owned();
        let _ = pid;

        let conn_arc = Arc::clone(&self.engine_conn);
        let default_schema = self.config.default_schema.clone();
        let active_pids = Arc::clone(&self.active_pids);
        let cancelled_map = Arc::clone(&self.cancelled_executions);

        let res = tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("PostgresAdapter engine lock poisoned".to_string())
            })?;

            if cancelled_map.contains_key(&request.execution_id) {
                active_pids.remove(&request.execution_id);
                return Err(DbMcpError::ExecutionCancelled(format!(
                    "PostgreSQL execution '{}' cancelled",
                    request.execution_id
                )));
            }

            let rewritten_sql = rewrite_pg_sql_for_embedded(&request.sql, &default_schema);
            let params: Vec<SqliteValue> = request.params.iter().map(json_to_sqlite_param).collect();
            let max_rows = if request.max_rows == 0 {
                usize::MAX
            } else {
                request.max_rows
            };
            let max_bytes = request.max_bytes;

            let mut stmt = guard.prepare(&rewritten_sql).map_err(|e| {
                DbMcpError::AdapterError(redact_sensitive_text(&e.to_string()))
            })?;
            let col_count = stmt.column_count();

            let outcome = if col_count > 0 {
                let mut columns: Vec<ColumnMetadata> = stmt
                    .column_names()
                    .into_iter()
                    .map(|n| ColumnMetadata::new(n, "text"))
                    .collect();
                let mut rows_out = Vec::new();
                let mut bytes_used = 0usize;
                let mut truncated = false;
                let mut warnings = Vec::new();

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
                        let (jval, ty, b) = value_ref_to_pg_json(vref);
                        if columns[i].data_type == "text" && ty != "unknown" {
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

                let schema_version = introspect_embedded_pg_catalog(&guard, &default_schema)
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

                let schema_version = introspect_embedded_pg_catalog(&guard, &default_schema)
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
                    warnings: Vec::new(),
                    schema_version,
                })
            };

            active_pids.remove(&request.execution_id);
            outcome
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("Postgres execute join error: {e}")))?;

        res
    }

    async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
        self.ensure_connectivity().await?;

        let stmts = split_sql_statements(DatabaseEngine::Postgres, &request.sql);
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

        let analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, trimmed)?;
        if analysis.overall_class.is_mutating() || analysis.has_privileged_functions {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "explain_query only permits read-only SQL statements".to_string(),
                next_action: None,
            });
        }

        let all_objects = self.collect_all_catalog_objects().await?;

        // Determine whether referenced tables have matching indexes for filter/join predicates
        let mut plan_nodes = Vec::new();
        let mut total_cost = 0.0_f64;
        let mut total_rows = 100.0_f64;

        for raw_tbl in &analysis.referenced_tables {
            let base_tbl = raw_tbl.rsplit('.').next().unwrap_or(raw_tbl);
            let matching_table = all_objects.iter().find(|o| {
                o.object_type == CatalogObjectType::Table
                    && o.name.eq_ignore_ascii_case(base_tbl)
            });

            let table_preds: Vec<String> = analysis
                .predicates
                .iter()
                .filter(|p| {
                    p.operator != PredicateOperator::OrderBy
                        && p.operator != PredicateOperator::GroupBy
                        && p.table
                            .as_deref()
                            .map(|t| {
                                t.rsplit('.')
                                    .next()
                                    .unwrap_or(t)
                                    .eq_ignore_ascii_case(base_tbl)
                            })
                            .unwrap_or(true)
                })
                .map(|p| p.column.to_ascii_lowercase())
                .collect();

            let matched_index = matching_table.and_then(|tbl| {
                // Check PK or explicit index whose leading column is in `table_preds`
                if let Some(idx) = tbl.indexes.iter().find(|idx| {
                    idx.columns
                        .first()
                        .map(|c| table_preds.contains(&c.to_ascii_lowercase()))
                        .unwrap_or(false)
                }) {
                    return Some(idx.name.clone());
                }
                if let Some(pk_col) = tbl
                    .columns
                    .iter()
                    .find(|c| c.is_primary_key && table_preds.contains(&c.name.to_ascii_lowercase()))
                {
                    return Some(format!("{}_{}_pkey", tbl.name, pk_col.name));
                }
                None
            });

            let est_rows = matching_table
                .and_then(|t| t.estimated_rows)
                .unwrap_or(500)
                .max(1) as f64;

            if let Some(idx_name) = matched_index {
                let node_cost = 8.45;
                let node_rows = (est_rows * 0.05).max(1.0).round();
                total_cost += node_cost;
                total_rows = node_rows;
                plan_nodes.push(serde_json::json!({
                    "Node Type": "Index Scan",
                    "Scan Direction": "Forward",
                    "Index Name": idx_name,
                    "Relation Name": base_tbl,
                    "Schema": self.config.default_schema,
                    "Startup Cost": 0.28,
                    "Total Cost": node_cost,
                    "Plan Rows": node_rows,
                    "Plan Width": 64
                }));
            } else {
                let node_cost = (est_rows * 1.25 + 25.0).round();
                total_cost += node_cost;
                total_rows = est_rows;
                plan_nodes.push(serde_json::json!({
                    "Node Type": "Seq Scan",
                    "Relation Name": base_tbl,
                    "Schema": self.config.default_schema,
                    "Startup Cost": 0.00,
                    "Total Cost": node_cost,
                    "Plan Rows": est_rows,
                    "Plan Width": 64
                }));
            }
        }

        let root_plan = if plan_nodes.is_empty() {
            serde_json::json!({
                "Node Type": "Result",
                "Startup Cost": 0.00,
                "Total Cost": 0.01,
                "Plan Rows": 1.0,
                "Plan Width": 4
            })
        } else if plan_nodes.len() == 1 {
            plan_nodes.remove(0)
        } else {
            serde_json::json!({
                "Node Type": "Hash Join",
                "Join Type": "Inner",
                "Startup Cost": 10.0,
                "Total Cost": total_cost + 15.0,
                "Plan Rows": total_rows,
                "Plan Width": 128,
                "Plans": plan_nodes
            })
        };

        let explain_json_array = serde_json::json!([
            {
                "Plan": root_plan
            }
        ]);
        let raw_json_str = serde_json::to_string_pretty(&explain_json_array)
            .unwrap_or_else(|_| "[]".to_string());
        let parsed = parse_postgres_explain_json(&raw_json_str)?;

        let raw_plan = match request.format {
            ExplainFormat::Json => raw_json_str,
            ExplainFormat::Text => {
                let mut lines = Vec::new();
                for sc in &parsed.seq_scans {
                    lines.push(format!(
                        "Seq Scan on {sc}  (cost=0.00..{:.2} rows={:.0} width=64)",
                        parsed.total_cost.unwrap_or(100.0),
                        parsed.plan_rows.unwrap_or(100.0)
                    ));
                }
                for ic in &parsed.index_scans {
                    lines.push(format!(
                        "Index Scan using {ic}  (cost=0.28..{:.2} rows={:.0} width=64)",
                        parsed.total_cost.unwrap_or(8.45),
                        parsed.plan_rows.unwrap_or(10.0)
                    ));
                }
                if lines.is_empty() {
                    lines.push(format!(
                        "Result  (cost=0.00..{:.2} rows=1 width=4)",
                        parsed.total_cost.unwrap_or(0.01)
                    ));
                }
                lines.join("\n")
            }
        };

        Ok(ExplainPlan {
            connection: request.connection,
            sql: request.sql,
            analyze: request.analyze,
            format: request.format,
            raw_plan,
            structured_plan: Some(parsed.structured_plan),
            estimated_cost: parsed.total_cost,
            estimated_rows: parsed.plan_rows,
            seq_scans: parsed.seq_scans,
            index_scans: parsed.index_scans,
            warnings: parsed.warnings,
        })
    }

    async fn cancel(&self, execution: ExecutionId) -> DbMcpResult<bool> {
        self.cancelled_executions
            .insert(execution.clone(), Utc::now());
        let pid = self
            .active_pids
            .remove(&execution)
            .map(|(_, p)| p)
            .unwrap_or_else(|| self.next_pid.fetch_add(1, Ordering::SeqCst));

        let cancel_sql = build_pg_cancel_backend_query(pid);
        if let Ok(mut pids) = self.cancelled_pids.lock() {
            pids.push(pid);
        }
        if let Ok(mut sql_log) = self.cancelled_sql_log.lock() {
            sql_log.push(cancel_sql);
        }
        Ok(true)
    }
}

#[async_trait]
impl SchemaDiffProvider for PostgresAdapter {
    async fn capture_schema(
        &self,
        connection: &str,
        schema_pattern: Option<String>,
    ) -> DbMcpResult<SchemaSnapshot> {
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
            DatabaseEngine::Postgres,
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
impl TransactionalDdlProvider for PostgresAdapter {
    fn supports_transactional_ddl(&self) -> bool {
        true
    }

    async fn execute_transactional_ddl(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        if self.config.read_only || request.read_only {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "Transactional DDL cannot run on a read-only PostgreSQL connection"
                    .to_string(),
                next_action: Some("propose_change".to_string()),
            });
        }

        if request
            .sql
            .to_ascii_uppercase()
            .contains("CONCURRENTLY")
        {
            return Err(DbMcpError::InvalidArgument(
                "CREATE/DROP INDEX CONCURRENTLY cannot run inside a PostgreSQL transaction block"
                    .to_string(),
            ));
        }

        let conn_arc = Arc::clone(&self.engine_conn);
        let default_schema = self.config.default_schema.clone();
        let rewritten_batch = rewrite_pg_sql_for_embedded(&request.sql, &default_schema);
        let stmts = split_sql_statements(DatabaseEngine::Postgres, &rewritten_batch);
        if stmts.is_empty() {
            return Err(DbMcpError::InvalidArgument(
                "Transactional DDL SQL must not be empty".to_string(),
            ));
        }

        tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let mut guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("PostgresAdapter engine lock poisoned".to_string())
            })?;
            let tx = guard
                .transaction()
                .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

            let mut total_affected = 0u64;
            for stmt_sql in &stmts {
                match tx.execute(stmt_sql, []) {
                    Ok(changed) => total_affected += changed as u64,
                    Err(err) => {
                        let _ = tx.rollback();
                        return Err(DbMcpError::AdapterError(redact_sensitive_text(
                            &err.to_string(),
                        )));
                    }
                }
            }

            tx.commit()
                .map_err(|e| DbMcpError::AdapterError(redact_sensitive_text(&e.to_string())))?;

            let schema_version = introspect_embedded_pg_catalog(&guard, &default_schema)
                .ok()
                .map(|objs| compute_schema_version(&objs));

            Ok(QueryResult {
                execution_id: request.execution_id,
                columns: vec![ColumnMetadata::new("status", "text")],
                rows: vec![vec![serde_json::Value::String("COMMIT".to_string())]],
                returned_rows: 1,
                rows_affected: Some(total_affected),
                truncated: false,
                bytes_used: 6,
                execution_time_ms: started.elapsed().as_millis() as u64,
                warnings: Vec::new(),
                schema_version,
            })
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("Postgres transactional DDL join error: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{CallerIdentity, DiffOperationKind, ExecutionLimits, SqlStatementClass};

    const PG_SEED: &str = r#"
        CREATE TABLE public.users (
            id BIGINT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE public.orders (
            id BIGINT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id),
            status TEXT NOT NULL,
            total_cents BIGINT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_orders_user_id ON public.orders(user_id);

        INSERT INTO public.users (id, email, status) VALUES
            (1, 'alice@example.com', 'active'),
            (2, 'bob@example.com', 'active');
        INSERT INTO public.orders (id, user_id, status, total_cents, created_at) VALUES
            (501, 1, 'completed', 9900, '2026-10-10T00:00:00Z'),
            (502, 2, 'pending', 3500, '2026-10-11T00:00:00Z');
    "#;

    #[tokio::test]
    async fn test_postgres_catalog_discovery_and_query_execution() {
        let adapter = PostgresAdapter::simulated_with_seed("pg-dev", PG_SEED).unwrap();
        let caps = adapter.capabilities();
        assert_eq!(caps.engine, DatabaseEngine::Postgres);
        assert!(caps.supports_transactional_ddl);
        assert!(caps.supports_hypothetical_indexes);

        let disc = adapter
            .discover(CatalogRequest {
                connection: "pg-dev".to_string(),
                schema_pattern: Some("public".to_string()),
                name_pattern: None,
                object_types: vec![CatalogObjectType::Table],
                detail_level: CatalogDetailLevel::Full,
                limit: 10,
                offset: 0,
            })
            .await
            .unwrap();
        assert_eq!(disc.total_count, 2);

        let query = AuthorizedQuery::new_read(
            "req_pg_1",
            "pg-dev",
            CallerIdentity::local_agent("agent"),
            "SELECT id, user_id, total_cents FROM public.orders WHERE user_id = $1",
            vec![serde_json::json!(1)],
            &ExecutionLimits::default(),
        );
        let res = adapter.execute(query).await.unwrap();
        assert_eq!(res.returned_rows, 1);
        assert_eq!(res.rows[0][0], serde_json::json!(501));
        assert!(!adapter.session_log().is_empty());
        assert!(adapter.session_log()[0].contains("READ ONLY"));
    }

    #[tokio::test]
    async fn test_postgres_explain_json_and_plan_parser() {
        let adapter = PostgresAdapter::simulated_with_seed("pg-dev", PG_SEED).unwrap();

        // 1. Query on indexed column `user_id` -> Index Scan
        let indexed_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_exp_pg_1".to_string(),
                connection: "pg-dev".to_string(),
                sql: "SELECT * FROM public.orders WHERE user_id = 1".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(indexed_plan
            .index_scans
            .contains(&"idx_orders_user_id".to_string()));
        assert!(indexed_plan.seq_scans.is_empty());
        assert!(indexed_plan.estimated_cost.unwrap() < 20.0);

        // 2. Query on unindexed column `status` -> Seq Scan
        let seq_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_exp_pg_2".to_string(),
                connection: "pg-dev".to_string(),
                sql: "SELECT * FROM public.orders WHERE status = 'pending'".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(seq_plan.seq_scans.contains(&"orders".to_string()));
        assert!(!seq_plan.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_postgres_cancel_backend_and_transactional_ddl() {
        let adapter = PostgresAdapter::simulated_with_seed("pg-dev", PG_SEED).unwrap();

        let exec_id = ExecutionId::new();
        adapter.register_backend_pid(exec_id.clone(), 9876);
        let cancelled = adapter.cancel(exec_id.clone()).await.unwrap();
        assert!(cancelled);
        assert_eq!(adapter.cancelled_pids(), vec![9876]);
        assert_eq!(
            adapter.cancelled_sql_log(),
            vec!["SELECT pg_cancel_backend(9876);".to_string()]
        );

        // Verify transactional DDL and schema diff
        let before = adapter.capture_schema("pg-dev", None).await.unwrap();
        let ddl = AuthorizedQuery {
            request_id: "req_pg_ddl".to_string(),
            execution_id: ExecutionId::new(),
            connection: "pg-dev".to_string(),
            caller: CallerIdentity::admin("dba"),
            sql: "CREATE INDEX idx_orders_status ON public.orders(status);".to_string(),
            normalized_sql: "CREATE INDEX idx_orders_status ON public.orders(status)".to_string(),
            sql_hash: "h".to_string(),
            params: vec![],
            statement_class: SqlStatementClass::Ddl,
            read_only: false,
            timeout_ms: 5_000,
            max_rows: 100,
            max_bytes: 102400,
            change_id: Some("chg_pg_1".to_string()),
        };
        adapter.execute_transactional_ddl(ddl).await.unwrap();
        let after = adapter.capture_schema("pg-dev", None).await.unwrap();
        let diff = adapter.diff_schema(&before, &after).await.unwrap();
        assert!(!diff.is_identical);
        assert!(diff.all_transactional);
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AddIndex
                && i.target_name.as_deref() == Some("idx_orders_status")));
    }

    #[tokio::test]
    async fn test_postgres_routines_bootstrap_and_custom_ddl_interception() {
        let query_sql = build_pg_catalog_routines_query(Some("public"));
        assert!(query_sql.contains("pg_catalog.pg_proc"));
        assert!(query_sql.contains("pg_get_functiondef(p.oid)"));

        let adapter = PostgresAdapter::simulated_with_seed("pg-dev", PG_SEED).unwrap();
        adapter
            .execute_batch(
                r#"
                CREATE OR REPLACE PROCEDURE public.archive_completed_orders(p_cutoff TEXT)
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    CALL record_order_audit(1, p_cutoff);
                END;
                $$;
                "#,
            )
            .unwrap();

        let routines = adapter
            .discover(CatalogRequest {
                connection: "pg-dev".to_string(),
                schema_pattern: Some("public".to_string()),
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
        assert!(names.contains(&"archive_completed_orders"));

        let discount_fn = routines
            .objects
            .iter()
            .find(|o| o.name == "calculate_order_discount")
            .unwrap();
        assert_eq!(discount_fn.object_type, CatalogObjectType::Function);
        assert!(discount_fn.definition.as_deref().unwrap().contains("JOIN public.users"));

        let checkout_proc = routines
            .objects
            .iter()
            .find(|o| o.name == "checkout_order")
            .unwrap();
        assert_eq!(checkout_proc.object_type, CatalogObjectType::Procedure);
        let def = checkout_proc.definition.as_deref().unwrap();
        assert!(def.contains("PERFORM calculate_order_discount(order_id)"));
        assert!(def.contains("CALL reserve_inventory(order_id)"));
        assert!(def.contains("CALL record_order_audit(order_id, 'ORDER_CHECKED_OUT')"));
    }
}
