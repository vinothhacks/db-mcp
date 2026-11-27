//! SQLite database adapter implementation (`SqliteAdapter`) with `rusqlite`,
//! progressive catalog discovery (`sqlite_master`, `PRAGMA table_info`, `PRAGMA index_list`,
//! `PRAGMA index_info`, `PRAGMA foreign_key_list`), parameter binding, row/byte budgets,
//! `PRAGMA query_only` read-only enforcement, `EXPLAIN QUERY PLAN` structured extraction,
//! real `InterruptHandle` cancellation, `SchemaDiffProvider`, and `TransactionalDdlProvider`.

use std::collections::BTreeMap;
use std::path::Path;
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
use db_mcp_secrets::redact_sensitive_text;
use db_mcp_sql::{normalize_sql, parse_and_analyze_sql, split_sql_statements};
use regex::Regex;
use rusqlite::types::{Value as SqliteValue, ValueRef};
use rusqlite::{ params_from_iter, Batch, Connection, Error as RusqliteError, ErrorCode, InterruptHandle, OpenFlags};
use serde::{Deserialize, Serialize};

/// Configuration for a `SqliteAdapter` connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqliteConfig {
    pub connection_id: String,
    pub database_path: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default = "default_sqlite_schema")]
    pub default_schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_sql: Option<String>,
    #[serde(default = "default_busy_timeout_ms")]
    pub busy_timeout_ms: u64,
}

fn default_sqlite_schema() -> String {
    "main".to_string()
}

fn default_busy_timeout_ms() -> u64 {
    5_000
}

impl SqliteConfig {
    pub fn new(connection_id: impl Into<String>, database_path: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            database_path: database_path.into(),
            read_only: false,
            default_schema: default_sqlite_schema(),
            init_sql: None,
            busy_timeout_ms: default_busy_timeout_ms(),
        }
    }

    pub fn in_memory(connection_id: impl Into<String>) -> Self {
        Self::new(connection_id, ":memory:")
    }

    pub fn from_dsn(connection_id: impl Into<String>, dsn: &str) -> Self {
        let trimmed = dsn.trim();
        let path = trimmed
            .strip_prefix("sqlite://")
            .or_else(|| trimmed.strip_prefix("sqlite:"))
            .unwrap_or(trimmed);
        let normalized_path = if path.is_empty() || path == ":memory:" || path == "/:memory:" {
            ":memory:".to_string()
        } else {
            path.to_string()
        };
        Self::new(connection_id, normalized_path)
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn with_init_sql(mut self, init_sql: impl Into<String>) -> Self {
        self.init_sql = Some(init_sql.into());
        self
    }

    pub fn with_default_schema(mut self, schema: impl Into<String>) -> Self {
        self.default_schema = schema.into();
        self
    }

    pub fn with_busy_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.busy_timeout_ms = timeout_ms;
        self
    }
}

/// SQLite implementation of `DatabaseAdapter`, `SchemaDiffProvider`, and `TransactionalDdlProvider`.
#[derive(Clone)]
pub struct SqliteAdapter {
    config: SqliteConfig,
    conn: Arc<Mutex<Connection>>,
    custom_catalog: Arc<DashMap<String, CatalogObject>>,
    interrupt_handle: Arc<InterruptHandle>,
    active_executions: Arc<DashMap<ExecutionId, Arc<InterruptHandle>>>,
    cancelled_executions: Arc<DashMap<ExecutionId, DateTime<Utc>>>,
}

impl std::fmt::Debug for SqliteAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteAdapter")
            .field("connection_id", &self.config.connection_id)
            .field("database_path", &redact_sensitive_text(&self.config.database_path))
            .field("read_only", &self.config.read_only)
            .finish()
    }
}

impl SqliteAdapter {
    /// Create a new `SqliteAdapter` from `SqliteConfig`.
    pub fn new(config: SqliteConfig) -> DbMcpResult<Self> {
        let conn = open_sqlite_connection(&config)?;
        let interrupt_handle = Arc::new(conn.get_interrupt_handle());

        if let Some(seed_sql) = &config.init_sql {
            if !seed_sql.trim().is_empty() {
                let (rewritten, has_routines) =
                    rewrite_sqlite_sql_for_routines(seed_sql, &config.default_schema);
                if has_routines {
                    ensure_sqlite_routines_table(&conn)?;
                }
                conn.execute_batch(&rewritten).map_err(map_rusqlite_error)?;
            }
        }

        if config.read_only {
            conn.execute_batch("PRAGMA query_only = ON;")
                .map_err(map_rusqlite_error)?;
        }

        Ok(Self {
            config,
            conn: Arc::new(Mutex::new(conn)),
            custom_catalog: Arc::new(DashMap::new()),
            interrupt_handle,
            active_executions: Arc::new(DashMap::new()),
            cancelled_executions: Arc::new(DashMap::new()),
        })
    }

    /// Open an in-memory SQLite adapter.
    pub fn open_memory(connection_id: impl Into<String>) -> DbMcpResult<Self> {
        Self::new(SqliteConfig::in_memory(connection_id))
    }

    /// Open an in-memory SQLite adapter and run initial seed DDL/DML.
    pub fn open_memory_with_seed(
        connection_id: impl Into<String>,
        seed_sql: impl Into<String>,
    ) -> DbMcpResult<Self> {
        Self::new(SqliteConfig::in_memory(connection_id).with_init_sql(seed_sql))
    }

    /// Open a file-backed SQLite database.
    pub fn open_file(
        connection_id: impl Into<String>,
        path: impl AsRef<Path>,
        read_only: bool,
    ) -> DbMcpResult<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        Self::new(SqliteConfig::new(connection_id, path_str).with_read_only(read_only))
    }

    /// Open a SQLite adapter from a DSN string (`sqlite://...` or `:memory:`).
    pub fn from_dsn(
        connection_id: impl Into<String>,
        dsn: &str,
        read_only: bool,
    ) -> DbMcpResult<Self> {
        Self::new(SqliteConfig::from_dsn(connection_id, dsn).with_read_only(read_only))
    }

    pub fn config(&self) -> &SqliteConfig {
        &self.config
    }

    /// Register or override a `CatalogObject` in the adapter's catalog.
    pub fn register_catalog_object(&self, object: CatalogObject) {
        self.custom_catalog
            .insert(object.qualified_name().to_ascii_lowercase(), object);
    }

    /// Execute a SQL batch directly (for test fixtures or initialization).
    pub fn execute_batch(&self, sql: &str) -> DbMcpResult<()> {
        let (rewritten, has_routines) =
            rewrite_sqlite_sql_for_routines(sql, &self.config.default_schema);
        let guard = self
            .conn
            .lock()
            .map_err(|_| DbMcpError::InternalError("SQLite connection mutex poisoned".to_string()))?;
        if has_routines {
            ensure_sqlite_routines_table(&guard)?;
        }
        guard.execute_batch(&rewritten).map_err(map_rusqlite_error)
    }

    /// Obtain a shared reference to the connection's `rusqlite::InterruptHandle`.
    pub fn interrupt_handle(&self) -> Arc<InterruptHandle> {
        Arc::clone(&self.interrupt_handle)
    }

    /// Pre-register an `ExecutionId` for cancellation tracking before or during execution.
    pub fn register_execution(&self, execution_id: ExecutionId) -> Arc<InterruptHandle> {
        let handle = Arc::clone(&self.interrupt_handle);
        self.active_executions.insert(execution_id, Arc::clone(&handle));
        handle
    }

    /// Check whether an `ExecutionId` has been marked cancelled.
    pub fn is_cancelled(&self, execution_id: &ExecutionId) -> bool {
        self.cancelled_executions.contains_key(execution_id)
    }

    /// Describe a single catalog object by name and optional schema.
    pub async fn describe_object(
        &self,
        schema: Option<&str>,
        object_name: &str,
        detail_level: CatalogDetailLevel,
    ) -> DbMcpResult<CatalogObject> {
        let objects = self.load_all_catalog_objects().await?;
        catalog_describe_object(&objects, schema, object_name, detail_level)
    }

    async fn load_all_catalog_objects(&self) -> DbMcpResult<Vec<CatalogObject>> {
        let conn = Arc::clone(&self.conn);
        let schema_name = self.config.default_schema.clone();
        let custom_map: BTreeMap<String, CatalogObject> = self
            .custom_catalog
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|_| {
                DbMcpError::InternalError("SQLite connection mutex poisoned".to_string())
            })?;
            let mut objects = introspect_sqlite_catalog(&guard, &schema_name)?;
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
        .map_err(|e| DbMcpError::InternalError(format!("SQLite catalog task join error: {e}")))?
    }
}

fn open_sqlite_connection(config: &SqliteConfig) -> DbMcpResult<Connection> {
    let raw_path = config.database_path.trim();
    let conn = if raw_path == ":memory:" || raw_path.is_empty() {
        Connection::open_in_memory().map_err(map_rusqlite_error)?
    } else if raw_path.starts_with("file:") {
        let flags = if config.read_only && !raw_path.contains("mode=memory") {
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        Connection::open_with_flags(raw_path, flags).map_err(map_rusqlite_error)?
    } else {
        let flags = if config.read_only && config.init_sql.is_none() {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        Connection::open_with_flags(raw_path, flags).map_err(map_rusqlite_error)?
    };

    conn.busy_timeout(Duration::from_millis(config.busy_timeout_ms))
        .map_err(map_rusqlite_error)?;
    let _ = conn.execute_batch("PRAGMA foreign_keys = ON;");
    Ok(conn)
}

fn map_rusqlite_error(err: RusqliteError) -> DbMcpError {
    match &err {
        RusqliteError::SqliteFailure(ffi_err, msg) => {
            if ffi_err.code == ErrorCode::OperationInterrupted {
                return DbMcpError::ExecutionCancelled(
                    msg.clone()
                        .unwrap_or_else(|| "SQLite execution interrupted".to_string()),
                );
            }
            if ffi_err.code == ErrorCode::ReadOnly {
                return DbMcpError::PolicyDenied {
                    code: "READONLY_VIOLATION".to_string(),
                    message: redact_sensitive_text(
                        msg.as_deref()
                            .unwrap_or("Attempted write on read-only SQLite connection"),
                    ),
                    next_action: Some("propose_change".to_string()),
                };
            }
            DbMcpError::AdapterError(redact_sensitive_text(&err.to_string()))
        }
        _ => DbMcpError::AdapterError(redact_sensitive_text(&err.to_string())),
    }
}

fn json_to_sqlite_value(value: &serde_json::Value) -> DbMcpResult<SqliteValue> {
    Ok(match value {
        serde_json::Value::Null => SqliteValue::Null,
        serde_json::Value::Bool(b) => SqliteValue::Integer(if *b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqliteValue::Integer(i)
            } else if n.is_u64() {
                return Err(DbMcpError::InvalidArgument(
                    "SQLite integer parameter exceeds the signed 64-bit range".to_string(),
                ));
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
    })
}

fn sqlite_value_ref_to_json(val: ValueRef<'_>) -> (serde_json::Value, &'static str, usize) {
    match val {
        ValueRef::Null => (serde_json::Value::Null, "NULL", 4),
        ValueRef::Integer(i) => (serde_json::json!(i), "INTEGER", 8),
        ValueRef::Real(f) => (serde_json::json!(f), "REAL", 8),
        ValueRef::Text(bytes) => {
            let s = String::from_utf8_lossy(bytes).into_owned();
            let len = s.len().max(1);
            (serde_json::Value::String(s), "TEXT", len)
        }
        ValueRef::Blob(bytes) => {
            let hex_str = format!("0x{}", hex_encode(bytes));
            let len = hex_str.len();
            (serde_json::Value::String(hex_str), "BLOB", len)
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn quote_sqlite_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn ensure_sqlite_routines_table(conn: &Connection) -> DbMcpResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS __db_mcp_routines (
            routine_name TEXT PRIMARY KEY,
            routine_schema TEXT NOT NULL DEFAULT 'main',
            routine_type TEXT NOT NULL DEFAULT 'PROCEDURE',
            definition TEXT NOT NULL,
            comment TEXT
        );
        "#,
    )
    .map_err(map_rusqlite_error)
}

/// A `$tag$` body belongs to the current routine header only when no statement
/// terminator or `BEGIN` keyword precedes it; otherwise it is the next statement's.
fn dollar_quote_in_header(prefix: &str) -> bool {
    if prefix.contains(';') {
        return false;
    }
    !prefix
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|w| w.eq_ignore_ascii_case("begin"))
}

fn find_sqlite_routine_ddl_end(sql: &str, after_open_paren: usize) -> usize {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = after_open_paren;
    let mut paren_depth = 1usize;

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

    let dollar_re = Regex::new(r"\$([A-Za-z0-9_]*)\$").unwrap();
    let rest = &sql[i..];
    if let Some(m) = dollar_re.find(rest).filter(|m| dollar_quote_in_header(&rest[..m.start()])) {
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

fn rewrite_sqlite_sql_for_routines(sql: &str, default_schema: &str) -> (String, bool) {
    let header_re = Regex::new(
        r#"(?im)(?:^|;)\s*(CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(PROCEDURE|FUNCTION)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*\()"#,
    )
    .unwrap();

    let mut out = String::new();
    let mut cursor = 0usize;
    let mut found_routine = false;

    while cursor < sql.len() {
        let Some(caps) = header_re.captures(&sql[cursor..]) else {
            out.push_str(&sql[cursor..]);
            break;
        };

        found_routine = true;
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
            out.push_str(&sql[cursor..prefix_end]);
        }

        let stmt_end = find_sqlite_routine_ddl_end(sql, after_open_paren);
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
            "\nINSERT OR REPLACE INTO __db_mcp_routines (routine_name, routine_schema, routine_type, definition, comment) VALUES ('{}', '{}', '{}', '{}', NULL);\n",
            routine_name.replace('\'', "''"),
            schema.replace('\'', "''"),
            routine_type,
            definition.replace('\'', "''"),
        ));

        cursor = stmt_end;
    }

    (out, found_routine)
}

fn introspect_sqlite_catalog(
    conn: &Connection,
    schema_name: &str,
) -> DbMcpResult<Vec<CatalogObject>> {
    let mut master_stmt = conn
        .prepare(
            "SELECT type, name, tbl_name, sql
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
               AND name NOT LIKE '__db_mcp_%'
             ORDER BY type, name",
        )
        .map_err(map_rusqlite_error)?;

    struct MasterRow {
        obj_type: String,
        name: String,
        tbl_name: String,
        sql: Option<String>,
    }

    let rows_iter = master_stmt
        .query_map([], |row| {
            Ok(MasterRow {
                obj_type: row.get::<_, String>(0)?,
                name: row.get::<_, String>(1)?,
                tbl_name: row.get::<_, String>(2)?,
                sql: row.get::<_, Option<String>>(3)?,
            })
        })
        .map_err(map_rusqlite_error)?;

    let mut master_rows = Vec::new();
    for r in rows_iter {
        master_rows.push(r.map_err(map_rusqlite_error)?);
    }

    let mut index_sql_by_name: BTreeMap<String, Option<String>> = BTreeMap::new();
    for row in &master_rows {
        if row.obj_type.eq_ignore_ascii_case("index") {
            index_sql_by_name.insert(row.name.clone(), row.sql.clone());
        }
    }

    let mut objects = Vec::new();

    for row in &master_rows {
        match row.obj_type.to_ascii_lowercase().as_str() {
            "table" | "view" => {
                let is_table = row.obj_type.eq_ignore_ascii_case("table");
                let columns = introspect_table_columns(conn, &row.name)?;
                let indexes = if is_table {
                    introspect_table_indexes(conn, &row.name, &index_sql_by_name)?
                } else {
                    Vec::new()
                };
                let foreign_keys = if is_table {
                    introspect_table_foreign_keys(conn, &row.name)?
                } else {
                    Vec::new()
                };
                let estimated_rows = if is_table {
                    let count_sql = format!("SELECT COUNT(*) FROM {}", quote_sqlite_ident(&row.name));
                    conn.query_row(&count_sql, [], |r| r.get::<_, i64>(0))
                        .ok()
                        .map(|n| n.max(0) as u64)
                } else {
                    None
                };

                // Emit standalone Index catalog objects as well for index searches
                for idx in &indexes {
                    objects.push(CatalogObject {
                        schema: schema_name.to_string(),
                        name: idx.name.clone(),
                        object_type: CatalogObjectType::Index,
                        comment: None,
                        estimated_rows: None,
                        size_bytes: None,
                        columns: idx
                            .columns
                            .iter()
                            .enumerate()
                            .map(|(i, col_name)| ColumnSpec {
                                name: col_name.clone(),
                                data_type: "INDEX_KEY".to_string(),
                                nullable: true,
                                default_value: None,
                                is_primary_key: idx.primary,
                                comment: None,
                                ordinal_position: i + 1,
                            })
                            .collect(),
                        indexes: vec![idx.clone()],
                        foreign_keys: Vec::new(),
                        definition: idx.definition.clone(),
                    });
                }

                objects.push(CatalogObject {
                    schema: schema_name.to_string(),
                    name: row.name.clone(),
                    object_type: if is_table {
                        CatalogObjectType::Table
                    } else {
                        CatalogObjectType::View
                    },
                    comment: None,
                    estimated_rows,
                    size_bytes: None,
                    columns,
                    indexes,
                    foreign_keys,
                    definition: row.sql.clone(),
                });
            }
            "trigger" => {
                objects.push(CatalogObject {
                    schema: schema_name.to_string(),
                    name: row.name.clone(),
                    object_type: CatalogObjectType::Trigger,
                    comment: Some(format!("Trigger on {}", row.tbl_name)),
                    estimated_rows: None,
                    size_bytes: None,
                    columns: Vec::new(),
                    indexes: Vec::new(),
                    foreign_keys: Vec::new(),
                    definition: row.sql.clone(),
                });
            }
            _ => {}
        }
    }

    // Introspect optional `__db_mcp_routines` metadata table if present in SQLite
    introspect_sqlite_routines_table(conn, schema_name, &mut objects)?;

    Ok(objects)
}

fn introspect_sqlite_routines_table(
    conn: &Connection,
    default_schema: &str,
    objects: &mut Vec<CatalogObject>,
) -> DbMcpResult<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '__db_mcp_routines' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !table_exists {
        return Ok(());
    }

    let cols = introspect_table_columns(conn, "__db_mcp_routines")?;
    let has_col = |target: &str| cols.iter().any(|c| c.name.eq_ignore_ascii_case(target));

    let name_expr = if has_col("routine_name") {
        "routine_name"
    } else if has_col("name") {
        "name"
    } else if has_col("proname") {
        "proname"
    } else {
        return Ok(());
    };

    let schema_expr = if has_col("routine_schema") {
        "routine_schema"
    } else if has_col("schema") {
        "schema"
    } else if has_col("nspname") {
        "nspname"
    } else {
        "''"
    };

    let type_expr = if has_col("routine_type") {
        "routine_type"
    } else if has_col("kind") {
        "kind"
    } else if has_col("type") {
        "type"
    } else if has_col("prokind") {
        "prokind"
    } else {
        "'PROCEDURE'"
    };

    let def_expr = if has_col("definition") {
        "definition"
    } else if has_col("sql") {
        "sql"
    } else if has_col("body") {
        "body"
    } else {
        return Ok(());
    };

    let comment_expr = if has_col("comment") {
        "comment"
    } else if has_col("description") {
        "description"
    } else {
        "NULL"
    };

    let query = format!(
        "SELECT {name_expr}, {schema_expr}, {type_expr}, {def_expr}, {comment_expr}
         FROM __db_mcp_routines
         ORDER BY {name_expr}"
    );

    if let Ok(mut stmt) = conn.prepare(&query) {
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(2)?
                        .unwrap_or_else(|| "PROCEDURE".to_string()),
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(map_rusqlite_error)?;

        for row in rows {
            let (r_name, r_schema, r_type, r_def, r_comment) = row.map_err(map_rusqlite_error)?;
            let schema = if r_schema.trim().is_empty() || r_schema == "main" {
                default_schema.to_string()
            } else {
                r_schema
            };
            let object_type = if r_type.eq_ignore_ascii_case("function")
                || r_type.eq_ignore_ascii_case("f")
            {
                CatalogObjectType::Function
            } else {
                CatalogObjectType::Procedure
            };
            objects.push(CatalogObject {
                schema,
                name: r_name,
                object_type,
                comment: r_comment,
                estimated_rows: None,
                size_bytes: None,
                columns: Vec::new(),
                indexes: Vec::new(),
                foreign_keys: Vec::new(),
                definition: Some(r_def),
            });
        }
    }

    Ok(())
}

fn introspect_table_columns(conn: &Connection, table_name: &str) -> DbMcpResult<Vec<ColumnSpec>> {
    let pragma_sql = format!("PRAGMA table_info({})", quote_sqlite_ident(table_name));
    let mut stmt = conn.prepare(&pragma_sql).map_err(map_rusqlite_error)?;
    let iter = stmt
        .query_map([], |row| {
            let cid: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let data_type: String = row.get::<_, Option<String>>(2)?.unwrap_or_else(|| "ANY".to_string());
            let notnull: i64 = row.get(3)?;
            let default_value: Option<String> = row.get(4)?;
            let pk: i64 = row.get(5)?;
            Ok(ColumnSpec {
                name,
                data_type: if data_type.trim().is_empty() {
                    "ANY".to_string()
                } else {
                    data_type
                },
                nullable: notnull == 0 && pk == 0,
                default_value,
                is_primary_key: pk > 0,
                comment: None,
                ordinal_position: (cid.max(0) as usize) + 1,
            })
        })
        .map_err(map_rusqlite_error)?;

    let mut cols = Vec::new();
    for col in iter {
        cols.push(col.map_err(map_rusqlite_error)?);
    }
    Ok(cols)
}

fn introspect_table_indexes(
    conn: &Connection,
    table_name: &str,
    index_sql_by_name: &BTreeMap<String, Option<String>>,
) -> DbMcpResult<Vec<IndexSpec>> {
    let pragma_sql = format!("PRAGMA index_list({})", quote_sqlite_ident(table_name));
    let mut stmt = conn.prepare(&pragma_sql).map_err(map_rusqlite_error)?;

    struct RawIndex {
        name: String,
        unique: bool,
        origin: String,
    }

    let iter = stmt
        .query_map([], |row| {
            let name: String = row.get(1)?;
            let unique_int: i64 = row.get(2)?;
            let origin: String = row
                .get::<_, Option<String>>(3)?
                .unwrap_or_else(|| "c".to_string());
            Ok(RawIndex {
                name,
                unique: unique_int != 0,
                origin,
            })
        })
        .map_err(map_rusqlite_error)?;

    let mut raw_indexes = Vec::new();
    for item in iter {
        raw_indexes.push(item.map_err(map_rusqlite_error)?);
    }

    let mut indexes = Vec::new();
    for raw in raw_indexes {
        let info_sql = format!("PRAGMA index_info({})", quote_sqlite_ident(&raw.name));
        let mut info_stmt = conn.prepare(&info_sql).map_err(map_rusqlite_error)?;
        let col_iter = info_stmt
            .query_map([], |row| row.get::<_, Option<String>>(2))
            .map_err(map_rusqlite_error)?;
        let mut cols = Vec::new();
        for c in col_iter {
            if let Some(col_name) = c.map_err(map_rusqlite_error)? {
                cols.push(col_name);
            }
        }
        let definition = index_sql_by_name.get(&raw.name).cloned().flatten();
        indexes.push(IndexSpec {
            name: raw.name,
            table_name: table_name.to_string(),
            columns: cols,
            unique: raw.unique,
            primary: raw.origin.eq_ignore_ascii_case("pk"),
            index_type: Some("btree".to_string()),
            predicate: None,
            definition,
        });
    }

    Ok(indexes)
}

fn introspect_table_foreign_keys(
    conn: &Connection,
    table_name: &str,
) -> DbMcpResult<Vec<ForeignKeySpec>> {
    let pragma_sql = format!("PRAGMA foreign_key_list({})", quote_sqlite_ident(table_name));
    let mut stmt = conn.prepare(&pragma_sql).map_err(map_rusqlite_error)?;

    #[derive(Clone)]
    struct RawFkRow {
        id: i64,
        table: String,
        from: String,
        to: String,
        on_update: Option<String>,
        on_delete: Option<String>,
    }

    let iter = stmt
        .query_map([], |row| {
            Ok(RawFkRow {
                id: row.get(0)?,
                table: row.get(2)?,
                from: row.get(3)?,
                to: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                on_update: row.get(5)?,
                on_delete: row.get(6)?,
            })
        })
        .map_err(map_rusqlite_error)?;

    let mut grouped: BTreeMap<i64, ForeignKeySpec> = BTreeMap::new();
    for item in iter {
        let r = item.map_err(map_rusqlite_error)?;
        let entry = grouped.entry(r.id).or_insert_with(|| ForeignKeySpec {
            name: Some(format!("fk_{}_{}_{}", table_name, r.table, r.id)),
            columns: Vec::new(),
            referenced_table: r.table.clone(),
            referenced_columns: Vec::new(),
            on_delete: r.on_delete.clone(),
            on_update: r.on_update.clone(),
        });
        entry.columns.push(r.from);
        if !r.to.is_empty() {
            entry.referenced_columns.push(r.to);
        }
    }

    Ok(grouped.into_values().collect())
}

/// Parse SQLite `EXPLAIN QUERY PLAN` details to extract sequential table scans and index scans.
pub fn parse_sqlite_explain_detail(
    detail: &str,
    seq_scans: &mut Vec<String>,
    index_scans: &mut Vec<String>,
) {
    let trimmed = detail.trim();
    let upper = trimmed.to_ascii_uppercase();
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();

    if upper.starts_with("SCAN ") {
        // Examples: "SCAN orders", "SCAN TABLE orders", "SCAN users AS u"
        let table_idx = if tokens.get(1).map(|t| t.eq_ignore_ascii_case("TABLE")) == Some(true) {
            2
        } else {
            1
        };
        if let Some(tbl) = tokens.get(table_idx) {
            let clean = tbl.trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');
            if !clean.is_empty() && !seq_scans.contains(&clean.to_string()) {
                seq_scans.push(clean.to_string());
            }
        }
    } else if upper.starts_with("SEARCH ") {
        // Examples:
        // "SEARCH orders USING INDEX idx_orders_user_id (user_id=?)"
        // "SEARCH orders USING COVERING INDEX idx_orders_status (status=?)"
        // "SEARCH users USING INTEGER PRIMARY KEY (rowid=?)"
        if let Some(pos) = tokens.iter().position(|t| t.eq_ignore_ascii_case("INDEX")) {
            if let Some(idx_name) = tokens.get(pos + 1) {
                let clean =
                    idx_name.trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']');
                if !clean.is_empty() && !index_scans.contains(&clean.to_string()) {
                    index_scans.push(clean.to_string());
                }
            }
        } else if upper.contains("PRIMARY KEY") {
            let tbl = if tokens.get(1).map(|t| t.eq_ignore_ascii_case("TABLE")) == Some(true) {
                tokens.get(2).copied().unwrap_or("PRIMARY")
            } else {
                tokens.get(1).copied().unwrap_or("PRIMARY")
            };
            let pk_label = format!("{tbl}_pk");
            if !index_scans.contains(&pk_label) {
                index_scans.push(pk_label);
            }
        }
    }
}

#[async_trait]
impl DatabaseAdapter for SqliteAdapter {
    fn connection_id(&self) -> &str {
        &self.config.connection_id
    }

    fn capabilities(&self) -> DatabaseCapabilities {
        DatabaseCapabilities::for_sqlite()
    }

    async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
        let all_objects = self.load_all_catalog_objects().await?;
        Ok(filter_and_paginate_objects(&all_objects, &request))
    }

    async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        let exec_id = request.execution_id.clone();
        if self.cancelled_executions.contains_key(&exec_id) {
            return Err(DbMcpError::ExecutionCancelled(format!(
                "Execution '{}' was cancelled prior to execution",
                exec_id
            )));
        }

        let effective_read_only = self.config.read_only || request.read_only;
        let analysis = parse_and_analyze_sql(DatabaseEngine::Sqlite, &request.sql)?;

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
                    "Statement classified as '{}' is not allowed in read-only execution on '{}'",
                    analysis.overall_class, self.config.connection_id
                ),
                next_action: Some("propose_change".to_string()),
            });
        }

        self.active_executions
            .insert(exec_id.clone(), Arc::clone(&self.interrupt_handle));

        let conn_arc = Arc::clone(&self.conn);
        let active_map = Arc::clone(&self.active_executions);
        let cancelled_map = Arc::clone(&self.cancelled_executions);
        let adapter_read_only = self.config.read_only;
        let default_schema = self.config.default_schema.clone();
        let timeout_ms = if request.timeout_ms == 0 {
            10_000
        } else {
            request.timeout_ms
        };
        let interrupt_for_timeout = Arc::clone(&self.interrupt_handle);

        let blocking_fut = tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("SQLite connection mutex poisoned".to_string())
            })?;

            if cancelled_map.contains_key(&request.execution_id) {
                active_map.remove(&request.execution_id);
                return Err(DbMcpError::ExecutionCancelled(format!(
                    "Execution '{}' was cancelled",
                    request.execution_id
                )));
            }

            if effective_read_only {
                let _ = guard.execute_batch("PRAGMA query_only = ON;");
            }

            let exec_outcome = execute_sqlite_query_inner(&guard, &request, &default_schema, started);

            if effective_read_only && !adapter_read_only {
                let _ = guard.execute_batch("PRAGMA query_only = OFF;");
            }

            active_map.remove(&request.execution_id);

            match exec_outcome {
                Ok(res) => {
                    if cancelled_map.contains_key(&request.execution_id) {
                        Err(DbMcpError::ExecutionCancelled(format!(
                            "Execution '{}' was cancelled",
                            request.execution_id
                        )))
                    } else {
                        Ok(res)
                    }
                }
                Err(err) => {
                    if cancelled_map.contains_key(&request.execution_id) {
                        Err(DbMcpError::ExecutionCancelled(format!(
                            "Execution '{}' was cancelled",
                            request.execution_id
                        )))
                    } else {
                        Err(err)
                    }
                }
            }
        });

        match tokio::time::timeout(Duration::from_millis(timeout_ms), blocking_fut).await {
            Ok(join_res) => join_res.map_err(|e| {
                self.active_executions.remove(&exec_id);
                DbMcpError::InternalError(format!("SQLite execution task join error: {e}"))
            })?,
            Err(_) => {
                interrupt_for_timeout.interrupt();
                self.active_executions.remove(&exec_id);
                Err(DbMcpError::ExecutionTimeout { timeout_ms })
            }
        }
    }

    async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
        let stmts = split_sql_statements(DatabaseEngine::Sqlite, &request.sql);
        if stmts.len() != 1 {
            return Err(DbMcpError::InvalidArgument(
                "explain_query requires exactly one SQL statement".to_string(),
            ));
        }

        let trimmed = stmts[0].trim();
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("EXPLAIN") {
            return Err(DbMcpError::InvalidArgument(
                "Statement passed to explain_query must not already begin with EXPLAIN".to_string(),
            ));
        }

        let analysis = parse_and_analyze_sql(DatabaseEngine::Sqlite, trimmed)?;
        if analysis.overall_class.is_mutating() || analysis.has_privileged_functions {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "explain_query only supports read-only queries".to_string(),
                next_action: None,
            });
        }

        let explain_sql = format!("EXPLAIN QUERY PLAN {trimmed}");
        let params = request
            .params
            .iter()
            .map(json_to_sqlite_value)
            .collect::<DbMcpResult<Vec<_>>>()?;
        let conn_arc = Arc::clone(&self.conn);
        let connection_id = request.connection.clone();
        let orig_sql = request.sql.clone();
        let format = request.format;
        let analyze = request.analyze;

        tokio::task::spawn_blocking(move || {
            let guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("SQLite connection mutex poisoned".to_string())
            })?;
            let mut stmt = guard.prepare(&explain_sql).map_err(map_rusqlite_error)?;
            let mut rows = stmt
                .query(params_from_iter(params.iter()))
                .map_err(map_rusqlite_error)?;

            let mut steps = Vec::new();
            let mut text_lines = Vec::new();
            let mut seq_scans = Vec::new();
            let mut index_scans = Vec::new();

            while let Some(row) = rows.next().map_err(map_rusqlite_error)? {
                let id: i64 = row.get(0).unwrap_or(0);
                let parent: i64 = row.get(1).unwrap_or(0);
                let notused: i64 = row.get(2).unwrap_or(0);
                let detail: String = row.get(3).unwrap_or_default();

                parse_sqlite_explain_detail(&detail, &mut seq_scans, &mut index_scans);
                text_lines.push(format!("id={id} parent={parent} notused={notused} detail={detail}"));
                steps.push(serde_json::json!({
                    "id": id,
                    "parent": parent,
                    "notused": notused,
                    "detail": detail,
                }));
            }

            let mut warnings = Vec::new();
            if analyze {
                warnings.push(
                    "SQLite uses static EXPLAIN QUERY PLAN without executing mutations.".to_string(),
                );
            }
            for tbl in &seq_scans {
                warnings.push(format!(
                    "Sequential scan (SCAN {tbl}) detected; consider an index on filter/join columns."
                ));
            }

            let estimated_cost = Some(if !seq_scans.is_empty() {
                100.0 * (seq_scans.len() as f64)
            } else {
                10.0 * (steps.len().max(1) as f64)
            });
            let estimated_rows = Some(if !seq_scans.is_empty() { 100.0 } else { 10.0 });

            let structured_plan = serde_json::json!({
                "engine": "sqlite",
                "steps": steps,
                "seq_scans": seq_scans,
                "index_scans": index_scans,
            });

            let raw_plan = match format {
                ExplainFormat::Text => text_lines.join("\n"),
                ExplainFormat::Json => {
                    serde_json::to_string_pretty(&structured_plan).unwrap_or_else(|_| text_lines.join("\n"))
                }
            };

            Ok(ExplainPlan {
                connection: connection_id,
                sql: orig_sql,
                analyze,
                format,
                raw_plan,
                structured_plan: Some(structured_plan),
                estimated_cost,
                estimated_rows,
                seq_scans,
                index_scans,
                warnings,
            })
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("SQLite explain task join error: {e}")))?
    }

    async fn cancel(&self, execution: ExecutionId) -> DbMcpResult<bool> {
        self.cancelled_executions.insert(execution.clone(), Utc::now());
        if let Some((_, handle)) = self.active_executions.remove(&execution) {
            handle.interrupt();
            return Ok(true);
        }
        // Trigger interrupt on the primary handle as well in case an execution is acquiring the lock
        self.interrupt_handle.interrupt();
        Ok(true)
    }
}

fn execute_sqlite_query_inner(
    conn: &Connection,
    request: &AuthorizedQuery,
    default_schema: &str,
    started: Instant,
) -> DbMcpResult<QueryResult> {
    let (rewritten_sql, has_routines) =
        rewrite_sqlite_sql_for_routines(&request.sql, default_schema);
    if has_routines {
        ensure_sqlite_routines_table(conn)?;
    }

    let params = request
        .params
        .iter()
        .map(json_to_sqlite_value)
        .collect::<DbMcpResult<Vec<_>>>()?;
    let max_rows = if request.max_rows == 0 {
        usize::MAX
    } else {
        request.max_rows
    };
    let max_bytes = request.max_bytes;

    // `Connection::prepare` compiles only the first statement of a string and ignores the rest.
    // A batch that policy allowed (allow_multi_statement = true) is executed statement by
    // statement instead of silently dropping its tail.
    let statement_count = split_sql_statements(DatabaseEngine::Sqlite, &rewritten_sql)
        .iter()
        .filter(|piece| !normalize_sql(piece).is_empty())
        .count();
    if statement_count > 1 {
        return execute_sqlite_batch(
            conn,
            request,
            &rewritten_sql,
            &params,
            max_rows,
            max_bytes,
            default_schema,
            started,
        );
    }

    let mut stmt = conn.prepare(&rewritten_sql).map_err(map_rusqlite_error)?;

    if stmt.column_count() > 0 {
        let set = collect_sqlite_rows(&mut stmt, &params, max_rows, max_bytes)?;
        drop(stmt);

        let schema_version = introspect_sqlite_catalog(conn, default_schema)
            .ok()
            .map(|objs| compute_schema_version(&objs));

        let returned_rows = set.rows.len();
        Ok(QueryResult {
            execution_id: request.execution_id.clone(),
            columns: set.columns,
            rows: set.rows,
            returned_rows,
            rows_affected: None,
            truncated: set.truncated,
            bytes_used: set.bytes_used,
            execution_time_ms: started.elapsed().as_millis() as u64,
            warnings: set.warnings,
            schema_version,
        })
    } else {
        drop(stmt);
        let changed = conn
            .execute(&rewritten_sql, params_from_iter(params.iter()))
            .map_err(map_rusqlite_error)?;

        let schema_version = introspect_sqlite_catalog(conn, default_schema)
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
    }
}

/// Rows read from one row-returning SQLite statement, bounded by `max_rows` / `max_bytes`.
struct SqliteRowSet {
    columns: Vec<ColumnMetadata>,
    rows: Vec<Vec<serde_json::Value>>,
    bytes_used: usize,
    truncated: bool,
    warnings: Vec<String>,
}

fn collect_sqlite_rows(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[SqliteValue],
    max_rows: usize,
    max_bytes: usize,
) -> DbMcpResult<SqliteRowSet> {
    let col_count = stmt.column_count();
    let mut columns: Vec<ColumnMetadata> = stmt
        .column_names()
        .into_iter()
        .map(|name| ColumnMetadata::new(name, "ANY"))
        .collect();

    let mut rows_out: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut bytes_used = 0usize;
    let mut truncated = false;
    let mut warnings = Vec::new();

    let mut rows = stmt
        .query(params_from_iter(params.iter()))
        .map_err(map_rusqlite_error)?;

    while let Some(row) = rows.next().map_err(map_rusqlite_error)? {
        if rows_out.len() >= max_rows {
            truncated = true;
            warnings.push(format!(
                "Result truncated at max_rows={max_rows}"
            ));
            break;
        }

        let mut row_vals = Vec::with_capacity(col_count);
        let mut row_bytes = 0usize;
        for i in 0..col_count {
            let val_ref = row.get_ref(i).map_err(map_rusqlite_error)?;
            let (json_val, inferred_type, val_bytes) = sqlite_value_ref_to_json(val_ref);
            if columns[i].data_type == "ANY" && inferred_type != "NULL" {
                columns[i].data_type = inferred_type.to_string();
            }
            row_bytes += val_bytes;
            row_vals.push(json_val);
        }

        if max_bytes > 0 && bytes_used + row_bytes > max_bytes && !rows_out.is_empty() {
            truncated = true;
            warnings.push(format!(
                "Result truncated at max_bytes={max_bytes} budget"
            ));
            break;
        }

        bytes_used += row_bytes;
        rows_out.push(row_vals);
    }

    Ok(SqliteRowSet {
        columns,
        rows: rows_out,
        bytes_used,
        truncated,
        warnings,
    })
}

/// Execute every statement of a multi-statement batch in order. The result set is the one of
/// the last row-returning statement; `rows_affected` sums the data-changing statements.
#[allow(clippy::too_many_arguments)]
fn execute_sqlite_batch(
    conn: &Connection,
    request: &AuthorizedQuery,
    sql: &str,
    params: &[SqliteValue],
    max_rows: usize,
    max_bytes: usize,
    default_schema: &str,
    started: Instant,
) -> DbMcpResult<QueryResult> {
    if !params.is_empty() {
        return Err(DbMcpError::InvalidArgument(
            "Bound parameters are not supported in a multi-statement batch; send one statement per call"
                .to_string(),
        ));
    }

    let mut batch = Batch::new(conn, sql);
    let mut executed = 0usize;
    let mut rows_affected: Option<u64> = None;
    let mut last_set: Option<(usize, SqliteRowSet)> = None;
    loop {
        let next = batch
            .next()
            .map_err(|err| batch_statement_error(map_rusqlite_error(err), executed))?;
        let Some(mut stmt) = next else {
            break;
        };
        if stmt.column_count() > 0 {
            let set = collect_sqlite_rows(&mut stmt, &[], max_rows, max_bytes)
                .map_err(|err| batch_statement_error(err, executed))?;
            executed += 1;
            last_set = Some((executed, set));
        } else {
            let changed = stmt
                .execute([])
                .map_err(|err| batch_statement_error(map_rusqlite_error(err), executed))?;
            executed += 1;
            *rows_affected.get_or_insert(0) += changed as u64;
        }
    }

    let schema_version = introspect_sqlite_catalog(conn, default_schema)
        .ok()
        .map(|objs| compute_schema_version(&objs));

    let mut warnings = Vec::new();
    let (columns, rows, bytes_used, truncated) = match last_set {
        Some((index, set)) => {
            if executed > 1 {
                warnings.push(format!(
                    "Executed {executed} statements as one batch; the result set is from statement {index}."
                ));
            }
            warnings.extend(set.warnings);
            (set.columns, set.rows, set.bytes_used, set.truncated)
        }
        None => {
            if executed > 1 {
                warnings.push(format!(
                    "Executed {executed} statements as one batch; no statement returned rows."
                ));
            }
            (Vec::new(), Vec::new(), 0, false)
        }
    };

    let returned_rows = rows.len();
    Ok(QueryResult {
        execution_id: request.execution_id.clone(),
        columns,
        rows,
        returned_rows,
        rows_affected,
        truncated,
        bytes_used,
        execution_time_ms: started.elapsed().as_millis() as u64,
        warnings,
        schema_version,
    })
}

/// Name the failing statement of a batch; the statements before it were already applied.
fn batch_statement_error(err: DbMcpError, applied: usize) -> DbMcpError {
    match err {
        DbMcpError::AdapterError(msg) => DbMcpError::AdapterError(format!(
            "Statement {} of the batch failed ({applied} earlier statement(s) already applied): {msg}",
            applied + 1
        )),
        other => other,
    }
}

#[async_trait]
impl SchemaDiffProvider for SqliteAdapter {
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
        let discovered = self.discover(req).await?;
        Ok(build_schema_snapshot(
            connection,
            DatabaseEngine::Sqlite,
            discovered.objects,
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
impl TransactionalDdlProvider for SqliteAdapter {
    fn supports_transactional_ddl(&self) -> bool {
        true
    }

    async fn execute_transactional_ddl(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
        if self.config.read_only || request.read_only {
            return Err(DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "Cannot execute DDL on a read-only SQLite connection".to_string(),
                next_action: Some("propose_change".to_string()),
            });
        }

        let conn_arc = Arc::clone(&self.conn);
        let default_schema = self.config.default_schema.clone();
        let (rewritten_batch, has_routines) =
            rewrite_sqlite_sql_for_routines(&request.sql, &default_schema);
        let stmts = split_sql_statements(DatabaseEngine::Sqlite, &rewritten_batch);
        if stmts.is_empty() {
            return Err(DbMcpError::InvalidArgument(
                "Transactional DDL SQL must not be empty".to_string(),
            ));
        }

        tokio::task::spawn_blocking(move || {
            let started = Instant::now();
            let mut guard = conn_arc.lock().map_err(|_| {
                DbMcpError::InternalError("SQLite connection mutex poisoned".to_string())
            })?;

            if has_routines {
                ensure_sqlite_routines_table(&guard)?;
            }

            let tx = guard.transaction().map_err(map_rusqlite_error)?;
            let params = request
                .params
                .iter()
                .map(json_to_sqlite_value)
                .collect::<DbMcpResult<Vec<_>>>()?;
            let mut total_affected = 0u64;

            for (idx, stmt_sql) in stmts.iter().enumerate() {
                let res = if idx == 0 && !params.is_empty() {
                    tx.execute(stmt_sql, params_from_iter(params.iter()))
                } else {
                    tx.execute(stmt_sql, [])
                };
                match res {
                    Ok(changed) => {
                        total_affected += changed as u64;
                    }
                    Err(err) => {
                        let _ = tx.rollback();
                        return Err(map_rusqlite_error(err));
                    }
                }
            }

            tx.commit().map_err(map_rusqlite_error)?;

            let schema_version = introspect_sqlite_catalog(&guard, &default_schema)
                .ok()
                .map(|objs| compute_schema_version(&objs));

            Ok(QueryResult {
                execution_id: request.execution_id,
                columns: vec![ColumnMetadata::new("status", "TEXT")],
                rows: vec![vec![serde_json::Value::String("committed".to_string())]],
                returned_rows: 1,
                rows_affected: Some(total_affected),
                truncated: false,
                bytes_used: 9,
                execution_time_ms: started.elapsed().as_millis() as u64,
                warnings: Vec::new(),
                schema_version,
            })
        })
        .await
        .map_err(|e| DbMcpError::InternalError(format!("SQLite transactional DDL join error: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{CallerIdentity, DiffOperationKind, ExecutionLimits, SqlStatementClass};

    const SAMPLE_SEED: &str = r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL DEFAULT 'member'
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            total_cents INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_orders_user_id ON orders(user_id);
        CREATE INDEX idx_orders_status_created ON orders(status, created_at);
        CREATE VIEW completed_orders_view AS
            SELECT id, user_id, total_cents FROM orders WHERE status = 'completed';

        INSERT INTO users (id, email, role) VALUES
            (1, 'alice@example.com', 'admin'),
            (2, 'bob@example.com', 'member'),
            (3, 'carol@example.com', 'member');

        INSERT INTO orders (id, user_id, status, total_cents, created_at) VALUES
            (101, 1, 'completed', 14900, '2026-10-01T10:00:00Z'),
            (102, 2, 'completed', 4900, '2026-10-02T11:00:00Z'),
            (103, 2, 'pending', 8900, '2026-10-03T12:00:00Z'),
            (104, 3, 'cancelled', 1900, '2026-10-04T13:00:00Z');
    "#;

    #[tokio::test]
    async fn test_sqlite_progressive_discovery_and_describe() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();

        // 1. Names detail level
        let names_req = CatalogRequest {
            connection: "sqlite-sample".to_string(),
            schema_pattern: Some("main".to_string()),
            name_pattern: None,
            object_types: vec![CatalogObjectType::Table],
            detail_level: CatalogDetailLevel::Names,
            limit: 10,
            offset: 0,
        };
        let names_resp = adapter.discover(names_req).await.unwrap();
        assert_eq!(names_resp.total_count, 2);
        assert!(names_resp.objects[0].columns.is_empty());
        assert!(names_resp
            .schema_version
            .as_deref()
            .unwrap()
            .starts_with("snapshot_"));

        // 2. Full detail level with foreign keys and indexes
        let orders_obj = adapter
            .describe_object(Some("main"), "orders", CatalogDetailLevel::Full)
            .await
            .unwrap();
        assert_eq!(orders_obj.name, "orders");
        assert_eq!(orders_obj.estimated_rows, Some(4));
        assert_eq!(orders_obj.columns.len(), 5);
        assert_eq!(orders_obj.indexes.len(), 2);
        assert_eq!(orders_obj.foreign_keys.len(), 1);
        assert_eq!(orders_obj.foreign_keys[0].referenced_table, "users");
    }

    #[tokio::test]
    async fn test_sqlite_parameter_binding_row_truncation_and_readonly() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();
        let limits = ExecutionLimits {
            timeout_ms: 5_000,
            max_rows: 1,
            max_bytes: 1_048_576,
            allow_multi_statement: false,
        };

        let query = AuthorizedQuery::new_read(
            "req_1",
            "sqlite-sample",
            CallerIdentity::local_agent("agent"),
            "SELECT id, user_id, status, total_cents FROM orders WHERE status = ?1 ORDER BY id ASC",
            vec![serde_json::json!("completed")],
            &limits,
        );
        let result = adapter.execute(query).await.unwrap();
        assert_eq!(result.returned_rows, 1);
        assert!(result.truncated);
        assert_eq!(result.rows[0][0], serde_json::json!(101));
        assert_eq!(result.rows[0][3], serde_json::json!(14900));

        // Attempt a write with read_only = true -> must fail closed with READONLY_VIOLATION
        let mut ro_write = AuthorizedQuery::new_read(
            "req_2",
            "sqlite-sample",
            CallerIdentity::local_agent("agent"),
            "DELETE FROM orders WHERE id = 104",
            vec![],
            &ExecutionLimits::default(),
        );
        ro_write.statement_class = SqlStatementClass::Write;
        ro_write.read_only = true;
        let err = adapter.execute(ro_write).await.unwrap_err();
        assert_eq!(err.code(), "READONLY_VIOLATION");
    }

    #[tokio::test]
    async fn test_sqlite_multi_statement_batch_executes_every_statement() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();
        let limits = ExecutionLimits {
            allow_multi_statement: true,
            ..ExecutionLimits::default()
        };
        let write = |id: &str, sql: &str, params: Vec<serde_json::Value>| {
            let mut q = AuthorizedQuery::new_read(
                id,
                "sqlite-sample",
                CallerIdentity::local_agent("agent"),
                sql,
                params,
                &limits,
            );
            q.statement_class = SqlStatementClass::Write;
            q.read_only = false;
            q
        };

        let result = adapter
            .execute(write(
                "req_batch",
                "SELECT 1 AS a; INSERT INTO users (id, email) VALUES (9, 'z@example.com'); SELECT count(*) AS b FROM users;",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(result.columns[0].name, "b");
        assert_eq!(result.rows[0][0], serde_json::json!(4));
        assert_eq!(result.rows_affected, Some(1));
        assert!(result.warnings.iter().any(|w| w.contains("Executed 3 statements")), "{:?}", result.warnings);

        // Parameters cannot be bound across a batch: rejected before any statement runs.
        let err = adapter
            .execute(write(
                "req_batch_params",
                "INSERT INTO users (id, email) VALUES (?1, 'p@example.com'); SELECT 1",
                vec![serde_json::json!(10)],
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGUMENT");

        // A failing statement names its position; earlier statements stay applied.
        let err = adapter
            .execute(write(
                "req_batch_fail",
                "INSERT INTO users (id, email) VALUES (11, 'q@example.com'); SELECT * FROM no_such_table",
                vec![],
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Statement 2 of the batch failed"), "{err}");

        let count = adapter
            .execute(write("req_count", "SELECT count(*) FROM users WHERE id IN (10, 11)", vec![]))
            .await
            .unwrap();
        assert_eq!(count.rows[0][0], serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_sqlite_explain_query_plan_extraction() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();

        // Indexed lookup
        let idx_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_exp_1".to_string(),
                connection: "sqlite-sample".to_string(),
                sql: "SELECT * FROM orders WHERE user_id = 2".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Json,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(idx_plan
            .index_scans
            .contains(&"idx_orders_user_id".to_string()));
        assert!(idx_plan.seq_scans.is_empty());

        // Full table scan on unindexed column
        let seq_plan = adapter
            .explain(ExplainRequest {
                request_id: "req_exp_2".to_string(),
                connection: "sqlite-sample".to_string(),
                sql: "SELECT * FROM orders WHERE total_cents > 5000".to_string(),
                params: vec![],
                analyze: false,
                format: ExplainFormat::Text,
                timeout_ms: 5_000,
            })
            .await
            .unwrap();
        assert!(seq_plan.seq_scans.contains(&"orders".to_string()));
        assert!(!seq_plan.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_sqlite_cancellation_and_transactional_ddl_diff() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();

        let snap_before = adapter.capture_schema("sqlite-sample", None).await.unwrap();

        // Execute transactional DDL adding an index and a column
        let ddl_query = AuthorizedQuery {
            request_id: "req_ddl_1".to_string(),
            execution_id: ExecutionId::new(),
            connection: "sqlite-sample".to_string(),
            caller: CallerIdentity::admin("dba"),
            sql: "ALTER TABLE users ADD COLUMN display_name TEXT; CREATE INDEX idx_users_role ON users(role);".to_string(),
            normalized_sql: "ALTER TABLE users ADD COLUMN display_name TEXT; CREATE INDEX idx_users_role ON users(role)".to_string(),
            sql_hash: "hash".to_string(),
            params: vec![],
            statement_class: SqlStatementClass::Ddl,
            read_only: false,
            timeout_ms: 5_000,
            max_rows: 100,
            max_bytes: 1_048_576,
            change_id: Some("chg_1".to_string()),
        };
        let ddl_res = adapter.execute_transactional_ddl(ddl_query).await.unwrap();
        assert_eq!(ddl_res.returned_rows, 1);

        let snap_after = adapter.capture_schema("sqlite-sample", None).await.unwrap();
        let diff = adapter.diff_schema(&snap_before, &snap_after).await.unwrap();
        assert!(!diff.is_identical);
        assert!(diff.all_transactional);
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AddColumn
                && i.target_name.as_deref() == Some("display_name")));
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AddIndex
                && i.target_name.as_deref() == Some("idx_users_role")));

        // Verify cancellation tracking via ExecutionId
        let cancel_exec_id = ExecutionId::new();
        let cancelled_ok = adapter.cancel(cancel_exec_id.clone()).await.unwrap();
        assert!(cancelled_ok);

        let mut cancelled_req = AuthorizedQuery::new_read(
            "req_cancel",
            "sqlite-sample",
            CallerIdentity::local_agent("agent"),
            "SELECT * FROM users",
            vec![],
            &ExecutionLimits::default(),
        );
        cancelled_req.execution_id = cancel_exec_id;
        let cancel_err = adapter.execute(cancelled_req).await.unwrap_err();
        assert_eq!(cancel_err.code(), "EXECUTION_CANCELLED");
    }

    #[tokio::test]
    async fn test_sqlite_routines_introspection_and_ddl_interception() {
        let adapter =
            SqliteAdapter::open_memory_with_seed("sqlite-sample", SAMPLE_SEED).unwrap();

        adapter
            .execute_batch(
                r#"
                CREATE PROCEDURE record_order_audit(order_id INTEGER, event_type TEXT)
                BEGIN
                    INSERT INTO audit_logs (order_id, event_type)
                    SELECT id, event_type FROM orders WHERE id = order_id;
                END;

                CREATE FUNCTION calculate_order_discount(order_id INTEGER)
                RETURNS NUMERIC
                BEGIN
                    SELECT o.total_cents FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = order_id;
                END;
                "#,
            )
            .unwrap();

        let routines = adapter
            .discover(CatalogRequest {
                connection: "sqlite-sample".to_string(),
                schema_pattern: Some("main".to_string()),
                name_pattern: None,
                object_types: vec![CatalogObjectType::Procedure, CatalogObjectType::Function],
                detail_level: CatalogDetailLevel::Full,
                limit: 20,
                offset: 0,
            })
            .await
            .unwrap();

        assert_eq!(routines.total_count, 2);
        let audit_proc = routines
            .objects
            .iter()
            .find(|o| o.name == "record_order_audit")
            .unwrap();
        assert_eq!(audit_proc.object_type, CatalogObjectType::Procedure);
        assert!(audit_proc
            .definition
            .as_deref()
            .unwrap()
            .contains("INSERT INTO audit_logs"));

        let discount_fn = routines
            .objects
            .iter()
            .find(|o| o.name == "calculate_order_discount")
            .unwrap();
        assert_eq!(discount_fn.object_type, CatalogObjectType::Function);
        assert!(discount_fn
            .definition
            .as_deref()
            .unwrap()
            .contains("JOIN users"));
    }

    #[test]
    fn test_dollar_quoted_routine_after_begin_end_routine_does_not_swallow_it() {
        let sql = r#"
CREATE PROCEDURE first_proc(x INTEGER)
BEGIN
    INSERT INTO t VALUES (x);
END;
CREATE FUNCTION dollar_fn(x INTEGER) RETURNS INTEGER AS $$
BEGIN
    RETURN x;
END;
$$ LANGUAGE plpgsql;
"#;
        let out = rewrite_sqlite_sql_for_routines(sql, "main").0;
        assert!(out.contains("'first_proc'"), "{out}");
        assert!(out.contains("'dollar_fn'"), "{out}");
        let first = out.split("'dollar_fn'").next().unwrap();
        assert!(!first.contains("RETURNS INTEGER AS $$"), "first_proc swallowed dollar_fn: {out}");
    }
}
