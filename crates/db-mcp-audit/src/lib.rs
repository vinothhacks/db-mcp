//! Structured audit trail persistence (In-Memory, JSONL, and SQLite stores) with credential redaction
//! and cryptographic hash-chain verification.
//!
//! Responsibilities:
//! - Ensure all logged SQL, parameters, and error messages pass through
//!   `db_mcp_secrets::redact_sensitive_text` before persistence.
//! - Provide `AuditSink` trait and concrete stores:
//!   - `InMemoryAuditStore` (`Arc<RwLock<Vec<AuditEvent>>>`)
//!   - `JsonlAuditStore` (append-only JSONL file writer + reader)
//!   - `SqliteAuditStore` (`audit_events` SQLite table with `list_events`, `get_by_request_id`, and `verify_chain`)
//!   - `CompositeAuditStore` (fans out to memory + JSONL + SQLite)

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use db_mcp_core::{
    AuditDecision, AuditEvent, CallerIdentity, DbMcpError, DbMcpResult, OperatingMode,
    SqlStatementClass,
};
use db_mcp_secrets::redact_sensitive_text;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Genesis marker for the first event in an audit hash chain.
pub const GENESIS_CHAIN_HASH: &str = "GENESIS";

/// Sanitize an `AuditEvent` by passing SQL, error messages, and identifiers through
/// `db_mcp_secrets::redact_sensitive_text` so credentials never reach persistent storage.
pub fn sanitize_audit_event(mut event: AuditEvent) -> AuditEvent {
    event.principal = redact_sensitive_text(&event.principal);
    event.connection = redact_sensitive_text(&event.connection);
    if let Some(sql) = event.normalized_sql.take() {
        // Persist a literal-free fingerprint: string/number literals (PII, secrets) become `?`.
        // `sql_hash` is recomputed over the same fingerprint so it cannot be used to confirm
        // guessed literal values offline.
        let fingerprint = redact_sensitive_text(&db_mcp_sql::fingerprint_sql(&sql));
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_bytes());
        event.sql_hash = Some(hex::encode(hasher.finalize()));
        event.normalized_sql = Some(fingerprint);
    }
    if let Some(err) = event.error_message.take() {
        event.error_message = Some(redact_sensitive_text(&err));
    }
    event
}

/// Sanitize a slice of query parameter values using `db_mcp_secrets::redact_sensitive_text`.
pub fn sanitize_audit_parameters(params: &[serde_json::Value]) -> Vec<serde_json::Value> {
    params.iter().cloned().map(sanitize_json_param).collect()
}

fn sanitize_json_param(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(redact_sensitive_text(&s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sanitize_json_param).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, sanitize_json_param(v)))
                .collect(),
        ),
        other => other,
    }
}

/// Deterministically compute the SHA-256 chain hash linking `prev_hash` and `event`.
pub fn compute_event_chain_hash(prev_hash: &str, event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    let payload = format!(
        "v1|prev={prev_hash}|id={}|req={}|ts={}|principal={}|role={}|conn={}|mode={}|tool={}|sql_hash={}|sql={}|class={}|decision={:?}|denial={}|change={}|rows={}|trunc={}|ms={}|schema={}|err={}",
        event.event_id,
        event.request_id,
        event.timestamp.to_rfc3339(),
        event.principal,
        event.role,
        event.connection,
        event.operating_mode,
        event.tool_name,
        event.sql_hash.as_deref().unwrap_or(""),
        event.normalized_sql.as_deref().unwrap_or(""),
        event.statement_class.map(|c| c.as_str()).unwrap_or(""),
        event.decision,
        event.denial_code.as_deref().unwrap_or(""),
        event.change_id.as_deref().unwrap_or(""),
        event.returned_rows.map(|r| r.to_string()).unwrap_or_default(),
        event.truncated.map(|t| t.to_string()).unwrap_or_default(),
        event.execution_time_ms.map(|m| m.to_string()).unwrap_or_default(),
        event.schema_version.as_deref().unwrap_or(""),
        event.error_message.as_deref().unwrap_or(""),
    );
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// Helper to construct a sanitized `AuditEvent`.
#[allow(clippy::too_many_arguments)]
pub fn create_audit_event(
    request_id: impl Into<String>,
    caller: &CallerIdentity,
    connection: impl Into<String>,
    operating_mode: OperatingMode,
    tool_name: impl Into<String>,
    sql_hash: Option<String>,
    normalized_sql: Option<String>,
    statement_class: Option<SqlStatementClass>,
    decision: AuditDecision,
    denial_code: Option<String>,
    change_id: Option<String>,
    returned_rows: Option<usize>,
    truncated: Option<bool>,
    execution_time_ms: Option<u64>,
    schema_version: Option<String>,
    error_message: Option<String>,
) -> AuditEvent {
    sanitize_audit_event(AuditEvent {
        event_id: format!("evt_{}", Uuid::new_v4().simple()),
        request_id: request_id.into(),
        timestamp: Utc::now(),
        principal: caller.principal.clone(),
        role: caller.role.clone(),
        transport: caller.transport.clone(),
        connection: connection.into(),
        operating_mode,
        tool_name: tool_name.into(),
        sql_hash,
        normalized_sql,
        statement_class,
        decision,
        denial_code,
        change_id,
        returned_rows,
        truncated,
        execution_time_ms,
        schema_version,
        error_message,
    })
}

/// Filter criteria for querying stored `AuditEvent`s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    pub connection: Option<String>,
    pub principal: Option<String>,
    pub tool_name: Option<String>,
    pub decision: Option<AuditDecision>,
    pub request_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl AuditFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_connection(mut self, connection: impl Into<String>) -> Self {
        self.connection = Some(connection.into());
        self
    }

    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    pub fn with_tool_name(mut self, tool_name: impl Into<String>) -> Self {
        self.tool_name = Some(tool_name.into());
        self
    }

    pub fn with_decision(mut self, decision: AuditDecision) -> Self {
        self.decision = Some(decision);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Check whether `event` matches this filter.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(conn) = &self.connection {
            if &event.connection != conn {
                return false;
            }
        }
        if let Some(principal) = &self.principal {
            if &event.principal != principal {
                return false;
            }
        }
        if let Some(tool) = &self.tool_name {
            if &event.tool_name != tool {
                return false;
            }
        }
        if let Some(dec) = &self.decision {
            if &event.decision != dec {
                return false;
            }
        }
        if let Some(req_id) = &self.request_id {
            if &event.request_id != req_id {
                return false;
            }
        }
        true
    }

    /// Apply filter, offset, and limit to an in-memory slice of `AuditEvent`s.
    pub fn apply(&self, events: &[AuditEvent]) -> Vec<AuditEvent> {
        let filtered_iter = events.iter().filter(|e| self.matches(e));
        let skipped: Box<dyn Iterator<Item = &AuditEvent>> = match self.offset {
            Some(off) => Box::new(filtered_iter.skip(off)),
            None => Box::new(filtered_iter),
        };
        match self.limit {
            Some(lim) => skipped.take(lim).cloned().collect(),
            None => skipped.cloned().collect(),
        }
    }
}

/// Detailed verification report for an audit hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainReport {
    pub valid: bool,
    pub total_events: usize,
    pub last_chain_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Trait implemented by all audit persistence backends.
pub trait AuditSink: Send + Sync {
    /// Sanitize and persist an `AuditEvent`.
    fn record(&self, event: AuditEvent) -> DbMcpResult<()>;

    /// Alias for `record`.
    fn append(&self, event: AuditEvent) -> DbMcpResult<()> {
        self.record(event)
    }

    /// List audit events matching `filter`.
    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>>;

    /// Retrieve audit events matching a specific `request_id`.
    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        self.list_events(&AuditFilter::new().with_request_id(request_id))
    }

    /// Verify the integrity of the persisted audit chain.
    fn verify_chain(&self) -> DbMcpResult<bool> {
        Ok(true)
    }
}

/// Thread-safe in-memory audit store backed by `Arc<RwLock<Vec<AuditEvent>>>`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAuditStore {
    events: Arc<RwLock<Vec<AuditEvent>>>,
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn shared_events(&self) -> Arc<RwLock<Vec<AuditEvent>>> {
        Arc::clone(&self.events)
    }

    pub fn len(&self) -> usize {
        self.events.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn all_events(&self) -> Vec<AuditEvent> {
        self.events.read().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        let sanitized = sanitize_audit_event(event);
        let mut guard = self.events.write().map_err(|e| {
            DbMcpError::StorageError(format!("InMemoryAuditStore lock poisoned: {e}"))
        })?;
        guard.push(sanitized);
        Ok(())
    }

    pub fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        let guard = self.events.read().map_err(|e| {
            DbMcpError::StorageError(format!("InMemoryAuditStore lock poisoned: {e}"))
        })?;
        Ok(filter.apply(&guard))
    }

    pub fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        self.list_events(&AuditFilter::new().with_request_id(request_id))
    }

    pub fn verify_chain(&self) -> DbMcpResult<bool> {
        Ok(true)
    }
}

impl AuditSink for InMemoryAuditStore {
    fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        InMemoryAuditStore::record(self, event)
    }

    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        InMemoryAuditStore::list_events(self, filter)
    }

    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        InMemoryAuditStore::get_by_request_id(self, request_id)
    }

    fn verify_chain(&self) -> DbMcpResult<bool> {
        InMemoryAuditStore::verify_chain(self)
    }
}

/// Envelope written per line in `JsonlAuditStore` including hash-chain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonlAuditRecord {
    prev_hash: String,
    chain_hash: String,
    #[serde(flatten)]
    event: AuditEvent,
}

/// Append-only JSONL file writer and reader for `AuditEvent`s.
#[derive(Debug, Clone)]
pub struct JsonlAuditStore {
    path: PathBuf,
    write_lock: Arc<Mutex<()>>,
}

impl JsonlAuditStore {
    pub fn new(path: impl Into<PathBuf>) -> DbMcpResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to create audit log directory '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        if !path.exists() {
            File::create(&path).map_err(|e| {
                DbMcpError::StorageError(format!(
                    "Failed to initialize JSONL audit file '{}': {e}",
                    path.display()
                ))
            })?;
        }
        Ok(Self {
            path,
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_records_locked(&self) -> DbMcpResult<Vec<JsonlAuditRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to open JSONL audit file '{}': {e}",
                self.path.display()
            ))
        })?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for (line_idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| {
                DbMcpError::StorageError(format!(
                    "Failed to read line {} of JSONL audit file '{}': {e}",
                    line_idx + 1,
                    self.path.display()
                ))
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<JsonlAuditRecord>(trimmed) {
                records.push(rec);
            } else {
                let event: AuditEvent = serde_json::from_str(trimmed).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Malformed JSONL audit record on line {}: {e}",
                        line_idx + 1
                    ))
                })?;
                let prev_hash = records
                    .last()
                    .map(|r: &JsonlAuditRecord| r.chain_hash.clone())
                    .unwrap_or_else(|| GENESIS_CHAIN_HASH.to_string());
                let chain_hash = compute_event_chain_hash(&prev_hash, &event);
                records.push(JsonlAuditRecord {
                    prev_hash,
                    chain_hash,
                    event,
                });
            }
        }
        Ok(records)
    }

    /// Take an exclusive OS lock on `<path>.lock`, held until the returned handle is dropped.
    fn acquire_process_lock(&self) -> DbMcpResult<File> {
        let mut lock_path = self.path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| {
                DbMcpError::StorageError(format!(
                    "Failed to open JSONL audit lock file '{}': {e}",
                    PathBuf::from(&lock_path).display()
                ))
            })?;
        lock_file.lock().map_err(|e| {
            DbMcpError::StorageError(format!("Failed to lock JSONL audit file: {e}"))
        })?;
        Ok(lock_file)
    }

    /// Return the `chain_hash` of the last JSONL record by reading only the file tail.
    ///
    /// Returns `Ok(Some(GENESIS))` for an empty file and `Ok(None)` when the tail is not a
    /// chained record (legacy line), in which case the caller falls back to a full scan.
    fn read_last_record_chain_hash(&self) -> DbMcpResult<Option<String>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Ok(Some(GENESIS_CHAIN_HASH.to_string())),
        };
        let len = file
            .metadata()
            .map_err(|e| DbMcpError::StorageError(format!("Failed to stat JSONL audit file: {e}")))?
            .len();
        if len == 0 {
            return Ok(Some(GENESIS_CHAIN_HASH.to_string()));
        }
        let mut chunk: u64 = 64 * 1024;
        loop {
            let start = len.saturating_sub(chunk);
            file.seek(SeekFrom::Start(start)).map_err(|e| {
                DbMcpError::StorageError(format!("Failed to seek JSONL audit file: {e}"))
            })?;
            let mut buf = Vec::with_capacity((len - start) as usize);
            file.read_to_end(&mut buf).map_err(|e| {
                DbMcpError::StorageError(format!("Failed to read JSONL audit file: {e}"))
            })?;
            let text = String::from_utf8_lossy(&buf);
            let trimmed = text.trim_end();
            if trimmed.is_empty() {
                return Ok(Some(GENESIS_CHAIN_HASH.to_string()));
            }
            match trimmed.rfind('\n') {
                Some(pos) => {
                    let last = trimmed[pos + 1..].trim();
                    return Ok(serde_json::from_str::<JsonlAuditRecord>(last)
                        .ok()
                        .map(|r| r.chain_hash));
                }
                None if start == 0 => {
                    return Ok(serde_json::from_str::<JsonlAuditRecord>(trimmed)
                        .ok()
                        .map(|r| r.chain_hash));
                }
                None => chunk = chunk.saturating_mul(4),
            }
        }
    }

    /// Read all persisted `AuditEvent`s from the JSONL file.
    pub fn read_all(&self) -> DbMcpResult<Vec<AuditEvent>> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("JsonlAuditStore lock poisoned: {e}")))?;
        let records = self.read_records_locked()?;
        Ok(records.into_iter().map(|r| r.event).collect())
    }

    pub fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        let sanitized = sanitize_audit_event(event);
        let _guard = self
            .write_lock
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("JsonlAuditStore lock poisoned: {e}")))?;

        // Cross-process exclusive lock (sibling `.lock` file) so read-tail + append is atomic
        // even when several processes share this audit file.
        let _file_lock = self.acquire_process_lock()?;

        let prev_hash = match self.read_last_record_chain_hash()? {
            Some(hash) => hash,
            None => self
                .read_records_locked()?
                .last()
                .map(|r| r.chain_hash.clone())
                .unwrap_or_else(|| GENESIS_CHAIN_HASH.to_string()),
        };
        let chain_hash = compute_event_chain_hash(&prev_hash, &sanitized);

        let record = JsonlAuditRecord {
            prev_hash,
            chain_hash,
            event: sanitized,
        };
        let mut line = serde_json::to_string(&record).map_err(|e| {
            DbMcpError::StorageError(format!("Failed to serialize audit event: {e}"))
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| {
                DbMcpError::StorageError(format!(
                    "Failed to open JSONL audit file '{}' for append: {e}",
                    self.path.display()
                ))
            })?;
        file.write_all(line.as_bytes()).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to write to JSONL audit file '{}': {e}",
                self.path.display()
            ))
        })?;
        file.flush().map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to flush JSONL audit file '{}': {e}",
                self.path.display()
            ))
        })?;
        Ok(())
    }

    pub fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        let all = self.read_all()?;
        Ok(filter.apply(&all))
    }

    pub fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        self.list_events(&AuditFilter::new().with_request_id(request_id))
    }

    pub fn verify_chain(&self) -> DbMcpResult<bool> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("JsonlAuditStore lock poisoned: {e}")))?;
        let records = self.read_records_locked()?;
        let mut expected_prev = GENESIS_CHAIN_HASH.to_string();
        for rec in records {
            if rec.prev_hash != expected_prev {
                return Ok(false);
            }
            let computed = compute_event_chain_hash(&rec.prev_hash, &rec.event);
            if rec.chain_hash != computed {
                return Ok(false);
            }
            expected_prev = rec.chain_hash;
        }
        Ok(true)
    }
}

impl AuditSink for JsonlAuditStore {
    fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        JsonlAuditStore::record(self, event)
    }

    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        JsonlAuditStore::list_events(self, filter)
    }

    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        JsonlAuditStore::get_by_request_id(self, request_id)
    }

    fn verify_chain(&self) -> DbMcpResult<bool> {
        JsonlAuditStore::verify_chain(self)
    }
}

/// SQLite-backed audit store persisting `AuditEvent` records into an `audit_events` table
/// with hash-chain tamper detection (`verify_chain`) and indexed lookup (`list_events`, `get_by_request_id`).
#[derive(Clone)]
pub struct SqliteAuditStore {
    conn: Arc<Mutex<Connection>>,
    db_path: Option<PathBuf>,
}

impl std::fmt::Debug for SqliteAuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteAuditStore")
            .field("db_path", &self.db_path)
            .finish()
    }
}

impl SqliteAuditStore {
    /// Open or create a persistent SQLite audit store at `path`.
    pub fn open(path: impl AsRef<Path>) -> DbMcpResult<Self> {
        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to create directory for SQLite audit store '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        let conn = Connection::open(&path_buf).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to open SQLite audit database '{}': {e}",
                path_buf.display()
            ))
        })?;
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to set SQLite audit busy_timeout: {e}"))
            })?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: Some(path_buf),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory SQLite audit store (useful for unit and integration tests).
    pub fn in_memory() -> DbMcpResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            DbMcpError::StorageError(format!("Failed to open in-memory SQLite audit store: {e}"))
        })?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: None,
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    fn init_schema(&self) -> DbMcpResult<()> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("SQLite audit lock poisoned: {e}")))?;
        guard
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    role TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    connection TEXT NOT NULL,
                    operating_mode TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    sql_hash TEXT,
                    normalized_sql TEXT,
                    statement_class TEXT,
                    decision TEXT NOT NULL,
                    denial_code TEXT,
                    change_id TEXT,
                    returned_rows INTEGER,
                    truncated INTEGER,
                    execution_time_ms INTEGER,
                    schema_version TEXT,
                    error_message TEXT,
                    prev_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_request_id ON audit_events(request_id);
                CREATE INDEX IF NOT EXISTS idx_audit_events_connection ON audit_events(connection);
                CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_events_principal ON audit_events(principal);
                ",
            )
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to initialize audit_events schema: {e}"))
            })?;
        Ok(())
    }

    pub fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        let sanitized = sanitize_audit_event(event);
        let guard = self
            .conn
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("SQLite audit lock poisoned: {e}")))?;

        // BEGIN IMMEDIATE takes the write lock before reading the chain tip, so a second
        // process cannot append between our read and insert (busy_timeout makes it wait).
        guard.execute_batch("BEGIN IMMEDIATE").map_err(|e| {
            DbMcpError::StorageError(format!("Failed to begin audit transaction: {e}"))
        })?;
        let result = Self::record_in_tx(&guard, sanitized);
        match &result {
            Ok(()) => {
                if let Err(e) = guard.execute_batch("COMMIT") {
                    let _ = guard.execute_batch("ROLLBACK");
                    return Err(DbMcpError::StorageError(format!(
                        "Failed to commit audit transaction: {e}"
                    )));
                }
            }
            Err(_) => {
                let _ = guard.execute_batch("ROLLBACK");
            }
        }
        result
    }

    fn record_in_tx(guard: &Connection, sanitized: AuditEvent) -> DbMcpResult<()> {
        let prev_hash: String = match guard.query_row(
            "SELECT chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        ) {
            Ok(h) => h,
            Err(rusqlite::Error::QueryReturnedNoRows) => GENESIS_CHAIN_HASH.to_string(),
            Err(e) => {
                return Err(DbMcpError::StorageError(format!(
                    "Failed to read audit chain tip: {e}"
                )))
            }
        };

        let chain_hash = compute_event_chain_hash(&prev_hash, &sanitized);
        let payload_json = serde_json::to_string(&sanitized).map_err(|e| {
            DbMcpError::StorageError(format!("Failed to serialize audit event JSON: {e}"))
        })?;
        let decision_str = serde_json::to_value(sanitized.decision)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| format!("{:?}", sanitized.decision).to_ascii_lowercase());
        let statement_class_str = sanitized.statement_class.map(|c| c.as_str().to_string());
        let returned_rows_i64 = sanitized.returned_rows.map(|r| r as i64);
        let truncated_i64 = sanitized.truncated.map(|t| if t { 1i64 } else { 0i64 });
        let exec_ms_i64 = sanitized.execution_time_ms.map(|m| m as i64);

        guard
            .execute(
                "INSERT INTO audit_events (
                    event_id, request_id, timestamp, principal, role, transport,
                    connection, operating_mode, tool_name, sql_hash, normalized_sql,
                    statement_class, decision, denial_code, change_id, returned_rows,
                    truncated, execution_time_ms, schema_version, error_message,
                    prev_hash, chain_hash, payload_json
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6,
                    ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16,
                    ?17, ?18, ?19, ?20,
                    ?21, ?22, ?23
                )",
                params![
                    sanitized.event_id,
                    sanitized.request_id,
                    sanitized.timestamp.to_rfc3339(),
                    sanitized.principal,
                    sanitized.role,
                    sanitized.transport,
                    sanitized.connection,
                    sanitized.operating_mode.as_str(),
                    sanitized.tool_name,
                    sanitized.sql_hash,
                    sanitized.normalized_sql,
                    statement_class_str,
                    decision_str,
                    sanitized.denial_code,
                    sanitized.change_id,
                    returned_rows_i64,
                    truncated_i64,
                    exec_ms_i64,
                    sanitized.schema_version,
                    sanitized.error_message,
                    prev_hash,
                    chain_hash,
                    payload_json
                ],
            )
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to insert audit_events record: {e}"))
            })?;

        Ok(())
    }

    /// Query `audit_events` matching `filter` in chronological order.
    pub fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("SQLite audit lock poisoned: {e}")))?;

        let mut stmt = guard
            .prepare("SELECT payload_json FROM audit_events ORDER BY seq ASC")
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to prepare audit_events query: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| DbMcpError::StorageError(format!("Failed to query audit_events: {e}")))?;

        let mut events = Vec::new();
        for row_res in rows {
            let payload_str = row_res.map_err(|e| {
                DbMcpError::StorageError(format!("Failed to read audit_events row: {e}"))
            })?;
            let event: AuditEvent = serde_json::from_str(&payload_str).map_err(|e| {
                DbMcpError::StorageError(format!("Failed to deserialize audit_events JSON: {e}"))
            })?;
            events.push(event);
        }

        Ok(filter.apply(&events))
    }

    /// Retrieve all `AuditEvent`s associated with `request_id`.
    pub fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("SQLite audit lock poisoned: {e}")))?;

        let mut stmt = guard
            .prepare("SELECT payload_json FROM audit_events WHERE request_id = ?1 ORDER BY seq ASC")
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to prepare get_by_request_id query: {e}"))
            })?;

        let rows = stmt
            .query_map(params![request_id], |row| row.get::<_, String>(0))
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to execute get_by_request_id: {e}"))
            })?;

        let mut events = Vec::new();
        for row_res in rows {
            let payload_str = row_res.map_err(|e| {
                DbMcpError::StorageError(format!("Failed to read audit_events row: {e}"))
            })?;
            let event: AuditEvent = serde_json::from_str(&payload_str).map_err(|e| {
                DbMcpError::StorageError(format!("Failed to deserialize audit_events JSON: {e}"))
            })?;
            events.push(event);
        }

        Ok(events)
    }

    /// Verify the cryptographic hash chain of all rows in `audit_events`.
    /// Returns `Ok(true)` if the chain is intact, or `Ok(false)` if tampering is detected.
    pub fn verify_chain(&self) -> DbMcpResult<bool> {
        Ok(self.verify_chain_report()?.valid)
    }

    /// Detailed hash-chain verification report across all `audit_events` rows.
    pub fn verify_chain_report(&self) -> DbMcpResult<AuditChainReport> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| DbMcpError::StorageError(format!("SQLite audit lock poisoned: {e}")))?;

        let mut stmt = guard
            .prepare(
                "SELECT event_id, normalized_sql, decision, prev_hash, chain_hash, payload_json
                 FROM audit_events
                 ORDER BY seq ASC",
            )
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to prepare verify_chain query: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| {
                DbMcpError::StorageError(format!("Failed to iterate audit_events chain: {e}"))
            })?;

        let mut expected_prev = GENESIS_CHAIN_HASH.to_string();
        let mut total_events = 0usize;

        for row_res in rows {
            let (event_id, col_sql, col_decision, prev_hash, chain_hash, payload_json) = row_res
                .map_err(|e| {
                    DbMcpError::StorageError(format!("Failed to read audit_events chain row: {e}"))
                })?;
            total_events += 1;

            if prev_hash != expected_prev {
                return Ok(AuditChainReport {
                    valid: false,
                    total_events,
                    last_chain_hash: chain_hash,
                    broken_at_event_id: Some(event_id),
                    failure_reason: Some(format!(
                        "prev_hash mismatch: expected '{expected_prev}', found '{prev_hash}'"
                    )),
                });
            }

            let event: AuditEvent = match serde_json::from_str(&payload_json) {
                Ok(ev) => ev,
                Err(e) => {
                    return Ok(AuditChainReport {
                        valid: false,
                        total_events,
                        last_chain_hash: chain_hash,
                        broken_at_event_id: Some(event_id),
                        failure_reason: Some(format!("Malformed payload_json: {e}")),
                    });
                }
            };

            // Verify columns match payload_json (detect direct SQL column tampering)
            if event.event_id != event_id || event.normalized_sql != col_sql {
                return Ok(AuditChainReport {
                    valid: false,
                    total_events,
                    last_chain_hash: chain_hash,
                    broken_at_event_id: Some(event_id),
                    failure_reason: Some(
                        "Column value diverges from signed payload_json".to_string(),
                    ),
                });
            }

            let expected_decision_str = serde_json::to_value(event.decision)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_default();
            if !expected_decision_str.is_empty() && col_decision != expected_decision_str {
                return Ok(AuditChainReport {
                    valid: false,
                    total_events,
                    last_chain_hash: chain_hash,
                    broken_at_event_id: Some(event_id),
                    failure_reason: Some(format!(
                        "Decision column '{col_decision}' diverges from signed payload '{expected_decision_str}'"
                    )),
                });
            }

            let recomputed = compute_event_chain_hash(&prev_hash, &event);
            if recomputed != chain_hash {
                return Ok(AuditChainReport {
                    valid: false,
                    total_events,
                    last_chain_hash: chain_hash.clone(),
                    broken_at_event_id: Some(event_id),
                    failure_reason: Some(format!(
                        "chain_hash mismatch: expected '{recomputed}', found '{chain_hash}'"
                    )),
                });
            }

            expected_prev = chain_hash;
        }

        Ok(AuditChainReport {
            valid: true,
            total_events,
            last_chain_hash: expected_prev,
            broken_at_event_id: None,
            failure_reason: None,
        })
    }

    /// Execute a raw SQL statement on the underlying SQLite connection (used in tests to simulate tampering).
    #[cfg(test)]
    pub(crate) fn raw_execute_for_test(&self, sql: &str) -> DbMcpResult<()> {
        let guard = self.conn.lock().unwrap();
        guard
            .execute(sql, [])
            .map_err(|e| DbMcpError::StorageError(e.to_string()))?;
        Ok(())
    }
}

impl AuditSink for SqliteAuditStore {
    fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        SqliteAuditStore::record(self, event)
    }

    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        SqliteAuditStore::list_events(self, filter)
    }

    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        SqliteAuditStore::get_by_request_id(self, request_id)
    }

    fn verify_chain(&self) -> DbMcpResult<bool> {
        SqliteAuditStore::verify_chain(self)
    }
}

/// Composite audit store that fans out `AuditEvent` writes to multiple `AuditSink`s
/// (e.g. `InMemoryAuditStore` + `JsonlAuditStore` + `SqliteAuditStore`).
#[derive(Clone, Default)]
pub struct CompositeAuditStore {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl CompositeAuditStore {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }

    pub fn from_stores(
        memory: Option<InMemoryAuditStore>,
        jsonl: Option<JsonlAuditStore>,
        sqlite: Option<SqliteAuditStore>,
    ) -> Self {
        let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();
        if let Some(m) = memory {
            sinks.push(Arc::new(m));
        }
        if let Some(j) = jsonl {
            sinks.push(Arc::new(j));
        }
        if let Some(s) = sqlite {
            sinks.push(Arc::new(s));
        }
        Self { sinks }
    }

    pub fn add_sink(&mut self, sink: Arc<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    pub fn with_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }

    pub fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        let sanitized = sanitize_audit_event(event);
        for sink in &self.sinks {
            sink.record(sanitized.clone())?;
        }
        Ok(())
    }

    pub fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        if let Some(first) = self.sinks.first() {
            first.list_events(filter)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        if let Some(first) = self.sinks.first() {
            first.get_by_request_id(request_id)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn verify_chain(&self) -> DbMcpResult<bool> {
        for sink in &self.sinks {
            if !sink.verify_chain()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl AuditSink for CompositeAuditStore {
    fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        CompositeAuditStore::record(self, event)
    }

    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        CompositeAuditStore::list_events(self, filter)
    }

    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        CompositeAuditStore::get_by_request_id(self, request_id)
    }

    fn verify_chain(&self) -> DbMcpResult<bool> {
        CompositeAuditStore::verify_chain(self)
    }
}

/// Build the configured audit sink fan-out (memory, JSONL, SQLite).
///
/// Shared by the MCP runtime and the out-of-band admin CLI so that every entry point writes to
/// the same audit trail. Falls back to an in-memory store only when nothing is configured.
pub fn build_audit_sink(
    in_memory: bool,
    jsonl_path: Option<&str>,
    sqlite_path: Option<&str>,
) -> DbMcpResult<Arc<dyn AuditSink>> {
    let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();
    if in_memory {
        sinks.push(Arc::new(InMemoryAuditStore::new()));
    }
    if let Some(path) = jsonl_path.map(str::trim).filter(|p| !p.is_empty()) {
        if Path::new(path).is_dir() {
            return Err(DbMcpError::StorageError(format!(
                "audit.jsonl_path '{path}' is a directory"
            )));
        }
        sinks.push(Arc::new(JsonlAuditStore::new(path)?));
    }
    if let Some(path) = sqlite_path.map(str::trim).filter(|p| !p.is_empty()) {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        sinks.push(Arc::new(SqliteAuditStore::open(path)?));
    }
    if sinks.is_empty() {
        sinks.push(Arc::new(InMemoryAuditStore::new()));
    }
    Ok(Arc::new(CompositeAuditStore::new(sinks)))
}

/// Helper to build a sample `AuditEvent` with explicit timestamp.
#[allow(clippy::too_many_arguments)]
pub fn new_audit_event_at(
    event_id: impl Into<String>,
    request_id: impl Into<String>,
    timestamp: DateTime<Utc>,
    principal: impl Into<String>,
    role: impl Into<String>,
    transport: impl Into<String>,
    connection: impl Into<String>,
    operating_mode: OperatingMode,
    tool_name: impl Into<String>,
    decision: AuditDecision,
) -> AuditEvent {
    sanitize_audit_event(AuditEvent {
        event_id: event_id.into(),
        request_id: request_id.into(),
        timestamp,
        principal: principal.into(),
        role: role.into(),
        transport: transport.into(),
        connection: connection.into(),
        operating_mode,
        tool_name: tool_name.into(),
        sql_hash: None,
        normalized_sql: None,
        statement_class: None,
        decision,
        denial_code: None,
        change_id: None,
        returned_rows: None,
        truncated: None,
        execution_time_ms: None,
        schema_version: None,
        error_message: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event_with_secrets(req_id: &str, tool: &str, decision: AuditDecision) -> AuditEvent {
        let caller = CallerIdentity::local_agent("agent:cursor");
        create_audit_event(
            req_id,
            &caller,
            "prod-pg",
            OperatingMode::GovernedProduction,
            tool,
            Some("hash_123".to_string()),
            Some("SELECT * FROM users WHERE password='super_secret_password_123'".to_string()),
            Some(SqlStatementClass::Read),
            decision,
            None,
            None,
            Some(2),
            Some(false),
            Some(12),
            Some("snapshot_abc".to_string()),
            Some(
                "Connection failed to postgres://admin:db_secret_pass@localhost:5432/prod"
                    .to_string(),
            ),
        )
    }

    #[test]
    fn test_audit_event_redacts_sql_params_and_errors_before_persistence() {
        let mem = InMemoryAuditStore::new();
        let ev = sample_event_with_secrets("req_redact_1", "execute_query", AuditDecision::Allowed);
        mem.record(ev).unwrap();

        let stored = mem.get_by_request_id("req_redact_1").unwrap();
        assert_eq!(stored.len(), 1);
        let s = &stored[0];
        let sql = s.normalized_sql.as_deref().unwrap();
        let err = s.error_message.as_deref().unwrap();
        assert!(!sql.contains("super_secret_password_123"));
        assert!(sql.contains("password=[REDACTED]"));
        assert!(!err.contains("db_secret_pass"));
        assert!(err.contains("postgres://admin:[REDACTED]@localhost:5432/prod"));

        let params = vec![serde_json::json!("Bearer secret_jwt_token_value_123456")];
        let redacted_params = sanitize_audit_parameters(&params);
        assert_eq!(redacted_params[0], serde_json::json!("Bearer [REDACTED]"));
    }

    #[test]
    fn test_sqlite_audit_store_list_get_and_verify_chain() {
        let sqlite = SqliteAuditStore::in_memory().unwrap();
        let ev1 = sample_event_with_secrets("req_101", "search_objects", AuditDecision::Allowed);
        let ev2 = sample_event_with_secrets("req_102", "execute_query", AuditDecision::Denied);

        sqlite.record(ev1).unwrap();
        sqlite.record(ev2).unwrap();

        let all = sqlite.list_events(&AuditFilter::new()).unwrap();
        assert_eq!(all.len(), 2);

        let denied_only = sqlite
            .list_events(&AuditFilter::new().with_decision(AuditDecision::Denied))
            .unwrap();
        assert_eq!(denied_only.len(), 1);
        assert_eq!(denied_only[0].request_id, "req_102");

        let by_req = sqlite.get_by_request_id("req_101").unwrap();
        assert_eq!(by_req.len(), 1);
        assert_eq!(by_req[0].tool_name, "search_objects");

        // Verify intact hash chain
        assert!(sqlite.verify_chain().unwrap());
        let report = sqlite.verify_chain_report().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_events, 2);

        // Tamper with a row and verify chain fails
        sqlite
            .raw_execute_for_test(
                "UPDATE audit_events SET decision = 'allowed' WHERE request_id = 'req_102'",
            )
            .unwrap();
        assert!(!sqlite.verify_chain().unwrap());
    }

    #[test]
    fn test_jsonl_and_composite_audit_store() {
        let temp_dir = std::env::temp_dir().join(format!("db_mcp_audit_test_{}", Uuid::new_v4()));
        let jsonl_path = temp_dir.join("audit.jsonl");
        let sqlite_path = temp_dir.join("audit.sqlite");

        let mem = InMemoryAuditStore::new();
        let jsonl = JsonlAuditStore::new(&jsonl_path).unwrap();
        let sqlite = SqliteAuditStore::open(&sqlite_path).unwrap();

        let composite = CompositeAuditStore::from_stores(
            Some(mem.clone()),
            Some(jsonl.clone()),
            Some(sqlite.clone()),
        );

        let ev1 = sample_event_with_secrets("req_comp_1", "execute_query", AuditDecision::Allowed);
        let ev2 = sample_event_with_secrets(
            "req_comp_2",
            "propose_change",
            AuditDecision::RequiresApproval,
        );

        composite.record(ev1).unwrap();
        composite.record(ev2).unwrap();

        assert_eq!(mem.len(), 2);
        assert_eq!(jsonl.read_all().unwrap().len(), 2);
        assert_eq!(sqlite.list_events(&AuditFilter::new()).unwrap().len(), 2);
        assert_eq!(composite.get_by_request_id("req_comp_2").unwrap().len(), 1);
        assert!(composite.verify_chain().unwrap());

        let _ = fs::remove_file(&jsonl_path);
        let _ = fs::remove_file(&sqlite_path);
        let _ = fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_concurrent_writers_keep_chains_intact() {
        let dir = std::env::temp_dir().join(format!("db_mcp_audit_conc_{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let jsonl_path = dir.join("audit.jsonl");
        let sqlite_path = dir.join("audit.sqlite");
        let mut handles = Vec::new();
        for t in 0..4 {
            let (jp, sp) = (jsonl_path.clone(), sqlite_path.clone());
            handles.push(std::thread::spawn(move || {
                // Separate store instances model separate processes (no shared in-process lock).
                let jsonl = JsonlAuditStore::new(&jp).unwrap();
                let sqlite = SqliteAuditStore::open(&sp).unwrap();
                for i in 0..15 {
                    let ev = sample_event_with_secrets(
                        &format!("req_{t}_{i}"),
                        "execute_query",
                        AuditDecision::Allowed,
                    );
                    jsonl.record(ev.clone()).unwrap();
                    sqlite.record(ev).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let jsonl = JsonlAuditStore::new(&jsonl_path).unwrap();
        let sqlite = SqliteAuditStore::open(&sqlite_path).unwrap();
        assert_eq!(jsonl.read_all().unwrap().len(), 60);
        assert!(jsonl.verify_chain().unwrap());
        assert!(sqlite.verify_chain().unwrap());
        drop(jsonl);
        drop(sqlite);
        let _ = fs::remove_dir_all(&dir);
    }
}
