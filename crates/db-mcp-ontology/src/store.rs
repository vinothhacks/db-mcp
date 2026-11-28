//! Versioned SQLite ontology metadata store.
//!
//! Dedicated metadata database (never business tables). Every query is scoped by
//! `(tenant_id, connection)`. Definition content is immutable: an edit inserts a new version,
//! and only the lifecycle `status` of a version row changes, through conditional updates.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use db_mcp_core::{DbMcpError, DbMcpResult};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::model::{
    Certification, Definition, DefinitionKind, DefinitionStatus, OntologyRevision, QuestionEvidence,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS ontology_definitions (
    tenant_id TEXT NOT NULL,
    connection TEXT NOT NULL,
    def_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, connection, def_id, version)
);
CREATE INDEX IF NOT EXISTS idx_ontology_definitions_status
    ON ontology_definitions (tenant_id, connection, status);
CREATE INDEX IF NOT EXISTS idx_ontology_definitions_name
    ON ontology_definitions (tenant_id, connection, name);
CREATE TABLE IF NOT EXISTS ontology_certifications (
    cert_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connection TEXT NOT NULL,
    def_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    action TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    cert_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    cert_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ontology_certifications_def
    ON ontology_certifications (tenant_id, connection, def_id, version);
CREATE TABLE IF NOT EXISTS ontology_revisions (
    revision_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connection TEXT NOT NULL,
    seq INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    published_at TEXT NOT NULL,
    revision_json TEXT NOT NULL,
    UNIQUE (tenant_id, connection, seq)
);
CREATE TABLE IF NOT EXISTS ontology_question_evidence (
    evidence_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connection TEXT NOT NULL,
    question_hash TEXT NOT NULL,
    revision_id TEXT,
    decision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL
);
"#;

fn storage_err(context: &str, e: impl std::fmt::Display) -> DbMcpError {
    DbMcpError::StorageError(format!("ontology store: {context}: {e}"))
}

fn decode<T: serde::de::DeserializeOwned>(json: &str) -> DbMcpResult<T> {
    serde_json::from_str(json).map_err(|e| storage_err("corrupt record", e))
}

fn encode<T: serde::Serialize>(value: &T) -> DbMcpResult<String> {
    serde_json::to_string(value).map_err(|e| storage_err("serialize", e))
}

/// Thread-safe handle to the ontology metadata database.
#[derive(Clone)]
pub struct OntologyStore {
    conn: Arc<Mutex<Connection>>,
    path: Option<String>,
}

impl std::fmt::Debug for OntologyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OntologyStore").field("path", &self.path).finish()
    }
}

impl OntologyStore {
    /// Ephemeral store (tests, demo config). Content is lost on restart.
    pub fn new_in_memory() -> DbMcpResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| storage_err("open memory", e))?;
        Self::init(conn, None)
    }

    /// Persistent store at `path` (parent directories are created).
    pub fn open(path: impl AsRef<Path>) -> DbMcpResult<Self> {
        let path = path.as_ref();
        if path.is_dir() {
            return Err(DbMcpError::StorageError(format!(
                "ontology.storage_path '{}' is a directory",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| storage_err("create directory", e))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| storage_err("open", e))?;
        Self::init(conn, Some(path.display().to_string()))
    }

    fn init(conn: Connection, path: Option<String>) -> DbMcpResult<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| storage_err("busy_timeout", e))?;
        conn.execute_batch(SCHEMA).map_err(|e| storage_err("schema", e))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
        })
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    fn with_conn<R>(&self, f: impl FnOnce(&mut Connection) -> DbMcpResult<R>) -> DbMcpResult<R> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| DbMcpError::StorageError("ontology store lock poisoned".to_string()))?;
        f(&mut guard)
    }

    /// Insert a new definition version. `def.version` must be exactly latest + 1 (or 1).
    pub fn insert_definition(&self, def: &Definition) -> DbMcpResult<()> {
        let json = encode(def)?;
        self.with_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage_err("begin", e))?;
            let latest: Option<u32> = tx
                .query_row(
                    "SELECT MAX(version) FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND def_id=?3",
                    params![def.tenant_id, def.connection, def.def_id],
                    |r| r.get::<_, Option<u32>>(0),
                )
                .map_err(|e| storage_err("latest version", e))?;
            let expected = latest.unwrap_or(0) + 1;
            if def.version != expected {
                return Err(DbMcpError::PolicyDenied {
                    code: "ONTOLOGY_VERSION_CONFLICT".to_string(),
                    message: format!(
                        "Definition '{}' is at version {}; version {} cannot be inserted",
                        def.def_id,
                        latest.unwrap_or(0),
                        def.version
                    ),
                    next_action: Some("Re-read the definition with describe_term and retry with expected_version".to_string()),
                });
            }
            tx.execute(
                "INSERT INTO ontology_definitions (tenant_id, connection, def_id, version, kind, name, status, content_hash, definition_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    def.tenant_id,
                    def.connection,
                    def.def_id,
                    def.version,
                    def.kind.as_str(),
                    def.name,
                    def.status.as_str(),
                    def.content_hash,
                    json,
                    def.updated_at.to_rfc3339(),
                ],
            )
            .map_err(|e| storage_err("insert definition", e))?;
            tx.commit().map_err(|e| storage_err("commit", e))
        })
    }

    /// Conditionally move one version from `from` to `to` (atomic compare-and-set).
    pub fn transition(
        &self,
        tenant: &str,
        connection: &str,
        def_id: &str,
        version: u32,
        from: DefinitionStatus,
        to: DefinitionStatus,
    ) -> DbMcpResult<Definition> {
        if !from.can_transition_to(to) {
            return Err(DbMcpError::PolicyDenied {
                code: "ONTOLOGY_INVALID_TRANSITION".to_string(),
                message: format!("Definition '{def_id}' v{version} cannot move from {} to {}", from.as_str(), to.as_str()),
                next_action: None,
            });
        }
        self.with_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage_err("begin", e))?;
            let changed = transition_in_tx(&tx, tenant, connection, def_id, version, from, to)?;
            tx.commit().map_err(|e| storage_err("commit", e))?;
            Ok(changed)
        })
    }

    /// Run several status transitions plus a revision insert atomically (publish).
    pub fn publish_atomically(
        &self,
        transitions: &[(String, u32, DefinitionStatus, DefinitionStatus)],
        revision: &OntologyRevision,
    ) -> DbMcpResult<()> {
        let revision_seq = i64::try_from(revision.seq).map_err(|e| storage_err("revision seq", e))?;
        let rev_json = encode(revision)?;
        self.with_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage_err("begin", e))?;
            let current_seq: Option<i64> = tx
                .query_row(
                    "SELECT MAX(seq) FROM ontology_revisions WHERE tenant_id=?1 AND connection=?2",
                    params![revision.tenant_id, revision.connection],
                    |r| r.get(0),
                )
                .map_err(|e| storage_err("revision seq", e))?;
            let current_seq = current_seq.unwrap_or(0);
            if current_seq < 0 {
                return Err(storage_err("revision seq", "negative stored sequence"));
            }
            if current_seq.checked_add(1) != Some(revision_seq) {
                return Err(DbMcpError::PolicyDenied {
                    code: "ONTOLOGY_VERSION_CONFLICT".to_string(),
                    message: "Another publish completed concurrently; retry".to_string(),
                    next_action: Some("Retry publish".to_string()),
                });
            }
            for (def_id, version, from, to) in transitions {
                transition_in_tx(&tx, &revision.tenant_id, &revision.connection, def_id, *version, *from, *to)?;
            }
            tx.execute(
                "INSERT INTO ontology_revisions (revision_id, tenant_id, connection, seq, content_hash, schema_fingerprint, published_at, revision_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    revision.revision_id,
                    revision.tenant_id,
                    revision.connection,
                    revision_seq,
                    revision.content_hash,
                    revision.schema_fingerprint,
                    revision.published_at.to_rfc3339(),
                    rev_json,
                ],
            )
            .map_err(|e| storage_err("insert revision", e))?;
            tx.commit().map_err(|e| storage_err("commit", e))
        })
    }

    pub fn get_version(&self, tenant: &str, connection: &str, def_id: &str, version: u32) -> DbMcpResult<Option<Definition>> {
        self.with_conn(|conn| {
            let json: Option<String> = conn
                .query_row(
                    "SELECT definition_json FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND def_id=?3 AND version=?4",
                    params![tenant, connection, def_id, version],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| storage_err("get version", e))?;
            json.map(|j| decode(&j)).transpose()
        })
    }

    /// All versions of one definition, oldest first.
    pub fn versions(&self, tenant: &str, connection: &str, def_id: &str) -> DbMcpResult<Vec<Definition>> {
        self.query_defs(
            "SELECT definition_json FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND def_id=?3 ORDER BY version",
            params![tenant, connection, def_id],
        )
    }

    pub fn latest(&self, tenant: &str, connection: &str, def_id: &str) -> DbMcpResult<Option<Definition>> {
        Ok(self.versions(tenant, connection, def_id)?.pop())
    }

    /// Every version of every definition of a connection.
    pub fn all_versions(&self, tenant: &str, connection: &str) -> DbMcpResult<Vec<Definition>> {
        self.query_defs(
            "SELECT definition_json FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 ORDER BY def_id, version",
            params![tenant, connection],
        )
    }

    /// Latest version of each definition.
    pub fn latest_all(&self, tenant: &str, connection: &str) -> DbMcpResult<Vec<Definition>> {
        let mut latest: BTreeMap<String, Definition> = BTreeMap::new();
        for def in self.all_versions(tenant, connection)? {
            latest.insert(def.def_id.clone(), def);
        }
        Ok(latest.into_values().collect())
    }

    /// Versions currently in `status` (any version, not only latest).
    pub fn by_status(&self, tenant: &str, connection: &str, status: DefinitionStatus) -> DbMcpResult<Vec<Definition>> {
        self.query_defs(
            "SELECT definition_json FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND status=?3 ORDER BY def_id, version",
            params![tenant, connection, status.as_str()],
        )
    }

    fn query_defs(&self, sql: &str, params: impl rusqlite::Params) -> DbMcpResult<Vec<Definition>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(sql).map_err(|e| storage_err("prepare", e))?;
            let rows = stmt
                .query_map(params, |r| r.get::<_, String>(0))
                .map_err(|e| storage_err("query", e))?;
            let mut out = Vec::new();
            for row in rows {
                let json = row.map_err(|e| storage_err("row", e))?;
                // Status column is authoritative (JSON snapshot reflects insertion time);
                // `refresh_status` overlays it below.
                out.push(decode::<Definition>(&json)?);
            }
            Ok(out)
        })
        .and_then(|defs| self.refresh_status(defs))
    }

    fn refresh_status(&self, mut defs: Vec<Definition>) -> DbMcpResult<Vec<Definition>> {
        if defs.is_empty() {
            return Ok(defs);
        }
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT status, updated_at FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND def_id=?3 AND version=?4")
                .map_err(|e| storage_err("prepare", e))?;
            for def in defs.iter_mut() {
                let (status, updated): (String, String) = stmt
                    .query_row(params![def.tenant_id, def.connection, def.def_id, def.version], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(|e| storage_err("status", e))?;
                if let Some(s) = DefinitionStatus::parse(&status) {
                    def.status = s;
                }
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&updated) {
                    def.updated_at = ts.with_timezone(&Utc);
                }
            }
            Ok(defs)
        })
    }

    pub fn insert_certification(&self, cert: &Certification) -> DbMcpResult<()> {
        let json = encode(cert)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO ontology_certifications (cert_id, tenant_id, connection, def_id, version, action, reviewer, cert_hash, created_at, cert_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    cert.cert_id,
                    cert.tenant_id,
                    cert.connection,
                    cert.def_id,
                    cert.version,
                    cert.action.as_str(),
                    cert.reviewer,
                    cert.cert_hash,
                    cert.at.to_rfc3339(),
                    json,
                ],
            )
            .map_err(|e| storage_err("insert certification", e))?;
            Ok(())
        })
    }

    pub fn certifications(&self, tenant: &str, connection: &str, def_id: &str) -> DbMcpResult<Vec<Certification>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT cert_json FROM ontology_certifications WHERE tenant_id=?1 AND connection=?2 AND def_id=?3 ORDER BY created_at, version")
                .map_err(|e| storage_err("prepare", e))?;
            let rows = stmt
                .query_map(params![tenant, connection, def_id], |r| r.get::<_, String>(0))
                .map_err(|e| storage_err("query", e))?;
            rows.map(|r| decode(&r.map_err(|e| storage_err("row", e))?)).collect()
        })
    }

    pub fn latest_revision(&self, tenant: &str, connection: &str) -> DbMcpResult<Option<OntologyRevision>> {
        self.with_conn(|conn| {
            let json: Option<String> = conn
                .query_row(
                    "SELECT revision_json FROM ontology_revisions WHERE tenant_id=?1 AND connection=?2 ORDER BY seq DESC LIMIT 1",
                    params![tenant, connection],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| storage_err("latest revision", e))?;
            json.map(|j| decode(&j)).transpose()
        })
    }

    pub fn revisions(&self, tenant: &str, connection: &str) -> DbMcpResult<Vec<OntologyRevision>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT revision_json FROM ontology_revisions WHERE tenant_id=?1 AND connection=?2 ORDER BY seq")
                .map_err(|e| storage_err("prepare", e))?;
            let rows = stmt
                .query_map(params![tenant, connection], |r| r.get::<_, String>(0))
                .map_err(|e| storage_err("query", e))?;
            rows.map(|r| decode(&r.map_err(|e| storage_err("row", e))?)).collect()
        })
    }

    pub fn insert_question_evidence(&self, ev: &QuestionEvidence) -> DbMcpResult<()> {
        let json = encode(ev)?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO ontology_question_evidence (evidence_id, tenant_id, connection, question_hash, revision_id, decision, created_at, evidence_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    ev.evidence_id,
                    ev.tenant_id,
                    ev.connection,
                    ev.question_hash,
                    ev.revision_id,
                    ev.decision,
                    ev.at.to_rfc3339(),
                    json,
                ],
            )
            .map_err(|e| storage_err("insert question evidence", e))?;
            Ok(())
        })
    }

    pub fn question_evidence_count(&self, tenant: &str, connection: &str) -> DbMcpResult<u64> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM ontology_question_evidence WHERE tenant_id=?1 AND connection=?2",
                params![tenant, connection],
                |r| r.get(0),
            )
            .map_err(|e| storage_err("count evidence", e))?;
            u64::try_from(count).map_err(|e| storage_err("count evidence", e))
        })
    }

    /// Count of latest-version definitions by `(kind, status)`.
    pub fn stats(&self, tenant: &str, connection: &str) -> DbMcpResult<BTreeMap<String, BTreeMap<String, u64>>> {
        let mut out: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for def in self.latest_all(tenant, connection)? {
            *out.entry(def.kind.as_str().to_string())
                .or_default()
                .entry(def.status.as_str().to_string())
                .or_default() += 1;
        }
        Ok(out)
    }

    /// Distinct connections that have any ontology content for a tenant.
    pub fn connections(&self, tenant: &str) -> DbMcpResult<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT DISTINCT connection FROM ontology_definitions WHERE tenant_id=?1 ORDER BY connection")
                .map_err(|e| storage_err("prepare", e))?;
            let rows = stmt
                .query_map(params![tenant], |r| r.get::<_, String>(0))
                .map_err(|e| storage_err("query", e))?;
            rows.map(|r| r.map_err(|e| storage_err("row", e))).collect()
        })
    }

    pub fn kinds_present(&self, tenant: &str, connection: &str) -> DbMcpResult<Vec<DefinitionKind>> {
        let mut kinds: Vec<DefinitionKind> = self
            .latest_all(tenant, connection)?
            .into_iter()
            .map(|d| d.kind)
            .collect();
        kinds.sort();
        kinds.dedup();
        Ok(kinds)
    }
}

fn transition_in_tx(
    tx: &rusqlite::Transaction<'_>,
    tenant: &str,
    connection: &str,
    def_id: &str,
    version: u32,
    from: DefinitionStatus,
    to: DefinitionStatus,
) -> DbMcpResult<Definition> {
    if !from.can_transition_to(to) {
        return Err(DbMcpError::PolicyDenied {
            code: "ONTOLOGY_INVALID_TRANSITION".to_string(),
            message: format!("Definition '{def_id}' v{version} cannot move from {} to {}", from.as_str(), to.as_str()),
            next_action: None,
        });
    }
    let now = Utc::now();
    let affected = tx
        .execute(
            "UPDATE ontology_definitions SET status=?1, updated_at=?2
             WHERE tenant_id=?3 AND connection=?4 AND def_id=?5 AND version=?6 AND status=?7",
            params![to.as_str(), now.to_rfc3339(), tenant, connection, def_id, version, from.as_str()],
        )
        .map_err(|e| storage_err("transition", e))?;
    if affected != 1 {
        return Err(DbMcpError::PolicyDenied {
            code: "ONTOLOGY_VERSION_CONFLICT".to_string(),
            message: format!(
                "Definition '{def_id}' v{version} is not in status '{}' (concurrent change?)",
                from.as_str()
            ),
            next_action: Some("Re-read the definition and retry".to_string()),
        });
    }
    let json: String = tx
        .query_row(
            "SELECT definition_json FROM ontology_definitions WHERE tenant_id=?1 AND connection=?2 AND def_id=?3 AND version=?4",
            params![tenant, connection, def_id, version],
            |r| r.get(0),
        )
        .map_err(|e| storage_err("reload", e))?;
    let mut def: Definition = decode(&json)?;
    def.status = to;
    def.updated_at = now;
    Ok(def)
}
