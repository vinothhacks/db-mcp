//! Governed database change proposals (`propose_change`), out-of-band administrative approvals
//! (`approve_change`), state inspection (`get_change`), and cryptographically bound execution
//! (`apply_change`) with replay prevention and schema drift detection.
//!
//! Implements Build Plan Section 6:
//! - Binds every approval to `SHA-256(normalized_sql + params + connection_id + proposing_principal + policy_revision + schema_fingerprint + expiry + constraints)`.
//! - Enforces separation of duties: coding agents and proposing principals cannot self-approve (`SELF_APPROVAL_FORBIDDEN`).
//! - Persists proposals across process boundaries via SQLite or JSON storage so out-of-band CLI
//!   (`db-mcp approve`) and running server instances share state deterministically.
//! - Atomically claims execution (`ChangeState::Executing`) to prevent replay attacks (`APPROVAL_ALREADY_CONSUMED`).
//! - Verifies schema fingerprint and cryptographic approval hash immediately prior to execution
//!   (`SCHEMA_DRIFT_DETECTED`, `APPROVAL_HASH_MISMATCH`).
//! - Signs every approval record with a keyed HMAC-SHA256 (`approval_mac`) when an approval key is
//!   configured, so approvals forged by editing the change store are rejected at apply time.
//! - Approves only `proposed` changes, with a compare-and-swap on the stored state so a second or
//!   concurrent approval can never replace the first one (`CHANGE_NOT_PENDING`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use db_mcp_catalog::capture_schema_via_adapter;
use db_mcp_core::{
    constant_time_eq, hmac_sha256_hex, ApprovalRecord, AuthorizedQuery, CallerIdentity,
    ChangeProposal, ChangeState, ColumnMetadata, DatabaseAdapter, DatabaseEngine, DbMcpError,
    DbMcpResult, ExecutionId, ExecutionLimits, McpSuccessResponse, QueryResult, ReversalSafety,
    SqlStatementClass,
};
use db_mcp_sql::{hash_sql, normalize_sql, parse_and_analyze_sql, SqlAnalysis};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default proposal validity window in seconds (1 hour).
pub const DEFAULT_PROPOSAL_TTL_SECONDS: i64 = 3_600;

/// Default policy revision identifier when not explicitly configured.
pub const DEFAULT_POLICY_REVISION: &str = "policy_v1";

/// Denial code: the change is not in the `proposed` state, so it cannot be approved (again).
pub const CODE_CHANGE_NOT_PENDING: &str = "CHANGE_NOT_PENDING";

/// Denial code: a read-only statement was proposed; it changes nothing and is not governed.
pub const CODE_NOT_A_CHANGE: &str = "NOT_A_CHANGE";

/// Denial code: keyed approvals are required (GovernedProduction) but no approval key is configured.
pub const CODE_APPROVAL_KEY_REQUIRED: &str = "APPROVAL_KEY_REQUIRED";

/// Warning attached to approve/apply results when the change store has no approval key.
pub const UNKEYED_APPROVAL_WARNING: &str = "approval records are not keyed: anyone who can write the change store can forge an approval; set changes.approval_key (or DB_MCP_APPROVAL_KEY)";

/// Minimum accepted approval key length in bytes.
pub const MIN_APPROVAL_KEY_BYTES: usize = 16;

/// Request parameters to create a new governed `ChangeProposal`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposeChangeRequest {
    pub connection: String,
    pub engine: DatabaseEngine,
    pub caller: CallerIdentity,
    pub sql: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
    pub schema_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default = "default_constraints")]
    pub constraints: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_constraints() -> serde_json::Value {
    serde_json::json!({})
}

/// Optional verification overrides for `apply_change_with_options`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApplyChangeOptions {
    /// Expected policy revision at execution time (defaults to manager's active `policy_revision`).
    pub current_policy_revision: Option<String>,
    /// Override current schema fingerprint instead of querying `adapter.discover`.
    pub current_schema_fingerprint: Option<String>,
    /// Optional SQL string supplied by caller at apply time to verify against approved SQL.
    pub verify_sql: Option<String>,
    /// Optional parameter list supplied by caller at apply time to verify against approved params.
    pub verify_params: Option<Vec<serde_json::Value>>,
    /// Execution limits applied when running the change on the adapter.
    pub execution_limits: Option<ExecutionLimits>,
    /// Refuse to apply unless the approval carries a valid keyed `approval_mac` (fail closed when
    /// no approval key is configured). Set for GovernedProduction connections.
    #[serde(default)]
    pub require_approval_mac: bool,
}

/// Outcome returned when a governed `ChangeProposal` is successfully executed via `apply_change`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplyChangeOutcome {
    pub proposal: ChangeProposal,
    pub query_result: QueryResult,
    pub post_schema_fingerprint: Option<String>,
    /// Non-fatal governance warnings (for example unkeyed approval records).
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
enum StorageBackend {
    InMemory,
    Sqlite(PathBuf),
    JsonFile(PathBuf),
}

/// Governed change lifecycle manager supporting in-memory, SQLite, and JSON file persistence.
#[derive(Clone)]
pub struct ChangeManager {
    backend: StorageBackend,
    memory_store: Arc<Mutex<BTreeMap<String, ChangeProposal>>>,
    policy_revision: String,
    default_ttl_seconds: i64,
    /// Secret key for the approval HMAC. In-memory stores use a random per-process key (their
    /// records cannot be edited from outside the process); persistent stores need a configured key.
    approval_key: Option<Arc<Vec<u8>>>,
}

impl Default for ChangeManager {
    fn default() -> Self {
        Self::new_in_memory()
    }
}

impl ChangeManager {
    /// Create an in-memory `ChangeManager`.
    pub fn new_in_memory() -> Self {
        Self {
            backend: StorageBackend::InMemory,
            memory_store: Arc::new(Mutex::new(BTreeMap::new())),
            policy_revision: DEFAULT_POLICY_REVISION.to_string(),
            default_ttl_seconds: DEFAULT_PROPOSAL_TTL_SECONDS,
            approval_key: Some(Arc::new(ephemeral_approval_key())),
        }
    }

    /// Create a `ChangeManager` backed by a SQLite database file so out-of-band CLI commands
    /// (`db-mcp approve`) and running MCP server processes share state safely.
    pub fn with_sqlite_path(path: impl Into<PathBuf>) -> DbMcpResult<Self> {
        let path_buf = path.into();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to create parent directory for SQLite change store '{}': {e}",
                        path_buf.display()
                    ))
                })?;
            }
        }
        let mgr = Self {
            backend: StorageBackend::Sqlite(path_buf),
            memory_store: Arc::new(Mutex::new(BTreeMap::new())),
            policy_revision: DEFAULT_POLICY_REVISION.to_string(),
            default_ttl_seconds: DEFAULT_PROPOSAL_TTL_SECONDS,
            approval_key: None,
        };
        mgr.init_sqlite_schema()?;
        Ok(mgr)
    }

    /// Create a `ChangeManager` backed by a JSON file on disk.
    pub fn with_json_path(path: impl Into<PathBuf>) -> DbMcpResult<Self> {
        let path_buf = path.into();
        if let Some(parent) = path_buf.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to create parent directory for JSON change store '{}': {e}",
                        path_buf.display()
                    ))
                })?;
            }
        }
        let mgr = Self {
            backend: StorageBackend::JsonFile(path_buf.clone()),
            memory_store: Arc::new(Mutex::new(BTreeMap::new())),
            policy_revision: DEFAULT_POLICY_REVISION.to_string(),
            default_ttl_seconds: DEFAULT_PROPOSAL_TTL_SECONDS,
            approval_key: None,
        };
        if !path_buf.exists() {
            mgr.save_all_to_json(&BTreeMap::new())?;
        }
        Ok(mgr)
    }

    /// Create a `ChangeManager` from a file path, selecting JSON backing for `.json` extensions
    /// and SQLite backing for all other extensions (`.db`, `.sqlite`, etc.).
    pub fn with_storage_path(path: impl Into<PathBuf>) -> DbMcpResult<Self> {
        let path_buf = path.into();
        let is_json = path_buf
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if is_json {
            Self::with_json_path(path_buf)
        } else {
            Self::with_sqlite_path(path_buf)
        }
    }

    /// Configure the active policy revision string bound into approval hashes.
    pub fn with_policy_revision(mut self, policy_revision: impl Into<String>) -> Self {
        self.policy_revision = policy_revision.into();
        self
    }

    /// Configure the default proposal expiration TTL in seconds.
    pub fn with_default_ttl_seconds(mut self, ttl_seconds: i64) -> Self {
        self.default_ttl_seconds = ttl_seconds;
        self
    }

    /// Configure the secret key that signs approval records (`approval_mac`, HMAC-SHA256).
    ///
    /// Keys shorter than `MIN_APPROVAL_KEY_BYTES` are rejected (fail closed).
    pub fn with_approval_key(mut self, key: impl Into<Vec<u8>>) -> DbMcpResult<Self> {
        let key = key.into();
        if key.len() < MIN_APPROVAL_KEY_BYTES {
            return Err(DbMcpError::ConfigurationError(format!(
                "approval key must be at least {MIN_APPROVAL_KEY_BYTES} bytes (got {})",
                key.len()
            )));
        }
        self.approval_key = Some(Arc::new(key));
        Ok(self)
    }

    /// True when approval records are signed and verified with a secret key.
    pub fn has_approval_key(&self) -> bool {
        self.approval_key.is_some()
    }

    /// Governance warnings for approve/apply results (empty when approvals are keyed).
    pub fn approval_warnings(&self) -> Vec<String> {
        if self.has_approval_key() {
            Vec::new()
        } else {
            vec![UNKEYED_APPROVAL_WARNING.to_string()]
        }
    }

    /// Return the active policy revision configured on this manager.
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }

    /// Propose a governed database change using an explicit `ProposeChangeRequest`.
    pub fn propose_change(&self, request: ProposeChangeRequest) -> DbMcpResult<ChangeProposal> {
        if !request.caller.can_access_connection(&request.connection) {
            return Err(DbMcpError::Unauthorized(format!(
                "Principal '{}' is not authorized to propose changes on connection '{}'",
                request.caller.principal, request.connection
            )));
        }

        let analysis = parse_and_analyze_sql(request.engine, &request.sql)?;
        validate_change_statement(&analysis)?;

        let (transactional, reversal_safety, compensating_sql) =
            classify_change_reversibility(request.engine, &analysis);

        let now = Utc::now();
        let ttl = request.ttl_seconds.unwrap_or(self.default_ttl_seconds);
        const MAX_TTL_SECONDS: i64 = 30 * 24 * 3600;
        if !(1..=MAX_TTL_SECONDS).contains(&ttl) {
            return Err(DbMcpError::InvalidArgument(format!(
                "ttl_seconds must be between 1 and {MAX_TTL_SECONDS} (got {ttl})"
            )));
        }
        let expires_at = request
            .expires_at
            .unwrap_or_else(|| now + Duration::seconds(ttl));

        let policy_revision = request
            .policy_revision
            .unwrap_or_else(|| self.policy_revision.clone());
        let normalized_sql = analysis.normalized_sql.clone();

        let approval_hash = ChangeProposal::compute_approval_hash(
            &normalized_sql,
            &request.params,
            &request.connection,
            &request.caller.principal,
            &policy_revision,
            &request.schema_fingerprint,
            &expires_at,
            &request.constraints,
        );

        let change_id = format!("chg_{}", Uuid::new_v4().simple());
        let proposal = ChangeProposal {
            change_id,
            connection: request.connection,
            proposing_principal: request.caller.principal,
            sql: request.sql.trim().to_string(),
            normalized_sql,
            params: request.params,
            statement_class: analysis.overall_class,
            policy_revision,
            schema_fingerprint: request.schema_fingerprint,
            approval_hash,
            state: ChangeState::Proposed,
            transactional,
            reversal_safety,
            compensating_sql,
            constraints: request.constraints,
            created_at: now,
            expires_at,
            approval: None,
            applied_at: None,
            applied_by: None,
            rows_affected: None,
            execution_error: None,
        };

        self.store_proposal(&proposal)?;
        Ok(proposal)
    }

    /// Propose a governed change while automatically capturing the current `schema_fingerprint`
    /// from the live `DatabaseAdapter`.
    pub async fn propose_change_with_adapter(
        &self,
        caller: &CallerIdentity,
        adapter: &dyn DatabaseAdapter,
        sql: impl Into<String>,
        params: Vec<serde_json::Value>,
        constraints: Option<serde_json::Value>,
        ttl_seconds: Option<i64>,
    ) -> DbMcpResult<ChangeProposal> {
        let connection = adapter.connection_id().to_string();
        let snapshot = capture_schema_via_adapter(adapter, &connection, None).await?;
        let req = ProposeChangeRequest {
            connection,
            engine: adapter.capabilities().engine,
            caller: caller.clone(),
            sql: sql.into(),
            params,
            schema_fingerprint: snapshot.schema_version,
            policy_revision: Some(self.policy_revision.clone()),
            constraints: constraints.unwrap_or_else(|| serde_json::json!({})),
            ttl_seconds,
            expires_at: None,
        };
        self.propose_change(req)
    }

    /// Approve a pending `ChangeProposal` with strict separation-of-duties checks.
    ///
    /// Fails with `DbMcpError::SelfApprovalForbidden` if:
    /// - `approver.principal` matches `proposal.proposing_principal`, or
    /// - `approver` has an agent role (`approver.is_agent()`), or
    /// - `approver` does not have administrative/DBA approval privileges (`!approver.is_admin()`).
    pub fn approve_change(
        &self,
        change_id: &str,
        approver: &CallerIdentity,
        comment: Option<String>,
    ) -> DbMcpResult<ChangeProposal> {
        let mut proposal = self.load_proposal(change_id)?;

        // 1. Separation of duties: proposing principal or any coding agent role cannot approve
        if approver
            .principal
            .trim()
            .eq_ignore_ascii_case(proposal.proposing_principal.trim())
        {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "Principal '{}' proposed change '{}' and is forbidden from self-approving it",
                approver.principal, change_id
            )));
        }

        if approver.is_agent() || !approver.is_admin() {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "Principal '{}' (role '{}') is not an out-of-band administrator/DBA; coding agents cannot approve production changes",
                approver.principal, approver.role
            )));
        }

        if !approver.can_access_connection(&proposal.connection) {
            return Err(DbMcpError::Unauthorized(format!(
                "Approver '{}' is not authorized for connection '{}'",
                approver.principal, proposal.connection
            )));
        }

        // 2. Lifecycle state checks
        if matches!(
            proposal.state,
            ChangeState::Applied | ChangeState::Executing
        ) {
            return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                "Change '{}' has already been executed (state: {:?})",
                change_id, proposal.state
            )));
        }

        if proposal.state == ChangeState::Expired
            || (matches!(
                proposal.state,
                ChangeState::Proposed | ChangeState::Approved
            ) && Utc::now() >= proposal.expires_at)
        {
            proposal.state = ChangeState::Expired;
            let _ = self.store_proposal(&proposal);
            return Err(DbMcpError::ApprovalExpired(format!(
                "Change proposal '{}' expired at {}",
                change_id,
                proposal.expires_at.to_rfc3339()
            )));
        }

        // Only a pending proposal can be approved: a second approval must never replace the first,
        // and rejected/failed changes cannot be revived.
        if proposal.state != ChangeState::Proposed {
            return Err(change_not_pending(change_id, &proposal));
        }

        // 3. Recompute approval hash to verify the stored proposal was not tampered with prior to approval
        let expected_hash = ChangeProposal::compute_approval_hash(
            &normalize_sql(&proposal.sql),
            &proposal.params,
            &proposal.connection,
            &proposal.proposing_principal,
            &proposal.policy_revision,
            &proposal.schema_fingerprint,
            &proposal.expires_at,
            &proposal.constraints,
        );
        if expected_hash != proposal.approval_hash
            || normalize_sql(&proposal.sql) != proposal.normalized_sql
        {
            return Err(DbMcpError::ApprovalHashMismatch(format!(
                "Stored proposal '{}' failed cryptographic integrity verification prior to approval",
                change_id
            )));
        }

        let mut record = ApprovalRecord {
            approved_by: approver.principal.clone(),
            approved_at: Utc::now(),
            approval_hash: expected_hash,
            comment,
            approval_mac: None,
        };
        if let Some(key) = &self.approval_key {
            record.approval_mac = Some(compute_approval_mac(key, change_id, &record));
        }
        proposal.state = ChangeState::Approved;
        proposal.approval = Some(record);

        // 4. Persist only if the stored proposal is still pending (compare-and-swap), so concurrent
        // approvals cannot both succeed.
        if !self.store_if_state(&proposal, ChangeState::Proposed)? {
            let current = self.load_proposal(change_id)?;
            return Err(change_not_pending(change_id, &current));
        }
        Ok(proposal)
    }

    /// Reject a pending `ChangeProposal`.
    pub fn reject_change(
        &self,
        change_id: &str,
        reviewer: &CallerIdentity,
        reason: Option<String>,
    ) -> DbMcpResult<ChangeProposal> {
        let mut proposal = self.load_proposal(change_id)?;
        if matches!(
            proposal.state,
            ChangeState::Applied | ChangeState::Executing
        ) {
            return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                "Change '{}' has already been executed and cannot be rejected",
                change_id
            )));
        }
        proposal.state = ChangeState::Rejected;
        proposal.execution_error =
            reason.or_else(|| Some(format!("Rejected by principal '{}'", reviewer.principal)));
        self.store_proposal(&proposal)?;
        Ok(proposal)
    }

    /// Retrieve the current state of a `ChangeProposal`, automatically marking it as
    /// `ChangeState::Expired` if its `expires_at` deadline has passed.
    pub fn get_change(&self, change_id: &str) -> DbMcpResult<ChangeProposal> {
        let mut proposal = self.load_proposal(change_id)?;
        if matches!(
            proposal.state,
            ChangeState::Proposed | ChangeState::Approved
        ) && Utc::now() >= proposal.expires_at
        {
            proposal.state = ChangeState::Expired;
            self.store_proposal(&proposal)?;
        }
        Ok(proposal)
    }

    /// List all tracked change proposals, optionally filtered by `connection`.
    pub fn list_changes(&self, connection: Option<&str>) -> DbMcpResult<Vec<ChangeProposal>> {
        let all = self.load_all_proposals()?;
        let now = Utc::now();
        let mut out = Vec::new();
        for mut prop in all {
            if matches!(prop.state, ChangeState::Proposed | ChangeState::Approved)
                && now >= prop.expires_at
            {
                prop.state = ChangeState::Expired;
                let _ = self.store_proposal(&prop);
            }
            if let Some(conn_filter) = connection {
                if !prop.connection.eq_ignore_ascii_case(conn_filter) {
                    continue;
                }
            }
            out.push(prop);
        }
        out.sort_by_key(|a| a.created_at);
        Ok(out)
    }

    /// Execute an approved `ChangeProposal` against `adapter` with default options.
    pub async fn apply_change(
        &self,
        change_id: &str,
        caller: &CallerIdentity,
        adapter: &dyn DatabaseAdapter,
    ) -> DbMcpResult<ApplyChangeOutcome> {
        self.apply_change_with_options(change_id, caller, adapter, ApplyChangeOptions::default())
            .await
    }

    /// Execute an approved `ChangeProposal` enforcing all 6 steps from Build Plan Section 6:
    /// 1. Recheck caller & connection authorization
    /// 2. Check replay/consumption state (`ApprovalAlreadyConsumed`), expiry (`ApprovalExpired`), and approval presence (`ApprovalRequired`)
    /// 3. Verify `schema_fingerprint` (`SchemaDriftDetected`) and recompute cryptographic `approval_hash` (`ApprovalHashMismatch`)
    /// 4. Atomically claim execution (`ChangeState::Executing`) to prevent concurrent replay races
    /// 5. Execute via `DatabaseAdapter::execute`
    /// 6. Record outcome (`ChangeState::Applied` or `ChangeState::Failed`) and persist to disk.
    pub async fn apply_change_with_options(
        &self,
        change_id: &str,
        caller: &CallerIdentity,
        adapter: &dyn DatabaseAdapter,
        options: ApplyChangeOptions,
    ) -> DbMcpResult<ApplyChangeOutcome> {
        let mut proposal = self.load_proposal(change_id)?;

        // Step 1: Recheck authorization and connection binding
        if !caller.can_access_connection(&proposal.connection) {
            return Err(DbMcpError::Unauthorized(format!(
                "Principal '{}' is not authorized to apply changes on connection '{}'",
                caller.principal, proposal.connection
            )));
        }
        if !adapter
            .connection_id()
            .eq_ignore_ascii_case(&proposal.connection)
        {
            return Err(DbMcpError::ApprovalHashMismatch(format!(
                "Change '{}' is bound to connection '{}', not adapter '{}'",
                change_id,
                proposal.connection,
                adapter.connection_id()
            )));
        }

        // Step 2: Check replay state, expiry, and approval presence
        if matches!(
            proposal.state,
            ChangeState::Applied | ChangeState::Executing
        ) {
            return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                "Approval for change '{}' has already been consumed (state: {:?})",
                change_id, proposal.state
            )));
        }

        if proposal.state == ChangeState::Expired || Utc::now() >= proposal.expires_at {
            proposal.state = ChangeState::Expired;
            let _ = self.store_proposal(&proposal);
            return Err(DbMcpError::ApprovalExpired(format!(
                "Approval for change '{}' expired at {}",
                change_id,
                proposal.expires_at.to_rfc3339()
            )));
        }

        if proposal.state != ChangeState::Approved {
            // Same APPROVAL_REQUIRED code, but the next step for a pending proposal is the
            // out-of-band approval, not another proposal.
            let next_action = if proposal.state == ChangeState::Proposed {
                format!("db-mcp approve --change-id {change_id} --approver <admin>")
            } else {
                "propose_change".to_string()
            };
            return Err(DbMcpError::PolicyDenied {
                code: "APPROVAL_REQUIRED".to_string(),
                message: format!(
                    "Change '{}' is in state '{}' and has not been approved; an administrator must approve it out of band (`db-mcp approve` or POST /admin/approve)",
                    change_id,
                    state_to_str(proposal.state)
                ),
                next_action: Some(next_action),
            });
        }

        let approval_record = proposal.approval.as_ref().ok_or_else(|| {
            DbMcpError::ApprovalRequired(format!(
                "Change '{}' has no attached ApprovalRecord",
                change_id
            ))
        })?;

        // Re-check separation of duties on the attached approval record in case storage was edited externally
        if approval_record
            .approved_by
            .trim()
            .eq_ignore_ascii_case(proposal.proposing_principal.trim())
        {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "Change '{}' has an invalid self-approval record by '{}'",
                change_id, approval_record.approved_by
            )));
        }

        // Verify the keyed approval MAC before anything else touches the database: an approval
        // record written directly into the change store carries no valid MAC.
        let mut warnings = Vec::new();
        match &self.approval_key {
            Some(key) => {
                let expected_mac = compute_approval_mac(key, change_id, approval_record);
                let valid = approval_record
                    .approval_mac
                    .as_deref()
                    .map(|mac| constant_time_eq(mac.as_bytes(), expected_mac.as_bytes()))
                    .unwrap_or(false);
                if !valid {
                    return Err(DbMcpError::ApprovalHashMismatch(format!(
                        "Approval record for change '{}' has no valid approval_mac: it was not issued by `db-mcp approve` with the configured approval key (forged record or rotated key; re-approve the change)",
                        change_id
                    )));
                }
            }
            None if options.require_approval_mac => {
                return Err(DbMcpError::PolicyDenied {
                    code: CODE_APPROVAL_KEY_REQUIRED.to_string(),
                    message: format!(
                        "Change '{}' cannot be applied on connection '{}': governed production changes require keyed approvals, but no approval key is configured",
                        change_id, proposal.connection
                    ),
                    next_action: Some(
                        "set changes.approval_key (e.g. \"env:DB_MCP_APPROVAL_KEY\") or DB_MCP_APPROVAL_KEY for the server and `db-mcp approve`, then re-approve".to_string(),
                    ),
                });
            }
            None => warnings.push(UNKEYED_APPROVAL_WARNING.to_string()),
        }

        // Step 3: Revalidate current schema fingerprint and cryptographic approval hash
        let live_schema_fingerprint = match &options.current_schema_fingerprint {
            Some(fp) => fp.clone(),
            None => {
                capture_schema_via_adapter(adapter, &proposal.connection, None)
                    .await?
                    .schema_version
            }
        };

        if live_schema_fingerprint != proposal.schema_fingerprint {
            return Err(DbMcpError::SchemaDriftDetected(format!(
                "Schema drift detected on connection '{}' for change '{}': approved against '{}', but current schema is '{}'",
                proposal.connection,
                change_id,
                proposal.schema_fingerprint,
                live_schema_fingerprint
            )));
        }

        let effective_sql = options.verify_sql.as_deref().unwrap_or(&proposal.sql);
        let effective_normalized_sql = normalize_sql(effective_sql);
        if effective_normalized_sql != proposal.normalized_sql {
            return Err(DbMcpError::ApprovalHashMismatch(format!(
                "SQL statement for change '{}' does not match the normalized SQL bound at proposal time",
                change_id
            )));
        }

        let effective_params = options.verify_params.as_deref().unwrap_or(&proposal.params);
        let effective_policy_revision = options
            .current_policy_revision
            .as_deref()
            .unwrap_or(&self.policy_revision);

        let recomputed_hash = ChangeProposal::compute_approval_hash(
            &effective_normalized_sql,
            effective_params,
            &proposal.connection,
            &proposal.proposing_principal,
            effective_policy_revision,
            &live_schema_fingerprint,
            &proposal.expires_at,
            &proposal.constraints,
        );

        if recomputed_hash != proposal.approval_hash
            || recomputed_hash != approval_record.approval_hash
        {
            return Err(DbMcpError::ApprovalHashMismatch(format!(
                "Approval hash mismatch for change '{}': expected '{}', recomputed '{}'",
                change_id, approval_record.approval_hash, recomputed_hash
            )));
        }

        // Step 4: Atomically claim the approved execution (Approved -> Executing)
        self.atomic_claim_execution(change_id)?;
        proposal.state = ChangeState::Executing;

        // Step 5: Execute via DatabaseAdapter::execute
        let limits = options.execution_limits.unwrap_or_default();
        let auth_query = AuthorizedQuery {
            request_id: format!("req_apply_{}", Uuid::new_v4().simple()),
            execution_id: ExecutionId::new(),
            connection: proposal.connection.clone(),
            caller: caller.clone(),
            sql: proposal.sql.clone(),
            normalized_sql: proposal.normalized_sql.clone(),
            sql_hash: hash_sql(&proposal.normalized_sql),
            params: proposal.params.clone(),
            statement_class: proposal.statement_class,
            read_only: false,
            timeout_ms: limits.timeout_ms,
            max_rows: limits.max_rows,
            max_bytes: limits.max_bytes,
            change_id: Some(proposal.change_id.clone()),
        };

        // Step 6: Record outcome and persist state
        match adapter.execute(auth_query).await {
            Ok(query_result) => {
                proposal.state = ChangeState::Applied;
                proposal.applied_at = Some(Utc::now());
                proposal.applied_by = Some(caller.principal.clone());
                proposal.rows_affected = query_result.rows_affected;
                proposal.execution_error = None;
                self.store_proposal(&proposal)?;

                let post_schema_fingerprint =
                    capture_schema_via_adapter(adapter, &proposal.connection, None)
                        .await
                        .ok()
                        .map(|s| s.schema_version);

                Ok(ApplyChangeOutcome {
                    proposal,
                    query_result,
                    post_schema_fingerprint,
                    warnings,
                })
            }
            Err(exec_err) => {
                proposal.state = ChangeState::Failed;
                proposal.execution_error = Some(exec_err.to_string());
                let _ = self.store_proposal(&proposal);
                Err(exec_err)
            }
        }
    }

    /// Format a `ChangeProposal` into a standard `McpSuccessResponse` matching the tool contract.
    pub fn proposal_to_response(
        request_id: impl Into<String>,
        proposal: &ChangeProposal,
    ) -> McpSuccessResponse<ChangeProposal> {
        let columns = vec![
            ColumnMetadata::new("change_id", "text"),
            ColumnMetadata::new("state", "text"),
            ColumnMetadata::new("approval_hash", "text"),
            ColumnMetadata::new("proposing_principal", "text"),
            ColumnMetadata::new("schema_fingerprint", "text"),
            ColumnMetadata::new("reversibility", "text"),
            ColumnMetadata::new("expires_at", "timestamptz"),
        ];
        let state_val = serde_json::to_value(proposal.state)
            .unwrap_or_else(|_| serde_json::Value::String("proposed".to_string()));
        let rev_val = serde_json::to_value(proposal.reversal_safety)
            .unwrap_or_else(|_| serde_json::Value::String("transactional_rollback".to_string()));
        let rows = vec![vec![
            serde_json::Value::String(proposal.change_id.clone()),
            state_val,
            serde_json::Value::String(proposal.approval_hash.clone()),
            serde_json::Value::String(proposal.proposing_principal.clone()),
            serde_json::Value::String(proposal.schema_fingerprint.clone()),
            rev_val,
            serde_json::Value::String(proposal.expires_at.to_rfc3339()),
        ]];
        let mut resp = McpSuccessResponse::with_data(
            request_id,
            proposal.connection.clone(),
            proposal.schema_fingerprint.clone(),
            "change_proposal",
            proposal.clone(),
        );
        resp.columns = columns;
        resp.rows = rows;
        resp.returned_rows = 1;
        resp
    }

    /// Test/diagnostic helper to overwrite a stored proposal directly (e.g. to simulate tampering).
    pub fn overwrite_proposal_unchecked(&self, proposal: &ChangeProposal) -> DbMcpResult<()> {
        self.store_proposal(proposal)
    }

    fn init_sqlite_schema(&self) -> DbMcpResult<()> {
        let StorageBackend::Sqlite(path) = &self.backend else {
            return Ok(());
        };
        let conn = open_sqlite_conn(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS change_proposals (
                change_id TEXT PRIMARY KEY,
                connection TEXT NOT NULL,
                state TEXT NOT NULL,
                approval_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                proposal_json TEXT NOT NULL
            );",
        )
        .map_err(|e| {
            DbMcpError::StorageError(format!("Failed to initialize SQLite change store: {e}"))
        })?;
        Ok(())
    }

    fn store_proposal(&self, proposal: &ChangeProposal) -> DbMcpResult<()> {
        {
            let mut guard = self.memory_store.lock().map_err(|_| {
                DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
            })?;
            guard.insert(proposal.change_id.clone(), proposal.clone());
        }

        match &self.backend {
            StorageBackend::InMemory => Ok(()),
            StorageBackend::Sqlite(path) => {
                let conn = open_sqlite_conn(path)?;
                let state_str = state_to_str(proposal.state);
                let json_str = serde_json::to_string(proposal).map_err(|e| {
                    DbMcpError::StorageError(format!("Failed to serialize ChangeProposal: {e}"))
                })?;
                conn.execute(
                    "INSERT INTO change_proposals (change_id, connection, state, approval_hash, created_at, expires_at, proposal_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(change_id) DO UPDATE SET
                        connection = excluded.connection,
                        state = excluded.state,
                        approval_hash = excluded.approval_hash,
                        expires_at = excluded.expires_at,
                        proposal_json = excluded.proposal_json",
                    params![
                        proposal.change_id,
                        proposal.connection,
                        state_str,
                        proposal.approval_hash,
                        proposal.created_at.to_rfc3339(),
                        proposal.expires_at.to_rfc3339(),
                        json_str
                    ],
                )
                .map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to persist ChangeProposal '{}': {e}",
                        proposal.change_id
                    ))
                })?;
                Ok(())
            }
            StorageBackend::JsonFile(_) => {
                let mut all = self.load_all_from_json()?;
                all.insert(proposal.change_id.clone(), proposal.clone());
                self.save_all_to_json(&all)
            }
        }
    }

    /// Compare-and-swap: persist `proposal` only while the stored state still equals `expected`.
    /// Returns `Ok(false)` (and writes nothing) when another writer changed the state first.
    fn store_if_state(
        &self,
        proposal: &ChangeProposal,
        expected: ChangeState,
    ) -> DbMcpResult<bool> {
        match &self.backend {
            StorageBackend::InMemory => {
                let mut guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                let current = guard.get(&proposal.change_id).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!(
                        "Change proposal '{}' not found",
                        proposal.change_id
                    ))
                })?;
                if current.state != expected {
                    return Ok(false);
                }
                guard.insert(proposal.change_id.clone(), proposal.clone());
                Ok(true)
            }
            StorageBackend::Sqlite(path) => {
                let conn = open_sqlite_conn(path)?;
                let json_str = serde_json::to_string(proposal).map_err(|e| {
                    DbMcpError::StorageError(format!("Failed to serialize ChangeProposal: {e}"))
                })?;
                let affected = conn
                    .execute(
                        "UPDATE change_proposals SET state = ?2, approval_hash = ?3, proposal_json = ?4
                         WHERE change_id = ?1 AND state = ?5",
                        params![
                            proposal.change_id,
                            state_to_str(proposal.state),
                            proposal.approval_hash,
                            json_str,
                            state_to_str(expected)
                        ],
                    )
                    .map_err(|e| {
                        DbMcpError::StorageError(format!(
                            "Failed to persist ChangeProposal '{}': {e}",
                            proposal.change_id
                        ))
                    })?;
                if affected != 1 {
                    return Ok(false);
                }
                if let Ok(mut guard) = self.memory_store.lock() {
                    guard.insert(proposal.change_id.clone(), proposal.clone());
                }
                Ok(true)
            }
            StorageBackend::JsonFile(_) => {
                let mut guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                let mut all = self.load_all_from_json()?;
                let current = all.get(&proposal.change_id).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!(
                        "Change proposal '{}' not found",
                        proposal.change_id
                    ))
                })?;
                if current.state != expected {
                    return Ok(false);
                }
                all.insert(proposal.change_id.clone(), proposal.clone());
                self.save_all_to_json(&all)?;
                guard.insert(proposal.change_id.clone(), proposal.clone());
                Ok(true)
            }
        }
    }

    fn load_proposal(&self, change_id: &str) -> DbMcpResult<ChangeProposal> {
        match &self.backend {
            StorageBackend::InMemory => {
                let guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                guard.get(change_id).cloned().ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Change proposal '{change_id}' not found"))
                })
            }
            StorageBackend::Sqlite(path) => {
                let conn = open_sqlite_conn(path)?;
                let json_opt: Option<String> = conn
                    .query_row(
                        "SELECT proposal_json FROM change_proposals WHERE change_id = ?1",
                        params![change_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| {
                        DbMcpError::StorageError(format!(
                            "Failed to read ChangeProposal '{change_id}' from SQLite: {e}"
                        ))
                    })?;
                let json_str = json_opt.ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Change proposal '{change_id}' not found"))
                })?;
                let proposal: ChangeProposal = serde_json::from_str(&json_str).map_err(|e| {
                    DbMcpError::StorageError(format!(
                        "Failed to deserialize ChangeProposal '{change_id}': {e}"
                    ))
                })?;
                if let Ok(mut guard) = self.memory_store.lock() {
                    guard.insert(proposal.change_id.clone(), proposal.clone());
                }
                Ok(proposal)
            }
            StorageBackend::JsonFile(_) => {
                let all = self.load_all_from_json()?;
                let proposal = all.get(change_id).cloned().ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Change proposal '{change_id}' not found"))
                })?;
                if let Ok(mut guard) = self.memory_store.lock() {
                    guard.insert(proposal.change_id.clone(), proposal.clone());
                }
                Ok(proposal)
            }
        }
    }

    fn load_all_proposals(&self) -> DbMcpResult<Vec<ChangeProposal>> {
        match &self.backend {
            StorageBackend::InMemory => {
                let guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                Ok(guard.values().cloned().collect())
            }
            StorageBackend::Sqlite(path) => {
                let conn = open_sqlite_conn(path)?;
                let mut stmt = conn
                    .prepare("SELECT proposal_json FROM change_proposals ORDER BY created_at ASC")
                    .map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to prepare SQLite query: {e}"))
                    })?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to query change proposals: {e}"))
                    })?;
                let mut out = Vec::new();
                for r in rows {
                    let s = r.map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to read row: {e}"))
                    })?;
                    let prop: ChangeProposal = serde_json::from_str(&s).map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to parse proposal JSON: {e}"))
                    })?;
                    out.push(prop);
                }
                Ok(out)
            }
            StorageBackend::JsonFile(_) => {
                let all = self.load_all_from_json()?;
                Ok(all.into_values().collect())
            }
        }
    }

    fn atomic_claim_execution(&self, change_id: &str) -> DbMcpResult<()> {
        match &self.backend {
            StorageBackend::InMemory => {
                let mut guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                let prop = guard.get_mut(change_id).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Change proposal '{change_id}' not found"))
                })?;
                if prop.state != ChangeState::Approved {
                    return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                        "Change '{change_id}' cannot be claimed for execution (current state: {:?})",
                        prop.state
                    )));
                }
                prop.state = ChangeState::Executing;
                Ok(())
            }
            StorageBackend::Sqlite(path) => {
                let conn = open_sqlite_conn(path)?;
                let json_opt: Option<String> = conn
                    .query_row(
                        "SELECT proposal_json FROM change_proposals WHERE change_id = ?1 AND state = 'approved'",
                        params![change_id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to query claimable change: {e}"))
                    })?;
                let Some(json_str) = json_opt else {
                    return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                        "Change '{change_id}' is no longer in 'approved' state and cannot be claimed"
                    )));
                };
                let mut prop: ChangeProposal = serde_json::from_str(&json_str).map_err(|e| {
                    DbMcpError::StorageError(format!("Failed to parse proposal JSON: {e}"))
                })?;
                prop.state = ChangeState::Executing;
                let updated_json = serde_json::to_string(&prop).map_err(|e| {
                    DbMcpError::StorageError(format!("Failed to serialize proposal JSON: {e}"))
                })?;
                let affected = conn
                    .execute(
                        "UPDATE change_proposals SET state = 'executing', proposal_json = ?2 WHERE change_id = ?1 AND state = 'approved'",
                        params![change_id, updated_json],
                    )
                    .map_err(|e| {
                        DbMcpError::StorageError(format!("Failed to claim change execution: {e}"))
                    })?;
                if affected != 1 {
                    return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                        "Concurrent execution already claimed change '{change_id}'"
                    )));
                }
                if let Ok(mut guard) = self.memory_store.lock() {
                    guard.insert(prop.change_id.clone(), prop);
                }
                Ok(())
            }
            StorageBackend::JsonFile(_) => {
                let mut guard = self.memory_store.lock().map_err(|_| {
                    DbMcpError::InternalError("ChangeManager mutex poisoned".to_string())
                })?;
                let mut all = self.load_all_from_json()?;
                let prop = all.get_mut(change_id).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Change proposal '{change_id}' not found"))
                })?;
                if prop.state != ChangeState::Approved {
                    return Err(DbMcpError::ApprovalAlreadyConsumed(format!(
                        "Change '{change_id}' cannot be claimed for execution (current state: {:?})",
                        prop.state
                    )));
                }
                prop.state = ChangeState::Executing;
                let cloned = prop.clone();
                self.save_all_to_json(&all)?;
                guard.insert(change_id.to_string(), cloned);
                Ok(())
            }
        }
    }

    fn load_all_from_json(&self) -> DbMcpResult<BTreeMap<String, ChangeProposal>> {
        let StorageBackend::JsonFile(path) = &self.backend else {
            return Ok(BTreeMap::new());
        };
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(path).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to read JSON change store '{}': {e}",
                path.display()
            ))
        })?;
        if raw.trim().is_empty() {
            return Ok(BTreeMap::new());
        }
        serde_json::from_str(&raw).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to parse JSON change store '{}': {e}",
                path.display()
            ))
        })
    }

    fn save_all_to_json(&self, map: &BTreeMap<String, ChangeProposal>) -> DbMcpResult<()> {
        let StorageBackend::JsonFile(path) = &self.backend else {
            return Ok(());
        };
        let serialized = serde_json::to_string_pretty(map).map_err(|e| {
            DbMcpError::StorageError(format!("Failed to serialize JSON change store: {e}"))
        })?;
        fs::write(path, serialized).map_err(|e| {
            DbMcpError::StorageError(format!(
                "Failed to write JSON change store '{}': {e}",
                path.display()
            ))
        })
    }
}

fn open_sqlite_conn(path: &Path) -> DbMcpResult<Connection> {
    let conn = Connection::open(path).map_err(|e| {
        DbMcpError::StorageError(format!(
            "Failed to open SQLite change store '{}': {e}",
            path.display()
        ))
    })?;
    let _ = conn.busy_timeout(std::time::Duration::from_millis(5_000));
    let _ = conn.pragma_update(None, "journal_mode", "DELETE");
    Ok(conn)
}

fn state_to_str(state: ChangeState) -> &'static str {
    match state {
        ChangeState::Proposed => "proposed",
        ChangeState::Approved => "approved",
        ChangeState::Rejected => "rejected",
        ChangeState::Executing => "executing",
        ChangeState::Applied => "applied",
        ChangeState::Failed => "failed",
        ChangeState::Expired => "expired",
    }
}

/// Reject statements that can never be a governed change, independent of connection policy:
/// privileged/side-effecting functions, unclassifiable SQL, plain reads (nothing to govern) and
/// administrative/privilege statements (`GRANT`, `VACUUM`, ...). Connection policy (restricted
/// tables, multi-statement, ReadOnly mode) is enforced by the caller's `PolicyEngine`.
pub fn validate_change_statement(analysis: &SqlAnalysis) -> DbMcpResult<()> {
    if analysis.has_privileged_functions {
        return Err(DbMcpError::PolicyDenied {
            code: "PRIVILEGED_FUNCTION_FORBIDDEN".to_string(),
            message: format!(
                "Side-effecting or privileged function(s) {:?} cannot be proposed in governed changes",
                analysis.privileged_functions
            ),
            next_action: Some("remove_privileged_function".to_string()),
        });
    }
    match analysis.overall_class {
        SqlStatementClass::Unknown => Err(DbMcpError::PolicyDenied {
            code: "UNKNOWN_SQL_CONSTRUCT".to_string(),
            message:
                "Unclassified or vendor-specific SQL construct cannot be proposed in governed mode"
                    .to_string(),
            next_action: None,
        }),
        SqlStatementClass::Read if !analysis.has_cte_write => Err(DbMcpError::PolicyDenied {
            code: CODE_NOT_A_CHANGE.to_string(),
            message:
                "Read-only statements change nothing and cannot be proposed as governed changes"
                    .to_string(),
            next_action: Some("execute_query".to_string()),
        }),
        SqlStatementClass::PrivilegeOrAdmin => Err(DbMcpError::PolicyDenied {
            code: "PRIVILEGED_FUNCTION_FORBIDDEN".to_string(),
            message:
                "Administrative or privilege statements cannot be proposed as governed changes"
                    .to_string(),
            next_action: None,
        }),
        _ => Ok(()),
    }
}

/// Keyed MAC binding an approval record to its change:
/// `HMAC-SHA256(key, "v1|change_id=..|approval_hash=..|approved_by=..|approved_at=<rfc3339>|comment=<json>")`.
pub fn compute_approval_mac(key: &[u8], change_id: &str, record: &ApprovalRecord) -> String {
    let comment = serde_json::to_string(&record.comment).unwrap_or_else(|_| "null".to_string());
    let payload = format!(
        "v1|change_id={change_id}|approval_hash={}|approved_by={}|approved_at={}|comment={comment}",
        record.approval_hash,
        record.approved_by,
        record.approved_at.to_rfc3339()
    );
    hmac_sha256_hex(key, payload.as_bytes())
}

/// Denial for approving a change that is no longer pending.
fn change_not_pending(change_id: &str, proposal: &ChangeProposal) -> DbMcpError {
    match (proposal.state, proposal.approval.as_ref()) {
        (ChangeState::Applied | ChangeState::Executing, _) => {
            DbMcpError::ApprovalAlreadyConsumed(format!(
                "Change '{}' has already been executed (state: {:?})",
                change_id, proposal.state
            ))
        }
        (ChangeState::Expired, _) => DbMcpError::ApprovalExpired(format!(
            "Change proposal '{}' expired at {}",
            change_id,
            proposal.expires_at.to_rfc3339()
        )),
        (ChangeState::Approved, Some(record)) => DbMcpError::PolicyDenied {
            code: CODE_CHANGE_NOT_PENDING.to_string(),
            message: format!(
                "Change '{}' was already approved by '{}' at {}; an approval cannot be replaced",
                change_id,
                record.approved_by,
                record.approved_at.to_rfc3339()
            ),
            next_action: Some("get_change".to_string()),
        },
        (state, _) => DbMcpError::PolicyDenied {
            code: CODE_CHANGE_NOT_PENDING.to_string(),
            message: format!(
                "Change '{}' is in state '{}'; only proposed changes can be approved",
                change_id,
                state_to_str(state)
            ),
            next_action: Some("propose_change".to_string()),
        },
    }
}

/// Random per-process approval key for in-memory stores (not shared with any other process).
fn ephemeral_approval_key() -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key
}

/// Classify whether a proposed SQL change is transactional and its `ReversalSafety` level
/// (`TransactionalRollback`, `CompensatingMigrationRequired`, or `BackupRecoveryRequired`),
/// plus an optional compensating SQL template when applicable.
pub fn classify_change_reversibility(
    engine: DatabaseEngine,
    analysis: &SqlAnalysis,
) -> (bool, ReversalSafety, Option<String>) {
    let transactional = analysis
        .statements
        .iter()
        .all(|s| s.is_transactional_ddl_safe);
    let upper = analysis.normalized_sql.to_ascii_uppercase();

    // 1. Destructive operations require point-in-time backup recovery
    let is_destructive = upper.starts_with("DROP TABLE ")
        || upper.starts_with("DROP SCHEMA ")
        || upper.starts_with("DROP DATABASE ")
        || upper.starts_with("TRUNCATE ")
        || upper.starts_with("DELETE ")
        || (upper.starts_with("ALTER TABLE ") && upper.contains(" DROP COLUMN "));

    if is_destructive {
        return (transactional, ReversalSafety::BackupRecoveryRequired, None);
    }

    // 2. Additive DDL with clean inverse DDL
    if upper.starts_with("CREATE INDEX ") || upper.starts_with("CREATE UNIQUE INDEX ") {
        let index_name = extract_created_index_name(&analysis.normalized_sql);
        let compensating = index_name.map(|idx| {
            if engine == DatabaseEngine::Postgres && upper.contains("CONCURRENTLY") {
                format!("DROP INDEX CONCURRENTLY IF EXISTS {idx};")
            } else {
                format!("DROP INDEX IF EXISTS {idx};")
            }
        });
        let safety = if transactional {
            ReversalSafety::TransactionalRollback
        } else {
            ReversalSafety::CompensatingMigrationRequired
        };
        return (transactional, safety, compensating);
    }

    if upper.starts_with("CREATE TABLE ") {
        let tbl = analysis.referenced_tables.first().cloned();
        let compensating = tbl.map(|t| format!("DROP TABLE IF EXISTS {t};"));
        let safety = if transactional {
            ReversalSafety::TransactionalRollback
        } else {
            ReversalSafety::CompensatingMigrationRequired
        };
        return (transactional, safety, compensating);
    }

    if upper.starts_with("CREATE VIEW ") || upper.starts_with("CREATE OR REPLACE VIEW ") {
        let safety = if transactional {
            ReversalSafety::TransactionalRollback
        } else {
            ReversalSafety::CompensatingMigrationRequired
        };
        return (transactional, safety, None);
    }

    if upper.starts_with("ALTER TABLE ") && upper.contains(" ADD ") && !upper.contains(" TYPE ") {
        let safety = if transactional {
            ReversalSafety::TransactionalRollback
        } else {
            ReversalSafety::CompensatingMigrationRequired
        };
        return (transactional, safety, None);
    }

    // 3. All other mutations (UPDATE, INSERT, ALTER COLUMN TYPE, DROP INDEX, MySQL DDL)
    // require a compensating migration to reverse after commit.
    (
        transactional,
        ReversalSafety::CompensatingMigrationRequired,
        None,
    )
}

fn extract_created_index_name(normalized_sql: &str) -> Option<String> {
    let tokens: Vec<&str> = normalized_sql.split_whitespace().collect();
    for (idx, word) in tokens.iter().enumerate() {
        if word.eq_ignore_ascii_case("ON") && idx >= 2 {
            let candidate = tokens[idx - 1];
            if !candidate.eq_ignore_ascii_case("INDEX")
                && !candidate.eq_ignore_ascii_case("CONCURRENTLY")
                && !candidate.eq_ignore_ascii_case("EXISTS")
            {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use db_mcp_catalog::filter_and_paginate_objects;
    use db_mcp_core::{
        CatalogObject, CatalogObjectType, CatalogRequest, CatalogResponse, ColumnSpec,
        DatabaseCapabilities, ExplainPlan, ExplainRequest,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockChangeAdapter {
        connection_id: String,
        engine: DatabaseEngine,
        objects: Arc<Mutex<Vec<CatalogObject>>>,
        executed_queries: Arc<Mutex<Vec<String>>>,
        execute_count: AtomicUsize,
    }

    impl MockChangeAdapter {
        fn new(connection_id: &str, engine: DatabaseEngine) -> Self {
            let initial_objects = vec![CatalogObject {
                schema: "public".to_string(),
                name: "users".to_string(),
                object_type: CatalogObjectType::Table,
                comment: None,
                estimated_rows: Some(100),
                size_bytes: Some(8192),
                columns: vec![
                    ColumnSpec {
                        name: "id".to_string(),
                        data_type: "bigint".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: true,
                        comment: None,
                        ordinal_position: 1,
                    },
                    ColumnSpec {
                        name: "role".to_string(),
                        data_type: "text".to_string(),
                        nullable: false,
                        default_value: Some("'member'".to_string()),
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 2,
                    },
                ],
                indexes: Vec::new(),
                foreign_keys: Vec::new(),
                definition: None,
            }];
            Self {
                connection_id: connection_id.to_string(),
                engine,
                objects: Arc::new(Mutex::new(initial_objects)),
                executed_queries: Arc::new(Mutex::new(Vec::new())),
                execute_count: AtomicUsize::new(0),
            }
        }

        fn simulate_schema_drift(&self) {
            let mut guard = self.objects.lock().unwrap();
            guard[0].columns.push(ColumnSpec {
                name: "unexpected_drift_col".to_string(),
                data_type: "text".to_string(),
                nullable: true,
                default_value: None,
                is_primary_key: false,
                comment: None,
                ordinal_position: 3,
            });
        }
    }

    #[async_trait]
    impl DatabaseAdapter for MockChangeAdapter {
        fn connection_id(&self) -> &str {
            &self.connection_id
        }

        fn capabilities(&self) -> DatabaseCapabilities {
            match self.engine {
                DatabaseEngine::Postgres => DatabaseCapabilities::for_postgres(true, true),
                DatabaseEngine::MySql => DatabaseCapabilities::for_mysql(),
                DatabaseEngine::Sqlite => DatabaseCapabilities::for_sqlite(),
                DatabaseEngine::SqlServer => DatabaseCapabilities::for_sqlserver(),
            }
        }

        async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
            let objs = self.objects.lock().unwrap().clone();
            Ok(filter_and_paginate_objects(&objs, &request))
        }

        async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
            self.execute_count.fetch_add(1, Ordering::SeqCst);
            self.executed_queries
                .lock()
                .unwrap()
                .push(request.normalized_sql.clone());
            Ok(QueryResult {
                execution_id: request.execution_id,
                columns: Vec::new(),
                rows: Vec::new(),
                returned_rows: 0,
                rows_affected: Some(1),
                truncated: false,
                bytes_used: 0,
                execution_time_ms: 2,
                warnings: Vec::new(),
                schema_version: None,
            })
        }

        async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
            Ok(ExplainPlan {
                connection: self.connection_id.clone(),
                sql: request.sql,
                analyze: request.analyze,
                format: request.format,
                raw_plan: "Plan".to_string(),
                structured_plan: None,
                estimated_cost: Some(1.0),
                estimated_rows: Some(1.0),
                seq_scans: Vec::new(),
                index_scans: Vec::new(),
                warnings: Vec::new(),
            })
        }

        async fn cancel(&self, _execution: ExecutionId) -> DbMcpResult<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_happy_path_propose_approve_apply_and_sqlite_persistence() {
        let temp_path = std::env::temp_dir().join(format!(
            "db_mcp_changes_test_{}.sqlite",
            Uuid::new_v4().simple()
        ));
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let agent = CallerIdentity::local_agent("agent:cursor");
        let admin = CallerIdentity::admin("admin:dba-alice");

        // Process 1 (MCP server): propose change
        let server_mgr = ChangeManager::with_sqlite_path(&temp_path).unwrap();
        let proposed = server_mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "CREATE INDEX idx_users_role ON public.users (role);",
                Vec::new(),
                None,
                Some(3600),
            )
            .await
            .unwrap();

        assert_eq!(proposed.state, ChangeState::Proposed);
        assert_eq!(
            proposed.reversal_safety,
            ReversalSafety::TransactionalRollback
        );
        assert_eq!(
            proposed.compensating_sql.as_deref(),
            Some("DROP INDEX IF EXISTS idx_users_role;")
        );

        // Process 2 (out-of-band CLI `db-mcp approve`): open same SQLite file and approve
        let cli_mgr = ChangeManager::with_sqlite_path(&temp_path).unwrap();
        let approved = cli_mgr
            .approve_change(
                &proposed.change_id,
                &admin,
                Some("Reviewed and approved for production rollout".to_string()),
            )
            .unwrap();
        assert_eq!(approved.state, ChangeState::Approved);
        assert_eq!(
            approved.approval.as_ref().unwrap().approved_by,
            "admin:dba-alice"
        );

        // Process 1 (MCP server): apply approved change
        let outcome = server_mgr
            .apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap();
        assert_eq!(outcome.proposal.state, ChangeState::Applied);
        assert!(outcome.proposal.applied_at.is_some());
        assert_eq!(adapter.execute_count.load(Ordering::SeqCst), 1);

        let _ = fs::remove_file(&temp_path);
    }

    #[tokio::test]
    async fn test_self_approval_and_agent_approval_denied() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let agent = CallerIdentity::local_agent("agent:cursor");

        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "ALTER TABLE public.users ADD COLUMN bio TEXT",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap();

        // Case 1: Proposing principal tries to approve its own change (even if disguised as admin)
        let same_principal_admin = CallerIdentity::admin("agent:cursor");
        let err1 = mgr
            .approve_change(&proposed.change_id, &same_principal_admin, None)
            .unwrap_err();
        assert_eq!(err1.code(), "SELF_APPROVAL_FORBIDDEN");

        // Case 2: A different coding agent principal tries to approve
        let second_agent = CallerIdentity::local_agent("agent:other-bot");
        let err2 = mgr
            .approve_change(&proposed.change_id, &second_agent, None)
            .unwrap_err();
        assert_eq!(err2.code(), "SELF_APPROVAL_FORBIDDEN");
    }

    #[tokio::test]
    async fn test_unapproved_apply_and_replay_attack_denied() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let agent = CallerIdentity::local_agent("agent:cursor");
        let admin = CallerIdentity::admin("admin:dba-bob");

        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "CREATE INDEX idx_users_role ON public.users (role)",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap();

        // Attempting to apply before approval must fail with APPROVAL_REQUIRED
        let unapproved_err = mgr
            .apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(unapproved_err.code(), "APPROVAL_REQUIRED");

        // Approve and apply once
        mgr.approve_change(&proposed.change_id, &admin, None)
            .unwrap();
        mgr.apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap();

        // Replay attack: attempting to apply the same change_id a second time must fail with APPROVAL_ALREADY_CONSUMED
        let replay_err = mgr
            .apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(replay_err.code(), "APPROVAL_ALREADY_CONSUMED");
        assert_eq!(adapter.execute_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_sql_tampering_hash_mismatch_rejected() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let agent = CallerIdentity::local_agent("agent:cursor");
        let admin = CallerIdentity::admin("admin:dba-alice");

        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "CREATE INDEX idx_users_role ON public.users (role)",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap();

        let approved = mgr
            .approve_change(&proposed.change_id, &admin, None)
            .unwrap();

        // Tamper with the stored SQL after approval
        let mut tampered = approved.clone();
        tampered.sql = "DROP TABLE public.users".to_string();
        tampered.normalized_sql = "DROP TABLE public.users".to_string();
        mgr.overwrite_proposal_unchecked(&tampered).unwrap();

        let err = mgr
            .apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "APPROVAL_HASH_MISMATCH");
        assert_eq!(adapter.execute_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_schema_drift_rejected_prior_to_execution() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let agent = CallerIdentity::local_agent("agent:cursor");
        let admin = CallerIdentity::admin("admin:dba-alice");

        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "ALTER TABLE public.users ADD COLUMN bio TEXT",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap();

        mgr.approve_change(&proposed.change_id, &admin, None)
            .unwrap();

        // Simulate concurrent schema drift on the target database before apply_change runs
        adapter.simulate_schema_drift();

        let drift_err = mgr
            .apply_change(&proposed.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(drift_err.code(), "SCHEMA_DRIFT_DETECTED");
        assert_eq!(adapter.execute_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_expired_proposal_rejected_and_marked_expired() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let agent = CallerIdentity::local_agent("agent:cursor");
        let admin = CallerIdentity::admin("admin:dba-alice");

        // Create proposal with the minimum TTL, then wait for it to expire
        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "CREATE INDEX idx_users_role ON public.users (role)",
                Vec::new(),
                None,
                Some(1),
            )
            .await
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1500));

        let approve_err = mgr
            .approve_change(&proposed.change_id, &admin, None)
            .unwrap_err();
        assert_eq!(approve_err.code(), "APPROVAL_EXPIRED");

        let fetched = mgr.get_change(&proposed.change_id).unwrap();
        assert_eq!(fetched.state, ChangeState::Expired);
    }

    #[test]
    fn test_reversibility_classification_destructive_vs_transactional_vs_compensating() {
        let drop_analysis =
            parse_and_analyze_sql(DatabaseEngine::Postgres, "DROP TABLE public.users").unwrap();
        let (tx1, safety1, _) =
            classify_change_reversibility(DatabaseEngine::Postgres, &drop_analysis);
        assert!(tx1);
        assert_eq!(safety1, ReversalSafety::BackupRecoveryRequired);

        let concurrent_idx_analysis = parse_and_analyze_sql(
            DatabaseEngine::Postgres,
            "CREATE INDEX CONCURRENTLY idx_users_role ON public.users (role)",
        )
        .unwrap();
        let (tx2, safety2, comp2) =
            classify_change_reversibility(DatabaseEngine::Postgres, &concurrent_idx_analysis);
        assert!(!tx2);
        assert_eq!(safety2, ReversalSafety::CompensatingMigrationRequired);
        assert_eq!(
            comp2.as_deref(),
            Some("DROP INDEX CONCURRENTLY IF EXISTS idx_users_role;")
        );
    }

    #[tokio::test]
    async fn test_json_persistence_privileged_rejection_and_response_envelope() {
        let temp_json = std::env::temp_dir().join(format!(
            "db_mcp_changes_test_{}.json",
            Uuid::new_v4().simple()
        ));
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let agent = CallerIdentity::local_agent("agent:cursor");
        let mgr = ChangeManager::with_storage_path(&temp_json).unwrap();

        // Privileged function in proposal must be denied
        let priv_err = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "SELECT pg_read_file('/etc/passwd')",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(priv_err.code(), "PRIVILEGED_FUNCTION_FORBIDDEN");

        let proposed = mgr
            .propose_change_with_adapter(
                &agent,
                &adapter,
                "CREATE INDEX idx_users_role ON public.users (role)",
                Vec::new(),
                None,
                None,
            )
            .await
            .unwrap();

        // Second manager instance reading from the same JSON file
        let mgr2 = ChangeManager::with_storage_path(&temp_json).unwrap();
        let loaded = mgr2.get_change(&proposed.change_id).unwrap();
        assert_eq!(loaded.approval_hash, proposed.approval_hash);

        let resp = ChangeManager::proposal_to_response("req_prop_1", &loaded);
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.columns.len(), 7);
        assert_eq!(resp.columns[0].name, "change_id");
        assert_eq!(resp.columns[6].name, "expires_at");

        let _ = fs::remove_file(&temp_json);
    }

    const TEST_KEY: &str = "unit-test-approval-key-0123456789";

    fn temp_store(ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "db_mcp_changes_test_{}.{ext}",
            Uuid::new_v4().simple()
        ))
    }

    async fn propose(
        mgr: &ChangeManager,
        adapter: &MockChangeAdapter,
        sql: &str,
    ) -> ChangeProposal {
        mgr.propose_change_with_adapter(
            &CallerIdentity::local_agent("agent:cursor"),
            adapter,
            sql,
            Vec::new(),
            None,
            None,
        )
        .await
        .unwrap()
    }

    #[test]
    fn test_validate_change_statement_rejects_reads_and_admin_statements() {
        let select =
            parse_and_analyze_sql(DatabaseEngine::Postgres, "SELECT id FROM users").unwrap();
        assert_eq!(
            validate_change_statement(&select).unwrap_err().code(),
            CODE_NOT_A_CHANGE
        );
        let vacuum = parse_and_analyze_sql(DatabaseEngine::Sqlite, "VACUUM").unwrap();
        assert_eq!(vacuum.overall_class, SqlStatementClass::PrivilegeOrAdmin);
        assert!(validate_change_statement(&vacuum).is_err());
        let update = parse_and_analyze_sql(
            DatabaseEngine::Postgres,
            "UPDATE users SET role = 'x' WHERE id = 1",
        )
        .unwrap();
        assert!(validate_change_statement(&update).is_ok());
    }

    #[tokio::test]
    async fn test_second_rejected_and_concurrent_approvals_only_one_wins() {
        let path = temp_store("db");
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::with_sqlite_path(&path)
            .unwrap()
            .with_approval_key(TEST_KEY)
            .unwrap();

        // Second approval never replaces the first.
        let p = propose(
            &mgr,
            &adapter,
            "CREATE INDEX idx_users_role ON public.users (role)",
        )
        .await;
        mgr.approve_change(
            &p.change_id,
            &CallerIdentity::admin("admin:alice"),
            Some("first".to_string()),
        )
        .unwrap();
        let err = mgr
            .approve_change(&p.change_id, &CallerIdentity::admin("admin:bob"), None)
            .unwrap_err();
        assert_eq!(err.code(), CODE_CHANGE_NOT_PENDING);
        let kept = mgr.get_change(&p.change_id).unwrap().approval.unwrap();
        assert_eq!(kept.approved_by, "admin:alice");
        assert_eq!(kept.comment.as_deref(), Some("first"));

        // A rejected change cannot be re-approved.
        let r = propose(
            &mgr,
            &adapter,
            "ALTER TABLE public.users ADD COLUMN bio TEXT",
        )
        .await;
        mgr.reject_change(&r.change_id, &CallerIdentity::admin("admin:alice"), None)
            .unwrap();
        let err = mgr
            .approve_change(&r.change_id, &CallerIdentity::admin("admin:bob"), None)
            .unwrap_err();
        assert_eq!(err.code(), CODE_CHANGE_NOT_PENDING);

        // Concurrent approvals from separate managers (processes) over one store: exactly one wins.
        let c = propose(
            &mgr,
            &adapter,
            "UPDATE public.users SET role = 'x' WHERE id = 1",
        )
        .await;
        let handles: Vec<_> = (0..6)
            .map(|i| {
                let path = path.clone();
                let id = c.change_id.clone();
                std::thread::spawn(move || {
                    let m = ChangeManager::with_sqlite_path(&path)
                        .unwrap()
                        .with_approval_key(TEST_KEY)
                        .unwrap();
                    m.approve_change(&id, &CallerIdentity::admin(format!("admin:{i}")), None)
                        .is_ok()
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1);
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_forged_or_unkeyed_approval_rejected_and_apply_records_outcome() {
        let path = temp_store("db");
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let agent = CallerIdentity::local_agent("agent:cursor");
        let keyed = ChangeManager::with_sqlite_path(&path)
            .unwrap()
            .with_approval_key(TEST_KEY)
            .unwrap();

        // Approval record forged directly in the store (no MAC) is rejected before execution.
        let p = propose(
            &keyed,
            &adapter,
            "UPDATE public.users SET role = 'x' WHERE id = 1",
        )
        .await;
        let mut forged = p.clone();
        forged.state = ChangeState::Approved;
        forged.approval = Some(ApprovalRecord {
            approved_by: "ghost".to_string(),
            approved_at: Utc::now(),
            approval_hash: p.approval_hash.clone(),
            comment: None,
            approval_mac: Some("00".repeat(32)),
        });
        keyed.overwrite_proposal_unchecked(&forged).unwrap();
        let err = keyed
            .apply_change(&p.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "APPROVAL_HASH_MISMATCH");

        // A MAC made with another key is rejected too.
        let other = ChangeManager::with_sqlite_path(&path)
            .unwrap()
            .with_approval_key("another-approval-key-9876543210")
            .unwrap();
        let q = propose(
            &keyed,
            &adapter,
            "UPDATE public.users SET role = 'y' WHERE id = 1",
        )
        .await;
        other
            .approve_change(&q.change_id, &CallerIdentity::admin("admin:alice"), None)
            .unwrap();
        let err = keyed
            .apply_change(&q.change_id, &agent, &adapter)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "APPROVAL_HASH_MISMATCH");
        assert_eq!(adapter.execute_count.load(Ordering::SeqCst), 0);

        // Unkeyed store: refused when keyed approvals are required, warned otherwise.
        let unkeyed = ChangeManager::with_sqlite_path(&path).unwrap();
        assert!(!unkeyed.approval_warnings().is_empty());
        let u = propose(
            &unkeyed,
            &adapter,
            "UPDATE public.users SET role = 'z' WHERE id = 1",
        )
        .await;
        let approved = unkeyed
            .approve_change(&u.change_id, &CallerIdentity::admin("admin:alice"), None)
            .unwrap();
        assert!(approved.approval.unwrap().approval_mac.is_none());
        let strict = ApplyChangeOptions {
            require_approval_mac: true,
            ..ApplyChangeOptions::default()
        };
        let err = unkeyed
            .apply_change_with_options(&u.change_id, &agent, &adapter, strict)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CODE_APPROVAL_KEY_REQUIRED);
        let outcome = unkeyed
            .apply_change(&u.change_id, &agent, &adapter)
            .await
            .unwrap();
        assert_eq!(outcome.warnings, vec![UNKEYED_APPROVAL_WARNING.to_string()]);
        assert_eq!(outcome.proposal.applied_by.as_deref(), Some("agent:cursor"));
        assert_eq!(outcome.proposal.rows_affected, Some(1));
        let stored = unkeyed.get_change(&u.change_id).unwrap();
        assert_eq!(stored.applied_by.as_deref(), Some("agent:cursor"));
        assert_eq!(stored.rows_affected, Some(1));

        // Short keys are refused (fail closed).
        assert!(ChangeManager::new_in_memory()
            .with_approval_key("short")
            .is_err());
        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_apply_before_approval_points_to_out_of_band_approval() {
        let adapter = MockChangeAdapter::new("prod-pg", DatabaseEngine::Postgres);
        let mgr = ChangeManager::new_in_memory();
        let p = propose(
            &mgr,
            &adapter,
            "CREATE INDEX idx_users_role ON public.users (role)",
        )
        .await;
        let err = mgr
            .apply_change(
                &p.change_id,
                &CallerIdentity::local_agent("agent:cursor"),
                &adapter,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "APPROVAL_REQUIRED");
        assert_eq!(
            err.next_action(),
            Some(
                format!(
                    "db-mcp approve --change-id {} --approver <admin>",
                    p.change_id
                )
                .as_str()
            )
        );
    }
}
