//! Bounded query execution pipeline enforcing deadlines, cancellation, row/byte limits,
//! result disclosure controls, and audit logging.
//!
//! Responsibilities:
//! - Maintain an active execution registry (`DashMap<ExecutionId, CancellationToken>`) and
//!   request-ID-to-execution-ID mapping.
//! - Enforce execution deadlines (`tokio::time::timeout`) with automatic adapter-level
//!   cancellation (`adapter.cancel(execution_id)`) when a timeout or client cancellation
//!   notification (`cancel_execution`) triggers.
//! - Enforce row limit truncation (`max_rows`, setting `truncated = true` and adding a warning)
//!   and byte budget limits (`max_bytes`).
//! - Provide the end-to-end governed execution pipeline (`execute_governed_query` and
//!   `explain_governed_query`): SQL analysis -> `PolicyEngine` evaluation -> bounded execution ->
//!   result disclosure controls -> `AuditEvent` persistence.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use db_mcp_audit::{create_audit_event, AuditSink, InMemoryAuditStore};
use db_mcp_core::{
    AuditDecision, AuthorizedQuery, CallerIdentity, DatabaseAdapter, DbMcpError, DbMcpResult,
    ExecutionId, ExplainPlan, ExplainRequest, OperatingMode, QueryResult, SqlStatementClass,
};
use db_mcp_policy::{
    apply_plan_disclosure_controls, apply_result_disclosure_controls, PolicyEngine,
};
use db_mcp_secrets::redact_sensitive_text;
use db_mcp_sql::parse_and_analyze_sql;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Request descriptor for the end-to-end governed query pipeline (`execute_governed_query`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernedQueryRequest {
    pub request_id: String,
    pub execution_id: ExecutionId,
    pub connection: String,
    pub caller: CallerIdentity,
    pub tool_name: String,
    pub sql: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms_override: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rows_override: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_override: Option<usize>,
    #[serde(default)]
    pub is_approved_change: bool,
    #[serde(default)]
    pub is_named_tool: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    /// Set by the caller after a fresh catalog lookup showed that no table the statement reads
    /// has a sensitive column; untracked result provenance (wildcards in positional contexts,
    /// column alias lists, whole-row references) can then not expose one.
    #[serde(default)]
    pub sources_verified_without_sensitive_columns: bool,
}

impl GovernedQueryRequest {
    pub fn new(
        request_id: impl Into<String>,
        connection: impl Into<String>,
        caller: CallerIdentity,
        sql: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            execution_id: ExecutionId::new(),
            connection: connection.into(),
            caller,
            tool_name: "execute_query".to_string(),
            sql: sql.into(),
            params: Vec::new(),
            timeout_ms_override: None,
            max_rows_override: None,
            max_bytes_override: None,
            is_approved_change: false,
            is_named_tool: false,
            change_id: None,
            sources_verified_without_sensitive_columns: false,
        }
    }

    pub fn with_execution_id(mut self, execution_id: ExecutionId) -> Self {
        self.execution_id = execution_id;
        self
    }

    pub fn with_tool_name(mut self, tool_name: impl Into<String>) -> Self {
        self.tool_name = tool_name.into();
        self
    }

    pub fn with_params(mut self, params: Vec<serde_json::Value>) -> Self {
        self.params = params;
        self
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms_override = Some(timeout_ms);
        self
    }

    pub fn with_max_rows(mut self, max_rows: usize) -> Self {
        self.max_rows_override = Some(max_rows);
        self
    }

    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes_override = Some(max_bytes);
        self
    }

    pub fn with_approved_change(mut self, change_id: impl Into<String>) -> Self {
        self.is_approved_change = true;
        self.change_id = Some(change_id.into());
        self
    }

    pub fn with_sources_verified_without_sensitive_columns(mut self, verified: bool) -> Self {
        self.sources_verified_without_sensitive_columns = verified;
        self
    }

    pub fn with_named_tool(mut self, is_named_tool: bool) -> Self {
        self.is_named_tool = is_named_tool;
        if is_named_tool && self.tool_name == "execute_query" {
            self.tool_name = "run_named_tool".to_string();
        }
        self
    }
}

/// Guard that automatically removes an `ExecutionId` from the active registry when dropped.
struct ActiveExecutionGuard {
    execution_id: ExecutionId,
    request_id: String,
    active_executions: Arc<DashMap<ExecutionId, CancellationToken>>,
    request_to_execution: Arc<DashMap<String, ExecutionId>>,
}

impl Drop for ActiveExecutionGuard {
    fn drop(&mut self) {
        self.active_executions.remove(&self.execution_id);
        self.request_to_execution.remove(&self.request_id);
    }
}

/// Bounded query executor managing in-flight cancellations, timeouts, row/byte budgets,
/// result disclosure, and audit persistence.
#[derive(Clone)]
pub struct BoundedExecutor {
    active_executions: Arc<DashMap<ExecutionId, CancellationToken>>,
    request_to_execution: Arc<DashMap<String, ExecutionId>>,
    policy_engine: Arc<PolicyEngine>,
    audit_sink: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for BoundedExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedExecutor")
            .field("active_executions", &self.active_executions.len())
            .finish()
    }
}

impl Default for BoundedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedExecutor {
    /// Create a new `BoundedExecutor` with default read-only policy and in-memory audit store.
    pub fn new() -> Self {
        Self {
            active_executions: Arc::new(DashMap::new()),
            request_to_execution: Arc::new(DashMap::new()),
            policy_engine: Arc::new(PolicyEngine::new(OperatingMode::ReadOnly)),
            audit_sink: Arc::new(InMemoryAuditStore::new()),
        }
    }

    /// Create a `BoundedExecutor` bound to a shared `PolicyEngine` and `AuditSink`.
    pub fn with_governance(
        policy_engine: Arc<PolicyEngine>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            active_executions: Arc::new(DashMap::new()),
            request_to_execution: Arc::new(DashMap::new()),
            policy_engine,
            audit_sink,
        }
    }

    /// Reference to the active execution map (`DashMap<ExecutionId, CancellationToken>`).
    pub fn active_executions(&self) -> &DashMap<ExecutionId, CancellationToken> {
        &self.active_executions
    }

    /// Number of currently running queries.
    pub fn active_count(&self) -> usize {
        self.active_executions.len()
    }

    /// Reference to the configured `PolicyEngine`.
    pub fn policy_engine(&self) -> &Arc<PolicyEngine> {
        &self.policy_engine
    }

    /// Reference to the configured `AuditSink`.
    pub fn audit_sink(&self) -> &Arc<dyn AuditSink> {
        &self.audit_sink
    }

    /// Pre-register or retrieve the `CancellationToken` for an `ExecutionId` before or during execution.
    pub fn register_execution(
        &self,
        execution_id: ExecutionId,
        request_id: Option<&str>,
    ) -> CancellationToken {
        let token = self
            .active_executions
            .entry(execution_id.clone())
            .or_insert_with(CancellationToken::new)
            .value()
            .clone();
        if let Some(req_id) = request_id {
            self.request_to_execution
                .insert(req_id.to_string(), execution_id);
        }
        token
    }

    /// Signal cancellation for `execution_id` via its `CancellationToken`.
    /// When the in-flight execution observes the token, it invokes `adapter.cancel(execution_id)` automatically.
    /// Returns `true` if an active execution was found and signalled.
    pub fn cancel_execution(&self, execution_id: &ExecutionId) -> bool {
        if let Some(entry) = self.active_executions.get(execution_id) {
            entry.value().cancel();
            return true;
        }
        false
    }

    /// Signal cancellation by MCP `request_id` (or `ExecutionId` string) when handling `notifications/cancelled`.
    pub fn cancel_by_request_id(&self, request_or_execution_id: &str) -> bool {
        if let Some(exec_id_ref) = self.request_to_execution.get(request_or_execution_id) {
            let exec_id = exec_id_ref.value().clone();
            drop(exec_id_ref);
            return self.cancel_execution(&exec_id);
        }
        let as_exec_id = ExecutionId(request_or_execution_id.to_string());
        self.cancel_execution(&as_exec_id)
    }

    /// Signal cancellation in the executor registry AND immediately invoke `adapter.cancel(execution_id)`.
    pub async fn cancel_execution_with_adapter(
        &self,
        adapter: &dyn DatabaseAdapter,
        execution_id: &ExecutionId,
    ) -> DbMcpResult<bool> {
        let signalled = self.cancel_execution(execution_id);
        let adapter_cancelled = adapter.cancel(execution_id.clone()).await?;
        Ok(signalled || adapter_cancelled)
    }

    /// Execute an `AuthorizedQuery` with deadline enforcement, cancellation token monitoring,
    /// adapter-level cancellation on timeout/cancel, and row/byte quota enforcement.
    pub async fn execute_bounded(
        &self,
        adapter: &dyn DatabaseAdapter,
        query: AuthorizedQuery,
    ) -> DbMcpResult<QueryResult> {
        let execution_id = query.execution_id.clone();
        let request_id = query.request_id.clone();
        let timeout_ms = if query.timeout_ms == 0 {
            10_000
        } else {
            query.timeout_ms
        };
        let max_rows = query.max_rows;
        let max_bytes = query.max_bytes;

        let token = self.register_execution(execution_id.clone(), Some(&request_id));
        let _guard = ActiveExecutionGuard {
            execution_id: execution_id.clone(),
            request_id,
            active_executions: Arc::clone(&self.active_executions),
            request_to_execution: Arc::clone(&self.request_to_execution),
        };

        // Check if already cancelled prior to starting adapter call
        if token.is_cancelled() {
            let _ = adapter.cancel(execution_id.clone()).await;
            return Err(DbMcpError::ExecutionCancelled(format!(
                "Execution '{}' was cancelled before start",
                execution_id
            )));
        }

        let started = Instant::now();
        let raw_outcome = tokio::select! {
            biased;
            _ = token.cancelled() => {
                let _ = adapter.cancel(execution_id.clone()).await;
                Err(DbMcpError::ExecutionCancelled(format!(
                    "Execution '{}' was cancelled by caller",
                    execution_id
                )))
            }
            timed = tokio::time::timeout(Duration::from_millis(timeout_ms), adapter.execute(query)) => {
                match timed {
                    Ok(Ok(res)) => Ok(res),
                    Ok(Err(e)) => Err(e),
                    Err(_elapsed) => {
                        token.cancel();
                        let _ = adapter.cancel(execution_id.clone()).await;
                        Err(DbMcpError::ExecutionTimeout { timeout_ms })
                    }
                }
            }
        };

        let mut result = raw_outcome?;
        if result.execution_time_ms == 0 {
            result.execution_time_ms = started.elapsed().as_millis() as u64;
        }
        enforce_result_quotas(&mut result, max_rows, max_bytes);
        Ok(result)
    }

    /// Execute a bounded `EXPLAIN` request with deadline enforcement.
    pub async fn explain_bounded(
        &self,
        adapter: &dyn DatabaseAdapter,
        request: ExplainRequest,
    ) -> DbMcpResult<ExplainPlan> {
        let execution_id = ExecutionId::new();
        let request_id = request.request_id.clone();
        let timeout_ms = if request.timeout_ms == 0 {
            10_000
        } else {
            request.timeout_ms
        };
        let token = self.register_execution(execution_id.clone(), Some(&request_id));
        let _guard = ActiveExecutionGuard {
            execution_id: execution_id.clone(),
            request_id: request_id.clone(),
            active_executions: Arc::clone(&self.active_executions),
            request_to_execution: Arc::clone(&self.request_to_execution),
        };

        tokio::select! {
            biased;
            _ = token.cancelled() => {
                let _ = adapter.cancel(execution_id).await;
                Err(DbMcpError::ExecutionCancelled(format!(
                    "EXPLAIN request '{}' was cancelled",
                    request_id
                )))
            }
            timed = tokio::time::timeout(Duration::from_millis(timeout_ms), adapter.explain(request)) => {
                match timed {
                    Ok(res) => res,
                    Err(_elapsed) => {
                        token.cancel();
                        let _ = adapter.cancel(execution_id).await;
                        Err(DbMcpError::ExecutionTimeout { timeout_ms })
                    }
                }
            }
        }
    }

    /// Execute a governed query using this executor's configured `PolicyEngine` and `AuditSink`.
    pub async fn execute_governed(
        &self,
        adapter: &dyn DatabaseAdapter,
        request: GovernedQueryRequest,
    ) -> DbMcpResult<QueryResult> {
        self.execute_governed_query(
            adapter,
            &self.policy_engine,
            self.audit_sink.as_ref(),
            request,
        )
        .await
    }

    /// End-to-end governed execution pipeline:
    /// 1. Dialect-aware SQL analysis (`parse_and_analyze_sql`)
    /// 2. `PolicyEngine` evaluation (connection/role auth, multi-statement, privileged functions,
    ///    CTE writes, unknown SQL fail-closed, restricted/sensitive tables & columns)
    /// 3. Bounded execution with deadline and cancellation (`execute_bounded`)
    /// 4. Result disclosure & redaction controls (`apply_result_disclosure_controls`)
    /// 5. Structured `AuditEvent` persistence (`audit.record`)
    pub async fn execute_governed_query(
        &self,
        adapter: &dyn DatabaseAdapter,
        policy: &PolicyEngine,
        audit: &dyn AuditSink,
        request: GovernedQueryRequest,
    ) -> DbMcpResult<QueryResult> {
        let engine = adapter.capabilities().engine;
        let cfg = policy.effective_config(&request.connection);
        let operating_mode = cfg.mode;

        // 1. Parse and classify SQL
        let analysis = match parse_and_analyze_sql(engine, &request.sql) {
            Ok(a) => a,
            Err(err) => {
                let event = create_audit_event(
                    &request.request_id,
                    &request.caller,
                    &request.connection,
                    operating_mode,
                    &request.tool_name,
                    None,
                    Some(redact_sensitive_text(&request.sql)),
                    None,
                    AuditDecision::Denied,
                    Some(err.code().to_string()),
                    request.change_id.clone(),
                    None,
                    None,
                    None,
                    None,
                    Some(redact_sensitive_text(&err.to_string())),
                );
                let _ = audit.record(event);
                return Err(err);
            }
        };

        // 2. Evaluate policy
        let analysis = if request.sources_verified_without_sensitive_columns {
            let mut analysis = analysis;
            analysis.disclosure.untracked_provenance.clear();
            analysis
        } else {
            analysis
        };
        let evaluation = policy.evaluate_sql_with_context(
            &request.caller,
            &request.connection,
            &analysis,
            request.is_approved_change,
            request.is_named_tool,
        );

        if !evaluation.is_allowed() {
            let audit_decision = evaluation.to_audit_decision();
            let denial_code = evaluation.denial_code().map(ToOwned::to_owned);
            let err = evaluation.into_result().unwrap_err();
            let event = create_audit_event(
                &request.request_id,
                &request.caller,
                &request.connection,
                operating_mode,
                &request.tool_name,
                Some(analysis.sql_hash.clone()),
                Some(analysis.normalized_sql.clone()),
                Some(analysis.overall_class),
                audit_decision,
                denial_code,
                request.change_id.clone(),
                None,
                None,
                None,
                None,
                Some(redact_sensitive_text(&err.to_string())),
            );
            let _ = audit.record(event);
            return Err(err);
        }

        // 3. Construct AuthorizedQuery with bounded limits. A zero override would mean "no limit"
        //    downstream, so it falls back to the connection limit instead of disabling it.
        let timeout_ms = request
            .timeout_ms_override
            .filter(|t| *t > 0)
            .map(|t| {
                if cfg.limits.timeout_ms > 0 {
                    t.min(cfg.limits.timeout_ms)
                } else {
                    t
                }
            })
            .unwrap_or(cfg.limits.timeout_ms);

        let max_rows = request
            .max_rows_override
            .filter(|r| *r > 0)
            .map(|r| {
                if cfg.limits.max_rows > 0 {
                    r.min(cfg.limits.max_rows)
                } else {
                    r
                }
            })
            .unwrap_or(cfg.limits.max_rows);

        let max_bytes = request
            .max_bytes_override
            .filter(|b| *b > 0)
            .map(|b| {
                if cfg.limits.max_bytes > 0 {
                    b.min(cfg.limits.max_bytes)
                } else {
                    b
                }
            })
            .unwrap_or(cfg.limits.max_bytes);

        let read_only = matches!(operating_mode, OperatingMode::ReadOnly)
            || analysis.overall_class == SqlStatementClass::Read;

        let authorized_query = AuthorizedQuery {
            request_id: request.request_id.clone(),
            execution_id: request.execution_id.clone(),
            connection: request.connection.clone(),
            caller: request.caller.clone(),
            sql: request.sql.clone(),
            normalized_sql: analysis.normalized_sql.clone(),
            sql_hash: analysis.sql_hash.clone(),
            params: request.params.clone(),
            statement_class: analysis.overall_class,
            read_only,
            timeout_ms,
            max_rows,
            max_bytes,
            change_id: request.change_id.clone(),
        };

        // 4. Execute bounded query
        let mut result = match self.execute_bounded(adapter, authorized_query).await {
            Ok(res) => res,
            Err(err) => {
                let decision = match &err {
                    DbMcpError::ExecutionCancelled(_) | DbMcpError::ExecutionTimeout { .. } => {
                        AuditDecision::Cancelled
                    }
                    _ => AuditDecision::Failed,
                };
                let event = create_audit_event(
                    &request.request_id,
                    &request.caller,
                    &request.connection,
                    operating_mode,
                    &request.tool_name,
                    Some(analysis.sql_hash),
                    Some(analysis.normalized_sql),
                    Some(analysis.overall_class),
                    decision,
                    Some(err.code().to_string()),
                    request.change_id,
                    None,
                    None,
                    None,
                    None,
                    Some(redact_sensitive_text(&err.to_string())),
                );
                let _ = audit.record(event);
                return Err(err);
            }
        };

        // 5. Enforce result disclosure controls
        if let Err(err) = apply_result_disclosure_controls(&mut result, &cfg) {
            let event = create_audit_event(
                &request.request_id,
                &request.caller,
                &request.connection,
                operating_mode,
                &request.tool_name,
                Some(analysis.sql_hash),
                Some(analysis.normalized_sql),
                Some(analysis.overall_class),
                AuditDecision::Denied,
                Some(err.code().to_string()),
                request.change_id,
                None,
                None,
                Some(result.execution_time_ms),
                result.schema_version.clone(),
                Some(redact_sensitive_text(&err.to_string())),
            );
            let _ = audit.record(event);
            return Err(err);
        }

        // Re-verify quotas after redaction
        enforce_result_quotas(&mut result, max_rows, max_bytes);

        // 6. Persist completion audit event
        let decision = if request.is_approved_change {
            AuditDecision::ApprovedExecution
        } else {
            AuditDecision::Allowed
        };
        let event = create_audit_event(
            &request.request_id,
            &request.caller,
            &request.connection,
            operating_mode,
            &request.tool_name,
            Some(analysis.sql_hash),
            Some(analysis.normalized_sql),
            Some(analysis.overall_class),
            decision,
            None,
            request.change_id,
            Some(result.returned_rows),
            Some(result.truncated),
            Some(result.execution_time_ms),
            result.schema_version.clone(),
            None,
        );
        audit.record(event)?;

        Ok(result)
    }

    /// End-to-end governed `EXPLAIN` pipeline:
    /// SQL analysis -> `PolicyEngine::evaluate_explain` -> `explain_bounded` ->
    /// `apply_plan_disclosure_controls` -> `AuditEvent` persistence.
    pub async fn explain_governed_query(
        &self,
        adapter: &dyn DatabaseAdapter,
        policy: &PolicyEngine,
        audit: &dyn AuditSink,
        caller: &CallerIdentity,
        mut request: ExplainRequest,
    ) -> DbMcpResult<ExplainPlan> {
        let engine = adapter.capabilities().engine;
        let cfg = policy.effective_config(&request.connection);
        let operating_mode = cfg.mode;

        let analysis = match parse_and_analyze_sql(engine, &request.sql) {
            Ok(a) => a,
            Err(err) => {
                let event = create_audit_event(
                    &request.request_id,
                    caller,
                    &request.connection,
                    operating_mode,
                    "explain_query",
                    None,
                    Some(redact_sensitive_text(&request.sql)),
                    None,
                    AuditDecision::Denied,
                    Some(err.code().to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(redact_sensitive_text(&err.to_string())),
                );
                let _ = audit.record(event);
                return Err(err);
            }
        };

        let evaluation =
            policy.evaluate_explain(caller, &request.connection, &analysis, request.analyze);
        if !evaluation.is_allowed() {
            let decision = evaluation.to_audit_decision();
            let denial_code = evaluation.denial_code().map(ToOwned::to_owned);
            let err = evaluation.into_result().unwrap_err();
            let event = create_audit_event(
                &request.request_id,
                caller,
                &request.connection,
                operating_mode,
                "explain_query",
                Some(analysis.sql_hash),
                Some(analysis.normalized_sql),
                Some(analysis.overall_class),
                decision,
                denial_code,
                None,
                None,
                None,
                None,
                None,
                Some(redact_sensitive_text(&err.to_string())),
            );
            let _ = audit.record(event);
            return Err(err);
        }

        if request.timeout_ms == 0 || request.timeout_ms > cfg.limits.timeout_ms {
            request.timeout_ms = cfg.limits.timeout_ms;
        }

        let started = Instant::now();
        let mut plan = match self.explain_bounded(adapter, request.clone()).await {
            Ok(p) => p,
            Err(err) => {
                let decision = match &err {
                    DbMcpError::ExecutionCancelled(_) | DbMcpError::ExecutionTimeout { .. } => {
                        AuditDecision::Cancelled
                    }
                    _ => AuditDecision::Failed,
                };
                let event = create_audit_event(
                    &request.request_id,
                    caller,
                    &request.connection,
                    operating_mode,
                    "explain_query",
                    Some(analysis.sql_hash),
                    Some(analysis.normalized_sql),
                    Some(analysis.overall_class),
                    decision,
                    Some(err.code().to_string()),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(redact_sensitive_text(&err.to_string())),
                );
                let _ = audit.record(event);
                return Err(err);
            }
        };

        apply_plan_disclosure_controls(&mut plan, &cfg);

        let event = create_audit_event(
            &request.request_id,
            caller,
            &request.connection,
            operating_mode,
            "explain_query",
            Some(analysis.sql_hash),
            Some(analysis.normalized_sql),
            Some(analysis.overall_class),
            AuditDecision::Allowed,
            None,
            None,
            Some(1),
            Some(false),
            Some(started.elapsed().as_millis() as u64),
            None,
            None,
        );
        audit.record(event)?;

        Ok(plan)
    }
}

/// Top-level convenience function for running the full governed query execution pipeline.
pub async fn execute_governed_query(
    executor: &BoundedExecutor,
    adapter: &dyn DatabaseAdapter,
    policy: &PolicyEngine,
    audit: &dyn AuditSink,
    request: GovernedQueryRequest,
) -> DbMcpResult<QueryResult> {
    executor
        .execute_governed_query(adapter, policy, audit, request)
        .await
}

/// Enforce `max_rows` truncation and `max_bytes` budget on a `QueryResult`.
pub fn enforce_result_quotas(result: &mut QueryResult, max_rows: usize, max_bytes: usize) {
    // 1. Enforce max_rows
    if max_rows > 0 && result.rows.len() > max_rows {
        result.rows.truncate(max_rows);
        result.truncated = true;
        let msg = format!("Result truncated to max_rows={max_rows} limit.");
        if !result.warnings.contains(&msg) {
            result.warnings.push(msg);
        }
    }

    // 2. Enforce max_bytes
    let mut accumulated_bytes = 0usize;
    let mut keep_rows = result.rows.len();
    for (idx, row) in result.rows.iter().enumerate() {
        let row_bytes = serde_json::to_vec(row).map(|b| b.len()).unwrap_or(0);
        if max_bytes > 0 && accumulated_bytes + row_bytes > max_bytes {
            keep_rows = idx;
            result.truncated = true;
            let msg = format!(
                "Result truncated at {keep_rows} row(s) to stay within max_bytes={max_bytes} budget."
            );
            if !result.warnings.contains(&msg) {
                result.warnings.push(msg);
            }
            break;
        }
        accumulated_bytes += row_bytes;
    }

    if keep_rows < result.rows.len() {
        result.rows.truncate(keep_rows);
    }

    result.returned_rows = result.rows.len();
    result.bytes_used = accumulated_bytes;

    if result.truncated && result.warnings.is_empty() {
        result
            .warnings
            .push("Result set was truncated by execution limits.".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use db_mcp_audit::AuditFilter;
    use db_mcp_core::{
        CatalogRequest, CatalogResponse, ColumnMetadata, DatabaseCapabilities, ExplainFormat,
    };
    use db_mcp_policy::{
        ConnectionPolicyConfig, CODE_APPROVAL_REQUIRED, CODE_MULTI_STATEMENT_FORBIDDEN,
        CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockAdapter {
        connection_id: String,
        delay_ms: u64,
        rows_to_return: usize,
        cancelled_count: Arc<AtomicUsize>,
        cancelled_ids: Arc<DashMap<ExecutionId, bool>>,
    }

    impl MockAdapter {
        fn new(connection_id: &str, delay_ms: u64, rows_to_return: usize) -> Self {
            Self {
                connection_id: connection_id.to_string(),
                delay_ms,
                rows_to_return,
                cancelled_count: Arc::new(AtomicUsize::new(0)),
                cancelled_ids: Arc::new(DashMap::new()),
            }
        }
    }

    #[async_trait]
    impl DatabaseAdapter for MockAdapter {
        fn connection_id(&self) -> &str {
            &self.connection_id
        }

        fn capabilities(&self) -> DatabaseCapabilities {
            DatabaseCapabilities::for_postgres(true, false)
        }

        async fn discover(&self, _request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
            Ok(CatalogResponse {
                objects: vec![],
                total_count: 0,
                returned_count: 0,
                has_more: false,
                next_offset: None,
                schema_version: Some("snapshot_mock".to_string()),
            })
        }

        async fn execute(&self, request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }
            let columns = vec![
                ColumnMetadata::new("id", "integer"),
                ColumnMetadata::new("email", "text"),
                ColumnMetadata::new("password_hash", "text"),
            ];
            let mut rows = Vec::with_capacity(self.rows_to_return);
            for i in 0..self.rows_to_return {
                rows.push(vec![
                    serde_json::json!(i + 1),
                    serde_json::json!(format!("user{}@example.com", i + 1)),
                    serde_json::json!(format!("secret_hash_{}", i + 1)),
                ]);
            }
            Ok(QueryResult {
                execution_id: request.execution_id,
                columns,
                returned_rows: rows.len(),
                rows,
                rows_affected: None,
                truncated: false,
                bytes_used: 0,
                execution_time_ms: self.delay_ms,
                warnings: vec![],
                schema_version: Some("snapshot_mock".to_string()),
            })
        }

        async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
            Ok(ExplainPlan {
                connection: request.connection,
                sql: request.sql,
                analyze: request.analyze,
                format: ExplainFormat::Json,
                raw_plan: "Seq Scan on users (password=supersecret)".to_string(),
                structured_plan: Some(serde_json::json!({"Node Type": "Seq Scan"})),
                estimated_cost: Some(10.0),
                estimated_rows: Some(100.0),
                seq_scans: vec!["users".to_string()],
                index_scans: vec![],
                warnings: vec![],
            })
        }

        async fn cancel(&self, execution: ExecutionId) -> DbMcpResult<bool> {
            self.cancelled_count.fetch_add(1, Ordering::SeqCst);
            self.cancelled_ids.insert(execution, true);
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_deadline_enforcement_triggers_adapter_cancel() {
        let adapter = MockAdapter::new("pg-slow", 250, 5);
        let executor = BoundedExecutor::new();
        let caller = CallerIdentity::local_agent("agent-1");

        let mut query = AuthorizedQuery::new_read(
            "req_timeout_1",
            "pg-slow",
            caller,
            "SELECT id, email FROM users",
            vec![],
            &db_mcp_core::ExecutionLimits {
                timeout_ms: 40,
                max_rows: 100,
                max_bytes: 1024 * 1024,
                allow_multi_statement: false,
            },
        );
        let exec_id = ExecutionId::new();
        query.execution_id = exec_id.clone();

        let res = executor.execute_bounded(&adapter, query).await;
        assert!(matches!(
            res,
            Err(DbMcpError::ExecutionTimeout { timeout_ms: 40 })
        ));
        assert_eq!(adapter.cancelled_count.load(Ordering::SeqCst), 1);
        assert!(adapter.cancelled_ids.contains_key(&exec_id));
        assert_eq!(executor.active_count(), 0);
    }

    #[tokio::test]
    async fn test_client_cancellation_triggers_adapter_cancel() {
        let adapter = Arc::new(MockAdapter::new("pg-cancel", 500, 5));
        let executor = BoundedExecutor::new();
        let caller = CallerIdentity::local_agent("agent-1");

        let exec_id = ExecutionId::new();
        let mut query = AuthorizedQuery::new_read(
            "req_cancel_1",
            "pg-cancel",
            caller,
            "SELECT id FROM users",
            vec![],
            &db_mcp_core::ExecutionLimits {
                timeout_ms: 5000,
                max_rows: 100,
                max_bytes: 1024 * 1024,
                allow_multi_statement: false,
            },
        );
        query.execution_id = exec_id.clone();

        let exec_clone = executor.clone();
        let exec_id_for_cancel = exec_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(exec_clone.cancel_execution(&exec_id_for_cancel));
        });

        let res = executor.execute_bounded(adapter.as_ref(), query).await;
        assert!(matches!(res, Err(DbMcpError::ExecutionCancelled(_))));
        assert_eq!(adapter.cancelled_count.load(Ordering::SeqCst), 1);
        assert!(adapter.cancelled_ids.contains_key(&exec_id));
        assert_eq!(executor.active_count(), 0);
    }

    #[tokio::test]
    async fn test_row_truncation_and_byte_budget_enforcement() {
        let adapter = MockAdapter::new("pg-rows", 0, 10);
        let executor = BoundedExecutor::new();
        let caller = CallerIdentity::local_agent("agent-1");

        // 1. Test max_rows = 3
        let query_rows = AuthorizedQuery::new_read(
            "req_rows",
            "pg-rows",
            caller.clone(),
            "SELECT id, email FROM users",
            vec![],
            &db_mcp_core::ExecutionLimits {
                timeout_ms: 1000,
                max_rows: 3,
                max_bytes: 100_000,
                allow_multi_statement: false,
            },
        );
        let res_rows = executor
            .execute_bounded(&adapter, query_rows)
            .await
            .unwrap();
        assert_eq!(res_rows.returned_rows, 3);
        assert_eq!(res_rows.rows.len(), 3);
        assert!(res_rows.truncated);
        assert!(res_rows.warnings.iter().any(|w| w.contains("max_rows=3")));

        // 2. Test max_bytes = 90 (each row is ~45 bytes JSON, so at most 1-2 rows fit)
        let query_bytes = AuthorizedQuery::new_read(
            "req_bytes",
            "pg-rows",
            caller,
            "SELECT id, email FROM users",
            vec![],
            &db_mcp_core::ExecutionLimits {
                timeout_ms: 1000,
                max_rows: 100,
                max_bytes: 90,
                allow_multi_statement: false,
            },
        );
        let res_bytes = executor
            .execute_bounded(&adapter, query_bytes)
            .await
            .unwrap();
        assert!(res_bytes.truncated);
        assert!(res_bytes.returned_rows <= 2);
        assert!(res_bytes.bytes_used <= 90);
        assert!(res_bytes
            .warnings
            .iter()
            .any(|w| w.contains("max_bytes=90")));
    }

    #[tokio::test]
    async fn test_zero_overrides_do_not_disable_connection_caps() {
        let adapter = MockAdapter::new("dev-conn", 0, 10);
        let policy = PolicyEngine::with_configs(
            OperatingMode::Development,
            vec![ConnectionPolicyConfig::development("dev-conn").with_limits(
                db_mcp_core::ExecutionLimits {
                    timeout_ms: 1000,
                    max_rows: 3,
                    max_bytes: 1_048_576,
                    allow_multi_statement: false,
                },
            )],
        );
        let audit = InMemoryAuditStore::new();
        let executor = BoundedExecutor::new();
        let req = GovernedQueryRequest::new(
            "req_zero",
            "dev-conn",
            CallerIdentity::local_agent("agent"),
            "SELECT id, email FROM users",
        )
        .with_max_rows(0)
        .with_max_bytes(0)
        .with_timeout_ms(0);
        let result = execute_governed_query(&executor, &adapter, &policy, &audit, req)
            .await
            .unwrap();
        assert_eq!(result.returned_rows, 3);
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn test_execute_governed_query_pipeline_end_to_end() {
        let adapter = MockAdapter::new("prod-conn", 0, 5);
        let policy = PolicyEngine::with_configs(
            OperatingMode::GovernedProduction,
            vec![
                ConnectionPolicyConfig::governed_production("prod-conn"),
                ConnectionPolicyConfig::read_only("ro-conn"),
            ],
        );
        let audit = InMemoryAuditStore::new();
        let executor = BoundedExecutor::new();
        let caller = CallerIdentity::local_agent("agent:cursor");

        // Case 1: Valid bounded read query with sensitive column redaction & row truncation
        let req_ok = GovernedQueryRequest::new(
            "req_gov_ok",
            "prod-conn",
            caller.clone(),
            "SELECT id, email, password_hash FROM users WHERE id > 0",
        )
        .with_max_rows(2);

        let result = execute_governed_query(&executor, &adapter, &policy, &audit, req_ok)
            .await
            .unwrap();
        assert_eq!(result.returned_rows, 2);
        assert!(result.truncated);
        assert!(result.columns[2].redacted);
        assert_eq!(result.rows[0][2], serde_json::json!("[REDACTED]"));

        // Verify audit event recorded
        let events_ok = audit.get_by_request_id("req_gov_ok").unwrap();
        assert_eq!(events_ok.len(), 1);
        assert_eq!(events_ok[0].decision, AuditDecision::Allowed);
        assert_eq!(events_ok[0].returned_rows, Some(2));
        assert_eq!(events_ok[0].truncated, Some(true));

        // Case 2: Write in GovernedProduction without approval -> denied with APPROVAL_REQUIRED + audited
        let req_write = GovernedQueryRequest::new(
            "req_gov_write",
            "prod-conn",
            caller.clone(),
            "DELETE FROM users WHERE id = 1",
        );
        let err_write = execute_governed_query(&executor, &adapter, &policy, &audit, req_write)
            .await
            .unwrap_err();
        assert_eq!(err_write.code(), CODE_APPROVAL_REQUIRED);

        let events_write = audit.get_by_request_id("req_gov_write").unwrap();
        assert_eq!(events_write.len(), 1);
        assert_eq!(events_write[0].decision, AuditDecision::RequiresApproval);
        assert_eq!(
            events_write[0].denial_code.as_deref(),
            Some(CODE_APPROVAL_REQUIRED)
        );

        // Case 3: Multi-statement injection -> denied with MULTI_STATEMENT_FORBIDDEN + audited
        let req_multi = GovernedQueryRequest::new(
            "req_gov_multi",
            "prod-conn",
            caller.clone(),
            "SELECT 1; DROP TABLE users;",
        );
        let err_multi = execute_governed_query(&executor, &adapter, &policy, &audit, req_multi)
            .await
            .unwrap_err();
        assert_eq!(err_multi.code(), CODE_MULTI_STATEMENT_FORBIDDEN);

        // Case 4: CTE write in ReadOnly mode -> denied with MUTATION_NOT_ALLOWED_IN_READ_ONLY
        let ro_adapter = MockAdapter::new("ro-conn", 0, 1);
        let req_cte = GovernedQueryRequest::new(
            "req_ro_cte",
            "ro-conn",
            caller,
            "WITH del AS (DELETE FROM users RETURNING id) SELECT * FROM del",
        );
        let err_cte = execute_governed_query(&executor, &ro_adapter, &policy, &audit, req_cte)
            .await
            .unwrap_err();
        assert_eq!(err_cte.code(), CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY);

        let all_audit = audit.list_events(&AuditFilter::new()).unwrap();
        assert_eq!(all_audit.len(), 4);
    }

    #[tokio::test]
    async fn test_explain_governed_query_and_request_id_cancellation() {
        let adapter = Arc::new(MockAdapter::new("prod-conn", 400, 1));
        let policy = PolicyEngine::with_configs(
            OperatingMode::GovernedProduction,
            vec![ConnectionPolicyConfig::governed_production("prod-conn")],
        );
        let audit = InMemoryAuditStore::new();
        let executor = BoundedExecutor::new();
        let caller = CallerIdentity::local_agent("agent:cursor");

        // Plain EXPLAIN succeeds and scrubs credentials from raw_plan
        let fast_adapter = MockAdapter::new("prod-conn", 0, 1);
        let explain_req = ExplainRequest {
            request_id: "req_exp_1".to_string(),
            connection: "prod-conn".to_string(),
            sql: "SELECT id, email FROM users WHERE id = 1".to_string(),
            params: vec![],
            analyze: false,
            format: ExplainFormat::Json,
            timeout_ms: 1000,
        };
        let plan = executor
            .explain_governed_query(&fast_adapter, &policy, &audit, &caller, explain_req)
            .await
            .unwrap();
        assert!(!plan.raw_plan.contains("supersecret"));
        assert!(plan.raw_plan.contains("password=[REDACTED]"));

        // Cancel in-flight governed query by MCP request_id
        let exec_clone = executor.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(exec_clone.cancel_by_request_id("req_cancel_by_id"));
        });

        let slow_req = GovernedQueryRequest::new(
            "req_cancel_by_id",
            "prod-conn",
            caller,
            "SELECT id, email FROM users",
        );
        let cancel_err =
            execute_governed_query(&executor, adapter.as_ref(), &policy, &audit, slow_req)
                .await
                .unwrap_err();
        assert_eq!(cancel_err.code(), "EXECUTION_CANCELLED");
        assert_eq!(adapter.cancelled_count.load(Ordering::SeqCst), 1);

        let cancelled_events = audit.get_by_request_id("req_cancel_by_id").unwrap();
        assert_eq!(cancelled_events.len(), 1);
        assert_eq!(cancelled_events[0].decision, AuditDecision::Cancelled);
    }
}
