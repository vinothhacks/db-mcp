//! Authorization, risk assessment, operating mode enforcement, and result disclosure controls.
//!
//! Responsibilities:
//! - Per-connection policy configuration (`ConnectionPolicyConfig`) with operating modes
//!   (`Development`, `ReadOnly`, `GovernedProduction`), policy revision IDs, caller/role
//!   access control, restricted tables, sensitive columns, and execution budgets.
//! - Deterministic policy evaluation (`PolicyEngine`, `PolicyEvaluation`) enforcing:
//!   - Caller connection & role authorization (`can_access_connection`)
//!   - Multi-statement rejection (`MULTI_STATEMENT_FORBIDDEN`)
//!   - Privileged / side-effecting function rejection (`PRIVILEGED_FUNCTION_FORBIDDEN`)
//!   - Unknown SQL fail-closed logic in `GovernedProduction` (`UNKNOWN_SQL_IN_GOVERNED_MODE`)
//!   - CTE write and mutation controls (`MUTATION_NOT_ALLOWED_IN_READ_ONLY`, `APPROVAL_REQUIRED`)
//!   - Restricted/sensitive table & column guards and unrestricted-SQL provenance rules
//! - Result disclosure and masking/redaction helpers (`apply_result_disclosure_controls`,
//!   `apply_plan_disclosure_controls`) that redact sensitive columns and secret patterns in
//!   query results and `EXPLAIN` plans.

use std::collections::BTreeMap;

use db_mcp_core::{
    AuditDecision, CallerIdentity, DatabaseEngine, DbMcpError, DbMcpResult, ExecutionLimits,
    ExplainPlan, McpDeniedResponse, OperatingMode, QueryResult, SqlStatementClass,
};
use db_mcp_secrets::{redact_sensitive_text, REDACTED_PLACEHOLDER};
use db_mcp_sql::{parse_and_analyze_sql, SqlAnalysis};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Standard policy denial codes.
pub const CODE_UNAUTHORIZED_CONNECTION: &str = "UNAUTHORIZED_CONNECTION";
pub const CODE_UNAUTHORIZED_ROLE: &str = "UNAUTHORIZED_ROLE";
pub const CODE_MULTI_STATEMENT_FORBIDDEN: &str = "MULTI_STATEMENT_FORBIDDEN";
pub const CODE_PRIVILEGED_FUNCTION_FORBIDDEN: &str = "PRIVILEGED_FUNCTION_FORBIDDEN";
pub const CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY: &str = "MUTATION_NOT_ALLOWED_IN_READ_ONLY";
pub const CODE_APPROVAL_REQUIRED: &str = "APPROVAL_REQUIRED";
pub const CODE_UNKNOWN_SQL_IN_GOVERNED_MODE: &str = "UNKNOWN_SQL_IN_GOVERNED_MODE";
pub const CODE_RESTRICTED_TABLE_FORBIDDEN: &str = "RESTRICTED_TABLE_FORBIDDEN";
pub const CODE_SENSITIVE_COLUMN_FORBIDDEN: &str = "SENSITIVE_COLUMN_FORBIDDEN";
pub const CODE_UNPROVENANCED_SENSITIVE_QUERY: &str = "UNPROVENANCED_SENSITIVE_QUERY";
pub const CODE_ANALYZE_EXPLAIN_FORBIDDEN: &str = "ANALYZE_EXPLAIN_FORBIDDEN";

fn default_policy_revision() -> String {
    "rev-1".to_string()
}

/// Default sensitive column names redacted by disclosure controls.
pub fn default_sensitive_columns() -> Vec<String> {
    vec![
        "password".to_string(),
        "password_hash".to_string(),
        "passwd".to_string(),
        "secret".to_string(),
        "secret_key".to_string(),
        "client_secret".to_string(),
        "api_key".to_string(),
        "apikey".to_string(),
        "access_token".to_string(),
        "refresh_token".to_string(),
        "auth_token".to_string(),
        "private_key".to_string(),
        "ssn".to_string(),
        "credit_card".to_string(),
        "dsn".to_string(),
    ]
}

/// Policy configuration for a single database connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPolicyConfig {
    pub connection_id: String,
    #[serde(default)]
    pub mode: OperatingMode,
    #[serde(default = "default_policy_revision")]
    pub policy_revision: String,
    #[serde(default)]
    pub limits: ExecutionLimits,
    /// Roles permitted to access this connection (empty or `["*"]` allows any authenticated role).
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    /// Principals explicitly permitted to access this connection (empty or `["*"]` allows any).
    #[serde(default)]
    pub allowed_principals: Vec<String>,
    /// Tables that cannot be queried or mutated via ad-hoc SQL (e.g. `audit_events` or `auth.secrets`).
    #[serde(default)]
    pub restricted_tables: Vec<String>,
    /// Tables containing sensitive data where provenance rules apply when `enforce_unrestricted_sql_provenance` is true.
    #[serde(default)]
    pub sensitive_tables: Vec<String>,
    /// Column names (unqualified `email` or qualified `users.ssn`) subject to disclosure redaction or access denial.
    #[serde(default = "default_sensitive_columns")]
    pub sensitive_columns: Vec<String>,
    /// If true, referencing a sensitive column in ad-hoc SQL is denied outright before execution.
    #[serde(default)]
    pub deny_sensitive_column_access: bool,
    /// If true, ad-hoc SQL with ambiguous column provenance (`SELECT *`, derived expressions on sensitive tables)
    /// is denied unless executed through a curated named tool.
    #[serde(default)]
    pub enforce_unrestricted_sql_provenance: bool,
    /// Whether execution-based `EXPLAIN ANALYZE` is permitted on this connection.
    #[serde(default)]
    pub allow_explain_analyze: bool,
    /// Optional custom regex patterns to redact from query results and plans.
    #[serde(default)]
    pub custom_redaction_patterns: Vec<String>,
}

impl ConnectionPolicyConfig {
    pub fn new(connection_id: impl Into<String>, mode: OperatingMode) -> Self {
        let allow_explain_analyze = matches!(mode, OperatingMode::Development);
        Self {
            connection_id: connection_id.into(),
            mode,
            policy_revision: default_policy_revision(),
            limits: ExecutionLimits::default(),
            allowed_roles: Vec::new(),
            allowed_principals: Vec::new(),
            restricted_tables: Vec::new(),
            sensitive_tables: Vec::new(),
            sensitive_columns: default_sensitive_columns(),
            deny_sensitive_column_access: false,
            enforce_unrestricted_sql_provenance: false,
            allow_explain_analyze,
            custom_redaction_patterns: Vec::new(),
        }
    }

    pub fn development(connection_id: impl Into<String>) -> Self {
        Self::new(connection_id, OperatingMode::Development)
    }

    pub fn read_only(connection_id: impl Into<String>) -> Self {
        Self::new(connection_id, OperatingMode::ReadOnly)
    }

    pub fn governed_production(connection_id: impl Into<String>) -> Self {
        Self::new(connection_id, OperatingMode::GovernedProduction)
    }

    pub fn with_policy_revision(mut self, revision: impl Into<String>) -> Self {
        self.policy_revision = revision.into();
        self
    }

    pub fn with_limits(mut self, limits: ExecutionLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_allowed_roles(mut self, roles: Vec<String>) -> Self {
        self.allowed_roles = roles;
        self
    }

    pub fn with_allowed_principals(mut self, principals: Vec<String>) -> Self {
        self.allowed_principals = principals;
        self
    }

    pub fn with_restricted_tables(mut self, tables: Vec<String>) -> Self {
        self.restricted_tables = tables;
        self
    }

    pub fn with_sensitive_tables(mut self, tables: Vec<String>) -> Self {
        self.sensitive_tables = tables;
        self
    }

    pub fn with_sensitive_columns(mut self, columns: Vec<String>) -> Self {
        self.sensitive_columns = columns;
        self
    }

    pub fn with_deny_sensitive_column_access(mut self, deny: bool) -> Self {
        self.deny_sensitive_column_access = deny;
        self
    }

    pub fn with_unrestricted_sql_provenance(mut self, enforce: bool) -> Self {
        self.enforce_unrestricted_sql_provenance = enforce;
        self
    }

    pub fn with_allow_explain_analyze(mut self, allow: bool) -> Self {
        self.allow_explain_analyze = allow;
        self
    }

    pub fn with_custom_redaction_patterns(mut self, patterns: Vec<String>) -> Self {
        self.custom_redaction_patterns = patterns;
        self
    }

    /// Compute a deterministic SHA-256 fingerprint of this policy configuration.
    pub fn compute_revision_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        let json = serde_json::to_vec(self).unwrap_or_default();
        hasher.update(&json);
        let hex_digest = hex::encode(hasher.finalize());
        format!("{}_{}", self.policy_revision, &hex_digest[..8])
    }

    /// Check whether `caller` is authorized to access this connection based on both
    /// caller-side connection scope and policy-side principal/role allowlists.
    pub fn can_access_connection(&self, caller: &CallerIdentity) -> bool {
        if !caller.can_access_connection(&self.connection_id) {
            return false;
        }

        if !self.allowed_principals.is_empty()
            && !self.allowed_principals.iter().any(|p| p == "*")
            && !self
                .allowed_principals
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&caller.principal))
        {
            return false;
        }

        // The connection allowlist is authoritative: roles are self-asserted by the caller, so an
        // admin/dba role gets no implicit bypass and must be listed like any other role.
        if !self.allowed_roles.is_empty() && !self.allowed_roles.iter().any(|r| r == "*") {
            let role_ok = self.allowed_roles.iter().any(|allowed| {
                allowed.eq_ignore_ascii_case(&caller.role)
                    || caller
                        .roles
                        .iter()
                        .any(|cr| cr.eq_ignore_ascii_case(allowed))
            });
            if !role_ok {
                return false;
            }
        }

        true
    }

    /// Remove catalog objects that would disclose restricted tables.
    ///
    /// Drops restricted tables/views, indexes and triggers defined on them, and foreign keys that
    /// reference them from otherwise visible tables. Apply before pagination, hashing or graph
    /// construction so counts, fingerprints and edges never reveal a restricted name.
    pub fn retain_allowed_objects(&self, objects: &mut Vec<db_mcp_core::CatalogObject>) -> usize {
        if self.restricted_tables.is_empty() {
            return 0;
        }
        let before = objects.len();
        objects.retain(|obj| {
            if self.is_restricted_table(&obj.name)
                || self.is_restricted_table(&obj.qualified_name())
            {
                return false;
            }
            !obj.indexes.iter().any(|idx| {
                matches!(
                    obj.object_type,
                    db_mcp_core::CatalogObjectType::Index | db_mcp_core::CatalogObjectType::Trigger
                ) && self.is_restricted_table(&idx.table_name)
            })
        });
        for obj in objects.iter_mut() {
            obj.foreign_keys
                .retain(|fk| !self.is_restricted_table(&fk.referenced_table));
        }
        before - objects.len()
    }

    /// Returns true if a table name (`schema.table` or `table`) matches `restricted_tables`.
    pub fn is_restricted_table(&self, table: &str) -> bool {
        identifier_matches_list(table, &self.restricted_tables)
    }

    /// Returns true if a table name matches `sensitive_tables` (or if `sensitive_tables` is empty/wildcard when provenance is enforced).
    pub fn is_sensitive_table(&self, table: &str) -> bool {
        if self.sensitive_tables.is_empty() {
            return true;
        }
        identifier_matches_list(table, &self.sensitive_tables)
    }

    /// Returns true if a column name (unqualified `col` or qualified `table.col`) matches `sensitive_columns`.
    pub fn is_sensitive_column(&self, table: Option<&str>, column: &str) -> bool {
        let col_clean = strip_quotes(column).to_ascii_lowercase();
        let qualified_clean = table.map(|t| {
            let base_t = base_identifier(t);
            format!("{base_t}.{col_clean}")
        });
        let full_qualified_clean = table.map(|t| {
            let clean_t = strip_quotes(t).to_ascii_lowercase();
            format!("{clean_t}.{col_clean}")
        });

        for pattern in &self.sensitive_columns {
            let pat_clean = strip_quotes(pattern).to_ascii_lowercase();
            if pat_clean == "*" || pat_clean == col_clean {
                return true;
            }
            if let Some(q) = &qualified_clean {
                if &pat_clean == q {
                    return true;
                }
            }
            if let Some(fq) = &full_qualified_clean {
                if &pat_clean == fq {
                    return true;
                }
            }
            // If pattern is `table.col` and `table` wasn't known, match if column name matches the suffix when unambiguous
            if table.is_none() {
                if let Some((_, pat_col)) = pat_clean.rsplit_once('.') {
                    if pat_col == col_clean {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn strip_quotes(s: &str) -> &str {
    s.trim()
        .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
}

fn base_identifier(s: &str) -> String {
    let base = s.rsplit('.').next().unwrap_or(s);
    strip_quotes(base).to_ascii_lowercase()
}

fn identifier_matches_list(candidate: &str, patterns: &[String]) -> bool {
    let cand_full = strip_quotes(candidate).to_ascii_lowercase();
    let cand_base = base_identifier(candidate);
    patterns.iter().any(|p| {
        let pat_full = strip_quotes(p).to_ascii_lowercase();
        let pat_base = base_identifier(p);
        pat_full == "*" || pat_full == cand_full || pat_base == cand_base
    })
}

/// Outcome of evaluating a request against a `ConnectionPolicyConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PolicyEvaluation {
    Allowed,
    RequiresApproval {
        reason: String,
        next_action: String,
    },
    Denied {
        code: String,
        message: String,
        next_action: Option<String>,
    },
}

impl PolicyEvaluation {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Map this policy evaluation to an `AuditDecision`.
    pub fn to_audit_decision(&self) -> AuditDecision {
        match self {
            Self::Allowed => AuditDecision::Allowed,
            Self::RequiresApproval { .. } => AuditDecision::RequiresApproval,
            Self::Denied { .. } => AuditDecision::Denied,
        }
    }

    /// Return the machine-readable denial code when not `Allowed`.
    pub fn denial_code(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::RequiresApproval { .. } => Some(CODE_APPROVAL_REQUIRED),
            Self::Denied { code, .. } => Some(code.as_str()),
        }
    }

    /// Convert this evaluation into `DbMcpResult<()>`.
    pub fn into_result(self) -> DbMcpResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::RequiresApproval {
                reason,
                next_action,
            } => Err(DbMcpError::PolicyDenied {
                code: CODE_APPROVAL_REQUIRED.to_string(),
                message: reason,
                next_action: Some(next_action),
            }),
            Self::Denied {
                code,
                message,
                next_action,
            } => Err(DbMcpError::PolicyDenied {
                code,
                message,
                next_action,
            }),
        }
    }

    /// Convert a non-allowed evaluation into an `McpDeniedResponse`.
    pub fn to_denied_response(
        &self,
        request_id: Option<String>,
        connection: Option<String>,
    ) -> Option<McpDeniedResponse> {
        match self {
            Self::Allowed => None,
            Self::RequiresApproval {
                reason,
                next_action,
            } => Some(McpDeniedResponse {
                request_id,
                connection,
                status: "denied".to_string(),
                code: CODE_APPROVAL_REQUIRED.to_string(),
                message: reason.clone(),
                next_action: Some(next_action.clone()),
                retryable: false,
                details: None,
            }),
            Self::Denied {
                code,
                message,
                next_action,
            } => Some(McpDeniedResponse {
                request_id,
                connection,
                status: "denied".to_string(),
                code: code.clone(),
                message: message.clone(),
                next_action: next_action.clone(),
                retryable: false,
                details: None,
            }),
        }
    }
}

/// Policy engine managing per-connection governance configurations and evaluating SQL requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyEngine {
    pub default_mode: OperatingMode,
    #[serde(default = "default_policy_revision")]
    pub default_policy_revision: String,
    #[serde(default)]
    pub connections: BTreeMap<String, ConnectionPolicyConfig>,
}

impl PolicyEngine {
    pub fn new(default_mode: OperatingMode) -> Self {
        Self {
            default_mode,
            default_policy_revision: default_policy_revision(),
            connections: BTreeMap::new(),
        }
    }

    pub fn with_configs(
        default_mode: OperatingMode,
        configs: impl IntoIterator<Item = ConnectionPolicyConfig>,
    ) -> Self {
        let mut engine = Self::new(default_mode);
        for cfg in configs {
            engine.register_connection(cfg);
        }
        engine
    }

    pub fn register_connection(&mut self, config: ConnectionPolicyConfig) {
        self.connections
            .insert(config.connection_id.clone(), config);
    }

    pub fn get_config(&self, connection_id: &str) -> Option<&ConnectionPolicyConfig> {
        self.connections.get(connection_id)
    }

    /// Resolve the effective `ConnectionPolicyConfig` for `connection_id`, falling back to `default_mode`.
    pub fn effective_config(&self, connection_id: &str) -> ConnectionPolicyConfig {
        self.connections
            .get(connection_id)
            .cloned()
            .unwrap_or_else(|| {
                ConnectionPolicyConfig::new(connection_id, self.default_mode)
                    .with_policy_revision(self.default_policy_revision.clone())
            })
    }

    /// Return the active policy revision ID for `connection_id`.
    pub fn policy_revision(&self, connection_id: &str) -> String {
        self.connections
            .get(connection_id)
            .map(|c| c.policy_revision.clone())
            .unwrap_or_else(|| self.default_policy_revision.clone())
    }

    /// Check whether `caller` is permitted to access `connection_id`.
    pub fn can_access_connection(&self, caller: &CallerIdentity, connection_id: &str) -> bool {
        let cfg = self.effective_config(connection_id);
        cfg.can_access_connection(caller)
    }

    /// Return a `PolicyEvaluation` for connection-level access authorization.
    pub fn authorize_connection(
        &self,
        caller: &CallerIdentity,
        connection_id: &str,
    ) -> PolicyEvaluation {
        let cfg = self.effective_config(connection_id);
        if !caller.can_access_connection(connection_id) {
            return PolicyEvaluation::Denied {
                code: CODE_UNAUTHORIZED_CONNECTION.to_string(),
                message: format!(
                    "Principal '{}' is not authorized to access connection '{}'.",
                    caller.principal, connection_id
                ),
                next_action: Some("list_connections".to_string()),
            };
        }
        if !cfg.can_access_connection(caller) {
            return PolicyEvaluation::Denied {
                code: CODE_UNAUTHORIZED_ROLE.to_string(),
                message: format!(
                    "Principal '{}' with role '{}' is not permitted by policy on connection '{}'.",
                    caller.principal, caller.role, connection_id
                ),
                next_action: Some("list_connections".to_string()),
            };
        }
        PolicyEvaluation::Allowed
    }

    /// Evaluate an analyzed SQL query under standard ad-hoc query execution rules.
    pub fn evaluate_sql(
        &self,
        caller: &CallerIdentity,
        connection_id: &str,
        analysis: &SqlAnalysis,
    ) -> PolicyEvaluation {
        self.evaluate_sql_with_context(caller, connection_id, analysis, false, false)
    }

    /// Evaluate an analyzed SQL query with explicit flags for approved change execution and named tools.
    pub fn evaluate_sql_with_context(
        &self,
        caller: &CallerIdentity,
        connection_id: &str,
        analysis: &SqlAnalysis,
        is_approved_change: bool,
        is_named_tool: bool,
    ) -> PolicyEvaluation {
        let auth = self.authorize_connection(caller, connection_id);
        if !auth.is_allowed() {
            return auth;
        }

        let cfg = self.effective_config(connection_id);

        // 1. Multi-statement check
        if analysis.is_multi_statement && !cfg.limits.allow_multi_statement {
            return PolicyEvaluation::Denied {
                code: CODE_MULTI_STATEMENT_FORBIDDEN.to_string(),
                message: "Multi-statement SQL batches are forbidden by policy.".to_string(),
                next_action: Some("split_statements".to_string()),
            };
        }

        // 2. Privileged / side-effecting function check
        if analysis.has_privileged_functions {
            let fn_list = analysis.privileged_functions.join(", ");
            return PolicyEvaluation::Denied {
                code: CODE_PRIVILEGED_FUNCTION_FORBIDDEN.to_string(),
                message: format!(
                    "Side-effecting or privileged database function '{}' is blocked by policy.",
                    fn_list
                ),
                next_action: Some("remove_privileged_function".to_string()),
            };
        }

        // 3. Unknown SQL fail-closed logic in GovernedProduction / ReadOnly
        if analysis.overall_class == SqlStatementClass::Unknown
            && cfg.mode.fails_closed_on_unknown_sql()
        {
            return PolicyEvaluation::Denied {
                code: CODE_UNKNOWN_SQL_IN_GOVERNED_MODE.to_string(),
                message: format!(
                    "Unknown or unparseable SQL constructs are forbidden in '{}' mode (fail-closed policy).",
                    cfg.mode
                ),
                next_action: Some("rewrite_standard_sql".to_string()),
            };
        }

        // 4. Restricted tables guard
        if !is_named_tool {
            for table in &analysis.referenced_tables {
                if cfg.is_restricted_table(table) {
                    return PolicyEvaluation::Denied {
                        code: CODE_RESTRICTED_TABLE_FORBIDDEN.to_string(),
                        message: format!(
                            "Access to restricted table '{}' on connection '{}' is forbidden by policy.",
                            table, connection_id
                        ),
                        next_action: Some("run_named_tool".to_string()),
                    };
                }
            }
        }

        // 5. Unrestricted-SQL provenance rules on sensitive tables
        if cfg.enforce_unrestricted_sql_provenance && !is_named_tool && !is_approved_change {
            let touches_sensitive_table = analysis.referenced_tables.is_empty()
                || analysis
                    .referenced_tables
                    .iter()
                    .any(|t| cfg.is_sensitive_table(t));

            if touches_sensitive_table && has_ambiguous_result_provenance(analysis) {
                return PolicyEvaluation::Denied {
                    code: CODE_UNPROVENANCED_SENSITIVE_QUERY.to_string(),
                    message: format!(
                        "Unrestricted SQL with wildcard projection or ambiguous column provenance is denied on connection '{}'. Use explicit non-sensitive columns or invoke a curated named tool.",
                        connection_id
                    ),
                    next_action: Some("run_named_tool".to_string()),
                };
            }
        }

        // 6. Sensitive column guard when direct access is denied
        if cfg.deny_sensitive_column_access && !is_named_tool && !is_approved_change {
            for col_ref in &analysis.referenced_columns {
                if cfg.is_sensitive_column(col_ref.table.as_deref(), &col_ref.column) {
                    return PolicyEvaluation::Denied {
                        code: CODE_SENSITIVE_COLUMN_FORBIDDEN.to_string(),
                        message: format!(
                            "Direct access to sensitive column '{}' is forbidden by policy.",
                            col_ref.column
                        ),
                        next_action: Some("run_named_tool".to_string()),
                    };
                }
            }
            for pred in &analysis.predicates {
                if cfg.is_sensitive_column(pred.table.as_deref(), &pred.column) {
                    return PolicyEvaluation::Denied {
                        code: CODE_SENSITIVE_COLUMN_FORBIDDEN.to_string(),
                        message: format!(
                            "Filtering or joining on sensitive column '{}' is forbidden by policy.",
                            pred.column
                        ),
                        next_action: Some("run_named_tool".to_string()),
                    };
                }
            }
        }

        // 7. CTE Write & Statement Class / Operating Mode rules
        let mode_evaluation = if analysis.has_cte_write {
            match cfg.mode {
                OperatingMode::Development => PolicyEvaluation::Allowed,
                OperatingMode::ReadOnly => PolicyEvaluation::Denied {
                    code: CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY.to_string(),
                    message: "Data-modifying CTEs are not allowed in ReadOnly mode.".to_string(),
                    next_action: Some("propose_change".to_string()),
                },
                OperatingMode::GovernedProduction => {
                    if is_approved_change {
                        PolicyEvaluation::Allowed
                    } else {
                        PolicyEvaluation::RequiresApproval {
                            reason: "Data-modifying CTEs in GovernedProduction require an approved change proposal."
                                .to_string(),
                            next_action: "propose_change".to_string(),
                        }
                    }
                }
            }
        } else {
            match analysis.overall_class {
                SqlStatementClass::Read => PolicyEvaluation::Allowed,
                SqlStatementClass::Write
                | SqlStatementClass::Ddl
                | SqlStatementClass::Transaction => match cfg.mode {
                    OperatingMode::Development => PolicyEvaluation::Allowed,
                    OperatingMode::ReadOnly => PolicyEvaluation::Denied {
                        code: CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY.to_string(),
                        message: format!(
                            "Mutating SQL statement class '{}' is not allowed in ReadOnly mode.",
                            analysis.overall_class
                        ),
                        next_action: Some("propose_change".to_string()),
                    },
                    OperatingMode::GovernedProduction => {
                        if is_approved_change {
                            PolicyEvaluation::Allowed
                        } else {
                            PolicyEvaluation::RequiresApproval {
                                reason: format!(
                                    "Production '{}' changes require an approved proposal.",
                                    analysis.overall_class
                                ),
                                next_action: "propose_change".to_string(),
                            }
                        }
                    }
                },
                SqlStatementClass::PrivilegeOrAdmin => match cfg.mode {
                    OperatingMode::Development if caller.is_admin() => PolicyEvaluation::Allowed,
                    OperatingMode::ReadOnly => PolicyEvaluation::Denied {
                        code: CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY.to_string(),
                        message:
                            "Administrative or privilege statements are forbidden in ReadOnly mode."
                                .to_string(),
                        next_action: None,
                    },
                    _ => PolicyEvaluation::Denied {
                        code: CODE_PRIVILEGED_FUNCTION_FORBIDDEN.to_string(),
                        message:
                            "Administrative or privilege SQL statements are forbidden by policy."
                                .to_string(),
                        next_action: None,
                    },
                },
                SqlStatementClass::Unknown => {
                    // Only reachable in Development mode since ReadOnly/GovernedProduction failed closed above.
                    PolicyEvaluation::Allowed
                }
            }
        };
        if !mode_evaluation.is_allowed() {
            return mode_evaluation;
        }

        // 7b. `EXPLAIN ANALYZE` executes the statement: the same switch that governs
        //     explain_query(analyze=true) applies when it is sent through execute_query.
        if !cfg.allow_explain_analyze && is_explain_analyze(analysis) {
            return explain_analyze_denied(connection_id);
        }

        // 8. Result-disclosure provenance: redaction masks sensitive columns by output column
        //    name, so ad-hoc SQL may only return a sensitive column as a bare, unaliased item.
        if !is_named_tool && !is_approved_change {
            if let Some(denial) = disclosure_provenance_denial(&cfg, analysis, connection_id) {
                return denial;
            }
        }

        PolicyEvaluation::Allowed
    }

    /// Parse and evaluate raw SQL in one step.
    pub fn evaluate_raw_sql(
        &self,
        caller: &CallerIdentity,
        connection_id: &str,
        engine: DatabaseEngine,
        sql: &str,
    ) -> DbMcpResult<(SqlAnalysis, PolicyEvaluation)> {
        let analysis = parse_and_analyze_sql(engine, sql)?;
        let evaluation = self.evaluate_sql(caller, connection_id, &analysis);
        Ok((analysis, evaluation))
    }

    /// Evaluate an `EXPLAIN` request, including execution-based `EXPLAIN ANALYZE` permission checks.
    pub fn evaluate_explain(
        &self,
        caller: &CallerIdentity,
        connection_id: &str,
        analysis: &SqlAnalysis,
        analyze_flag: bool,
    ) -> PolicyEvaluation {
        let base_eval = self.evaluate_sql(caller, connection_id, analysis);
        if !base_eval.is_allowed() {
            return base_eval;
        }
        let cfg = self.effective_config(connection_id);
        let is_analyze = analyze_flag || is_explain_analyze(analysis);
        if is_analyze && !cfg.allow_explain_analyze {
            return explain_analyze_denied(connection_id);
        }
        PolicyEvaluation::Allowed
    }

    /// Apply result disclosure controls to a `QueryResult` using the connection's policy config.
    pub fn apply_result_disclosure_controls(
        &self,
        connection_id: &str,
        result: &mut QueryResult,
    ) -> DbMcpResult<()> {
        let cfg = self.effective_config(connection_id);
        apply_result_disclosure_controls(result, &cfg)
    }

    /// Apply disclosure and secret redaction controls to an `ExplainPlan`.
    pub fn apply_plan_disclosure_controls(&self, connection_id: &str, plan: &mut ExplainPlan) {
        let cfg = self.effective_config(connection_id);
        apply_plan_disclosure_controls(plan, &cfg);
    }
}

/// True if any statement is an execution-based `EXPLAIN ANALYZE` (read or mutating).
fn is_explain_analyze(analysis: &SqlAnalysis) -> bool {
    analysis
        .statements
        .iter()
        .any(|s| s.statement_kind.starts_with("EXPLAIN_ANALYZE"))
}

fn explain_analyze_denied(connection_id: &str) -> PolicyEvaluation {
    PolicyEvaluation::Denied {
        code: CODE_ANALYZE_EXPLAIN_FORBIDDEN.to_string(),
        message: format!(
            "Execution-based EXPLAIN ANALYZE is disabled by policy on connection '{}'. Use plain EXPLAIN (analyze=false).",
            connection_id
        ),
        next_action: Some("explain_query".to_string()),
    }
}

/// Deny ad-hoc SQL that would let a sensitive column's value reach the result (or a readable
/// column) under a name result redaction does not recognise: aliases, expressions, set-operation
/// positions, column alias lists, `INSERT ... SELECT`, `UPDATE ... SET` and column renames.
/// Fails closed when output provenance cannot be tracked or a statement body is opaque.
fn disclosure_provenance_denial(
    cfg: &ConnectionPolicyConfig,
    analysis: &SqlAnalysis,
    connection_id: &str,
) -> Option<PolicyEvaluation> {
    if cfg.sensitive_columns.is_empty() {
        return None;
    }
    let disclosure = &analysis.disclosure;

    for exp in &disclosure.exposures {
        if !cfg.is_sensitive_column(exp.table.as_deref(), &exp.column) {
            continue;
        }
        // Still masked when it surfaces under another sensitive name.
        if exp
            .output_name
            .as_deref()
            .is_some_and(|name| cfg.is_sensitive_column(None, name))
        {
            continue;
        }
        let surfaces_as = match &exp.output_name {
            Some(name) => format!("as '{name}'"),
            None => "inside an expression or an unnamed position".to_string(),
        };
        return Some(PolicyEvaluation::Denied {
            code: CODE_SENSITIVE_COLUMN_FORBIDDEN.to_string(),
            message: format!(
                "Sensitive column '{}' would be returned {} on connection '{}', where result redaction cannot mask it. Select the column directly without an alias, expression, set operation or positional copy (it is returned as [REDACTED]), or use a curated named tool.",
                exp.column, surfaces_as, connection_id
            ),
            next_action: Some("select_sensitive_column_directly".to_string()),
        });
    }

    if let Some(reason) = disclosure.untracked_provenance.first() {
        let touches_sensitive_table = analysis.referenced_tables.is_empty()
            || analysis
                .referenced_tables
                .iter()
                .any(|t| cfg.is_sensitive_table(t));
        if touches_sensitive_table {
            return Some(PolicyEvaluation::Denied {
                code: CODE_UNPROVENANCED_SENSITIVE_QUERY.to_string(),
                message: format!(
                    "Result column provenance cannot be tracked on connection '{}' ({}), so sensitive columns could be returned unredacted. List the columns explicitly.",
                    connection_id, reason
                ),
                next_action: Some("list_columns_explicitly".to_string()),
            });
        }
    }

    for text in &disclosure.opaque_sql {
        if let Some(column) = cfg
            .sensitive_columns
            .iter()
            .find(|pattern| mentions_sensitive_column(text, pattern))
        {
            return Some(PolicyEvaluation::Denied {
                code: CODE_SENSITIVE_COLUMN_FORBIDDEN.to_string(),
                message: format!(
                    "SQL whose body cannot be analysed references sensitive column '{}' on connection '{}'; its output cannot be redacted reliably.",
                    column, connection_id
                ),
                next_action: Some("remove_sensitive_column_reference".to_string()),
            });
        }
    }
    None
}

/// True if `text` mentions the column named by a `sensitive_columns` pattern as a whole word.
fn mentions_sensitive_column(text: &str, pattern: &str) -> bool {
    let name = base_identifier(pattern);
    if name == "*" {
        return true;
    }
    if name.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let lower = text.to_ascii_lowercase();
    lower.match_indices(&name).any(|(start, matched)| {
        let before = lower[..start].chars().next_back();
        let after = lower[start + matched.len()..].chars().next();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

/// Returns true if a query uses wildcard projection (`SELECT *`, `tbl.*`) or has no explicit column provenance.
fn has_ambiguous_result_provenance(analysis: &SqlAnalysis) -> bool {
    let norm_upper = analysis.normalized_sql.to_ascii_uppercase();
    if norm_upper.contains("SELECT *")
        || norm_upper.contains(".*")
        || norm_upper.contains(", *")
        || norm_upper.contains(",*")
    {
        return true;
    }
    if analysis.overall_class == SqlStatementClass::Read && analysis.referenced_columns.is_empty() {
        return true;
    }
    false
}

/// Apply result disclosure and masking/redaction controls to a `QueryResult`:
/// - Enforces unrestricted-SQL provenance rules when `config.enforce_unrestricted_sql_provenance` is enabled.
/// - Marks columns matching `config.sensitive_columns` with `redacted = true` and masks cell values with `"[REDACTED]"`.
/// - Scrubs all string/JSON cell values and warnings through `redact_sensitive_text` and `custom_redaction_patterns`.
pub fn apply_result_disclosure_controls(
    result: &mut QueryResult,
    config: &ConnectionPolicyConfig,
) -> DbMcpResult<()> {
    let custom_regexes: Vec<Regex> = config
        .custom_redaction_patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    // 1. Identify sensitive or unprovenanced columns
    let mut sensitive_col_indices = Vec::new();
    for (idx, col) in result.columns.iter_mut().enumerate() {
        let col_lower = col.name.trim().to_ascii_lowercase();
        let is_anonymous_expr = col_lower.is_empty()
            || col_lower == "?column?"
            || col_lower.starts_with("column")
                && col_lower
                    .trim_start_matches("column")
                    .parse::<u32>()
                    .is_ok()
            || col_lower.contains('(');

        // Output names may be qualified (`users.password_hash` under SQLite full_column_names).
        let is_sensitive = config.is_sensitive_column(None, &col.name)
            || col
                .name
                .rsplit_once('.')
                .is_some_and(|(table, column)| config.is_sensitive_column(Some(table), column));

        if config.enforce_unrestricted_sql_provenance && (is_sensitive || is_anonymous_expr) {
            return Err(DbMcpError::PolicyDenied {
                code: CODE_UNPROVENANCED_SENSITIVE_QUERY.to_string(),
                message: format!(
                    "Result disclosure blocked column '{}' under unrestricted-SQL provenance policy on connection '{}'.",
                    col.name, config.connection_id
                ),
                next_action: Some("run_named_tool".to_string()),
            });
        }

        if config.deny_sensitive_column_access && is_sensitive {
            return Err(DbMcpError::PolicyDenied {
                code: CODE_SENSITIVE_COLUMN_FORBIDDEN.to_string(),
                message: format!(
                    "Result disclosure blocked sensitive column '{}' on connection '{}'.",
                    col.name, config.connection_id
                ),
                next_action: Some("run_named_tool".to_string()),
            });
        }

        if is_sensitive {
            col.redacted = true;
            sensitive_col_indices.push(idx);
        }
    }

    // 2. Redact sensitive column cells and scrub all string/JSON values for secret patterns
    let mut redacted_any_value = !sensitive_col_indices.is_empty();
    for row in &mut result.rows {
        for &col_idx in &sensitive_col_indices {
            if let Some(cell) = row.get_mut(col_idx) {
                if !cell.is_null() {
                    *cell = serde_json::Value::String(REDACTED_PLACEHOLDER.to_string());
                }
            }
        }
        for cell in row.iter_mut() {
            if redact_json_value(cell, &custom_regexes) {
                redacted_any_value = true;
            }
        }
    }

    // 3. Scrub existing warnings and append a disclosure notice if redaction occurred
    for warning in &mut result.warnings {
        *warning = scrub_text(warning, &custom_regexes);
    }

    if redacted_any_value {
        let notice = "Result disclosure controls redacted one or more sensitive columns or credential patterns.".to_string();
        if !result.warnings.contains(&notice) {
            result.warnings.push(notice);
        }
    }

    Ok(())
}

/// Apply secret and sensitive pattern redaction to an `ExplainPlan`.
pub fn apply_plan_disclosure_controls(plan: &mut ExplainPlan, config: &ConnectionPolicyConfig) {
    let custom_regexes: Vec<Regex> = config
        .custom_redaction_patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    plan.sql = scrub_text(&plan.sql, &custom_regexes);
    plan.raw_plan = scrub_text(&plan.raw_plan, &custom_regexes);
    if let Some(structured) = &mut plan.structured_plan {
        let _ = redact_json_value(structured, &custom_regexes);
    }
    for warning in &mut plan.warnings {
        *warning = scrub_text(warning, &custom_regexes);
    }
}

/// Recursively scrub a `serde_json::Value` for sensitive text patterns.
/// Returns `true` if any string inside `value` was modified.
pub fn redact_json_value(value: &mut serde_json::Value, custom_regexes: &[Regex]) -> bool {
    match value {
        serde_json::Value::String(s) => {
            if s == REDACTED_PLACEHOLDER {
                return false;
            }
            let scrubbed = scrub_text(s, custom_regexes);
            if scrubbed != *s {
                *s = scrubbed;
                true
            } else {
                false
            }
        }
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for item in items {
                if redact_json_value(item, custom_regexes) {
                    changed = true;
                }
            }
            changed
        }
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for (k, v) in map.iter_mut() {
                let key_lower = k.to_ascii_lowercase();
                if matches!(
                    key_lower.as_str(),
                    "password"
                        | "password_hash"
                        | "secret"
                        | "api_key"
                        | "apikey"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "private_key"
                ) && !v.is_null()
                {
                    *v = serde_json::Value::String(REDACTED_PLACEHOLDER.to_string());
                    changed = true;
                } else if redact_json_value(v, custom_regexes) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}

fn scrub_text(input: &str, custom_regexes: &[Regex]) -> String {
    let mut out = redact_sensitive_text(input);
    for re in custom_regexes {
        out = re.replace_all(&out, REDACTED_PLACEHOLDER).into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{ColumnMetadata, ExecutionId};

    #[test]
    fn test_caller_authorization_and_roles() {
        let cfg = ConnectionPolicyConfig::governed_production("prod-db")
            .with_allowed_roles(vec!["developer".to_string(), "dba".to_string()]);
        let engine = PolicyEngine::with_configs(OperatingMode::ReadOnly, vec![cfg]);

        let dev_caller =
            CallerIdentity::new("alice", "developer", vec!["prod-db".to_string()], "stdio");
        assert!(engine.can_access_connection(&dev_caller, "prod-db"));

        let wrong_conn_caller = CallerIdentity::new(
            "alice",
            "developer",
            vec!["staging-db".to_string()],
            "stdio",
        );
        assert!(!engine.can_access_connection(&wrong_conn_caller, "prod-db"));
        assert_eq!(
            engine
                .authorize_connection(&wrong_conn_caller, "prod-db")
                .denial_code(),
            Some(CODE_UNAUTHORIZED_CONNECTION)
        );

        let wrong_role_caller =
            CallerIdentity::new("bob", "guest", vec!["prod-db".to_string()], "http");
        assert!(!engine.can_access_connection(&wrong_role_caller, "prod-db"));
        assert_eq!(
            engine
                .authorize_connection(&wrong_role_caller, "prod-db")
                .denial_code(),
            Some(CODE_UNAUTHORIZED_ROLE)
        );
    }

    #[test]
    fn test_explain_analyze_via_execute_query_follows_allow_explain_analyze() {
        let caller = CallerIdentity::local_agent("agent-1");
        let engine = PolicyEngine::with_configs(
            OperatingMode::ReadOnly,
            vec![
                ConnectionPolicyConfig::read_only("ro"),
                ConnectionPolicyConfig::development("dev").with_allow_explain_analyze(false),
                ConnectionPolicyConfig::development("dev-allow"),
            ],
        );
        let eval = |conn: &str, sql: &str| {
            engine
                .evaluate_raw_sql(&caller, conn, DatabaseEngine::Postgres, sql)
                .unwrap()
                .1
        };
        let denied = eval("ro", "EXPLAIN ANALYZE SELECT id FROM users");
        assert_eq!(denied.denial_code(), Some(CODE_ANALYZE_EXPLAIN_FORBIDDEN));
        let PolicyEvaluation::Denied { next_action, .. } = denied else {
            unreachable!()
        };
        assert_eq!(next_action.as_deref(), Some("explain_query"));
        // Mode rules keep their codes for mutations; Development still needs the switch.
        assert_eq!(
            eval("ro", "EXPLAIN ANALYZE DELETE FROM users").denial_code(),
            Some(CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY)
        );
        assert_eq!(
            eval("dev", "EXPLAIN ANALYZE DELETE FROM users").denial_code(),
            Some(CODE_ANALYZE_EXPLAIN_FORBIDDEN)
        );
        assert!(eval("ro", "EXPLAIN SELECT id FROM users").is_allowed());
        assert!(eval("dev-allow", "EXPLAIN ANALYZE SELECT id FROM users").is_allowed());
    }

    #[test]
    fn test_bareword_pragma_write_denied_for_non_admin_in_development() {
        let engine = PolicyEngine::with_configs(
            OperatingMode::Development,
            vec![ConnectionPolicyConfig::development("dev")],
        );
        let agent = CallerIdentity::local_agent("agent-1");
        let admin = CallerIdentity::new("root", "admin", vec!["*".to_string()], "stdio");
        for sql in [
            "PRAGMA journal_mode = WAL",
            "/**/PRAGMA journal_mode = WAL",
            "PRAGMA journal_mode(WAL)",
        ] {
            let (_, eval) = engine
                .evaluate_raw_sql(&agent, "dev", DatabaseEngine::Sqlite, sql)
                .unwrap();
            assert_eq!(
                eval.denial_code(),
                Some(CODE_PRIVILEGED_FUNCTION_FORBIDDEN),
                "{sql}"
            );
            let (_, eval) = engine
                .evaluate_raw_sql(&admin, "dev", DatabaseEngine::Sqlite, sql)
                .unwrap();
            assert!(eval.is_allowed(), "{sql}");
        }
        let (_, eval) = engine
            .evaluate_raw_sql(
                &agent,
                "dev",
                DatabaseEngine::Sqlite,
                "PRAGMA table_info(users)",
            )
            .unwrap();
        assert!(eval.is_allowed());
    }

    #[test]
    fn test_allowed_roles_has_no_admin_bypass() {
        let cfg = ConnectionPolicyConfig::development("dev-db")
            .with_allowed_roles(vec!["developer".to_string()]);
        let engine = PolicyEngine::with_configs(OperatingMode::Development, vec![cfg]);
        for role in ["dba", "admin", "DBA"] {
            let caller = CallerIdentity::new("bob", role, vec!["*".to_string()], "stdio");
            assert!(caller.is_admin());
            assert!(!engine.can_access_connection(&caller, "dev-db"), "{role}");
            assert_eq!(
                engine.authorize_connection(&caller, "dev-db").denial_code(),
                Some(CODE_UNAUTHORIZED_ROLE),
                "{role}"
            );
        }
        let developer = CallerIdentity::new("bob", "Developer", vec!["*".to_string()], "stdio");
        assert!(engine.can_access_connection(&developer, "dev-db"));

        // Listing an admin role still grants it access.
        let listed = ConnectionPolicyConfig::development("dev-db")
            .with_allowed_roles(vec!["developer".to_string(), "dba".to_string()]);
        let engine = PolicyEngine::with_configs(OperatingMode::Development, vec![listed]);
        let dba = CallerIdentity::new("bob", "dba", vec!["*".to_string()], "stdio");
        assert!(engine.can_access_connection(&dba, "dev-db"));
    }

    #[test]
    fn test_multi_statement_and_privileged_function_rejection() {
        let engine = PolicyEngine::new(OperatingMode::ReadOnly);
        let caller = CallerIdentity::local_agent("agent-1");

        let (_, eval_multi) = engine
            .evaluate_raw_sql(
                &caller,
                "ro-conn",
                DatabaseEngine::Postgres,
                "SELECT 1; DROP TABLE users;",
            )
            .unwrap();
        assert_eq!(
            eval_multi.denial_code(),
            Some(CODE_MULTI_STATEMENT_FORBIDDEN)
        );

        let (_, eval_priv) = engine
            .evaluate_raw_sql(
                &caller,
                "ro-conn",
                DatabaseEngine::Postgres,
                "SELECT pg_read_file('/etc/passwd')",
            )
            .unwrap();
        assert_eq!(
            eval_priv.denial_code(),
            Some(CODE_PRIVILEGED_FUNCTION_FORBIDDEN)
        );
    }

    #[test]
    fn test_cte_write_and_mode_enforcement() {
        let engine = PolicyEngine::with_configs(
            OperatingMode::ReadOnly,
            vec![
                ConnectionPolicyConfig::development("dev-conn"),
                ConnectionPolicyConfig::read_only("ro-conn"),
                ConnectionPolicyConfig::governed_production("prod-conn"),
            ],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        let cte_sql =
            "WITH deleted AS (DELETE FROM orders WHERE id = 10 RETURNING *) SELECT * FROM deleted";

        // ReadOnly -> Denied (MUTATION_NOT_ALLOWED_IN_READ_ONLY)
        let (_, ro_eval) = engine
            .evaluate_raw_sql(&caller, "ro-conn", DatabaseEngine::Postgres, cte_sql)
            .unwrap();
        assert_eq!(
            ro_eval.denial_code(),
            Some(CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY)
        );

        // GovernedProduction -> RequiresApproval (APPROVAL_REQUIRED)
        let (analysis, prod_eval) = engine
            .evaluate_raw_sql(&caller, "prod-conn", DatabaseEngine::Postgres, cte_sql)
            .unwrap();
        assert!(prod_eval.requires_approval());
        assert_eq!(prod_eval.denial_code(), Some(CODE_APPROVAL_REQUIRED));

        // GovernedProduction with approved change -> Allowed
        let approved_eval =
            engine.evaluate_sql_with_context(&caller, "prod-conn", &analysis, true, false);
        assert!(approved_eval.is_allowed());

        // Development -> Allowed
        let (_, dev_eval) = engine
            .evaluate_raw_sql(&caller, "dev-conn", DatabaseEngine::Postgres, cte_sql)
            .unwrap();
        assert!(dev_eval.is_allowed());
    }

    #[test]
    fn test_unknown_sql_fails_closed_in_governed_mode() {
        let engine = PolicyEngine::with_configs(
            OperatingMode::GovernedProduction,
            vec![
                ConnectionPolicyConfig::governed_production("prod-conn"),
                ConnectionPolicyConfig::development("dev-conn"),
            ],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        let unknown_sql = "CUSTOM_EXTENSION_COMMAND MagicTable";

        let (_, prod_eval) = engine
            .evaluate_raw_sql(&caller, "prod-conn", DatabaseEngine::Postgres, unknown_sql)
            .unwrap();
        assert_eq!(
            prod_eval.denial_code(),
            Some(CODE_UNKNOWN_SQL_IN_GOVERNED_MODE)
        );

        let (_, dev_eval) = engine
            .evaluate_raw_sql(&caller, "dev-conn", DatabaseEngine::Postgres, unknown_sql)
            .unwrap();
        assert!(dev_eval.is_allowed());
    }

    #[test]
    fn test_restricted_tables_and_unrestricted_sql_provenance() {
        let cfg = ConnectionPolicyConfig::governed_production("prod-conn")
            .with_restricted_tables(vec!["internal_secrets".to_string()])
            .with_sensitive_tables(vec!["users".to_string()])
            .with_unrestricted_sql_provenance(true);
        let engine = PolicyEngine::with_configs(OperatingMode::GovernedProduction, vec![cfg]);
        let caller = CallerIdentity::local_agent("agent-1");

        // Restricted table is blocked
        let (_, restricted_eval) = engine
            .evaluate_raw_sql(
                &caller,
                "prod-conn",
                DatabaseEngine::Postgres,
                "SELECT id FROM public.internal_secrets",
            )
            .unwrap();
        assert_eq!(
            restricted_eval.denial_code(),
            Some(CODE_RESTRICTED_TABLE_FORBIDDEN)
        );

        // SELECT * on sensitive table is blocked when enforce_unrestricted_sql_provenance = true
        let (star_analysis, star_eval) = engine
            .evaluate_raw_sql(
                &caller,
                "prod-conn",
                DatabaseEngine::Postgres,
                "SELECT * FROM public.users WHERE id = 1",
            )
            .unwrap();
        assert_eq!(
            star_eval.denial_code(),
            Some(CODE_UNPROVENANCED_SENSITIVE_QUERY)
        );

        // Same query via curated named tool is allowed
        let named_eval =
            engine.evaluate_sql_with_context(&caller, "prod-conn", &star_analysis, false, true);
        assert!(named_eval.is_allowed());

        // Explicit non-sensitive columns are allowed
        let (_, explicit_eval) = engine
            .evaluate_raw_sql(
                &caller,
                "prod-conn",
                DatabaseEngine::Postgres,
                "SELECT id, email FROM public.users WHERE id = 1",
            )
            .unwrap();
        assert!(explicit_eval.is_allowed());
    }

    #[test]
    fn test_result_disclosure_controls_redacts_columns_and_secret_patterns() {
        let cfg = ConnectionPolicyConfig::read_only("ro-conn")
            .with_custom_redaction_patterns(vec![r"EMP-[0-9]{6}".to_string()]);

        let mut result = QueryResult {
            execution_id: ExecutionId::new(),
            columns: vec![
                ColumnMetadata::new("id", "integer"),
                ColumnMetadata::new("password_hash", "text"),
                ColumnMetadata::new("notes", "text"),
            ],
            rows: vec![vec![
                serde_json::json!(1),
                serde_json::json!("$2b$12$supersecretbcrypt"),
                serde_json::json!(
                    "Connected via postgres://admin:topsecret@db.internal:5432/app for badge EMP-123456"
                ),
            ]],
            returned_rows: 1,
            rows_affected: None,
            truncated: false,
            bytes_used: 128,
            execution_time_ms: 4,
            warnings: vec![],
            schema_version: Some("snapshot_1".to_string()),
        };

        apply_result_disclosure_controls(&mut result, &cfg).unwrap();

        assert!(!result.columns[0].redacted);
        assert!(result.columns[1].redacted);
        assert_eq!(result.rows[0][1], serde_json::json!("[REDACTED]"));

        let notes = result.rows[0][2].as_str().unwrap();
        assert!(!notes.contains("topsecret"));
        assert!(!notes.contains("EMP-123456"));
        assert!(notes.contains("postgres://admin:[REDACTED]@db.internal:5432/app"));
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_sensitive_column_access_denial_and_plan_disclosure_controls() {
        let cfg = ConnectionPolicyConfig::governed_production("prod-conn")
            .with_deny_sensitive_column_access(true)
            .with_allow_explain_analyze(false)
            .with_custom_redaction_patterns(vec![r"SECRET_TOKEN_[A-Z0-9]+".to_string()]);
        let engine =
            PolicyEngine::with_configs(OperatingMode::GovernedProduction, vec![cfg.clone()]);
        let caller = CallerIdentity::local_agent("agent-1");

        // Direct reference to sensitive column `ssn` is denied
        let (_, eval_col) = engine
            .evaluate_raw_sql(
                &caller,
                "prod-conn",
                DatabaseEngine::Postgres,
                "SELECT id, ssn FROM public.users WHERE id = 1",
            )
            .unwrap();
        assert_eq!(
            eval_col.denial_code(),
            Some(CODE_SENSITIVE_COLUMN_FORBIDDEN)
        );

        // EXPLAIN ANALYZE is denied when allow_explain_analyze = false
        let (explain_analysis, _) = engine
            .evaluate_raw_sql(
                &caller,
                "prod-conn",
                DatabaseEngine::Postgres,
                "SELECT id FROM public.users WHERE id = 1",
            )
            .unwrap();
        let eval_explain = engine.evaluate_explain(&caller, "prod-conn", &explain_analysis, true);
        assert_eq!(
            eval_explain.denial_code(),
            Some(CODE_ANALYZE_EXPLAIN_FORBIDDEN)
        );

        // Plan disclosure controls scrub secrets from raw_plan and structured_plan
        let mut plan = ExplainPlan {
            connection: "prod-conn".to_string(),
            sql: "SELECT * FROM users WHERE api_key='SECRET_TOKEN_XYZ999'".to_string(),
            analyze: false,
            format: db_mcp_core::ExplainFormat::Json,
            raw_plan: "Index Scan using password=my_raw_pass and SECRET_TOKEN_XYZ999".to_string(),
            structured_plan: Some(serde_json::json!({
                "Filter": "password=my_struct_pass",
                "secret": "should_be_redacted"
            })),
            estimated_cost: Some(1.0),
            estimated_rows: Some(1.0),
            seq_scans: vec![],
            index_scans: vec![],
            warnings: vec![],
        };
        engine.apply_plan_disclosure_controls("prod-conn", &mut plan);
        assert!(!plan.sql.contains("SECRET_TOKEN_XYZ999"));
        assert!(!plan.raw_plan.contains("my_raw_pass"));
        assert!(!plan.raw_plan.contains("SECRET_TOKEN_XYZ999"));
        let struct_str = serde_json::to_string(&plan.structured_plan).unwrap();
        assert!(!struct_str.contains("my_struct_pass"));
        assert!(!struct_str.contains("should_be_redacted"));
    }

    fn eval_dev(engine: DatabaseEngine, sql: &str) -> PolicyEvaluation {
        let policy = PolicyEngine::with_configs(
            OperatingMode::Development,
            vec![ConnectionPolicyConfig::development("dev")],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        policy
            .evaluate_raw_sql(&caller, "dev", engine, sql)
            .unwrap()
            .1
    }

    #[test]
    fn test_sensitive_column_rename_bypasses_fail_closed() {
        for engine in [
            DatabaseEngine::Sqlite,
            DatabaseEngine::Postgres,
            DatabaseEngine::MySql,
        ] {
            for sql in [
                "SELECT password_hash AS ph FROM users",
                "SELECT upper(password_hash) FROM users",
                "SELECT email || ':' || password_hash AS creds FROM users",
                "SELECT ph FROM (SELECT password_hash AS ph FROM users) t",
                "SELECT 1 UNION SELECT password_hash FROM users",
                "SELECT (SELECT password_hash FROM users LIMIT 1) AS v",
                "INSERT INTO notes (body) SELECT password_hash FROM users",
                "UPDATE users SET email = password_hash",
                "EXPLAIN SELECT password_hash AS ph FROM users",
            ] {
                let eval = eval_dev(engine, sql);
                assert_eq!(
                    eval.denial_code(),
                    Some(CODE_SENSITIVE_COLUMN_FORBIDDEN),
                    "{engine} {sql}"
                );
                let PolicyEvaluation::Denied { next_action, .. } = eval else {
                    unreachable!()
                };
                assert_eq!(
                    next_action.as_deref(),
                    Some("select_sensitive_column_directly")
                );
            }
            let eval = eval_dev(
                engine,
                "SELECT id, email, role, created_at, 1 FROM orders UNION SELECT * FROM users",
            );
            assert_eq!(
                eval.denial_code(),
                Some(CODE_UNPROVENANCED_SENSITIVE_QUERY),
                "{engine}"
            );
        }
        // Mode rules keep their own denial codes; disclosure only gates otherwise-allowed SQL.
        let ro = PolicyEngine::with_configs(
            OperatingMode::ReadOnly,
            vec![ConnectionPolicyConfig::read_only("ro")],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        let (_, eval) = ro
            .evaluate_raw_sql(
                &caller,
                "ro",
                DatabaseEngine::Postgres,
                "INSERT INTO copy SELECT * FROM users",
            )
            .unwrap();
        assert_eq!(
            eval.denial_code(),
            Some(CODE_MUTATION_NOT_ALLOWED_IN_READ_ONLY)
        );
        assert_eq!(
            eval_dev(
                DatabaseEngine::Sqlite,
                "SELECT ph FROM (SELECT password_hash AS ph FROM users)"
            )
            .denial_code(),
            Some(CODE_SENSITIVE_COLUMN_FORBIDDEN)
        );
        assert_eq!(
            eval_dev(
                DatabaseEngine::Sqlite,
                "ALTER TABLE users RENAME COLUMN password_hash TO ph"
            )
            .denial_code(),
            Some(CODE_SENSITIVE_COLUMN_FORBIDDEN)
        );
        assert_eq!(
            eval_dev(
                DatabaseEngine::Postgres,
                "SELECT row_to_json(u) AS j FROM users u"
            )
            .denial_code(),
            Some(CODE_UNPROVENANCED_SENSITIVE_QUERY)
        );
        assert_eq!(
            eval_dev(
                DatabaseEngine::Postgres,
                "CREATE FUNCTION leak() RETURNS text AS $$ SELECT password_hash FROM users LIMIT 1 $$ LANGUAGE sql"
            )
            .denial_code(),
            Some(CODE_SENSITIVE_COLUMN_FORBIDDEN)
        );
    }

    #[test]
    fn test_sqlserver_tsql_rules() {
        let e = DatabaseEngine::SqlServer;
        for sql in [
            "SELECT password_hash AS ph FROM dbo.users",
            "SELECT TOP 1 UPPER(password_hash) FROM dbo.users",
            "SELECT ph FROM (SELECT [password_hash] AS ph FROM [dbo].[users]) t",
        ] {
            assert_eq!(
                eval_dev(e, sql).denial_code(),
                Some(CODE_SENSITIVE_COLUMN_FORBIDDEN),
                "{sql}"
            );
        }
        assert!(eval_dev(e, "SELECT TOP (5) password_hash FROM [dbo].[users]").is_allowed());
        let ro = PolicyEngine::with_configs(
            OperatingMode::ReadOnly,
            vec![ConnectionPolicyConfig::read_only("ro")
                .with_restricted_tables(vec!["internal_secrets".to_string()])],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        let eval = |sql: &str| ro.evaluate_raw_sql(&caller, "ro", e, sql).map(|(_, ev)| ev);
        assert!(eval("SELECT TOP 5 id, email FROM dbo.users ORDER BY id")
            .unwrap()
            .is_allowed());
        for sql in [
            "EXEC sp_who",
            "EXEC xp_cmdshell 'whoami'",
            "SELECT 1 DELETE FROM dbo.users",
            "SELECT id INTO dbo.copy FROM dbo.users",
            "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
            "BEGIN TRAN",
            "USE master",
        ] {
            if let Ok(ev) = eval(sql) {
                assert!(!ev.is_allowed(), "{sql} was allowed")
            }
        }
        assert_eq!(
            eval("SELECT * FROM [dbo].[internal_secrets]")
                .unwrap()
                .denial_code(),
            Some(CODE_RESTRICTED_TABLE_FORBIDDEN)
        );
    }

    #[test]
    fn test_sensitive_column_direct_select_and_filters_still_allowed() {
        for engine in [
            DatabaseEngine::Sqlite,
            DatabaseEngine::Postgres,
            DatabaseEngine::MySql,
        ] {
            for sql in [
                "SELECT password_hash FROM users",
                "SELECT * FROM users ORDER BY id",
                "SELECT u.password_hash, o.id FROM users u JOIN orders o ON o.user_id = u.id",
                "WITH c AS (SELECT password_hash FROM users) SELECT * FROM c",
                "SELECT id FROM users WHERE password_hash = 'hash_alice_secret'",
                "SELECT upper(password_hash) AS password_hash FROM users",
                "SELECT id FROM users UNION ALL SELECT id FROM orders",
                "INSERT INTO users (id, email, password_hash) VALUES (3, 'c@example.com', 'h')",
                "SELECT 'k' AS api_key",
            ] {
                assert!(
                    eval_dev(engine, sql).is_allowed(),
                    "{engine} {sql}: {:?}",
                    eval_dev(engine, sql)
                );
            }
        }
    }

    #[test]
    fn test_named_tools_and_approved_changes_keep_curated_sensitive_projections() {
        let policy = PolicyEngine::with_configs(
            OperatingMode::Development,
            vec![ConnectionPolicyConfig::development("dev")],
        );
        let caller = CallerIdentity::local_agent("agent-1");
        let analysis = parse_and_analyze_sql(
            DatabaseEngine::Sqlite,
            "SELECT password_hash AS ph FROM users",
        )
        .unwrap();
        assert!(policy
            .evaluate_sql_with_context(&caller, "dev", &analysis, false, true)
            .is_allowed());
        assert_eq!(
            policy
                .evaluate_explain(&caller, "dev", &analysis, false)
                .denial_code(),
            Some(CODE_SENSITIVE_COLUMN_FORBIDDEN)
        );
    }

    #[test]
    fn test_result_redaction_matches_qualified_output_names() {
        let cfg = ConnectionPolicyConfig::development("dev");
        let mut result = QueryResult {
            execution_id: ExecutionId::new(),
            columns: vec![ColumnMetadata::new("users.password_hash", "text")],
            rows: vec![vec![serde_json::json!("hash_alice_secret")]],
            returned_rows: 1,
            rows_affected: None,
            truncated: false,
            bytes_used: 32,
            execution_time_ms: 1,
            warnings: vec![],
            schema_version: None,
        };
        apply_result_disclosure_controls(&mut result, &cfg).unwrap();
        assert!(result.columns[0].redacted);
        assert_eq!(result.rows[0][0], serde_json::json!("[REDACTED]"));
    }
}
