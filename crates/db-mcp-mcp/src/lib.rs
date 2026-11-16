//! MCP JSON-RPC 2.0 protocol handler, tool profile registry, and governed runtime.

pub mod config;
pub mod schemas;

pub use config::{AuditConfig, ChangeStoreConfig, ConnectionConfig, HttpServerConfig, OntologyConfig, ServerConfig};
pub use schemas::{build_tool_definitions, JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpToolDefinition};

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use std::collections::HashSet;
use std::sync::Mutex;

use db_mcp_audit::{build_audit_sink, create_audit_event, AuditFilter, AuditSink};
use db_mcp_catalog::{
    build_procedure_call_graph, capture_schema, compute_schema_version, describe_object,
    diff_schema, filter_and_paginate_objects, trace_table_dependencies,
};
use db_mcp_changes::ChangeManager;
use db_mcp_ontology::{
    Certification, Definition, DefinitionBody, DefinitionKind, DefinitionStatus, GovernanceOptions,
    OntologyRevision, OntologyService, OntologyStore, PlanRequest, ProposalInput, QuestionEvidence,
    ReviewAction, SemanticPlan,
};
use db_mcp_core::{
    AuditDecision, AuditEvent, CallerIdentity, CatalogDetailLevel, CatalogObject, CatalogObjectType,
    CatalogRequest, ChangeProposal, ConnectionSummary, DatabaseAdapter, DatabaseEngine,
    DbMcpError, DbMcpResult, ExplainFormat, ExplainRequest, McpSuccessResponse,
    PostgresHealthProvider, PostgresIndexAdvisor, SchemaSnapshot, SqlStatementClass,
};
use db_mcp_executor::{BoundedExecutor, GovernedQueryRequest};
use db_mcp_mysql::{MySqlAdapter, MySqlConfig};
use db_mcp_pg_insights::PgInsightsEngine;
use db_mcp_policy::{PolicyEngine, PolicyEvaluation};
use db_mcp_postgres::{PostgresAdapter, PostgresConfig};
use db_mcp_secrets::{CompositeSecretProvider, SecretProvider, SecretString, StaticSecretProvider};
use db_mcp_sql::hash_sql;
use db_mcp_sqlite::{SqliteAdapter, SqliteConfig};
use db_mcp_tools::NamedToolRegistry;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

fn to_json<T: Serialize>(val: T) -> DbMcpResult<Value> {
    serde_json::to_value(val).map_err(|e| DbMcpError::InvalidArgument(e.to_string()))
}

/// Audit sink wrapper that remembers which request ids already produced an audit event, so the
/// runtime can guarantee exactly-once auditing of every tool call (allowed, denied or failed)
/// without double-recording calls whose executor or arm already audited them.
struct TrackingAuditSink {
    inner: Arc<dyn AuditSink>,
    seen: Mutex<HashSet<String>>,
}

impl TrackingAuditSink {
    fn new(inner: Arc<dyn AuditSink>) -> Self {
        Self {
            inner,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Returns true (and forgets the id) when an event for `request_id` was recorded.
    fn take_seen(&self, request_id: &str) -> bool {
        self.seen
            .lock()
            .map(|mut set| set.remove(request_id))
            .unwrap_or(false)
    }
}

impl AuditSink for TrackingAuditSink {
    fn record(&self, event: AuditEvent) -> DbMcpResult<()> {
        if let Ok(mut set) = self.seen.lock() {
            set.insert(event.request_id.clone());
        }
        self.inner.record(event)
    }

    fn list_events(&self, filter: &AuditFilter) -> DbMcpResult<Vec<AuditEvent>> {
        self.inner.list_events(filter)
    }

    fn get_by_request_id(&self, request_id: &str) -> DbMcpResult<Vec<AuditEvent>> {
        self.inner.get_by_request_id(request_id)
    }

    fn verify_chain(&self) -> DbMcpResult<bool> {
        self.inner.verify_chain()
    }
}

fn audit_decision_for_error(err: &DbMcpError) -> AuditDecision {
    match err {
        DbMcpError::ApprovalRequired(_) => AuditDecision::RequiresApproval,
        DbMcpError::ExecutionCancelled(..) => AuditDecision::Cancelled,
        DbMcpError::AdapterError(_)
        | DbMcpError::StorageError(_)
        | DbMcpError::InternalError(_)
        | DbMcpError::ExecutionTimeout { .. } => AuditDecision::Failed,
        _ => AuditDecision::Denied,
    }
}

/// Split free text into identifier-like tokens (`schema.table` kept together) for restricted checks.
fn mentions_restricted(text: &str, cfg: &db_mcp_policy::ConnectionPolicyConfig) -> bool {
    if cfg.restricted_tables.is_empty() {
        return false;
    }
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"' || c == '`'))
        .map(|t| t.trim_matches(|c| c == '"' || c == '`' || c == '.'))
        .filter(|t| !t.is_empty())
        .any(|t| cfg.is_restricted_table(t) || t.rsplit('.').next().map(|b| cfg.is_restricted_table(b)).unwrap_or(false))
}

fn element_mentions_restricted(value: &Value, cfg: &db_mcp_policy::ConnectionPolicyConfig) -> bool {
    match value {
        Value::String(s) => mentions_restricted(s, cfg),
        Value::Object(map) => map.values().any(|v| match v {
            Value::String(s) => mentions_restricted(s, cfg),
            _ => false,
        }),
        Value::Array(items) => items.iter().any(|v| match v {
            Value::String(s) => mentions_restricted(s, cfg),
            _ => false,
        }),
        _ => false,
    }
}

/// Remove every array element (finding, recommendation, workload row, evidence string) that
/// would disclose a restricted table. Used for diagnostics computed outside the catalog filter.
fn scrub_restricted(value: &mut Value, cfg: &db_mcp_policy::ConnectionPolicyConfig) -> usize {
    let mut removed = 0;
    match value {
        Value::Array(items) => {
            let before = items.len();
            items.retain(|item| !element_mentions_restricted(item, cfg));
            removed += before - items.len();
            for item in items.iter_mut() {
                removed += scrub_restricted(item, cfg);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                removed += scrub_restricted(v, cfg);
            }
        }
        _ => {}
    }
    removed
}

/// Core governed runtime coordinating adapters, policy, executor, audit, named tools, and changes.
pub struct DbMcpRuntime {
    config: ServerConfig,
    adapters: BTreeMap<String, Arc<dyn DatabaseAdapter>>,
    summaries: BTreeMap<String, ConnectionSummary>,
    policy: Arc<PolicyEngine>,
    audit: Arc<dyn AuditSink>,
    audit_tracker: Arc<TrackingAuditSink>,
    executor: BoundedExecutor,
    named_tools: NamedToolRegistry,
    pg_insights: PgInsightsEngine,
    changes: ChangeManager,
    ontology: OntologyService,
}

/// Build the ontology service from configuration (shared by the runtime and the admin CLI).
///
/// A configured `review_key` that cannot be resolved is a startup error (fail closed).
pub fn build_ontology_service(config: &ServerConfig) -> DbMcpResult<OntologyService> {
    let store = match config.ontology.storage_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(path) => OntologyStore::open(path)?,
        None => OntologyStore::new_in_memory()?,
    };
    let review_key = match config.ontology.review_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(reference) => {
            let secrets = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
            let secret = secrets.resolve_dsn(reference).map_err(|e| {
                DbMcpError::ConfigurationError(format!("ontology.review_key could not be resolved: {e}"))
            })?;
            Some(secret.expose_secret().as_bytes().to_vec())
        }
        None => None,
    };
    Ok(OntologyService::new(
        store,
        GovernanceOptions {
            tenant_id: config.ontology.tenant_id.clone(),
            review_key,
            certification_ttl_days: config.ontology.certification_ttl_days,
        },
    ))
}

fn arg_u64(args: &Value, key: &str) -> DbMcpResult<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| DbMcpError::InvalidArgument(format!("'{key}' must be a non-negative integer"))),
    }
}

/// Like `arg_u64` but rejects zero (for limits and counts where zero is meaningless).
fn arg_positive_u64(args: &Value, key: &str) -> DbMcpResult<Option<u64>> {
    match arg_u64(args, key)? {
        Some(0) => Err(DbMcpError::InvalidArgument(format!("'{key}' must be a positive integer (>= 1)"))),
        other => Ok(other),
    }
}

/// Optional array-of-strings argument; anything else is rejected instead of silently ignored.
fn arg_string_array(args: &Value, key: &str) -> DbMcpResult<Option<Vec<String>>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("'{key}' must be an array of strings"))
                })
            })
            .collect::<DbMcpResult<Vec<_>>>()
            .map(Some),
        Some(_) => Err(DbMcpError::InvalidArgument(format!("'{key}' must be an array of strings"))),
    }
}

/// Deny a diagnostics tool when the adapter does not advertise the capability behind it.
fn unsupported_capability(tool: &str, conn: &str, adapter: &dyn DatabaseAdapter, capability: &str) -> DbMcpError {
    let caps = adapter.capabilities();
    DbMcpError::PolicyDenied {
        code: "UNSUPPORTED_CAPABILITY".to_string(),
        message: format!(
            "{tool} is not supported on {} connection '{conn}' (capability {capability} is false)",
            caps.engine.as_str()
        ),
        next_action: Some(
            "list_connections (check capabilities); use a connection whose capability is true".to_string(),
        ),
    }
}

fn definition_touches_restricted(def: &Definition, cfg: &db_mcp_policy::ConnectionPolicyConfig) -> bool {
    def.body.tables().iter().any(|t| cfg.is_restricted_table(t))
}

fn definition_summary(def: &Definition) -> Value {
    json!({
        "def_id": def.def_id,
        "version": def.version,
        "kind": def.kind,
        "name": def.name,
        "synonyms": def.synonyms,
        "status": def.status,
        "strength": def.strength,
        "flags": def.flags,
        "tables": def.body.tables(),
        "proposed_by": def.proposed_by,
    })
}

impl DbMcpRuntime {
    pub fn from_config(config: ServerConfig) -> DbMcpResult<Self> {
        config.validate()?;
        let secrets = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
        let mut adapters: BTreeMap<String, Arc<dyn DatabaseAdapter>> = BTreeMap::new();
        let mut summaries = BTreeMap::new();
        let mut policy_configs = Vec::new();

        for conn in &config.connections {
            let resolved_dsn = secrets
                .resolve_dsn(&conn.dsn)
                .unwrap_or_else(|_| SecretString::new(conn.dsn.clone()));
            let adapter: Arc<dyn DatabaseAdapter> = match conn.engine {
                DatabaseEngine::Sqlite => {
                    let mut cfg = SqliteConfig::from_dsn(&conn.id, resolved_dsn.expose_secret())
                        .with_read_only(conn.read_only);
                    if cfg.database_path != ":memory:" {
                        if let Some(parent) = Path::new(&cfg.database_path).parent() {
                            if !parent.as_os_str().is_empty() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                        }
                    }
                    if let Some(schema) = &conn.default_schema {
                        cfg = cfg.with_default_schema(schema.clone());
                    }
                    if let Some(init_sql) = &conn.init_sql {
                        cfg = cfg.with_init_sql(init_sql.clone());
                    }
                    Arc::new(SqliteAdapter::new(cfg)?)
                }
                DatabaseEngine::Postgres => {
                    let mut cfg = PostgresConfig::new(&conn.id, resolved_dsn)
                        .with_read_only(conn.read_only)
                        .with_extensions(conn.has_pg_stat_statements, conn.has_hypopg);
                    if let Some(schema) = &conn.default_schema {
                        cfg = cfg.with_default_schema(schema.clone());
                    }
                    if let Some(init_sql) = &conn.init_sql {
                        cfg = cfg.with_init_sql(init_sql.clone());
                    }
                    Arc::new(PostgresAdapter::new(cfg)?)
                }
                DatabaseEngine::MySql => {
                    let mut cfg =
                        MySqlConfig::new(&conn.id, resolved_dsn).with_read_only(conn.read_only);
                    if let Some(schema) = &conn.default_schema {
                        cfg = cfg.with_default_schema(schema.clone());
                    }
                    if let Some(init_sql) = &conn.init_sql {
                        cfg = cfg.with_init_sql(init_sql.clone());
                    }
                    Arc::new(MySqlAdapter::new(cfg)?)
                }
            };

            let mode = conn.effective_mode(config.default_mode);
            summaries.insert(
                conn.id.clone(),
                ConnectionSummary {
                    id: conn.id.clone(),
                    engine: conn.engine,
                    mode,
                    read_only: conn.read_only || matches!(mode, db_mcp_core::OperatingMode::ReadOnly),
                    description: conn.description.clone(),
                    default_schema: conn.default_schema.clone(),
                    capabilities: adapter.capabilities(),
                    limits: conn.execution_limits(),
                },
            );
            policy_configs.push(conn.to_policy_config(config.default_mode, &config.changes.policy_revision));
            adapters.insert(conn.id.clone(), adapter);
        }

        if config.default_mode == db_mcp_core::OperatingMode::GovernedProduction
            && !config.audit.in_memory
            && config.audit.jsonl_path.as_deref().map(str::trim).unwrap_or("").is_empty()
            && config.audit.sqlite_path.as_deref().map(str::trim).unwrap_or("").is_empty()
        {
            return Err(DbMcpError::StorageError(
                "governed_production requires a durable audit trail: set audit.jsonl_path or audit.sqlite_path (or audit.in_memory=true to opt in to a non-durable trail)".to_string(),
            ));
        }
        let base_sink = build_audit_sink(
            config.audit.in_memory,
            config.audit.jsonl_path.as_deref(),
            config.audit.sqlite_path.as_deref(),
        )?;
        let audit_tracker = Arc::new(TrackingAuditSink::new(base_sink));
        let audit: Arc<dyn AuditSink> = audit_tracker.clone();
        let policy = Arc::new(PolicyEngine::with_configs(config.default_mode, policy_configs));
        let executor = BoundedExecutor::with_governance(policy.clone(), audit.clone());
        let named_tools = NamedToolRegistry::from_specs(config.named_tools.clone())?;
        let pg_insights = PgInsightsEngine::with_adapters(adapters.values().cloned());

        let changes = match &config.changes.storage_path {
            Some(path) if !path.trim().is_empty() => {
                if let Some(parent) = Path::new(path).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                ChangeManager::with_storage_path(path)?
            }
            _ => ChangeManager::new_in_memory(),
        }
        .with_policy_revision(&config.changes.policy_revision)
        .with_default_ttl_seconds(config.changes.default_ttl_seconds);
        let ontology = build_ontology_service(&config)?;

        Ok(Self {
            config,
            adapters,
            summaries,
            policy,
            audit,
            audit_tracker,
            executor,
            named_tools,
            pg_insights,
            changes,
            ontology,
        })
    }

    pub fn default_demo() -> DbMcpResult<Self> {
        Self::from_config(ServerConfig::default_demo())
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn list_tools(&self) -> Vec<McpToolDefinition> {
        build_tool_definitions(&self.config.active_profiles)
    }

    pub fn approve_change(
        &self,
        change_id: &str,
        approver: &CallerIdentity,
        comment: Option<String>,
    ) -> DbMcpResult<ChangeProposal> {
        let req_id = format!("req_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let started = Instant::now();
        let outcome = self.changes.approve_change(change_id, approver, comment);
        let (conn, decision, code, err_msg) = match &outcome {
            Ok(p) => (p.connection.clone(), AuditDecision::Allowed, None, None),
            Err(e) => (
                "server".to_string(),
                AuditDecision::Denied,
                Some(e.code().to_string()),
                Some(e.to_string()),
            ),
        };
        let mode = self.policy.effective_config(&conn).mode;
        let _ = self.audit.record(create_audit_event(
            &req_id,
            approver,
            &conn,
            mode,
            "approve_change",
            None,
            None,
            None,
            decision,
            code,
            Some(change_id.to_string()),
            None,
            None,
            Some(started.elapsed().as_millis() as u64),
            None,
            err_msg,
        ));
        outcome
    }

    /// True when the connection's adapter serves results from an embedded simulation.
    pub fn is_simulated(&self, connection: &str) -> bool {
        self.adapters
            .get(connection)
            .map(|a| a.is_simulated())
            .unwrap_or(false)
    }

    /// Discover the full catalog of a connection with restricted objects removed.
    async fn discover_allowed(
        &self,
        adapter: &dyn DatabaseAdapter,
        connection: &str,
        schema_pattern: Option<String>,
    ) -> DbMcpResult<(Vec<CatalogObject>, usize)> {
        let catalog = adapter
            .discover(CatalogRequest {
                connection: connection.to_string(),
                schema_pattern,
                name_pattern: None,
                object_types: Vec::new(),
                detail_level: CatalogDetailLevel::Full,
                limit: 10_000,
                offset: 0,
            })
            .await?;
        let mut objects = catalog.objects;
        let hidden = self
            .policy
            .effective_config(connection)
            .retain_allowed_objects(&mut objects);
        Ok((objects, hidden))
    }

    /// Capture a schema snapshot over the policy-visible catalog only.
    async fn capture_allowed(
        &self,
        adapter: &dyn DatabaseAdapter,
        connection: &str,
        schema_pattern: Option<String>,
    ) -> DbMcpResult<SchemaSnapshot> {
        let (objects, _) = self.discover_allowed(adapter, connection, schema_pattern).await?;
        Ok(capture_schema(connection, adapter.capabilities().engine, objects))
    }

    /// Post-process every successful tool response: envelope counts and simulation disclosure.
    fn finalize_response(&self, val: &mut Value, args: &Value) {
        let Some(obj) = val.as_object_mut() else { return };
        let rows_empty = obj.get("rows").and_then(|r| r.as_array()).map(|r| r.is_empty()).unwrap_or(true);
        let returned_zero = obj.get("returned_rows").and_then(|r| r.as_u64()) == Some(0);
        if rows_empty && returned_zero {
            if let Some(data) = obj.get("data").filter(|d| !d.is_null()) {
                let count = if let Some(arr) = data.as_array() {
                    arr.len()
                } else if let Some(arr) = data.get("objects").and_then(|o| o.as_array()) {
                    arr.len()
                } else {
                    1
                };
                obj.insert("returned_rows".to_string(), json!(count));
            }
        }
        let mut conns: Vec<String> = Vec::new();
        for key in ["connection", "base_connection", "target_connection"] {
            if let Some(c) = args.get(key).and_then(|v| v.as_str()) {
                conns.push(c.to_string());
            }
        }
        if let Some(c) = obj.get("connection").and_then(|v| v.as_str()) {
            conns.push(c.to_string());
        }
        conns.sort();
        conns.dedup();
        let mut notes = Vec::new();
        for c in conns {
            if let Some(adapter) = self.adapters.get(&c) {
                if adapter.is_simulated() {
                    notes.push(format!(
                        "connection '{c}' is served by the embedded simulated {} engine (no external server is queried; results are illustrative)",
                        adapter.capabilities().engine.as_str()
                    ));
                }
            }
        }
        if !notes.is_empty() {
            let warnings = obj.entry("warnings").or_insert_with(|| json!([]));
            if let Some(arr) = warnings.as_array_mut() {
                for n in notes {
                    if !arr.iter().any(|w| w.as_str() == Some(n.as_str())) {
                        arr.push(Value::String(n));
                    }
                }
            }
        }
    }

    /// Ontology governance service (admin channel and tests).
    pub fn ontology(&self) -> &OntologyService {
        &self.ontology
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_ontology_admin(
        &self,
        caller: &CallerIdentity,
        connection: &str,
        tool: &str,
        subject: Option<String>,
        outcome: Result<Option<String>, &DbMcpError>,
        started: Instant,
    ) {
        let req_id = format!("req_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let (decision, code, msg, schema_version) = match outcome {
            Ok(sv) => (AuditDecision::Allowed, None, None, sv),
            Err(e) => (AuditDecision::Denied, Some(e.code().to_string()), Some(e.to_string()), None),
        };
        let mode = self.policy.effective_config(connection).mode;
        let _ = self.audit.record(create_audit_event(
            req_id,
            caller,
            connection,
            mode,
            tool,
            None,
            None,
            None,
            decision,
            code,
            subject,
            None,
            None,
            Some(started.elapsed().as_millis() as u64),
            schema_version,
            msg,
        ));
    }

    /// Admin channel: certify, reject or deprecate one definition version (audited).
    pub fn review_ontology(
        &self,
        reviewer: &CallerIdentity,
        connection: &str,
        def_id: &str,
        version: u32,
        action: ReviewAction,
        reason: Option<String>,
    ) -> DbMcpResult<(Definition, Certification)> {
        let started = Instant::now();
        let outcome = if self.adapters.contains_key(connection) {
            self.ontology.review(reviewer, connection, def_id, version, action, reason)
        } else {
            Err(DbMcpError::ConnectionNotFound(format!("Unknown connection '{connection}'")))
        };
        self.audit_ontology_admin(
            reviewer,
            connection,
            &format!("ontology_review:{}", action.as_str()),
            Some(format!("{def_id}@{version}")),
            outcome.as_ref().map(|_| None),
            started,
        );
        outcome
    }

    /// Admin channel: publish all certified definitions as a new revision bound to the live
    /// schema fingerprint (audited).
    pub async fn publish_ontology(
        &self,
        reviewer: &CallerIdentity,
        connection: &str,
    ) -> DbMcpResult<OntologyRevision> {
        let started = Instant::now();
        let outcome = async {
            let adapter = self.adapters.get(connection).cloned().ok_or_else(|| {
                DbMcpError::ConnectionNotFound(format!("Unknown connection '{connection}'"))
            })?;
            let (objects, _) = self.discover_allowed(adapter.as_ref(), connection, None).await?;
            let drift = self.ontology.check_drift(connection, &objects)?;
            if !drift.newly_stale.is_empty() {
                return Err(DbMcpError::SchemaDriftDetected(format!(
                    "{} certified definition(s) became stale against the live schema; re-certify before publishing",
                    drift.newly_stale.len()
                )));
            }
            let fingerprint = compute_schema_version(&objects);
            self.ontology.publish(reviewer, connection, Some(&fingerprint))
        }
        .await;
        self.audit_ontology_admin(
            reviewer,
            connection,
            "ontology_publish",
            outcome.as_ref().ok().map(|r| r.revision_id.clone()),
            outcome.as_ref().map(|r| Some(r.revision_id.clone())),
            started,
        );
        outcome
    }

    /// Plan a question against the published ontology (used by MCP tools and golden eval).
    pub async fn plan_question(
        &self,
        caller: &CallerIdentity,
        connection: &str,
        question: &str,
        max_rows: Option<usize>,
    ) -> DbMcpResult<SemanticPlan> {
        let question = question.trim();
        if question.is_empty() || question.len() > 1000 {
            return Err(DbMcpError::InvalidArgument("question must be 1-1000 characters".to_string()));
        }
        let adapter = self.get_authorized_adapter(caller, connection)?;
        let cfg = self.policy.effective_config(connection);
        let (objects, _) = self.discover_allowed(adapter.as_ref(), connection, None).await?;
        let fingerprint = compute_schema_version(&objects);
        self.ontology.check_drift(connection, &objects)?;
        let (revision, live, stale) = self.ontology.published_set(connection)?;
        let live: Vec<Definition> = live.into_iter().filter(|d| !definition_touches_restricted(d, &cfg)).collect();
        let row_cap = max_rows
            .unwrap_or(self.config.ontology.default_max_rows)
            .min(self.config.ontology.default_max_rows.max(1))
            .min(cfg.limits.max_rows.max(1));
        let plan = db_mcp_ontology::plan(&PlanRequest {
            question,
            engine: adapter.capabilities().engine,
            max_rows: row_cap,
            revision: revision.as_ref(),
            published: &live,
            stale: &stale,
            schema_fingerprint: &fingerprint,
        });
        // Fail closed: every definition the plan relies on must still carry a valid certification.
        if plan.is_answerable() {
            for used in plan.all_used() {
                let def = live
                    .iter()
                    .find(|d| d.def_id == used.def_id && d.version == used.version)
                    .ok_or_else(|| DbMcpError::InternalError(format!("plan references unknown definition {}", used.def_id)))?;
                self.ontology.verify_certification(def)?;
            }
        }
        let evidence = QuestionEvidence {
            evidence_id: format!("qev_{}", Uuid::new_v4().simple()),
            tenant_id: self.config.ontology.tenant_id.clone(),
            connection: connection.to_string(),
            question_hash: plan.question_hash.clone(),
            revision_id: plan.revision_id.clone(),
            def_refs: plan
                .all_used()
                .iter()
                .map(|u| db_mcp_ontology::DefinitionRef {
                    def_id: u.def_id.clone(),
                    version: u.version,
                    content_hash: u.content_hash.clone(),
                })
                .collect(),
            sql_hash: plan.sql.as_ref().map(|s| hash_sql(s)),
            decision: serde_json::to_value(plan.status)
                .ok()
                .and_then(|v| v.as_str().map(ToOwned::to_owned))
                .unwrap_or_default(),
            returned_rows: None,
            principal: caller.principal.clone(),
            at: chrono::Utc::now(),
        };
        let _ = self.ontology.store.insert_question_evidence(&evidence);
        Ok(plan)
    }

    pub fn audit_events(&self) -> DbMcpResult<Vec<AuditEvent>> {
        self.audit.list_events(&AuditFilter::new())
    }

    fn authorize_conn(&self, caller: &CallerIdentity, connection: &str) -> DbMcpResult<()> {
        match self.policy.authorize_connection(caller, connection) {
            PolicyEvaluation::Allowed => Ok(()),
            PolicyEvaluation::RequiresApproval { reason, .. } => {
                Err(DbMcpError::ApprovalRequired(reason))
            }
            PolicyEvaluation::Denied {
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

    fn get_authorized_adapter(
        &self,
        caller: &CallerIdentity,
        connection: &str,
    ) -> DbMcpResult<Arc<dyn DatabaseAdapter>> {
        self.authorize_conn(caller, connection)?;
        self.adapters.get(connection).cloned().ok_or_else(|| {
            DbMcpError::ConnectionNotFound(format!("Unknown connection '{connection}'"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn log_audit(
        &self,
        req_id: &str,
        caller: &CallerIdentity,
        connection: &str,
        tool_name: &str,
        decision: AuditDecision,
        execution_time_ms: Option<u64>,
        schema_version: Option<String>,
    ) {
        let mode = self.policy.effective_config(connection).mode;
        let _ = self.audit.record(create_audit_event(
            req_id,
            caller,
            connection,
            mode,
            tool_name,
            None,
            None,
            Some(SqlStatementClass::Read),
            decision,
            None,
            None,
            None,
            None,
            execution_time_ms,
            schema_version,
            None,
        ));
    }

    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: Value,
        caller: &CallerIdentity,
    ) -> Value {
        let req_id = format!("req_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let started = Instant::now();
        let conn_hint = arguments
            .get("connection")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        if !self.list_tools().iter().any(|t| t.name == tool_name) {
            let err = DbMcpError::PolicyDenied {
                code: "TOOL_NOT_ENABLED".to_string(),
                message: format!("Tool '{tool_name}' is not enabled in active profiles"),
                next_action: Some("Enable the required tool profile in ServerConfig".to_string()),
            };
            self.audit_call_outcome(&req_id, tool_name, caller, conn_hint.as_deref(), Err(&err), started);
            let denied = err.to_denied_response(Some(req_id), conn_hint);
            return serde_json::to_value(denied).unwrap_or_else(|_| json!({"status": "denied"}));
        }

        let outcome = self.dispatch_tool(&req_id, tool_name, &arguments, caller).await;
        let already_audited = self.audit_tracker.take_seen(&req_id);
        match outcome {
            Ok(mut val) => {
                self.finalize_response(&mut val, &arguments);
                if !already_audited {
                    self.audit_call_outcome(&req_id, tool_name, caller, conn_hint.as_deref(), Ok(&val), started);
                    self.audit_tracker.take_seen(&req_id);
                }
                val
            }
            Err(err) => {
                if !already_audited {
                    self.audit_call_outcome(&req_id, tool_name, caller, conn_hint.as_deref(), Err(&err), started);
                    self.audit_tracker.take_seen(&req_id);
                }
                let denied = err.to_denied_response(Some(req_id), conn_hint);
                serde_json::to_value(denied).unwrap_or_else(|_| json!({"status": "denied"}))
            }
        }
    }

    /// Record exactly one audit event for a tool call that no deeper layer audited.
    fn audit_call_outcome(
        &self,
        req_id: &str,
        tool_name: &str,
        caller: &CallerIdentity,
        conn_hint: Option<&str>,
        outcome: Result<&Value, &DbMcpError>,
        started: Instant,
    ) {
        let elapsed = Some(started.elapsed().as_millis() as u64);
        let (connection, decision, code, err_msg, rows, schema_version) = match outcome {
            Ok(val) => (
                val.get("connection")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
                    .or_else(|| conn_hint.map(ToOwned::to_owned))
                    .unwrap_or_else(|| "server".to_string()),
                AuditDecision::Allowed,
                None,
                None,
                val.get("returned_rows").and_then(|v| v.as_u64()).map(|r| r as usize),
                val.get("schema_version").and_then(|v| v.as_str()).map(ToOwned::to_owned),
            ),
            Err(err) => (
                conn_hint.map(ToOwned::to_owned).unwrap_or_else(|| "server".to_string()),
                audit_decision_for_error(err),
                Some(err.code().to_string()),
                Some(err.to_string()),
                None,
                None,
            ),
        };
        let mode = self.policy.effective_config(&connection).mode;
        let _ = self.audit.record(create_audit_event(
            req_id,
            caller,
            &connection,
            mode,
            tool_name,
            None,
            None,
            None,
            decision,
            code,
            None,
            rows,
            None,
            elapsed,
            schema_version,
            err_msg,
        ));
    }

    async fn dispatch_tool(
        &self,
        req_id: &str,
        tool_name: &str,
        args: &Value,
        caller: &CallerIdentity,
    ) -> DbMcpResult<Value> {
        let req_str = |key: &str| -> DbMcpResult<String> {
            args.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| DbMcpError::InvalidArgument(format!("Missing required parameter '{key}'")))
        };

        match tool_name {
            "list_connections" => {
                let list: Vec<Value> = self
                    .summaries
                    .values()
                    .filter(|c| self.policy.authorize_connection(caller, &c.id).is_allowed())
                    .map(|c| {
                        let mut summary: ConnectionSummary = c.clone();
                        let simulated = self.is_simulated(&c.id);
                        if simulated {
                            // An embedded simulation cannot interrupt statements or run real ANALYZE plans.
                            summary.capabilities.supports_cancellation = false;
                            summary.capabilities.supports_analyze_explain = false;
                        }
                        let mut entry = serde_json::to_value(&summary).unwrap_or_else(|_| json!({}));
                        entry["simulated"] = json!(simulated);
                        if simulated {
                            entry["warnings"] = json!([format!(
                                "connection '{}' is served by the embedded simulated {} engine (no external server is queried; results are illustrative)",
                                c.id,
                                c.engine.as_str()
                            )]);
                        }
                        entry
                    })
                    .collect();
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    "server",
                    "snapshot_connections",
                    "connection_list",
                    list,
                ))
            }
            "search_objects" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                let detail_level = parse_detail_level(args.get("detail_level"), CatalogDetailLevel::Summary)?;
                let object_types = parse_object_types(args.get("object_types"))?;
                let limit = arg_positive_u64(args, "limit")?.unwrap_or(50) as usize;
                let offset = arg_u64(args, "offset")?.unwrap_or(0) as usize;
                let _ = &cfg;
                // Restricted objects are removed BEFORE filtering/pagination so totals never leak them.
                let (visible, _hidden) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let request = CatalogRequest {
                    connection: conn.clone(),
                    schema_pattern: args.get("schema_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned),
                    name_pattern: args.get("name_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned),
                    object_types,
                    detail_level,
                    limit,
                    offset,
                };
                let mut catalog = filter_and_paginate_objects(&visible, &request);
                catalog.schema_version = Some(compute_schema_version(&visible));
                let sv = catalog.schema_version.clone().unwrap_or_else(|| "snapshot_catalog".to_string());
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    sv,
                    "catalog_search",
                    catalog,
                ))
            }
            "describe_object" => {
                let conn = req_str("connection")?;
                let object_name = req_str("object_name")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                if cfg.is_restricted_table(&object_name) {
                    return Err(DbMcpError::PolicyDenied {
                        code: "RESTRICTED_TABLE".to_string(),
                        message: format!("Object '{object_name}' is restricted by connection policy"),
                        next_action: Some("Query an allowed table or view".to_string()),
                    });
                }
                let detail_level = parse_detail_level(args.get("detail_level"), CatalogDetailLevel::Full)?;
                let schema = args.get("schema").and_then(|v| v.as_str());
                let (visible, _) = self
                    .discover_allowed(adapter.as_ref(), &conn, schema.map(ToOwned::to_owned))
                    .await?;
                let described = describe_object(&visible, schema, &object_name, detail_level)?;
                let sv = compute_schema_version(&visible);
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    sv,
                    "catalog_object",
                    described,
                ))
            }
            "trace_table_dependencies" => {
                let started = Instant::now();
                let conn = req_str("connection")?;
                let table_name = req_str("table_name")?;
                self.authorize_conn(caller, &conn)?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                if cfg.is_restricted_table(&table_name) {
                    return Err(DbMcpError::PolicyDenied {
                        code: "RESTRICTED_TABLE".to_string(),
                        message: format!("Object '{table_name}' is restricted by connection policy"),
                        next_action: Some("Query an allowed table or view".to_string()),
                    });
                }
                let target_table = args
                    .get("target_table")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                if let Some(ref target) = target_table {
                    if cfg.is_restricted_table(target) {
                        return Err(DbMcpError::PolicyDenied {
                            code: "RESTRICTED_TABLE".to_string(),
                            message: format!("Object '{target}' is restricted by connection policy"),
                            next_action: Some("Query an allowed table or view".to_string()),
                        });
                    }
                }
                let max_depth = arg_u64(args, "max_depth")?.unwrap_or(3) as usize;
                let (visible, _) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let report = trace_table_dependencies(
                    &visible,
                    adapter.capabilities().engine,
                    &conn,
                    &table_name,
                    target_table.as_deref(),
                    max_depth,
                )?;
                let elapsed_ms = started.elapsed().as_millis() as u64;
                let schema_version = "snapshot_lineage".to_string();
                self.log_audit(
                    req_id,
                    caller,
                    &conn,
                    "trace_table_dependencies",
                    AuditDecision::Allowed,
                    Some(elapsed_ms),
                    Some(schema_version.clone()),
                );
                let mut resp = McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    schema_version,
                    "table_dependencies",
                    report,
                );
                resp.execution_time_ms = Some(elapsed_ms);
                to_json(resp)
            }
            "get_procedure_call_graph" => {
                let started = Instant::now();
                let conn = req_str("connection")?;
                self.authorize_conn(caller, &conn)?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let procedure_name = args
                    .get("procedure_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let direction = args
                    .get("direction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("both")
                    .to_string();
                let max_depth = arg_u64(args, "max_depth")?.unwrap_or(5) as usize;
                let (visible, _) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let report = build_procedure_call_graph(
                    &visible,
                    adapter.capabilities().engine,
                    &conn,
                    procedure_name.as_deref(),
                    &direction,
                    max_depth,
                )?;
                let elapsed_ms = started.elapsed().as_millis() as u64;
                let schema_version = "snapshot_call_graph".to_string();
                self.log_audit(
                    req_id,
                    caller,
                    &conn,
                    "get_procedure_call_graph",
                    AuditDecision::Allowed,
                    Some(elapsed_ms),
                    Some(schema_version.clone()),
                );
                let mut resp = McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    schema_version,
                    "procedure_call_graph",
                    report,
                );
                resp.execution_time_ms = Some(elapsed_ms);
                to_json(resp)
            }
            "execute_query" => {
                let conn = req_str("connection")?;
                let sql = req_str("sql")?;
                let adapter = self.adapters.get(&conn).cloned().ok_or_else(|| {
                    DbMcpError::ConnectionNotFound(format!("Unknown connection '{conn}'"))
                })?;
                let params = args
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut gov_req = GovernedQueryRequest::new(req_id, &conn, caller.clone(), &sql)
                    .with_tool_name("execute_query")
                    .with_params(params);
                if let Some(ms) = args.get("timeout_ms").and_then(|v| v.as_u64()) {
                    gov_req = gov_req.with_timeout_ms(ms);
                }
                if let Some(rows) = args.get("max_rows").and_then(|v| v.as_u64()) {
                    gov_req = gov_req.with_max_rows(rows as usize);
                }
                if let Some(bytes) = args.get("max_bytes").and_then(|v| v.as_u64()) {
                    gov_req = gov_req.with_max_bytes(bytes as usize);
                }
                if args.get("change_id").is_some() {
                    // Approved changes must be executed through apply_change, which verifies the
                    // approval hash, TTL, schema fingerprint and performs the atomic claim.
                    return Err(DbMcpError::PolicyDenied {
                        code: "USE_APPLY_CHANGE".to_string(),
                        message: "execute_query does not accept change_id; approved proposals are executed via apply_change".to_string(),
                        next_action: Some("apply_change".to_string()),
                    });
                }
                let result = self.executor.execute_governed(adapter.as_ref(), gov_req).await?;
                self.pg_insights.record_query_execution(
                    &conn,
                    &sql,
                    result.execution_time_ms as f64,
                    result.returned_rows as u64,
                );
                to_json(McpSuccessResponse::<Value>::from_query_result(
                    req_id, &conn, result, None,
                ))
            }
            "explain_query" => {
                let conn = req_str("connection")?;
                let sql = req_str("sql")?;
                let adapter = self.adapters.get(&conn).cloned().ok_or_else(|| {
                    DbMcpError::ConnectionNotFound(format!("Unknown connection '{conn}'"))
                })?;
                let format = match args.get("format").and_then(|v| v.as_str()) {
                    Some("text") => ExplainFormat::Text,
                    _ => ExplainFormat::Json,
                };
                let explain_req = ExplainRequest {
                    request_id: req_id.to_string(),
                    connection: conn.clone(),
                    sql,
                    params: args.get("params").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
                    analyze: args.get("analyze").and_then(|v| v.as_bool()).unwrap_or(false),
                    format,
                    timeout_ms: args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(10_000),
                };
                let plan = self
                    .executor
                    .explain_governed_query(adapter.as_ref(), &self.policy, self.audit.as_ref(), caller, explain_req)
                    .await?;
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    "snapshot_explain",
                    "explain_plan",
                    plan,
                ))
            }
            "run_named_tool" => {
                let name = req_str("tool_name")?;
                let spec = self.named_tools.get(&name).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!("Named tool '{name}' is not registered"))
                })?;
                let conn = spec.connection.clone();
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let default_limits = self.policy.effective_config(&conn).limits;
                let args_map: BTreeMap<String, Value> = match args.get("arguments") {
                    None | Some(Value::Null) => BTreeMap::new(),
                    Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    Some(_) => {
                        return Err(DbMcpError::InvalidArgument(
                            "`arguments` must be a JSON object of named parameters".to_string(),
                        ))
                    }
                };
                let prepared = self.named_tools.validate_and_bind(
                    req_id,
                    &name,
                    caller,
                    &args_map,
                    &default_limits,
                )?;
                let gov_req = GovernedQueryRequest::new(
                    req_id,
                    &conn,
                    caller.clone(),
                    prepared.authorized_query.sql.clone(),
                )
                .with_tool_name(format!("run_named_tool:{name}"))
                .with_params(prepared.bound_params)
                .with_timeout_ms(prepared.authorized_query.timeout_ms)
                .with_max_rows(prepared.authorized_query.max_rows)
                .with_max_bytes(prepared.authorized_query.max_bytes)
                .with_named_tool(true);
                let result = self.executor.execute_governed(adapter.as_ref(), gov_req).await?;
                to_json(McpSuccessResponse::<Value>::from_query_result(
                    req_id, &conn, result, None,
                ))
            }
            "database_health" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                if !adapter.capabilities().supports_health_diagnostics {
                    return Err(unsupported_capability(
                        "database_health",
                        &conn,
                        adapter.as_ref(),
                        "supports_health_diagnostics",
                    ));
                }
                let report = self.pg_insights.database_health(&conn).await?;
                let mut val = to_json(PgInsightsEngine::health_report_to_response(
                    req_id,
                    "snapshot_health",
                    &report,
                ))?;
                if scrub_restricted(&mut val, &self.policy.effective_config(&conn)) > 0 {
                    if let Some(rows) = val.get("rows").and_then(|r| r.as_array()).map(|r| r.len()) {
                        val["returned_rows"] = json!(rows);
                    }
                }
                Ok(val)
            }
            "analyze_workload" => {
                let conn = req_str("connection")?;
                let _adapter = self.get_authorized_adapter(caller, &conn)?;
                let top_n = arg_positive_u64(args, "top_n")?.unwrap_or(10) as usize;
                let workload = self.pg_insights.analyze_workload(&conn, top_n).await?;
                let mut val = to_json(PgInsightsEngine::workload_to_response(
                    req_id,
                    "snapshot_workload",
                    &workload,
                ))?;
                if scrub_restricted(&mut val, &self.policy.effective_config(&conn)) > 0 {
                    if let Some(rows) = val.get("rows").and_then(|r| r.as_array()).map(|r| r.len()) {
                        val["returned_rows"] = json!(rows);
                    }
                }
                Ok(val)
            }
            "recommend_indexes" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                if !adapter.capabilities().supports_index_advisor {
                    return Err(unsupported_capability(
                        "recommend_indexes",
                        &conn,
                        adapter.as_ref(),
                        "supports_index_advisor",
                    ));
                }
                let queries: Vec<String> = arg_string_array(args, "queries")?.unwrap_or_default();
                let max_recs = arg_positive_u64(args, "max_recommendations")?.unwrap_or(5) as usize;
                let cfg = self.policy.effective_config(&conn);
                if let Some(q) = queries.iter().find(|q| mentions_restricted(q, &cfg)) {
                    return Err(DbMcpError::PolicyDenied {
                        code: "RESTRICTED_TABLE".to_string(),
                        message: format!(
                            "Query references a table restricted by connection policy: {}",
                            db_mcp_sql::fingerprint_sql(q)
                        ),
                        next_action: Some("Remove restricted tables from the workload".to_string()),
                    });
                }
                let recs = self.pg_insights.recommend_indexes(&conn, queries, max_recs).await?;
                let mut val = to_json(PgInsightsEngine::recommendations_to_response(
                    req_id,
                    &conn,
                    "snapshot_indexes",
                    recs,
                ))?;
                if scrub_restricted(&mut val, &cfg) > 0 {
                    if let Some(rows) = val.get("rows").and_then(|r| r.as_array()).map(|r| r.len()) {
                        val["returned_rows"] = json!(rows);
                    }
                }
                Ok(val)
            }
            "propose_change" => {
                let conn = req_str("connection")?;
                let sql = req_str("sql")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let params = args.get("params").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let constraints = args.get("constraints").cloned();
                let ttl = args.get("ttl_seconds").and_then(|v| v.as_i64());
                let proposal = self
                    .changes
                    .propose_change_with_adapter(caller, adapter.as_ref(), sql, params, constraints, ttl)
                    .await?;
                let mode = self.policy.effective_config(&conn).mode;
                let _ = self.audit.record(create_audit_event(
                    req_id,
                    caller,
                    &conn,
                    mode,
                    "propose_change",
                    Some(hash_sql(&proposal.normalized_sql)),
                    Some(proposal.normalized_sql.clone()),
                    Some(proposal.statement_class),
                    AuditDecision::RequiresApproval,
                    None,
                    Some(proposal.change_id.clone()),
                    None,
                    None,
                    None,
                    Some(proposal.schema_fingerprint.clone()),
                    None,
                ));
                to_json(ChangeManager::proposal_to_response(req_id, &proposal))
            }
            "get_change" => {
                let change_id = req_str("change_id")?;
                let proposal = self.changes.get_change(&change_id)?;
                let _ = self.get_authorized_adapter(caller, &proposal.connection)?;
                to_json(ChangeManager::proposal_to_response(req_id, &proposal))
            }
            "apply_change" => {
                let change_id = req_str("change_id")?;
                let existing = self.changes.get_change(&change_id)?;
                let adapter = self.get_authorized_adapter(caller, &existing.connection)?;
                let outcome = self.changes.apply_change(&change_id, caller, adapter.as_ref()).await?;
                let mode = self.policy.effective_config(&existing.connection).mode;
                let _ = self.audit.record(create_audit_event(
                    req_id,
                    caller,
                    &existing.connection,
                    mode,
                    "apply_change",
                    Some(hash_sql(&outcome.proposal.normalized_sql)),
                    Some(outcome.proposal.normalized_sql.clone()),
                    Some(outcome.proposal.statement_class),
                    AuditDecision::ApprovedExecution,
                    None,
                    Some(outcome.proposal.change_id.clone()),
                    Some(outcome.query_result.returned_rows),
                    Some(outcome.query_result.truncated),
                    Some(outcome.query_result.execution_time_ms),
                    outcome.post_schema_fingerprint.clone(),
                    None,
                ));
                to_json(ChangeManager::proposal_to_response(
                    req_id,
                    &outcome.proposal,
                ))
            }
            "capture_schema" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let schema_pattern = args.get("schema_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned);
                let snapshot = self.capture_allowed(adapter.as_ref(), &conn, schema_pattern).await?;
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    snapshot.schema_version.clone(),
                    "schema_snapshot",
                    snapshot,
                ))
            }
            "diff_schema" => {
                let schema_pattern = args.get("schema_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned);
                let base: SchemaSnapshot = if let Some(b) = args.get("base_snapshot") {
                    serde_json::from_value(b.clone())
                        .map_err(|e| DbMcpError::InvalidArgument(format!("Invalid base_snapshot: {e}")))?
                } else {
                    let conn = req_str("base_connection")?;
                    let adapter = self.get_authorized_adapter(caller, &conn)?;
                    self.capture_allowed(adapter.as_ref(), &conn, schema_pattern.clone()).await?
                };
                let target: SchemaSnapshot = if let Some(t) = args.get("target_snapshot") {
                    serde_json::from_value(t.clone())
                        .map_err(|e| DbMcpError::InvalidArgument(format!("Invalid target_snapshot: {e}")))?
                } else {
                    let conn = req_str("target_connection")?;
                    let adapter = self.get_authorized_adapter(caller, &conn)?;
                    self.capture_allowed(adapter.as_ref(), &conn, schema_pattern).await?
                };
                let diff = diff_schema(&base, &target);
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &base.connection,
                    target.schema_version,
                    "schema_diff",
                    diff,
                ))
            }
            "ontology_status" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                let (objects, hidden) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let fingerprint = compute_schema_version(&objects);
                let drift = self.ontology.check_drift(&conn, &objects)?;
                let tenant = self.config.ontology.tenant_id.clone();
                let counts = self.ontology.store.stats(&tenant, &conn)?;
                let (revision, live, stale) = self.ontology.published_set(&conn)?;
                let live: Vec<Definition> = live.into_iter().filter(|d| !definition_touches_restricted(d, &cfg)).collect();
                let tables_total = objects
                    .iter()
                    .filter(|o| matches!(o.object_type, CatalogObjectType::Table | CatalogObjectType::View))
                    .count();
                let covered: std::collections::BTreeSet<String> = live
                    .iter()
                    .filter(|d| d.kind == DefinitionKind::Entity)
                    .flat_map(|d| d.body.tables())
                    .map(|t| t.to_ascii_lowercase())
                    .collect();
                let metrics = live.iter().filter(|d| d.kind == DefinitionKind::Metric).count();
                let mut reasons = Vec::new();
                let readiness = match &revision {
                    None => {
                        reasons.push("no published revision: run discover_ontology, propose_semantic_definition, then ask a reviewer to certify and publish".to_string());
                        "not_ready"
                    }
                    Some(rev) => {
                        if !stale.is_empty() {
                            reasons.push(format!("{} published definition(s) are stale after schema drift and are excluded until re-certified", stale.len()));
                        }
                        if metrics == 0 {
                            reasons.push("published revision contains no metrics; questions cannot be answered".to_string());
                        }
                        if rev.schema_fingerprint != fingerprint {
                            reasons.push(format!("schema changed since publication ({} -> {}); dependencies are re-verified on every plan", rev.schema_fingerprint, fingerprint));
                        }
                        if !stale.is_empty() || metrics == 0 { "degraded" } else { "ready" }
                    }
                };
                let data = json!({
                    "connection": conn,
                    "tenant_id": tenant,
                    "readiness": readiness,
                    "reasons": reasons,
                    "schema_fingerprint": fingerprint,
                    "revision": revision.as_ref().map(|r| json!({
                        "revision_id": r.revision_id,
                        "seq": r.seq,
                        "published_by": r.published_by,
                        "published_at": r.published_at,
                        "schema_fingerprint": r.schema_fingerprint,
                        "definitions": r.def_refs.len(),
                    })),
                    "counts_by_kind_and_status": counts,
                    "published_definitions": live.len(),
                    "stale_definitions": stale.iter().map(|d| json!({"def_id": d.def_id, "version": d.version, "name": d.name})).collect::<Vec<_>>(),
                    "coverage": {
                        "tables_visible": tables_total,
                        "tables_with_published_entity": covered.len(),
                        "published_metrics": metrics,
                        "restricted_objects_hidden": hidden,
                    },
                    "drift": drift,
                    "store": { "persistent": self.ontology.store.is_persistent() },
                });
                let sv = revision.as_ref().map(|r| r.revision_id.clone()).unwrap_or_else(|| "ontology_unpublished".to_string());
                to_json(McpSuccessResponse::with_data(req_id, &conn, sv, "ontology_status", data))
            }
            "discover_ontology" => {
                let started = Instant::now();
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                let (mut objects, hidden) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let fingerprint = compute_schema_version(&objects);
                let mut warnings = Vec::new();
                if hidden > 0 {
                    warnings.push(format!("{hidden} restricted object(s) were excluded from discovery"));
                }
                let cap = self.config.ontology.max_discovery_objects;
                if objects.len() > cap {
                    warnings.push(format!("catalog has {} objects; discovery limited to the first {cap}", objects.len()));
                    objects.truncate(cap);
                }
                let infer = match args.get("infer_joins") {
                    None | Some(Value::Null) => self.config.ontology.infer_joins,
                    Some(v) => v.as_bool().ok_or_else(|| DbMcpError::InvalidArgument("'infer_joins' must be a boolean".to_string()))?,
                };
                let scope = db_mcp_ontology::DiscoveryScope {
                    tenant_id: self.config.ontology.tenant_id.clone(),
                    connection: conn.clone(),
                    engine: adapter.capabilities().engine,
                    schema_fingerprint: fingerprint.clone(),
                    principal: caller.principal.clone(),
                    sensitive_columns: cfg.sensitive_columns.clone(),
                    include_inferred_joins: infer,
                };
                let (candidates, report) = db_mcp_ontology::discover(&objects, &scope);
                let merge = self.ontology.merge_discovered(candidates)?;
                warnings.extend(report.warnings.iter().cloned());
                let mut resp = McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    fingerprint.clone(),
                    "ontology_discovery",
                    json!({
                        "connection": conn,
                        "schema_fingerprint": fingerprint,
                        "candidates": report.candidates,
                        "by_kind": report.by_kind,
                        "merge": merge,
                        "note": "Candidates are unverified (status=discovered). They cannot generate SQL until a reviewer certifies and publishes them (db-mcp ontology review / publish).",
                    }),
                );
                resp.warnings = warnings;
                resp.execution_time_ms = Some(started.elapsed().as_millis() as u64);
                to_json(resp)
            }
            "search_terms" => {
                let conn = req_str("connection")?;
                let query = req_str("query")?;
                self.authorize_conn(caller, &conn)?;
                if !self.adapters.contains_key(&conn) {
                    return Err(DbMcpError::ConnectionNotFound(format!("Unknown connection '{conn}'")));
                }
                let cfg = self.policy.effective_config(&conn);
                let kinds: Vec<DefinitionKind> = match args.get("kinds").and_then(|v| v.as_array()) {
                    Some(arr) => arr
                        .iter()
                        .map(|v| v.as_str().and_then(DefinitionKind::parse).ok_or_else(|| DbMcpError::InvalidArgument(format!("unknown kind {v}"))))
                        .collect::<DbMcpResult<_>>()?,
                    None => Vec::new(),
                };
                let statuses: Vec<DefinitionStatus> = match args.get("statuses").and_then(|v| v.as_array()) {
                    Some(arr) => arr
                        .iter()
                        .map(|v| v.as_str().and_then(DefinitionStatus::parse).ok_or_else(|| DbMcpError::InvalidArgument(format!("unknown status {v}"))))
                        .collect::<DbMcpResult<_>>()?,
                    None => Vec::new(),
                };
                let limit = arg_u64(args, "limit")?.unwrap_or(20).clamp(1, 100) as usize;
                let pool: Vec<Definition> = self
                    .ontology
                    .store
                    .latest_all(&self.config.ontology.tenant_id, &conn)?
                    .into_iter()
                    .filter(|d| !definition_touches_restricted(d, &cfg))
                    .filter(|d| kinds.is_empty() || kinds.contains(&d.kind))
                    .filter(|d| {
                        if statuses.is_empty() {
                            !matches!(d.status, DefinitionStatus::Rejected | DefinitionStatus::Deprecated)
                        } else {
                            statuses.contains(&d.status)
                        }
                    })
                    .collect();
                let results: Vec<Value> = db_mcp_ontology::rank(&query, &pool)
                    .into_iter()
                    .take(limit)
                    .map(|r| {
                        let mut v = definition_summary(&r.definition);
                        v["score"] = json!(r.score);
                        v["matched_terms"] = json!(r.matched_terms);
                        v["usable_for_sql"] = json!(r.definition.status == DefinitionStatus::Published);
                        v
                    })
                    .collect();
                to_json(McpSuccessResponse::with_data(req_id, &conn, "ontology_search", "ontology_terms", results))
            }
            "describe_term" => {
                let conn = req_str("connection")?;
                self.authorize_conn(caller, &conn)?;
                if !self.adapters.contains_key(&conn) {
                    return Err(DbMcpError::ConnectionNotFound(format!("Unknown connection '{conn}'")));
                }
                let cfg = self.policy.effective_config(&conn);
                let tenant = self.config.ontology.tenant_id.clone();
                let def_id = match (args.get("def_id").and_then(|v| v.as_str()), args.get("name").and_then(|v| v.as_str())) {
                    (Some(id), _) if !id.trim().is_empty() => id.trim().to_string(),
                    (_, Some(name)) if !name.trim().is_empty() => self
                        .ontology
                        .store
                        .latest_all(&tenant, &conn)?
                        .into_iter()
                        .find(|d| d.name.eq_ignore_ascii_case(name.trim()))
                        .map(|d| d.def_id)
                        .ok_or_else(|| DbMcpError::PolicyDenied {
                            code: "ONTOLOGY_UNKNOWN_OBJECT".to_string(),
                            message: format!("No definition named '{}'", name.trim()),
                            next_action: Some("search_terms".to_string()),
                        })?,
                    _ => return Err(DbMcpError::InvalidArgument("Provide 'def_id' or 'name'".to_string())),
                };
                let versions = self.ontology.store.versions(&tenant, &conn, &def_id)?;
                let Some(latest) = versions.last().cloned() else {
                    return Err(DbMcpError::PolicyDenied {
                        code: "ONTOLOGY_UNKNOWN_OBJECT".to_string(),
                        message: format!("Definition '{def_id}' does not exist on '{conn}'"),
                        next_action: Some("search_terms".to_string()),
                    });
                };
                if definition_touches_restricted(&latest, &cfg) {
                    return Err(DbMcpError::PolicyDenied {
                        code: "RESTRICTED_TABLE".to_string(),
                        message: format!("Definition '{def_id}' references a restricted table"),
                        next_action: None,
                    });
                }
                let certifications = self.ontology.store.certifications(&tenant, &conn, &def_id)?;
                let revision = self.ontology.store.latest_revision(&tenant, &conn)?;
                let in_revision = revision.as_ref().map(|r| versions.iter().any(|v| r.contains(v))).unwrap_or(false);
                let data = json!({
                    "definition": latest,
                    "versions": versions.iter().map(|v| json!({
                        "version": v.version,
                        "status": v.status,
                        "content_hash": v.content_hash,
                        "proposed_by": v.proposed_by,
                        "created_at": v.created_at,
                        "schema_fingerprint": v.schema_fingerprint,
                    })).collect::<Vec<_>>(),
                    "certifications": certifications.iter().map(|c| json!({
                        "version": c.version,
                        "action": c.action,
                        "reviewer": c.reviewer,
                        "reviewer_role": c.reviewer_role,
                        "at": c.at,
                        "expires_at": c.expires_at,
                        "reason": c.reason,
                        "signed": c.hmac.is_some(),
                    })).collect::<Vec<_>>(),
                    "in_published_revision": in_revision,
                    "revision_id": revision.map(|r| r.revision_id),
                });
                to_json(McpSuccessResponse::with_data(req_id, &conn, latest.content_hash.clone(), "ontology_definition", data))
            }
            "trace_semantic_relationships" => {
                let conn = req_str("connection")?;
                self.authorize_conn(caller, &conn)?;
                if !self.adapters.contains_key(&conn) {
                    return Err(DbMcpError::ConnectionNotFound(format!("Unknown connection '{conn}'")));
                }
                let cfg = self.policy.effective_config(&conn);
                let certified_only = args.get("certified_only").and_then(|v| v.as_bool()).unwrap_or(false);
                let max_depth = arg_u64(args, "max_depth")?.unwrap_or(3).clamp(1, 10) as usize;
                let rels: Vec<Definition> = self
                    .ontology
                    .store
                    .latest_all(&self.config.ontology.tenant_id, &conn)?
                    .into_iter()
                    .filter(|d| d.kind == DefinitionKind::Relationship)
                    .filter(|d| !definition_touches_restricted(d, &cfg))
                    .filter(|d| !matches!(d.status, DefinitionStatus::Rejected | DefinitionStatus::Deprecated))
                    .filter(|d| !certified_only || matches!(d.status, DefinitionStatus::Published | DefinitionStatus::Certified))
                    .collect();
                let key = |t: &str| t.to_ascii_lowercase();
                let mut keep: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
                if let Some(entity) = args.get("entity").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
                    let start: Vec<String> = rels
                        .iter()
                        .flat_map(|d| d.body.tables())
                        .filter(|t| key(t) == key(entity) || db_mcp_ontology::base_table_name(t) == key(entity))
                        .map(|t| key(&t))
                        .collect();
                    let Some(first) = start.first().cloned() else {
                        return Err(DbMcpError::PolicyDenied {
                            code: "ONTOLOGY_UNKNOWN_OBJECT".to_string(),
                            message: format!("No relationship touches '{entity}'"),
                            next_action: Some("discover_ontology".to_string()),
                        });
                    };
                    let mut frontier = vec![first.clone()];
                    keep.insert(first);
                    for _ in 0..max_depth {
                        let mut next = Vec::new();
                        for d in &rels {
                            let ts: Vec<String> = d.body.tables().iter().map(|t| key(t)).collect();
                            if ts.iter().any(|t| frontier.contains(t)) {
                                for t in ts {
                                    if keep.insert(t.clone()) {
                                        next.push(t);
                                    }
                                }
                            }
                        }
                        frontier = next;
                    }
                }
                let edges: Vec<Value> = rels
                    .iter()
                    .filter(|d| keep.is_empty() || d.body.tables().iter().all(|t| keep.contains(&key(t))))
                    .filter_map(|d| match &d.body {
                        DefinitionBody::Relationship { from_table, to_table, column_pairs, cardinality, source } => Some(json!({
                            "def_id": d.def_id,
                            "version": d.version,
                            "name": d.name,
                            "from": from_table,
                            "to": to_table,
                            "column_pairs": column_pairs,
                            "cardinality": cardinality,
                            "source": source,
                            "status": d.status,
                            "strength": d.strength,
                            "usable_for_sql": d.status == DefinitionStatus::Published,
                        })),
                        _ => None,
                    })
                    .collect();
                let mut mermaid = String::from("flowchart LR\n");
                for e in &edges {
                    let id = |t: &str| db_mcp_ontology::slug(t);
                    let from = e["from"].as_str().unwrap_or_default();
                    let to = e["to"].as_str().unwrap_or_default();
                    let arrow = if e["usable_for_sql"].as_bool() == Some(true) { "-->" } else { "-.->" };
                    mermaid.push_str(&format!(
                        "    {}[\"{}\"] {}|{}| {}[\"{}\"]\n",
                        id(from), from, arrow, e["status"].as_str().unwrap_or_default(), id(to), to
                    ));
                }
                to_json(McpSuccessResponse::with_data(
                    req_id,
                    &conn,
                    "ontology_relationships",
                    "ontology_relationships",
                    json!({ "edges": edges, "mermaid_diagram": mermaid, "legend": "solid = published (usable for SQL), dashed = candidate/certified-not-published" }),
                ))
            }
            "propose_semantic_definition" => {
                let conn = req_str("connection")?;
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let cfg = self.policy.effective_config(&conn);
                let draft = args
                    .get("definition")
                    .cloned()
                    .ok_or_else(|| DbMcpError::InvalidArgument("Missing required parameter 'definition'".to_string()))?;
                let mut input: ProposalInput = serde_json::from_value(draft)
                    .map_err(|e| DbMcpError::InvalidArgument(format!("invalid definition: {e}")))?;
                if let Some(id) = args.get("def_id").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                    input.def_id = Some(id.trim().to_string());
                }
                if let Some(v) = arg_u64(args, "expected_version")? {
                    input.expected_version = Some(v as u32);
                }
                let (objects, _) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let fingerprint = compute_schema_version(&objects);
                let def = self.ontology.propose(caller, &conn, input, &objects, &cfg.sensitive_columns, &fingerprint)?;
                let next = format!(
                    "A reviewer (admin/dba, not '{}') must certify it: db-mcp ontology review --connection {} --def-id {} --version {} --action approve --reviewer <name> --config <file>; then publish.",
                    def.proposed_by, conn, def.def_id, def.version
                );
                let mut resp = McpSuccessResponse::with_data(req_id, &conn, def.content_hash.clone(), "ontology_proposal", json!({ "definition": def, "next_action": next }));
                resp.warnings.push("Proposals are drafts: they are not used for SQL until certified and published.".to_string());
                to_json(resp)
            }
            "plan_semantic_query" => {
                let started = Instant::now();
                let conn = req_str("connection")?;
                let question = req_str("question")?;
                let max_rows = arg_u64(args, "max_rows")?.map(|v| v as usize);
                let plan = self.plan_question(caller, &conn, &question, max_rows).await?;
                let sv = plan.revision_id.clone().unwrap_or_else(|| "ontology_unpublished".to_string());
                let mut resp = McpSuccessResponse::with_data(req_id, &conn, sv, "ontology_plan", &plan);
                resp.warnings = plan.limitations.clone();
                if !plan.is_answerable() {
                    resp.warnings.extend(plan.missing.iter().cloned());
                }
                resp.execution_time_ms = Some(started.elapsed().as_millis() as u64);
                to_json(resp)
            }
            "ask_semantic_question" => {
                let started = Instant::now();
                let conn = req_str("connection")?;
                let question = req_str("question")?;
                let max_rows = arg_u64(args, "max_rows")?.map(|v| v as usize);
                let adapter = self.get_authorized_adapter(caller, &conn)?;
                let plan = self.plan_question(caller, &conn, &question, max_rows).await?;
                if let Some(pinned) = args.get("plan_hash").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()) {
                    if plan.plan_hash.as_deref() != Some(pinned.trim()) {
                        return Err(DbMcpError::PolicyDenied {
                            code: "ONTOLOGY_PLAN_MISMATCH".to_string(),
                            message: "The recomputed plan differs from the pinned plan_hash (schema, ontology revision or question changed)".to_string(),
                            next_action: Some("Call plan_semantic_query again and review the new plan".to_string()),
                        });
                    }
                }
                let sv = plan.revision_id.clone().unwrap_or_else(|| "ontology_unpublished".to_string());
                if !plan.is_answerable() {
                    let mut resp = McpSuccessResponse::with_data(req_id, &conn, sv, "ontology_answer", json!({ "answered": false, "plan": plan }));
                    resp.warnings = plan.missing.clone();
                    resp.execution_time_ms = Some(started.elapsed().as_millis() as u64);
                    return to_json(resp);
                }
                let sql = plan.sql.clone().unwrap_or_default();
                let metric_id = plan.metric.as_ref().map(|m| m.def_id.clone()).unwrap_or_default();
                let gov_req = GovernedQueryRequest::new(req_id, &conn, caller.clone(), sql)
                    .with_tool_name(format!("ask_semantic_question:{metric_id}"))
                    .with_params(plan.params.clone())
                    .with_max_rows(max_rows.unwrap_or(self.config.ontology.default_max_rows).min(self.config.ontology.default_max_rows.max(1)));
                let result = self.executor.execute_governed(adapter.as_ref(), gov_req).await?;
                let mut resp = McpSuccessResponse::from_query_result(req_id, &conn, result, Some(sv));
                resp.warnings.extend(plan.limitations.iter().cloned());
                resp.data = Some(json!({ "answered": true, "plan": plan }));
                to_json(resp)
            }
            other => Err(DbMcpError::InvalidArgument(format!("Unknown tool '{other}'"))),
        }
    }

    pub async fn handle_jsonrpc(
        &self,
        request: JsonRpcRequest,
        caller: &CallerIdentity,
    ) -> JsonRpcResponse {
        let id = request.id.clone();
        match request.method.as_str() {
            "initialize" => JsonRpcResponse::ok(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": self.config.server_name,
                        "version": self.config.server_version
                    }
                }),
            ),
            "notifications/initialized" | "ping" => JsonRpcResponse::ok(id, json!({})),
            "tools/list" => JsonRpcResponse::ok(id, json!({ "tools": self.list_tools() })),
            "tools/call" => {
                let params = request.params.unwrap_or_else(|| json!({}));
                let Some(name) = params
                    .get("name")
                    .or_else(|| params.get("tool_name"))
                    .and_then(|v| v.as_str())
                else {
                    return JsonRpcResponse::err(id, -32602, "Missing tool 'name' in tools/call params", None);
                };
                let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let payload = self.call_tool(name, arguments, caller).await;
                let is_error = payload.get("status").and_then(|v| v.as_str()) == Some("denied");
                let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
                JsonRpcResponse::ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "structuredContent": payload,
                        "isError": is_error
                    }),
                )
            }
            "resources/list" => JsonRpcResponse::ok(id, json!({ "resources": [] })),
            "prompts/list" => JsonRpcResponse::ok(id, json!({ "prompts": [] })),
            "notifications/cancelled" | "cancel" => {
                let req_id = request
                    .params
                    .as_ref()
                    .and_then(|p| p.get("requestId").or_else(|| p.get("request_id")))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let cancelled = self.executor.cancel_by_request_id(req_id);
                JsonRpcResponse::ok(id, json!({ "cancelled": cancelled }))
            }
            other => JsonRpcResponse::err(id, -32601, format!("Method '{other}' not found"), None),
        }
    }

    pub async fn handle_jsonrpc_str(&self, raw_json: &str, caller: &CallerIdentity) -> String {
        self.handle_jsonrpc_line(raw_json, caller).await.unwrap_or_default()
    }

    /// Handle one raw JSON-RPC message. Returns `None` for notifications (no reply allowed).
    ///
    /// Invalid JSON -> `-32700`; valid JSON that is not a request object (array batch, missing or
    /// non-string `method`, bad `id` type) -> `-32600` with the id echoed when available.
    pub async fn handle_jsonrpc_line(&self, raw_json: &str, caller: &CallerIdentity) -> Option<String> {
        let resp = match serde_json::from_str::<Value>(raw_json) {
            Err(e) => JsonRpcResponse::err(None, -32700, format!("Parse error: {e}"), None),
            Ok(Value::Object(map)) => {
                let has_id = map.contains_key("id");
                let id = map.get("id").cloned();
                let id_ok = matches!(id, None | Some(Value::Null) | Some(Value::String(_)) | Some(Value::Number(_)));
                let echo_id = if id_ok { id.clone() } else { None };
                if !id_ok || !map.get("method").map(Value::is_string).unwrap_or(false) {
                    JsonRpcResponse::err(
                        echo_id,
                        -32600,
                        "Invalid Request: expected a JSON-RPC request object with a string 'method'",
                        None,
                    )
                } else {
                    match serde_json::from_value::<JsonRpcRequest>(Value::Object(map)) {
                        Ok(req) => {
                            let resp = self.handle_jsonrpc(req, caller).await;
                            if !has_id {
                                return None;
                            }
                            resp
                        }
                        Err(e) => JsonRpcResponse::err(echo_id, -32600, format!("Invalid Request: {e}"), None),
                    }
                }
            }
            Ok(_) => JsonRpcResponse::err(
                None,
                -32600,
                "Invalid Request: batch arrays and non-object messages are not supported",
                None,
            ),
        };
        Some(serde_json::to_string(&resp).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
                .to_string()
        }))
    }
}

/// Shareable MCP JSON-RPC protocol handler wrapping `Arc<DbMcpRuntime>`.
#[derive(Clone)]
pub struct McpProtocolHandler {
    inner: Arc<DbMcpRuntime>,
}

impl McpProtocolHandler {
    pub fn new(runtime: Arc<DbMcpRuntime>) -> Self {
        Self { inner: runtime }
    }

    pub fn from_config(config: ServerConfig) -> DbMcpResult<Self> {
        Ok(Self::new(Arc::new(DbMcpRuntime::from_config(config)?)))
    }

    pub fn default_demo() -> DbMcpResult<Self> {
        Ok(Self::new(Arc::new(DbMcpRuntime::default_demo()?)))
    }
}

impl Deref for McpProtocolHandler {
    type Target = DbMcpRuntime;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn parse_detail_level(val: Option<&Value>, default: CatalogDetailLevel) -> DbMcpResult<CatalogDetailLevel> {
    match val {
        None | Some(Value::Null) => Ok(default),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "names" => Ok(CatalogDetailLevel::Names),
            "summary" => Ok(CatalogDetailLevel::Summary),
            "full" => Ok(CatalogDetailLevel::Full),
            other => Err(DbMcpError::InvalidArgument(format!(
                "'detail_level' must be one of names|summary|full (got '{other}')"
            ))),
        },
        Some(_) => Err(DbMcpError::InvalidArgument(
            "'detail_level' must be one of names|summary|full".to_string(),
        )),
    }
}

fn parse_object_types(val: Option<&Value>) -> DbMcpResult<Vec<CatalogObjectType>> {
    match val {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| {
                        DbMcpError::InvalidArgument("'object_types' must be an array of strings".to_string())
                    })
                    .and_then(|s| s.parse::<CatalogObjectType>())
            })
            .collect(),
        Some(_) => Err(DbMcpError::InvalidArgument(
            "'object_types' must be an array of strings".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_toml_parses_and_validates() {
        let toml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/db-mcp.example.toml");
        let cfg = ServerConfig::from_file(&toml_path).expect("example config should parse");
        assert_eq!(cfg.server_name, "db-mcp");
        assert_eq!(cfg.connections.len(), 3);
        assert_eq!(cfg.named_tools.len(), 2);
    }

    #[tokio::test]
    async fn tools_list_returns_all_24_tools_in_demo() {
        let handler = McpProtocolHandler::default_demo().expect("demo handler");
        let caller = CallerIdentity::local_agent("local-agent");
        let resp = handler
            .handle_jsonrpc(
                JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    id: Some(json!(1)),
                    method: "tools/list".to_string(),
                    params: None,
                },
                &caller,
            )
            .await;
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 24);

        let dep = handler
            .call_tool(
                "trace_table_dependencies",
                json!({
                    "connection": "prod-postgres",
                    "table_name": "users",
                    "target_table": "order_items",
                    "max_depth": 3
                }),
                &caller,
            )
            .await;
        assert_eq!(dep["status"], "ok");
        assert_eq!(dep["_meta"]["provenance"]["untrusted_content"], true);
        assert_eq!(dep["data"]["join_path"]["hops"].as_array().unwrap().len(), 2);
        assert!(dep["data"]["mermaid_diagram"]
            .as_str()
            .unwrap()
            .contains("flowchart LR"));

        let cg = handler
            .call_tool(
                "get_procedure_call_graph",
                json!({
                    "connection": "prod-postgres",
                    "procedure_name": "checkout_order",
                    "direction": "callees",
                    "max_depth": 5
                }),
                &caller,
            )
            .await;
        assert_eq!(cg["status"], "ok");
        assert_eq!(cg["_meta"]["provenance"]["untrusted_content"], true);
        assert!(cg["data"]["nodes"].as_array().unwrap().len() >= 3);
        assert!(cg["data"]["mermaid_diagram"]
            .as_str()
            .unwrap()
            .contains("flowchart TD"));
    }

    #[tokio::test]
    async fn execute_query_and_named_tool_work_with_redaction() {
        let handler = McpProtocolHandler::default_demo().expect("demo handler");
        let caller = CallerIdentity::local_agent("local-agent");

        let q = handler
            .call_tool(
                "execute_query",
                json!({
                    "connection": "local-sqlite",
                    "sql": "SELECT id, email, password_hash FROM users WHERE id = 1"
                }),
                &caller,
            )
            .await;
        assert_eq!(q["status"], "ok");
        assert_eq!(q["rows"][0][2], "[REDACTED]");

        let nt = handler
            .call_tool(
                "run_named_tool",
                json!({
                    "tool_name": "get_user_by_id",
                    "arguments": { "user_id": 1 }
                }),
                &caller,
            )
            .await;
        assert_eq!(nt["status"], "ok");
        assert_eq!(nt["returned_rows"], 1);
    }

    #[tokio::test]
    async fn governed_production_blocks_direct_write_and_allows_approved_change() {
        let handler = McpProtocolHandler::default_demo().expect("demo handler");
        let agent = CallerIdentity::local_agent("local-agent");
        let admin = CallerIdentity::admin("dba-approver");

        let denied = handler
            .call_tool(
                "execute_query",
                json!({
                    "connection": "prod-postgres",
                    "sql": "UPDATE orders SET status = 'shipped' WHERE id = 102"
                }),
                &agent,
            )
            .await;
        assert_eq!(denied["status"], "denied");

        let prop = handler
            .call_tool(
                "propose_change",
                json!({
                    "connection": "prod-postgres",
                    "sql": "UPDATE orders SET status = 'shipped' WHERE id = 102"
                }),
                &agent,
            )
            .await;
        assert_eq!(prop["status"], "ok");
        let change_id = prop["data"]["change_id"].as_str().unwrap().to_string();

        let self_approve = handler.approve_change(&change_id, &agent, None);
        assert!(self_approve.is_err());

        handler
            .approve_change(&change_id, &admin, Some("Approved for rollout".to_string()))
            .expect("admin approval should succeed");

        let applied = handler
            .call_tool("apply_change", json!({ "change_id": change_id }), &agent)
            .await;
        assert_eq!(applied["status"], "ok");
        assert_eq!(applied["data"]["state"], "applied");
        assert!(!handler.audit_events().unwrap().is_empty());
    }
}
