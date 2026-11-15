//! MCP JSON-RPC 2.0 protocol handler, tool profile registry, and governed runtime.

pub mod config;
pub mod schemas;

pub use config::{AuditConfig, ChangeStoreConfig, ConnectionConfig, HttpServerConfig, ServerConfig};
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
                let list: Vec<ConnectionSummary> = self
                    .summaries
                    .values()
                    .filter(|c| self.policy.authorize_connection(caller, &c.id).is_allowed())
                    .cloned()
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
                let detail_level = parse_detail_level(args.get("detail_level"), CatalogDetailLevel::Summary);
                let object_types = parse_object_types(args.get("object_types"));
                let _ = &cfg;
                // Restricted objects are removed BEFORE filtering/pagination so totals never leak them.
                let (visible, _hidden) = self.discover_allowed(adapter.as_ref(), &conn, None).await?;
                let request = CatalogRequest {
                    connection: conn.clone(),
                    schema_pattern: args.get("schema_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned),
                    name_pattern: args.get("name_pattern").and_then(|v| v.as_str()).map(ToOwned::to_owned),
                    object_types,
                    detail_level,
                    limit: args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize,
                    offset: args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
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
                let detail_level = parse_detail_level(args.get("detail_level"), CatalogDetailLevel::Full);
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
                let max_depth = args
                    .get("max_depth")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3) as usize;
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
                let max_depth = args
                    .get("max_depth")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(5) as usize;
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
                let args_map: BTreeMap<String, Value> = args
                    .get("arguments")
                    .and_then(|v| v.as_object())
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default();
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
                let _adapter = self.get_authorized_adapter(caller, &conn)?;
                let report = self.pg_insights.database_health(&conn).await?;
                let mut val = to_json(PgInsightsEngine::health_report_to_response(
                    req_id,
                    "snapshot_health",
                    &report,
                ))?;
                scrub_restricted(&mut val, &self.policy.effective_config(&conn));
                Ok(val)
            }
            "analyze_workload" => {
                let conn = req_str("connection")?;
                let _adapter = self.get_authorized_adapter(caller, &conn)?;
                let top_n = args.get("top_n").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
                let workload = self.pg_insights.analyze_workload(&conn, top_n).await?;
                let mut val = to_json(PgInsightsEngine::workload_to_response(
                    req_id,
                    "snapshot_workload",
                    &workload,
                ))?;
                scrub_restricted(&mut val, &self.policy.effective_config(&conn));
                Ok(val)
            }
            "recommend_indexes" => {
                let conn = req_str("connection")?;
                let _adapter = self.get_authorized_adapter(caller, &conn)?;
                let queries: Vec<String> = args
                    .get("queries")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
                    .unwrap_or_default();
                let max_recs = args.get("max_recommendations").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
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
        let resp = match serde_json::from_str::<JsonRpcRequest>(raw_json) {
            Ok(req) => self.handle_jsonrpc(req, caller).await,
            Err(e) => JsonRpcResponse::err(None, -32700, format!("Parse error: {e}"), None),
        };
        serde_json::to_string(&resp).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
                .to_string()
        })
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

fn parse_detail_level(val: Option<&Value>, default: CatalogDetailLevel) -> CatalogDetailLevel {
    match val.and_then(|v| v.as_str()) {
        Some("names") => CatalogDetailLevel::Names,
        Some("summary") => CatalogDetailLevel::Summary,
        Some("full") => CatalogDetailLevel::Full,
        _ => default,
    }
}

fn parse_object_types(val: Option<&Value>) -> Vec<CatalogObjectType> {
    val.and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| match item.as_str()?.to_ascii_lowercase().as_str() {
                    "table" => Some(CatalogObjectType::Table),
                    "view" => Some(CatalogObjectType::View),
                    "materialized_view" => Some(CatalogObjectType::MaterializedView),
                    "index" => Some(CatalogObjectType::Index),
                    "sequence" => Some(CatalogObjectType::Sequence),
                    "function" => Some(CatalogObjectType::Function),
                    "procedure" => Some(CatalogObjectType::Procedure),
                    "trigger" => Some(CatalogObjectType::Trigger),
                    "schema" => Some(CatalogObjectType::Schema),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
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
    async fn tools_list_returns_all_16_tools_in_demo() {
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
        assert_eq!(tools.len(), 16);

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
