//! DB-MCP server binary entrypoint supporting stdio, Streamable HTTP, and out-of-band admin approvals.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use db_mcp_core::CallerIdentity;
use db_mcp_mcp::{JsonRpcRequest, McpProtocolHandler, ServerConfig};
use db_mcp_secrets::{CompositeSecretProvider, SecretProvider, StaticSecretProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Parser)]
#[command(
    name = "db-mcp-server",
    version,
    about = "Self-hosted Rust database MCP server with bounded SQL execution and change governance"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the MCP server over stdio or Streamable HTTP transport.
    Serve {
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[arg(long)]
        bind: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "local-agent")]
        principal: String,
        #[arg(long, default_value = "agent")]
        role: String,
    },
    /// Out-of-band approval for a pending `chg_*` change proposal.
    Approve {
        #[arg(long)]
        change_id: String,
        #[arg(long)]
        approver: String,
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Validate a `ServerConfig` file (TOML, YAML, or JSON).
    VerifyConfig {
        #[arg(long)]
        config: PathBuf,
        /// Also run the read-only `check-connection` smoke test against every connection.
        #[arg(long)]
        live: bool,
    },
    /// Read-only smoke test of configured connections: connect, server version, permissions,
    /// `SELECT 1`, catalog object count, and a warning when the account can write.
    /// Prints JSON; exits non-zero when a connection cannot be reached.
    CheckConnection {
        #[arg(long)]
        config: PathBuf,
        /// Only check this connection id (default: every connection).
        #[arg(long)]
        connection: Option<String>,
    },
    /// Verify the hash chains of the configured JSONL and SQLite audit trails (non-zero exit on tamper).
    VerifyAudit {
        #[arg(long)]
        config: PathBuf,
    },
    /// Out-of-band ontology governance (admin channel; never exposed to agents over MCP).
    Ontology {
        #[command(subcommand)]
        command: OntologyCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OntologyCommand {
    /// List the latest version of every definition on a connection.
    List {
        #[arg(long)]
        connection: String,
        /// Filter by status (discovered, proposed, certified, published, stale, ...).
        #[arg(long)]
        status: Option<String>,
        /// Filter by kind (entity, attribute, relationship, metric, filter).
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        config: PathBuf,
    },
    /// Show every version, certification and evidence of one definition.
    Show {
        #[arg(long)]
        connection: String,
        #[arg(long)]
        def_id: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Approve (certify), reject or deprecate one exact definition version.
    Review {
        #[arg(long)]
        connection: String,
        #[arg(long)]
        def_id: String,
        #[arg(long)]
        version: u32,
        /// approve | reject | deprecate
        #[arg(long)]
        action: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        config: PathBuf,
    },
    /// Publish all certified definitions of a connection as a new pinned revision.
    Publish {
        #[arg(long)]
        connection: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long, default_value = "admin")]
        role: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a golden question set against the published ontology and enforce quality gates.
    Eval {
        #[arg(long)]
        connection: String,
        /// JSON array of golden cases ({id, question, expect:{status, metric?, dimensions?, ...}}).
        #[arg(long)]
        cases: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Clone)]
pub struct HttpAppState {
    pub handler: McpProtocolHandler,
    pub default_caller: CallerIdentity,
    pub expected_auth_token: Option<String>,
    pub expected_admin_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminApprovePayload {
    pub change_id: String,
    pub approver: String,
    #[serde(default = "default_admin_role")]
    pub role: String,
    #[serde(default)]
    pub comment: Option<String>,
}

fn default_admin_role() -> String {
    "admin".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminOntologyReviewPayload {
    pub connection: String,
    pub def_id: String,
    pub version: u32,
    pub action: String,
    pub reviewer: String,
    #[serde(default = "default_admin_role")]
    pub role: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminOntologyPublishPayload {
    pub connection: String,
    pub reviewer: String,
    #[serde(default = "default_admin_role")]
    pub role: String,
}

fn denied_json(err: &db_mcp_core::DbMcpError) -> serde_json::Value {
    serde_json::to_value(err.to_denied_response(None, None)).unwrap_or_else(|_| json!({"status": "denied"}))
}

/// Open the ontology store for the admin CLI; review requires a persistent store.
fn cli_ontology_service(cfg: &ServerConfig, connection: &str) -> anyhow::Result<db_mcp_ontology::OntologyService> {
    if !cfg.connections.iter().any(|c| c.id == connection) {
        anyhow::bail!("Unknown connection '{connection}' in configuration");
    }
    if cfg.ontology.storage_path.as_deref().map(str::trim).unwrap_or("").is_empty() {
        anyhow::bail!(
            "ontology.storage_path is not set: the server keeps the ontology in memory, so an out-of-band review would have no effect. Configure a persistent [ontology] storage_path."
        );
    }
    Ok(db_mcp_mcp::build_ontology_service(cfg)?)
}

fn load_server_config(path: Option<&PathBuf>) -> anyhow::Result<ServerConfig> {
    match path {
        Some(p) => Ok(ServerConfig::from_file(p)?),
        None => Ok(ServerConfig::default_demo()),
    }
}

fn resolve_optional_token(raw: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(token_ref) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let secrets = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
    // Fail closed: a configured token reference that cannot be resolved must never
    // silently disable authentication.
    let sec = secrets.resolve_dsn(token_ref).map_err(|e| {
        anyhow::anyhow!(
            "HTTP token reference '{token_ref}' could not be resolved ({e}); set the variable or remove the setting"
        )
    })?;
    Ok(Some(sec.expose_secret().to_string()))
}

fn check_bearer(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(exp) = expected else {
        return true;
    };
    let Some(header_val) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    header_val
        .strip_prefix("Bearer ")
        .or_else(|| header_val.strip_prefix("bearer "))
        .map(|tok| tok.trim() == exp)
        .unwrap_or(false)
}

/// Guard for `/admin/*` endpoints: they fail closed when no admin token is configured.
fn admin_guard(
    headers: &HeaderMap,
    expected: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if expected.is_none() {
        return Some((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "denied",
                "code": "ADMIN_TOKEN_NOT_CONFIGURED",
                "message": "Admin endpoints are disabled until http.admin_token is configured",
                "next_action": "Set http.admin_token (e.g. env:DB_MCP_ADMIN_TOKEN) or use the db-mcp CLI"
            })),
        ));
    }
    if !check_bearer(headers, expected) {
        return Some((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "denied", "code": "UNAUTHORIZED", "message": "Invalid admin token" })),
        ));
    }
    None
}

/// Record an out-of-band admin action (CLI) in the configured audit trail.
#[allow(clippy::too_many_arguments)]
fn audit_admin_action(
    cfg: &ServerConfig,
    caller: &CallerIdentity,
    connection: &str,
    tool_name: &str,
    subject_id: Option<String>,
    outcome: Result<(), &db_mcp_core::DbMcpError>,
) {
    let Ok(sink) = db_mcp_audit::build_audit_sink(
        false,
        cfg.audit.jsonl_path.as_deref(),
        cfg.audit.sqlite_path.as_deref(),
    ) else {
        return;
    };
    let (decision, code, msg) = match outcome {
        Ok(()) => (db_mcp_core::AuditDecision::Allowed, None, None),
        Err(e) => (
            db_mcp_core::AuditDecision::Denied,
            Some(e.code().to_string()),
            Some(e.to_string()),
        ),
    };
    let req_id = format!("req_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let _ = sink.record(db_mcp_audit::create_audit_event(
        req_id,
        caller,
        connection,
        cfg.default_mode,
        tool_name,
        None,
        None,
        None,
        decision,
        code,
        subject_id,
        None,
        None,
        None,
        None,
        msg,
    ));
}

fn extract_http_caller(headers: &HeaderMap, default_caller: &CallerIdentity) -> CallerIdentity {
    let principal = headers
        .get("x-mcp-principal")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_caller.principal);
    let role = headers
        .get("x-mcp-role")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_caller.role);
    CallerIdentity::new(principal, role, vec!["*".to_string()], "http")
}

pub fn build_http_router(state: HttpAppState) -> Router {
    Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/admin/approve", post(handle_admin_approve))
        .route("/admin/ontology/review", post(handle_admin_ontology_review))
        .route("/admin/ontology/publish", post(handle_admin_ontology_publish))
        .with_state(Arc::new(state))
}

async fn handle_health(State(state): State<Arc<HttpAppState>>) -> impl IntoResponse {
    let cfg = state.handler.config();
    Json(json!({
        "status": "ok",
        "server_name": cfg.server_name,
        "server_version": cfg.server_version,
        "connections": cfg.connections.len(),
        "tools": state.handler.list_tools().len()
    }))
}

async fn handle_metrics(State(state): State<Arc<HttpAppState>>) -> impl IntoResponse {
    let audit_count = state
        .handler
        .audit_events()
        .map(|e| e.len())
        .unwrap_or(0);
    Json(json!({
        "status": "ok",
        "audit_events_total": audit_count,
        "registered_tools": state.handler.list_tools().len(),
        "configured_connections": state.handler.config().connections.len()
    }))
}

async fn handle_mcp_post(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    if !check_bearer(&headers, state.expected_auth_token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": { "code": -32001, "message": "Unauthorized: invalid or missing Bearer token" }
            })),
        )
            .into_response();
    }
    let caller = extract_http_caller(&headers, &state.default_caller);
    let is_notification = req.id.is_none();
    let resp = state.handler.handle_jsonrpc(req, &caller).await;
    if is_notification {
        return StatusCode::ACCEPTED.into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::to_value(resp).unwrap_or_else(|_| json!({}))),
    )
        .into_response()
}

async fn handle_admin_approve(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(payload): Json<AdminApprovePayload>,
) -> impl IntoResponse {
    if let Some(rejection) = admin_guard(&headers, state.expected_admin_token.as_deref()) {
        return rejection;
    }
    let approver = CallerIdentity::new(&payload.approver, &payload.role, vec!["*".to_string()], "http-admin");
    match state
        .handler
        .approve_change(&payload.change_id, &approver, payload.comment)
    {
        Ok(proposal) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "proposal": proposal, "warnings": state.handler.approval_warnings() })),
        ),
        Err(err) => {
            let denied = err.to_denied_response(None, None);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::to_value(denied).unwrap_or_else(|_| json!({"status": "denied"}))),
            )
        }
    }
}

async fn handle_admin_ontology_review(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(payload): Json<AdminOntologyReviewPayload>,
) -> impl IntoResponse {
    if let Some(rejection) = admin_guard(&headers, state.expected_admin_token.as_deref()) {
        return rejection;
    }
    let Some(action) = db_mcp_ontology::ReviewAction::parse(&payload.action) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "denied", "code": "INVALID_ARGUMENT", "message": "action must be approve, reject or deprecate"})),
        );
    };
    let reviewer = CallerIdentity::new(&payload.reviewer, &payload.role, vec!["*".to_string()], "http-admin");
    match state.handler.review_ontology(
        &reviewer,
        &payload.connection,
        &payload.def_id,
        payload.version,
        action,
        payload.reason,
    ) {
        Ok((definition, certification)) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "definition": definition, "certification": certification})),
        ),
        Err(err) => (StatusCode::BAD_REQUEST, Json(denied_json(&err))),
    }
}

async fn handle_admin_ontology_publish(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(payload): Json<AdminOntologyPublishPayload>,
) -> impl IntoResponse {
    if let Some(rejection) = admin_guard(&headers, state.expected_admin_token.as_deref()) {
        return rejection;
    }
    let reviewer = CallerIdentity::new(&payload.reviewer, &payload.role, vec!["*".to_string()], "http-admin");
    match state.handler.publish_ontology(&reviewer, &payload.connection).await {
        Ok(revision) => (StatusCode::OK, Json(json!({"status": "ok", "revision": revision}))),
        Err(err) => (StatusCode::BAD_REQUEST, Json(denied_json(&err))),
    }
}

/// Verify the hash chain of every configured durable audit store.
/// Returns `(all_valid, per-store JSON results)`; a missing store file counts as valid (empty).
fn verify_audit_stores(cfg: &ServerConfig) -> (bool, Vec<Value>) {
    let mut results = Vec::new();
    let mut all_ok = true;
    let mut push = |store: &str, path: &str, verdict: db_mcp_core::DbMcpResult<bool>| {
        let (ok, err) = match verdict {
            Ok(v) => (v, None),
            Err(e) => (false, Some(e.to_string())),
        };
        all_ok &= ok;
        results.push(json!({ "store": store, "path": path, "chain_valid": ok, "error": err }));
    };
    if let Some(p) = cfg.audit.jsonl_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let v = if std::path::Path::new(p).exists() {
            db_mcp_audit::JsonlAuditStore::new(p).and_then(|st| st.verify_chain())
        } else {
            Ok(true)
        };
        push("jsonl", p, v);
    }
    if let Some(p) = cfg.audit.sqlite_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let v = if std::path::Path::new(p).exists() {
            db_mcp_audit::SqliteAuditStore::open(p).and_then(|st| st.verify_chain())
        } else {
            Ok(true)
        };
        push("sqlite", p, v);
    }
    (all_ok, results)
}

/// Base `check-connection` report: `{connection, engine, backend, server_version, can_connect,
/// select_1, object_count, permissions[], can_write, warnings[]}`.
fn base_check_report(conn: &db_mcp_mcp::ConnectionConfig, backend: &str) -> Value {
    json!({
        "connection": conn.id,
        "engine": conn.engine.as_str(),
        "backend": backend,
        "server_version": Value::Null,
        "can_connect": false,
        "select_1": false,
        "object_count": Value::Null,
        "permissions": [],
        "can_write": false,
        "warnings": [],
    })
}

async fn check_sqlserver_connection(conn: &db_mcp_mcp::ConnectionConfig, mut report: Value) -> (Value, bool) {
    let secrets = db_mcp_secrets::CompositeSecretProvider::with_static_and_env(db_mcp_secrets::StaticSecretProvider::new());
    let adapter = match conn
        .resolve_dsn(&secrets)
        .and_then(|dsn| db_mcp_sqlserver::SqlServerAdapter::new(db_mcp_sqlserver::SqlServerConfig::new(&conn.id, dsn)))
    {
        Ok(a) => a,
        Err(e) => {
            report["warnings"] = json!([db_mcp_secrets::redact_sensitive_text(&e.to_string())]);
            report["error_code"] = json!(e.code());
            return (report, false);
        }
    };
    let c = adapter.check_connection().await;
    report["target"] = json!(c.target);
    report["server_version"] = json!(c.server_version);
    report["database"] = json!(c.database);
    report["login"] = json!(c.login);
    report["can_connect"] = json!(c.can_connect);
    report["select_1"] = json!(c.select_1);
    report["object_count"] = json!(c.object_count);
    report["permissions"] = json!(c.permissions);
    report["can_write"] = json!(c.can_write);
    report["warnings"] = json!(c.warnings);
    if let Some(code) = &c.error_code {
        report["error_code"] = json!(code);
        report["next_action"] = json!("check host, port, instance, login and password (env:/file: DSN reference), then retry");
    }
    (report, c.can_connect && c.select_1)
}

async fn run_stdio_loop(handler: McpProtocolHandler, caller: CallerIdentity) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        // Read raw bytes so an invalid UTF-8 line cannot abort the loop; stop only on EOF.
        if reader.read_until(b'\n', &mut buf).await? == 0 {
            break;
        }
        let response_json = match std::str::from_utf8(&buf) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match handler.handle_jsonrpc_line(trimmed, &caller).await {
                    Some(r) => r,
                    None => continue,
                }
            }
            Err(e) => serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32700, "message": format!("Parse error: invalid UTF-8: {e}") }
            }))?,
        };
        stdout.write_all(response_json.as_bytes()).await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

/// Stack size for the thread that drives the async runtime and for every Tokio worker thread.
///
/// SQL parsing (`sqlparser`) and the lineage / call-graph analyzers recurse deeply, and the large
/// `tools/call` state machine lives on the stack of whichever thread polls it. Windows gives the
/// main thread only 1 MiB (Linux: 8 MiB), which overflows on `trace_table_dependencies`; running
/// everything on explicitly sized threads makes behaviour identical across platforms.
const RUNTIME_STACK_SIZE: usize = 64 * 1024 * 1024;
const WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let handle = std::thread::Builder::new()
        .name("db-mcp-main".to_string())
        .stack_size(RUNTIME_STACK_SIZE)
        .spawn(move || -> anyhow::Result<()> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("db-mcp-worker")
                .thread_stack_size(WORKER_STACK_SIZE)
                .build()?;
            runtime.block_on(async_main(cli))
        })
        .map_err(|e| anyhow::anyhow!("failed to spawn runtime thread: {e}"))?;
    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("db-mcp runtime thread panicked"),
    }
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    let command = cli.command.unwrap_or(Commands::Serve {
        transport: "stdio".to_string(),
        bind: None,
        config: None,
        principal: "local-agent".to_string(),
        role: "agent".to_string(),
    });

    match command {
        Commands::CheckConnection { config, connection } => {
            let parsed = ServerConfig::from_file(&config)?;
            let (all_ok, results) = check_connections(&parsed, connection.as_deref()).await?;
            let out = if results.len() == 1 { results[0].clone() } else { Value::Array(results) };
            println!("{}", serde_json::to_string_pretty(&out)?);
            if !all_ok {
                std::process::exit(3);
            }
            Ok(())
        }
        Commands::VerifyConfig { config, live } => {
            let parsed = ServerConfig::from_file(&config)?;
            let live_checks = if live {
                Some(check_connections(&parsed, None).await?)
            } else {
                None
            };
            let mut summary = json!({
                "status": "ok",
                "config_path": config.display().to_string(),
                "server_name": parsed.server_name,
                "server_version": parsed.server_version,
                "default_mode": parsed.default_mode,
                "connections": parsed.connections.len(),
                "named_tools": parsed.named_tools.len(),
                "active_profiles": parsed.active_profiles,
            });
            if let Some((all_ok, results)) = live_checks {
                summary["status"] = json!(if all_ok { "ok" } else { "unreachable" });
                summary["connection_checks"] = Value::Array(results);
                println!("{}", serde_json::to_string_pretty(&summary)?);
                if !all_ok {
                    std::process::exit(3);
                }
                return Ok(());
            }
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        Commands::VerifyAudit { config } => {
            let parsed = ServerConfig::from_file(&config)?;
            let (all_ok, results) = verify_audit_stores(&parsed);
            let summary = json!({
                "status": if all_ok { "ok" } else { "tampered" },
                "stores": results,
                "note": if results.is_empty() { Some("no durable audit store configured") } else { None },
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            if !all_ok {
                std::process::exit(2);
            }
            Ok(())
        }
        Commands::Ontology { command } => run_ontology_command(command).await,
        Commands::Approve {
            change_id,
            approver,
            role,
            comment,
            config,
        } => {
            let cfg = load_server_config(config.as_ref())?;
            // Same store and approval key as the server, so the approval MAC verifies at apply time.
            let changes = db_mcp_mcp::build_change_manager(&cfg)?;
            let warnings = changes.approval_warnings();
            for w in &warnings {
                eprintln!("[db-mcp] WARNING: {w}");
            }
            let caller = CallerIdentity::new(approver, role, vec!["*".to_string()], "cli");
            let outcome = changes.approve_change(&change_id, &caller, comment);
            let conn = outcome.as_ref().map(|p| p.connection.clone()).unwrap_or_else(|_| "server".to_string());
            audit_admin_action(
                &cfg,
                &caller,
                &conn,
                "approve_change",
                Some(change_id.clone()),
                outcome.as_ref().map(|_| ()),
            );
            let proposal = outcome?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "ok",
                    "change_id": proposal.change_id,
                    "state": proposal.state,
                    "approval": proposal.approval,
                    "approval_hash": proposal.approval_hash,
                    "warnings": warnings,
                }))?
            );
            Ok(())
        }
        Commands::Serve {
            transport,
            bind,
            config,
            principal,
            role,
        } => {
            let cfg = load_server_config(config.as_ref())?;
            let bind_addr = bind.unwrap_or_else(|| cfg.http.bind.clone());
            let auth_token_ref = cfg.http.auth_token.clone();
            let admin_token_ref = cfg.http.admin_token.clone();
            let (audit_ok, audit_results) = verify_audit_stores(&cfg);
            if !audit_ok {
                eprintln!("[db-mcp] WARNING: audit chain integrity check FAILED (possible tampering): {}", Value::Array(audit_results));
            }
            let handler = McpProtocolHandler::from_config(cfg)?;
            for w in handler.approval_warnings() {
                eprintln!("[db-mcp] WARNING: {w}; apply_change is refused on GovernedProduction connections");
            }

            match transport.trim().to_ascii_lowercase().as_str() {
                "stdio" => {
                    let caller = CallerIdentity::new(principal, role, vec!["*".to_string()], "stdio");
                    run_stdio_loop(handler, caller).await
                }
                "http" => {
                    let expected_auth_token = resolve_optional_token(auth_token_ref.as_deref())?;
                    let expected_admin_token = resolve_optional_token(admin_token_ref.as_deref())?;
                    if expected_auth_token.is_none() {
                        eprintln!("[db-mcp] WARNING: no http.auth_token configured; POST /mcp is unauthenticated");
                    }
                    let state = HttpAppState {
                        handler,
                        default_caller: CallerIdentity::new(principal, role, vec!["*".to_string()], "http"),
                        expected_auth_token,
                        expected_admin_token,
                    };
                    let app = build_http_router(state);
                    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
                    axum::serve(listener, app).await?;
                    Ok(())
                }
                other => anyhow::bail!("Unsupported transport '{other}' (expected 'stdio' or 'http')"),
            }
        }
    }
}

/// Run the read-only connection smoke test. Live MySQL and SQL Server connections are checked by the adapter
/// itself (grants, version, read-only session); every other connection goes through the governed
/// runtime as an admin caller (`SELECT 1` + catalog count). Never prints DSNs or passwords.
async fn check_connections(cfg: &ServerConfig, only: Option<&str>) -> anyhow::Result<(bool, Vec<Value>)> {
    let selected: Vec<&db_mcp_mcp::ConnectionConfig> = cfg
        .connections
        .iter()
        .filter(|c| only.map(|id| c.id == id).unwrap_or(true))
        .collect();
    if selected.is_empty() {
        anyhow::bail!("Unknown connection '{}' in configuration", only.unwrap_or_default());
    }
    let mut results = Vec::new();
    let mut all_ok = true;
    let mut runtime: Option<db_mcp_mcp::DbMcpRuntime> = None;
    for conn in selected {
        let backend = conn.effective_backend()?;
        let result = if conn.engine == db_mcp_core::DatabaseEngine::SqlServer {
            check_sqlserver_connection(conn, base_check_report(conn, backend)).await.0
        } else if conn.engine == db_mcp_core::DatabaseEngine::MySql && backend == db_mcp_mcp::config::BACKEND_LIVE {
            check_mysql_live(conn).await
        } else {
            if runtime.is_none() {
                runtime = Some(db_mcp_mcp::DbMcpRuntime::from_config(cfg.clone())?);
            }
            check_via_runtime(runtime.as_ref().expect("runtime"), conn, backend).await
        };
        all_ok &= result.get("can_connect").and_then(Value::as_bool).unwrap_or(false);
        results.push(result);
    }
    Ok((all_ok, results))
}

async fn check_mysql_live(conn: &db_mcp_mcp::ConnectionConfig) -> Value {
    let secrets = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
    let built = conn.resolve_dsn(&secrets).and_then(|dsn| {
        let mut cfg = db_mcp_mysql::MySqlConfig::new(&conn.id, dsn)
            .with_read_only(true)
            .with_backend_mode(db_mcp_mysql::MySqlBackendMode::LiveOnly)
            .with_max_execution_time_ms(conn.timeout_ms);
        if let Some(schema) = &conn.default_schema {
            cfg = cfg.with_default_schema(schema.clone());
        }
        db_mcp_mysql::MySqlAdapter::new(cfg)
    });
    match built {
        Ok(adapter) => adapter.check_connection().await,
        Err(e) => json!({
            "connection": conn.id,
            "engine": conn.engine.as_str(),
            "backend": "live",
            "server_version": null,
            "can_connect": false,
            "select_1": false,
            "object_count": null,
            "permissions": [],
            "can_write": null,
            "warnings": [db_mcp_secrets::redact_sensitive_text(&e.to_string())],
        }),
    }
}

async fn check_via_runtime(runtime: &db_mcp_mcp::DbMcpRuntime, conn: &db_mcp_mcp::ConnectionConfig, backend: &str) -> Value {
    let admin = CallerIdentity::new("check-connection", "admin", vec!["*".to_string()], "cli");
    let mut warnings = Vec::new();
    if backend == db_mcp_mcp::config::BACKEND_SIMULATED {
        warnings.push(format!(
            "connection '{}' uses the embedded simulated {} engine: no server is contacted and the DSN is ignored",
            conn.id,
            conn.engine.as_str()
        ));
    }
    let select = runtime
        .call_tool("execute_query", json!({"connection": conn.id, "sql": "SELECT 1 AS one"}), &admin)
        .await;
    let select_1 = select.get("status").and_then(Value::as_str) == Some("ok");
    if !select_1 {
        warnings.push(format!(
            "SELECT 1 failed: {}",
            select.get("message").and_then(Value::as_str).unwrap_or("unknown error")
        ));
    }
    let search = runtime
        .call_tool("search_objects", json!({"connection": conn.id, "detail_level": "names", "limit": 1}), &admin)
        .await;
    let object_count = search.pointer("/data/total_count").cloned().unwrap_or(Value::Null);
    json!({
        "connection": conn.id,
        "engine": conn.engine.as_str(),
        "backend": backend,
        "server_version": null,
        "can_connect": select_1,
        "select_1": select_1,
        "object_count": object_count,
        "permissions": [],
        "can_write": !conn.read_only,
        "warnings": warnings,
    })
}

async fn run_ontology_command(command: OntologyCommand) -> anyhow::Result<()> {
    use db_mcp_ontology::{DefinitionKind, DefinitionStatus, ReviewAction};
    match command {
        OntologyCommand::List { connection, status, kind, config } => {
            let cfg = load_server_config(Some(&config))?;
            let svc = cli_ontology_service(&cfg, &connection)?;
            let status = status
                .as_deref()
                .map(|s| DefinitionStatus::parse(s).ok_or_else(|| anyhow::anyhow!("unknown status '{s}'")))
                .transpose()?;
            let kind = kind
                .as_deref()
                .map(|k| DefinitionKind::parse(k).ok_or_else(|| anyhow::anyhow!("unknown kind '{k}'")))
                .transpose()?;
            let rows: Vec<serde_json::Value> = svc
                .store
                .latest_all(&cfg.ontology.tenant_id, &connection)?
                .into_iter()
                .filter(|d| status.map(|s| d.status == s).unwrap_or(true))
                .filter(|d| kind.map(|k| d.kind == k).unwrap_or(true))
                .map(|d| {
                    json!({
                        "def_id": d.def_id,
                        "version": d.version,
                        "kind": d.kind,
                        "name": d.name,
                        "status": d.status,
                        "strength": d.strength,
                        "flags": d.flags,
                        "proposed_by": d.proposed_by,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json!({"status": "ok", "count": rows.len(), "definitions": rows}))?);
            Ok(())
        }
        OntologyCommand::Show { connection, def_id, config } => {
            let cfg = load_server_config(Some(&config))?;
            let svc = cli_ontology_service(&cfg, &connection)?;
            let versions = svc.store.versions(&cfg.ontology.tenant_id, &connection, &def_id)?;
            if versions.is_empty() {
                anyhow::bail!("Definition '{def_id}' not found on '{connection}'");
            }
            let certifications = svc.store.certifications(&cfg.ontology.tenant_id, &connection, &def_id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"status": "ok", "versions": versions, "certifications": certifications}))?
            );
            Ok(())
        }
        OntologyCommand::Review { connection, def_id, version, action, reviewer, role, reason, config } => {
            let cfg = load_server_config(Some(&config))?;
            let svc = cli_ontology_service(&cfg, &connection)?;
            let action = ReviewAction::parse(&action)
                .ok_or_else(|| anyhow::anyhow!("action must be approve, reject or deprecate"))?;
            let caller = CallerIdentity::new(reviewer, role, vec!["*".to_string()], "cli");
            let outcome = svc.review(&caller, &connection, &def_id, version, action, reason);
            audit_admin_action(
                &cfg,
                &caller,
                &connection,
                &format!("ontology_review:{}", action.as_str()),
                Some(format!("{def_id}@{version}")),
                outcome.as_ref().map(|_| ()),
            );
            let (definition, certification) = outcome?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "ok",
                    "def_id": definition.def_id,
                    "version": definition.version,
                    "state": definition.status,
                    "certification": certification,
                }))?
            );
            Ok(())
        }
        OntologyCommand::Publish { connection, reviewer, role, config } => {
            let cfg = load_server_config(Some(&config))?;
            let svc = cli_ontology_service(&cfg, &connection)?;
            let caller = CallerIdentity::new(reviewer, role, vec!["*".to_string()], "cli");
            let outcome = svc.publish(&caller, &connection, None);
            audit_admin_action(
                &cfg,
                &caller,
                &connection,
                "ontology_publish",
                outcome.as_ref().ok().map(|r| r.revision_id.clone()),
                outcome.as_ref().map(|_| ()),
            );
            let revision = outcome?;
            println!("{}", serde_json::to_string_pretty(&json!({"status": "ok", "revision": revision}))?);
            Ok(())
        }
        OntologyCommand::Eval { connection, cases, config } => {
            let cfg = load_server_config(Some(&config))?;
            let raw = std::fs::read_to_string(&cases)
                .map_err(|e| anyhow::anyhow!("cannot read golden cases {}: {e}", cases.display()))?;
            let cases: Vec<db_mcp_ontology::GoldenCase> = serde_json::from_str(&raw)?;
            let runtime = db_mcp_mcp::DbMcpRuntime::from_config(cfg)?;
            let evaluator = CallerIdentity::new("ontology-eval", "admin", vec!["*".to_string()], "cli");
            let mut plans = Vec::new();
            for case in &cases {
                plans.push(runtime.plan_question(&evaluator, &connection, &case.question, None).await?);
            }
            let mut iter = plans.into_iter();
            let report = db_mcp_ontology::evaluate(&cases, |_| iter.next().expect("one plan per case"));
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.all_gates_passed() {
                anyhow::bail!("golden evaluation gates failed");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_verify_config_and_default_serve() {
        let cli = Cli::parse_from(["db-mcp-server", "verify-config", "--config", "config/db-mcp.example.toml"]);
        assert!(matches!(cli.command, Some(Commands::VerifyConfig { live: false, .. })));
        let cli = Cli::parse_from(["db-mcp-server", "check-connection", "--config", "c.toml", "--connection", "m"]);
        assert!(matches!(cli.command, Some(Commands::CheckConnection { connection: Some(_), .. })));

        let default_cli = Cli::parse_from(["db-mcp-server"]);
        assert!(default_cli.command.is_none());
    }

    #[tokio::test]
    async fn http_state_handles_mcp_and_approval() {
        let handler = McpProtocolHandler::default_demo().unwrap();
        let agent = CallerIdentity::local_agent("local-agent");
        let prop = handler
            .call_tool(
                "propose_change",
                json!({
                    "connection": "prod-postgres",
                    "sql": "UPDATE orders SET status = 'completed' WHERE id = 102"
                }),
                &agent,
            )
            .await;
        let change_id = prop["data"]["change_id"].as_str().unwrap().to_string();

        let admin = CallerIdentity::admin("release-admin");
        let approved = handler
            .approve_change(&change_id, &admin, Some("LGTM".to_string()))
            .unwrap();
        assert_eq!(approved.change_id, change_id);
    }
}
