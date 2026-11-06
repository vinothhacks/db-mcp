//! DB-MCP server binary entrypoint supporting stdio, Streamable HTTP, and out-of-band admin approvals.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
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
            Json(json!({
                "jsonrpc": "2.0",
                "id": req.id,
                "error": { "code": -32001, "message": "Unauthorized: invalid or missing Bearer token" }
            })),
        );
    }
    let caller = extract_http_caller(&headers, &state.default_caller);
    let resp = state.handler.handle_jsonrpc(req, &caller).await;
    (
        StatusCode::OK,
        Json(serde_json::to_value(resp).unwrap_or_else(|_| json!({}))),
    )
}

async fn handle_admin_approve(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(payload): Json<AdminApprovePayload>,
) -> impl IntoResponse {
    if !check_bearer(&headers, state.expected_admin_token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "denied", "code": "UNAUTHORIZED", "message": "Invalid admin token" })),
        );
    }
    let approver = CallerIdentity::new(&payload.approver, &payload.role, vec!["*".to_string()], "http-admin");
    match state
        .handler
        .approve_change(&payload.change_id, &approver, payload.comment)
    {
        Ok(proposal) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "proposal": proposal })),
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

async fn run_stdio_loop(handler: McpProtocolHandler, caller: CallerIdentity) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            let is_notification = parsed.get("id").is_none()
                && parsed
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(|m| m.starts_with("notifications/"))
                    .unwrap_or(false);
            if is_notification {
                let _ = handler.handle_jsonrpc_str(trimmed, &caller).await;
                continue;
            }
        }
        let response_json = handler.handle_jsonrpc_str(trimmed, &caller).await;
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
        Commands::VerifyConfig { config } => {
            let parsed = ServerConfig::from_file(&config)?;
            let summary = json!({
                "status": "ok",
                "config_path": config.display().to_string(),
                "server_name": parsed.server_name,
                "server_version": parsed.server_version,
                "default_mode": parsed.default_mode,
                "connections": parsed.connections.len(),
                "named_tools": parsed.named_tools.len(),
                "active_profiles": parsed.active_profiles,
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        Commands::Approve {
            change_id,
            approver,
            role,
            comment,
            config,
        } => {
            let cfg = load_server_config(config.as_ref())?;
            let changes = match &cfg.changes.storage_path {
                Some(path) if !path.trim().is_empty() => {
                    db_mcp_changes::ChangeManager::with_storage_path(path)?
                }
                _ => db_mcp_changes::ChangeManager::new_in_memory(),
            }
            .with_policy_revision(&cfg.changes.policy_revision)
            .with_default_ttl_seconds(cfg.changes.default_ttl_seconds);
            let caller = CallerIdentity::new(approver, role, vec!["*".to_string()], "cli");
            let proposal = changes.approve_change(&change_id, &caller, comment)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "ok",
                    "change_id": proposal.change_id,
                    "state": proposal.state,
                    "approval": proposal.approval,
                    "approval_hash": proposal.approval_hash,
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
            let handler = McpProtocolHandler::from_config(cfg)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_verify_config_and_default_serve() {
        let cli = Cli::parse_from(["db-mcp-server", "verify-config", "--config", "config/db-mcp.example.toml"]);
        assert!(matches!(cli.command, Some(Commands::VerifyConfig { .. })));

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
