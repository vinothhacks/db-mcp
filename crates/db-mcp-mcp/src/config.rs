//! Server, connection, HTTP, audit, and change-store configuration for `db-mcp`.

use std::collections::HashSet;
use std::path::Path;

use db_mcp_core::{
    DatabaseEngine, DbMcpError, DbMcpResult, ExecutionLimits, NamedToolSpec, OperatingMode,
    ToolProfile,
};
use db_mcp_policy::ConnectionPolicyConfig;
use db_mcp_tools::NamedToolRegistry;
use db_mcp_secrets::{CompositeSecretProvider, SecretProvider, SecretString, StaticSecretProvider};
use serde::{Deserialize, Deserializer, Serialize};

fn default_server_name() -> String {
    "db-mcp".to_string()
}

fn default_server_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_bind() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_policy_revision() -> String {
    "policy_v1".to_string()
}

fn default_ttl_seconds() -> i64 {
    3600
}

fn default_timeout_ms() -> u64 {
    10_000
}

fn default_max_rows() -> usize {
    500
}

fn default_max_bytes() -> usize {
    1_048_576
}

fn default_true() -> bool {
    true
}

fn default_wildcard_vec() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_active_profiles() -> Vec<ToolProfile> {
    ToolProfile::all().to_vec()
}

fn parse_engine_str(raw: &str) -> Result<DatabaseEngine, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "postgres" | "postgresql" | "pg" => Ok(DatabaseEngine::Postgres),
        "mysql" | "mariadb" => Ok(DatabaseEngine::MySql),
        "sqlite" | "sqlite3" => Ok(DatabaseEngine::Sqlite),
        "sqlserver" | "mssql" | "sql_server" | "tsql" => Ok(DatabaseEngine::SqlServer),
        other => Err(format!("Unsupported database engine '{other}'")),
    }
}

fn parse_mode_str(raw: &str) -> Result<OperatingMode, String> {
    match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "development" | "dev" => Ok(OperatingMode::Development),
        "read_only" | "readonly" => Ok(OperatingMode::ReadOnly),
        "governed_production" | "governedproduction" | "production" | "prod" => {
            Ok(OperatingMode::GovernedProduction)
        }
        other => Err(format!("Unsupported operating mode '{other}'")),
    }
}

fn parse_profile_str(raw: &str) -> Result<ToolProfile, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "explore" => Ok(ToolProfile::Explore),
        "query" => Ok(ToolProfile::Query),
        "diagnose" => Ok(ToolProfile::Diagnose),
        "change" => Ok(ToolProfile::Change),
        "schema" => Ok(ToolProfile::Schema),
        "ontology" => Ok(ToolProfile::Ontology),
        other => Err(format!("Unsupported tool profile '{other}'")),
    }
}

fn deserialize_engine<'de, D>(deserializer: D) -> Result<DatabaseEngine, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_engine_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_mode<'de, D>(deserializer: D) -> Result<OperatingMode, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_mode_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_opt_mode<'de, D>(deserializer: D) -> Result<Option<OperatingMode>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        Some(s) => parse_mode_str(&s).map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

fn deserialize_profiles<'de, D>(deserializer: D) -> Result<Vec<ToolProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw_list = Vec::<String>::deserialize(deserializer)?;
    raw_list
        .into_iter()
        .map(|item| parse_profile_str(&item).map_err(serde::de::Error::custom))
        .collect()
}

/// Configuration for a single database connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    pub id: String,
    #[serde(deserialize_with = "deserialize_engine")]
    pub engine: DatabaseEngine,
    pub dsn: String,
    #[serde(default, deserialize_with = "deserialize_opt_mode")]
    pub mode: Option<OperatingMode>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_schema: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    #[serde(default)]
    pub allow_multi_statement: bool,
    #[serde(default)]
    pub allow_explain_analyze: bool,
    #[serde(default = "default_true")]
    pub has_pg_stat_statements: bool,
    #[serde(default)]
    pub has_hypopg: bool,
    #[serde(default)]
    pub restricted_tables: Vec<String>,
    #[serde(default)]
    pub sensitive_tables: Vec<String>,
    #[serde(default)]
    pub sensitive_columns: Vec<String>,
    #[serde(default)]
    pub deny_sensitive_column_access: bool,
    #[serde(default)]
    pub unrestricted_sql_provenance: bool,
    #[serde(default = "default_wildcard_vec")]
    pub allowed_roles: Vec<String>,
    #[serde(default = "default_wildcard_vec")]
    pub allowed_principals: Vec<String>,
    #[serde(default)]
    pub init_sql: Option<String>,
}

impl ConnectionConfig {
    pub fn effective_mode(&self, default_mode: OperatingMode) -> OperatingMode {
        self.mode.unwrap_or(default_mode)
    }

    pub fn execution_limits(&self) -> ExecutionLimits {
        ExecutionLimits {
            timeout_ms: self.timeout_ms,
            max_rows: self.max_rows,
            max_bytes: self.max_bytes,
            allow_multi_statement: self.allow_multi_statement,
        }
    }

    /// Resolve the DSN (`env:NAME`, `file:/path`, `secret:NAME`, `${NAME}`, or literal).
    ///
    /// Unset variables and unreadable files are errors. Messages name the variable or path,
    /// never the DSN or secret contents. For SQLite, `file:` is a SQLite URI, not a secret ref.
    pub fn resolve_dsn(&self, secrets: &dyn SecretProvider) -> DbMcpResult<SecretString> {
        let raw = self.dsn.trim();
        if self.engine == DatabaseEngine::Sqlite && raw.starts_with("file:") {
            return Ok(SecretString::new(raw));
        }
        secrets.resolve_dsn(raw).map_err(|e| {
            DbMcpError::ConfigurationError(format!(
                "Connection '{}' dsn could not be resolved: {e}",
                self.id.trim()
            ))
        })
    }

    pub fn to_policy_config(
        &self,
        default_mode: OperatingMode,
        policy_revision: &str,
    ) -> ConnectionPolicyConfig {
        ConnectionPolicyConfig::new(self.id.clone(), self.effective_mode(default_mode))
            .with_policy_revision(policy_revision.to_string())
            .with_limits(self.execution_limits())
            .with_allowed_roles(self.allowed_roles.clone())
            .with_allowed_principals(self.allowed_principals.clone())
            .with_restricted_tables(self.restricted_tables.clone())
            .with_sensitive_tables(self.sensitive_tables.clone())
            .with_sensitive_columns(self.sensitive_columns.clone())
            .with_deny_sensitive_column_access(self.deny_sensitive_column_access)
            .with_unrestricted_sql_provenance(self.unrestricted_sql_provenance)
            .with_allow_explain_analyze(self.allow_explain_analyze)
    }
}

/// Streamable HTTP transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            auth_token: None,
            admin_token: None,
        }
    }
}

/// Audit sink configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub in_memory: bool,
    #[serde(default)]
    pub jsonl_path: Option<String>,
    #[serde(default)]
    pub sqlite_path: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            in_memory: true,
            jsonl_path: None,
            sqlite_path: None,
        }
    }
}

/// Out-of-band change proposal store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeStoreConfig {
    #[serde(default)]
    pub storage_path: Option<String>,
    #[serde(default = "default_policy_revision")]
    pub policy_revision: String,
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: i64,
    /// Secret reference (`env:VAR`, `file:/path`, `secret:NAME` or literal) for the HMAC key that
    /// signs approval records. When unset, env `DB_MCP_APPROVAL_KEY` is used if present. Without
    /// a key, approvals in a persistent store are unkeyed (warning) and GovernedProduction
    /// connections refuse `apply_change`. A set but unresolvable reference is a startup error.
    #[serde(default)]
    pub approval_key: Option<String>,
}

impl Default for ChangeStoreConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            policy_revision: default_policy_revision(),
            default_ttl_seconds: default_ttl_seconds(),
            approval_key: None,
        }
    }
}

/// Governed ontology (semantic layer) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OntologyConfig {
    /// Dedicated metadata database (SQLite file). `None` keeps an in-memory store (demo only):
    /// out-of-band review via the CLI requires a persistent path.
    #[serde(default)]
    pub storage_path: Option<String>,
    /// Namespace isolating ontology content of different tenants in a shared store.
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    /// Optional HMAC key reference (`env:VAR`, `file:/path` or literal) signing certifications.
    #[serde(default)]
    pub review_key: Option<String>,
    #[serde(default = "default_certification_ttl_days")]
    pub certification_ttl_days: i64,
    #[serde(default = "default_max_discovery_objects")]
    pub max_discovery_objects: usize,
    #[serde(default = "default_ontology_max_rows")]
    pub default_max_rows: usize,
    /// Propose `<x>_id` joins without declared FKs (always as unverified candidates).
    #[serde(default = "default_true")]
    pub infer_joins: bool,
}

fn default_tenant_id() -> String {
    "default".to_string()
}
fn default_certification_ttl_days() -> i64 {
    180
}
fn default_max_discovery_objects() -> usize {
    2000
}
fn default_ontology_max_rows() -> usize {
    200
}
impl Default for OntologyConfig {
    fn default() -> Self {
        Self {
            storage_path: None,
            tenant_id: default_tenant_id(),
            review_key: None,
            certification_ttl_days: default_certification_ttl_days(),
            max_discovery_objects: default_max_discovery_objects(),
            default_max_rows: default_ontology_max_rows(),
            infer_joins: true,
        }
    }
}

/// `http.bind` must be `host:port` with a numeric port.
fn validate_bind(bind: &str) -> DbMcpResult<()> {
    let bad = || {
        DbMcpError::ConfigurationError(format!(
            "http.bind '{bind}' is not a valid host:port (e.g. 127.0.0.1:8080)"
        ))
    };
    let (host, port) = bind.trim().rsplit_once(':').ok_or_else(bad)?;
    if host.trim().is_empty() || host.contains(char::is_whitespace) || port.parse::<u16>().is_err() {
        return Err(bad());
    }
    Ok(())
}

/// Top-level `db-mcp` server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default = "default_server_version")]
    pub server_version: String,
    #[serde(default, deserialize_with = "deserialize_mode")]
    pub default_mode: OperatingMode,
    #[serde(
        default = "default_active_profiles",
        deserialize_with = "deserialize_profiles"
    )]
    pub active_profiles: Vec<ToolProfile>,
    #[serde(default)]
    pub http: HttpServerConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub changes: ChangeStoreConfig,
    #[serde(default)]
    pub ontology: OntologyConfig,
    #[serde(default)]
    pub connections: Vec<ConnectionConfig>,
    #[serde(default)]
    pub named_tools: Vec<NamedToolSpec>,
}

const DEMO_SEED_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    total_cents INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inventory (
    sku TEXT PRIMARY KEY,
    available_qty INTEGER NOT NULL,
    reserved_qty INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    sku TEXT NOT NULL REFERENCES inventory(sku),
    quantity INTEGER NOT NULL,
    unit_price_cents INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS internal_secrets (
    id INTEGER PRIMARY KEY,
    secret_key TEXT NOT NULL,
    secret_value TEXT NOT NULL
);
CREATE VIEW IF NOT EXISTS active_user_orders AS
    SELECT o.id AS order_id, u.id AS user_id, u.email, o.status, o.total_cents, o.created_at
    FROM orders o
    JOIN users u ON o.user_id = u.id
    WHERE o.status = 'completed';
INSERT OR IGNORE INTO users (id, email, role, password_hash, created_at) VALUES
    (1, 'alice@example.com', 'admin', 'hash_alice_secret', '2025-01-01T00:00:00Z'),
    (2, 'bob@example.com', 'customer', 'hash_bob_secret', '2025-01-02T00:00:00Z');
INSERT OR IGNORE INTO orders (id, user_id, status, total_cents, created_at) VALUES
    (101, 1, 'completed', 4500, '2025-01-03T10:00:00Z'),
    (102, 2, 'pending', 1900, '2025-01-04T12:00:00Z');
INSERT OR IGNORE INTO inventory (sku, available_qty, reserved_qty) VALUES
    ('SKU-PRO-1', 50, 1),
    ('SKU-STD-2', 100, 0);
INSERT OR IGNORE INTO order_items (id, order_id, sku, quantity, unit_price_cents) VALUES
    (1001, 101, 'SKU-PRO-1', 1, 4500),
    (1002, 102, 'SKU-STD-2', 1, 1900);
INSERT OR IGNORE INTO audit_logs (id, order_id, event_type, created_at) VALUES
    (1, 101, 'ORDER_CHECKED_OUT', '2025-01-03T10:01:00Z');
CREATE OR REPLACE PROCEDURE record_order_audit(order_id INTEGER, event_type TEXT)
BEGIN
    INSERT INTO audit_logs (order_id, event_type, created_at)
    SELECT o.id, event_type, o.created_at
    FROM orders o
    WHERE o.id = order_id;
END;
CREATE OR REPLACE PROCEDURE reserve_inventory(order_id INTEGER)
BEGIN
    UPDATE inventory
    SET reserved_qty = reserved_qty + 1
    WHERE sku IN (
        SELECT oi.sku
        FROM order_items oi
        WHERE oi.order_id = order_id
    );
    CALL record_order_audit(order_id, 'INVENTORY_RESERVED');
END;
CREATE OR REPLACE FUNCTION calculate_order_discount(order_id INTEGER)
RETURNS NUMERIC
BEGIN
    SELECT o.total_cents * 0.10
    FROM orders o
    JOIN users u ON u.id = o.user_id
    WHERE o.id = order_id;
END;
CREATE OR REPLACE PROCEDURE checkout_order(order_id INTEGER)
BEGIN
    PERFORM calculate_order_discount(order_id);
    UPDATE orders
    SET status = 'completed'
    WHERE id = order_id
      AND user_id IN (
          SELECT u.id
          FROM users u
          WHERE u.role = 'customer'
      );
    SELECT o.id, u.email
    FROM orders o
    JOIN users u ON u.id = o.user_id
    WHERE o.id = order_id;
    CALL reserve_inventory(order_id);
    CALL record_order_audit(order_id, 'ORDER_CHECKED_OUT');
END;
"#;

impl ServerConfig {
    /// Construct a self-contained in-memory demo configuration with SQLite, PostgreSQL, and MySQL connections.
    pub fn default_demo() -> Self {
        use db_mcp_core::{NamedToolParamSpec, NamedToolParamType};
        Self {
            server_name: default_server_name(),
            server_version: default_server_version(),
            default_mode: OperatingMode::ReadOnly,
            active_profiles: ToolProfile::all().to_vec(),
            http: HttpServerConfig::default(),
            audit: AuditConfig::default(),
            changes: ChangeStoreConfig::default(),
            ontology: OntologyConfig::default(),
            connections: vec![
                ConnectionConfig {
                    id: "local-sqlite".to_string(),
                    engine: DatabaseEngine::Sqlite,
                    dsn: "sqlite://:memory:".to_string(),
                    mode: Some(OperatingMode::Development),
                    read_only: false,
                    description: Some("Local SQLite development fixture database".to_string()),
                    default_schema: Some("main".to_string()),
                    timeout_ms: 10_000,
                    max_rows: 500,
                    max_bytes: 1_048_576,
                    allow_multi_statement: false,
                    allow_explain_analyze: true,
                    has_pg_stat_statements: false,
                    has_hypopg: false,
                    restricted_tables: vec!["internal_secrets".to_string()],
                    sensitive_tables: Vec::new(),
                    sensitive_columns: vec![
                        "password_hash".to_string(),
                        "api_key".to_string(),
                        "secret_token".to_string(),
                    ],
                    deny_sensitive_column_access: false,
                    unrestricted_sql_provenance: false,
                    allowed_roles: default_wildcard_vec(),
                    allowed_principals: default_wildcard_vec(),
                    init_sql: Some(DEMO_SEED_SQL.to_string()),
                },
                ConnectionConfig {
                    id: "prod-postgres".to_string(),
                    engine: DatabaseEngine::Postgres,
                    dsn: "postgres://localhost:5432/app_prod".to_string(),
                    mode: Some(OperatingMode::GovernedProduction),
                    read_only: false,
                    description: Some("Governed production PostgreSQL database".to_string()),
                    default_schema: Some("public".to_string()),
                    timeout_ms: 10_000,
                    max_rows: 500,
                    max_bytes: 1_048_576,
                    allow_multi_statement: false,
                    allow_explain_analyze: false,
                    has_pg_stat_statements: true,
                    has_hypopg: true,
                    restricted_tables: vec!["internal_secrets".to_string()],
                    sensitive_tables: vec!["users".to_string()],
                    sensitive_columns: vec![
                        "password_hash".to_string(),
                        "api_key".to_string(),
                        "secret_token".to_string(),
                    ],
                    deny_sensitive_column_access: false,
                    unrestricted_sql_provenance: false,
                    allowed_roles: vec![
                        "agent".to_string(),
                        "developer".to_string(),
                        "dba".to_string(),
                        "admin".to_string(),
                    ],
                    allowed_principals: default_wildcard_vec(),
                    init_sql: Some(DEMO_SEED_SQL.to_string()),
                },
                ConnectionConfig {
                    id: "analytics-mysql".to_string(),
                    engine: DatabaseEngine::MySql,
                    dsn: "mysql://localhost:3306/analytics".to_string(),
                    mode: Some(OperatingMode::ReadOnly),
                    read_only: true,
                    description: Some("Read-only MySQL analytics replica".to_string()),
                    default_schema: Some("analytics".to_string()),
                    timeout_ms: 15_000,
                    max_rows: 1_000,
                    max_bytes: 1_048_576,
                    allow_multi_statement: false,
                    allow_explain_analyze: false,
                    has_pg_stat_statements: false,
                    has_hypopg: false,
                    restricted_tables: Vec::new(),
                    sensitive_tables: Vec::new(),
                    sensitive_columns: vec![
                        "password_hash".to_string(),
                        "api_key".to_string(),
                        "secret_token".to_string(),
                    ],
                    deny_sensitive_column_access: false,
                    unrestricted_sql_provenance: false,
                    allowed_roles: default_wildcard_vec(),
                    allowed_principals: default_wildcard_vec(),
                    init_sql: Some(DEMO_SEED_SQL.to_string()),
                },
            ],
            named_tools: vec![
                NamedToolSpec {
                    name: "get_user_by_id".to_string(),
                    description:
                        "Retrieve a single user record by numeric user ID using bound parameters."
                            .to_string(),
                    connection: "local-sqlite".to_string(),
                    statement: "SELECT id, email, role, created_at FROM users WHERE id = ?1"
                        .to_string(),
                    parameters: vec![NamedToolParamSpec {
                        name: "user_id".to_string(),
                        param_type: NamedToolParamType::Integer,
                        description: "Unique numeric user identifier".to_string(),
                        required: true,
                        default_value: None,
                    }],
                    read_only: true,
                    max_rows: Some(1),
                    timeout_ms: Some(5000),
                    allowed_roles: vec![
                        "agent".to_string(),
                        "developer".to_string(),
                        "dba".to_string(),
                        "admin".to_string(),
                    ],
                },
                NamedToolSpec {
                    name: "list_orders_by_status".to_string(),
                    description:
                        "List orders filtered by status with an optional minimum total in cents."
                            .to_string(),
                    connection: "local-sqlite".to_string(),
                    statement: "SELECT id, user_id, status, total_cents, created_at FROM orders WHERE status = ?1 AND total_cents >= ?2 ORDER BY id ASC".to_string(),
                    parameters: vec![
                        NamedToolParamSpec {
                            name: "status".to_string(),
                            param_type: NamedToolParamType::String,
                            description: "Order lifecycle status".to_string(),
                            required: true,
                            default_value: None,
                        },
                        NamedToolParamSpec {
                            name: "min_total_cents".to_string(),
                            param_type: NamedToolParamType::Integer,
                            description: "Minimum order total in cents".to_string(),
                            required: false,
                            default_value: Some(serde_json::json!(0)),
                        },
                    ],
                    read_only: true,
                    max_rows: Some(100),
                    timeout_ms: Some(5000),
                    allowed_roles: vec![
                        "agent".to_string(),
                        "developer".to_string(),
                        "dba".to_string(),
                        "admin".to_string(),
                    ],
                },
            ],
        }
    }

    pub fn from_toml_str(content: &str) -> DbMcpResult<Self> {
        let cfg: Self = toml::from_str(content)
            .map_err(|e| DbMcpError::InvalidArgument(format!("Invalid TOML config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_json_str(content: &str) -> DbMcpResult<Self> {
        let cfg: Self = serde_json::from_str(content)
            .map_err(|e| DbMcpError::InvalidArgument(format!("Invalid JSON config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_yaml_str(content: &str) -> DbMcpResult<Self> {
        let cfg: Self = serde_yaml::from_str(content)
            .map_err(|e| DbMcpError::InvalidArgument(format!("Invalid YAML config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_file(path: impl AsRef<Path>) -> DbMcpResult<Self> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            DbMcpError::InvalidArgument(format!(
                "Failed to read config file '{}': {e}",
                path_ref.display()
            ))
        })?;
        let content = content
            .strip_prefix('\u{feff}')
            .unwrap_or(&content)
            .to_string();
        let ext = path_ref
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("toml")
            .to_ascii_lowercase();
        match ext.as_str() {
            "json" => Self::from_json_str(&content),
            "yaml" | "yml" => Self::from_yaml_str(&content),
            _ => Self::from_toml_str(&content),
        }
    }

    pub fn validate(&self) -> DbMcpResult<()> {
        if self.server_name.trim().is_empty() {
            return Err(DbMcpError::InvalidArgument(
                "server_name must not be empty".to_string(),
            ));
        }
        if self.connections.is_empty() {
            return Err(DbMcpError::ConfigurationError(
                "config defines no connections; add at least one [[connections]] entry".to_string(),
            ));
        }
        validate_bind(&self.http.bind)?;
        if self.changes.default_ttl_seconds <= 0 {
            return Err(DbMcpError::ConfigurationError(
                "changes.default_ttl_seconds must be greater than zero".to_string(),
            ));
        }
        let dsn_secrets = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
        let mut seen_ids = HashSet::new();
        for conn in &self.connections {
            let trimmed = conn.id.trim();
            if trimmed.is_empty() {
                return Err(DbMcpError::InvalidArgument(
                    "Connection id must not be empty".to_string(),
                ));
            }
            if !seen_ids.insert(trimmed.to_string()) {
                return Err(DbMcpError::InvalidArgument(format!(
                    "Duplicate connection id '{trimmed}'"
                )));
            }
            if conn.dsn.trim().is_empty() {
                return Err(DbMcpError::InvalidArgument(format!(
                    "Connection '{trimmed}' has an empty dsn"
                )));
            }
            if conn.timeout_ms == 0 || conn.max_rows == 0 || conn.max_bytes == 0 {
                return Err(DbMcpError::InvalidArgument(format!(
                    "Connection '{trimmed}' limits must be greater than zero"
                )));
            }
            conn.resolve_dsn(&dsn_secrets)?;
        }
        let _registry = NamedToolRegistry::from_specs(self.named_tools.clone())?;
        for tool in &self.named_tools {
            if !seen_ids.contains(tool.connection.trim()) {
                return Err(DbMcpError::InvalidArgument(format!(
                    "Named tool '{}' references unknown connection '{}'",
                    tool.name, tool.connection
                )));
            }
        }
        if self.ontology.tenant_id.trim().is_empty() {
            return Err(DbMcpError::ConfigurationError("ontology.tenant_id must not be empty".to_string()));
        }
        if self.ontology.certification_ttl_days < 1 || self.ontology.certification_ttl_days > 3650 {
            return Err(DbMcpError::ConfigurationError(
                "ontology.certification_ttl_days must be between 1 and 3650".to_string(),
            ));
        }
        if self.ontology.max_discovery_objects == 0 || self.ontology.default_max_rows == 0 {
            return Err(DbMcpError::ConfigurationError(
                "ontology.max_discovery_objects and ontology.default_max_rows must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "server_name = \"t\"\n[[connections]]\nid = \"c1\"\nengine = \"Sqlite\"\ndsn = \"sqlite://:memory:\"\n";
    const TOOL: &str = "[[named_tools]]\nname = \"t\"\ndescription = \"d\"\nconnection = \"c1\"\nstatement = \"SELECT 1\"\n";

    fn err(extra: &str) -> String {
        ServerConfig::from_toml_str(&format!("{BASE}{extra}"))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn base_loads() {
        ServerConfig::from_toml_str(BASE).unwrap();
        ServerConfig::from_toml_str(&format!("{BASE}{TOOL}")).unwrap();
    }

    #[test]
    fn unknown_fields_rejected_everywhere() {
        assert!(err("read_onli = true\n").contains("unknown field `read_onli`"));
        let top = ServerConfig::from_toml_str(&format!("bogus = 1\n{BASE}")).unwrap_err();
        assert!(top.to_string().contains("unknown field `bogus`"));
        for table in ["http", "audit", "changes", "ontology"] {
            let cfg = format!("{BASE}[{table}]\nbogus_key = 1\n");
            assert!(
                ServerConfig::from_toml_str(&cfg)
                    .unwrap_err()
                    .to_string()
                    .contains("unknown field"),
                "[{table}] accepted an unknown key"
            );
        }
        assert!(ServerConfig::from_toml_str(&format!("{BASE}{TOOL}bogus = 1\n")).is_err());
        let param = "[[named_tools.parameters]]\nname = \"p\"\nparam_type = \"string\"\ndescription = \"d\"\nbogus = 1\n";
        assert!(ServerConfig::from_toml_str(&format!("{BASE}{TOOL}{param}")).is_err());
    }

    #[test]
    fn missing_env_dsn_fails_naming_variable() {
        let cfg = BASE.replace("sqlite://:memory:", "env:DB_MCP_TEST_UNSET_DSN_VAR");
        let e = ServerConfig::from_toml_str(&cfg).unwrap_err().to_string();
        assert!(e.contains("DB_MCP_TEST_UNSET_DSN_VAR") && e.contains("'c1'"), "{e}");
    }

    #[test]
    fn missing_secret_file_fails() {
        let cfg = BASE
            .replace("Sqlite", "Postgres")
            .replace("sqlite://:memory:", "file:/definitely/not/here.secret");
        let e = ServerConfig::from_toml_str(&cfg).unwrap_err().to_string();
        assert!(e.contains("not/here.secret"), "{e}");
    }

    #[test]
    fn sqlite_file_uri_dsn_is_not_a_secret_ref() {
        let cfg = BASE.replace("sqlite://:memory:", "file:/tmp/x.db");
        ServerConfig::from_toml_str(&cfg).unwrap();
    }

    #[test]
    fn tool_with_unknown_connection_rejected_even_without_connections() {
        let tool = TOOL.replace("\"c1\"", "\"ghost\"");
        assert!(ServerConfig::from_toml_str(&format!("server_name = \"t\"\n{tool}")).is_err());
        assert!(err(&tool).contains("unknown connection 'ghost'"));
    }

    #[test]
    fn zero_connections_ttl_and_bind_rejected() {
        let e = ServerConfig::from_toml_str("server_name = \"t\"\n").unwrap_err();
        assert!(e.to_string().contains("no connections"));
        assert!(err("[changes]\ndefault_ttl_seconds = -5\n").contains("default_ttl_seconds"));
        assert!(err("[changes]\ndefault_ttl_seconds = 0\n").contains("default_ttl_seconds"));
        assert!(err("[http]\nbind = \"not-an-addr\"\n").contains("http.bind"));
        assert!(err("[http]\nbind = \"host:99999\"\n").contains("http.bind"));
        ServerConfig::from_toml_str(&format!("{BASE}[http]\nbind = \"localhost:9000\"\n")).unwrap();
    }

    #[test]
    fn bom_prefixed_json_loads() {
        let dir = std::env::temp_dir().join(format!("db_mcp_bom_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("c.json");
        let body = r#"{"connections":[{"id":"c1","engine":"Sqlite","dsn":"sqlite://:memory:"}]}"#;
        std::fs::write(&p, format!("\u{feff}{body}")).unwrap();
        assert!(ServerConfig::from_file(&p).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
