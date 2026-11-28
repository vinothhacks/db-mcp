//! Google MCP Toolbox–style declarative parameterized named tools (`NamedToolRegistry`).
//!
//! Responsibilities:
//! - Parse and register `NamedToolSpec` definitions from TOML, YAML, or JSON strings and files.
//! - Enforce single-statement and read-only SQL invariants at tool registration time.
//! - Validate caller role and connection permissions before tool execution.
//! - Validate arguments strictly against `NamedToolParamSpec` (`String`, `Integer`, `Float`,
//!   `Boolean`, `Json`), required flags, and default values.
//! - Execute `run_named_tool` against any `DatabaseAdapter` using bound positional parameters
//!   (`AuthorizedQuery.params`) with zero SQL string interpolation.

use std::collections::BTreeMap;
use std::path::Path;

use db_mcp_core::{
    AuthorizedQuery, CallerIdentity, DatabaseAdapter, DatabaseEngine, DbMcpError, DbMcpResult,
    ExecutionId, ExecutionLimits, QueryResult, SqlStatementClass,
};
pub use db_mcp_core::{NamedToolParamSpec, NamedToolParamType, NamedToolSpec};
use db_mcp_sql::{hash_sql, normalize_sql, parse_and_analyze_sql};
use serde::{Deserialize, Serialize};

/// Wrapper supporting `{ "tools": [...] }` / `[[tools]]` config files as well as raw lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum NamedToolsConfigEnvelope {
    Wrapped {
        tools: Vec<NamedToolSpec>,
    },
    MapWrapped {
        tools: BTreeMap<String, NamedToolSpec>,
    },
    List(Vec<NamedToolSpec>),
}

impl NamedToolsConfigEnvelope {
    fn into_specs(self) -> Vec<NamedToolSpec> {
        match self {
            Self::Wrapped { tools } => tools,
            Self::MapWrapped { tools } => tools
                .into_iter()
                .map(|(k, mut spec)| {
                    if spec.name.trim().is_empty() {
                        spec.name = k;
                    }
                    spec
                })
                .collect(),
            Self::List(tools) => tools,
        }
    }
}

/// Request payload for invoking a registered named tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedToolInvocation {
    pub request_id: String,
    pub tool_name: String,
    pub caller: CallerIdentity,
    #[serde(default)]
    pub arguments: BTreeMap<String, serde_json::Value>,
}

impl NamedToolInvocation {
    pub fn new(
        request_id: impl Into<String>,
        tool_name: impl Into<String>,
        caller: CallerIdentity,
        arguments: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            tool_name: tool_name.into(),
            caller,
            arguments,
        }
    }

    pub fn from_json_args(
        request_id: impl Into<String>,
        tool_name: impl Into<String>,
        caller: CallerIdentity,
        json_args: &serde_json::Value,
    ) -> DbMcpResult<Self> {
        let map = match json_args {
            serde_json::Value::Null => BTreeMap::new(),
            serde_json::Value::Object(obj) => {
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            }
            _ => {
                return Err(DbMcpError::InvalidArgument(
                    "Named tool arguments must be a JSON object".to_string(),
                ))
            }
        };
        Ok(Self::new(request_id, tool_name, caller, map))
    }
}

/// Validated, bound named tool call ready for adapter execution without string interpolation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreparedNamedToolCall {
    pub tool: NamedToolSpec,
    pub bound_params: Vec<serde_json::Value>,
    pub authorized_query: AuthorizedQuery,
}

/// Registry of declarative parameterized named tools (`run_named_tool`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamedToolRegistry {
    tools: BTreeMap<String, NamedToolSpec>,
}

impl NamedToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    /// Construct a `NamedToolRegistry` from an iterator of `NamedToolSpec`s.
    pub fn from_specs(specs: impl IntoIterator<Item = NamedToolSpec>) -> DbMcpResult<Self> {
        let mut registry = Self::new();
        for spec in specs {
            registry.register(spec)?;
        }
        Ok(registry)
    }

    /// Load tool definitions from a TOML configuration string.
    pub fn from_toml_str(content: &str) -> DbMcpResult<Self> {
        let envelope: NamedToolsConfigEnvelope = toml::from_str(content).map_err(|e| {
            DbMcpError::ConfigurationError(format!("Failed to parse named tools TOML: {e}"))
        })?;
        Self::from_specs(envelope.into_specs())
    }

    /// Load tool definitions from a YAML configuration string.
    pub fn from_yaml_str(content: &str) -> DbMcpResult<Self> {
        let envelope: NamedToolsConfigEnvelope = serde_yaml::from_str(content).map_err(|e| {
            DbMcpError::ConfigurationError(format!("Failed to parse named tools YAML: {e}"))
        })?;
        Self::from_specs(envelope.into_specs())
    }

    /// Load tool definitions from a JSON configuration string.
    pub fn from_json_str(content: &str) -> DbMcpResult<Self> {
        let envelope: NamedToolsConfigEnvelope = serde_json::from_str(content).map_err(|e| {
            DbMcpError::ConfigurationError(format!("Failed to parse named tools JSON: {e}"))
        })?;
        Self::from_specs(envelope.into_specs())
    }

    /// Load tool definitions from a `.toml`, `.yaml`/`.yml`, or `.json` file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> DbMcpResult<Self> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref).map_err(|e| {
            DbMcpError::ConfigurationError(format!(
                "Failed to read named tools file '{}': {e}",
                path_ref.display()
            ))
        })?;

        let ext = path_ref
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        match ext.as_str() {
            "toml" => Self::from_toml_str(&content),
            "yaml" | "yml" => Self::from_yaml_str(&content),
            "json" => Self::from_json_str(&content),
            _ => Self::from_toml_str(&content)
                .or_else(|_| Self::from_yaml_str(&content))
                .or_else(|_| Self::from_json_str(&content)),
        }
    }

    /// Validate and register a `NamedToolSpec`.
    pub fn register(&mut self, spec: NamedToolSpec) -> DbMcpResult<()> {
        let name = spec.name.trim();
        if name.is_empty() {
            return Err(DbMcpError::ConfigurationError(
                "Named tool name must not be empty".to_string(),
            ));
        }
        if spec.connection.trim().is_empty() {
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' must specify a target connection"
            )));
        }
        if spec.statement.trim().is_empty() {
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' must specify a non-empty SQL statement"
            )));
        }

        // Parse and validate statement across supported SQL dialects (`Postgres`, `Sqlite`, `MySql`)
        let analysis = analyze_named_tool_statement(&spec.statement)?;
        if analysis.is_multi_statement {
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' must contain a single SQL statement (found {})",
                analysis.statement_count
            )));
        }
        if analysis.has_privileged_functions {
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' contains forbidden privileged function(s): {:?}",
                analysis.privileged_functions
            )));
        }
        if spec.read_only
            && (analysis.overall_class.is_mutating()
                || analysis.has_writes
                || analysis.has_ddl
                || analysis.has_cte_write)
        {
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' is marked read_only=true but statement is classified as '{}'",
                analysis.overall_class
            )));
        }

        // Validate default values on parameters if provided
        for param in &spec.parameters {
            if param.name.trim().is_empty() {
                return Err(DbMcpError::ConfigurationError(format!(
                    "Named tool '{name}' has a parameter with an empty name"
                )));
            }
            if let Some(default_val) = &param.default_value {
                if !default_val.is_null() {
                    validate_param_value(name, param, default_val)?;
                }
            }
        }

        // Every declared parameter must be bound by exactly one placeholder position and vice versa,
        // otherwise the mismatch only surfaces as an adapter error at call time.
        let declared = spec.parameters.len();
        let (numbered, bare) = placeholder_positions(&spec.statement);
        let arity_ok = if numbered.is_empty() {
            bare == declared
        } else {
            numbered.iter().copied().eq(1..=declared)
        };
        if !arity_ok {
            let found = if numbered.is_empty() {
                format!("{bare} positional '?' placeholder(s)")
            } else {
                let list: Vec<String> = numbered.iter().map(|n| format!("?{n}")).collect();
                format!("placeholders {}", list.join(", "))
            };
            return Err(DbMcpError::ConfigurationError(format!(
                "Named tool '{name}' declares {declared} parameter(s) but its statement uses {found}; \
                 placeholders must be ?1..?{declared} (or {declared} bare '?')"
            )));
        }

        if self.tools.contains_key(name) {
            return Err(DbMcpError::ConfigurationError(format!(
                "Duplicate named tool '{name}': each named tool must have a unique name"
            )));
        }

        self.tools.insert(name.to_string(), spec);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&NamedToolSpec> {
        self.tools.get(name.trim())
    }

    pub fn list(&self) -> Vec<&NamedToolSpec> {
        self.tools.values().collect()
    }

    /// Return all tools that the given `CallerIdentity` is authorized to invoke.
    pub fn list_for_caller(&self, caller: &CallerIdentity) -> Vec<&NamedToolSpec> {
        self.tools
            .values()
            .filter(|spec| {
                caller.can_access_connection(&spec.connection)
                    && is_caller_role_allowed(caller, &spec.allowed_roles)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Validate caller permissions and arguments against `NamedToolSpec`, producing a bound
    /// `PreparedNamedToolCall` with zero SQL string interpolation.
    pub fn validate_and_bind(
        &self,
        request_id: impl Into<String>,
        tool_name: &str,
        caller: &CallerIdentity,
        arguments: &BTreeMap<String, serde_json::Value>,
        default_limits: &ExecutionLimits,
    ) -> DbMcpResult<PreparedNamedToolCall> {
        let spec = self.get(tool_name).ok_or_else(|| {
            DbMcpError::InvalidArgument(format!("Named tool '{}' is not registered", tool_name))
        })?;

        if !caller.can_access_connection(&spec.connection) {
            return Err(DbMcpError::Unauthorized(format!(
                "Principal '{}' is not authorized to access connection '{}' for tool '{}'",
                caller.principal, spec.connection, spec.name
            )));
        }

        if !is_caller_role_allowed(caller, &spec.allowed_roles) {
            return Err(DbMcpError::Unauthorized(format!(
                "Caller role '{}' is not in allowed_roles {:?} for named tool '{}'",
                caller.role, spec.allowed_roles, spec.name
            )));
        }

        // Reject any undeclared arguments
        for arg_key in arguments.keys() {
            if !spec.parameters.iter().any(|p| p.name == *arg_key) {
                return Err(DbMcpError::InvalidArgument(format!(
                    "Unknown argument '{}' for named tool '{}'",
                    arg_key, spec.name
                )));
            }
        }

        let mut bound_params = Vec::with_capacity(spec.parameters.len());
        for param_spec in &spec.parameters {
            let provided = arguments.get(&param_spec.name).filter(|v| !v.is_null());
            let resolved = match (provided, param_spec.default_value.as_ref()) {
                (Some(val), _) => {
                    validate_param_value(&spec.name, param_spec, val)?;
                    val.clone()
                }
                (None, Some(def)) if !def.is_null() => {
                    validate_param_value(&spec.name, param_spec, def)?;
                    def.clone()
                }
                (None, _) => {
                    if param_spec.required {
                        return Err(DbMcpError::InvalidArgument(format!(
                            "Missing required parameter '{}' (type {:?}) for named tool '{}'",
                            param_spec.name, param_spec.param_type, spec.name
                        )));
                    }
                    serde_json::Value::Null
                }
            };
            bound_params.push(resolved);
        }

        let analysis = analyze_named_tool_statement(&spec.statement)?;
        let statement_class = if spec.read_only {
            SqlStatementClass::Read
        } else {
            analysis.overall_class
        };

        let normalized_sql = normalize_sql(&spec.statement);
        let sql_hash = hash_sql(&spec.statement);

        let authorized_query = AuthorizedQuery {
            request_id: request_id.into(),
            execution_id: ExecutionId::new(),
            connection: spec.connection.clone(),
            caller: caller.clone(),
            sql: spec.statement.clone(),
            normalized_sql,
            sql_hash,
            params: bound_params.clone(),
            statement_class,
            read_only: spec.read_only,
            timeout_ms: spec.timeout_ms.unwrap_or(default_limits.timeout_ms),
            max_rows: spec.max_rows.unwrap_or(default_limits.max_rows),
            max_bytes: default_limits.max_bytes,
            change_id: None,
        };

        Ok(PreparedNamedToolCall {
            tool: spec.clone(),
            bound_params,
            authorized_query,
        })
    }

    /// Execute a `NamedToolInvocation` against a `DatabaseAdapter` using bound parameters.
    pub async fn execute(
        &self,
        adapter: &dyn DatabaseAdapter,
        invocation: NamedToolInvocation,
        default_limits: &ExecutionLimits,
    ) -> DbMcpResult<QueryResult> {
        let prepared = self.validate_and_bind(
            invocation.request_id,
            &invocation.tool_name,
            &invocation.caller,
            &invocation.arguments,
            default_limits,
        )?;

        if adapter.connection_id() != prepared.tool.connection {
            return Err(DbMcpError::InvalidArgument(format!(
                "Adapter connection '{}' does not match named tool '{}' connection '{}'",
                adapter.connection_id(),
                prepared.tool.name,
                prepared.tool.connection
            )));
        }

        adapter.execute(prepared.authorized_query).await
    }

    /// Convenience helper for `run_named_tool` accepting a JSON object of arguments.
    pub async fn run_named_tool(
        &self,
        adapter: &dyn DatabaseAdapter,
        request_id: impl Into<String>,
        tool_name: &str,
        caller: CallerIdentity,
        arguments: &serde_json::Value,
        default_limits: &ExecutionLimits,
    ) -> DbMcpResult<QueryResult> {
        let invocation =
            NamedToolInvocation::from_json_args(request_id, tool_name, caller, arguments)?;
        self.execute(adapter, invocation, default_limits).await
    }
}

/// Positional placeholders used by a statement, ignoring quoted text and comments:
/// the set of numbered `?N` / `$N` indices and the count of bare `?`.
fn placeholder_positions(sql: &str) -> (std::collections::BTreeSet<usize>, usize) {
    let chars: Vec<char> = sql.chars().collect();
    let mut numbered = std::collections::BTreeSet::new();
    let mut bare = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' | '"' | '`' => {
                i += 1;
                while i < chars.len() && chars[i] != c {
                    i += 1;
                }
            }
            '-' if chars.get(i + 1) == Some(&'-') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 1;
            }
            '?' | '$' => {
                let start = i + 1;
                let mut end = start;
                while end < chars.len() && chars[end].is_ascii_digit() {
                    end += 1;
                }
                if end > start {
                    if let Ok(n) = chars[start..end]
                        .iter()
                        .collect::<String>()
                        .parse::<usize>()
                    {
                        numbered.insert(n);
                    }
                    i = end;
                    continue;
                } else if c == '?' {
                    bare += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    (numbered, bare)
}

fn analyze_named_tool_statement(statement: &str) -> DbMcpResult<db_mcp_sql::SqlAnalysis> {
    let engines = [
        DatabaseEngine::Postgres,
        DatabaseEngine::Sqlite,
        DatabaseEngine::MySql,
    ];
    let mut last_analysis = None;
    for engine in engines {
        let analysis = parse_and_analyze_sql(engine, statement)?;
        if analysis.overall_class != SqlStatementClass::Unknown {
            return Ok(analysis);
        }
        last_analysis = Some(analysis);
    }
    Ok(last_analysis.expect("at least one engine checked"))
}

fn is_caller_role_allowed(caller: &CallerIdentity, allowed_roles: &[String]) -> bool {
    if allowed_roles.is_empty() {
        return true;
    }
    allowed_roles.iter().any(|allowed| {
        let a = allowed.trim();
        a == "*"
            || caller.role.eq_ignore_ascii_case(a)
            || caller.roles.iter().any(|r| r.eq_ignore_ascii_case(a))
    })
}

fn validate_param_value(
    tool_name: &str,
    spec: &NamedToolParamSpec,
    value: &serde_json::Value,
) -> DbMcpResult<()> {
    let valid = match spec.param_type {
        NamedToolParamType::String => value.is_string(),
        NamedToolParamType::Integer => value
            .as_number()
            .map(|n| n.is_i64() || n.is_u64())
            .unwrap_or(false),
        NamedToolParamType::Float => value.is_number(),
        NamedToolParamType::Boolean => value.is_boolean(),
        NamedToolParamType::Json => true,
    };

    if !valid {
        return Err(DbMcpError::InvalidArgument(format!(
            "Parameter '{}' for named tool '{}' expected type {:?}, got {}",
            spec.name,
            tool_name,
            spec.param_type,
            json_type_name(value)
        )));
    }
    Ok(())
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "float"
            }
        }
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_sqlite::SqliteAdapter;

    const SAMPLE_TOML: &str = r#"
        [[tools]]
        name = "get_orders_by_status"
        description = "Fetch orders filtered by status with an optional minimum total in cents."
        connection = "sqlite-sample"
        statement = "SELECT id, user_id, status, total_cents FROM orders WHERE status = ?1 AND total_cents >= ?2 ORDER BY id ASC"
        read_only = true
        max_rows = 50
        timeout_ms = 3000
        allowed_roles = ["agent", "developer", "admin"]

        [[tools.parameters]]
        name = "status"
        param_type = "string"
        description = "Order status filter"
        required = true

        [[tools.parameters]]
        name = "min_total_cents"
        param_type = "integer"
        description = "Minimum order total in cents"
        required = false
        default_value = 0
    "#;

    #[tokio::test]
    async fn test_named_tool_toml_load_validation_and_bound_execution() {
        let registry = NamedToolRegistry::from_toml_str(SAMPLE_TOML).unwrap();
        assert_eq!(registry.len(), 1);

        let adapter = SqliteAdapter::open_memory_with_seed(
            "sqlite-sample",
            r#"
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                total_cents INTEGER NOT NULL
            );
            INSERT INTO orders (id, user_id, status, total_cents) VALUES
                (101, 1, 'completed', 14900),
                (102, 2, 'completed', 4900),
                (103, 2, 'pending', 8900);
            "#,
        )
        .unwrap();

        let caller = CallerIdentity::local_agent("cursor-agent");
        let args = serde_json::json!({
            "status": "completed"
        });

        let result = registry
            .run_named_tool(
                &adapter,
                "req_nt_1",
                "get_orders_by_status",
                caller.clone(),
                &args,
                &ExecutionLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.returned_rows, 2);
        assert_eq!(result.rows[0][0], serde_json::json!(101));
        assert_eq!(result.rows[1][0], serde_json::json!(102));

        // SQL injection string passed as parameter must be bound literally (0 rows, no injection)
        let sqli_args = serde_json::json!({
            "status": "completed' OR '1'='1",
            "min_total_cents": 0
        });
        let sqli_res = registry
            .run_named_tool(
                &adapter,
                "req_nt_sqli",
                "get_orders_by_status",
                caller,
                &sqli_args,
                &ExecutionLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(sqli_res.returned_rows, 0);
    }

    #[test]
    fn test_named_tool_type_and_role_enforcement() {
        let registry = NamedToolRegistry::from_toml_str(SAMPLE_TOML).unwrap();
        let caller = CallerIdentity::local_agent("cursor-agent");

        // Wrong parameter type (integer instead of string for `status`)
        let mut bad_args = BTreeMap::new();
        bad_args.insert("status".to_string(), serde_json::json!(12345));
        let err = registry
            .validate_and_bind(
                "req_bad_type",
                "get_orders_by_status",
                &caller,
                &bad_args,
                &ExecutionLimits::default(),
            )
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGUMENT");

        // Unauthorized role
        let guest = CallerIdentity::new(
            "guest-user",
            "guest",
            vec!["sqlite-sample".to_string()],
            "http",
        );
        let mut valid_args = BTreeMap::new();
        valid_args.insert("status".to_string(), serde_json::json!("completed"));
        let role_err = registry
            .validate_and_bind(
                "req_role_err",
                "get_orders_by_status",
                &guest,
                &valid_args,
                &ExecutionLimits::default(),
            )
            .unwrap_err();
        assert_eq!(role_err.code(), "UNAUTHORIZED");
    }

    #[test]
    fn test_reject_mutating_tool_marked_read_only() {
        let yaml = r#"
tools:
  - name: "bad_delete_tool"
    description: "Mutating tool disguised as read_only"
    connection: "sqlite-sample"
    statement: "DELETE FROM orders WHERE id = $1"
    read_only: true
    parameters:
      - name: "id"
        param_type: "integer"
        description: "Order ID"
        required: true
"#;
        let err = NamedToolRegistry::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err.code(), "CONFIGURATION_ERROR");
    }
}
