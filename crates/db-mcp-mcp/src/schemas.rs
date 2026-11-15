//! MCP JSON-RPC 2.0 wire types and JSON Schema definitions for the 24 DB-MCP tools.

use db_mcp_core::ToolProfile;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// MCP tool definition returned by `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub profile: ToolProfile,
    #[serde(rename = "inputSchema", alias = "input_schema")]
    pub input_schema: Value,
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

fn default_jsonrpc() -> String {
    "2.0".to_string()
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.unwrap_or(Value::Null),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<Value>, code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: id.unwrap_or(Value::Null),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

fn def(
    name: &str,
    description: &str,
    profile: ToolProfile,
    input_schema: Value,
) -> McpToolDefinition {
    McpToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        profile,
        input_schema,
    }
}

/// Build the MCP tool definitions filtered by `active_profiles`.
pub fn build_tool_definitions(active_profiles: &[ToolProfile]) -> Vec<McpToolDefinition> {
    let all = vec![
        def(
            "list_connections",
            "List configured database connections, operating modes, execution limits, and engine capabilities.",
            ToolProfile::Explore,
            json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        ),
        def(
            "search_objects",
            "Progressive schema discovery across tables, views, indexes, functions, and schemas with pagination.",
            ToolProfile::Explore,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string", "description": "Target connection identifier" },
                    "schema_pattern": { "type": "string", "description": "Optional SQL LIKE or substring filter on schema name" },
                    "name_pattern": { "type": "string", "description": "Optional SQL LIKE or substring filter on object name" },
                    "object_types": { "type": "array", "items": { "type": "string" } },
                    "detail_level": { "type": "string", "enum": ["names", "summary", "full"], "default": "summary" },
                    "limit": { "type": "integer", "default": 50 },
                    "offset": { "type": "integer", "default": 0 }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "describe_object",
            "Inspect full or summary metadata (columns, indexes, foreign keys, DDL) for a single database object.",
            ToolProfile::Explore,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "schema": { "type": "string" },
                    "object_name": { "type": "string" },
                    "detail_level": { "type": "string", "enum": ["names", "summary", "full"], "default": "full" }
                },
                "required": ["connection", "object_name"]
            }),
        ),
        def(
            "trace_table_dependencies",
            "Trace table foreign-key relationships (inbound and outbound), transitive table lineage, dependent views/triggers/procedures, and optional shortest multi-hop join paths with Mermaid diagrams.",
            ToolProfile::Explore,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string", "description": "Target connection identifier" },
                    "table_name": { "type": "string", "description": "Source table name (qualified or unqualified)" },
                    "target_table": { "type": "string", "description": "Optional target table to compute the shortest multi-hop FK join path and synthesized JOIN SQL" },
                    "max_depth": { "type": "integer", "default": 3, "description": "Maximum traversal depth for transitive table relationships and join paths" }
                },
                "required": ["connection", "table_name"]
            }),
        ),
        def(
            "get_procedure_call_graph",
            "Analyze stored procedures and functions to build caller/callee call graphs, transitive call chains, cycle detection, table read/write touchpoints, and Mermaid diagrams.",
            ToolProfile::Explore,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string", "description": "Target connection identifier" },
                    "procedure_name": { "type": "string", "description": "Optional root procedure or function name to trace; if omitted, builds the full schema call graph" },
                    "direction": { "type": "string", "enum": ["callees", "callers", "both"], "default": "both", "description": "Traversal direction from procedure_name" },
                    "max_depth": { "type": "integer", "default": 5, "description": "Maximum call-chain traversal depth" }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "execute_query",
            "Execute a bounded, policy-governed SQL statement with parameter binding and disclosure controls.",
            ToolProfile::Query,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "sql": { "type": "string" },
                    "params": { "type": "array", "items": {} },
                    "timeout_ms": { "type": "integer" },
                    "max_rows": { "type": "integer" },
                    "max_bytes": { "type": "integer" },
                    "change_id": { "type": "string" }
                },
                "required": ["connection", "sql"]
            }),
        ),
        def(
            "explain_query",
            "Generate a structured EXPLAIN plan for a SQL statement without side effects.",
            ToolProfile::Query,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "sql": { "type": "string" },
                    "params": { "type": "array", "items": {} },
                    "analyze": { "type": "boolean", "default": false },
                    "format": { "type": "string", "enum": ["text", "json"], "default": "json" },
                    "timeout_ms": { "type": "integer" }
                },
                "required": ["connection", "sql"]
            }),
        ),
        def(
            "run_named_tool",
            "Execute a declarative parameterized named SQL tool registered in the server configuration.",
            ToolProfile::Query,
            json!({
                "type": "object",
                "properties": {
                    "tool_name": { "type": "string" },
                    "arguments": { "type": "object" }
                },
                "required": ["tool_name"]
            }),
        ),
        def(
            "database_health",
            "Run PostgreSQL/database health checks (connections, cache hit ratio, dead tuples, invalid/duplicate indexes, long-running queries).",
            ToolProfile::Diagnose,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "analyze_workload",
            "Rank top queries by total and mean execution time with pg_stat_statements or runtime telemetry.",
            ToolProfile::Diagnose,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "top_n": { "type": "integer", "default": 10 }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "recommend_indexes",
            "Recommend candidate B-Tree indexes from workload queries and validate cost reductions via HypoPG.",
            ToolProfile::Diagnose,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "queries": { "type": "array", "items": { "type": "string" } },
                    "max_recommendations": { "type": "integer", "default": 5 }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "propose_change",
            "Create a cryptographically bound change proposal (`chg_*`) for a write or DDL statement in governed production mode.",
            ToolProfile::Change,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "sql": { "type": "string" },
                    "params": { "type": "array", "items": {} },
                    "constraints": {},
                    "ttl_seconds": { "type": "integer" }
                },
                "required": ["connection", "sql"]
            }),
        ),
        def(
            "get_change",
            "Inspect the lifecycle status, approval hash, reversibility, and audit metadata of a change proposal.",
            ToolProfile::Change,
            json!({
                "type": "object",
                "properties": {
                    "change_id": { "type": "string" }
                },
                "required": ["change_id"]
            }),
        ),
        def(
            "apply_change",
            "Apply an out-of-band approved change proposal after verifying approval hash, TTL, and live schema fingerprint.",
            ToolProfile::Change,
            json!({
                "type": "object",
                "properties": {
                    "change_id": { "type": "string" }
                },
                "required": ["change_id"]
            }),
        ),
        def(
            "capture_schema",
            "Capture a deterministic point-in-time schema snapshot with a `snapshot_<hash>` version identifier.",
            ToolProfile::Schema,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "schema_pattern": { "type": "string" }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "diff_schema",
            "Compute a structural schema diff between two snapshots or connections with DDL and reversal safety classification.",
            ToolProfile::Schema,
            json!({
                "type": "object",
                "properties": {
                    "base_snapshot": { "type": "object" },
                    "target_snapshot": { "type": "object" },
                    "base_connection": { "type": "string" },
                    "target_connection": { "type": "string" },
                    "schema_pattern": { "type": "string" }
                }
            }),
        ),
        def(
            "ontology_status",
            "Ontology readiness for a connection: published revision, coverage, counts per lifecycle status, stale definitions after schema drift, and ready/degraded/not_ready reasons.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string", "description": "Target connection identifier" }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "discover_ontology",
            "Deterministically extract candidate business terms, attributes, metrics and relationships from the policy-visible catalog (FKs, columns, routine touchpoints). Writes unverified candidates only; nothing is usable for SQL until a human reviewer certifies and publishes it.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "infer_joins": { "type": "boolean", "description": "Also propose `<x>_id` joins without declared FKs (unverified candidates). Defaults to the server setting." }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "search_terms",
            "Search ontology definitions (terms, synonyms, metrics, relationships, filters) with lexical ranking; returns status, evidence strength and provenance.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "query": { "type": "string" },
                    "kinds": { "type": "array", "items": { "type": "string", "enum": ["entity", "attribute", "relationship", "metric", "filter"] } },
                    "statuses": { "type": "array", "items": { "type": "string", "enum": ["discovered", "proposed", "in_review", "certified", "published", "stale", "deprecated", "rejected"] } },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                },
                "required": ["connection", "query"]
            }),
        ),
        def(
            "describe_term",
            "Describe one ontology definition: current body, mapped columns, every version, certifications, evidence and whether it is in the published revision.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "def_id": { "type": "string", "description": "Definition id (e.g. metric:main.orders.total_cents.sum)" },
                    "name": { "type": "string", "description": "Alternative: exact definition name" }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "trace_semantic_relationships",
            "Walk the semantic entity graph (declared and inferred relationships) with cardinality, certification status and evidence strength, plus a Mermaid diagram.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "entity": { "type": "string", "description": "Optional start table/entity" },
                    "max_depth": { "type": "integer", "minimum": 1, "maximum": 10, "default": 3 },
                    "certified_only": { "type": "boolean", "default": false }
                },
                "required": ["connection"]
            }),
        ),
        def(
            "propose_semantic_definition",
            "Propose a new or revised semantic definition (entity, attribute, relationship, metric or filter) as a reviewable draft. Bodies are typed (no free-form SQL). Requires expected_version when revising. Never certifies or publishes.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "def_id": { "type": "string", "description": "Existing definition to revise" },
                    "expected_version": { "type": "integer", "minimum": 1 },
                    "definition": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "synonyms": { "type": "array", "items": { "type": "string" } },
                            "description": { "type": "string" },
                            "body": {
                                "type": "object",
                                "description": "One of: {type:'entity',table} | {type:'attribute',table,column,unit?} | {type:'relationship',from_table,to_table,column_pairs:[[from,to]],cardinality:'many_to_one'|'one_to_many'|'one_to_one'|'many_to_many',source:'manual'} | {type:'metric',base_table,aggregation:'sum'|'count'|'count_distinct'|'avg'|'min'|'max',column?,default_filters?,unit?,grain?} | {type:'filter',table,column,operator:'eq'|'ne'|'gt'|'gte'|'lt'|'lte'|'in'|'is_null'|'is_not_null',value}"
                            }
                        },
                        "required": ["name", "body"]
                    }
                },
                "required": ["connection", "definition"]
            }),
        ),
        def(
            "plan_semantic_query",
            "Check whether a natural-language question is answerable from the certified, published ontology and return the typed parameterized SQL plan with provenance, assumptions and limitations, without executing it. Refuses (not_answerable / ambiguous / stale) instead of guessing.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "question": { "type": "string", "maxLength": 1000 },
                    "max_rows": { "type": "integer", "minimum": 1, "maximum": 10000 }
                },
                "required": ["connection", "question"]
            }),
        ),
        def(
            "ask_semantic_question",
            "Plan a question from the certified ontology and execute the validated SQL through the governed executor (policy, limits, redaction, audit). Returns rows plus SQL, revision, evidence and caveats. Pass plan_hash to pin a previously reviewed plan.",
            ToolProfile::Ontology,
            json!({
                "type": "object",
                "properties": {
                    "connection": { "type": "string" },
                    "question": { "type": "string", "maxLength": 1000 },
                    "plan_hash": { "type": "string", "description": "Optional: refuse unless the recomputed plan matches this hash" },
                    "max_rows": { "type": "integer", "minimum": 1, "maximum": 10000 }
                },
                "required": ["connection", "question"]
            }),
        ),
    ];

    all.into_iter()
        .filter(|tool| active_profiles.contains(&tool.profile))
        .collect()
}
