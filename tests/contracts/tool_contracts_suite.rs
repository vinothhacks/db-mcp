//! Contract test suite verifying all 16 MCP tools against `research/contracts/tool-contracts.json`.
//! Executed by Cargo via `crates/db-mcp-server/tests/contracts_and_security.rs`.

pub const CANONICAL_TOOLS: [&str; 16] = [
    "list_connections",
    "search_objects",
    "describe_object",
    "trace_table_dependencies",
    "get_procedure_call_graph",
    "execute_query",
    "explain_query",
    "run_named_tool",
    "database_health",
    "analyze_workload",
    "recommend_indexes",
    "propose_change",
    "get_change",
    "apply_change",
    "capture_schema",
    "diff_schema",
];

pub const REQUIRED_SUCCESS_ENVELOPE_FIELDS: [&str; 9] = [
    "request_id",
    "connection",
    "status",
    "columns",
    "rows",
    "returned_rows",
    "truncated",
    "warnings",
    "schema_version",
];
