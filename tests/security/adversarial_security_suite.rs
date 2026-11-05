//! Adversarial SQL & Governance Security Suite reference definitions.
//! Executed by Cargo via `crates/db-mcp-server/tests/contracts_and_security.rs`.

pub const ADVERSARIAL_SECURITY_CASES: [(&str, &str); 7] = [
    ("multi_statement_injection", "MULTI_STATEMENT_FORBIDDEN"),
    ("mutating_cte_read_only", "MUTATION_NOT_ALLOWED_IN_READ_ONLY"),
    ("privileged_function_call", "PRIVILEGED_FUNCTION_FORBIDDEN"),
    ("self_approval_attempt", "SELF_APPROVAL_FORBIDDEN"),
    ("approval_replay_attack", "APPROVAL_ALREADY_CONSUMED"),
    ("post_approval_schema_drift", "SCHEMA_DRIFT_DETECTED"),
    ("post_approval_sql_tampering", "APPROVAL_HASH_MISMATCH"),
];
