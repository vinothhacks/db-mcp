//! Workspace Integration, Contract, and Adversarial Security Tests for DB-MCP.
//!
//! Exercises:
//! 1. Canonical MCP tool contract envelopes across all 24 tools (`research/contracts/tool-contracts.json`).
//! 2. Adversarial SQL & governance defenses (multi-statement, mutating CTE, privileged functions,
//!    self-approval rejection, approval replay prevention, schema drift, proposal tampering, and redaction).

use std::path::Path;

use db_mcp_changes::ChangeManager;
use db_mcp_core::CallerIdentity;
use db_mcp_mcp::{DbMcpRuntime, JsonRpcRequest, McpProtocolHandler, ServerConfig};
use serde_json::{json, Value};

fn assert_success_envelope(resp: &Value, expected_connection: Option<&str>) {
    assert_eq!(
        resp["status"], "ok",
        "Expected status='ok', got payload: {resp}"
    );
    assert!(
        resp["request_id"]
            .as_str()
            .map(|s| s.starts_with("req_"))
            .unwrap_or(false),
        "Missing or invalid request_id in {resp}"
    );
    if let Some(conn) = expected_connection {
        assert_eq!(resp["connection"], conn);
    } else {
        assert!(resp["connection"].is_string());
    }
    assert!(resp["columns"].is_array(), "columns must be an array");
    assert!(resp["rows"].is_array(), "rows must be an array");
    assert!(
        resp["returned_rows"].is_number(),
        "returned_rows must be numeric"
    );
    assert!(resp["truncated"].is_boolean(), "truncated must be boolean");
    assert!(resp["warnings"].is_array(), "warnings must be an array");
    assert!(
        resp["schema_version"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "schema_version must be a non-empty string"
    );
    assert_eq!(
        resp["_meta"]["provenance"]["untrusted_content"], true,
        "Database output must carry _meta.provenance.untrusted_content = true"
    );
}

fn assert_denied_envelope(resp: &Value, expected_code: &str) {
    assert_eq!(
        resp["status"], "denied",
        "Expected status='denied', got payload: {resp}"
    );
    assert_eq!(
        resp["code"], expected_code,
        "Expected denial code '{expected_code}', got payload: {resp}"
    );
    assert!(
        resp["message"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "Denial message must be non-empty"
    );
}

#[tokio::test]
async fn contract_suite_exercises_all_24_tools_and_matches_contract_schema() {
    // Verify canonical contract definition file exists and lists the required envelope fields
    let contracts_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../research/contracts/tool-contracts.json");
    let contracts_raw =
        std::fs::read_to_string(&contracts_path).expect("read tool-contracts.json");
    let contracts_doc: Value =
        serde_json::from_str(&contracts_raw).expect("parse tool-contracts.json");
    assert_eq!(contracts_doc["envelopes"]["success"]["status_value"], "ok");
    assert_eq!(
        contracts_doc["envelopes"]["denial"]["status_value"],
        "denied"
    );

    let runtime = DbMcpRuntime::default_demo().expect("default_demo runtime");
    let agent = CallerIdentity::local_agent("agent:contract-tester");
    let admin = CallerIdentity::admin("dba:release-approver");

    let tools = runtime.list_tools();
    assert_eq!(tools.len(), 24, "All 24 MCP tools must be registered");

    // 1. list_connections
    let r_list = runtime.call_tool("list_connections", json!({}), &agent).await;
    assert_success_envelope(&r_list, Some("server"));
    assert_eq!(r_list["data"].as_array().unwrap().len(), 3);

    // 2. search_objects
    let r_search = runtime
        .call_tool(
            "search_objects",
            json!({ "connection": "local-sqlite", "detail_level": "summary" }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_search, Some("local-sqlite"));

    // 3. describe_object
    let r_desc = runtime
        .call_tool(
            "describe_object",
            json!({ "connection": "local-sqlite", "object_name": "users", "detail_level": "full" }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_desc, Some("local-sqlite"));
    assert_eq!(r_desc["data"]["name"], "users");

    // 3b. trace_table_dependencies (multi-hop FK join path users -> orders -> order_items + dependent views/procedures)
    let r_trace = runtime
        .call_tool(
            "trace_table_dependencies",
            json!({
                "connection": "prod-postgres",
                "table_name": "users",
                "target_table": "order_items",
                "max_depth": 3
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_trace, Some("prod-postgres"));
    assert_eq!(r_trace["data"]["table_name"], "public.users");
    assert_eq!(
        r_trace["data"]["inbound_foreign_keys"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        r_trace["data"]["inbound_foreign_keys"][0]["from_table"],
        "public.orders"
    );
    let dep_objs = r_trace["data"]["dependent_objects"].as_array().unwrap();
    assert!(
        dep_objs.iter().any(|d| d["name"] == "active_user_orders" && d["object_type"] == "view"),
        "Expected active_user_orders view in dependent_objects: {dep_objs:?}"
    );
    assert!(
        dep_objs.iter().any(|d| d["name"] == "checkout_order" && d["object_type"] == "procedure"),
        "Expected checkout_order procedure in dependent_objects: {dep_objs:?}"
    );
    let hops = r_trace["data"]["join_path"]["hops"].as_array().unwrap();
    assert_eq!(hops.len(), 2, "Expected 2-hop join path users -> orders -> order_items");
    assert_eq!(hops[0]["from_table"], "public.users");
    assert_eq!(hops[0]["to_table"], "public.orders");
    assert_eq!(hops[1]["from_table"], "public.orders");
    assert_eq!(hops[1]["to_table"], "public.order_items");
    let synth_sql = r_trace["data"]["join_path"]["synthesized_join_sql"]
        .as_str()
        .unwrap();
    assert!(synth_sql.contains("JOIN public.orders ON"));
    assert!(synth_sql.contains("JOIN public.order_items ON"));
    assert!(r_trace["data"]["mermaid_diagram"]
        .as_str()
        .unwrap()
        .contains("flowchart LR"));

    // 3c. get_procedure_call_graph (checkout_order downstream callees, call chains, table touchpoints)
    let r_callgraph = runtime
        .call_tool(
            "get_procedure_call_graph",
            json!({
                "connection": "prod-postgres",
                "procedure_name": "checkout_order",
                "direction": "callees",
                "max_depth": 5
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_callgraph, Some("prod-postgres"));
    assert_eq!(r_callgraph["data"]["root_procedure"], "public.checkout_order");
    let cg_nodes = r_callgraph["data"]["nodes"].as_array().unwrap();
    let node_names: Vec<&str> = cg_nodes
        .iter()
        .filter_map(|n| n["name"].as_str())
        .collect();
    assert!(node_names.contains(&"checkout_order"));
    assert!(node_names.contains(&"reserve_inventory"));
    assert!(node_names.contains(&"record_order_audit"));
    assert!(node_names.contains(&"calculate_order_discount"));
    let checkout_node = cg_nodes
        .iter()
        .find(|n| n["name"] == "checkout_order")
        .unwrap();
    assert!(checkout_node["tables_read"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "public.users"));
    assert!(checkout_node["tables_written"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "public.orders"));
    assert!(!r_callgraph["data"]["call_chains"].as_array().unwrap().is_empty());
    assert!(r_callgraph["data"]["mermaid_diagram"]
        .as_str()
        .unwrap()
        .contains("flowchart TD"));

    // 4. execute_query
    let r_exec = runtime
        .call_tool(
            "execute_query",
            json!({
                "connection": "local-sqlite",
                "sql": "SELECT id, email, role FROM users ORDER BY id ASC"
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_exec, Some("local-sqlite"));
    assert_eq!(r_exec["returned_rows"], 2);

    // 5. explain_query
    let r_explain = runtime
        .call_tool(
            "explain_query",
            json!({
                "connection": "local-sqlite",
                "sql": "SELECT id, email FROM users WHERE id = 1"
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_explain, Some("local-sqlite"));

    // 6. run_named_tool
    let r_named = runtime
        .call_tool(
            "run_named_tool",
            json!({
                "tool_name": "get_user_by_id",
                "arguments": { "user_id": 1 }
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_named, Some("local-sqlite"));
    assert_eq!(r_named["returned_rows"], 1);

    // 7. database_health
    let r_health = runtime
        .call_tool("database_health", json!({ "connection": "prod-postgres" }), &agent)
        .await;
    assert_success_envelope(&r_health, Some("prod-postgres"));

    // 8. analyze_workload
    let r_workload = runtime
        .call_tool(
            "analyze_workload",
            json!({ "connection": "prod-postgres", "top_n": 5 }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_workload, Some("prod-postgres"));

    // 9. recommend_indexes
    let r_rec = runtime
        .call_tool(
            "recommend_indexes",
            json!({
                "connection": "prod-postgres",
                "queries": ["SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"]
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_rec, Some("prod-postgres"));

    // 10. capture_schema (before change)
    let r_cap1 = runtime
        .call_tool("capture_schema", json!({ "connection": "local-sqlite" }), &agent)
        .await;
    assert_success_envelope(&r_cap1, Some("local-sqlite"));
    let snap_before = r_cap1["data"].clone();

    // 11. propose_change
    let r_prop = runtime
        .call_tool(
            "propose_change",
            json!({
                "connection": "local-sqlite",
                "sql": "CREATE INDEX idx_orders_status ON orders (status)"
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_prop, Some("local-sqlite"));
    let change_id = r_prop["data"]["change_id"].as_str().unwrap().to_string();

    // 12. get_change
    let r_get = runtime
        .call_tool("get_change", json!({ "change_id": change_id }), &agent)
        .await;
    assert_success_envelope(&r_get, Some("local-sqlite"));
    assert_eq!(r_get["data"]["state"], "proposed");

    // Out-of-band approval by admin
    runtime
        .approve_change(&change_id, &admin, Some("Approved in contract test".to_string()))
        .expect("admin approve_change");

    // 13. apply_change
    let r_apply = runtime
        .call_tool("apply_change", json!({ "change_id": change_id }), &agent)
        .await;
    assert_success_envelope(&r_apply, Some("local-sqlite"));
    assert_eq!(r_apply["data"]["state"], "applied");

    // 14. diff_schema
    let r_cap2 = runtime
        .call_tool("capture_schema", json!({ "connection": "local-sqlite" }), &agent)
        .await;
    let snap_after = r_cap2["data"].clone();
    let r_diff = runtime
        .call_tool(
            "diff_schema",
            json!({
                "base_snapshot": snap_before,
                "target_snapshot": snap_after
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&r_diff, Some("local-sqlite"));
    assert_eq!(r_diff["data"]["is_identical"], false);
}

#[tokio::test]
async fn adversarial_security_and_governance_suite() {
    let handler = McpProtocolHandler::default_demo().expect("demo handler");
    let agent = CallerIdentity::local_agent("agent:adversary");
    let admin = CallerIdentity::admin("dba:sec-admin");

    // 1. Multi-statement SQL injection -> MULTI_STATEMENT_FORBIDDEN
    let multi = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "local-sqlite",
                "sql": "SELECT 1; DROP TABLE users"
            }),
            &agent,
        )
        .await;
    assert_denied_envelope(&multi, "MULTI_STATEMENT_FORBIDDEN");

    // 2. Data-modifying CTE in ReadOnly (analytics-mysql) & GovernedProduction (prod-postgres)
    let cte_ro = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "analytics-mysql",
                "sql": "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted"
            }),
            &agent,
        )
        .await;
    assert_denied_envelope(&cte_ro, "MUTATION_NOT_ALLOWED_IN_READ_ONLY");

    let cte_prod = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "prod-postgres",
                "sql": "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted"
            }),
            &agent,
        )
        .await;
    assert_denied_envelope(&cte_prod, "APPROVAL_REQUIRED");

    // 3. Privileged function calls (pg_read_file & load_file) -> PRIVILEGED_FUNCTION_FORBIDDEN
    let priv_pg = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "prod-postgres",
                "sql": "SELECT pg_read_file('/etc/passwd')"
            }),
            &agent,
        )
        .await;
    assert_denied_envelope(&priv_pg, "PRIVILEGED_FUNCTION_FORBIDDEN");

    let priv_mysql = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "analytics-mysql",
                "sql": "SELECT load_file('/etc/passwd')"
            }),
            &agent,
        )
        .await;
    assert_denied_envelope(&priv_mysql, "PRIVILEGED_FUNCTION_FORBIDDEN");

    // 4. Self-approval rejection -> SELF_APPROVAL_FORBIDDEN
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
    let change_id = prop["data"]["change_id"].as_str().unwrap().to_string();
    let self_err = handler.approve_change(&change_id, &agent, None).unwrap_err();
    assert_eq!(self_err.code(), "SELF_APPROVAL_FORBIDDEN");

    // 5. Approval replay attack -> first apply succeeds, second fails with APPROVAL_ALREADY_CONSUMED
    handler
        .approve_change(&change_id, &admin, Some("Approved once".to_string()))
        .expect("admin approval");
    let first_apply = handler
        .call_tool("apply_change", json!({ "change_id": change_id }), &agent)
        .await;
    assert_success_envelope(&first_apply, Some("prod-postgres"));

    let replay_apply = handler
        .call_tool("apply_change", json!({ "change_id": change_id }), &agent)
        .await;
    assert_denied_envelope(&replay_apply, "APPROVAL_ALREADY_CONSUMED");

    // 6a. Post-approval schema drift -> SCHEMA_DRIFT_DETECTED
    let drift_prop = handler
        .call_tool(
            "propose_change",
            json!({
                "connection": "local-sqlite",
                "sql": "UPDATE orders SET total_cents = 5000 WHERE id = 101"
            }),
            &agent,
        )
        .await;
    let drift_id = drift_prop["data"]["change_id"].as_str().unwrap().to_string();
    handler.approve_change(&drift_id, &admin, None).unwrap();

    // Mutate schema on local-sqlite before applying the approved change
    let alter_res = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "local-sqlite",
                "sql": "ALTER TABLE users ADD COLUMN drift_col TEXT"
            }),
            &agent,
        )
        .await;
    assert_eq!(alter_res["status"], "ok");

    let drift_apply = handler
        .call_tool("apply_change", json!({ "change_id": drift_id }), &agent)
        .await;
    assert_denied_envelope(&drift_apply, "SCHEMA_DRIFT_DETECTED");

    // 6b. Post-approval SQL tampering -> APPROVAL_HASH_MISMATCH
    let tmp_store = std::env::temp_dir().join(format!(
        "db_mcp_tamper_{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    let mut cfg = ServerConfig::default_demo();
    cfg.changes.storage_path = Some(tmp_store.display().to_string());
    // A persistent store needs an approval key for GovernedProduction apply_change (fail closed).
    cfg.changes.approval_key = Some("contract-test-approval-key-0123456789".to_string());
    let tamper_runtime = DbMcpRuntime::from_config(cfg).unwrap();
    let t_prop = tamper_runtime
        .call_tool(
            "propose_change",
            json!({
                "connection": "prod-postgres",
                "sql": "UPDATE orders SET status = 'completed' WHERE id = 101"
            }),
            &agent,
        )
        .await;
    let t_id = t_prop["data"]["change_id"].as_str().unwrap().to_string();
    let approved_prop = tamper_runtime.approve_change(&t_id, &admin, None).unwrap();

    let direct_mgr = ChangeManager::with_storage_path(&tmp_store).unwrap();
    let mut tampered = approved_prop.clone();
    tampered.sql = "DELETE FROM orders".to_string();
    tampered.normalized_sql = "DELETE FROM orders".to_string();
    direct_mgr.overwrite_proposal_unchecked(&tampered).unwrap();

    let tamper_apply = tamper_runtime
        .call_tool("apply_change", json!({ "change_id": t_id }), &agent)
        .await;
    assert_denied_envelope(&tamper_apply, "APPROVAL_HASH_MISMATCH");
    let _ = std::fs::remove_file(&tmp_store);

    // 7. Secret and sensitive column redaction across query results & audit logs
    let redacted_q = handler
        .call_tool(
            "execute_query",
            json!({
                "connection": "local-sqlite",
                "sql": "SELECT id, email, password_hash FROM users WHERE id = 1"
            }),
            &agent,
        )
        .await;
    assert_success_envelope(&redacted_q, Some("local-sqlite"));
    assert_eq!(redacted_q["rows"][0][2], "[REDACTED]");
    assert_eq!(redacted_q["columns"][2]["redacted"], true);

    // Trigger a failed parse containing an inline credential and verify audit log redaction
    let _ = handler
        .handle_jsonrpc(
            JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(99)),
                method: "tools/call".to_string(),
                params: Some(json!({
                    "name": "execute_query",
                    "arguments": {
                        "connection": "local-sqlite",
                        "sql": "INVALID SQL postgres://admin:topsecret123@db.internal:5432/prod"
                    }
                })),
            },
            &agent,
        )
        .await;

    let audit_dump = serde_json::to_string(&handler.audit_events().unwrap()).unwrap();
    assert!(
        !audit_dump.contains("topsecret123"),
        "Audit log must never leak raw DSN passwords"
    );
    assert!(
        !audit_dump.contains("hash_alice_secret"),
        "Audit log must never leak sensitive row values"
    );
}
