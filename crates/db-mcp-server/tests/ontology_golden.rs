//! End-to-end ontology flow through the governed runtime: discovery, agent proposals,
//! separation-of-duties review, publish, golden-question gates, governed execution, drift.

use std::path::PathBuf;

use db_mcp_core::CallerIdentity;
use db_mcp_mcp::{McpProtocolHandler, ServerConfig};
use db_mcp_ontology::{evaluate, GoldenCase, ReviewAction};
use serde_json::{json, Value};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn isolated_config() -> (ServerConfig, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "db-mcp-ontology-it-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().replace('\\', "/");
    let text = std::fs::read_to_string(repo_root().join("config/db-mcp.example.toml"))
        .unwrap()
        .replace(
            "sqlite://research/fixtures/sample.db",
            &format!("sqlite://{d}/sample.db"),
        )
        .replace(
            "\"research/traces/audit.jsonl\"",
            &format!("\"{d}/audit.jsonl\""),
        )
        .replace("\"research/traces/audit.db\"", &format!("\"{d}/audit.db\""))
        .replace(
            "\"research/traces/changes.db\"",
            &format!("\"{d}/changes.db\""),
        )
        .replace(
            "\"research/traces/ontology.db\"",
            &format!("\"{d}/ontology.db\""),
        );
    let mut cfg = ServerConfig::from_toml_str(&text).unwrap();
    cfg.ontology.storage_path = Some(format!("{d}/ontology.db"));
    (cfg, dir)
}

fn agent() -> CallerIdentity {
    CallerIdentity::new("agent-1", "agent", vec!["*".to_string()], "stdio")
}

fn reviewer() -> CallerIdentity {
    CallerIdentity::new("reviewer-1", "admin", vec!["*".to_string()], "cli")
}

async fn call(h: &McpProtocolHandler, tool: &str, args: Value, who: &CallerIdentity) -> Value {
    h.call_tool(tool, args, who).await
}

fn ok(v: &Value, label: &str) {
    assert_eq!(v["status"], "ok", "{label}: {v}");
    assert_eq!(
        v["_meta"]["provenance"]["untrusted_content"], true,
        "{label}: provenance"
    );
}

async fn propose(h: &McpProtocolHandler, def: Value) -> (String, u32) {
    let r = call(
        h,
        "propose_semantic_definition",
        json!({"connection": "local-sqlite", "definition": def}),
        &agent(),
    )
    .await;
    ok(&r, "propose");
    (
        r["data"]["definition"]["def_id"]
            .as_str()
            .unwrap()
            .to_string(),
        r["data"]["definition"]["version"].as_u64().unwrap() as u32,
    )
}

fn latest_version(h: &McpProtocolHandler, def_id: &str) -> u32 {
    h.ontology()
        .store
        .latest("default", "local-sqlite", def_id)
        .unwrap()
        .unwrap_or_else(|| panic!("{def_id} missing"))
        .version
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ontology_end_to_end_golden_flow() {
    let (cfg, dir) = isolated_config();
    let h = McpProtocolHandler::from_config(cfg).unwrap();

    // ---- surface: 24 tools, no review tool for agents ----
    let names: Vec<String> = h.list_tools().iter().map(|t| t.name.clone()).collect();
    assert_eq!(names.len(), 24, "{names:?}");
    assert!(names
        .iter()
        .all(|n| !n.contains("review") && !n.contains("publish")));

    // ---- not ready before publication ----
    let st = call(
        &h,
        "ontology_status",
        json!({"connection": "local-sqlite"}),
        &agent(),
    )
    .await;
    ok(&st, "status");
    assert_eq!(st["data"]["readiness"], "not_ready");
    let refused = call(
        &h,
        "plan_semantic_query",
        json!({"connection": "local-sqlite", "question": "count of orders"}),
        &agent(),
    )
    .await;
    ok(&refused, "plan before publish");
    assert_eq!(refused["data"]["status"], "not_answerable");

    // ---- discovery: deterministic, restricted tables excluded, idempotent ----
    let d1 = call(
        &h,
        "discover_ontology",
        json!({"connection": "local-sqlite"}),
        &agent(),
    )
    .await;
    ok(&d1, "discover");
    assert!(d1["data"]["candidates"].as_u64().unwrap() > 20, "{d1}");
    let all = h
        .ontology()
        .store
        .latest_all("default", "local-sqlite")
        .unwrap();
    assert!(
        all.iter().all(|d| !d.def_id.contains("internal_secrets")),
        "restricted table leaked into ontology"
    );
    assert!(all
        .iter()
        .any(|d| d.def_id == "relationship:main.orders(user_id)->main.users"));
    let pw = all
        .iter()
        .find(|d| d.def_id == "attribute:main.users.password_hash")
        .unwrap();
    assert!(pw.flags.sensitive, "sensitive column must be flagged");
    let d2 = call(
        &h,
        "discover_ontology",
        json!({"connection": "local-sqlite"}),
        &agent(),
    )
    .await;
    assert_eq!(
        d2["data"]["merge"]["inserted"], 0,
        "second discovery must be idempotent: {d2}"
    );

    // ---- agent proposals (typed bodies, no SQL) ----
    let (order_value, ov_v) = propose(&h, json!({
        "name": "order value", "synonyms": ["order total", "sales", "revenue"],
        "description": "Sum of order totals in cents",
        "body": {"type": "metric", "base_table": "orders", "aggregation": "sum", "column": "total_cents", "unit": "cents", "grain": "order"}
    })).await;
    let (item_revenue, ir_v) = propose(&h, json!({
        "name": "item revenue", "synonyms": ["revenue"],
        "body": {"type": "metric", "base_table": "order_items", "aggregation": "sum", "column": "unit_price_cents", "unit": "cents"}
    })).await;
    let (completed, c_v) = propose(&h, json!({
        "name": "completed order", "synonyms": ["fulfilled order"],
        "body": {"type": "filter", "table": "orders", "column": "status", "operator": "eq", "value": "completed"}
    })).await;

    // sensitive and restricted proposals are refused
    let bad = call(&h, "propose_semantic_definition", json!({"connection": "local-sqlite", "definition": {
        "name": "password filter", "body": {"type": "filter", "table": "users", "column": "password_hash", "operator": "eq", "value": "x"}}}), &agent()).await;
    assert_eq!(bad["code"], "ONTOLOGY_SENSITIVE_COLUMN", "{bad}");
    let bad = call(&h, "propose_semantic_definition", json!({"connection": "local-sqlite", "definition": {
        "name": "secret count", "body": {"type": "metric", "base_table": "internal_secrets", "aggregation": "count"}}}), &agent()).await;
    assert_eq!(bad["code"], "ONTOLOGY_UNKNOWN_OBJECT", "{bad}");
    // optimistic concurrency
    let conflict = call(&h, "propose_semantic_definition", json!({"connection": "local-sqlite", "def_id": order_value, "expected_version": 7,
        "definition": {"name": "order value", "body": {"type": "metric", "base_table": "orders", "aggregation": "sum", "column": "total_cents"}}}), &agent()).await;
    assert_eq!(conflict["code"], "ONTOLOGY_VERSION_CONFLICT", "{conflict}");

    // ---- separation of duties ----
    let self_review = h.review_ontology(
        &agent(),
        "local-sqlite",
        &order_value,
        ov_v,
        ReviewAction::Approve,
        None,
    );
    assert!(matches!(
        self_review,
        Err(db_mcp_core::DbMcpError::SelfApprovalForbidden(_))
    ));
    let proposer_as_admin = CallerIdentity::new("agent-1", "admin", vec!["*".to_string()], "cli");
    let own = h.review_ontology(
        &proposer_as_admin,
        "local-sqlite",
        &order_value,
        ov_v,
        ReviewAction::Approve,
        None,
    );
    assert!(
        matches!(own, Err(db_mcp_core::DbMcpError::SelfApprovalForbidden(_))),
        "proposer must not certify own draft"
    );

    // ---- reviewer certifies the curated set ----
    let curated = [
        "metric:main.orders.count",
        "metric:main.order_items.quantity.sum",
        "attribute:main.users.role",
        "attribute:main.order_items.sku",
        "attribute:main.inventory.sku",
        "relationship:main.orders(user_id)->main.users",
        "relationship:main.order_items(order_id)->main.orders",
        "relationship:main.order_items(sku)->main.inventory",
    ];
    for id in curated {
        let v = latest_version(&h, id);
        h.review_ontology(
            &reviewer(),
            "local-sqlite",
            id,
            v,
            ReviewAction::Approve,
            Some("golden fixture".into()),
        )
        .unwrap_or_else(|e| panic!("approve {id}: {e}"));
    }
    for (id, v) in [
        (&order_value, ov_v),
        (&item_revenue, ir_v),
        (&completed, c_v),
    ] {
        h.review_ontology(
            &reviewer(),
            "local-sqlite",
            id,
            v,
            ReviewAction::Approve,
            None,
        )
        .unwrap();
    }
    // an unpublished certified definition is still not usable
    let pre = call(
        &h,
        "plan_semantic_query",
        json!({"connection": "local-sqlite", "question": "total order value by user role"}),
        &agent(),
    )
    .await;
    assert_eq!(pre["data"]["status"], "not_answerable", "{pre}");

    let rev = h
        .publish_ontology(&reviewer(), "local-sqlite")
        .await
        .unwrap();
    assert_eq!(rev.def_refs.len(), curated.len() + 3);
    let st = call(
        &h,
        "ontology_status",
        json!({"connection": "local-sqlite"}),
        &agent(),
    )
    .await;
    assert_eq!(st["data"]["readiness"], "ready", "{st}");

    // ---- golden gates ----
    let cases: Vec<GoldenCase> = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("research/ontology/golden-local-sqlite.json"))
            .unwrap(),
    )
    .unwrap();
    let mut plans = Vec::new();
    for c in &cases {
        plans.push(
            h.plan_question(&agent(), "local-sqlite", &c.question, None)
                .await
                .unwrap(),
        );
    }
    let mut it = plans.into_iter();
    let report = evaluate(&cases, |_| it.next().unwrap());
    assert!(
        report.all_gates_passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );

    // ---- governed execution with a pinned plan ----
    let plan = call(
        &h,
        "plan_semantic_query",
        json!({"connection": "local-sqlite", "question": "total order value by user role"}),
        &agent(),
    )
    .await;
    ok(&plan, "plan");
    let plan_hash = plan["data"]["plan_hash"].as_str().unwrap().to_string();
    let ans = call(&h, "ask_semantic_question", json!({"connection": "local-sqlite", "question": "total order value by user role", "plan_hash": plan_hash}), &agent()).await;
    ok(&ans, "ask");
    assert_eq!(ans["data"]["answered"], true);
    assert_eq!(ans["returned_rows"], 2, "{ans}");
    assert_eq!(ans["rows"][0], json!(["admin", 4500]), "{ans}");
    let wrong_pin = call(&h, "ask_semantic_question", json!({"connection": "local-sqlite", "question": "total order value by user role", "plan_hash": "deadbeef"}), &agent()).await;
    assert_eq!(wrong_pin["code"], "ONTOLOGY_PLAN_MISMATCH");

    // ---- answers equal direct SQL; unsupported parts of a question are refused, never dropped ----
    for (question, sql) in [
        (
            "total order value by user role for completed orders",
            "SELECT u.role, SUM(o.total_cents) FROM orders o JOIN users u ON u.id = o.user_id WHERE o.status = 'completed' GROUP BY u.role ORDER BY 2 DESC",
        ),
        ("total order value where status is completed", "SELECT SUM(total_cents) FROM orders WHERE status = 'completed'"),
        (
            "total quantity by sku for completed orders",
            "SELECT i.sku, SUM(i.quantity) FROM order_items i JOIN orders o ON o.id = i.order_id WHERE o.status = 'completed' GROUP BY i.sku ORDER BY 2 DESC",
        ),
        ("count of completed orders", "SELECT COUNT(*) FROM orders WHERE status = 'completed'"),
    ] {
        let ans = call(&h, "ask_semantic_question", json!({"connection": "local-sqlite", "question": question}), &agent()).await;
        ok(&ans, question);
        assert_eq!(ans["data"]["answered"], true, "{question}: {ans}");
        let truth = call(&h, "execute_query", json!({"connection": "local-sqlite", "sql": sql}), &reviewer()).await;
        ok(&truth, "truth query");
        assert_eq!(ans["rows"], truth["rows"], "{question}: {ans}");
    }
    let filtered = call(&h, "ask_semantic_question", json!({"connection": "local-sqlite", "question": "total order value by user role for completed orders"}), &agent()).await;
    assert_eq!(filtered["rows"], json!([["admin", 4500]]), "{filtered}");
    for (question, why) in [
        (
            "average order value",
            "certified metric 'order value' is a sum, not an average",
        ),
        ("total order value for pending orders", "'pending'"),
        ("count of orders excluding completed orders", "'excluding'"),
        (
            "how many order items",
            "does not name what certified metric",
        ),
    ] {
        let ans = call(
            &h,
            "ask_semantic_question",
            json!({"connection": "local-sqlite", "question": question}),
            &agent(),
        )
        .await;
        ok(&ans, question);
        assert_eq!(ans["data"]["answered"], false, "{question}: {ans}");
        assert_eq!(
            ans["data"]["plan"]["status"], "not_answerable",
            "{question}: {ans}"
        );
        let missing = ans["data"]["plan"]["missing"].to_string();
        assert!(missing.contains(why), "{question}: {missing}");
    }

    // ---- search / describe / relationships ----
    let s = call(
        &h,
        "search_terms",
        json!({"connection": "local-sqlite", "query": "revenue"}),
        &agent(),
    )
    .await;
    ok(&s, "search");
    assert!(s["data"].as_array().unwrap().len() >= 2);
    let dsc = call(
        &h,
        "describe_term",
        json!({"connection": "local-sqlite", "def_id": order_value}),
        &agent(),
    )
    .await;
    ok(&dsc, "describe");
    assert_eq!(dsc["data"]["in_published_revision"], true);
    assert_eq!(dsc["data"]["certifications"][0]["reviewer"], "reviewer-1");
    let tr = call(
        &h,
        "trace_semantic_relationships",
        json!({"connection": "local-sqlite", "entity": "orders"}),
        &agent(),
    )
    .await;
    ok(&tr, "trace");
    assert!(tr["data"]["mermaid_diagram"]
        .as_str()
        .unwrap()
        .starts_with("flowchart LR"));

    // ---- schema drift makes dependent definitions stale and plans fail closed ----
    let ddl = call(&h, "execute_query", json!({"connection": "local-sqlite", "sql": "ALTER TABLE order_items RENAME COLUMN quantity TO qty"}), &agent()).await;
    ok(&ddl, "ddl");
    let stale = h
        .plan_question(&agent(), "local-sqlite", "quantity sold by sku", None)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(stale.status).unwrap(),
        "stale",
        "{:?}",
        stale.missing
    );
    let replay = call(&h, "ask_semantic_question", json!({"connection": "local-sqlite", "question": "total order value by user role", "plan_hash": plan_hash}), &agent()).await;
    assert_eq!(
        replay["code"], "ONTOLOGY_PLAN_MISMATCH",
        "pinned plan must not survive a schema change: {replay}"
    );
    let st = call(
        &h,
        "ontology_status",
        json!({"connection": "local-sqlite"}),
        &agent(),
    )
    .await;
    assert_eq!(st["data"]["readiness"], "degraded", "{st}");
    // unaffected definitions keep working
    let still = h
        .plan_question(
            &agent(),
            "local-sqlite",
            "total order value by user role",
            None,
        )
        .await
        .unwrap();
    assert!(still.is_answerable(), "{:?}", still.missing);

    // ---- audit covers ontology tools and admin actions ----
    let events = h.audit_events().unwrap();
    for tool in [
        "discover_ontology",
        "propose_semantic_definition",
        "plan_semantic_query",
        "ontology_publish",
        "ontology_review:approve",
    ] {
        assert!(
            events.iter().any(|e| e.tool_name == tool),
            "no audit event for {tool}"
        );
    }
    assert!(events
        .iter()
        .any(|e| e.tool_name.starts_with("ask_semantic_question:")));
    assert!(events
        .iter()
        .any(|e| e.tool_name == "ontology_review:approve"
            && e.denial_code.as_deref() == Some("SELF_APPROVAL_FORBIDDEN")));

    let _ = std::fs::remove_dir_all(dir);
}
