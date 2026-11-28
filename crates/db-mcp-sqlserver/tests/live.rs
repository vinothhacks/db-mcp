//! Live SQL Server tests. They run only when `DB_MCP_MSSQL_TEST_DSN` (db_datareader login) is set,
//! and the extra-grant checks only when `DB_MCP_MSSQL_FULL_TEST_DSN` is set too
//! (`eval "$(scripts/live-db-up.sh mssql)"`). Without them every test returns early.

use std::time::Duration;

use db_mcp_core::{
    AuthorizedQuery, CallerIdentity, CatalogObjectType, CatalogRequest, DatabaseAdapter,
    ExecutionLimits, ExplainFormat, ExplainRequest, HealthSeverity,
};
use db_mcp_sqlserver::{diagnostics, SqlServerAdapter, SqlServerConfig};
use serde_json::json;

fn dsn(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.trim().is_empty())
}

fn adapter(var: &str, read_only: bool) -> Option<SqlServerAdapter> {
    let d = dsn(var)?;
    let mut cfg = SqlServerConfig::new("mssql-live", d).with_read_only(read_only);
    cfg.catalog_ttl = Duration::from_secs(0);
    Some(SqlServerAdapter::new(cfg).unwrap())
}

fn query(sql: &str, params: Vec<serde_json::Value>, max_rows: usize) -> AuthorizedQuery {
    let limits = ExecutionLimits {
        timeout_ms: 10_000,
        max_rows,
        max_bytes: 1_048_576,
        allow_multi_statement: false,
    };
    AuthorizedQuery::new_read(
        "req_live",
        "mssql-live",
        CallerIdentity::local_agent("live-test"),
        sql,
        params,
        &limits,
    )
}

#[tokio::test]
async fn check_connection_reports_read_only_login() {
    let Some(a) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let c = a.check_connection().await;
    let raw = serde_json::to_string(&c).unwrap();
    assert!(c.can_connect && c.select_1, "{raw}");
    assert!(!c.can_write, "{raw}");
    assert!(c.object_count.unwrap_or(0) >= 7, "{raw}");
    assert!(
        c.server_version
            .as_deref()
            .unwrap_or("")
            .contains("SQL Server"),
        "{raw}"
    );
    assert!(
        c.warnings.iter().any(|w| w.contains("VIEW DEFINITION")),
        "{raw}"
    );
    assert_eq!(c.database.as_deref(), Some("dbmcp_fixture"));
    let pw = a.dsn().password().to_string();
    assert!(!raw.contains(&pw));
}

#[tokio::test]
async fn reads_map_values_and_bind_parameters() {
    let Some(a) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let r = a
        .execute(query(
            "SELECT event_id, payload, amount, ref_guid, raw_bytes, happened_at, is_valid FROM dbo.event_staging WHERE event_id = @P1",
            vec![json!(1)],
            10,
        ))
        .await
        .unwrap();
    assert_eq!(r.returned_rows, 1);
    assert_eq!(r.columns[2].data_type, "decimal");
    assert_eq!(
        r.rows[0],
        vec![
            json!(1),
            json!("first"),
            json!("12.50"),
            json!("6F9619FF-8B86-D011-B42D-00C04FC964FF"),
            json!("0xDEAD01"),
            json!("2025-05-06T07:08:09+02:00"),
            json!(true)
        ]
    );
    let nulls = a
        .execute(query(
            "SELECT payload, amount FROM dbo.event_staging WHERE event_id = ?",
            vec![json!(2)],
            10,
        ))
        .await
        .unwrap();
    assert_eq!(nulls.rows[0], vec![json!(null), json!(null)]);
    let dt = a
        .execute(query(
            "SELECT TOP (1) created_at FROM dbo.orders ORDER BY id",
            vec![],
            10,
        ))
        .await
        .unwrap();
    assert_eq!(dt.rows[0][0], json!("2025-01-03T10:00:00"));
    let s = a
        .execute(query(
            "SELECT email FROM dbo.users WHERE role = @P1 ORDER BY id",
            vec![json!("customer")],
            10,
        ))
        .await
        .unwrap();
    assert_eq!(s.returned_rows, 2);
}

#[tokio::test]
async fn truncation_and_timeouts_drop_the_connection_but_the_adapter_recovers() {
    let Some(a) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let r = a
        .execute(query("SELECT id FROM dbo.orders ORDER BY id", vec![], 2))
        .await
        .unwrap();
    assert!(r.truncated);
    assert_eq!(r.returned_rows, 2);
    let heavy = "SELECT COUNT_BIG(*) FROM sys.all_columns a CROSS JOIN sys.all_columns b CROSS JOIN sys.all_columns c";
    let t = tokio::time::timeout(
        Duration::from_millis(400),
        a.execute(query(heavy, vec![], 1)),
    )
    .await;
    assert!(t.is_err(), "heavy query should not finish in 400 ms");
    // Explicit cancellation through cancel().
    let q = query(heavy, vec![], 1);
    let id = q.execution_id.clone();
    let a2 = a.clone();
    let h = tokio::spawn(async move { a2.execute(q).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(a.cancel(id).await.unwrap());
    let res = h.await.unwrap();
    assert_eq!(res.unwrap_err().code(), "EXECUTION_CANCELLED");
    let ok = a
        .execute(query("SELECT COUNT(*) FROM dbo.orders", vec![], 5))
        .await
        .unwrap();
    assert_eq!(ok.rows[0][0], json!(4));
}

#[tokio::test]
async fn writes_are_refused_by_the_adapter_and_by_the_server() {
    let Some(ro) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let e = ro
        .execute(query("DELETE FROM dbo.audit_logs", vec![], 1))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "MUTATION_NOT_ALLOWED_IN_READ_ONLY");
    let e = ro
        .execute(query("SELECT 1 DELETE FROM dbo.audit_logs", vec![], 1))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "MUTATION_NOT_ALLOWED_IN_READ_ONLY");
    // A connection configured as writable still cannot write with a db_datareader login.
    let rw = adapter("DB_MCP_MSSQL_TEST_DSN", false).unwrap();
    let mut q = query("INSERT INTO dbo.audit_logs (order_id, event_type, created_at) VALUES (101, 'X', SYSUTCDATETIME())", vec![], 1);
    q.read_only = false;
    q.statement_class = db_mcp_core::SqlStatementClass::Write;
    let e = rw.execute(q).await.unwrap_err();
    assert_eq!(e.code(), "SERVER_PERMISSION_DENIED", "{e}");
    let n = ro
        .execute(query("SELECT COUNT(*) FROM dbo.audit_logs", vec![], 1))
        .await
        .unwrap();
    assert_eq!(n.rows[0][0], json!(1));
}

#[tokio::test]
async fn catalog_discovery_with_and_without_view_definition() {
    let Some(ro) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let resp = ro
        .discover(CatalogRequest {
            limit: 1000,
            detail_level: db_mcp_core::CatalogDetailLevel::Full,
            ..CatalogRequest::new("mssql-live")
        })
        .await
        .unwrap();
    let users = resp
        .objects
        .iter()
        .find(|o| o.name == "users")
        .expect("users table");
    assert_eq!(users.schema, "dbo");
    assert!(users
        .columns
        .iter()
        .any(|c| c.name == "id" && c.is_primary_key));
    assert_eq!(users.comment.as_deref(), Some("Customer accounts"));
    let orders = resp.objects.iter().find(|o| o.name == "orders").unwrap();
    assert_eq!(orders.foreign_keys[0].referenced_table, "dbo.users");
    assert_eq!(orders.foreign_keys[0].on_delete.as_deref(), Some("CASCADE"));
    assert_eq!(orders.estimated_rows, Some(4));
    assert!(resp
        .objects
        .iter()
        .any(|o| o.object_type == CatalogObjectType::View));
    let Some(full) = adapter("DB_MCP_MSSQL_FULL_TEST_DSN", true) else {
        return;
    };
    let resp = full
        .discover(CatalogRequest {
            limit: 1000,
            detail_level: db_mcp_core::CatalogDetailLevel::Full,
            ..CatalogRequest::new("mssql-live")
        })
        .await
        .unwrap();
    let proc_ = resp
        .objects
        .iter()
        .find(|o| o.name == "checkout_order")
        .expect("procedure visible with VIEW DEFINITION");
    assert!(proc_
        .definition
        .as_deref()
        .unwrap_or("")
        .contains("reserve_inventory"));
    assert!(resp
        .objects
        .iter()
        .any(|o| o.object_type == CatalogObjectType::Trigger));
    let view = resp
        .objects
        .iter()
        .find(|o| o.name == "active_user_orders")
        .unwrap();
    assert!(view.definition.is_some());
}

#[tokio::test]
async fn explain_needs_showplan_and_returns_estimated_plans() {
    let req = |sql: &str| ExplainRequest {
        request_id: "r".into(),
        connection: "mssql-live".into(),
        sql: sql.into(),
        params: vec![json!("completed")],
        analyze: false,
        format: ExplainFormat::Json,
        timeout_ms: 5_000,
    };
    let Some(ro) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let e = ro
        .explain(req("SELECT id FROM dbo.orders WHERE status = @P1"))
        .await
        .unwrap_err();
    assert_eq!(e.code(), "UNSUPPORTED_CAPABILITY");
    assert!(e.to_string().contains("GRANT SHOWPLAN"), "{e}");
    let Some(full) = adapter("DB_MCP_MSSQL_FULL_TEST_DSN", true) else {
        return;
    };
    let plan = full.explain(req("SELECT o.id, u.email FROM dbo.orders o JOIN dbo.users u ON u.id = o.user_id WHERE o.status = @P1")).await.unwrap();
    assert!(plan.estimated_cost.unwrap_or(0.0) > 0.0);
    assert!(!plan.seq_scans.is_empty() || !plan.index_scans.is_empty());
    assert!(plan.raw_plan.contains("ShowPlanXML"));
    let mut text = req("SELECT id FROM dbo.orders WHERE status = @P1");
    text.format = ExplainFormat::Text;
    assert!(full
        .explain(text)
        .await
        .unwrap()
        .raw_plan
        .contains("dbo.orders"));
    let mut analyze = req("SELECT 1");
    analyze.analyze = true;
    assert_eq!(
        full.explain(analyze).await.unwrap_err().code(),
        "UNSUPPORTED_CAPABILITY"
    );
    // Session is clean after SHOWPLAN: a normal query returns rows again.
    let r = full
        .execute(query("SELECT COUNT(*) FROM dbo.users", vec![], 1))
        .await
        .unwrap();
    assert_eq!(r.rows[0][0], json!(3));
}

#[tokio::test]
async fn health_degrades_without_grants_and_is_complete_with_them() {
    let Some(ro) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let h = diagnostics::database_health(&ro).await.unwrap();
    let ids: Vec<&str> = h.findings.iter().map(|f| f.check_id.as_str()).collect();
    for id in [
        "tables_without_primary_key",
        "heap_tables",
        "duplicate_indexes",
        "server_version",
        "server_state_checks",
    ] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    let heaps = h
        .findings
        .iter()
        .find(|f| f.check_id == "heap_tables")
        .unwrap();
    assert_eq!(heaps.evidence["tables"], json!(["dbo.event_staging"]));
    assert_eq!(heaps.severity, HealthSeverity::Warning);
    assert!(h.findings.iter().any(|f| f
        .remediation
        .as_deref()
        .unwrap_or("")
        .contains("GRANT VIEW SERVER STATE")));
    let Some(full) = adapter("DB_MCP_MSSQL_FULL_TEST_DSN", true) else {
        return;
    };
    let h = diagnostics::database_health(&full).await.unwrap();
    assert!(h.active_connections.is_some(), "{:?}", h.findings);
    assert!(h
        .findings
        .iter()
        .any(|f| f.check_id == "page_life_expectancy"));
    assert!(!h
        .findings
        .iter()
        .any(|f| f.check_id == "server_state_checks"));
}

#[tokio::test]
async fn workload_reads_query_store_with_grants() {
    let Some(full) = adapter("DB_MCP_MSSQL_FULL_TEST_DSN", true) else {
        return;
    };
    for _ in 0..3 {
        full.execute(query(
            "SELECT id, total_cents FROM dbo.orders WHERE status = @P1",
            vec![json!("completed")],
            10,
        ))
        .await
        .unwrap();
    }
    let (found, notes) = diagnostics::server_workload(&full, 10).await.unwrap();
    let (source, stats) = found.unwrap_or_else(|| panic!("no workload: {notes:?}"));
    assert!(
        source == "query_store" || source == "sys.dm_exec_query_stats",
        "{source}"
    );
    assert!(
        stats.iter().any(|s| s
            .normalized_query
            .to_ascii_lowercase()
            .contains("dbo.orders")),
        "{stats:?}"
    );
    assert!(!stats
        .iter()
        .any(|s| s.normalized_query.contains("db-mcp:internal")));
    let Some(ro) = adapter("DB_MCP_MSSQL_TEST_DSN", true) else {
        return;
    };
    let (found, notes) = diagnostics::server_workload(&ro, 10).await.unwrap();
    assert!(found.is_none());
    assert!(
        notes.iter().any(|n| n.contains("VIEW DATABASE STATE")),
        "{notes:?}"
    );
}
