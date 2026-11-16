//! SQL Server diagnostics: health, workload and index advice (advisory only, never executed).
//!
//! Catalog checks (missing primary keys, heaps, duplicate/disabled indexes, unindexed foreign
//! keys) always work with `db_datareader`. Server checks degrade to findings that name the grant
//! to request instead of failing:
//! - VIEW SERVER STATE: performance counters, connections, running requests, plan cache,
//!   missing-index DMVs;
//! - VIEW DATABASE STATE: Query Store (SQL Server 2016+);
//! - SHOWPLAN: optimizer missing-index hints for the queries passed to `recommend_indexes`.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use db_mcp_core::{
    CatalogObject, CatalogObjectType, DatabaseAdapter, DatabaseEngine, DbMcpResult, ExplainFormat, ExplainRequest,
    HealthFinding, HealthReport, HealthSeverity, IndexRecommendation, WorkloadAnalysis, WorkloadQueryStat,
};
use db_mcp_sql::{fingerprint_sql, hash_sql, parse_and_analyze_sql};
use serde_json::{json, Value};

use crate::showplan::MissingIndexHint;
use crate::{FetchedRows, ServerInfo, SqlServerAdapter};

/// Marker placed inside DB-MCP's own diagnostic statements so workload analysis can skip them.
pub const INTERNAL_MARKER: &str = "/* db-mcp:internal */";

fn finding(
    check_id: &str,
    category: &str,
    severity: HealthSeverity,
    summary: String,
    evidence: Value,
    remediation: Option<String>,
) -> HealthFinding {
    HealthFinding {
        check_id: check_id.to_string(),
        category: category.to_string(),
        severity,
        summary,
        evidence,
        remediation,
    }
}

fn needs_grant(check_id: &str, what: &str, grant: String) -> HealthFinding {
    finding(
        check_id,
        "permissions",
        HealthSeverity::Info,
        format!("{what} skipped: the login lacks the permission"),
        json!({ "required_grant": grant }),
        Some(format!("needs {grant}")),
    )
}

fn is_clustered(idx: &db_mcp_core::IndexSpec) -> bool {
    let t = idx.index_type.as_deref().unwrap_or("").to_ascii_lowercase();
    t.contains("clustered") && !t.contains("nonclustered")
}

/// Catalog-only checks: they need nothing beyond `db_datareader`.
pub fn catalog_findings(objects: &[CatalogObject]) -> Vec<HealthFinding> {
    let tables: Vec<&CatalogObject> = objects.iter().filter(|o| o.object_type == CatalogObjectType::Table).collect();
    let mut out = Vec::new();

    let no_pk: Vec<String> = tables.iter().filter(|t| !t.indexes.iter().any(|i| i.primary)).map(|t| t.qualified_name()).collect();
    out.push(finding(
        "tables_without_primary_key",
        "schema",
        if no_pk.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
        format!("{} table(s) without a primary key", no_pk.len()),
        json!({ "tables": no_pk }),
        (!no_pk.is_empty()).then(|| "Add a primary key (ALTER TABLE ... ADD CONSTRAINT pk_... PRIMARY KEY (...)) so rows are addressable and replication/CDC work.".to_string()),
    ));

    let heaps: Vec<String> = tables.iter().filter(|t| !t.indexes.iter().any(is_clustered)).map(|t| t.qualified_name()).collect();
    out.push(finding(
        "heap_tables",
        "storage",
        if heaps.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
        format!("{} heap table(s) without a clustered index", heaps.len()),
        json!({ "tables": heaps }),
        (!heaps.is_empty()).then(|| "Heaps suffer forwarded records and scan-heavy access; add a clustered index on a narrow, ever-increasing key.".to_string()),
    ));

    let mut dups = Vec::new();
    for t in &tables {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for i in &t.indexes {
            let key = i.columns.iter().map(|c| c.to_ascii_lowercase()).collect::<Vec<_>>().join(",");
            if key.is_empty() {
                continue;
            }
            if let Some(first) = seen.get(&key) {
                dups.push(json!({ "table": t.qualified_name(), "index": i.name, "duplicates": first, "columns": i.columns }));
            } else {
                seen.insert(key, i.name.clone());
            }
        }
    }
    out.push(finding(
        "duplicate_indexes",
        "indexes",
        if dups.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
        format!("{} duplicate index(es) with identical key columns", dups.len()),
        json!({ "duplicates": dups }),
        (!dups.is_empty()).then(|| "Drop the redundant index (DROP INDEX <name> ON <table>) after confirming no query hints reference it.".to_string()),
    ));

    let disabled: Vec<String> = tables
        .iter()
        .flat_map(|t| t.indexes.iter().filter(|i| i.index_type.as_deref().unwrap_or("").contains("disabled")).map(move |i| format!("{}.{}", t.qualified_name(), i.name)))
        .collect();
    out.push(finding(
        "disabled_indexes",
        "indexes",
        if disabled.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
        format!("{} disabled index(es)", disabled.len()),
        json!({ "indexes": disabled }),
        (!disabled.is_empty()).then(|| "Rebuild (ALTER INDEX ... REBUILD) or drop disabled indexes.".to_string()),
    ));

    let mut unindexed = Vec::new();
    for t in &tables {
        for fk in &t.foreign_keys {
            let covered = t.indexes.iter().any(|i| {
                i.columns.len() >= fk.columns.len()
                    && i.columns.iter().zip(fk.columns.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b))
            });
            if !covered {
                unindexed.push(json!({ "table": t.qualified_name(), "columns": fk.columns, "references": fk.referenced_table, "constraint": fk.name }));
            }
        }
    }
    out.push(finding(
        "unindexed_foreign_keys",
        "indexes",
        if unindexed.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Info },
        format!("{} foreign key(s) without a supporting index", unindexed.len()),
        json!({ "foreign_keys": unindexed }),
        (!unindexed.is_empty()).then(|| "Index foreign key columns used in joins and cascading deletes (see recommend_indexes).".to_string()),
    ));
    out
}

fn first_row(set: &FetchedRows) -> Option<&Vec<Value>> {
    set.rows.first()
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
}

/// `database_health` for a live SQL Server connection.
pub async fn database_health(adapter: &SqlServerAdapter) -> DbMcpResult<HealthReport> {
    let info = adapter.server_info().await?;
    let objects = adapter.catalog_objects().await?;
    let mut findings = catalog_findings(&objects);
    let mut report = HealthReport {
        connection: adapter.connection_id().to_string(),
        engine: DatabaseEngine::SqlServer,
        collected_at: Utc::now(),
        overall_status: HealthSeverity::Healthy,
        cache_hit_ratio: None,
        active_connections: None,
        max_connections: None,
        dead_tuples_total: None,
        invalid_indexes: objects
            .iter()
            .flat_map(|t| t.indexes.iter().filter(|i| i.index_type.as_deref().unwrap_or("").contains("disabled")).map(move |i| format!("{}.{}", t.qualified_name(), i.name)))
            .collect(),
        long_running_queries: 0,
        findings: Vec::new(),
    };

    findings.push(finding(
        "server_version",
        "server",
        if info.major_version > 0 && info.major_version <= 13 { HealthSeverity::Warning } else { HealthSeverity::Info },
        format!("SQL Server {} {} ({}), database {}", info.product_version, info.product_level, info.edition, info.database),
        json!({ "product_version": info.product_version, "major_version": info.major_version, "edition": info.edition, "product_level": info.product_level, "instance": info.instance_name }),
        (info.major_version > 0 && info.major_version <= 13).then(|| "SQL Server 2016 and older are out of extended support; plan an upgrade.".to_string()),
    ));

    let db_sql = format!(
        "SELECT {INTERNAL_MARKER} d.state_desc, d.recovery_model_desc, d.compatibility_level, d.page_verify_option_desc, \
         CAST(d.is_auto_create_stats_on AS int), CAST(d.is_auto_update_stats_on AS int), CAST(d.is_read_committed_snapshot_on AS int), \
         CAST(d.is_query_store_on AS int) FROM sys.databases d WHERE d.database_id = DB_ID()"
    );
    if let Ok(set) = adapter.query_rows(&db_sql, 1).await {
        if let Some(r) = first_row(&set) {
            let s = |i: usize| r.get(i).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let b = |i: usize| r.get(i).and_then(|v| v.as_i64()) == Some(1);
            let mut problems = Vec::new();
            if s(0) != "ONLINE" {
                problems.push(format!("database state is {}", s(0)));
            }
            if s(3) != "CHECKSUM" {
                problems.push(format!("PAGE_VERIFY is {} (CHECKSUM recommended)", s(3)));
            }
            if !b(4) || !b(5) {
                problems.push("automatic statistics creation/update is off".to_string());
            }
            findings.push(finding(
                "database_options",
                "configuration",
                if problems.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
                if problems.is_empty() { "Database options look healthy".to_string() } else { problems.join("; ") },
                json!({ "state": s(0), "recovery_model": s(1), "compatibility_level": r.get(2), "page_verify": s(3),
                        "auto_create_stats": b(4), "auto_update_stats": b(5), "read_committed_snapshot": b(6), "query_store_on": b(7) }),
                (!problems.is_empty()).then(|| "ALTER DATABASE ... SET PAGE_VERIFY CHECKSUM / AUTO_CREATE_STATISTICS ON / AUTO_UPDATE_STATISTICS ON".to_string()),
            ));
        }
    }

    let untrusted_sql = format!(
        "SELECT {INTERNAL_MARKER} OBJECT_SCHEMA_NAME(parent_object_id) + '.' + OBJECT_NAME(parent_object_id), name FROM sys.foreign_keys WHERE is_not_trusted = 1 \
         UNION ALL SELECT OBJECT_SCHEMA_NAME(parent_object_id) + '.' + OBJECT_NAME(parent_object_id), name FROM sys.check_constraints WHERE is_not_trusted = 1"
    );
    if let Ok(set) = adapter.query_rows(&untrusted_sql, 500).await {
        let items: Vec<String> = set.rows.iter().map(|r| format!("{}.{}", r[0].as_str().unwrap_or("?"), r[1].as_str().unwrap_or("?"))).collect();
        findings.push(finding(
            "untrusted_constraints",
            "schema",
            if items.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
            format!("{} untrusted foreign key/check constraint(s)", items.len()),
            json!({ "constraints": items }),
            (!items.is_empty()).then(|| "Re-validate with ALTER TABLE ... WITH CHECK CHECK CONSTRAINT ... so the optimizer can trust them.".to_string()),
        ));
    }

    if info.can_view_server_state() {
        let counters = format!(
            "SELECT {INTERNAL_MARKER} RTRIM(counter_name), cntr_value FROM sys.dm_os_performance_counters \
             WHERE (object_name LIKE '%Buffer Manager%' AND counter_name IN ('Page life expectancy', 'Buffer cache hit ratio', 'Buffer cache hit ratio base')) \
             OR (object_name LIKE '%General Statistics%' AND counter_name = 'User Connections')"
        );
        match adapter.query_rows(&counters, 50).await {
            Ok(set) => {
                let mut c: BTreeMap<String, f64> = BTreeMap::new();
                for r in &set.rows {
                    if let (Some(k), Some(v)) = (r[0].as_str(), num(r.get(1))) {
                        c.insert(k.to_string(), v);
                    }
                }
                if let (Some(hit), Some(base)) = (c.get("Buffer cache hit ratio"), c.get("Buffer cache hit ratio base")) {
                    if *base > 0.0 {
                        let ratio = hit / base;
                        report.cache_hit_ratio = Some(ratio);
                        findings.push(finding(
                            "buffer_cache_hit_ratio",
                            "memory",
                            if ratio < 0.90 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
                            format!("Buffer cache hit ratio is {:.2}%", ratio * 100.0),
                            json!({ "cache_hit_ratio": ratio }),
                            (ratio < 0.90).then(|| "Investigate memory pressure (max server memory) and scan-heavy queries.".to_string()),
                        ));
                    }
                }
                if let Some(ple) = c.get("Page life expectancy") {
                    findings.push(finding(
                        "page_life_expectancy",
                        "memory",
                        if *ple < 300.0 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
                        format!("Page life expectancy is {ple:.0} s"),
                        json!({ "page_life_expectancy_s": ple, "warning_below_s": 300 }),
                        (*ple < 300.0).then(|| "Pages leave the buffer pool quickly: add memory or reduce large scans.".to_string()),
                    ));
                }
            }
            Err(_) => findings.push(needs_grant("performance_counters", "Performance counter check", format!("GRANT VIEW SERVER STATE TO [{}]", info.login))),
        }
        let conns = format!(
            "SELECT {INTERNAL_MARKER} (SELECT COUNT(*) FROM sys.dm_exec_connections), @@MAX_CONNECTIONS, \
             (SELECT COUNT(*) FROM sys.dm_exec_requests r WHERE r.session_id <> @@SPID AND r.session_id > 50 AND r.total_elapsed_time > 60000), \
             (SELECT COUNT(*) FROM sys.dm_exec_requests r WHERE r.blocking_session_id <> 0)"
        );
        if let Ok(set) = adapter.query_rows(&conns, 1).await {
            if let Some(r) = first_row(&set) {
                let active = r.first().and_then(|v| v.as_i64()).unwrap_or(0);
                let max = r.get(1).and_then(|v| v.as_i64()).unwrap_or(32767).max(1);
                let long = r.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let blocked = r.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                report.active_connections = Some(active as u32);
                report.max_connections = Some(max as u32);
                report.long_running_queries = long as usize;
                let util = active as f64 / max as f64;
                findings.push(finding(
                    "connection_saturation",
                    "connections",
                    if util >= 0.8 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
                    format!("{active} of {max} connections in use"),
                    json!({ "active_connections": active, "max_connections": max }),
                    None,
                ));
                findings.push(finding(
                    "long_running_requests",
                    "queries",
                    if long > 0 || blocked > 0 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
                    format!("{long} request(s) running over 60 s, {blocked} blocked request(s)"),
                    json!({ "long_running": long, "blocked": blocked }),
                    (long > 0 || blocked > 0).then(|| "Inspect sys.dm_exec_requests / sys.dm_os_waiting_tasks for blockers.".to_string()),
                ));
            }
        }
    } else {
        findings.push(needs_grant(
            "server_state_checks",
            "Buffer cache, page life expectancy, connection and blocking checks",
            format!("GRANT VIEW SERVER STATE TO [{}]", info.login),
        ));
    }
    if !info.can_view_definition() {
        findings.push(needs_grant(
            "routine_visibility",
            "Procedure, function and trigger inspection",
            format!("GRANT VIEW DEFINITION TO [{}]", info.database_user),
        ));
    }

    report.overall_status = findings.iter().map(|f| f.severity).max().unwrap_or(HealthSeverity::Healthy);
    report.findings = findings;
    Ok(report)
}

fn is_internal(text: &str) -> bool {
    let up = text.to_ascii_uppercase();
    text.contains("db-mcp:internal")
        || up.contains("SHOWPLAN_XML")
        || up.contains("@@TRANCOUNT")
        || up.starts_with("SET ")
        || up.contains("FN_MY_PERMISSIONS")
        || up.contains("SYS.SQL_MODULES")
        || up.contains("SYS.EXTENDED_PROPERTIES")
        || up.trim_start().starts_with("BEGIN TRAN")
}

/// Parameterized statements are stored as `(@P1 bigint,@P2 nvarchar(4000))SELECT ...`.
pub fn strip_param_prefix(text: &str) -> &str {
    let t = text.trim_start();
    if !t.starts_with("(@") {
        return t;
    }
    let mut depth = 0i32;
    for (i, c) in t.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return t[i + 1..].trim_start();
                }
            }
            _ => {}
        }
    }
    t
}

fn rows_to_stats(set: &FetchedRows) -> Vec<WorkloadQueryStat> {
    set.rows
        .iter()
        .filter_map(|r| {
            let text = strip_param_prefix(r.get(1)?.as_str()?).to_string();
            if is_internal(&text) {
                return None;
            }
            let calls = num(r.get(2)).unwrap_or(0.0).max(0.0) as u64;
            let total = num(r.get(3)).unwrap_or(0.0);
            let normalized = fingerprint_sql(&text);
            Some(WorkloadQueryStat {
                query_id: r.first().map(|v| v.as_str().map(ToOwned::to_owned).unwrap_or_else(|| v.to_string())).unwrap_or_else(|| format!("q_{}", &hash_sql(&normalized)[..12])),
                tables_referenced: parse_and_analyze_sql(DatabaseEngine::SqlServer, &text).map(|a| a.referenced_tables).unwrap_or_default(),
                normalized_query: normalized,
                calls,
                total_exec_time_ms: total,
                mean_exec_time_ms: if calls > 0 { total / calls as f64 } else { total },
                rows: num(r.get(4)).unwrap_or(0.0).max(0.0) as u64,
                shared_blks_hit: num(r.get(5)).unwrap_or(0.0).max(0.0) as u64,
                shared_blks_read: num(r.get(6)).unwrap_or(0.0).max(0.0) as u64,
            })
        })
        .collect()
}

/// Statements from Query Store (preferred) or the plan cache; `None` when neither is readable.
pub async fn server_workload(adapter: &SqlServerAdapter, top_n: usize) -> DbMcpResult<(Option<(String, Vec<WorkloadQueryStat>)>, Vec<String>)> {
    let info = adapter.server_info().await?;
    let mut notes = Vec::new();
    let fetch = (top_n * 3).clamp(10, 300);
    if info.has_query_store() && info.can_view_database_state() {
        let qs = format!(
            "SELECT {INTERNAL_MARKER} TOP ({fetch}) CAST(q.query_id AS nvarchar(20)), qt.query_sql_text, SUM(rs.count_executions), \
             SUM(rs.avg_duration * rs.count_executions) / 1000.0, SUM(rs.avg_rowcount * rs.count_executions), \
             SUM(rs.avg_logical_io_reads * rs.count_executions), SUM(rs.avg_physical_io_reads * rs.count_executions) \
             FROM sys.query_store_query q JOIN sys.query_store_query_text qt ON qt.query_text_id = q.query_text_id \
             JOIN sys.query_store_plan p ON p.query_id = q.query_id JOIN sys.query_store_runtime_stats rs ON rs.plan_id = p.plan_id \
             WHERE qt.query_sql_text NOT LIKE '%db-mcp:internal%' \
             GROUP BY q.query_id, qt.query_sql_text ORDER BY 4 DESC"
        );
        match adapter.query_rows(&qs, fetch).await {
            Ok(set) => {
                let stats = rows_to_stats(&set);
                if !stats.is_empty() {
                    return Ok((Some(("query_store".to_string(), stats)), notes));
                }
                notes.push("Query Store is readable but holds no statements yet (or is OFF for this database).".to_string());
            }
            Err(e) => notes.push(format!("Query Store could not be read: {e}")),
        }
    } else if !info.has_query_store() {
        notes.push(format!("Query Store needs SQL Server 2016+ (server is {}).", info.product_version));
    } else {
        notes.push(format!("Query Store needs GRANT VIEW DATABASE STATE TO [{}].", info.database_user));
    }
    if info.can_view_server_state() {
        let dmv = format!(
            "SELECT {INTERNAL_MARKER} TOP ({fetch}) CONVERT(varchar(34), qs.query_hash, 1), \
             SUBSTRING(st.text, qs.statement_start_offset / 2 + 1, ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text) ELSE qs.statement_end_offset END - qs.statement_start_offset) / 2) + 1), \
             qs.execution_count, qs.total_elapsed_time / 1000.0, qs.total_rows, qs.total_logical_reads, qs.total_physical_reads \
             FROM sys.dm_exec_query_stats qs CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st \
             CROSS APPLY (SELECT CONVERT(int, value) AS dbid FROM sys.dm_exec_plan_attributes(qs.plan_handle) WHERE attribute = N'dbid') pa \
             WHERE pa.dbid = DB_ID() AND st.text NOT LIKE '%db-mcp:internal%' ORDER BY qs.total_elapsed_time DESC"
        );
        match adapter.query_rows(&dmv, fetch).await {
            Ok(set) => {
                let stats = rows_to_stats(&set);
                if !stats.is_empty() {
                    return Ok((Some(("sys.dm_exec_query_stats".to_string(), stats)), notes));
                }
            }
            Err(e) => notes.push(format!("plan cache could not be read: {e}")),
        }
    } else {
        notes.push(format!("plan-cache statistics need GRANT VIEW SERVER STATE TO [{}].", info.login));
    }
    Ok((None, notes))
}

/// Finish a workload analysis from server statistics.
pub fn workload_from_stats(connection: &str, source: String, mut stats: Vec<WorkloadQueryStat>, top_n: usize, notes: Vec<String>) -> WorkloadAnalysis {
    // Merge statements that share a fingerprint (literal-only differences).
    let mut merged: BTreeMap<String, WorkloadQueryStat> = BTreeMap::new();
    for s in stats.drain(..) {
        match merged.get_mut(&s.normalized_query) {
            Some(m) => {
                m.calls += s.calls;
                m.total_exec_time_ms += s.total_exec_time_ms;
                m.rows += s.rows;
                m.shared_blks_hit += s.shared_blks_hit;
                m.shared_blks_read += s.shared_blks_read;
                m.mean_exec_time_ms = if m.calls > 0 { m.total_exec_time_ms / m.calls as f64 } else { m.total_exec_time_ms };
            }
            None => {
                merged.insert(s.normalized_query.clone(), s);
            }
        }
    }
    let mut stats: Vec<WorkloadQueryStat> = merged.into_values().collect();
    stats.sort_by(|a, b| b.total_exec_time_ms.partial_cmp(&a.total_exec_time_ms).unwrap_or(std::cmp::Ordering::Equal));
    let total = stats.len();
    stats.truncate(top_n.max(1));
    let mut scores: BTreeMap<String, f64> = BTreeMap::new();
    for q in &stats {
        for t in &q.tables_referenced {
            *scores.entry(t.clone()).or_default() += q.total_exec_time_ms;
        }
    }
    let mut hot: Vec<(String, f64)> = scores.into_iter().collect();
    hot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    WorkloadAnalysis {
        connection: connection.to_string(),
        collected_at: Utc::now(),
        source,
        total_queries_analyzed: total,
        top_queries: stats,
        hot_tables: hot.into_iter().map(|(t, _)| t).collect(),
        notes,
    }
}

fn split_columns(raw: Option<&Value>) -> Vec<String> {
    raw.and_then(|v| v.as_str())
        .map(|s| s.split(',').map(|c| c.trim().trim_start_matches('[').trim_end_matches(']').to_string()).filter(|c| !c.is_empty()).collect())
        .unwrap_or_default()
}

/// Missing-index suggestions recorded by the server (`sys.dm_db_missing_index_*`).
pub async fn missing_index_dmv(adapter: &SqlServerAdapter, info: &ServerInfo) -> (Vec<(MissingIndexHint, Value)>, Vec<String>) {
    if !info.can_view_server_state() {
        return (Vec::new(), vec![format!("missing-index DMVs need GRANT VIEW SERVER STATE TO [{}]", info.login)]);
    }
    let sql = format!(
        "SELECT {INTERNAL_MARKER} TOP (50) OBJECT_SCHEMA_NAME(d.object_id), OBJECT_NAME(d.object_id), d.equality_columns, d.inequality_columns, d.included_columns, \
         s.avg_user_impact, s.user_seeks + s.user_scans, s.avg_total_user_cost, s.last_user_seek \
         FROM sys.dm_db_missing_index_details d JOIN sys.dm_db_missing_index_groups g ON g.index_handle = d.index_handle \
         JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle \
         WHERE d.database_id = DB_ID() ORDER BY s.avg_user_impact * (s.user_seeks + s.user_scans) DESC"
    );
    match adapter.query_rows(&sql, 50).await {
        Ok(set) => (
            set.rows
                .iter()
                .map(|r| {
                    let hint = MissingIndexHint {
                        impact: num(r.get(5)).unwrap_or(0.0),
                        schema: r[0].as_str().unwrap_or("dbo").to_string(),
                        table: r[1].as_str().unwrap_or_default().to_string(),
                        equality: split_columns(r.get(2)),
                        inequality: split_columns(r.get(3)),
                        include: split_columns(r.get(4)),
                    };
                    let evidence = json!({ "source": "sys.dm_db_missing_index_details", "avg_user_impact": r.get(5), "user_seeks_scans": r.get(6), "avg_total_user_cost": r.get(7), "last_user_seek": r.get(8) });
                    (hint, evidence)
                })
                .collect(),
            Vec::new(),
        ),
        Err(e) => (Vec::new(), vec![format!("missing-index DMVs could not be read: {e}")]),
    }
}

fn covered(objects: &[CatalogObject], table: &str, cols: &[String]) -> bool {
    let base = table.rsplit('.').next().unwrap_or(table);
    objects.iter().filter(|o| o.qualified_name().eq_ignore_ascii_case(table) || o.name.eq_ignore_ascii_case(base)).any(|o| {
        o.indexes.iter().any(|i| i.columns.len() >= cols.len() && i.columns.iter().zip(cols).all(|(a, b)| a.eq_ignore_ascii_case(b)))
    })
}

/// Turn a missing-index hint into an advisory recommendation.
pub fn hint_to_recommendation(hint: &MissingIndexHint, evidence: Value, queries: Vec<String>, observed: &str) -> IndexRecommendation {
    let table = hint.qualified_table();
    let columns: Vec<String> = hint.equality.iter().chain(hint.inequality.iter()).cloned().collect();
    let ddl = hint.suggested_ddl();
    let name = ddl.split_whitespace().nth(3).unwrap_or("ix_new").to_string();
    IndexRecommendation {
        id: format!("rec_{}_{}", hint.table, columns.join("_")),
        table_name: table.clone(),
        columns: columns.clone(),
        index_type: "nonclustered".to_string(),
        observed_issue: format!(
            "{observed}: SQL Server reports a missing index on '{table}' (equality [{}], inequality [{}], include [{}]).",
            hint.equality.join(", "),
            hint.inequality.join(", "),
            hint.include.join(", ")
        ),
        evidence,
        collected_at: Utc::now(),
        relevant_queries: queries,
        suggested_ddl: ddl,
        estimated_benefit: format!("Optimizer-estimated improvement of ~{:.1}% for the affected queries.", hint.impact),
        estimated_cost_reduction_pct: Some((hint.impact * 10.0).round() / 10.0),
        hypopg_validated: false,
        assumptions: vec![
            "Missing-index hints ignore existing index overlap, column order beyond equality/inequality, and write cost.".to_string(),
            "Statistics are current (AUTO_UPDATE_STATISTICS or a recent UPDATE STATISTICS).".to_string(),
        ],
        write_storage_tradeoffs: format!("Every INSERT/UPDATE/DELETE on '{table}' touching ({}) maintains the new index; storage grows by roughly the key plus included column size per row.", columns.join(", ")),
        required_privileges_extensions: vec![format!("ALTER on table '{table}' (CREATE INDEX); advisory only, DB-MCP never creates it")],
        validation_procedure: "In staging: SET SHOWPLAN_XML ON and compare StatementSubTreeCost before/after creating the index; after rollout watch sys.dm_db_index_usage_stats for seeks.".to_string(),
        recovery_considerations: format!("Non-destructive to data; roll back with DROP INDEX {name} ON {table};"),
    }
}

/// Merge server-side hints (DMV and showplan) with heuristic recommendations, de-duplicated by
/// (table, columns) and skipping hints already covered by an existing index.
pub fn merge_recommendations(
    objects: &[CatalogObject],
    server: Vec<IndexRecommendation>,
    heuristic: Vec<IndexRecommendation>,
    max: usize,
) -> Vec<IndexRecommendation> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for r in server.into_iter().chain(heuristic) {
        if r.columns.is_empty() || covered(objects, &r.table_name, &r.columns) {
            continue;
        }
        let key = format!("{}|{}", r.table_name.to_ascii_lowercase(), r.columns.join(",").to_ascii_lowercase());
        if seen.insert(key) {
            out.push(r);
        }
    }
    out.truncate(max.max(1));
    out
}

/// Showplan missing-index hints for the given queries (needs SHOWPLAN).
pub async fn showplan_hints(adapter: &SqlServerAdapter, queries: &[String]) -> (Vec<IndexRecommendation>, Vec<String>) {
    let mut recs = Vec::new();
    let mut notes = Vec::new();
    for q in queries.iter().take(20) {
        let req = ExplainRequest {
            request_id: "req_index_advice".to_string(),
            connection: adapter.connection_id().to_string(),
            sql: q.clone(),
            params: Vec::new(),
            analyze: false,
            format: ExplainFormat::Json,
            timeout_ms: 5_000,
        };
        match adapter.explain(req).await {
            Ok(plan) => {
                let hints = plan.structured_plan.as_ref().and_then(|s| s.get("missing_indexes")).and_then(|m| m.as_array()).cloned().unwrap_or_default();
                for h in hints {
                    let cols = |k: &str| h.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|c| c.as_str().map(ToOwned::to_owned)).collect()).unwrap_or_default();
                    let table = h.get("table").and_then(|v| v.as_str()).unwrap_or_default();
                    let (schema, tname) = table.split_once('.').unwrap_or(("dbo", table));
                    let hint = MissingIndexHint {
                        impact: h.get("impact").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        schema: schema.to_string(),
                        table: tname.to_string(),
                        equality: cols("equality_columns"),
                        inequality: cols("inequality_columns"),
                        include: cols("include_columns"),
                    };
                    let evidence = json!({ "source": "showplan_xml", "statement_subtree_cost": plan.estimated_cost, "impact": hint.impact });
                    recs.push(hint_to_recommendation(&hint, evidence, vec![fingerprint_sql(q)], "Estimated plan"));
                }
            }
            Err(e) => {
                notes.push(format!("estimated plan unavailable for a query: {e}"));
                if e.to_string().contains("SHOWPLAN") {
                    break;
                }
            }
        }
    }
    (recs, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{ColumnSpec, ForeignKeySpec, IndexSpec};

    fn table(name: &str, indexes: Vec<IndexSpec>, fks: Vec<ForeignKeySpec>) -> CatalogObject {
        CatalogObject {
            schema: "dbo".into(),
            name: name.into(),
            object_type: CatalogObjectType::Table,
            comment: None,
            estimated_rows: None,
            size_bytes: None,
            columns: vec![ColumnSpec { name: "id".into(), data_type: "int".into(), nullable: false, default_value: None, is_primary_key: false, comment: None, ordinal_position: 1 }],
            indexes,
            foreign_keys: fks,
            definition: None,
        }
    }
    fn idx(name: &str, cols: &[&str], primary: bool, ty: &str) -> IndexSpec {
        IndexSpec { name: name.into(), table_name: String::new(), columns: cols.iter().map(|c| c.to_string()).collect(), unique: primary, primary, index_type: Some(ty.into()), predicate: None, definition: None }
    }

    #[test]
    fn catalog_findings_detect_heaps_missing_pk_duplicates_and_unindexed_fks() {
        let objs = vec![
            table("users", vec![idx("pk_users", &["id"], true, "clustered")], vec![]),
            table("event_staging", vec![idx("ix_a", &["event_id"], false, "nonclustered"), idx("ix_b", &["event_id"], false, "nonclustered")], vec![]),
            table(
                "orders",
                vec![idx("pk_orders", &["id"], true, "clustered")],
                vec![ForeignKeySpec { name: Some("fk".into()), columns: vec!["user_id".into()], referenced_table: "dbo.users".into(), referenced_columns: vec!["id".into()], on_delete: None, on_update: None }],
            ),
        ];
        let f = catalog_findings(&objs);
        let get = |id: &str| f.iter().find(|x| x.check_id == id).unwrap();
        assert_eq!(get("tables_without_primary_key").evidence["tables"], json!(["dbo.event_staging"]));
        assert_eq!(get("heap_tables").evidence["tables"], json!(["dbo.event_staging"]));
        assert_eq!(get("duplicate_indexes").severity, HealthSeverity::Warning);
        assert_eq!(get("unindexed_foreign_keys").evidence["foreign_keys"][0]["table"], "dbo.orders");
        assert_eq!(get("disabled_indexes").severity, HealthSeverity::Healthy);
    }

    #[test]
    fn recommendations_merge_dedupe_and_skip_covered() {
        let objs = vec![table("orders", vec![idx("pk_orders", &["id"], true, "clustered")], vec![])];
        let h = |cols: &[&str]| MissingIndexHint { impact: 80.0, schema: "dbo".into(), table: "orders".into(), equality: cols.iter().map(|c| c.to_string()).collect(), inequality: vec![], include: vec![] };
        let a = hint_to_recommendation(&h(&["status"]), json!({}), vec![], "x");
        assert_eq!(a.suggested_ddl, "CREATE NONCLUSTERED INDEX ix_orders_status ON dbo.orders (status);");
        assert!(a.recovery_considerations.contains("DROP INDEX ix_orders_status ON dbo.orders"));
        let b = hint_to_recommendation(&h(&["status"]), json!({}), vec![], "y");
        let c = hint_to_recommendation(&h(&["id"]), json!({}), vec![], "z");
        let merged = merge_recommendations(&objs, vec![a, b], vec![c], 5);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn workload_merges_fingerprints_and_skips_internal_statements() {
        let set = FetchedRows {
            rows: vec![
                vec![json!("1"), json!("SELECT id FROM dbo.orders WHERE status = 'a'"), json!(2), json!(10.0), json!(4), json!(0), json!(0)],
                vec![json!("2"), json!("SELECT id FROM dbo.orders WHERE status = 'b'"), json!(3), json!(5.0), json!(6), json!(0), json!(0)],
                vec![json!("3"), json!("SELECT /* db-mcp:internal */ 1"), json!(9), json!(99.0), json!(1), json!(0), json!(0)],
            ],
            ..FetchedRows::default()
        };
        let stats = rows_to_stats(&set);
        assert_eq!(stats.len(), 2);
        let w = workload_from_stats("c", "query_store".into(), stats, 10, vec![]);
        assert_eq!(w.top_queries.len(), 1);
        assert_eq!(w.top_queries[0].calls, 5);
        assert!(!w.top_queries[0].normalized_query.contains("'a'"));
        assert_eq!(w.hot_tables, vec!["dbo.orders"]);
        assert_eq!(strip_param_prefix("(@P1 nvarchar(4000),@P2 int)SELECT 1"), "SELECT 1");
        assert_eq!(strip_param_prefix("SELECT (1)"), "SELECT (1)");
    }
}
