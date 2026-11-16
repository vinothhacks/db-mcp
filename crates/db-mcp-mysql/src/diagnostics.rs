//! Live MySQL diagnostics: `database_health` from `SHOW GLOBAL STATUS/VARIABLES`,
//! `information_schema` and the catalog; `analyze_workload` from
//! `performance_schema.events_statements_summary_by_digest`; MySQL-specific finishing of the
//! heuristic index advice (real `EXPLAIN` validation, MySQL DDL, advisory only).
//!
//! A missing optional grant never fails a tool: it becomes an `info` finding / note naming the
//! `GRANT` to request.

use std::collections::BTreeMap;

use chrono::Utc;
use db_mcp_core::{
    CatalogObject, CatalogObjectType, DbMcpError, DbMcpResult, ExplainFormat, ExplainRequest, HealthFinding,
    HealthReport, HealthSeverity, IndexRecommendation, WorkloadAnalysis, WorkloadQueryStat, DatabaseEngine,
};
use db_mcp_sql::{fingerprint_sql, hash_sql, parse_and_analyze_sql};
use serde_json::{json, Value as J};

use crate::live::{LiveMySql, CODE_DATABASE_PERMISSION_DENIED};

const DIAG_TIMEOUT_MS: u64 = 10_000;

fn as_u64(v: Option<&J>) -> Option<u64> {
    match v {
        Some(J::Number(n)) => n.as_u64().or_else(|| n.as_f64().map(|f| f.max(0.0) as u64)),
        Some(J::String(s)) => s.trim().parse::<u64>().ok().or_else(|| s.trim().parse::<f64>().ok().map(|f| f.max(0.0) as u64)),
        _ => None,
    }
}

fn as_str(v: Option<&J>) -> String {
    match v {
        Some(J::String(s)) => s.clone(),
        Some(J::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn finding(check_id: &str, category: &str, severity: HealthSeverity, summary: String, evidence: J, remediation: Option<String>) -> HealthFinding {
    HealthFinding {
        check_id: check_id.to_string(),
        category: category.to_string(),
        severity,
        summary,
        evidence,
        remediation,
    }
}

/// Non-unique indexes whose column list is a leading prefix of another index on the same table.
pub fn redundant_indexes(objects: &[CatalogObject]) -> Vec<J> {
    let mut out = Vec::new();
    for t in objects.iter().filter(|o| o.object_type == CatalogObjectType::Table) {
        for a in t.indexes.iter().filter(|i| !i.unique && !i.primary) {
            if let Some(b) = t.indexes.iter().find(|b| {
                b.name != a.name
                    && b.columns.len() > a.columns.len()
                    && b.columns.iter().zip(a.columns.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
            }) {
                out.push(json!({
                    "table": t.qualified_name(),
                    "redundant_index": a.name,
                    "covered_by": b.name,
                    "columns": a.columns,
                }));
            }
        }
    }
    out
}

/// Base tables without a primary key.
pub fn tables_without_primary_key(objects: &[CatalogObject]) -> Vec<String> {
    objects
        .iter()
        .filter(|o| o.object_type == CatalogObjectType::Table)
        .filter(|o| !o.indexes.iter().any(|i| i.primary) && !o.columns.iter().any(|c| c.is_primary_key))
        .map(|o| o.qualified_name())
        .collect()
}

/// Turn `SHOW GLOBAL STATUS` / `VARIABLES` rows into a lowercase name -> value map.
fn kv(rows: &[Vec<J>]) -> BTreeMap<String, String> {
    rows.iter().map(|r| (as_str(r.first()).to_ascii_lowercase(), as_str(r.get(1)))).collect()
}

/// Build the health report from collected inputs (pure; unit-tested without a server).
pub fn build_health_report(
    connection: &str,
    status: Option<&BTreeMap<String, String>>,
    variables: Option<&BTreeMap<String, String>>,
    long_running: Option<&[Vec<J>]>,
    has_process: bool,
    workload_readable: Option<bool>,
    objects: &[CatalogObject],
    user: &str,
) -> HealthReport {
    let mut findings = Vec::new();
    let num = |m: Option<&BTreeMap<String, String>>, k: &str| m.and_then(|m| m.get(k)).and_then(|v| v.parse::<f64>().ok());

    let threads = num(status, "threads_connected");
    let max_conn = num(variables, "max_connections");
    if let (Some(t), Some(m)) = (threads, max_conn) {
        let ratio = if m > 0.0 { t / m } else { 0.0 };
        let severity = if ratio >= 0.9 {
            HealthSeverity::Critical
        } else if ratio >= 0.75 {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Healthy
        };
        findings.push(finding(
            "connection_saturation",
            "connections",
            severity,
            format!("{t:.0} of max_connections={m:.0} in use ({:.1}%)", ratio * 100.0),
            json!({"threads_connected": t, "threads_running": num(status, "threads_running"), "max_connections": m, "max_used_connections": num(status, "max_used_connections")}),
            (severity != HealthSeverity::Healthy).then(|| "Raise max_connections or reduce idle client pools.".to_string()),
        ));
    }

    let reads = num(status, "innodb_buffer_pool_reads");
    let requests = num(status, "innodb_buffer_pool_read_requests");
    let hit_ratio = match (reads, requests) {
        (Some(r), Some(q)) if q > 0.0 => Some((1.0 - r / q).clamp(0.0, 1.0)),
        _ => None,
    };
    if let Some(h) = hit_ratio {
        let severity = if requests.unwrap_or(0.0) >= 10_000.0 && h < 0.95 { HealthSeverity::Warning } else { HealthSeverity::Healthy };
        findings.push(finding(
            "buffer_pool_hit_ratio",
            "memory",
            severity,
            format!("InnoDB buffer pool hit ratio {:.2}%", h * 100.0),
            json!({"innodb_buffer_pool_reads": reads, "innodb_buffer_pool_read_requests": requests, "innodb_buffer_pool_size": variables.and_then(|v| v.get("innodb_buffer_pool_size"))}),
            (severity != HealthSeverity::Healthy).then(|| "Increase innodb_buffer_pool_size towards the working-set size.".to_string()),
        ));
    }

    if let Some(slow) = num(status, "slow_queries") {
        findings.push(finding(
            "slow_queries",
            "performance",
            if slow > 0.0 { HealthSeverity::Info } else { HealthSeverity::Healthy },
            format!("{slow:.0} statement(s) exceeded long_query_time since server start"),
            json!({"slow_queries": slow, "long_query_time": variables.and_then(|v| v.get("long_query_time")), "slow_query_log": variables.and_then(|v| v.get("slow_query_log")), "uptime_s": num(status, "uptime")}),
            (slow > 0.0).then(|| "Review the slow query log or analyze_workload for the statements responsible.".to_string()),
        ));
    }
    if let (Some(disk), Some(all)) = (num(status, "created_tmp_disk_tables"), num(status, "created_tmp_tables")) {
        if all > 0.0 {
            let ratio = disk / all;
            findings.push(finding(
                "tmp_tables_on_disk",
                "performance",
                if all >= 100.0 && ratio > 0.25 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
                format!("{:.1}% of internal temporary tables spilled to disk", ratio * 100.0),
                json!({"created_tmp_disk_tables": disk, "created_tmp_tables": all}),
                None,
            ));
        }
    }
    if status.is_none() {
        findings.push(finding(
            "server_status_visibility",
            "permissions",
            HealthSeverity::Info,
            "SHOW GLOBAL STATUS is not readable by this login; server counters are omitted".to_string(),
            json!({"user": user}),
            Some(format!("Optional: GRANT SELECT ON performance_schema.global_status TO '{user}'")),
        ));
    }

    let mut long_count = 0usize;
    if let Some(rows) = long_running {
        long_count = rows.len();
        let sample: Vec<J> = rows
            .iter()
            .take(10)
            .map(|r| json!({"id": r.first(), "user": r.get(1), "seconds": r.get(2), "state": r.get(3), "query_fingerprint": fingerprint_sql(&as_str(r.get(4)))}))
            .collect();
        findings.push(finding(
            "long_running_queries",
            "activity",
            if long_count > 0 { HealthSeverity::Warning } else { HealthSeverity::Healthy },
            format!("{long_count} statement(s) running for 30 s or more"),
            json!({"queries": sample, "all_sessions_visible": has_process}),
            (long_count > 0).then(|| "Inspect the statements; cancel runaway queries with KILL QUERY <id>.".to_string()),
        ));
    }
    if !has_process {
        findings.push(finding(
            "process_visibility",
            "permissions",
            HealthSeverity::Info,
            "Only this login's own sessions are visible (long-running query check is partial)".to_string(),
            json!({"user": user}),
            Some(format!("Optional: GRANT PROCESS ON *.* TO '{user}'")),
        ));
    }

    let no_pk = tables_without_primary_key(objects);
    findings.push(finding(
        "tables_without_primary_key",
        "schema",
        if no_pk.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Warning },
        format!("{} table(s) without a primary key", no_pk.len()),
        json!({"tables": no_pk}),
        (!no_pk.is_empty()).then(|| "Add a primary key: InnoDB otherwise uses a hidden row id and replication/row lookups suffer.".to_string()),
    ));
    let redundant = redundant_indexes(objects);
    findings.push(finding(
        "redundant_indexes",
        "schema",
        if redundant.is_empty() { HealthSeverity::Healthy } else { HealthSeverity::Info },
        format!("{} index(es) are a leading prefix of another index", redundant.len()),
        json!({"indexes": redundant}),
        (!redundant.is_empty()).then(|| "Consider dropping the redundant index after confirming no query depends on it (governed change).".to_string()),
    ));
    if workload_readable == Some(false) {
        findings.push(finding(
            "workload_visibility",
            "permissions",
            HealthSeverity::Info,
            "performance_schema statement digests are not readable: analyze_workload falls back to this server's own session history".to_string(),
            json!({"user": user}),
            Some(format!("Optional: GRANT SELECT ON performance_schema.* TO '{user}'")),
        ));
    }

    let overall_status = findings.iter().map(|f| f.severity).max().unwrap_or(HealthSeverity::Healthy);
    HealthReport {
        connection: connection.to_string(),
        engine: DatabaseEngine::MySql,
        collected_at: Utc::now(),
        overall_status,
        cache_hit_ratio: hit_ratio,
        active_connections: threads.map(|t| t as u32),
        max_connections: max_conn.map(|m| m as u32),
        dead_tuples_total: None,
        invalid_indexes: Vec::new(),
        long_running_queries: long_count,
        findings,
    }
}

const STATUS_NAMES: &str = "'Threads_connected','Threads_running','Max_used_connections','Uptime','Slow_queries','Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Created_tmp_disk_tables','Created_tmp_tables','Innodb_row_lock_waits','Aborted_connects'";
const VARIABLE_NAMES: &str = "'max_connections','innodb_buffer_pool_size','long_query_time','slow_query_log','performance_schema','read_only','super_read_only'";

/// Digest query for `analyze_workload`, limited to the schemas the login can see and excluding
/// DB-MCP's own catalog / diagnostics probes.
pub fn build_digest_query(schemas: &[String], top_n: usize) -> String {
    let list = if schemas.is_empty() {
        "''".to_string()
    } else {
        schemas.iter().map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))).collect::<Vec<_>>().join(", ")
    };
    format!(
        "SELECT SCHEMA_NAME, DIGEST, DIGEST_TEXT, COUNT_STAR, SUM_TIMER_WAIT, AVG_TIMER_WAIT, SUM_ROWS_SENT, SUM_ROWS_EXAMINED
         FROM performance_schema.events_statements_summary_by_digest
         WHERE SCHEMA_NAME IN ({list})
           AND DIGEST_TEXT IS NOT NULL
           AND DIGEST_TEXT NOT LIKE '%information_schema%'
           AND DIGEST_TEXT NOT LIKE '%performance_schema%'
           AND DIGEST_TEXT NOT REGEXP '^(SET|SHOW|EXPLAIN|KILL|USE|COMMIT|ROLLBACK|START|BEGIN|SELECT @@|SELECT VERSION|SELECT CURRENT_USER|SELECT DATABASE|SELECT ?$)'
         ORDER BY SUM_TIMER_WAIT DESC
         LIMIT {}",
        top_n.clamp(1, 500)
    )
}

impl LiveMySql {
    async fn try_rows(&self, conn: &mut mysql_async::Conn, sql: &str) -> Result<Vec<Vec<J>>, DbMcpError> {
        self.query_json(conn, sql, DIAG_TIMEOUT_MS).await.map(|(_, rows)| rows)
    }

    /// `database_health` on a live server. `objects` is the policy-visible catalog (restricted
    /// tables already removed by the caller).
    pub async fn database_health(&self, objects: &[CatalogObject]) -> DbMcpResult<HealthReport> {
        let mut conn = self.session(true, DIAG_TIMEOUT_MS).await?;
        let grants = self.grants(&mut conn).await.unwrap_or_default();
        let privileges = crate::live::summarize_grants(&grants);
        let status = self
            .try_rows(&mut conn, &format!("SHOW GLOBAL STATUS WHERE Variable_name IN ({STATUS_NAMES})"))
            .await
            .ok()
            .map(|r| kv(&r));
        let variables = self
            .try_rows(&mut conn, &format!("SHOW GLOBAL VARIABLES WHERE Variable_name IN ({VARIABLE_NAMES})"))
            .await
            .ok()
            .map(|r| kv(&r));
        let long_running = self
            .try_rows(
                &mut conn,
                "SELECT ID, USER, TIME, STATE, LEFT(INFO, 500) FROM information_schema.PROCESSLIST \
                 WHERE COMMAND NOT IN ('Sleep', 'Daemon', 'Binlog Dump') AND TIME >= 30 AND ID <> CONNECTION_ID() ORDER BY TIME DESC",
            )
            .await
            .ok();
        let workload_readable = match self
            .try_rows(&mut conn, "SELECT 1 FROM performance_schema.events_statements_summary_by_digest LIMIT 1")
            .await
        {
            Ok(_) => Some(true),
            Err(e) if e.code() == CODE_DATABASE_PERMISSION_DENIED => Some(false),
            Err(_) => None,
        };
        drop(conn);
        let mut report = build_health_report(
            &self.connection_id,
            status.as_ref(),
            variables.as_ref(),
            long_running.as_deref(),
            privileges.has_process,
            workload_readable,
            objects,
            &self.dsn.user,
        );
        if let Some(v) = variables.as_ref() {
            let ro = v.get("read_only").map(|s| s == "ON" || s == "1").unwrap_or(false);
            let sro = v.get("super_read_only").map(|s| s == "ON" || s == "1").unwrap_or(false);
            report.findings.push(finding(
                "server_read_only",
                "configuration",
                HealthSeverity::Healthy,
                format!("server read_only={}, super_read_only={}", if ro { "ON" } else { "OFF" }, if sro { "ON" } else { "OFF" }),
                json!({"read_only": ro, "super_read_only": sro, "server_version": self.server_version()}),
                None,
            ));
        }
        Ok(report)
    }

    /// Workload from `performance_schema` digests. `Ok(Err(note))` when the login lacks the
    /// optional grant (the caller falls back to session history and adds the note).
    pub async fn analyze_workload(&self, top_n: usize) -> DbMcpResult<Result<WorkloadAnalysis, String>> {
        let catalog = self.catalog(false).await?;
        let mut schemas: Vec<String> = catalog.objects.iter().map(|o| o.schema.clone()).collect();
        if let Some(db) = &self.dsn.database {
            schemas.push(db.clone());
        }
        schemas.sort();
        schemas.dedup();
        let mut conn = self.session(true, DIAG_TIMEOUT_MS).await?;
        let rows = match self.try_rows(&mut conn, &build_digest_query(&schemas, top_n)).await {
            Ok(rows) => rows,
            Err(e) if e.code() == CODE_DATABASE_PERMISSION_DENIED => {
                return Ok(Err(format!(
                    "performance_schema.events_statements_summary_by_digest is not readable by '{}'; showing this server's session history instead (optional: GRANT SELECT ON performance_schema.* TO '{}')",
                    self.dsn.user, self.dsn.user
                )))
            }
            Err(e) => return Err(e),
        };
        let mut top = Vec::new();
        let mut table_time: BTreeMap<String, f64> = BTreeMap::new();
        for r in &rows {
            let digest_text = as_str(r.get(2));
            let normalized = fingerprint_sql(&digest_text);
            let calls = as_u64(r.get(3)).unwrap_or(0);
            let total_ms = as_u64(r.get(4)).unwrap_or(0) as f64 / 1e9;
            let mean_ms = as_u64(r.get(5)).unwrap_or(0) as f64 / 1e9;
            let tables = parse_and_analyze_sql(DatabaseEngine::MySql, &digest_text)
                .map(|a| a.referenced_tables)
                .unwrap_or_default();
            for t in &tables {
                *table_time.entry(t.clone()).or_default() += total_ms;
            }
            let digest = as_str(r.get(1));
            top.push(WorkloadQueryStat {
                query_id: format!("q_{}", if digest.len() >= 12 { digest[..12].to_string() } else { hash_sql(&normalized)[..12].to_string() }),
                normalized_query: normalized,
                calls,
                total_exec_time_ms: (total_ms * 1000.0).round() / 1000.0,
                mean_exec_time_ms: (mean_ms * 1000.0).round() / 1000.0,
                rows: as_u64(r.get(6)).unwrap_or(0),
                shared_blks_hit: 0,
                shared_blks_read: as_u64(r.get(7)).unwrap_or(0),
                tables_referenced: tables,
            });
        }
        let mut hot: Vec<(String, f64)> = table_time.into_iter().collect();
        hot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Ok(Ok(WorkloadAnalysis {
            connection: self.connection_id.clone(),
            collected_at: Utc::now(),
            source: "performance_schema.events_statements_summary_by_digest".to_string(),
            total_queries_analyzed: top.len(),
            top_queries: top,
            hot_tables: hot.into_iter().take(10).map(|(t, _)| t).collect(),
            notes: vec![
                "Digests aggregate every client of this server since startup (or the last TRUNCATE of the digest table); literals are replaced by '?'.".to_string(),
                "shared_blks_read carries SUM_ROWS_EXAMINED (rows examined) for MySQL.".to_string(),
            ],
        }))
    }

    /// Finish heuristic index advice for MySQL: validate each candidate with a real
    /// `EXPLAIN FORMAT=JSON`, emit MySQL DDL, and state the privileges a change would need.
    /// Candidates whose query already uses an index on that table are dropped.
    pub async fn finish_index_recommendations(&self, recs: Vec<IndexRecommendation>) -> Vec<IndexRecommendation> {
        let mut out = Vec::new();
        for mut rec in recs {
            let (schema, table) = match rec.table_name.split_once('.') {
                Some((s, t)) => (s.to_string(), t.to_string()),
                None => (self.dsn.database.clone().unwrap_or_default(), rec.table_name.clone()),
            };
            let qualified = if schema.is_empty() { format!("`{table}`") } else { format!("`{schema}`.`{table}`") };
            let index_name = format!(
                "idx_{}_{}",
                table.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_"),
                rec.columns.iter().map(|c| c.replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_', "_")).collect::<Vec<_>>().join("_")
            );
            let cols = rec.columns.iter().map(|c| format!("`{}`", c.replace('`', "``"))).collect::<Vec<_>>().join(", ");
            rec.suggested_ddl = format!("ALTER TABLE {qualified} ADD INDEX `{index_name}` ({cols});");
            rec.recovery_considerations = format!(
                "Online DDL (ALGORITHM=INPLACE, LOCK=NONE) builds the index without blocking reads/writes on InnoDB; roll back with `ALTER TABLE {qualified} DROP INDEX `{index_name}`;`. MySQL DDL is not transactional."
            );
            rec.validation_procedure = format!(
                "Run EXPLAIN FORMAT=JSON on the relevant queries before and after creating `{index_name}` on a staging copy; expect access_type ref/range with key={index_name} instead of ALL, then compare analyze_workload timings."
            );
            rec.required_privileges_extensions = vec![format!(
                "ALTER and INDEX privilege on {qualified} (a read-only login cannot apply it: route it through propose_change on a writable connection)"
            )];
            rec.write_storage_tradeoffs = format!(
                "Adds B-Tree maintenance on INSERT/UPDATE/DELETE touching ({}) on {qualified} and extra InnoDB buffer pool / disk footprint for the secondary index (it also stores the primary key).",
                rec.columns.join(", ")
            );
            rec.hypopg_validated = false;
            rec.assumptions = vec![
                "InnoDB index statistics are current (ANALYZE TABLE has run recently).".to_string(),
                "Predicate selectivity of the observed queries is representative of the workload.".to_string(),
            ];
            let probe = rec.relevant_queries.iter().find(|q| !q.trim_start().starts_with("/*") && !q.contains('?')).cloned();
            let mut validation = json!({"explain_validated": false});
            if let Some(sql) = probe {
                let req = ExplainRequest {
                    request_id: format!("req_idx_{}", uuid::Uuid::new_v4().simple()),
                    connection: self.connection_id.clone(),
                    sql: sql.clone(),
                    params: Vec::new(),
                    analyze: false,
                    format: ExplainFormat::Json,
                    timeout_ms: 5_000,
                };
                if let Ok(plan) = self.explain(&req).await {
                    let full_scan = plan.seq_scans.iter().any(|t| t.eq_ignore_ascii_case(&table));
                    if !full_scan && !plan.index_scans.is_empty() && plan.seq_scans.is_empty() {
                        continue;
                    }
                    validation = json!({
                        "explain_validated": true,
                        "query": fingerprint_sql(&sql),
                        "full_table_scan_confirmed": full_scan,
                        "seq_scans": plan.seq_scans,
                        "index_scans": plan.index_scans,
                        "estimated_cost": plan.estimated_cost,
                    });
                }
            }
            if let J::Object(map) = &mut rec.evidence {
                map.insert("mysql_explain".to_string(), validation);
                map.insert("hypopg_validated".to_string(), J::Bool(false));
            }
            out.push(rec);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{ColumnSpec, IndexSpec};

    fn table(name: &str, pk: bool, indexes: Vec<(&str, Vec<&str>, bool)>) -> CatalogObject {
        let mut idx: Vec<IndexSpec> = indexes
            .into_iter()
            .map(|(n, cols, unique)| IndexSpec {
                name: n.to_string(),
                table_name: name.to_string(),
                columns: cols.into_iter().map(String::from).collect(),
                unique,
                primary: false,
                index_type: Some("BTREE".to_string()),
                predicate: None,
                definition: None,
            })
            .collect();
        if pk {
            idx.push(IndexSpec {
                name: "PRIMARY".to_string(),
                table_name: name.to_string(),
                columns: vec!["id".to_string()],
                unique: true,
                primary: true,
                index_type: None,
                predicate: None,
                definition: None,
            });
        }
        CatalogObject {
            schema: "appdb".to_string(),
            name: name.to_string(),
            object_type: CatalogObjectType::Table,
            comment: None,
            estimated_rows: Some(10),
            size_bytes: None,
            columns: vec![ColumnSpec {
                name: "id".to_string(),
                data_type: "bigint".to_string(),
                nullable: false,
                default_value: None,
                is_primary_key: pk,
                comment: None,
                ordinal_position: 1,
            }],
            indexes: idx,
            foreign_keys: Vec::new(),
            definition: None,
        }
    }

    #[test]
    fn health_report_from_counters_catalog_and_missing_grants() {
        let objects = vec![
            table("orders", true, vec![("idx_status", vec!["status"], false), ("idx_status_created", vec!["status", "created_at"], false)]),
            table("event_log", false, vec![]),
        ];
        let status: BTreeMap<String, String> = [
            ("threads_connected", "95"),
            ("innodb_buffer_pool_reads", "100"),
            ("innodb_buffer_pool_read_requests", "100000"),
            ("slow_queries", "3"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let variables: BTreeMap<String, String> = [("max_connections", "100")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let r = build_health_report("m", Some(&status), Some(&variables), Some(&[]), false, Some(false), &objects, "ro");
        let f = |id: &str| r.findings.iter().find(|f| f.check_id == id).unwrap_or_else(|| panic!("{id} missing"));
        assert_eq!(f("connection_saturation").severity, HealthSeverity::Critical);
        assert_eq!(r.overall_status, HealthSeverity::Critical);
        assert!((r.cache_hit_ratio.unwrap() - 0.999).abs() < 1e-9);
        assert_eq!(f("tables_without_primary_key").evidence["tables"], json!(["appdb.event_log"]));
        assert_eq!(f("redundant_indexes").evidence["indexes"][0]["redundant_index"], json!("idx_status"));
        assert!(f("process_visibility").remediation.as_deref().unwrap().contains("GRANT PROCESS"));
        assert!(f("workload_visibility").remediation.as_deref().unwrap().contains("performance_schema"));
        let none = build_health_report("m", None, None, None, true, Some(true), &objects, "ro");
        assert!(none.findings.iter().any(|f| f.check_id == "server_status_visibility"));
        assert!(none.active_connections.is_none());
    }

    #[test]
    fn digest_query_is_scoped_and_excludes_probes() {
        let q = build_digest_query(&["appdb".to_string(), "o'x".to_string()], 7);
        assert!(q.contains("SCHEMA_NAME IN ('appdb', 'o''x')"));
        assert!(q.contains("NOT LIKE '%information_schema%'"));
        assert!(q.trim_end().ends_with("LIMIT 7"));
    }
}
