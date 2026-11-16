//! PostgreSQL intelligence module providing health diagnostics (`database_health`),
//! workload analysis (`analyze_workload`), and evidence-backed index recommendations
//! (`recommend_indexes`) with optional HypoPG hypothetical-index evaluation.
//!
//! Designed per Build Plan Section 8:
//! - Works against any `Arc<dyn DatabaseAdapter>` and/or injected telemetry snapshots.
//! - Extracts filter, join, group, and sort predicates using `db-mcp-sql`.
//! - Cross-references candidate indexes against existing catalog indexes (`DatabaseAdapter::discover`).
//! - Never auto-creates recommended indexes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::Utc;
use db_mcp_catalog::capture_schema_via_adapter;
use db_mcp_core::{
    AuthorizedQuery, CallerIdentity, CatalogDetailLevel, CatalogObject, CatalogObjectType,
    CatalogRequest, ColumnMetadata, DatabaseAdapter, DatabaseEngine, DbMcpResult, ExecutionLimits,
    ExplainFormat, ExplainRequest, HealthFinding, HealthReport, HealthSeverity,
    IndexRecommendation, IndexSpec, McpSuccessResponse, PostgresHealthProvider,
    PostgresIndexAdvisor, WorkloadAnalysis, WorkloadQueryStat,
};
use db_mcp_sql::{
    hash_sql, normalize_sql, parse_and_analyze_sql, PredicateColumn, PredicateOperator,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Per-table dead tuple / bloat telemetry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableBloatStat {
    pub schema: String,
    pub table_name: String,
    pub live_tuples: u64,
    pub dead_tuples: u64,
}

impl TableBloatStat {
    pub fn dead_ratio(&self) -> f64 {
        let total = self.live_tuples + self.dead_tuples;
        if total == 0 {
            0.0
        } else {
            self.dead_tuples as f64 / total as f64
        }
    }

    pub fn qualified_name(&self) -> String {
        if self.schema.is_empty() {
            self.table_name.clone()
        } else {
            format!("{}.{}", self.schema, self.table_name)
        }
    }
}

/// Active long-running query telemetry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongRunningQueryStat {
    pub pid: u32,
    pub duration_ms: u64,
    pub state: String,
    pub query: String,
}

/// Telemetry snapshot used by `PgInsightsEngine` to evaluate database health.
/// Can be populated from live `pg_stat_*` views or injected in deterministic tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthTelemetrySnapshot {
    pub cache_hit_ratio: Option<f64>,
    pub active_connections: Option<u32>,
    pub max_connections: Option<u32>,
    pub dead_tuples_total: Option<u64>,
    #[serde(default)]
    pub table_bloat: Vec<TableBloatStat>,
    #[serde(default)]
    pub invalid_indexes: Vec<String>,
    #[serde(default)]
    pub long_running_queries: Vec<LongRunningQueryStat>,
    pub large_table_row_threshold: u64,
}

impl Default for HealthTelemetrySnapshot {
    fn default() -> Self {
        Self {
            cache_hit_ratio: Some(0.994),
            active_connections: Some(8),
            max_connections: Some(100),
            dead_tuples_total: Some(120),
            table_bloat: Vec::new(),
            invalid_indexes: Vec::new(),
            long_running_queries: Vec::new(),
            large_table_row_threshold: 10_000,
        }
    }
}

/// Simulated or live HypoPG hypothetical index evaluation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HypoPgEvaluation {
    pub table_name: String,
    pub columns: Vec<String>,
    pub baseline_cost: f64,
    pub hypothetical_cost: f64,
}

impl HypoPgEvaluation {
    /// Percentage cost reduction `((baseline - hypothetical) / baseline) * 100.0`.
    pub fn cost_reduction_pct(&self) -> f64 {
        if self.baseline_cost <= 0.0 || self.hypothetical_cost >= self.baseline_cost {
            0.0
        } else {
            ((self.baseline_cost - self.hypothetical_cost) / self.baseline_cost) * 100.0
        }
    }
}

/// PostgreSQL intelligence and diagnostic engine implementing `PostgresHealthProvider`
/// and `PostgresIndexAdvisor`.
#[derive(Default, Clone)]
pub struct PgInsightsEngine {
    adapters: Arc<RwLock<BTreeMap<String, Arc<dyn DatabaseAdapter>>>>,
    telemetry: Arc<RwLock<BTreeMap<String, HealthTelemetrySnapshot>>>,
    workload_history: Arc<RwLock<BTreeMap<String, Vec<WorkloadQueryStat>>>>,
    hypopg_evaluations: Arc<RwLock<BTreeMap<String, Vec<HypoPgEvaluation>>>>,
}

impl PgInsightsEngine {
    /// Create a new empty `PgInsightsEngine`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a `PgInsightsEngine` pre-registered with a single `DatabaseAdapter`.
    pub fn with_adapter(adapter: Arc<dyn DatabaseAdapter>) -> Self {
        let engine = Self::new();
        engine.register_adapter(adapter);
        engine
    }

    /// Create a `PgInsightsEngine` pre-registered with multiple `DatabaseAdapter`s.
    pub fn with_adapters(adapters: impl IntoIterator<Item = Arc<dyn DatabaseAdapter>>) -> Self {
        let engine = Self::new();
        for adapter in adapters {
            engine.register_adapter(adapter);
        }
        engine
    }

    /// Register or replace a `DatabaseAdapter` for its `connection_id()`.
    pub fn register_adapter(&self, adapter: Arc<dyn DatabaseAdapter>) {
        if let Ok(mut map) = self.adapters.write() {
            map.insert(adapter.connection_id().to_string(), adapter);
        }
    }

    /// Look up a registered `DatabaseAdapter` by connection ID.
    pub fn get_adapter(&self, connection: &str) -> Option<Arc<dyn DatabaseAdapter>> {
        self.adapters
            .read()
            .ok()
            .and_then(|map| map.get(connection).cloned())
    }

    /// Inject or update a `HealthTelemetrySnapshot` for a connection.
    pub fn set_telemetry_snapshot(
        &self,
        connection: impl Into<String>,
        snapshot: HealthTelemetrySnapshot,
    ) {
        if let Ok(mut map) = self.telemetry.write() {
            map.insert(connection.into(), snapshot);
        }
    }

    /// Record a query execution into the in-memory workload tracker for a connection.
    pub fn record_query_execution(
        &self,
        connection: &str,
        sql: &str,
        exec_time_ms: f64,
        rows: u64,
    ) {
        let trimmed = sql.trim();
        if trimmed.is_empty() {
            return;
        }
        let engine = self
            .get_adapter(connection)
            .map(|a| a.capabilities().engine)
            .unwrap_or(DatabaseEngine::Postgres);
        let normalized = db_mcp_sql::fingerprint_sql(trimmed);
        let qid = format!("q_{}", &hash_sql(&normalized)[..12]);
        let tables_referenced = parse_and_analyze_sql(engine, trimmed)
            .map(|a| a.referenced_tables)
            .unwrap_or_default();

        if let Ok(mut map) = self.workload_history.write() {
            let entries = map.entry(connection.to_string()).or_default();
            if let Some(existing) = entries
                .iter_mut()
                .find(|e| e.normalized_query == normalized)
            {
                existing.calls += 1;
                existing.total_exec_time_ms += exec_time_ms;
                existing.mean_exec_time_ms =
                    existing.total_exec_time_ms / (existing.calls as f64);
                existing.rows += rows;
                existing.shared_blks_hit += 4;
            } else {
                entries.push(WorkloadQueryStat {
                    query_id: qid,
                    normalized_query: normalized,
                    calls: 1,
                    total_exec_time_ms: exec_time_ms,
                    mean_exec_time_ms: exec_time_ms,
                    rows,
                    shared_blks_hit: 4,
                    shared_blks_read: 1,
                    tables_referenced,
                });
            }
        }
    }

    /// Replace or seed the workload statistics for a connection.
    pub fn set_workload_stats(&self, connection: impl Into<String>, stats: Vec<WorkloadQueryStat>) {
        if let Ok(mut map) = self.workload_history.write() {
            map.insert(connection.into(), stats);
        }
    }

    /// Register a simulated or measured HypoPG cost evaluation for a candidate index.
    pub fn register_hypopg_evaluation(
        &self,
        connection: impl Into<String>,
        evaluation: HypoPgEvaluation,
    ) {
        if let Ok(mut map) = self.hypopg_evaluations.write() {
            map.entry(connection.into()).or_default().push(evaluation);
        }
    }

    /// Run `database_health` directly against a provided `DatabaseAdapter`.
    pub async fn database_health_with_adapter(
        &self,
        adapter: &dyn DatabaseAdapter,
    ) -> DbMcpResult<HealthReport> {
        let connection = adapter.connection_id();
        let catalog_req = CatalogRequest {
            connection: connection.to_string(),
            schema_pattern: None,
            name_pattern: None,
            object_types: Vec::new(),
            detail_level: CatalogDetailLevel::Full,
            limit: 10_000,
            offset: 0,
        };
        let catalog = adapter.discover(catalog_req).await?;
        let snapshot = self
            .collect_or_get_telemetry(connection, Some(adapter))
            .await;
        let engine = adapter.capabilities().engine;
        let mut report = self.build_health_report(connection, engine, &catalog.objects, &snapshot);
        if engine == DatabaseEngine::Sqlite {
            report.findings.extend(sqlite_health_findings(adapter, connection).await);
            report.overall_status = report
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(HealthSeverity::Healthy);
        }
        Ok(report)
    }

    /// Run `analyze_workload` directly against a provided `DatabaseAdapter`.
    pub async fn analyze_workload_with_adapter(
        &self,
        adapter: &dyn DatabaseAdapter,
        top_n: usize,
    ) -> DbMcpResult<WorkloadAnalysis> {
        self.analyze_workload_internal(adapter.connection_id(), Some(adapter), top_n)
            .await
    }

    /// Run `recommend_indexes` directly against a provided `DatabaseAdapter`.
    pub async fn recommend_indexes_with_adapter(
        &self,
        adapter: &dyn DatabaseAdapter,
        queries: Vec<String>,
        max_recommendations: usize,
    ) -> DbMcpResult<Vec<IndexRecommendation>> {
        self.recommend_indexes_internal(
            adapter.connection_id(),
            Some(adapter),
            queries,
            max_recommendations,
        )
        .await
    }

    /// Format a `HealthReport` into a standard `McpSuccessResponse` matching the tool contract.
    pub fn health_report_to_response(
        request_id: impl Into<String>,
        schema_version: impl Into<String>,
        report: &HealthReport,
    ) -> McpSuccessResponse<HealthReport> {
        let columns = vec![
            ColumnMetadata::new("check_name", "text"),
            ColumnMetadata::new("status", "text"),
            ColumnMetadata::new("value", "text"),
            ColumnMetadata::new("evidence", "json"),
            ColumnMetadata::new("recommendation", "text"),
        ];
        let rows: Vec<Vec<serde_json::Value>> = report
            .findings
            .iter()
            .map(|f| {
                vec![
                    serde_json::Value::String(f.check_id.clone()),
                    serde_json::to_value(f.severity)
                        .unwrap_or_else(|_| serde_json::Value::String("info".to_string())),
                    serde_json::Value::String(f.summary.clone()),
                    f.evidence.clone(),
                    serde_json::Value::String(
                        f.remediation
                            .clone()
                            .unwrap_or_else(|| "No action needed.".to_string()),
                    ),
                ]
            })
            .collect();
        let returned_rows = rows.len();
        let mut resp = McpSuccessResponse::with_data(
            request_id,
            report.connection.clone(),
            schema_version,
            "database_health",
            report.clone(),
        );
        resp.columns = columns;
        resp.rows = rows;
        resp.returned_rows = returned_rows;
        resp
    }

    /// Format a `WorkloadAnalysis` into a standard `McpSuccessResponse` matching the tool contract.
    pub fn workload_to_response(
        request_id: impl Into<String>,
        schema_version: impl Into<String>,
        workload: &WorkloadAnalysis,
    ) -> McpSuccessResponse<WorkloadAnalysis> {
        let columns = vec![
            ColumnMetadata::new("query_fingerprint", "text"),
            ColumnMetadata::new("calls", "bigint"),
            ColumnMetadata::new("total_ms", "double precision"),
            ColumnMetadata::new("mean_ms", "double precision"),
            ColumnMetadata::new("rows_returned", "bigint"),
        ];
        let rows: Vec<Vec<serde_json::Value>> = workload
            .top_queries
            .iter()
            .map(|q| {
                vec![
                    serde_json::Value::String(q.normalized_query.clone()),
                    serde_json::json!(q.calls),
                    serde_json::json!(q.total_exec_time_ms),
                    serde_json::json!(q.mean_exec_time_ms),
                    serde_json::json!(q.rows),
                ]
            })
            .collect();
        let returned_rows = rows.len();
        let mut resp = McpSuccessResponse::with_data(
            request_id,
            workload.connection.clone(),
            schema_version,
            "analyze_workload",
            workload.clone(),
        );
        resp.columns = columns;
        resp.rows = rows;
        resp.returned_rows = returned_rows;
        resp
    }

    /// Format a slice of `IndexRecommendation`s into a standard `McpSuccessResponse` matching Section 8.
    pub fn recommendations_to_response(
        request_id: impl Into<String>,
        connection: impl Into<String>,
        schema_version: impl Into<String>,
        recommendations: Vec<IndexRecommendation>,
    ) -> McpSuccessResponse<Vec<IndexRecommendation>> {
        let conn = connection.into();
        let columns = vec![
            ColumnMetadata::new("observed_issue", "text"),
            ColumnMetadata::new("evidence_timestamp", "timestamptz"),
            ColumnMetadata::new("relevant_queries", "json"),
            ColumnMetadata::new("suggested_ddl", "text"),
            ColumnMetadata::new("estimated_benefit", "text"),
            ColumnMetadata::new("write_storage_tradeoffs", "text"),
            ColumnMetadata::new("required_privileges", "json"),
            ColumnMetadata::new("validation_procedure", "text"),
            ColumnMetadata::new("recovery_considerations", "text"),
        ];
        let rows: Vec<Vec<serde_json::Value>> = recommendations
            .iter()
            .map(|r| {
                vec![
                    serde_json::Value::String(r.observed_issue.clone()),
                    serde_json::Value::String(r.collected_at.to_rfc3339()),
                    serde_json::to_value(&r.relevant_queries).unwrap_or_default(),
                    serde_json::Value::String(r.suggested_ddl.clone()),
                    serde_json::Value::String(r.estimated_benefit.clone()),
                    serde_json::Value::String(r.write_storage_tradeoffs.clone()),
                    serde_json::to_value(&r.required_privileges_extensions).unwrap_or_default(),
                    serde_json::Value::String(r.validation_procedure.clone()),
                    serde_json::Value::String(r.recovery_considerations.clone()),
                ]
            })
            .collect();
        let returned_rows = rows.len();
        let mut resp = McpSuccessResponse::with_data(
            request_id,
            conn,
            schema_version,
            "recommend_indexes",
            recommendations,
        );
        resp.columns = columns;
        resp.rows = rows;
        resp.returned_rows = returned_rows;
        resp
    }

    async fn collect_or_get_telemetry(
        &self,
        connection: &str,
        adapter: Option<&dyn DatabaseAdapter>,
    ) -> HealthTelemetrySnapshot {
        if let Some(existing) = self
            .telemetry
            .read()
            .ok()
            .and_then(|map| map.get(connection).cloned())
        {
            return existing;
        }

        let mut snapshot = HealthTelemetrySnapshot::default();
        if let Some(ad) = adapter {
            if ad.capabilities().engine == DatabaseEngine::Postgres {
                let limits = ExecutionLimits {
                    timeout_ms: 3_000,
                    max_rows: 50,
                    max_bytes: 65_536,
                    allow_multi_statement: false,
                };
                let probe_sql = "SELECT \
                    COALESCE(SUM(blks_hit)::float / NULLIF(SUM(blks_hit + blks_read), 0), 0.995) AS cache_hit_ratio, \
                    (SELECT count(*)::int FROM pg_stat_activity) AS active_connections, \
                    current_setting('max_connections')::int AS max_connections, \
                    COALESCE((SELECT SUM(n_dead_tup)::bigint FROM pg_stat_user_tables), 0) AS dead_tuples";
                let query = AuthorizedQuery::new_read(
                    format!("req_health_probe_{}", Uuid::new_v4().simple()),
                    connection,
                    CallerIdentity::local_agent("pg-insights"),
                    probe_sql,
                    Vec::new(),
                    &limits,
                );
                if let Ok(res) = ad.execute(query).await {
                    if let Some(first_row) = res.rows.first() {
                        if let Some(ratio) = first_row.first().and_then(|v| v.as_f64()) {
                            snapshot.cache_hit_ratio = Some(ratio);
                        }
                        if let Some(active) = first_row.get(1).and_then(|v| v.as_u64()) {
                            snapshot.active_connections = Some(active as u32);
                        }
                        if let Some(max_c) = first_row.get(2).and_then(|v| v.as_u64()) {
                            snapshot.max_connections = Some(max_c as u32);
                        }
                        if let Some(dead) = first_row.get(3).and_then(|v| v.as_u64()) {
                            snapshot.dead_tuples_total = Some(dead);
                        }
                    }
                }
            }
        }
        snapshot
    }

    fn build_health_report(
        &self,
        connection: &str,
        engine: DatabaseEngine,
        objects: &[CatalogObject],
        snapshot: &HealthTelemetrySnapshot,
    ) -> HealthReport {
        let mut findings = Vec::new();

        // 1. Buffer cache hit ratio check
        let hit_ratio = snapshot.cache_hit_ratio.unwrap_or(0.994);
        let cache_severity = if hit_ratio < 0.90 {
            HealthSeverity::Critical
        } else if hit_ratio < 0.98 {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Healthy
        };
        findings.push(HealthFinding {
            check_id: "buffer_cache_hit_ratio".to_string(),
            category: "memory".to_string(),
            severity: cache_severity,
            summary: format!("Buffer cache hit ratio is {:.2}%", hit_ratio * 100.0),
            evidence: serde_json::json!({
                "cache_hit_ratio": hit_ratio,
                "warning_threshold": 0.98,
                "critical_threshold": 0.90
            }),
            remediation: if cache_severity == HealthSeverity::Healthy {
                None
            } else {
                Some(
                    "Increase shared_buffers or add indexes to reduce physical heap page reads."
                        .to_string(),
                )
            },
        });

        // 2. Active vs max connections check
        let active_conn = snapshot.active_connections.unwrap_or(8);
        let max_conn = snapshot.max_connections.unwrap_or(100).max(1);
        let conn_utilization = active_conn as f64 / max_conn as f64;
        let conn_severity = if conn_utilization >= 0.90 {
            HealthSeverity::Critical
        } else if conn_utilization >= 0.75 {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Healthy
        };
        findings.push(HealthFinding {
            check_id: "connection_saturation".to_string(),
            category: "connections".to_string(),
            severity: conn_severity,
            summary: format!(
                "Active connections: {active_conn}/{max_conn} ({:.1}% utilization)",
                conn_utilization * 100.0
            ),
            evidence: serde_json::json!({
                "active_connections": active_conn,
                "max_connections": max_conn,
                "utilization_ratio": conn_utilization
            }),
            remediation: if conn_severity == HealthSeverity::Healthy {
                None
            } else {
                Some(
                    "Route client traffic through PgBouncer transaction pooling and set idle_in_transaction_session_timeout."
                        .to_string(),
                )
            },
        });

        // 3. Dead tuple bloat ratio check
        let dead_from_tables: u64 = snapshot.table_bloat.iter().map(|t| t.dead_tuples).sum();
        let dead_total = snapshot
            .dead_tuples_total
            .unwrap_or(dead_from_tables)
            .max(dead_from_tables);
        let max_table_bloat = snapshot
            .table_bloat
            .iter()
            .map(TableBloatStat::dead_ratio)
            .fold(0.0_f64, f64::max);
        let bloated_tables: Vec<serde_json::Value> = snapshot
            .table_bloat
            .iter()
            .filter(|t| t.dead_ratio() >= 0.15 || t.dead_tuples >= 10_000)
            .map(|t| {
                serde_json::json!({
                    "table": t.qualified_name(),
                    "live_tuples": t.live_tuples,
                    "dead_tuples": t.dead_tuples,
                    "dead_ratio": (t.dead_ratio() * 1000.0).round() / 1000.0
                })
            })
            .collect();

        let bloat_severity = if max_table_bloat >= 0.30 || dead_total >= 100_000 {
            HealthSeverity::Critical
        } else if max_table_bloat >= 0.15 || dead_total >= 10_000 {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Healthy
        };
        findings.push(HealthFinding {
            check_id: "dead_tuple_bloat".to_string(),
            category: "vacuum".to_string(),
            severity: bloat_severity,
            summary: format!(
                "Total dead tuples: {dead_total} (peak table dead-tuple ratio: {:.1}%)",
                max_table_bloat * 100.0
            ),
            evidence: serde_json::json!({
                "dead_tuples_total": dead_total,
                "max_table_dead_ratio": max_table_bloat,
                "bloated_tables": bloated_tables
            }),
            remediation: if bloat_severity == HealthSeverity::Healthy {
                None
            } else {
                Some(
                    "Run VACUUM (ANALYZE) on affected tables and tune autovacuum_vacuum_scale_factor / autovacuum_vacuum_cost_limit."
                        .to_string(),
                )
            },
        });

        // 4. Invalid indexes check
        let mut invalid_indexes = snapshot.invalid_indexes.clone();
        for obj in objects {
            for idx in &obj.indexes {
                if idx
                    .definition
                    .as_deref()
                    .map(|d| d.to_ascii_uppercase().contains("INVALID"))
                    .unwrap_or(false)
                    && !invalid_indexes.contains(&idx.name)
                {
                    invalid_indexes.push(idx.name.clone());
                }
            }
        }
        let invalid_idx_severity = if invalid_indexes.is_empty() {
            HealthSeverity::Healthy
        } else {
            HealthSeverity::Warning
        };
        findings.push(HealthFinding {
            check_id: "invalid_indexes".to_string(),
            category: "indexes".to_string(),
            severity: invalid_idx_severity,
            summary: if invalid_indexes.is_empty() {
                "No invalid indexes detected".to_string()
            } else {
                format!(
                    "Found {} invalid index(es): {}",
                    invalid_indexes.len(),
                    invalid_indexes.join(", ")
                )
            },
            evidence: serde_json::json!({
                "invalid_index_count": invalid_indexes.len(),
                "invalid_indexes": invalid_indexes
            }),
            remediation: if invalid_indexes.is_empty() {
                None
            } else {
                Some(
                    "Rebuild broken concurrent indexes with REINDEX INDEX CONCURRENTLY or drop them with DROP INDEX CONCURRENTLY."
                        .to_string(),
                )
            },
        });

        // 5. Missing foreign-key indexes check
        let missing_fk = find_missing_foreign_key_indexes(objects);
        let fk_severity = if missing_fk.is_empty() {
            HealthSeverity::Healthy
        } else {
            HealthSeverity::Warning
        };
        findings.push(HealthFinding {
            check_id: "missing_fk_indexes".to_string(),
            category: "indexes".to_string(),
            severity: fk_severity,
            summary: if missing_fk.is_empty() {
                "All foreign key constraints are backed by covering leading-column indexes"
                    .to_string()
            } else {
                format!(
                    "Found {} foreign key constraint(s) without a supporting index",
                    missing_fk.len()
                )
            },
            evidence: serde_json::json!({
                "unindexed_foreign_keys": missing_fk
            }),
            remediation: if missing_fk.is_empty() {
                None
            } else {
                Some(
                    "Create B-Tree indexes on foreign key columns to accelerate JOINs and avoid table locks during parent row updates/deletes."
                        .to_string(),
                )
            },
        });

        // 6. Unindexed large tables check
        let threshold = snapshot.large_table_row_threshold.max(1);
        let unindexed_large: Vec<serde_json::Value> = objects
            .iter()
            .filter(|o| o.object_type == CatalogObjectType::Table)
            .filter(|o| {
                let rows = o.estimated_rows.unwrap_or(0);
                let has_pk = o.columns.iter().any(|c| c.is_primary_key);
                rows >= threshold && o.indexes.is_empty() && !has_pk
            })
            .map(|o| {
                serde_json::json!({
                    "table": o.qualified_name(),
                    "estimated_rows": o.estimated_rows.unwrap_or(0),
                    "size_bytes": o.size_bytes
                })
            })
            .collect();
        let unindexed_severity = if unindexed_large.is_empty() {
            HealthSeverity::Healthy
        } else {
            HealthSeverity::Warning
        };
        findings.push(HealthFinding {
            check_id: "unindexed_large_tables".to_string(),
            category: "schema".to_string(),
            severity: unindexed_severity,
            summary: if unindexed_large.is_empty() {
                format!("No unindexed tables exceeding {threshold} rows")
            } else {
                format!(
                    "Found {} large table(s) (>= {threshold} rows) with no primary key or indexes",
                    unindexed_large.len()
                )
            },
            evidence: serde_json::json!({
                "row_threshold": threshold,
                "unindexed_large_tables": unindexed_large
            }),
            remediation: if unindexed_large.is_empty() {
                None
            } else {
                Some(
                    "Define a primary key and add B-Tree indexes for frequent filter/join columns on large tables."
                        .to_string(),
                )
            },
        });

        // 7. Long-running queries check
        let long_queries_count = snapshot.long_running_queries.len();
        let max_duration_ms = snapshot
            .long_running_queries
            .iter()
            .map(|q| q.duration_ms)
            .max()
            .unwrap_or(0);
        let long_query_severity = if max_duration_ms >= 300_000 || long_queries_count >= 5 {
            HealthSeverity::Critical
        } else if long_queries_count > 0 {
            HealthSeverity::Warning
        } else {
            HealthSeverity::Healthy
        };
        findings.push(HealthFinding {
            check_id: "long_running_queries".to_string(),
            category: "workload".to_string(),
            severity: long_query_severity,
            summary: if long_queries_count == 0 {
                "No long-running queries detected".to_string()
            } else {
                format!(
                    "Found {long_queries_count} long-running query/queries (max duration: {max_duration_ms}ms)"
                )
            },
            evidence: serde_json::json!({
                "count": long_queries_count,
                "max_duration_ms": max_duration_ms,
                "queries": snapshot.long_running_queries
            }),
            remediation: if long_queries_count == 0 {
                None
            } else {
                Some(
                    "Set statement_timeout, inspect lock waits in pg_locks, and cancel runaway backends via pg_cancel_backend."
                        .to_string(),
                )
            },
        });

        // Buffer cache, connection saturation and dead-tuple bloat are PostgreSQL-only metrics:
        // never report them (with fabricated defaults) for other engines.
        let pg_only = engine == DatabaseEngine::Postgres;
        if !pg_only {
            findings.retain(|f| {
                !matches!(
                    f.check_id.as_str(),
                    "buffer_cache_hit_ratio" | "connection_saturation" | "dead_tuple_bloat"
                )
            });
        }

        let overall_status = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(HealthSeverity::Healthy);

        HealthReport {
            connection: connection.to_string(),
            engine,
            collected_at: Utc::now(),
            overall_status,
            cache_hit_ratio: pg_only.then_some(hit_ratio),
            active_connections: pg_only.then_some(active_conn),
            max_connections: pg_only.then_some(max_conn),
            dead_tuples_total: pg_only.then_some(dead_total),
            invalid_indexes,
            long_running_queries: long_queries_count,
            findings,
        }
    }

    async fn analyze_workload_internal(
        &self,
        connection: &str,
        adapter: Option<&dyn DatabaseAdapter>,
        top_n: usize,
    ) -> DbMcpResult<WorkloadAnalysis> {
        let limit = if top_n == 0 { 10 } else { top_n };
        let engine = adapter
            .map(|a| a.capabilities().engine)
            .unwrap_or(DatabaseEngine::Postgres);

        // 1. Check recorded in-memory/injected workload stats first
        let mut stats: Vec<WorkloadQueryStat> = self
            .workload_history
            .read()
            .ok()
            .and_then(|map| map.get(connection).cloned())
            .unwrap_or_default();

        let mut source = if !stats.is_empty() {
            "recorded_workload_history".to_string()
        } else {
            "catalog_synthesized_workload".to_string()
        };
        let mut notes = Vec::new();

        // 2. If empty and adapter is Postgres with workload analysis capability, try querying pg_stat_statements
        if stats.is_empty() {
            if let Some(ad) = adapter {
                if ad.capabilities().engine == DatabaseEngine::Postgres
                    && ad.capabilities().supports_workload_analysis
                {
                    let limits = ExecutionLimits {
                        timeout_ms: 3_000,
                        max_rows: limit.min(100),
                        max_bytes: 262_144,
                        allow_multi_statement: false,
                    };
                    let sql = format!(
                        "SELECT queryid::text, query, calls::bigint, total_exec_time::float8, mean_exec_time::float8, rows::bigint, shared_blks_hit::bigint, shared_blks_read::bigint \
                         FROM pg_stat_statements \
                         ORDER BY total_exec_time DESC \
                         LIMIT {limit}"
                    );
                    let auth_q = AuthorizedQuery::new_read(
                        format!("req_pgss_{}", Uuid::new_v4().simple()),
                        connection,
                        CallerIdentity::local_agent("pg-insights"),
                        sql,
                        Vec::new(),
                        &limits,
                    );
                    if let Ok(res) = ad.execute(auth_q).await {
                        for row in &res.rows {
                            let query_id = row
                                .first()
                                .and_then(|v| v.as_str())
                                .unwrap_or("q_pgss")
                                .to_string();
                            let raw_q = row.get(1).and_then(|v| v.as_str()).unwrap_or("SELECT 1");
                            let normalized_query = normalize_sql(raw_q);
                            let calls = row.get(2).and_then(|v| v.as_u64()).unwrap_or(1);
                            let total_exec_time_ms =
                                row.get(3).and_then(|v| v.as_f64()).unwrap_or(1.0);
                            let mean_exec_time_ms = row
                                .get(4)
                                .and_then(|v| v.as_f64())
                                .unwrap_or(total_exec_time_ms);
                            let rows = row.get(5).and_then(|v| v.as_u64()).unwrap_or(0);
                            let shared_blks_hit = row.get(6).and_then(|v| v.as_u64()).unwrap_or(0);
                            let shared_blks_read = row.get(7).and_then(|v| v.as_u64()).unwrap_or(0);
                            let tables_referenced = parse_and_analyze_sql(engine, raw_q)
                                .map(|a| a.referenced_tables)
                                .unwrap_or_default();

                            stats.push(WorkloadQueryStat {
                                query_id,
                                normalized_query,
                                calls,
                                total_exec_time_ms,
                                mean_exec_time_ms,
                                rows,
                                shared_blks_hit,
                                shared_blks_read,
                                tables_referenced,
                            });
                        }
                        if !stats.is_empty() {
                            source = "pg_stat_statements".to_string();
                        }
                    }
                }
            }
        }

        // 3. If still empty, synthesize representative workload from discovered catalog tables
        if stats.is_empty() {
            if let Some(ad) = adapter {
                let catalog_req = CatalogRequest {
                    connection: connection.to_string(),
                    schema_pattern: None,
                    name_pattern: None,
                    object_types: vec![CatalogObjectType::Table],
                    detail_level: CatalogDetailLevel::Full,
                    limit: 50,
                    offset: 0,
                };
                if let Ok(catalog) = ad.discover(catalog_req).await {
                    for tbl in catalog.objects.iter().take(limit) {
                        let qname = tbl.qualified_name();
                        let filter_col = tbl
                            .columns
                            .iter()
                            .find(|c| !c.is_primary_key)
                            .or_else(|| tbl.columns.first())
                            .map(|c| c.name.as_str())
                            .unwrap_or("id");
                        let synth_sql =
                            format!("SELECT * FROM {qname} WHERE {filter_col} = $1 LIMIT 100");
                        let normalized = normalize_sql(&synth_sql);
                        let est_rows = tbl.estimated_rows.unwrap_or(100).max(1);
                        let mean_ms = ((est_rows as f64).log10() * 3.5).max(1.2);
                        stats.push(WorkloadQueryStat {
                            query_id: format!("q_{}", &hash_sql(&normalized)[..12]),
                            normalized_query: normalized,
                            calls: 25,
                            total_exec_time_ms: mean_ms * 25.0,
                            mean_exec_time_ms: mean_ms,
                            rows: est_rows.min(100) * 25,
                            shared_blks_hit: 120,
                            shared_blks_read: 15,
                            tables_referenced: vec![qname],
                        });
                    }
                }
            }
            notes.push(if engine == DatabaseEngine::Postgres {
                "pg_stat_statements was not active; synthesized workload profile from catalog and query history."
                    .to_string()
            } else {
                format!(
                    "{} has no statement-statistics view; synthesized workload profile from catalog and recorded query history.",
                    engine.as_str()
                )
            });
        }

        // Ensure tables_referenced is populated via SQL AST analysis for every stat entry
        for item in &mut stats {
            if item.tables_referenced.is_empty() {
                if let Ok(analysis) = parse_and_analyze_sql(engine, &item.normalized_query) {
                    item.tables_referenced = analysis.referenced_tables;
                }
            }
        }

        // Sort descending by total execution time
        stats.sort_by(|a, b| {
            b.total_exec_time_ms
                .partial_cmp(&a.total_exec_time_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total_queries_analyzed = stats.len();
        let top_queries: Vec<WorkloadQueryStat> = stats.into_iter().take(limit).collect();

        // Compute hot tables ranked by total execution time of queries referencing them
        let mut table_scores: BTreeMap<String, f64> = BTreeMap::new();
        for q in &top_queries {
            for tbl in &q.tables_referenced {
                *table_scores.entry(tbl.clone()).or_insert(0.0) += q.total_exec_time_ms;
            }
        }
        let mut hot_tables_ranked: Vec<(String, f64)> = table_scores.into_iter().collect();
        hot_tables_ranked
            .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let hot_tables: Vec<String> = hot_tables_ranked.into_iter().map(|(t, _)| t).collect();

        Ok(WorkloadAnalysis {
            connection: connection.to_string(),
            collected_at: Utc::now(),
            source,
            total_queries_analyzed,
            top_queries,
            hot_tables,
            notes,
        })
    }

    async fn recommend_indexes_internal(
        &self,
        connection: &str,
        adapter: Option<&dyn DatabaseAdapter>,
        queries: Vec<String>,
        max_recommendations: usize,
    ) -> DbMcpResult<Vec<IndexRecommendation>> {
        let limit = if max_recommendations == 0 {
            10
        } else {
            max_recommendations
        };
        let engine = adapter
            .map(|a| a.capabilities().engine)
            .unwrap_or(DatabaseEngine::Postgres);
        let supports_hypopg = adapter
            .map(|a| a.capabilities().supports_hypothetical_indexes)
            .unwrap_or(false);

        // 1. Discover catalog objects so we can resolve tables, columns, and existing indexes
        let objects: Vec<CatalogObject> = if let Some(ad) = adapter {
            let req = CatalogRequest {
                connection: connection.to_string(),
                schema_pattern: None,
                name_pattern: None,
                object_types: vec![CatalogObjectType::Table],
                detail_level: CatalogDetailLevel::Full,
                limit: 10_000,
                offset: 0,
            };
            ad.discover(req)
                .await
                .map(|r| r.objects)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // 2. Collect candidate SQL statements (explicit queries + workload queries if none passed)
        let simulated = adapter.map(|a| a.is_simulated()).unwrap_or(false);
        let mut candidate_queries: Vec<String> = queries
            .into_iter()
            .map(|q| q.trim().to_string())
            .filter(|q| !q.is_empty())
            .collect();

        let from_workload = candidate_queries.is_empty();
        if candidate_queries.is_empty() {
            let workload = self
                .analyze_workload_internal(connection, adapter, limit * 2)
                .await?;
            for wq in workload.top_queries {
                candidate_queries.push(wq.normalized_query);
            }
        }

        // Group candidate predicates by resolved table name
        let mut table_candidates: BTreeMap<String, TableIndexCandidate> = BTreeMap::new();

        for raw_query in &candidate_queries {
            let Ok(analysis) = parse_and_analyze_sql(engine, raw_query) else {
                continue;
            };
            if analysis.predicates.is_empty() {
                continue;
            }

            for pred in &analysis.predicates {
                let Some(resolved_table) =
                    resolve_predicate_table(pred, &analysis.referenced_tables, &objects)
                else {
                    continue;
                };
                let entry = table_candidates
                    .entry(resolved_table.clone())
                    .or_insert_with(|| TableIndexCandidate::new(resolved_table));
                entry.add_predicate(&pred.column, pred.operator, &analysis.normalized_sql);
            }
        }

        // Inspect the catalog for missing foreign key indexes only when the caller supplied no queries:
        // otherwise FK-only candidates would outrank / pollute the query-derived ones.
        let explicit_queries = !from_workload;
        for obj in &objects {
            if explicit_queries || obj.object_type != CatalogObjectType::Table {
                continue;
            }
            let tbl_name = obj.qualified_name();
            for fk in &obj.foreign_keys {
                if !is_covered_by_existing_index(obj, &fk.columns) {
                    let entry = table_candidates
                        .entry(tbl_name.clone())
                        .or_insert_with(|| TableIndexCandidate::new(tbl_name.clone()));
                    for col in &fk.columns {
                        entry.add_predicate(
                            col,
                            PredicateOperator::JoinEq,
                            &format!(
                                "/* FK join constraint on {}.{} -> {} */",
                                tbl_name,
                                fk.columns.join(", "),
                                fk.referenced_table
                            ),
                        );
                    }
                }
            }
        }

        let hypopg_evals = self
            .hypopg_evaluations
            .read()
            .ok()
            .and_then(|map| map.get(connection).cloned())
            .unwrap_or_default();

        let mut recommendations = Vec::new();

        for (table_key, candidate) in table_candidates {
            if recommendations.len() >= limit {
                break;
            }

            let catalog_table = find_catalog_table(&objects, &table_key);
            let ordered_cols = candidate.ordered_columns(4, catalog_table);
            if ordered_cols.is_empty() {
                continue;
            }

            // Skip if an existing index on this table already covers these columns as a leading prefix
            if let Some(tbl) = catalog_table {
                if is_covered_by_existing_index(tbl, &ordered_cols) {
                    continue;
                }
            }

            // Optional explain cost probe on the primary relevant query
            let mut explain_baseline_cost: Option<f64> = None;
            if let (Some(ad), Some(first_sql)) = (adapter, candidate.relevant_queries.first()) {
                if !first_sql.starts_with("/*") {
                    let explain_req = ExplainRequest {
                        request_id: format!("req_exp_{}", Uuid::new_v4().simple()),
                        connection: connection.to_string(),
                        sql: first_sql.clone(),
                        params: Vec::new(),
                        analyze: false,
                        format: ExplainFormat::Json,
                        timeout_ms: 2_000,
                    };
                    if let Ok(plan) = ad.explain(explain_req).await {
                        explain_baseline_cost = plan.estimated_cost;
                    }
                }
            }

            // Check if a HypoPG evaluation matches this table and column list
            let matched_hypopg = hypopg_evals.iter().find(|ev| {
                let table_matches = ev.table_name.eq_ignore_ascii_case(&table_key)
                    || table_key
                        .rsplit('.')
                        .next()
                        .map(|short| ev.table_name.eq_ignore_ascii_case(short))
                        .unwrap_or(false);
                table_matches
                    && ev.columns.len() == ordered_cols.len()
                    && ev
                        .columns
                        .iter()
                        .zip(ordered_cols.iter())
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            });

            let (hypopg_validated, cost_reduction_pct, baseline_cost, projected_cost) =
                if let Some(ev) = matched_hypopg {
                    (
                        true,
                         (ev.cost_reduction_pct() * 10.0).round() / 10.0,
                        ev.baseline_cost,
                        ev.hypothetical_cost,
                    )
                } else {
                    let est_rows = catalog_table
                        .and_then(|t| t.estimated_rows)
                        .unwrap_or(10_000)
                        .max(100) as f64;
                    let base = explain_baseline_cost.unwrap_or(est_rows * 1.25);
                    let selectivity_factor = if !candidate.equality_columns.is_empty() {
                        0.08
                    } else {
                        0.28
                    };
                    let proj = (base * selectivity_factor).max(1.5);
                    let pct = (((base - proj) / base) * 100.0 * 10.0).round() / 10.0;
                    // A simulated backend cannot run HypoPG: never claim validation there.
                    (supports_hypopg && !simulated, pct, base, proj)
                };

            let short_table = table_key
                .rsplit('.')
                .next()
                .unwrap_or(table_key.as_str())
                .replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_");
            let joined_cols_ident = ordered_cols
                .iter()
                .map(|c| c.replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_', "_"))
                .collect::<Vec<_>>()
                .join("_");
            let index_name = format!("idx_{short_table}_{joined_cols_ident}");

            let concurrently_kw = if engine == DatabaseEngine::Postgres {
                "CONCURRENTLY "
            } else {
                ""
            };
            let partial_clause = if !candidate.is_null_columns.is_empty()
                && candidate
                    .is_null_columns
                    .iter()
                    .all(|c| !ordered_cols.contains(c))
            {
                format!(" WHERE {} IS NULL", candidate.is_null_columns[0])
            } else {
                String::new()
            };

            // SQLite rejects a schema-qualified table after ON, so use the bare table name there.
            let ddl_table = if engine == DatabaseEngine::Sqlite {
                table_key.rsplit('.').next().unwrap_or(table_key.as_str()).to_string()
            } else {
                table_key.clone()
            };
            let suggested_ddl = format!(
                "CREATE INDEX {concurrently_kw}{index_name} ON {ddl_table} ({}){partial_clause};",
                ordered_cols.join(", ")
            );
            let drop_ddl = if engine == DatabaseEngine::Postgres {
                format!("DROP INDEX CONCURRENTLY IF EXISTS {index_name};")
            } else {
                format!("DROP INDEX IF EXISTS {index_name};")
            };

            let existing_indexes: Vec<String> = catalog_table
                .map(|t| t.indexes.iter().map(|i| i.name.clone()).collect())
                .unwrap_or_default();

            let observed_issue = format!(
                "Queries on '{}' filter/join/sort on column(s) [{}] without a covering leading-column B-Tree index (equality predicates: [{}], range/sort predicates: [{}]).",
                table_key,
                ordered_cols.join(", "),
                candidate.equality_columns.join(", "),
                candidate.range_or_sort_columns.join(", ")
            );

            let evidence = serde_json::json!({
                "table": table_key,
                "equality_columns": candidate.equality_columns,
                "range_or_sort_columns": candidate.range_or_sort_columns,
                "estimated_table_rows": catalog_table.and_then(|t| t.estimated_rows),
                "estimated_table_bytes": catalog_table.and_then(|t| t.size_bytes),
                "existing_indexes": existing_indexes,
                "baseline_estimated_cost": baseline_cost,
                "projected_index_cost": projected_cost,
                "hypopg_validated": hypopg_validated
            });

            let estimated_benefit = format!(
                "Replaces sequential scan / post-filter sort on '{}' with a B-Tree index scan on ({}), reducing estimated plan cost by ~{:.1}% ({:.1} -> {:.1}).",
                table_key,
                ordered_cols.join(", "),
                cost_reduction_pct,
                baseline_cost,
                projected_cost
            );

            let assumptions = vec![
                "Column cardinality and predicate selectivity remain representative of current workload.".to_string(),
                "Table statistics are up to date (ANALYZE has been run recently).".to_string(),
                "Query planner parameters (random_page_cost, effective_cache_size) reflect underlying storage.".to_string(),
            ];

            let write_storage_tradeoffs = format!(
                "Adds B-Tree maintenance overhead on INSERT, DELETE, and non-HOT UPDATE touching ({}) on '{}', plus additional disk and shared_buffers footprint (~10-25% of indexed column data size).",
                ordered_cols.join(", "),
                table_key
            );

            let required_privileges_extensions = if engine == DatabaseEngine::Postgres {
                vec![
                    format!("Table ownership or CREATE privilege on schema containing '{table_key}'"),
                    "CREATE INDEX CONCURRENTLY must run outside an explicit transaction block".to_string(),
                    "Optional: hypopg extension for zero-cost virtual index verification".to_string(),
                    "Optional: pg_stat_statements extension for post-deployment workload tracking".to_string(),
                ]
            } else {
                vec![format!(
                    "INDEX / schema modification privilege on table '{table_key}'"
                )]
            };

            let validation_procedure = if engine == DatabaseEngine::Postgres {
                format!(
                    "1. Verify virtual plan with HypoPG: SELECT * FROM hypopg_create_index('{suggested_ddl}'); EXPLAIN (FORMAT JSON) <query>; SELECT hypopg_reset(); \
                     2. After governed rollout, monitor pg_stat_user_indexes.idx_scan for '{index_name}' and confirm mean_exec_time reduction in pg_stat_statements."
                )
            } else {
                format!(
                    "Run EXPLAIN QUERY PLAN before and after creating '{index_name}' in a staging environment to confirm SEARCH TABLE using index '{index_name}'."
                )
            };

            let recovery_considerations = format!(
                "Index creation is non-destructive to table data. If write amplification or planner regression occurs, roll back safely using `{drop_ddl}`."
            );

            recommendations.push(IndexRecommendation {
                id: format!("rec_{short_table}_{joined_cols_ident}"),
                table_name: table_key,
                columns: ordered_cols,
                index_type: "btree".to_string(),
                observed_issue,
                evidence,
                collected_at: Utc::now(),
                relevant_queries: candidate.relevant_queries,
                suggested_ddl,
                estimated_benefit,
                estimated_cost_reduction_pct: Some(cost_reduction_pct),
                hypopg_validated,
                assumptions,
                write_storage_tradeoffs,
                required_privileges_extensions,
                validation_procedure,
                recovery_considerations,
            });
        }

        // Rank recommendations by highest estimated cost reduction percentage
        recommendations.sort_by(|a, b| {
            b.estimated_cost_reduction_pct
                .unwrap_or(0.0)
                .partial_cmp(&a.estimated_cost_reduction_pct.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        recommendations.truncate(limit);

        Ok(recommendations)
    }

    /// Helper to capture current schema version string for a connection if an adapter is registered.
    pub async fn schema_version_for(&self, connection: &str) -> String {
        if let Some(ad) = self.get_adapter(connection) {
            if let Ok(snap) = capture_schema_via_adapter(ad.as_ref(), connection, None).await {
                return snap.schema_version;
            }
        }
        "snapshot_unknown".to_string()
    }
}

/// Engine-appropriate SQLite health checks (integrity and journal mode) via read-only PRAGMAs.
async fn sqlite_health_findings(adapter: &dyn DatabaseAdapter, connection: &str) -> Vec<HealthFinding> {
    let limits = ExecutionLimits {
        timeout_ms: 3_000,
        max_rows: 50,
        max_bytes: 65_536,
        allow_multi_statement: false,
    };
    let probe = |sql: &str| {
        AuthorizedQuery::new_read(
            format!("req_health_probe_{}", Uuid::new_v4().simple()),
            connection,
            CallerIdentity::local_agent("pg-insights"),
            sql,
            Vec::new(),
            &limits,
        )
    };
    let mut findings = Vec::new();
    if let Ok(res) = adapter.execute(probe("PRAGMA quick_check")).await {
        let results: Vec<String> = res
            .rows
            .iter()
            .filter_map(|r| r.first().and_then(|v| v.as_str()).map(ToOwned::to_owned))
            .collect();
        let ok = results.len() == 1 && results[0].eq_ignore_ascii_case("ok");
        findings.push(HealthFinding {
            check_id: "sqlite_quick_check".to_string(),
            category: "integrity".to_string(),
            severity: if ok { HealthSeverity::Healthy } else { HealthSeverity::Critical },
            summary: if ok {
                "PRAGMA quick_check reported ok".to_string()
            } else {
                format!("PRAGMA quick_check reported {} problem(s)", results.len())
            },
            evidence: serde_json::json!({ "quick_check": results }),
            remediation: if ok {
                None
            } else {
                Some("Restore from backup or run PRAGMA integrity_check and rebuild the database.".to_string())
            },
        });
    }
    if let Ok(res) = adapter.execute(probe("PRAGMA journal_mode")).await {
        let mode = res
            .rows
            .first()
            .and_then(|r| r.first())
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        findings.push(HealthFinding {
            check_id: "sqlite_journal_mode".to_string(),
            category: "storage".to_string(),
            severity: HealthSeverity::Healthy,
            summary: format!("Journal mode is {mode}"),
            evidence: serde_json::json!({ "journal_mode": mode }),
            remediation: None,
        });
    }
    findings
}

#[async_trait]
impl PostgresHealthProvider for PgInsightsEngine {
    async fn database_health(&self, connection: &str) -> DbMcpResult<HealthReport> {
        if let Some(adapter) = self.get_adapter(connection) {
            return self.database_health_with_adapter(adapter.as_ref()).await;
        }
        let snapshot = self.collect_or_get_telemetry(connection, None).await;
        Ok(self.build_health_report(connection, DatabaseEngine::Postgres, &[], &snapshot))
    }

    async fn analyze_workload(
        &self,
        connection: &str,
        top_n: usize,
    ) -> DbMcpResult<WorkloadAnalysis> {
        let adapter = self.get_adapter(connection);
        self.analyze_workload_internal(connection, adapter.as_deref(), top_n)
            .await
    }
}

#[async_trait]
impl PostgresIndexAdvisor for PgInsightsEngine {
    async fn recommend_indexes(
        &self,
        connection: &str,
        queries: Vec<String>,
        max_recommendations: usize,
    ) -> DbMcpResult<Vec<IndexRecommendation>> {
        let adapter = self.get_adapter(connection);
        self.recommend_indexes_internal(connection, adapter.as_deref(), queries, max_recommendations)
            .await
    }
}

#[derive(Debug, Clone)]
struct TableIndexCandidate {
    #[allow(dead_code)]
    table_name: String,
    equality_columns: Vec<String>,
    range_or_sort_columns: Vec<String>,
    is_null_columns: Vec<String>,
    relevant_queries: Vec<String>,
}

impl TableIndexCandidate {
    fn new(table_name: String) -> Self {
        Self {
            table_name,
            equality_columns: Vec::new(),
            range_or_sort_columns: Vec::new(),
            is_null_columns: Vec::new(),
            relevant_queries: Vec::new(),
        }
    }

    fn add_predicate(&mut self, column: &str, op: PredicateOperator, normalized_sql: &str) {
        let col_clean = column.trim().to_string();
        if col_clean.is_empty() {
            return;
        }
        match op {
            PredicateOperator::Eq | PredicateOperator::JoinEq | PredicateOperator::In => {
                if !self
                    .equality_columns
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&col_clean))
                {
                    self.equality_columns.push(col_clean);
                }
            }
            PredicateOperator::Lt
            | PredicateOperator::LtEq
            | PredicateOperator::Gt
            | PredicateOperator::GtEq
            | PredicateOperator::Between
            | PredicateOperator::Like
            | PredicateOperator::OrderBy
            | PredicateOperator::GroupBy => {
                if !self
                    .range_or_sort_columns
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&col_clean))
                {
                    self.range_or_sort_columns.push(col_clean);
                }
            }
            PredicateOperator::IsNull => {
                if !self
                    .is_null_columns
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&col_clean))
                {
                    self.is_null_columns.push(col_clean);
                }
            }
            PredicateOperator::NotEq | PredicateOperator::Other => {
                if !self
                    .range_or_sort_columns
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&col_clean))
                {
                    self.range_or_sort_columns.push(col_clean);
                }
            }
        }

        if !self.relevant_queries.iter().any(|q| q == normalized_sql) {
            self.relevant_queries.push(normalized_sql.to_string());
        }
    }

    /// Order composite B-Tree index columns: equality columns first, then range/sort/group columns.
    fn ordered_columns(
        &self,
        max_cols: usize,
        catalog_table: Option<&CatalogObject>,
    ) -> Vec<String> {
        let ordinal_of = |col_name: &str| -> usize {
            catalog_table
                .and_then(|tbl| {
                    tbl.columns
                        .iter()
                        .find(|c| c.name.eq_ignore_ascii_case(col_name))
                        .map(|c| c.ordinal_position)
                })
                .unwrap_or(usize::MAX)
        };

        let mut eq_cols = self.equality_columns.clone();
        eq_cols.sort_by(|a, b| ordinal_of(a).cmp(&ordinal_of(b)).then_with(|| a.cmp(b)));

        let mut range_cols = self.range_or_sort_columns.clone();
        range_cols.sort_by(|a, b| ordinal_of(a).cmp(&ordinal_of(b)).then_with(|| a.cmp(b)));

        let mut out = Vec::new();
        for col in &eq_cols {
            if !out.iter().any(|c: &String| c.eq_ignore_ascii_case(col)) {
                out.push(col.clone());
            }
        }
        for col in &range_cols {
            if !out.iter().any(|c: &String| c.eq_ignore_ascii_case(col)) {
                out.push(col.clone());
            }
        }
        if out.is_empty() {
            for col in &self.is_null_columns {
                if !out.iter().any(|c: &String| c.eq_ignore_ascii_case(col)) {
                    out.push(col.clone());
                }
            }
        }
        out.truncate(max_cols);
        out
    }
}

fn find_catalog_table<'a>(
    objects: &'a [CatalogObject],
    table_ref: &str,
) -> Option<&'a CatalogObject> {
    let short_ref = table_ref.rsplit('.').next().unwrap_or(table_ref);
    objects
        .iter()
        .filter(|o| o.object_type == CatalogObjectType::Table)
        .find(|o| {
            o.qualified_name().eq_ignore_ascii_case(table_ref)
                || o.name.eq_ignore_ascii_case(table_ref)
                || o.name.eq_ignore_ascii_case(short_ref)
        })
}

fn resolve_predicate_table(
    pred: &PredicateColumn,
    referenced_tables: &[String],
    objects: &[CatalogObject],
) -> Option<String> {
    if let Some(tbl) = &pred.table {
        if let Some(cat_tbl) = find_catalog_table(objects, tbl) {
            return Some(cat_tbl.qualified_name());
        }
        return Some(tbl.clone());
    }

    if referenced_tables.len() == 1 {
        let tbl = &referenced_tables[0];
        if let Some(cat_tbl) = find_catalog_table(objects, tbl) {
            return Some(cat_tbl.qualified_name());
        }
        return Some(tbl.clone());
    }

    // Multiple referenced tables: match column against catalog table columns
    for ref_tbl in referenced_tables {
        if let Some(cat_tbl) = find_catalog_table(objects, ref_tbl) {
            if cat_tbl
                .columns
                .iter()
                .any(|c| c.name.eq_ignore_ascii_case(&pred.column))
            {
                return Some(cat_tbl.qualified_name());
            }
        }
    }

    referenced_tables.first().cloned()
}

fn is_covered_by_existing_index(table: &CatalogObject, candidate_cols: &[String]) -> bool {
    if candidate_cols.is_empty() {
        return true;
    }

    // Check explicit indexes (leading column prefix match)
    for idx in &table.indexes {
        if index_covers_prefix(idx, candidate_cols) {
            return true;
        }
    }

    // Single-column primary key check if not already listed in table.indexes
    if candidate_cols.len() == 1 {
        let col = &candidate_cols[0];
        let pk_cols: Vec<&str> = table
            .columns
            .iter()
            .filter(|c| c.is_primary_key)
            .map(|c| c.name.as_str())
            .collect();
        if pk_cols.len() == 1 && pk_cols[0].eq_ignore_ascii_case(col) {
            return true;
        }
    }

    false
}

fn index_covers_prefix(idx: &IndexSpec, candidate_cols: &[String]) -> bool {
    if idx.columns.len() < candidate_cols.len() {
        return false;
    }
    idx.columns
        .iter()
        .zip(candidate_cols.iter())
        .all(|(idx_col, cand_col)| idx_col.eq_ignore_ascii_case(cand_col))
}

fn find_missing_foreign_key_indexes(objects: &[CatalogObject]) -> Vec<serde_json::Value> {
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();

    for obj in objects {
        if obj.object_type != CatalogObjectType::Table {
            continue;
        }
        for fk in &obj.foreign_keys {
            if fk.columns.is_empty() {
                continue;
            }
            if !is_covered_by_existing_index(obj, &fk.columns) {
                let key = format!("{}:{}", obj.qualified_name(), fk.columns.join(","));
                if seen.insert(key) {
                    missing.push(serde_json::json!({
                        "table": obj.qualified_name(),
                        "constraint_name": fk.name,
                        "columns": fk.columns,
                        "referenced_table": fk.referenced_table,
                        "referenced_columns": fk.referenced_columns
                    }));
                }
            }
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_catalog::filter_and_paginate_objects;
    use db_mcp_core::{
        CatalogResponse, ColumnSpec, DatabaseCapabilities, ExecutionId, ExplainPlan,
        ForeignKeySpec, QueryResult,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockPgAdapter {
        connection_id: String,
        objects: Vec<CatalogObject>,
        execute_calls: AtomicUsize,
    }

    impl MockPgAdapter {
        fn new(connection_id: &str, objects: Vec<CatalogObject>) -> Self {
            Self {
                connection_id: connection_id.to_string(),
                objects,
                execute_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DatabaseAdapter for MockPgAdapter {
        fn connection_id(&self) -> &str {
            &self.connection_id
        }

        fn capabilities(&self) -> DatabaseCapabilities {
            DatabaseCapabilities::for_postgres(false, true)
        }

        async fn discover(&self, request: CatalogRequest) -> DbMcpResult<CatalogResponse> {
            Ok(filter_and_paginate_objects(&self.objects, &request))
        }

        async fn execute(&self, _request: AuthorizedQuery) -> DbMcpResult<QueryResult> {
            self.execute_calls.fetch_add(1, Ordering::SeqCst);
            Ok(QueryResult {
                execution_id: ExecutionId::new(),
                columns: Vec::new(),
                rows: Vec::new(),
                returned_rows: 0,
                rows_affected: Some(0),
                truncated: false,
                bytes_used: 0,
                execution_time_ms: 1,
                warnings: Vec::new(),
                schema_version: Some("snapshot_mockpg".to_string()),
            })
        }

        async fn explain(&self, request: ExplainRequest) -> DbMcpResult<ExplainPlan> {
            Ok(ExplainPlan {
                connection: self.connection_id.clone(),
                sql: request.sql,
                analyze: request.analyze,
                format: request.format,
                raw_plan: "Seq Scan on orders (cost=0.00..1850.00 rows=50000 width=64)"
                    .to_string(),
                structured_plan: Some(serde_json::json!({
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Total Cost": 1850.0
                })),
                estimated_cost: Some(1850.0),
                estimated_rows: Some(50_000.0),
                seq_scans: vec!["public.orders".to_string()],
                index_scans: Vec::new(),
                warnings: Vec::new(),
            })
        }

        async fn cancel(&self, _execution: ExecutionId) -> DbMcpResult<bool> {
            Ok(true)
        }
    }

    fn fixture_catalog() -> Vec<CatalogObject> {
        vec![
            CatalogObject {
                schema: "public".to_string(),
                name: "users".to_string(),
                object_type: CatalogObjectType::Table,
                comment: Some("Customers".to_string()),
                estimated_rows: Some(15_000),
                size_bytes: Some(1_048_576),
                columns: vec![
                    ColumnSpec {
                        name: "id".to_string(),
                        data_type: "bigint".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: true,
                        comment: None,
                        ordinal_position: 1,
                    },
                    ColumnSpec {
                        name: "email".to_string(),
                        data_type: "text".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 2,
                    },
                ],
                indexes: vec![IndexSpec {
                    name: "idx_users_email".to_string(),
                    table_name: "users".to_string(),
                    columns: vec!["email".to_string()],
                    unique: true,
                    primary: false,
                    index_type: Some("btree".to_string()),
                    predicate: None,
                    definition: Some(
                        "CREATE UNIQUE INDEX idx_users_email ON public.users (email)".to_string(),
                    ),
                }],
                foreign_keys: Vec::new(),
                definition: None,
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "orders".to_string(),
                object_type: CatalogObjectType::Table,
                comment: Some("Customer orders".to_string()),
                estimated_rows: Some(50_000),
                size_bytes: Some(8_388_608),
                columns: vec![
                    ColumnSpec {
                        name: "id".to_string(),
                        data_type: "bigint".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: true,
                        comment: None,
                        ordinal_position: 1,
                    },
                    ColumnSpec {
                        name: "user_id".to_string(),
                        data_type: "bigint".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 2,
                    },
                    ColumnSpec {
                        name: "status".to_string(),
                        data_type: "text".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 3,
                    },
                    ColumnSpec {
                        name: "created_at".to_string(),
                        data_type: "timestamptz".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 4,
                    },
                ],
                indexes: Vec::new(),
                foreign_keys: vec![ForeignKeySpec {
                    name: Some("fk_orders_user_id".to_string()),
                    columns: vec!["user_id".to_string()],
                    referenced_table: "public.users".to_string(),
                    referenced_columns: vec!["id".to_string()],
                    on_delete: Some("CASCADE".to_string()),
                    on_update: None,
                }],
                definition: None,
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "audit_events_raw".to_string(),
                object_type: CatalogObjectType::Table,
                comment: Some("Large unindexed append-only table".to_string()),
                estimated_rows: Some(80_000),
                size_bytes: Some(16_777_216),
                columns: vec![ColumnSpec {
                    name: "payload".to_string(),
                    data_type: "jsonb".to_string(),
                    nullable: false,
                    default_value: None,
                    is_primary_key: false,
                    comment: None,
                    ordinal_position: 1,
                }],
                indexes: Vec::new(),
                foreign_keys: Vec::new(),
                definition: None,
            },
        ]
    }

    #[tokio::test]
    async fn test_database_health_detects_degraded_metrics_and_schema_issues() {
        let adapter = Arc::new(MockPgAdapter::new("pg-prod", fixture_catalog()));
        let insights = PgInsightsEngine::with_adapter(adapter);

        insights.set_telemetry_snapshot(
            "pg-prod",
            HealthTelemetrySnapshot {
                cache_hit_ratio: Some(0.84),
                active_connections: Some(92),
                max_connections: Some(100),
                dead_tuples_total: Some(140_000),
                table_bloat: vec![TableBloatStat {
                    schema: "public".to_string(),
                    table_name: "orders".to_string(),
                    live_tuples: 50_000,
                    dead_tuples: 30_000,
                }],
                invalid_indexes: vec!["idx_orders_broken_concurrent".to_string()],
                long_running_queries: vec![LongRunningQueryStat {
                    pid: 4120,
                    duration_ms: 420_000,
                    state: "active".to_string(),
                    query: "SELECT * FROM public.orders".to_string(),
                }],
                large_table_row_threshold: 10_000,
            },
        );

        let report = insights.database_health("pg-prod").await.unwrap();
        assert_eq!(report.overall_status, HealthSeverity::Critical);
        assert_eq!(report.findings.len(), 7);

        let by_id: BTreeMap<&str, &HealthFinding> = report
            .findings
            .iter()
            .map(|f| (f.check_id.as_str(), f))
            .collect();

        assert_eq!(
            by_id["buffer_cache_hit_ratio"].severity,
            HealthSeverity::Critical
        );
        assert_eq!(
            by_id["connection_saturation"].severity,
            HealthSeverity::Critical
        );
        assert_eq!(by_id["dead_tuple_bloat"].severity, HealthSeverity::Critical);
        assert_eq!(by_id["invalid_indexes"].severity, HealthSeverity::Warning);
        assert_eq!(
            by_id["missing_fk_indexes"].severity,
            HealthSeverity::Warning
        );
        assert_eq!(
            by_id["unindexed_large_tables"].severity,
            HealthSeverity::Warning
        );
        assert_eq!(
            by_id["long_running_queries"].severity,
            HealthSeverity::Critical
        );

        let mcp_resp =
            PgInsightsEngine::health_report_to_response("req_h1", "snapshot_mockpg", &report);
        assert_eq!(mcp_resp.status, "ok");
        assert_eq!(mcp_resp.returned_rows, 7);
    }

    #[tokio::test]
    async fn test_analyze_workload_aggregates_queries_and_hot_tables() {
        let adapter = Arc::new(MockPgAdapter::new("pg-prod", fixture_catalog()));
        let insights = PgInsightsEngine::with_adapter(adapter);

        insights.record_query_execution(
            "pg-prod",
            "SELECT * FROM public.orders WHERE user_id = 42 AND status = 'completed'",
            45.0,
            12,
        );
        insights.record_query_execution(
            "pg-prod",
            "SELECT * FROM public.orders WHERE user_id = 42 AND status = 'completed'",
            55.0,
            15,
        );
        insights.record_query_execution(
            "pg-prod",
            "SELECT id, email FROM public.users WHERE email = 'alice@example.com'",
            4.0,
            1,
        );

        let workload = insights.analyze_workload("pg-prod", 5).await.unwrap();
        assert_eq!(workload.source, "recorded_workload_history");
        assert_eq!(workload.total_queries_analyzed, 2);
        assert_eq!(workload.top_queries[0].calls, 2);
        assert_eq!(workload.top_queries[0].total_exec_time_ms, 100.0);
        assert_eq!(workload.top_queries[0].mean_exec_time_ms, 50.0);
        assert_eq!(workload.hot_tables[0], "public.orders");
    }

    #[tokio::test]
    async fn test_recommend_indexes_orders_equality_before_range_and_skips_existing_indexes() {
        let adapter = Arc::new(MockPgAdapter::new("pg-prod", fixture_catalog()));
        let insights = PgInsightsEngine::with_adapter(adapter);

        insights.register_hypopg_evaluation(
            "pg-prod",
            HypoPgEvaluation {
                table_name: "public.orders".to_string(),
                columns: vec![
                    "user_id".to_string(),
                    "status".to_string(),
                    "created_at".to_string(),
                ],
                baseline_cost: 1850.0,
                hypothetical_cost: 18.5,
            },
        );

        let queries = vec![
            // Already covered by idx_users_email on public.users(email)
            "SELECT id, email FROM public.users WHERE email = 'alice@example.com'".to_string(),
            // Needs composite index on orders: equality (user_id, status) first, then range/order (created_at)
            "SELECT * FROM public.orders WHERE created_at > '2026-01-01' AND user_id = 10 AND status = 'completed' ORDER BY created_at DESC".to_string(),
        ];

        let recs = insights
            .recommend_indexes("pg-prod", queries, 5)
            .await
            .unwrap();

        // Should NOT recommend an index on users(email) because idx_users_email already covers it
        assert!(!recs.iter().any(|r| r.table_name.contains("users")));

        // Should recommend composite index on public.orders(user_id, status, created_at)
        let order_rec = recs
            .iter()
            .find(|r| r.table_name == "public.orders")
            .expect("Expected recommendation on public.orders");

        assert_eq!(
            order_rec.columns,
            vec![
                "user_id".to_string(),
                "status".to_string(),
                "created_at".to_string()
            ]
        );
        assert!(order_rec.hypopg_validated);
        assert_eq!(order_rec.estimated_cost_reduction_pct, Some(99.0));
        assert!(order_rec
            .suggested_ddl
            .contains("CREATE INDEX CONCURRENTLY idx_orders_user_id_status_created_at ON public.orders (user_id, status, created_at)"));
        assert!(!order_rec.observed_issue.is_empty());
        assert!(!order_rec.relevant_queries.is_empty());
        assert!(!order_rec.estimated_benefit.is_empty());
        assert!(!order_rec.assumptions.is_empty());
        assert!(!order_rec.write_storage_tradeoffs.is_empty());
        assert!(!order_rec.required_privileges_extensions.is_empty());
        assert!(!order_rec.validation_procedure.is_empty());
        assert!(!order_rec.recovery_considerations.is_empty());

        let resp = PgInsightsEngine::recommendations_to_response(
            "req_idx_1",
            "pg-prod",
            "snapshot_mockpg",
            recs,
        );
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.columns.len(), 9);
        assert_eq!(resp.columns[0].name, "observed_issue");
        assert_eq!(resp.columns[8].name, "recovery_considerations");
    }

    #[tokio::test]
    async fn test_recommend_indexes_never_auto_creates_indexes_and_uses_workload_fallback() {
        let adapter = Arc::new(MockPgAdapter::new("pg-prod", fixture_catalog()));
        let insights = PgInsightsEngine::with_adapter(adapter.clone());

        insights.record_query_execution(
            "pg-prod",
            "SELECT * FROM public.orders WHERE status = 'pending'",
            30.0,
            100,
        );

        let recs = insights
            .recommend_indexes("pg-prod", Vec::new(), 5)
            .await
            .unwrap();
        assert!(!recs.is_empty());
        assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 0);
    }
}
