//! Progressive schema discovery (`filter_and_paginate_objects`, `describe_object`),
//! deterministic schema snapshots (`capture_schema` with `snapshot_<short_hash>`),
//! and structural schema diffing (`diff_schema`) with transactional and reversal safety classification.

use std::collections::BTreeMap;

use chrono::Utc;
use db_mcp_core::{
    CatalogDetailLevel, CatalogObject, CatalogObjectType, CatalogRequest, CatalogResponse,
    ColumnSpec, DatabaseAdapter, DatabaseEngine, DbMcpError, DbMcpResult, DiffOperationKind,
    IndexSpec, ReversalSafety, SchemaDiff, SchemaDiffItem, SchemaSnapshot,
};
use sha2::{Digest, Sha256};

pub mod lineage;
pub use lineage::*;

/// Match an identifier against an optional SQL `LIKE` (`%`, `_`), glob (`*`, `?`), or substring pattern.
pub fn matches_pattern(pattern: Option<&str>, candidate: &str) -> bool {
    let Some(raw_pat) = pattern.map(str::trim).filter(|p| !p.is_empty()) else {
        return true;
    };
    if raw_pat == "*" || raw_pat == "%" {
        return true;
    }

    let pat_lower = raw_pat.to_ascii_lowercase();
    let cand_lower = candidate.to_ascii_lowercase();

    if pat_lower.contains('%')
        || pat_lower.contains('_')
        || pat_lower.contains('*')
        || pat_lower.contains('?')
    {
        wildcard_match(&pat_lower, &cand_lower)
    } else {
        cand_lower.contains(&pat_lower)
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == '%' || p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p.len() {
        for j in 1..=t.len() {
            match p[i - 1] {
                '%' | '*' => {
                    dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
                }
                '_' | '?' => {
                    dp[i][j] = dp[i - 1][j - 1];
                }
                ch => {
                    dp[i][j] = dp[i - 1][j - 1] && ch == t[j - 1];
                }
            }
        }
    }

    dp[p.len()][t.len()]
}

/// Canonicalize and sort a slice of `CatalogObject`s for deterministic hashing and pagination.
pub fn canonicalize_objects(objects: &[CatalogObject]) -> Vec<CatalogObject> {
    let mut sorted = objects.to_vec();
    for obj in &mut sorted {
        obj.columns
            .sort_by(|a, b| a.ordinal_position.cmp(&b.ordinal_position).then_with(|| a.name.cmp(&b.name)));
        obj.indexes.sort_by(|a, b| a.name.cmp(&b.name));
        obj.foreign_keys
            .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.columns.cmp(&b.columns)));
    }
    sorted.sort_by(|a, b| {
        a.schema
            .cmp(&b.schema)
            .then_with(|| a.object_type.cmp(&b.object_type))
            .then_with(|| a.name.cmp(&b.name))
    });
    sorted
}

/// Compute both `(schema_version, full_sha256_hash)` for a catalog object set.
/// `schema_version` has the deterministic format `snapshot_<12_char_hex>`.
pub fn compute_schema_hashes(objects: &[CatalogObject]) -> (String, String) {
    let mut canonical = canonicalize_objects(objects);
    // Row statistics are data, not schema: inserting rows must never change the fingerprint
    // (it would otherwise trigger false schema-drift denials and ontology staleness).
    for obj in &mut canonical {
        obj.estimated_rows = None;
        obj.size_bytes = None;
    }
    let mut hasher = Sha256::new();
    let serialized = serde_json::to_vec(&canonical).unwrap_or_default();
    hasher.update(&serialized);
    let full_hash = hex::encode(hasher.finalize());
    let short_hash = &full_hash[..12];
    (format!("snapshot_{short_hash}"), full_hash)
}

/// Compute the `snapshot_<short_hash>` version string for a catalog object set.
pub fn compute_schema_version(objects: &[CatalogObject]) -> String {
    compute_schema_hashes(objects).0
}

/// Filter, sort, project to the requested `CatalogDetailLevel`, and paginate catalog objects.
pub fn filter_and_paginate_objects(
    all_objects: &[CatalogObject],
    request: &CatalogRequest,
) -> CatalogResponse {
    let canonical = canonicalize_objects(all_objects);
    let schema_version = compute_schema_version(&canonical);

    let filtered: Vec<&CatalogObject> = canonical
        .iter()
        .filter(|obj| {
            if !request.object_types.is_empty() && !request.object_types.contains(&obj.object_type)
            {
                return false;
            }
            if !matches_pattern(request.schema_pattern.as_deref(), &obj.schema) {
                return false;
            }
            if let Some(name_pat) = request.name_pattern.as_deref() {
                let matches_name = matches_pattern(Some(name_pat), &obj.name)
                    || matches_pattern(Some(name_pat), &obj.qualified_name())
                    || obj
                        .columns
                        .iter()
                        .any(|col| matches_pattern(Some(name_pat), &col.name));
                if !matches_name {
                    return false;
                }
            }
            true
        })
        .collect();

    let total_count = filtered.len();
    let limit = if request.limit == 0 { 50 } else { request.limit };
    let offset = request.offset.min(total_count);

    let page: Vec<CatalogObject> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|obj| obj.project(request.detail_level))
        .collect();

    let returned_count = page.len();
    let has_more = offset + returned_count < total_count;
    let next_offset = if has_more {
        Some(offset + returned_count)
    } else {
        None
    };

    CatalogResponse {
        objects: page,
        total_count,
        returned_count,
        has_more,
        next_offset,
        schema_version: Some(schema_version),
    }
}

/// Locate a single catalog object by `(optional_schema, object_name)` and project it to `detail_level`.
pub fn describe_object(
    all_objects: &[CatalogObject],
    schema: Option<&str>,
    object_name: &str,
    detail_level: CatalogDetailLevel,
) -> DbMcpResult<CatalogObject> {
    let trimmed = object_name.trim();
    if trimmed.is_empty() {
        return Err(DbMcpError::InvalidArgument(
            "object_name must not be empty".to_string(),
        ));
    }

    let (target_schema, target_name) = match (schema, trimmed.split_once('.')) {
        (Some(s), _) if !s.trim().is_empty() => (Some(s.trim()), trimmed),
        (None, Some((s, n))) => (Some(s.trim()), n.trim()),
        _ => (None, trimmed),
    };

    let found = all_objects
        .iter()
        .find(|obj| {
            let name_match = obj.name.eq_ignore_ascii_case(target_name);
            let schema_match = target_schema
                .map(|s| obj.schema.eq_ignore_ascii_case(s))
                .unwrap_or(true);
            name_match && schema_match
        })
        .ok_or_else(|| {
            DbMcpError::InvalidArgument(format!(
                "Catalog object '{}' was not found",
                object_name
            ))
        })?;

    Ok(found.project(detail_level))
}

/// Capture a deterministic `SchemaSnapshot` from a collection of `CatalogObject`s.
pub fn capture_schema(
    connection: impl Into<String>,
    engine: DatabaseEngine,
    objects: Vec<CatalogObject>,
) -> SchemaSnapshot {
    let canonical = canonicalize_objects(&objects);
    let (schema_version, full_hash) = compute_schema_hashes(&canonical);
    SchemaSnapshot {
        connection: connection.into(),
        engine,
        schema_version,
        full_hash,
        captured_at: Utc::now(),
        objects: canonical,
    }
}

/// Capture a `SchemaSnapshot` directly from a `DatabaseAdapter`.
pub async fn capture_schema_via_adapter(
    adapter: &dyn DatabaseAdapter,
    connection: &str,
    schema_pattern: Option<String>,
) -> DbMcpResult<SchemaSnapshot> {
    let request = CatalogRequest {
        connection: connection.to_string(),
        schema_pattern,
        name_pattern: None,
        object_types: Vec::new(),
        detail_level: CatalogDetailLevel::Full,
        limit: 10_000,
        offset: 0,
    };
    let response = adapter.discover(request).await?;
    let engine = adapter.capabilities().engine;
    Ok(capture_schema(connection, engine, response.objects))
}

/// Compute a structural `SchemaDiff` between `base` and `target` snapshots,
/// comparing tables, columns, indexes, and views with transactional/reversal safety classification.
pub fn diff_schema(base: &SchemaSnapshot, target: &SchemaSnapshot) -> SchemaDiff {
    let engine = target.engine;
    let engine_transactional_ddl = matches!(
        engine,
        DatabaseEngine::Postgres | DatabaseEngine::Sqlite
    );

    let mut items = Vec::new();

    // Index base and target objects by (object_type, qualified_name_lower)
    let mut base_tables: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut target_tables: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut base_views: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut target_views: BTreeMap<String, &CatalogObject> = BTreeMap::new();

    for obj in &base.objects {
        let key = obj.qualified_name().to_ascii_lowercase();
        match obj.object_type {
            CatalogObjectType::Table => {
                base_tables.insert(key, obj);
            }
            CatalogObjectType::View | CatalogObjectType::MaterializedView => {
                base_views.insert(key, obj);
            }
            _ => {}
        }
    }

    for obj in &target.objects {
        let key = obj.qualified_name().to_ascii_lowercase();
        match obj.object_type {
            CatalogObjectType::Table => {
                target_tables.insert(key, obj);
            }
            CatalogObjectType::View | CatalogObjectType::MaterializedView => {
                target_views.insert(key, obj);
            }
            _ => {}
        }
    }

    // 1. Compare tables
    for (key, target_tbl) in &target_tables {
        let qname = target_tbl.qualified_name();
        if let Some(base_tbl) = base_tables.get(key) {
            diff_table_columns(
                &qname,
                &base_tbl.columns,
                &target_tbl.columns,
                engine_transactional_ddl,
                &mut items,
            );
            diff_table_indexes(
                &qname,
                &base_tbl.indexes,
                &target_tbl.indexes,
                engine_transactional_ddl,
                &mut items,
            );
        } else {
            let reversal = if engine_transactional_ddl {
                ReversalSafety::TransactionalRollback
            } else {
                ReversalSafety::CompensatingMigrationRequired
            };
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::AddTable,
                object_name: qname.clone(),
                target_name: None,
                before: None,
                after: target_tbl.definition.clone().or_else(|| {
                    Some(format!("table {} ({} columns)", qname, target_tbl.columns.len()))
                }),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: reversal,
                suggested_ddl: target_tbl
                    .definition
                    .clone()
                    .or_else(|| Some(format!("CREATE TABLE {qname} (...);"))),
                compensating_ddl: Some(format!("DROP TABLE {qname};")),
            });
        }
    }

    for (key, base_tbl) in &base_tables {
        if !target_tables.contains_key(key) {
            let qname = base_tbl.qualified_name();
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::DropTable,
                object_name: qname.clone(),
                target_name: None,
                before: base_tbl.definition.clone().or_else(|| {
                    Some(format!("table {} ({} columns)", qname, base_tbl.columns.len()))
                }),
                after: None,
                destructive: true,
                transactional: engine_transactional_ddl,
                reversal_safety: ReversalSafety::BackupRecoveryRequired,
                suggested_ddl: Some(format!("DROP TABLE {qname};")),
                compensating_ddl: base_tbl.definition.clone(),
            });
        }
    }

    // 2. Compare views
    for (key, target_view) in &target_views {
        let qname = target_view.qualified_name();
        if let Some(base_view) = base_views.get(key) {
            if base_view.definition != target_view.definition
                || base_view.columns != target_view.columns
            {
                let reversal = if engine_transactional_ddl {
                    ReversalSafety::TransactionalRollback
                } else {
                    ReversalSafety::CompensatingMigrationRequired
                };
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterView,
                    object_name: qname.clone(),
                    target_name: None,
                    before: base_view.definition.clone(),
                    after: target_view.definition.clone(),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: reversal,
                    suggested_ddl: target_view.definition.clone(),
                    compensating_ddl: base_view.definition.clone(),
                });
            }
        } else {
            let reversal = if engine_transactional_ddl {
                ReversalSafety::TransactionalRollback
            } else {
                ReversalSafety::CompensatingMigrationRequired
            };
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::AddView,
                object_name: qname.clone(),
                target_name: None,
                before: None,
                after: target_view.definition.clone(),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: reversal,
                suggested_ddl: target_view
                    .definition
                    .clone()
                    .or_else(|| Some(format!("CREATE VIEW {qname} AS ...;"))),
                compensating_ddl: Some(format!("DROP VIEW {qname};")),
            });
        }
    }

    for (key, base_view) in &base_views {
        if !target_views.contains_key(key) {
            let qname = base_view.qualified_name();
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::DropView,
                object_name: qname.clone(),
                target_name: None,
                before: base_view.definition.clone(),
                after: None,
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                suggested_ddl: Some(format!("DROP VIEW {qname};")),
                compensating_ddl: base_view.definition.clone(),
            });
        }
    }

    let is_identical = items.is_empty();
    let has_destructive_changes = items.iter().any(|i| i.destructive);
    let all_transactional = items.iter().all(|i| i.transactional);
    let summary = if is_identical {
        format!(
            "Schemas {} and {} are identical (0 changes).",
            base.schema_version, target.schema_version
        )
    } else {
        format!(
            "Detected {} structural change(s) between {} and {} (destructive={}, all_transactional={}).",
            items.len(),
            base.schema_version,
            target.schema_version,
            has_destructive_changes,
            all_transactional
        )
    };

    SchemaDiff {
        base_schema_version: base.schema_version.clone(),
        target_schema_version: target.schema_version.clone(),
        engine,
        is_identical,
        has_destructive_changes,
        all_transactional,
        items,
        summary,
    }
}

fn diff_table_columns(
    table_qname: &str,
    base_cols: &[ColumnSpec],
    target_cols: &[ColumnSpec],
    engine_transactional_ddl: bool,
    items: &mut Vec<SchemaDiffItem>,
) {
    let base_map: BTreeMap<String, &ColumnSpec> = base_cols
        .iter()
        .map(|c| (c.name.to_ascii_lowercase(), c))
        .collect();
    let target_map: BTreeMap<String, &ColumnSpec> = target_cols
        .iter()
        .map(|c| (c.name.to_ascii_lowercase(), c))
        .collect();

    for (col_key, t_col) in &target_map {
        if let Some(b_col) = base_map.get(col_key) {
            if !b_col.data_type.eq_ignore_ascii_case(&t_col.data_type) {
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterColumnType,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_col.name.clone()),
                    before: Some(b_col.data_type.clone()),
                    after: Some(t_col.data_type.clone()),
                    destructive: true,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: Some(format!(
                        "ALTER TABLE {table_qname} ALTER COLUMN {} TYPE {};",
                        t_col.name, t_col.data_type
                    )),
                    compensating_ddl: Some(format!(
                        "ALTER TABLE {table_qname} ALTER COLUMN {} TYPE {};",
                        b_col.name, b_col.data_type
                    )),
                });
            }
            if b_col.nullable != t_col.nullable {
                let action = if t_col.nullable {
                    "DROP NOT NULL"
                } else {
                    "SET NOT NULL"
                };
                let reverse_action = if b_col.nullable {
                    "DROP NOT NULL"
                } else {
                    "SET NOT NULL"
                };
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterColumnNullability,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_col.name.clone()),
                    before: Some(format!("nullable={}", b_col.nullable)),
                    after: Some(format!("nullable={}", t_col.nullable)),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: Some(format!(
                        "ALTER TABLE {table_qname} ALTER COLUMN {} {action};",
                        t_col.name
                    )),
                    compensating_ddl: Some(format!(
                        "ALTER TABLE {table_qname} ALTER COLUMN {} {reverse_action};",
                        b_col.name
                    )),
                });
            }
            if b_col.default_value != t_col.default_value {
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterColumnDefault,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_col.name.clone()),
                    before: b_col.default_value.clone(),
                    after: t_col.default_value.clone(),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: if engine_transactional_ddl {
                        ReversalSafety::TransactionalRollback
                    } else {
                        ReversalSafety::CompensatingMigrationRequired
                    },
                    suggested_ddl: None,
                    compensating_ddl: None,
                });
            }
        } else {
            let null_clause = if t_col.nullable { "" } else { " NOT NULL" };
            let default_clause = t_col
                .default_value
                .as_ref()
                .map(|d| format!(" DEFAULT {d}"))
                .unwrap_or_default();
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::AddColumn,
                object_name: table_qname.to_string(),
                target_name: Some(t_col.name.clone()),
                before: None,
                after: Some(format!(
                    "{} {}{}{}",
                    t_col.name, t_col.data_type, null_clause, default_clause
                )),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: if engine_transactional_ddl {
                    ReversalSafety::TransactionalRollback
                } else {
                    ReversalSafety::CompensatingMigrationRequired
                },
                suggested_ddl: Some(format!(
                    "ALTER TABLE {table_qname} ADD COLUMN {} {}{}{};",
                    t_col.name, t_col.data_type, null_clause, default_clause
                )),
                compensating_ddl: Some(format!(
                    "ALTER TABLE {table_qname} DROP COLUMN {};",
                    t_col.name
                )),
            });
        }
    }

    for (col_key, b_col) in &base_map {
        if !target_map.contains_key(col_key) {
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::DropColumn,
                object_name: table_qname.to_string(),
                target_name: Some(b_col.name.clone()),
                before: Some(format!("{} {}", b_col.name, b_col.data_type)),
                after: None,
                destructive: true,
                transactional: engine_transactional_ddl,
                reversal_safety: ReversalSafety::BackupRecoveryRequired,
                suggested_ddl: Some(format!(
                    "ALTER TABLE {table_qname} DROP COLUMN {};",
                    b_col.name
                )),
                compensating_ddl: Some(format!(
                    "ALTER TABLE {table_qname} ADD COLUMN {} {};",
                    b_col.name, b_col.data_type
                )),
            });
        }
    }
}

fn diff_table_indexes(
    table_qname: &str,
    base_idxs: &[IndexSpec],
    target_idxs: &[IndexSpec],
    engine_transactional_ddl: bool,
    items: &mut Vec<SchemaDiffItem>,
) {
    let base_map: BTreeMap<String, &IndexSpec> = base_idxs
        .iter()
        .map(|i| (i.name.to_ascii_lowercase(), i))
        .collect();
    let target_map: BTreeMap<String, &IndexSpec> = target_idxs
        .iter()
        .map(|i| (i.name.to_ascii_lowercase(), i))
        .collect();

    for (idx_key, t_idx) in &target_map {
        let unique_kw = if t_idx.unique { "UNIQUE " } else { "" };
        let create_ddl = t_idx.definition.clone().unwrap_or_else(|| {
            format!(
                "CREATE {unique_kw}INDEX {} ON {table_qname} ({});",
                t_idx.name,
                t_idx.columns.join(", ")
            )
        });
        if let Some(b_idx) = base_map.get(idx_key) {
            if b_idx.columns != t_idx.columns
                || b_idx.unique != t_idx.unique
                || b_idx.predicate != t_idx.predicate
            {
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterIndex,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_idx.name.clone()),
                    before: Some(format!(
                        "columns=({}), unique={}",
                        b_idx.columns.join(","),
                        b_idx.unique
                    )),
                    after: Some(format!(
                        "columns=({}), unique={}",
                        t_idx.columns.join(","),
                        t_idx.unique
                    )),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: Some(format!("DROP INDEX {}; {create_ddl}", b_idx.name)),
                    compensating_ddl: b_idx.definition.clone(),
                });
            }
        } else {
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::AddIndex,
                object_name: table_qname.to_string(),
                target_name: Some(t_idx.name.clone()),
                before: None,
                after: Some(format!(
                    "columns=({}), unique={}",
                    t_idx.columns.join(","),
                    t_idx.unique
                )),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: if engine_transactional_ddl {
                    ReversalSafety::TransactionalRollback
                } else {
                    ReversalSafety::CompensatingMigrationRequired
                },
                suggested_ddl: Some(create_ddl),
                compensating_ddl: Some(format!("DROP INDEX {};", t_idx.name)),
            });
        }
    }

    for (idx_key, b_idx) in &base_map {
        if !target_map.contains_key(idx_key) {
            let unique_kw = if b_idx.unique { "UNIQUE " } else { "" };
            let recreate_ddl = b_idx.definition.clone().unwrap_or_else(|| {
                format!(
                    "CREATE {unique_kw}INDEX {} ON {table_qname} ({});",
                    b_idx.name,
                    b_idx.columns.join(", ")
                )
            });
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::DropIndex,
                object_name: table_qname.to_string(),
                target_name: Some(b_idx.name.clone()),
                before: Some(format!(
                    "columns=({}), unique={}",
                    b_idx.columns.join(","),
                    b_idx.unique
                )),
                after: None,
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                suggested_ddl: Some(format!("DROP INDEX {};", b_idx.name)),
                compensating_ddl: Some(recreate_ddl),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_objects() -> Vec<CatalogObject> {
        vec![
            CatalogObject {
                schema: "public".to_string(),
                name: "users".to_string(),
                object_type: CatalogObjectType::Table,
                comment: Some("Application users".to_string()),
                estimated_rows: Some(1200),
                size_bytes: Some(65536),
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
                    definition: None,
                }],
                foreign_keys: vec![],
                definition: Some(
                    "CREATE TABLE public.users (id bigint PRIMARY KEY, email text NOT NULL);"
                        .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "orders".to_string(),
                object_type: CatalogObjectType::Table,
                comment: Some("Customer orders".to_string()),
                estimated_rows: Some(5400),
                size_bytes: Some(131072),
                columns: vec![ColumnSpec {
                    name: "id".to_string(),
                    data_type: "bigint".to_string(),
                    nullable: false,
                    default_value: None,
                    is_primary_key: true,
                    comment: None,
                    ordinal_position: 1,
                }],
                indexes: vec![],
                foreign_keys: vec![],
                definition: None,
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "active_users_view".to_string(),
                object_type: CatalogObjectType::View,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some("SELECT id, email FROM public.users".to_string()),
            },
        ]
    }

    #[test]
    fn test_progressive_discovery_and_pagination() {
        let objects = sample_objects();
        let req = CatalogRequest {
            connection: "app-dev".to_string(),
            schema_pattern: Some("public".to_string()),
            name_pattern: None,
            object_types: vec![CatalogObjectType::Table],
            detail_level: CatalogDetailLevel::Names,
            limit: 1,
            offset: 0,
        };
        let page1 = filter_and_paginate_objects(&objects, &req);
        assert_eq!(page1.total_count, 2);
        assert_eq!(page1.returned_count, 1);
        assert!(page1.has_more);
        assert_eq!(page1.next_offset, Some(1));
        assert_eq!(page1.objects[0].name, "orders");
        assert!(page1.objects[0].columns.is_empty()); // Names detail level strips columns

        let described = describe_object(
            &objects,
            Some("public"),
            "users",
            CatalogDetailLevel::Full,
        )
        .unwrap();
        assert_eq!(described.columns.len(), 2);
        assert_eq!(described.indexes.len(), 1);
    }

    #[test]
    fn test_deterministic_schema_capture_and_structural_diff() {
        let base_objects = sample_objects();
        let mut target_objects = sample_objects();

        // Modify users: add column `status`, drop index `idx_users_email`, add index `idx_users_status`
        let users = target_objects
            .iter_mut()
            .find(|o| o.name == "users")
            .unwrap();
        users.columns.push(ColumnSpec {
            name: "status".to_string(),
            data_type: "text".to_string(),
            nullable: false,
            default_value: Some("'active'".to_string()),
            is_primary_key: false,
            comment: None,
            ordinal_position: 3,
        });
        users.indexes.clear();
        users.indexes.push(IndexSpec {
            name: "idx_users_status".to_string(),
            table_name: "users".to_string(),
            columns: vec!["status".to_string()],
            unique: false,
            primary: false,
            index_type: Some("btree".to_string()),
            predicate: None,
            definition: None,
        });

        // Drop `orders` table to verify destructive classification
        target_objects.retain(|o| o.name != "orders");

        let snap_base = capture_schema("app-dev", DatabaseEngine::Postgres, base_objects.clone());
        let snap_base_repeat = capture_schema("app-dev", DatabaseEngine::Postgres, base_objects);
        assert_eq!(snap_base.schema_version, snap_base_repeat.schema_version);
        assert!(snap_base.schema_version.starts_with("snapshot_"));

        let snap_target = capture_schema("app-dev", DatabaseEngine::Postgres, target_objects);
        assert_ne!(snap_base.schema_version, snap_target.schema_version);

        let diff = diff_schema(&snap_base, &snap_target);
        assert!(!diff.is_identical);
        assert!(diff.has_destructive_changes);
        assert!(diff.all_transactional);

        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AddColumn
                && i.target_name.as_deref() == Some("status")
                && i.reversal_safety == ReversalSafety::TransactionalRollback));
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::DropTable
                && i.object_name == "public.orders"
                && i.destructive
                && i.reversal_safety == ReversalSafety::BackupRecoveryRequired));
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AddIndex
                && i.target_name.as_deref() == Some("idx_users_status")));
        assert!(diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::DropIndex
                && i.target_name.as_deref() == Some("idx_users_email")));
    }
}
