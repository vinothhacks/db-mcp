//! Progressive schema discovery (`filter_and_paginate_objects`, `describe_object`),
//! deterministic schema snapshots (`capture_schema` with `snapshot_<short_hash>`),
//! and structural schema diffing (`diff_schema`) with transactional and reversal safety classification.

use std::collections::BTreeMap;

use chrono::Utc;
use db_mcp_core::{
    CatalogDetailLevel, CatalogObject, CatalogObjectType, CatalogRequest, CatalogResponse,
    ColumnSpec, DatabaseAdapter, DatabaseEngine, DbMcpError, DbMcpResult, DiffOperationKind,
    ForeignKeySpec, IndexSpec, ReversalSafety, SchemaDiff, SchemaDiffItem, SchemaSnapshot,
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
            // name_pattern filters on the object name only (not columns / qualified name).
            if !matches_pattern(request.name_pattern.as_deref(), &obj.name) {
                return false;
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
        (Some(s), split) if !s.trim().is_empty() => {
            let s = s.trim();
            // An already-qualified name whose prefix equals the schema argument resolves to the bare name.
            match split {
                Some((prefix, n)) if prefix.trim().eq_ignore_ascii_case(s) => (Some(s), n.trim()),
                _ => (Some(s), trimmed),
            }
        }
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
            DbMcpError::PolicyDenied {
                code: "OBJECT_NOT_FOUND".to_string(),
                message: format!("Catalog object '{}' was not found", object_name),
                next_action: Some("search_objects".to_string()),
            }
        })?;

    Ok(found.project(detail_level))
}

/// Capture a deterministic `SchemaSnapshot` from a collection of `CatalogObject`s.
pub fn capture_schema(
    connection: impl Into<String>,
    engine: DatabaseEngine,
    objects: Vec<CatalogObject>,
) -> SchemaSnapshot {
    let mut canonical = canonicalize_objects(&objects);
    let (schema_version, full_hash) = compute_schema_hashes(&canonical);
    // Row statistics are data, not schema: keep them out of the snapshot payload too.
    for obj in &mut canonical {
        obj.estimated_rows = None;
        obj.size_bytes = None;
    }
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
        DatabaseEngine::Postgres | DatabaseEngine::Sqlite | DatabaseEngine::SqlServer
    );

    let mut items = Vec::new();

    // Cross-engine diffs compare logical names: the engine default schema (main/public/dbo)
    // is stripped so `main.users` and `public.users` are the same table.
    let cross_engine = base.engine != target.engine;
    let key_of = |obj: &CatalogObject, eng: DatabaseEngine| -> String {
        if cross_engine && is_default_schema(eng, &obj.schema) {
            obj.name.to_ascii_lowercase()
        } else {
            obj.qualified_name().to_ascii_lowercase()
        }
    };

    // Index base and target objects by (object_type, qualified_name_lower)
    let mut base_tables: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut target_tables: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut base_views: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut target_views: BTreeMap<String, &CatalogObject> = BTreeMap::new();
    let mut base_other: BTreeMap<(CatalogObjectType, String), &CatalogObject> = BTreeMap::new();
    let mut target_other: BTreeMap<(CatalogObjectType, String), &CatalogObject> = BTreeMap::new();

    for obj in &base.objects {
        let key = key_of(obj, base.engine);
        match obj.object_type {
            CatalogObjectType::Table => {
                base_tables.insert(key, obj);
            }
            CatalogObjectType::View | CatalogObjectType::MaterializedView => {
                base_views.insert(key, obj);
            }
            CatalogObjectType::Function
            | CatalogObjectType::Procedure
            | CatalogObjectType::Trigger => {
                base_other.insert((obj.object_type, key), obj);
            }
            _ => {}
        }
    }

    for obj in &target.objects {
        let key = key_of(obj, target.engine);
        match obj.object_type {
            CatalogObjectType::Table => {
                target_tables.insert(key, obj);
            }
            CatalogObjectType::View | CatalogObjectType::MaterializedView => {
                target_views.insert(key, obj);
            }
            CatalogObjectType::Function
            | CatalogObjectType::Procedure
            | CatalogObjectType::Trigger => {
                target_other.insert((obj.object_type, key), obj);
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
                engine,
                engine_transactional_ddl,
                &mut items,
            );
            diff_table_foreign_keys(
                &qname,
                &base_tbl.foreign_keys,
                &target_tbl.foreign_keys,
                engine,
                engine_transactional_ddl,
                &mut items,
            );
            diff_table_indexes(
                &qname,
                &base_tbl.indexes,
                &target_tbl.indexes,
                engine,
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

    // 3. Compare routines (procedures/functions, on definition) and triggers
    diff_routines_and_triggers(&base_other, &target_other, engine_transactional_ddl, &mut items);

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
    engine: DatabaseEngine,
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
                let (suggested_ddl, compensating_ddl) = match engine {
                    DatabaseEngine::Postgres => (
                        Some(format!(
                            "ALTER TABLE {table_qname} ALTER COLUMN {} TYPE {};",
                            t_col.name, t_col.data_type
                        )),
                        Some(format!(
                            "ALTER TABLE {table_qname} ALTER COLUMN {} TYPE {};",
                            b_col.name, b_col.data_type
                        )),
                    ),
                    DatabaseEngine::MySql => (
                        Some(mysql_modify_column(table_qname, t_col)),
                        Some(mysql_modify_column(table_qname, b_col)),
                    ),
                    DatabaseEngine::Sqlite => (None, None),
                    DatabaseEngine::SqlServer => (
                        Some(sqlserver_alter_column(table_qname, t_col)),
                        Some(sqlserver_alter_column(table_qname, b_col)),
                    ),
                };
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterColumnType,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_col.name.clone()),
                    before: Some(b_col.data_type.clone()),
                    after: Some(t_col.data_type.clone()),
                    destructive: true,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl,
                    compensating_ddl,
                });
            }
            if b_col.nullable != t_col.nullable {
                let (suggested_ddl, compensating_ddl) = match engine {
                    DatabaseEngine::Postgres => {
                        let action = if t_col.nullable { "DROP NOT NULL" } else { "SET NOT NULL" };
                        let reverse_action =
                            if b_col.nullable { "DROP NOT NULL" } else { "SET NOT NULL" };
                        (
                            Some(format!(
                                "ALTER TABLE {table_qname} ALTER COLUMN {} {action};",
                                t_col.name
                            )),
                            Some(format!(
                                "ALTER TABLE {table_qname} ALTER COLUMN {} {reverse_action};",
                                b_col.name
                            )),
                        )
                    }
                    DatabaseEngine::MySql => (
                        Some(mysql_modify_column(table_qname, t_col)),
                        Some(mysql_modify_column(table_qname, b_col)),
                    ),
                    DatabaseEngine::Sqlite => (None, None),
                    DatabaseEngine::SqlServer => (
                        Some(sqlserver_alter_column(table_qname, t_col)),
                        Some(sqlserver_alter_column(table_qname, b_col)),
                    ),
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
                    suggested_ddl,
                    compensating_ddl,
                });
            }
            if b_col.is_primary_key != t_col.is_primary_key {
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterColumnPrimaryKey,
                    object_name: table_qname.to_string(),
                    target_name: Some(t_col.name.clone()),
                    before: Some(format!("primary_key={}", b_col.is_primary_key)),
                    after: Some(format!("primary_key={}", t_col.is_primary_key)),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: None,
                    compensating_ddl: None,
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
                    suggested_ddl: set_default_ddl(
                        engine,
                        table_qname,
                        &t_col.name,
                        &t_col.default_value,
                    ),
                    compensating_ddl: set_default_ddl(
                        engine,
                        table_qname,
                        &b_col.name,
                        &b_col.default_value,
                    ),
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
                    "ALTER TABLE {table_qname} {} {} {}{}{};",
                    add_column_keyword(engine),
                    t_col.name,
                    t_col.data_type,
                    null_clause,
                    default_clause
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
                suggested_ddl: Some(if engine == DatabaseEngine::SqlServer {
                    format!(
                        "ALTER TABLE {table_qname} DROP COLUMN {}; -- if this is a rename, use EXEC sp_rename '{table_qname}.{}', '<new_name>', 'COLUMN' instead",
                        b_col.name, b_col.name
                    )
                } else {
                    format!("ALTER TABLE {table_qname} DROP COLUMN {};", b_col.name)
                }),
                compensating_ddl: Some(format!(
                    "ALTER TABLE {table_qname} {} {} {};",
                    add_column_keyword(engine),
                    b_col.name,
                    b_col.data_type
                )),
            });
        }
    }
}

fn diff_table_indexes(
    table_qname: &str,
    base_idxs: &[IndexSpec],
    target_idxs: &[IndexSpec],
    engine: DatabaseEngine,
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
                    suggested_ddl: Some(format!("{} {create_ddl}", drop_index_ddl(engine, table_qname, &b_idx.name))),
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
                compensating_ddl: Some(drop_index_ddl(engine, table_qname, &t_idx.name)),
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
                suggested_ddl: Some(drop_index_ddl(engine, table_qname, &b_idx.name)),
                compensating_ddl: Some(recreate_ddl),
            });
        }
    }
}

/// True when `schema` is the implicit default schema of `engine` (or SQL Server's `dbo`).
fn is_default_schema(engine: DatabaseEngine, schema: &str) -> bool {
    let default = match engine {
        DatabaseEngine::Sqlite => "main",
        DatabaseEngine::Postgres => "public",
        DatabaseEngine::MySql => "",
        DatabaseEngine::SqlServer => "dbo",
    };
    schema.is_empty()
        || schema.eq_ignore_ascii_case("dbo")
        || (!default.is_empty() && schema.eq_ignore_ascii_case(default))
}

/// `ADD COLUMN` everywhere except T-SQL, which spells it `ADD`.
fn add_column_keyword(engine: DatabaseEngine) -> &'static str {
    if engine == DatabaseEngine::SqlServer {
        "ADD"
    } else {
        "ADD COLUMN"
    }
}

/// `DROP INDEX`; SQL Server names the table (`DROP INDEX ix ON dbo.t`).
fn drop_index_ddl(engine: DatabaseEngine, table_qname: &str, index: &str) -> String {
    if engine == DatabaseEngine::SqlServer {
        format!("DROP INDEX {index} ON {table_qname};")
    } else {
        format!("DROP INDEX {index};")
    }
}

/// SQL Server `ALTER COLUMN` restating type and nullability (defaults are separate constraints).
fn sqlserver_alter_column(table_qname: &str, col: &ColumnSpec) -> String {
    let null_clause = if col.nullable { "NULL" } else { "NOT NULL" };
    format!(
        "ALTER TABLE {table_qname} ALTER COLUMN {} {} {null_clause};",
        col.name, col.data_type
    )
}

/// MySQL `MODIFY COLUMN` restating the full column definition.
fn mysql_modify_column(table_qname: &str, col: &ColumnSpec) -> String {
    let null_clause = if col.nullable { "" } else { " NOT NULL" };
    let default_clause = col
        .default_value
        .as_ref()
        .map(|d| format!(" DEFAULT {d}"))
        .unwrap_or_default();
    format!(
        "ALTER TABLE {table_qname} MODIFY COLUMN {} {}{null_clause}{default_clause};",
        col.name, col.data_type
    )
}

/// `SET DEFAULT` / `DROP DEFAULT` for engines that support it; SQLite needs a table rebuild.
fn set_default_ddl(
    engine: DatabaseEngine,
    table_qname: &str,
    column: &str,
    default: &Option<String>,
) -> Option<String> {
    if engine == DatabaseEngine::Sqlite {
        return None;
    }
    if engine == DatabaseEngine::SqlServer {
        // Defaults are named constraints: drop the current one (looked up by column), then add.
        let table_lit = table_qname.replace('\'', "''");
        let column_lit = column.replace('\'', "''");
        let drop = format!(
            "DECLARE @df sysname = (SELECT name FROM sys.default_constraints WHERE parent_object_id = OBJECT_ID(N'{table_lit}') AND parent_column_id = COLUMNPROPERTY(OBJECT_ID(N'{table_lit}'), N'{column_lit}', 'ColumnId')); IF @df IS NOT NULL EXEC(N'ALTER TABLE {table_lit} DROP CONSTRAINT ' + QUOTENAME(@df));"
        );
        let short = table_qname.rsplit('.').next().unwrap_or(table_qname);
        return Some(match default {
            Some(d) => format!("{drop} ALTER TABLE {table_qname} ADD CONSTRAINT DF_{short}_{column} DEFAULT {d} FOR {column};"),
            None => drop,
        });
    }
    Some(match default {
        Some(d) => format!("ALTER TABLE {table_qname} ALTER COLUMN {column} SET DEFAULT {d};"),
        None => format!("ALTER TABLE {table_qname} ALTER COLUMN {column} DROP DEFAULT;"),
    })
}

fn fk_signature(fk: &ForeignKeySpec) -> String {
    format!(
        "({})->{}({})",
        fk.columns.join(",").to_ascii_lowercase(),
        fk.referenced_table.to_ascii_lowercase(),
        fk.referenced_columns.join(",").to_ascii_lowercase()
    )
}

fn fk_describe(fk: &ForeignKeySpec) -> String {
    format!(
        "{} on_delete={} on_update={}",
        fk_signature(fk),
        fk.on_delete.as_deref().unwrap_or("-"),
        fk.on_update.as_deref().unwrap_or("-")
    )
}

fn fk_add_ddl(engine: DatabaseEngine, table_qname: &str, fk: &ForeignKeySpec) -> Option<String> {
    if engine == DatabaseEngine::Sqlite {
        return None;
    }
    let name = fk.name.clone().unwrap_or_else(|| {
        format!(
            "fk_{}_{}",
            table_qname.rsplit('.').next().unwrap_or(table_qname),
            fk.columns.join("_")
        )
    });
    let mut ddl = format!(
        "ALTER TABLE {table_qname} ADD CONSTRAINT {name} FOREIGN KEY ({}) REFERENCES {} ({})",
        fk.columns.join(", "),
        fk.referenced_table,
        fk.referenced_columns.join(", ")
    );
    if let Some(d) = &fk.on_delete {
        ddl.push_str(&format!(" ON DELETE {d}"));
    }
    if let Some(u) = &fk.on_update {
        ddl.push_str(&format!(" ON UPDATE {u}"));
    }
    ddl.push(';');
    Some(ddl)
}

fn fk_drop_ddl(engine: DatabaseEngine, table_qname: &str, fk: &ForeignKeySpec) -> Option<String> {
    let name = fk.name.as_ref()?;
    match engine {
        DatabaseEngine::Postgres => {
            Some(format!("ALTER TABLE {table_qname} DROP CONSTRAINT {name};"))
        }
        DatabaseEngine::MySql => {
            Some(format!("ALTER TABLE {table_qname} DROP FOREIGN KEY {name};"))
        }
        DatabaseEngine::Sqlite => None,
        DatabaseEngine::SqlServer => {
            Some(format!("ALTER TABLE {table_qname} DROP CONSTRAINT {name};"))
        }
    }
}

fn diff_table_foreign_keys(
    table_qname: &str,
    base_fks: &[ForeignKeySpec],
    target_fks: &[ForeignKeySpec],
    engine: DatabaseEngine,
    engine_transactional_ddl: bool,
    items: &mut Vec<SchemaDiffItem>,
) {
    let base_map: BTreeMap<String, &ForeignKeySpec> =
        base_fks.iter().map(|f| (fk_signature(f), f)).collect();
    let target_map: BTreeMap<String, &ForeignKeySpec> =
        target_fks.iter().map(|f| (fk_signature(f), f)).collect();

    for (sig, t_fk) in &target_map {
        match base_map.get(sig) {
            None => items.push(SchemaDiffItem {
                kind: DiffOperationKind::AddForeignKey,
                object_name: table_qname.to_string(),
                target_name: t_fk.name.clone(),
                before: None,
                after: Some(fk_describe(t_fk)),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: if engine_transactional_ddl {
                    ReversalSafety::TransactionalRollback
                } else {
                    ReversalSafety::CompensatingMigrationRequired
                },
                suggested_ddl: fk_add_ddl(engine, table_qname, t_fk),
                compensating_ddl: fk_drop_ddl(engine, table_qname, t_fk),
            }),
            Some(b_fk) if b_fk.on_delete != t_fk.on_delete || b_fk.on_update != t_fk.on_update => {
                let suggested = match (
                    fk_drop_ddl(engine, table_qname, b_fk),
                    fk_add_ddl(engine, table_qname, t_fk),
                ) {
                    (Some(d), Some(a)) => Some(format!("{d} {a}")),
                    _ => None,
                };
                let compensating = match (
                    fk_drop_ddl(engine, table_qname, t_fk),
                    fk_add_ddl(engine, table_qname, b_fk),
                ) {
                    (Some(d), Some(a)) => Some(format!("{d} {a}")),
                    _ => None,
                };
                items.push(SchemaDiffItem {
                    kind: DiffOperationKind::AlterForeignKey,
                    object_name: table_qname.to_string(),
                    target_name: t_fk.name.clone(),
                    before: Some(fk_describe(b_fk)),
                    after: Some(fk_describe(t_fk)),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: suggested,
                    compensating_ddl: compensating,
                });
            }
            Some(_) => {}
        }
    }

    for (sig, b_fk) in &base_map {
        if !target_map.contains_key(sig) {
            items.push(SchemaDiffItem {
                kind: DiffOperationKind::DropForeignKey,
                object_name: table_qname.to_string(),
                target_name: b_fk.name.clone(),
                before: Some(fk_describe(b_fk)),
                after: None,
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                suggested_ddl: fk_drop_ddl(engine, table_qname, b_fk),
                compensating_ddl: fk_add_ddl(engine, table_qname, b_fk),
            });
        }
    }
}

fn routine_keyword(object_type: CatalogObjectType) -> &'static str {
    match object_type {
        CatalogObjectType::Function => "FUNCTION",
        CatalogObjectType::Procedure => "PROCEDURE",
        _ => "TRIGGER",
    }
}

/// DDL that (re)creates a routine/trigger from `definition`: used as-is when it already
/// says `CREATE OR REPLACE`, otherwise preceded by a `DROP`.
fn recreate_ddl(object_type: CatalogObjectType, qname: &str, definition: Option<&str>) -> Option<String> {
    let definition = definition?;
    if definition.to_ascii_uppercase().contains("CREATE OR REPLACE") {
        return Some(definition.to_string());
    }
    Some(format!("DROP {} {qname}; {definition}", routine_keyword(object_type)))
}

fn diff_routines_and_triggers(
    base: &BTreeMap<(CatalogObjectType, String), &CatalogObject>,
    target: &BTreeMap<(CatalogObjectType, String), &CatalogObject>,
    engine_transactional_ddl: bool,
    items: &mut Vec<SchemaDiffItem>,
) {
    let norm = |d: &Option<String>| d.as_deref().map(|s| s.trim().to_string());
    for ((ty, key), t_obj) in target {
        let is_trigger = *ty == CatalogObjectType::Trigger;
        let qname = t_obj.qualified_name();
        let kw = routine_keyword(*ty);
        match base.get(&(*ty, key.clone())) {
            None => items.push(SchemaDiffItem {
                kind: if is_trigger {
                    DiffOperationKind::AddTrigger
                } else {
                    DiffOperationKind::AddRoutine
                },
                object_name: qname.clone(),
                target_name: Some(ty.as_str().to_string()),
                before: None,
                after: t_obj.definition.clone(),
                destructive: false,
                transactional: engine_transactional_ddl,
                reversal_safety: if engine_transactional_ddl {
                    ReversalSafety::TransactionalRollback
                } else {
                    ReversalSafety::CompensatingMigrationRequired
                },
                suggested_ddl: t_obj.definition.clone(),
                compensating_ddl: Some(format!("DROP {kw} {qname};")),
            }),
            Some(b_obj) if norm(&b_obj.definition) != norm(&t_obj.definition) => {
                items.push(SchemaDiffItem {
                    kind: if is_trigger {
                        DiffOperationKind::AlterTrigger
                    } else {
                        DiffOperationKind::AlterRoutine
                    },
                    object_name: qname.clone(),
                    target_name: Some(ty.as_str().to_string()),
                    before: b_obj.definition.clone(),
                    after: t_obj.definition.clone(),
                    destructive: false,
                    transactional: engine_transactional_ddl,
                    reversal_safety: ReversalSafety::CompensatingMigrationRequired,
                    suggested_ddl: recreate_ddl(*ty, &qname, t_obj.definition.as_deref()),
                    compensating_ddl: recreate_ddl(*ty, &qname, b_obj.definition.as_deref()),
                });
            }
            Some(_) => {}
        }
    }
    for ((ty, key), b_obj) in base {
        if target.contains_key(&(*ty, key.clone())) {
            continue;
        }
        let qname = b_obj.qualified_name();
        items.push(SchemaDiffItem {
            kind: if *ty == CatalogObjectType::Trigger {
                DiffOperationKind::DropTrigger
            } else {
                DiffOperationKind::DropRoutine
            },
            object_name: qname.clone(),
            target_name: Some(ty.as_str().to_string()),
            before: b_obj.definition.clone(),
            after: None,
            destructive: false,
            transactional: engine_transactional_ddl,
            reversal_safety: ReversalSafety::CompensatingMigrationRequired,
            suggested_ddl: Some(format!("DROP {} {qname};", routine_keyword(*ty))),
            compensating_ddl: b_obj.definition.clone(),
        });
    }
}

/// Warnings that accompany a `diff_schema` result: unexplained hash differences, mixed engines,
/// and engine limitations that leave `suggested_ddl` empty.
pub fn schema_diff_warnings(
    base: &SchemaSnapshot,
    target: &SchemaSnapshot,
    diff: &SchemaDiff,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if diff.is_identical && base.full_hash != target.full_hash {
        warnings.push(format!(
            "Snapshot hashes differ ({} vs {}) but no structural differences were found; the difference may be in an object type or attribute diff_schema does not compare.",
            base.schema_version, target.schema_version
        ));
    }
    if diff.engine == DatabaseEngine::Sqlite
        && diff.items.iter().any(|i| {
            matches!(
                i.kind,
                DiffOperationKind::AlterColumnType
                    | DiffOperationKind::AlterColumnNullability
                    | DiffOperationKind::AlterColumnDefault
                    | DiffOperationKind::AlterColumnPrimaryKey
                    | DiffOperationKind::AddForeignKey
                    | DiffOperationKind::AlterForeignKey
                    | DiffOperationKind::DropForeignKey
            ) && i.suggested_ddl.is_none()
        })
    {
        warnings.push("SQLite cannot ALTER COLUMN or change constraints in place: items with suggested_ddl=null need a table rebuild (create new table, copy rows, drop old, rename).".to_string());
    }
    if diff.engine != DatabaseEngine::Sqlite
        && diff
            .items
            .iter()
            .any(|i| i.kind == DiffOperationKind::AlterColumnPrimaryKey)
    {
        warnings.push(
            "Primary-key changes have no generated DDL; write a manual migration.".to_string(),
        );
    }
    warnings
}

/// Recompute a snapshot's schema hashes from its objects; returns a warning when they do not
/// match the supplied `schema_version` / `full_hash` (tampered or hand-edited snapshot).
pub fn verify_snapshot_hash(label: &str, snapshot: &SchemaSnapshot) -> Option<String> {
    let (version, full) = compute_schema_hashes(&snapshot.objects);
    if full != snapshot.full_hash || version != snapshot.schema_version {
        Some(format!(
            "{label} snapshot hash mismatch: supplied {} but its objects hash to {version}; the snapshot was modified or not produced by capture_schema.",
            snapshot.schema_version
        ))
    } else {
        None
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
    fn describe_object_accepts_schema_with_qualified_name_and_not_found_has_next_action() {
        let objects = sample_objects();
        let d = describe_object(&objects, Some("public"), "public.users", CatalogDetailLevel::Names).unwrap();
        assert_eq!(d.name, "users");
        let err = describe_object(&objects, None, "missing_thing", CatalogDetailLevel::Names).unwrap_err();
        assert_eq!(err.next_action(), Some("search_objects"));
    }

    #[test]
    fn name_pattern_matches_object_name_only() {
        let objects = sample_objects();
        let req = CatalogRequest {
            connection: "app-dev".to_string(),
            schema_pattern: None,
            name_pattern: Some("email".to_string()),
            object_types: Vec::new(),
            detail_level: CatalogDetailLevel::Names,
            limit: 50,
            offset: 0,
        };
        // `email` is a column of users, not an object name.
        assert!(!filter_and_paginate_objects(&objects, &req)
            .objects
            .iter()
            .any(|o| o.name == "users"));
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

    fn snap(engine: DatabaseEngine, objects: Vec<CatalogObject>) -> SchemaSnapshot {
        capture_schema("c", engine, objects)
    }

    fn col(name: &str, ty: &str, nullable: bool, pk: bool) -> ColumnSpec {
        ColumnSpec {
            name: name.to_string(),
            data_type: ty.to_string(),
            nullable,
            default_value: None,
            is_primary_key: pk,
            comment: None,
            ordinal_position: 1,
        }
    }

    fn tbl(schema: &str, name: &str, cols: Vec<ColumnSpec>, fks: Vec<ForeignKeySpec>) -> CatalogObject {
        CatalogObject {
            schema: schema.to_string(),
            name: name.to_string(),
            object_type: CatalogObjectType::Table,
            comment: None,
            estimated_rows: Some(5),
            size_bytes: Some(9),
            columns: cols,
            indexes: vec![],
            foreign_keys: fks,
            definition: None,
        }
    }

    fn routine(name: &str, ty: CatalogObjectType, def: &str) -> CatalogObject {
        CatalogObject {
            schema: "main".to_string(),
            name: name.to_string(),
            object_type: ty,
            comment: None,
            estimated_rows: None,
            size_bytes: None,
            columns: vec![],
            indexes: vec![],
            foreign_keys: vec![],
            definition: Some(def.to_string()),
        }
    }

    #[test]
    fn sqlserver_diff_emits_tsql_ddl() {
        let mut idx_tbl = tbl("dbo", "orders", vec![col("id", "int", false, true), col("status", "nvarchar(20)", false, false)], vec![]);
        let base = snap(DatabaseEngine::SqlServer, vec![idx_tbl.clone()]);
        idx_tbl.columns[1] = col("status", "nvarchar(40)", true, false);
        idx_tbl.columns.push(col("note", "nvarchar(max)", true, false));
        idx_tbl.indexes.push(IndexSpec {
            name: "ix_orders_status".to_string(),
            table_name: "dbo.orders".to_string(),
            columns: vec!["status".to_string()],
            unique: false,
            primary: false,
            index_type: None,
            predicate: None,
            definition: None,
        });
        let target = snap(DatabaseEngine::SqlServer, vec![idx_tbl]);
        let diff = diff_schema(&base, &target);
        assert!(diff.all_transactional);
        let ddl: Vec<String> = diff.items.iter().filter_map(|i| i.suggested_ddl.clone()).collect();
        let comp: Vec<String> = diff.items.iter().filter_map(|i| i.compensating_ddl.clone()).collect();
        assert!(ddl.contains(&"ALTER TABLE dbo.orders ALTER COLUMN status nvarchar(40) NULL;".to_string()), "{ddl:?}");
        assert!(ddl.contains(&"ALTER TABLE dbo.orders ADD note nvarchar(max);".to_string()), "{ddl:?}");
        assert!(comp.contains(&"DROP INDEX ix_orders_status ON dbo.orders;".to_string()), "{comp:?}");
        let back = diff_schema(&target, &base);
        assert!(back
            .items
            .iter()
            .any(|i| i.suggested_ddl.as_deref().unwrap_or("").contains("sp_rename")));
    }

    #[test]
    fn diff_reports_routines_triggers_fks_and_pk() {
        let fk = ForeignKeySpec {
            name: Some("fk_o_u".to_string()),
            columns: vec!["user_id".to_string()],
            referenced_table: "users".to_string(),
            referenced_columns: vec!["id".to_string()],
            on_delete: None,
            on_update: None,
        };
        let base = snap(
            DatabaseEngine::Postgres,
            vec![
                tbl("main", "orders", vec![col("id", "int", false, true)], vec![fk]),
                routine("p1", CatalogObjectType::Procedure, "CREATE PROCEDURE p1() BEGIN END;"),
                routine("f1", CatalogObjectType::Function, "CREATE FUNCTION f1() BEGIN END;"),
            ],
        );
        let target = snap(
            DatabaseEngine::Postgres,
            vec![
                tbl("main", "orders", vec![col("id", "int", false, false)], vec![]),
                routine("p1", CatalogObjectType::Procedure, "CREATE PROCEDURE p1() BEGIN SELECT 1; END;"),
                routine("trg", CatalogObjectType::Trigger, "CREATE TRIGGER trg ..."),
            ],
        );
        let diff = diff_schema(&base, &target);
        let kinds: Vec<DiffOperationKind> = diff.items.iter().map(|i| i.kind).collect();
        for k in [
            DiffOperationKind::AlterColumnPrimaryKey,
            DiffOperationKind::DropForeignKey,
            DiffOperationKind::AlterRoutine,
            DiffOperationKind::DropRoutine,
            DiffOperationKind::AddTrigger,
        ] {
            assert!(kinds.contains(&k), "missing {k:?} in {kinds:?}");
        }
        assert!(!diff.is_identical);
    }

    #[test]
    fn diff_ddl_is_engine_specific_and_defaults_get_ddl() {
        let mk = |engine, ty: &str, def: Option<&str>| {
            let mut c = col("qty", ty, true, false);
            c.default_value = def.map(str::to_string);
            snap(engine, vec![tbl("main", "t", vec![c], vec![])])
        };
        let d = diff_schema(
            &mk(DatabaseEngine::MySql, "int", None),
            &mk(DatabaseEngine::MySql, "bigint", Some("0")),
        );
        let ty = d.items.iter().find(|i| i.kind == DiffOperationKind::AlterColumnType).unwrap();
        assert_eq!(ty.suggested_ddl.as_deref(), Some("ALTER TABLE main.t MODIFY COLUMN qty bigint DEFAULT 0;"));
        let df = d.items.iter().find(|i| i.kind == DiffOperationKind::AlterColumnDefault).unwrap();
        assert!(df.suggested_ddl.as_deref().unwrap().contains("SET DEFAULT 0"));

        let base = mk(DatabaseEngine::Sqlite, "int", None);
        let target = mk(DatabaseEngine::Sqlite, "bigint", None);
        let d = diff_schema(&base, &target);
        let ty = d.items.iter().find(|i| i.kind == DiffOperationKind::AlterColumnType).unwrap();
        assert!(ty.suggested_ddl.is_none());
        assert!(schema_diff_warnings(&base, &target, &d).iter().any(|w| w.contains("rebuild")));
    }

    #[test]
    fn cross_engine_diff_strips_default_schema_and_capture_nulls_stats() {
        let a = snap(DatabaseEngine::Sqlite, vec![tbl("main", "users", vec![col("id", "int", false, true)], vec![])]);
        let b = snap(DatabaseEngine::Postgres, vec![tbl("public", "users", vec![col("id", "int", false, true)], vec![])]);
        assert!(a.objects[0].estimated_rows.is_none() && a.objects[0].size_bytes.is_none());
        let d = diff_schema(&a, &b);
        assert!(d.items.is_empty(), "{:?}", d.items);
    }

    #[test]
    fn tampered_snapshot_hash_and_unexplained_hash_diff_warn() {
        let mut a = snap(DatabaseEngine::Sqlite, vec![tbl("main", "users", vec![col("id", "int", false, true)], vec![])]);
        assert!(verify_snapshot_hash("base", &a).is_none());
        a.objects.clear();
        assert!(verify_snapshot_hash("base", &a).unwrap().contains("mismatch"));
        let x = snap(DatabaseEngine::Sqlite, vec![routine("s", CatalogObjectType::Sequence, "x")]);
        let y = snap(DatabaseEngine::Sqlite, vec![routine("s", CatalogObjectType::Sequence, "y")]);
        let d = diff_schema(&x, &y);
        assert!(d.is_identical);
        assert!(schema_diff_warnings(&x, &y, &d).iter().any(|w| w.contains("hashes differ")));
    }
}
