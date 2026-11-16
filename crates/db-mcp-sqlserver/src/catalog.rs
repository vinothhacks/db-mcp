//! Catalog discovery from `sys.*` views (current database only).
//!
//! Works with `db_datareader` alone: tables, views, columns, keys, indexes and foreign keys are
//! visible for every object the login can SELECT. Procedures, functions and triggers, and all
//! module definitions (`sys.sql_modules`), need VIEW DEFINITION; without it they are missing or
//! have no definition and a warning says which grant to request.

use std::collections::BTreeMap;

use db_mcp_core::{CatalogObject, CatalogObjectType, ColumnSpec, DbMcpResult, ForeignKeySpec, IndexSpec};
use serde_json::Value;

use crate::{FetchedRows, SqlServerAdapter};

pub const OBJECTS_SQL: &str = "SELECT /* db-mcp:internal */ o.object_id, s.name AS schema_name, o.name, RTRIM(o.type) AS type, \
    CAST(ep.value AS nvarchar(4000)) AS comment, o.parent_object_id \
    FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id \
    LEFT JOIN sys.extended_properties ep ON ep.class = 1 AND ep.major_id = o.object_id AND ep.minor_id = 0 AND ep.name = 'MS_Description' \
    WHERE o.is_ms_shipped = 0 AND o.type IN ('U','V','P','FN','IF','TF','TR','SO') \
    ORDER BY s.name, o.name";

pub const COLUMNS_SQL: &str = "SELECT /* db-mcp:internal */ c.object_id, c.column_id, c.name, t.name AS type_name, c.max_length, c.precision, c.scale, \
    c.is_nullable, OBJECT_DEFINITION(c.default_object_id) AS default_def, CAST(ep.value AS nvarchar(4000)) AS comment \
    FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id \
    JOIN sys.objects o ON o.object_id = c.object_id \
    LEFT JOIN sys.extended_properties ep ON ep.class = 1 AND ep.major_id = c.object_id AND ep.minor_id = c.column_id AND ep.name = 'MS_Description' \
    WHERE o.is_ms_shipped = 0 AND o.type IN ('U','V') \
    ORDER BY c.object_id, c.column_id";

pub const INDEXES_SQL: &str = "SELECT /* db-mcp:internal */ i.object_id, i.name, i.index_id, i.type_desc, i.is_unique, i.is_primary_key, \
    i.filter_definition, ic.key_ordinal, ic.is_included_column, c.name AS column_name, i.is_disabled \
    FROM sys.indexes i JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id \
    JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id \
    JOIN sys.objects o ON o.object_id = i.object_id \
    WHERE o.is_ms_shipped = 0 AND o.type IN ('U','V') AND i.type > 0 \
    ORDER BY i.object_id, i.index_id, ic.is_included_column, ic.key_ordinal, ic.index_column_id";

pub const FOREIGN_KEYS_SQL: &str = "SELECT /* db-mcp:internal */ fk.parent_object_id, fk.name, fkc.constraint_column_id, pc.name AS column_name, \
    SCHEMA_NAME(ro.schema_id) AS ref_schema, ro.name AS ref_table, rc.name AS ref_column, \
    fk.delete_referential_action_desc, fk.update_referential_action_desc \
    FROM sys.foreign_keys fk JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id \
    JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id \
    JOIN sys.objects ro ON ro.object_id = fkc.referenced_object_id \
    JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id \
    ORDER BY fk.parent_object_id, fk.name, fkc.constraint_column_id";

pub const MODULES_SQL: &str = "SELECT /* db-mcp:internal */ m.object_id, m.definition FROM sys.sql_modules m";

pub const ROWCOUNT_SQL: &str = "SELECT /* db-mcp:internal */ p.object_id, SUM(p.rows) AS row_count FROM sys.partitions p \
    WHERE p.index_id IN (0, 1) GROUP BY p.object_id";

pub const SIZE_SQL: &str = "SELECT /* db-mcp:internal */ ps.object_id, SUM(ps.used_page_count) * 8192 AS used_bytes \
    FROM sys.dm_db_partition_stats ps GROUP BY ps.object_id";

fn int(v: &Value) -> i64 {
    v.as_i64().unwrap_or_default()
}
fn text(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}
fn opt_text(v: &Value) -> Option<String> {
    v.as_str().map(ToOwned::to_owned).filter(|s| !s.is_empty())
}
fn flag(v: &Value) -> bool {
    v.as_bool().unwrap_or_else(|| v.as_i64() == Some(1))
}

/// Human-readable T-SQL type (`nvarchar(255)`, `decimal(12,2)`, `datetime2(3)`, `varchar(max)`).
pub fn format_column_type(type_name: &str, max_length: i64, precision: i64, scale: i64) -> String {
    let t = type_name.to_ascii_lowercase();
    match t.as_str() {
        "varchar" | "char" | "varbinary" | "binary" => {
            if max_length < 0 {
                format!("{t}(max)")
            } else {
                format!("{t}({max_length})")
            }
        }
        "nvarchar" | "nchar" => {
            if max_length < 0 {
                format!("{t}(max)")
            } else {
                format!("{t}({})", max_length / 2)
            }
        }
        "decimal" | "numeric" => format!("{t}({precision},{scale})"),
        "datetime2" | "time" | "datetimeoffset" => format!("{t}({scale})"),
        _ => t,
    }
}

/// Strip the wrapping parentheses SQL Server stores around defaults: `((0))` -> `0`.
pub fn clean_default(def: &str) -> String {
    let mut s = def.trim();
    while s.starts_with('(') && s.ends_with(')') && balanced_inner(s) {
        s = s[1..s.len() - 1].trim();
    }
    s.to_string()
}

fn balanced_inner(s: &str) -> bool {
    let inner = &s[1..s.len() - 1];
    let mut depth = 0i32;
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

fn object_type(code: &str) -> Option<CatalogObjectType> {
    Some(match code {
        "U" => CatalogObjectType::Table,
        "V" => CatalogObjectType::View,
        "P" => CatalogObjectType::Procedure,
        "FN" | "IF" | "TF" => CatalogObjectType::Function,
        "TR" => CatalogObjectType::Trigger,
        "SO" => CatalogObjectType::Sequence,
        _ => return None,
    })
}

/// Raw result sets of the catalog queries.
#[derive(Debug, Default, Clone)]
pub struct CatalogRows {
    pub objects: FetchedRows,
    pub columns: FetchedRows,
    pub indexes: FetchedRows,
    pub foreign_keys: FetchedRows,
    pub modules: Option<FetchedRows>,
    pub row_counts: Option<FetchedRows>,
    pub sizes: Option<FetchedRows>,
}

/// Map catalog rows to `CatalogObject`s (pure; unit tested without a server).
pub fn build_catalog(rows: &CatalogRows) -> Vec<CatalogObject> {
    let modules: BTreeMap<i64, String> = rows
        .modules
        .as_ref()
        .map(|m| m.rows.iter().filter_map(|r| opt_text(&r[1]).map(|d| (int(&r[0]), d))).collect())
        .unwrap_or_default();
    let counts: BTreeMap<i64, u64> = rows
        .row_counts
        .as_ref()
        .map(|m| m.rows.iter().map(|r| (int(&r[0]), int(&r[1]).max(0) as u64)).collect())
        .unwrap_or_default();
    let sizes: BTreeMap<i64, u64> = rows
        .sizes
        .as_ref()
        .map(|m| m.rows.iter().map(|r| (int(&r[0]), int(&r[1]).max(0) as u64)).collect())
        .unwrap_or_default();

    let mut names: BTreeMap<i64, (String, String)> = BTreeMap::new();
    let mut objects: BTreeMap<i64, CatalogObject> = BTreeMap::new();
    for r in &rows.objects.rows {
        let id = int(&r[0]);
        let schema = text(&r[1]);
        let name = text(&r[2]);
        names.insert(id, (schema.clone(), name.clone()));
        let Some(ty) = object_type(text(&r[3]).trim()) else { continue };
        objects.insert(
            id,
            CatalogObject {
                schema,
                name,
                object_type: ty,
                comment: opt_text(&r[4]),
                estimated_rows: if ty == CatalogObjectType::Table { counts.get(&id).copied() } else { None },
                size_bytes: if ty == CatalogObjectType::Table { sizes.get(&id).copied() } else { None },
                columns: Vec::new(),
                indexes: Vec::new(),
                foreign_keys: Vec::new(),
                definition: modules.get(&id).cloned(),
            },
        );
    }

    for r in &rows.columns.rows {
        let id = int(&r[0]);
        if let Some(obj) = objects.get_mut(&id) {
            obj.columns.push(ColumnSpec {
                name: text(&r[2]),
                data_type: format_column_type(&text(&r[3]), int(&r[4]), int(&r[5]), int(&r[6])),
                nullable: flag(&r[7]),
                default_value: opt_text(&r[8]).map(|d| clean_default(&d)),
                is_primary_key: false,
                comment: opt_text(&r[9]),
                ordinal_position: int(&r[1]).max(0) as usize,
            });
        }
    }

    // Indexes: group rows by (object_id, index_id); key columns before included columns.
    let mut idx: BTreeMap<(i64, i64), (IndexSpec, bool)> = BTreeMap::new();
    for r in &rows.indexes.rows {
        let id = int(&r[0]);
        let Some(obj) = objects.get(&id) else { continue };
        let key = (id, int(&r[2]));
        let entry = idx.entry(key).or_insert_with(|| {
            (
                IndexSpec {
                    name: text(&r[1]),
                    table_name: obj.qualified_name(),
                    columns: Vec::new(),
                    unique: flag(&r[4]),
                    primary: flag(&r[5]),
                    index_type: Some(text(&r[3]).to_ascii_lowercase()),
                    predicate: opt_text(&r[6]),
                    definition: None,
                },
                flag(&r[10]),
            )
        });
        if !flag(&r[8]) {
            entry.0.columns.push(text(&r[9]));
        }
    }
    for ((id, _), (mut spec, disabled)) in idx {
        if let Some(obj) = objects.get_mut(&id) {
            if spec.primary {
                for c in obj.columns.iter_mut() {
                    if spec.columns.iter().any(|k| k.eq_ignore_ascii_case(&c.name)) {
                        c.is_primary_key = true;
                    }
                }
            }
            let unique = if spec.unique { "UNIQUE " } else { "" };
            let kind = spec.index_type.clone().unwrap_or_default().to_ascii_uppercase();
            let kind = if kind.contains("NONCLUSTERED") { "NONCLUSTERED " } else if kind.contains("CLUSTERED") { "CLUSTERED " } else { "" };
            if !spec.primary {
                spec.definition = Some(format!(
                    "CREATE {unique}{kind}INDEX {} ON {} ({}){};",
                    spec.name,
                    spec.table_name,
                    spec.columns.join(", "),
                    spec.predicate.as_ref().map(|p| format!(" WHERE {p}")).unwrap_or_default()
                ));
            }
            if disabled {
                spec.index_type = Some(format!("{} (disabled)", spec.index_type.clone().unwrap_or_default()));
            }
            obj.indexes.push(spec);
        }
    }

    // Foreign keys.
    let mut fks: BTreeMap<(i64, String), ForeignKeySpec> = BTreeMap::new();
    for r in &rows.foreign_keys.rows {
        let id = int(&r[0]);
        if !objects.contains_key(&id) {
            continue;
        }
        let name = text(&r[1]);
        let action = |v: &Value| {
            let a = text(v).replace('_', " ");
            (!a.is_empty() && a != "NO ACTION").then_some(a)
        };
        let fk = fks.entry((id, name.clone())).or_insert_with(|| ForeignKeySpec {
            name: Some(name.clone()),
            columns: Vec::new(),
            referenced_table: format!("{}.{}", text(&r[4]), text(&r[5])),
            referenced_columns: Vec::new(),
            on_delete: action(&r[7]),
            on_update: action(&r[8]),
        });
        fk.columns.push(text(&r[3]));
        fk.referenced_columns.push(text(&r[6]));
    }
    for ((id, _), fk) in fks {
        if let Some(obj) = objects.get_mut(&id) {
            obj.foreign_keys.push(fk);
        }
    }

    objects.into_values().collect()
}

/// Load the catalog of the current database. Optional sources (module definitions, sizes)
/// degrade to warnings instead of failing.
pub async fn load_catalog(adapter: &SqlServerAdapter) -> DbMcpResult<(Vec<CatalogObject>, Vec<String>)> {
    let cap = 200_000;
    let mut warnings = Vec::new();
    let mut rows = CatalogRows {
        objects: adapter.query_rows(OBJECTS_SQL, cap).await?,
        columns: adapter.query_rows(COLUMNS_SQL, cap).await?,
        indexes: adapter.query_rows(INDEXES_SQL, cap).await?,
        foreign_keys: adapter.query_rows(FOREIGN_KEYS_SQL, cap).await?,
        ..CatalogRows::default()
    };
    rows.modules = adapter.query_rows(MODULES_SQL, cap).await.ok();
    rows.row_counts = adapter.query_rows(ROWCOUNT_SQL, cap).await.ok();
    let info = adapter.cached_server_info();
    if info.as_ref().map(|i| i.can_view_database_state()).unwrap_or(false) {
        rows.sizes = adapter.query_rows(SIZE_SQL, cap).await.ok();
    }
    let objects = build_catalog(&rows);
    if let Some(info) = info {
        if !info.can_view_definition() {
            warnings.push(format!(
                "login '{}' lacks VIEW DEFINITION: stored procedures, functions and triggers may be missing and view definitions are hidden (lineage and call graphs are partial); GRANT VIEW DEFINITION TO [{}]",
                info.login, info.database_user
            ));
        }
    }
    let views_without_def = objects
        .iter()
        .filter(|o| o.object_type == CatalogObjectType::View && o.definition.is_none())
        .count();
    if views_without_def > 0 {
        warnings.push(format!("{views_without_def} view definition(s) are not visible to this login"));
    }
    Ok((objects, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(rows: Vec<Vec<Value>>) -> FetchedRows {
        FetchedRows { rows, ..FetchedRows::default() }
    }

    #[test]
    fn type_formatting_and_default_cleanup() {
        assert_eq!(format_column_type("nvarchar", 510, 0, 0), "nvarchar(255)");
        assert_eq!(format_column_type("varchar", -1, 0, 0), "varchar(max)");
        assert_eq!(format_column_type("decimal", 9, 12, 2), "decimal(12,2)");
        assert_eq!(format_column_type("datetime2", 8, 23, 3), "datetime2(3)");
        assert_eq!(format_column_type("INT", 4, 10, 0), "int");
        assert_eq!(clean_default("((0))"), "0");
        assert_eq!(clean_default("(sysutcdatetime())"), "sysutcdatetime()");
        assert_eq!(clean_default("(N'x')"), "N'x'");
        assert_eq!(clean_default("((1)+(2))"), "(1)+(2)");
    }

    #[test]
    fn maps_rows_to_catalog_objects() {
        let rows = CatalogRows {
            objects: set(vec![
                vec![json!(1), json!("dbo"), json!("users"), json!("U"), json!("Customer accounts"), json!(0)],
                vec![json!(2), json!("dbo"), json!("orders"), json!("U"), Value::Null, json!(0)],
                vec![json!(3), json!("dbo"), json!("active_user_orders"), json!("V"), Value::Null, json!(0)],
                vec![json!(4), json!("dbo"), json!("checkout_order"), json!("P"), Value::Null, json!(0)],
                vec![json!(5), json!("dbo"), json!("trg_orders_audit"), json!("TR"), Value::Null, json!(2)],
            ]),
            columns: set(vec![
                vec![json!(1), json!(1), json!("id"), json!("int"), json!(4), json!(10), json!(0), json!(false), Value::Null, Value::Null],
                vec![json!(1), json!(2), json!("email"), json!("nvarchar"), json!(510), json!(0), json!(0), json!(false), Value::Null, json!("login")],
                vec![json!(2), json!(1), json!("id"), json!("int"), json!(4), json!(10), json!(0), json!(false), Value::Null, Value::Null],
                vec![json!(2), json!(2), json!("user_id"), json!("int"), json!(4), json!(10), json!(0), json!(true), json!("((0))"), Value::Null],
            ]),
            indexes: set(vec![
                vec![json!(1), json!("pk_users"), json!(1), json!("CLUSTERED"), json!(true), json!(true), Value::Null, json!(1), json!(false), json!("id"), json!(false)],
                vec![json!(2), json!("ix_orders_user"), json!(2), json!("NONCLUSTERED"), json!(false), json!(false), Value::Null, json!(1), json!(false), json!("user_id"), json!(false)],
                vec![json!(2), json!("ix_orders_user"), json!(2), json!("NONCLUSTERED"), json!(false), json!(false), Value::Null, json!(0), json!(true), json!("id"), json!(false)],
            ]),
            foreign_keys: set(vec![vec![
                json!(2), json!("fk_orders_users"), json!(1), json!("user_id"), json!("dbo"), json!("users"), json!("id"), json!("CASCADE"), json!("NO_ACTION"),
            ]]),
            modules: Some(set(vec![vec![json!(4), json!("CREATE PROCEDURE dbo.checkout_order AS SELECT 1")]])),
            row_counts: Some(set(vec![vec![json!(1), json!(3)], vec![json!(3), json!(99)]])),
            sizes: None,
        };
        let objs = build_catalog(&rows);
        assert_eq!(objs.len(), 5);
        let users = objs.iter().find(|o| o.name == "users").unwrap();
        assert_eq!(users.comment.as_deref(), Some("Customer accounts"));
        assert_eq!(users.estimated_rows, Some(3));
        assert!(users.columns[0].is_primary_key);
        assert_eq!(users.columns[1].data_type, "nvarchar(255)");
        let orders = objs.iter().find(|o| o.name == "orders").unwrap();
        assert_eq!(orders.columns[1].default_value.as_deref(), Some("0"));
        assert_eq!(orders.indexes[0].columns, vec!["user_id"]);
        assert_eq!(orders.indexes[0].definition.as_deref(), Some("CREATE NONCLUSTERED INDEX ix_orders_user ON dbo.orders (user_id);"));
        assert_eq!(orders.foreign_keys[0].referenced_table, "dbo.users");
        assert_eq!(orders.foreign_keys[0].on_delete.as_deref(), Some("CASCADE"));
        assert_eq!(orders.foreign_keys[0].on_update, None);
        let view = objs.iter().find(|o| o.name == "active_user_orders").unwrap();
        assert_eq!(view.estimated_rows, None);
        let proc_ = objs.iter().find(|o| o.object_type == CatalogObjectType::Procedure).unwrap();
        assert!(proc_.definition.as_deref().unwrap().starts_with("CREATE PROCEDURE"));
        assert!(objs.iter().any(|o| o.object_type == CatalogObjectType::Trigger));
    }
}
