//! Live MySQL catalog discovery from `information_schema` (tables, views, columns, indexes,
//! foreign keys, triggers, routines) with a short per-connection cache.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use db_mcp_core::{
    CatalogObject, CatalogObjectType, ColumnSpec, DbMcpResult, ForeignKeySpec, IndexSpec,
};

use serde_json::Value as J;

use crate::live::LiveMySql;

/// System schemas never listed.
pub const MYSQL_SYSTEM_SCHEMAS: &str = "'information_schema', 'mysql', 'performance_schema', 'sys'";

/// How long a discovered catalog is reused before it is read again.
pub const CATALOG_CACHE_TTL: Duration = Duration::from_secs(15);

/// Bulk `information_schema.COLUMNS` query for every visible application schema.
pub fn build_information_schema_all_columns_query() -> String {
    format!(
        "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, (IS_NULLABLE = 'YES') AS is_nullable,
                COLUMN_DEFAULT, (COLUMN_KEY = 'PRI') AS is_primary_key, COLUMN_COMMENT, ORDINAL_POSITION
         FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
    )
}

/// Bulk `information_schema.STATISTICS` query (index columns in order).
pub fn build_information_schema_all_statistics_query() -> String {
    format!(
        "SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, COLUMN_NAME, (NON_UNIQUE = 0) AS is_unique,
                INDEX_TYPE, SEQ_IN_INDEX, EXPRESSION
         FROM information_schema.STATISTICS
         WHERE TABLE_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX"
    )
}

/// Foreign keys: `KEY_COLUMN_USAGE` joined with `REFERENTIAL_CONSTRAINTS` (rules).
pub fn build_information_schema_foreign_keys_query() -> String {
    format!(
        "SELECT k.TABLE_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME, k.COLUMN_NAME,
                k.REFERENCED_TABLE_SCHEMA, k.REFERENCED_TABLE_NAME, k.REFERENCED_COLUMN_NAME,
                r.UPDATE_RULE, r.DELETE_RULE
         FROM information_schema.KEY_COLUMN_USAGE k
         JOIN information_schema.REFERENTIAL_CONSTRAINTS r
           ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA
          AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
          AND r.TABLE_NAME = k.TABLE_NAME
         WHERE k.REFERENCED_TABLE_NAME IS NOT NULL
           AND k.TABLE_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY k.TABLE_SCHEMA, k.TABLE_NAME, k.CONSTRAINT_NAME, k.ORDINAL_POSITION"
    )
}

/// View definitions (`SHOW VIEW` + `SELECT` are needed for a non-empty definition).
pub fn build_information_schema_views_query() -> String {
    format!(
        "SELECT TABLE_SCHEMA, TABLE_NAME, VIEW_DEFINITION
         FROM information_schema.VIEWS
         WHERE TABLE_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY TABLE_SCHEMA, TABLE_NAME"
    )
}

/// Triggers (visible only with the TRIGGER privilege on the table).
pub fn build_information_schema_triggers_query() -> String {
    format!(
        "SELECT TRIGGER_SCHEMA, TRIGGER_NAME, ACTION_TIMING, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_STATEMENT
         FROM information_schema.TRIGGERS
         WHERE TRIGGER_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY TRIGGER_SCHEMA, TRIGGER_NAME"
    )
}

/// Routine parameters (to rebuild a `CREATE PROCEDURE|FUNCTION` header).
pub fn build_information_schema_parameters_query() -> String {
    format!(
        "SELECT SPECIFIC_SCHEMA, SPECIFIC_NAME, ORDINAL_POSITION, PARAMETER_MODE, PARAMETER_NAME, DTD_IDENTIFIER, ROUTINE_TYPE
         FROM information_schema.PARAMETERS
         WHERE SPECIFIC_SCHEMA NOT IN ({MYSQL_SYSTEM_SCHEMAS})
         ORDER BY SPECIFIC_SCHEMA, SPECIFIC_NAME, ORDINAL_POSITION"
    )
}

fn s(v: Option<&J>) -> String {
    match v {
        Some(J::String(x)) => x.clone(),
        Some(J::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn opt_s(v: Option<&J>) -> Option<String> {
    match v {
        Some(J::String(x)) => Some(x.clone()),
        Some(J::Null) | None => None,
        Some(other) => Some(other.to_string()),
    }
}

fn truthy(v: Option<&J>) -> bool {
    match v {
        Some(J::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        Some(J::Bool(b)) => *b,
        Some(J::String(x)) => x == "1",
        _ => false,
    }
}

fn num(v: Option<&J>) -> Option<u64> {
    match v {
        Some(J::Number(n)) => n.as_u64(),
        Some(J::String(x)) => x.parse().ok(),
        _ => None,
    }
}

fn bq(ident: &str) -> String {
    format!("`{}`", ident.replace('`', "``"))
}

type Rows = Vec<Vec<J>>;

/// Raw result sets of every discovery query (kept separate from I/O for unit tests).
#[derive(Default)]
pub struct CatalogRows {
    pub tables: Rows,
    pub columns: Rows,
    pub statistics: Rows,
    pub foreign_keys: Rows,
    pub views: Rows,
    pub triggers: Rows,
    pub routines: Rows,
    pub parameters: Rows,
}

/// Turn `information_schema` rows into catalog objects. `default_schema` decides whether a
/// foreign-key target is written bare (same schema) or qualified.
pub fn build_catalog_objects(rows: &CatalogRows) -> Vec<CatalogObject> {
    let key = |schema: &str, name: &str| {
        format!(
            "{}.{}",
            schema.to_ascii_lowercase(),
            name.to_ascii_lowercase()
        )
    };

    let mut columns: BTreeMap<String, Vec<ColumnSpec>> = BTreeMap::new();
    for r in &rows.columns {
        columns
            .entry(key(&s(r.first()), &s(r.get(1))))
            .or_default()
            .push(ColumnSpec {
                name: s(r.get(2)),
                data_type: s(r.get(3)).to_ascii_lowercase(),
                nullable: truthy(r.get(4)),
                default_value: opt_s(r.get(5)),
                is_primary_key: truthy(r.get(6)),
                comment: opt_s(r.get(7)).filter(|c| !c.is_empty()),
                ordinal_position: num(r.get(8)).unwrap_or(0) as usize,
            });
    }

    // (table key) -> ordered index specs
    let mut indexes: BTreeMap<String, Vec<IndexSpec>> = BTreeMap::new();
    for r in &rows.statistics {
        let schema = s(r.first());
        let table = s(r.get(1));
        let index_name = s(r.get(2));
        let column = opt_s(r.get(3))
            .or_else(|| opt_s(r.get(7)).map(|e| format!("({e})")))
            .unwrap_or_default();
        let list = indexes.entry(key(&schema, &table)).or_default();
        if let Some(existing) = list.iter_mut().find(|i| i.name == index_name) {
            existing.columns.push(column);
        } else {
            list.push(IndexSpec {
                name: index_name.clone(),
                table_name: table.clone(),
                columns: vec![column],
                unique: truthy(r.get(4)),
                primary: index_name == "PRIMARY",
                index_type: opt_s(r.get(5)),
                predicate: None,
                definition: None,
            });
        }
    }
    for (k, list) in indexes.iter_mut() {
        let (schema, _) = k.split_once('.').unwrap_or(("", k));
        let _ = schema;
        for idx in list.iter_mut() {
            if idx.primary {
                continue;
            }
            let schema_name = rows
                .tables
                .iter()
                .find(|t| key(&s(t.first()), &s(t.get(1))) == *k)
                .map(|t| s(t.first()))
                .unwrap_or_default();
            idx.definition = Some(format!(
                "CREATE {}INDEX {} ON {}.{} ({});",
                if idx.unique { "UNIQUE " } else { "" },
                bq(&idx.name),
                bq(&schema_name),
                bq(&idx.table_name),
                idx.columns
                    .iter()
                    .map(|c| if c.starts_with('(') { c.clone() } else { bq(c) })
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let mut fks: BTreeMap<String, Vec<ForeignKeySpec>> = BTreeMap::new();
    for r in &rows.foreign_keys {
        let schema = s(r.first());
        let table = s(r.get(1));
        let constraint = s(r.get(2));
        let ref_schema = s(r.get(4));
        let ref_table = s(r.get(5));
        let referenced_table = if ref_schema.eq_ignore_ascii_case(&schema) || ref_schema.is_empty()
        {
            ref_table
        } else {
            format!("{ref_schema}.{ref_table}")
        };
        let list = fks.entry(key(&schema, &table)).or_default();
        let pos = list
            .iter()
            .position(|f| f.name.as_deref() == Some(constraint.as_str()));
        let fk = match pos {
            Some(p) => &mut list[p],
            None => {
                list.push(ForeignKeySpec {
                    name: Some(constraint.clone()),
                    columns: Vec::new(),
                    referenced_table,
                    referenced_columns: Vec::new(),
                    on_update: opt_s(r.get(7)),
                    on_delete: opt_s(r.get(8)),
                });
                list.last_mut().expect("just pushed")
            }
        };
        fk.columns.push(s(r.get(3)));
        fk.referenced_columns.push(s(r.get(6)));
    }

    let views: BTreeMap<String, Option<String>> = rows
        .views
        .iter()
        .map(|r| {
            (
                key(&s(r.first()), &s(r.get(1))),
                opt_s(r.get(2)).filter(|d| !d.trim().is_empty()),
            )
        })
        .collect();

    let mut objects = Vec::new();
    for t in &rows.tables {
        let schema = s(t.first());
        let name = s(t.get(1));
        let is_view = s(t.get(2)).eq_ignore_ascii_case("view");
        let k = key(&schema, &name);
        let table_indexes = if is_view {
            Vec::new()
        } else {
            indexes.get(&k).cloned().unwrap_or_default()
        };
        for idx in table_indexes.iter().filter(|i| !i.primary) {
            objects.push(CatalogObject {
                schema: schema.clone(),
                name: idx.name.clone(),
                object_type: CatalogObjectType::Index,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: idx
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(pos, c)| ColumnSpec {
                        name: c.clone(),
                        data_type: "index_key".to_string(),
                        nullable: true,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: pos + 1,
                    })
                    .collect(),
                indexes: vec![idx.clone()],
                foreign_keys: Vec::new(),
                definition: idx.definition.clone(),
            });
        }
        let definition = if is_view {
            views
                .get(&k)
                .cloned()
                .flatten()
                .map(|body| format!("CREATE VIEW {}.{} AS {body}", bq(&schema), bq(&name)))
        } else {
            None
        };
        objects.push(CatalogObject {
            schema: schema.clone(),
            name: name.clone(),
            object_type: if is_view {
                CatalogObjectType::View
            } else {
                CatalogObjectType::Table
            },
            comment: opt_s(t.get(3)).filter(|c| !c.is_empty()),
            estimated_rows: if is_view { None } else { num(t.get(4)) },
            size_bytes: if is_view { None } else { num(t.get(5)) },
            columns: columns.get(&k).cloned().unwrap_or_default(),
            indexes: table_indexes,
            foreign_keys: if is_view {
                Vec::new()
            } else {
                fks.get(&k).cloned().unwrap_or_default()
            },
            definition,
        });
    }

    for r in &rows.triggers {
        let schema = s(r.first());
        let name = s(r.get(1));
        let table = s(r.get(4));
        objects.push(CatalogObject {
            schema: schema.clone(),
            name: name.clone(),
            object_type: CatalogObjectType::Trigger,
            comment: Some(format!("Trigger on {table}")),
            estimated_rows: None,
            size_bytes: None,
            columns: Vec::new(),
            indexes: Vec::new(),
            foreign_keys: Vec::new(),
            definition: Some(format!(
                "CREATE TRIGGER {} {} {} ON {}.{} FOR EACH ROW {}",
                bq(&name),
                s(r.get(2)),
                s(r.get(3)),
                bq(&schema),
                bq(&table),
                s(r.get(5))
            )),
        });
    }

    // (schema.routine) -> rendered parameter list and RETURNS clause.
    let mut params: BTreeMap<String, (Vec<String>, Option<String>)> = BTreeMap::new();
    for r in &rows.parameters {
        let entry = params.entry(key(&s(r.first()), &s(r.get(1)))).or_default();
        let ordinal = num(r.get(2)).unwrap_or(0);
        let dtd = s(r.get(5));
        if ordinal == 0 {
            entry.1 = Some(dtd);
            continue;
        }
        let is_function = s(r.get(6)).eq_ignore_ascii_case("FUNCTION");
        let mode = opt_s(r.get(3))
            .filter(|_| !is_function)
            .map(|m| format!("{m} "))
            .unwrap_or_default();
        entry.0.push(format!("{mode}{} {dtd}", s(r.get(4))));
    }
    for r in &rows.routines {
        let schema = s(r.first());
        let name = s(r.get(1));
        let kind = s(r.get(2));
        let is_function = kind.eq_ignore_ascii_case("function");
        let body = opt_s(r.get(3));
        let (plist, returns) = params
            .get(&key(&schema, &name))
            .cloned()
            .unwrap_or_default();
        let definition = body.map(|b| {
            format!(
                "CREATE {} {}.{}({}){}\n{b}",
                if is_function { "FUNCTION" } else { "PROCEDURE" },
                bq(&schema),
                bq(&name),
                plist.join(", "),
                returns
                    .filter(|_| is_function)
                    .map(|r| format!(" RETURNS {r}"))
                    .unwrap_or_default()
            )
        });
        objects.push(CatalogObject {
            schema,
            name,
            object_type: if is_function {
                CatalogObjectType::Function
            } else {
                CatalogObjectType::Procedure
            },
            comment: opt_s(r.get(4)).filter(|c| !c.is_empty()),
            estimated_rows: None,
            size_bytes: None,
            columns: Vec::new(),
            indexes: Vec::new(),
            foreign_keys: Vec::new(),
            definition,
        });
    }
    objects
}

/// Discovered catalog plus visibility warnings (missing grants), cached per connection.
#[derive(Clone)]
pub struct CachedCatalog {
    pub at: Instant,
    pub objects: std::sync::Arc<Vec<CatalogObject>>,
    pub warnings: Vec<String>,
    pub schema_version: String,
}

impl LiveMySql {
    /// Read the catalog from `information_schema` (or reuse a fresh cached copy).
    pub async fn catalog(&self, force: bool) -> DbMcpResult<CachedCatalog> {
        if !force {
            if let Some(c) = self.cached_catalog() {
                if c.at.elapsed() < CATALOG_CACHE_TTL {
                    return Ok(c);
                }
            }
        }
        let timeout_ms = 30_000;
        let mut conn = self.session(true, timeout_ms).await?;
        let rows = CatalogRows {
            tables: self
                .query_json(
                    &mut conn,
                    &crate::build_information_schema_tables_query(None),
                    timeout_ms,
                )
                .await?
                .1,
            columns: self
                .query_json(
                    &mut conn,
                    &build_information_schema_all_columns_query(),
                    timeout_ms,
                )
                .await?
                .1,
            statistics: self
                .query_json(
                    &mut conn,
                    &build_information_schema_all_statistics_query(),
                    timeout_ms,
                )
                .await?
                .1,
            foreign_keys: self
                .query_json(
                    &mut conn,
                    &build_information_schema_foreign_keys_query(),
                    timeout_ms,
                )
                .await?
                .1,
            views: self
                .query_json(
                    &mut conn,
                    &build_information_schema_views_query(),
                    timeout_ms,
                )
                .await?
                .1,
            triggers: self
                .query_json(
                    &mut conn,
                    &build_information_schema_triggers_query(),
                    timeout_ms,
                )
                .await?
                .1,
            routines: self
                .query_json(
                    &mut conn,
                    &crate::build_information_schema_routines_query(None),
                    timeout_ms,
                )
                .await?
                .1,
            parameters: self
                .query_json(
                    &mut conn,
                    &build_information_schema_parameters_query(),
                    timeout_ms,
                )
                .await?
                .1,
        };
        let grants = self.grants(&mut conn).await.unwrap_or_default();
        drop(conn);

        let mut warnings = Vec::new();
        let privileges = crate::live::summarize_grants(&grants);
        if !privileges.can_read_routine_definitions {
            warnings.push(format!(
                "routine definitions are hidden from '{}': procedures/functions are not listed and the call graph is incomplete (optional: GRANT SHOW_ROUTINE ON *.* TO the login)",
                self.dsn.user
            ));
        } else if rows
            .routines
            .iter()
            .any(|r| matches!(r.get(3), Some(J::Null) | None))
        {
            warnings.push("some routine definitions are NULL (definition hidden); the call graph omits their bodies".to_string());
        }
        if rows.triggers.is_empty() && !privileges.has_trigger {
            warnings.push(
                "triggers are not listed: information_schema.TRIGGERS needs the TRIGGER privilege, which also allows creating triggers (not granted to a read-only login by design)".to_string(),
            );
        }
        if rows
            .views
            .iter()
            .any(|r| matches!(r.get(2), Some(J::Null) | None) || s(r.get(2)).is_empty())
        {
            warnings.push(
                "some view definitions are empty: GRANT SHOW VIEW on the schema to read them"
                    .to_string(),
            );
        }
        let objects = build_catalog_objects(&rows);
        let schema_version = db_mcp_catalog::compute_schema_version(&objects);
        let cached = CachedCatalog {
            at: Instant::now(),
            objects: std::sync::Arc::new(objects),
            warnings,
            schema_version,
        };
        self.store_catalog(cached.clone());
        Ok(cached)
    }
}

// ---------------------------------------------------------------------------------------------
// EXPLAIN
// ---------------------------------------------------------------------------------------------

impl LiveMySql {
    /// Real `EXPLAIN FORMAT=JSON` (plus `FORMAT=TREE` for text, `EXPLAIN ANALYZE` when requested
    /// on 8.0.18+). The statement must be a single read; policy decides whether ANALYZE is allowed.
    pub async fn explain(
        &self,
        request: &db_mcp_core::ExplainRequest,
    ) -> DbMcpResult<db_mcp_core::ExplainPlan> {
        let stmts =
            db_mcp_sql::split_sql_statements(db_mcp_core::DatabaseEngine::MySql, &request.sql);
        let stmts: Vec<&String> = stmts.iter().filter(|s| !s.trim().is_empty()).collect();
        if stmts.len() != 1 {
            return Err(db_mcp_core::DbMcpError::InvalidArgument(
                "explain_query requires a single SQL statement".to_string(),
            ));
        }
        let trimmed = stmts[0].trim().trim_end_matches(';').trim().to_string();
        if trimmed.to_ascii_uppercase().starts_with("EXPLAIN") {
            return Err(db_mcp_core::DbMcpError::InvalidArgument(
                "SQL passed to explain_query must not already start with EXPLAIN".to_string(),
            ));
        }
        let analysis =
            db_mcp_sql::parse_and_analyze_sql(db_mcp_core::DatabaseEngine::MySql, &trimmed)?;
        if analysis.overall_class.is_mutating()
            || analysis.has_privileged_functions
            || analysis.has_cte_write
        {
            return Err(db_mcp_core::DbMcpError::PolicyDenied {
                code: "READONLY_VIOLATION".to_string(),
                message: "explain_query only permits read-only SQL statements".to_string(),
                next_action: None,
            });
        }
        let timeout_ms = if request.timeout_ms == 0 {
            10_000
        } else {
            request.timeout_ms
        };
        let (sql, params) = crate::live::bind_mysql_placeholders(&trimmed, &request.params)?;
        let params: Vec<mysql_async::Value> = params
            .iter()
            .map(crate::live::json_to_mysql_param)
            .collect();
        let mut conn = self.session(true, timeout_ms).await?;
        let raw_json = self
            .explain_text(
                &mut conn,
                &format!("EXPLAIN FORMAT=JSON {sql}"),
                &params,
                timeout_ms,
            )
            .await?;
        let parsed = crate::parse_mysql_explain_json(&raw_json)?;
        let mut warnings = parsed.warnings.clone();
        let raw_plan = if request.analyze {
            if self
                .server_version_tuple()
                .map(|v| v < (8, 0, 18))
                .unwrap_or(false)
            {
                return Err(db_mcp_core::DbMcpError::UnsupportedCapability(format!(
                    "EXPLAIN ANALYZE needs MySQL 8.0.18 or later (server {})",
                    self.server_version().unwrap_or_default()
                )));
            }
            warnings.push("EXPLAIN ANALYZE executed the statement (read-only session) to measure actual rows and timings".to_string());
            self.explain_text(
                &mut conn,
                &format!("EXPLAIN ANALYZE {sql}"),
                &params,
                timeout_ms,
            )
            .await?
        } else {
            match request.format {
                db_mcp_core::ExplainFormat::Json => raw_json.clone(),
                db_mcp_core::ExplainFormat::Text => {
                    self.explain_text(
                        &mut conn,
                        &format!("EXPLAIN FORMAT=TREE {sql}"),
                        &params,
                        timeout_ms,
                    )
                    .await?
                }
            }
        };
        drop(conn);
        Ok(db_mcp_core::ExplainPlan {
            connection: request.connection.clone(),
            sql: request.sql.clone(),
            analyze: request.analyze,
            format: request.format,
            raw_plan,
            structured_plan: Some(parsed.structured_plan),
            estimated_cost: parsed.query_cost,
            estimated_rows: parsed.rows_examined,
            seq_scans: parsed.seq_scans,
            index_scans: parsed.index_scans,
            warnings,
        })
    }

    async fn explain_text(
        &self,
        conn: &mut mysql_async::Conn,
        sql: &str,
        params: &[mysql_async::Value],
        timeout_ms: u64,
    ) -> DbMcpResult<String> {
        use mysql_async::prelude::Queryable;
        let map = |e: mysql_async::Error| {
            crate::live::map_exec_error(&self.connection_id, &self.dsn, timeout_ms, &e)
        };
        let row: Option<mysql_async::Row> = if params.is_empty() {
            conn.query_first(sql).await.map_err(map)?
        } else {
            conn.exec_first(sql, mysql_async::Params::Positional(params.to_vec()))
                .await
                .map_err(map)?
        };
        let value = row
            .and_then(|r| r.unwrap().into_iter().next())
            .unwrap_or(mysql_async::Value::NULL);
        match value {
            mysql_async::Value::Bytes(b) => Ok(String::from_utf8_lossy(&b).into_owned()),
            mysql_async::Value::NULL => Err(db_mcp_core::DbMcpError::AdapterError(
                "MySQL returned an empty plan".to_string(),
            )),
            other => Ok(format!("{other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_rows_map_to_objects() {
        let rows = CatalogRows {
            tables: vec![
                vec![
                    json!("appdb"),
                    json!("orders"),
                    json!("table"),
                    json!("Customer orders"),
                    json!(2),
                    json!(32768),
                ],
                vec![
                    json!("appdb"),
                    json!("users"),
                    json!("table"),
                    json!(""),
                    json!(2),
                    json!(16384),
                ],
                vec![
                    json!("appdb"),
                    json!("active_user_orders"),
                    json!("view"),
                    json!(""),
                    J::Null,
                    J::Null,
                ],
            ],
            columns: vec![
                vec![
                    json!("appdb"),
                    json!("orders"),
                    json!("id"),
                    json!("bigint"),
                    json!(0),
                    J::Null,
                    json!(1),
                    json!(""),
                    json!(1),
                ],
                vec![
                    json!("appdb"),
                    json!("orders"),
                    json!("user_id"),
                    json!("bigint"),
                    json!(0),
                    J::Null,
                    json!(0),
                    json!(""),
                    json!(2),
                ],
                vec![
                    json!("appdb"),
                    json!("users"),
                    json!("id"),
                    json!("bigint"),
                    json!(0),
                    J::Null,
                    json!(1),
                    json!(""),
                    json!(1),
                ],
            ],
            statistics: vec![
                vec![
                    json!("appdb"),
                    json!("orders"),
                    json!("PRIMARY"),
                    json!("id"),
                    json!(1),
                    json!("BTREE"),
                    json!(1),
                    J::Null,
                ],
                vec![
                    json!("appdb"),
                    json!("orders"),
                    json!("fk_orders_user"),
                    json!("user_id"),
                    json!(0),
                    json!("BTREE"),
                    json!(1),
                    J::Null,
                ],
            ],
            foreign_keys: vec![vec![
                json!("appdb"),
                json!("orders"),
                json!("fk_orders_user"),
                json!("user_id"),
                json!("appdb"),
                json!("users"),
                json!("id"),
                json!("NO ACTION"),
                json!("CASCADE"),
            ]],
            views: vec![vec![
                json!("appdb"),
                json!("active_user_orders"),
                json!("select `o`.`id` AS `order_id` from `appdb`.`orders` `o`"),
            ]],
            triggers: vec![vec![
                json!("appdb"),
                json!("trg"),
                json!("AFTER"),
                json!("UPDATE"),
                json!("orders"),
                json!("BEGIN END"),
            ]],
            routines: vec![
                vec![
                    json!("appdb"),
                    json!("calc"),
                    json!("function"),
                    json!("BEGIN RETURN 1; END"),
                    json!(""),
                ],
                vec![
                    json!("appdb"),
                    json!("hidden"),
                    json!("procedure"),
                    J::Null,
                    json!(""),
                ],
            ],
            parameters: vec![
                vec![
                    json!("appdb"),
                    json!("calc"),
                    json!(0),
                    J::Null,
                    J::Null,
                    json!("decimal(12,2)"),
                    json!("FUNCTION"),
                ],
                vec![
                    json!("appdb"),
                    json!("calc"),
                    json!(1),
                    json!("IN"),
                    json!("p_id"),
                    json!("bigint"),
                    json!("FUNCTION"),
                ],
            ],
        };
        let objs = build_catalog_objects(&rows);
        let orders = objs.iter().find(|o| o.name == "orders").unwrap();
        assert_eq!(orders.columns.len(), 2);
        assert!(orders
            .indexes
            .iter()
            .any(|i| i.primary && i.columns == vec!["id"]));
        assert_eq!(orders.foreign_keys[0].referenced_table, "users");
        assert_eq!(orders.foreign_keys[0].on_delete.as_deref(), Some("CASCADE"));
        assert_eq!(orders.comment.as_deref(), Some("Customer orders"));
        let idx = objs
            .iter()
            .find(|o| o.object_type == CatalogObjectType::Index)
            .unwrap();
        assert_eq!(
            idx.definition.as_deref(),
            Some("CREATE INDEX `fk_orders_user` ON `appdb`.`orders` (`user_id`);")
        );
        let view = objs
            .iter()
            .find(|o| o.object_type == CatalogObjectType::View)
            .unwrap();
        assert!(view
            .definition
            .as_deref()
            .unwrap()
            .starts_with("CREATE VIEW `appdb`.`active_user_orders` AS select"));
        let f = objs.iter().find(|o| o.name == "calc").unwrap();
        assert_eq!(f.object_type, CatalogObjectType::Function);
        assert_eq!(f.definition.as_deref().unwrap(), "CREATE FUNCTION `appdb`.`calc`(p_id bigint) RETURNS decimal(12,2)\nBEGIN RETURN 1; END");
        assert!(objs
            .iter()
            .find(|o| o.name == "hidden")
            .unwrap()
            .definition
            .is_none());
        assert_eq!(
            objs.iter()
                .filter(|o| o.object_type == CatalogObjectType::Trigger)
                .count(),
            1
        );
    }
}
