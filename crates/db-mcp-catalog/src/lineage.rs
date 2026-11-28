//! Table dependency lineage, foreign-key graph traversal, shortest multi-hop join path synthesis,
//! and stored procedure / function call-graph analysis.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use db_mcp_core::{
    CatalogDetailLevel, CatalogObject, CatalogObjectType, CatalogRequest, DatabaseAdapter,
    DatabaseEngine, DbMcpError, DbMcpResult, DependentObjectRef, ProcedureCallEdge,
    ProcedureCallGraphReport, ProcedureNode, TableDependencyReport, TableJoinHop, TableJoinPath,
    TableRelationshipEdge,
};
use db_mcp_sql::{analyze_routine_definition, parse_and_analyze_sql, StatementAnalysis};
use regex::Regex;

/// Clean quotes and whitespace from a SQL identifier while preserving schema qualification.
fn clean_identifier(raw: &str) -> String {
    raw.split('.')
        .map(|part| {
            part.trim()
                .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn base_name(ident: &str) -> &str {
    ident.rsplit('.').next().unwrap_or(ident)
}

fn sanitize_mermaid_id(prefix: &str, name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{prefix}_{sanitized}")
}

/// Resolve a table identifier against catalog `Table` objects (case-insensitive qualified or unqualified match).
fn resolve_table_object<'a>(
    tables: &[&'a CatalogObject],
    raw_query: &str,
    preferred_schema: Option<&str>,
) -> Option<&'a CatalogObject> {
    let cleaned = clean_identifier(raw_query);
    if cleaned.is_empty() {
        return None;
    }

    // 1. Exact qualified name match
    for tbl in tables {
        if tbl.qualified_name().eq_ignore_ascii_case(&cleaned) {
            return Some(*tbl);
        }
    }

    // 2. If unqualified and a preferred schema is known, try `<preferred_schema>.<cleaned>`
    if !cleaned.contains('.') {
        if let Some(schema) = preferred_schema.filter(|s| !s.is_empty()) {
            let candidate = format!("{schema}.{cleaned}");
            for tbl in tables {
                if tbl.qualified_name().eq_ignore_ascii_case(&candidate) {
                    return Some(*tbl);
                }
            }
        }
    }

    // 3. Unqualified / base-name match
    let target_base = base_name(&cleaned);
    for tbl in tables {
        if tbl.name.eq_ignore_ascii_case(target_base) {
            return Some(*tbl);
        }
    }

    None
}

/// Resolve a routine identifier against catalog `Function` and `Procedure` objects.
fn resolve_routine_object<'a>(
    routines: &[&'a CatalogObject],
    raw_query: &str,
    preferred_schema: Option<&str>,
) -> Option<&'a CatalogObject> {
    let cleaned = clean_identifier(raw_query);
    if cleaned.is_empty() {
        return None;
    }

    for r in routines {
        if r.qualified_name().eq_ignore_ascii_case(&cleaned) {
            return Some(*r);
        }
    }

    if !cleaned.contains('.') {
        if let Some(schema) = preferred_schema.filter(|s| !s.is_empty()) {
            let candidate = format!("{schema}.{cleaned}");
            for r in routines {
                if r.qualified_name().eq_ignore_ascii_case(&candidate) {
                    return Some(*r);
                }
            }
        }
    }

    let target_base = base_name(&cleaned);
    for r in routines {
        if r.name.eq_ignore_ascii_case(target_base) {
            return Some(*r);
        }
    }

    None
}

fn identifiers_match_table(candidate: &str, table_obj: &CatalogObject) -> bool {
    let cleaned = clean_identifier(candidate);
    if cleaned.is_empty() {
        return false;
    }
    let qname = table_obj.qualified_name();
    if cleaned.eq_ignore_ascii_case(&qname) || cleaned.eq_ignore_ascii_case(&table_obj.name) {
        return true;
    }
    if !cleaned.contains('.') && base_name(&cleaned).eq_ignore_ascii_case(&table_obj.name) {
        return true;
    }
    false
}

/// Build the full list of foreign key edges across all tables in the catalog.
fn build_fk_edges(tables: &[&CatalogObject]) -> Vec<TableRelationshipEdge> {
    let mut edges = Vec::new();
    for tbl in tables {
        let from_table = tbl.qualified_name();
        for fk in &tbl.foreign_keys {
            let to_table = resolve_table_object(tables, &fk.referenced_table, Some(&tbl.schema))
                .map(|t| t.qualified_name())
                .unwrap_or_else(|| {
                    let cleaned_ref = clean_identifier(&fk.referenced_table);
                    if !cleaned_ref.contains('.') && !tbl.schema.is_empty() {
                        format!("{}.{}", tbl.schema, cleaned_ref)
                    } else {
                        cleaned_ref
                    }
                });
            let to_columns = if fk.referenced_columns.is_empty() {
                vec!["id".to_string()]
            } else {
                fk.referenced_columns.clone()
            };
            edges.push(TableRelationshipEdge {
                from_table: from_table.clone(),
                from_columns: fk.columns.clone(),
                to_table,
                to_columns,
                constraint_name: fk.name.clone(),
                relationship_kind: "foreign_key".to_string(),
                on_delete: fk.on_delete.clone(),
                on_update: fk.on_update.clone(),
            });
        }
    }
    edges.sort();
    edges.dedup();
    edges
}

/// Inspect views, materialized views, triggers, functions, and procedures for dependencies on `target_table`.
fn scan_dependent_objects(
    objects: &[CatalogObject],
    engine: DatabaseEngine,
    target_table: &CatalogObject,
    known_routines: &[String],
    known_tables: &[String],
) -> Vec<DependentObjectRef> {
    let mut dependents = Vec::new();
    let target_qname = target_table.qualified_name();
    let target_base = &target_table.name;

    let trigger_on_re = Regex::new(&format!(
        r#"(?is)\bON\s+(?:ONLY\s+)?([A-Za-z0-9_."`\[\]]*\b{}\b)"#,
        regex::escape(target_base)
    ))
    .ok();
    let word_re = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(target_base))).ok();
    let qname_re = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&target_qname))).ok();

    for obj in objects {
        if !matches!(
            obj.object_type,
            CatalogObjectType::View
                | CatalogObjectType::MaterializedView
                | CatalogObjectType::Trigger
                | CatalogObjectType::Function
                | CatalogObjectType::Procedure
        ) {
            continue;
        }

        let Some(def_sql) = obj
            .definition
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        let routine_analysis = analyze_routine_definition(
            engine,
            &obj.qualified_name(),
            def_sql,
            known_routines,
            known_tables,
        );

        let mut is_read = routine_analysis
            .tables_read
            .iter()
            .any(|t| identifiers_match_table(t, target_table));
        let mut is_write = routine_analysis
            .tables_written
            .iter()
            .any(|t| identifiers_match_table(t, target_table));

        if let Ok(parsed) = parse_and_analyze_sql(engine, def_sql) {
            for stmt in &parsed.statements {
                inspect_statement_for_table(
                    stmt,
                    target_table,
                    obj.object_type,
                    &mut is_read,
                    &mut is_write,
                );
            }
        }

        if obj.object_type == CatalogObjectType::Trigger {
            if let Some(re) = &trigger_on_re {
                if re.is_match(def_sql) {
                    is_read = true;
                }
            }
        }

        if !is_read
            && !is_write
            && matches!(
                obj.object_type,
                CatalogObjectType::View | CatalogObjectType::MaterializedView
            )
            && word_re
                .as_ref()
                .map(|r| r.is_match(def_sql))
                .unwrap_or(false)
        {
            is_read = true;
        }

        if !is_read && !is_write {
            continue;
        }

        let access_mode = match obj.object_type {
            CatalogObjectType::View | CatalogObjectType::MaterializedView => "read".to_string(),
            _ => match (is_read, is_write) {
                (true, true) => "read_write".to_string(),
                (false, true) => "write".to_string(),
                _ => "read".to_string(),
            },
        };

        let matched_reference = if qname_re
            .as_ref()
            .map(|r| r.is_match(def_sql))
            .unwrap_or(false)
        {
            target_qname.clone()
        } else {
            target_base.clone()
        };

        dependents.push(DependentObjectRef {
            schema: obj.schema.clone(),
            name: obj.name.clone(),
            qualified_name: obj.qualified_name(),
            object_type: obj.object_type,
            access_mode,
            matched_reference,
        });
    }

    dependents.sort_by(|a, b| {
        a.qualified_name
            .cmp(&b.qualified_name)
            .then_with(|| a.object_type.cmp(&b.object_type))
    });
    dependents
}

fn inspect_statement_for_table(
    stmt: &StatementAnalysis,
    target_table: &CatalogObject,
    object_type: CatalogObjectType,
    is_read: &mut bool,
    is_write: &mut bool,
) {
    let touches_target = stmt
        .referenced_tables
        .iter()
        .any(|t| identifiers_match_table(t, target_table));
    if !touches_target {
        return;
    }

    match object_type {
        CatalogObjectType::View | CatalogObjectType::MaterializedView => {
            *is_read = true;
        }
        _ => match stmt.statement_kind.as_str() {
            "INSERT" | "UPDATE" | "DELETE" | "MERGE" => {
                *is_write = true;
            }
            _ => {
                *is_read = true;
            }
        },
    }
}

/// Find the shortest multi-hop join path between `source_table` and `target_table` over the undirected FK graph.
fn find_shortest_join_path(
    source_table: &str,
    target_table: &str,
    all_edges: &[TableRelationshipEdge],
    max_depth: usize,
) -> Option<TableJoinPath> {
    if source_table.eq_ignore_ascii_case(target_table) {
        return Some(TableJoinPath {
            source_table: source_table.to_string(),
            target_table: target_table.to_string(),
            hops: Vec::new(),
            synthesized_join_sql: format!("SELECT * FROM {source_table}"),
        });
    }

    let search_depth = max_depth;
    let mut queue: VecDeque<(String, Vec<TableJoinHop>)> = VecDeque::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();

    queue.push_back((source_table.to_string(), Vec::new()));
    visited.insert(source_table.to_ascii_lowercase());

    while let Some((current_table, hops_so_far)) = queue.pop_front() {
        if hops_so_far.len() >= search_depth {
            continue;
        }

        // Gather candidate neighbor hops in deterministic order
        let mut candidate_hops: Vec<TableJoinHop> = Vec::new();
        for edge in all_edges {
            if edge.from_table.eq_ignore_ascii_case(&current_table) {
                let join_condition = format_join_condition(
                    &edge.from_table,
                    &edge.from_columns,
                    &edge.to_table,
                    &edge.to_columns,
                );
                candidate_hops.push(TableJoinHop {
                    from_table: edge.from_table.clone(),
                    to_table: edge.to_table.clone(),
                    join_condition,
                    constraint_name: edge.constraint_name.clone(),
                });
            } else if edge.to_table.eq_ignore_ascii_case(&current_table) {
                let join_condition = format_join_condition(
                    &edge.to_table,
                    &edge.to_columns,
                    &edge.from_table,
                    &edge.from_columns,
                );
                candidate_hops.push(TableJoinHop {
                    from_table: edge.to_table.clone(),
                    to_table: edge.from_table.clone(),
                    join_condition,
                    constraint_name: edge.constraint_name.clone(),
                });
            }
        }

        for hop in candidate_hops {
            let next_key = hop.to_table.to_ascii_lowercase();
            if visited.contains(&next_key) {
                continue;
            }
            let mut next_hops = hops_so_far.clone();
            let next_table = hop.to_table.clone();
            next_hops.push(hop);

            if next_table.eq_ignore_ascii_case(target_table) {
                let mut sql = format!("SELECT * FROM {source_table}");
                for h in &next_hops {
                    sql.push_str(&format!(" JOIN {} ON {}", h.to_table, h.join_condition));
                }
                return Some(TableJoinPath {
                    source_table: source_table.to_string(),
                    target_table: next_table,
                    hops: next_hops,
                    synthesized_join_sql: sql,
                });
            }

            visited.insert(next_key);
            queue.push_back((next_table, next_hops));
        }
    }

    None
}

fn format_join_condition(
    left_table: &str,
    left_cols: &[String],
    right_table: &str,
    right_cols: &[String],
) -> String {
    let pairs: Vec<String> = left_cols
        .iter()
        .zip(right_cols.iter())
        .map(|(l, r)| format!("{left_table}.{l} = {right_table}.{r}"))
        .collect();
    if pairs.is_empty() {
        format!("{left_table}.id = {right_table}.id")
    } else {
        pairs.join(" AND ")
    }
}

fn render_table_dependency_mermaid(
    root_table: &str,
    outbound_fks: &[TableRelationshipEdge],
    inbound_fks: &[TableRelationshipEdge],
    dependent_objects: &[DependentObjectRef],
    join_path: Option<&TableJoinPath>,
) -> String {
    let mut lines = vec!["flowchart LR".to_string()];
    let mut declared_nodes = BTreeSet::new();
    let mut declared_edges = BTreeSet::new();

    let mut declare_table_node = |tbl: &str, lines: &mut Vec<String>| -> String {
        let id = sanitize_mermaid_id("tbl", tbl);
        if declared_nodes.insert(id.clone()) {
            lines.push(format!("    {id}[\"{tbl}\"]"));
        }
        id
    };

    let root_id = declare_table_node(root_table, &mut lines);

    for fk in outbound_fks {
        let from_id = declare_table_node(&fk.from_table, &mut lines);
        let to_id = declare_table_node(&fk.to_table, &mut lines);
        let label = fk.from_columns.join(", ");
        let edge_line = format!("    {from_id} -->|\"FK ({label})\"| {to_id}");
        if declared_edges.insert(edge_line.clone()) {
            lines.push(edge_line);
        }
    }

    for fk in inbound_fks {
        let from_id = declare_table_node(&fk.from_table, &mut lines);
        let to_id = declare_table_node(&fk.to_table, &mut lines);
        let label = fk.from_columns.join(", ");
        let edge_line = format!("    {from_id} -->|\"FK ({label})\"| {to_id}");
        if declared_edges.insert(edge_line.clone()) {
            lines.push(edge_line);
        }
    }

    if let Some(path) = join_path {
        for hop in &path.hops {
            let from_id = declare_table_node(&hop.from_table, &mut lines);
            let to_id = declare_table_node(&hop.to_table, &mut lines);
            let edge_line = format!("    {from_id} -.->|\"JOIN\"| {to_id}");
            if declared_edges.insert(edge_line.clone()) {
                lines.push(edge_line);
            }
        }
    }

    for dep in dependent_objects {
        let dep_id = sanitize_mermaid_id(dep.object_type.as_str(), &dep.qualified_name);
        if declared_nodes.insert(dep_id.clone()) {
            lines.push(format!(
                "    {dep_id}([\"{} ({})\"])",
                dep.qualified_name,
                dep.object_type.as_str()
            ));
        }
        let edge_line = format!("    {dep_id} -->|\"{}\"| {root_id}", dep.access_mode);
        if declared_edges.insert(edge_line.clone()) {
            lines.push(edge_line);
        }
    }

    lines.join("\n")
}

/// Trace foreign-key relationships, transitive table lineage, dependent views/triggers/procedures,
/// and optional shortest multi-hop join paths for a table.
pub fn trace_table_dependencies(
    objects: &[CatalogObject],
    engine: DatabaseEngine,
    connection: &str,
    table_name: &str,
    target_table: Option<&str>,
    max_depth: usize,
) -> DbMcpResult<TableDependencyReport> {
    let trimmed_table = table_name.trim();
    if trimmed_table.is_empty() {
        return Err(DbMcpError::InvalidArgument(
            "table_name must not be empty".to_string(),
        ));
    }

    let tables: Vec<&CatalogObject> = objects
        .iter()
        .filter(|o| o.object_type == CatalogObjectType::Table)
        .collect();

    let root_obj = resolve_table_object(&tables, trimmed_table, None).ok_or_else(|| {
        DbMcpError::InvalidArgument(format!(
            "Table '{}' was not found in connection '{}'",
            trimmed_table, connection
        ))
    })?;
    let root_qname = root_obj.qualified_name();

    let resolved_target = match target_table.map(str::trim).filter(|s| !s.is_empty()) {
        Some(target_raw) => {
            let t_obj = resolve_table_object(&tables, target_raw, Some(&root_obj.schema))
                .ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!(
                        "Target table '{}' was not found in connection '{}'",
                        target_raw, connection
                    ))
                })?;
            Some(t_obj.qualified_name())
        }
        None => None,
    };

    let depth_limit = if max_depth == 0 { 3 } else { max_depth };
    let all_edges = build_fk_edges(&tables);

    let outbound_foreign_keys: Vec<TableRelationshipEdge> = all_edges
        .iter()
        .filter(|e| e.from_table.eq_ignore_ascii_case(&root_qname))
        .cloned()
        .collect();

    let inbound_foreign_keys: Vec<TableRelationshipEdge> = all_edges
        .iter()
        .filter(|e| e.to_table.eq_ignore_ascii_case(&root_qname))
        .cloned()
        .collect();

    // Compute transitive tables reachable within `depth_limit` across inbound and outbound FKs
    let mut transitive_set = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    visited.insert(root_qname.to_ascii_lowercase());
    queue.push_back((root_qname.clone(), 0));

    while let Some((curr, depth)) = queue.pop_front() {
        if depth >= depth_limit {
            continue;
        }
        for edge in &all_edges {
            let neighbor = if edge.from_table.eq_ignore_ascii_case(&curr) {
                Some(&edge.to_table)
            } else if edge.to_table.eq_ignore_ascii_case(&curr) {
                Some(&edge.from_table)
            } else {
                None
            };
            if let Some(next_tbl) = neighbor {
                let key = next_tbl.to_ascii_lowercase();
                if visited.insert(key) {
                    transitive_set.insert(next_tbl.clone());
                    queue.push_back((next_tbl.clone(), depth + 1));
                }
            }
        }
    }

    let known_tables: Vec<String> = tables.iter().map(|t| t.qualified_name()).collect();
    let known_routines: Vec<String> = objects
        .iter()
        .filter(|o| {
            matches!(
                o.object_type,
                CatalogObjectType::Function | CatalogObjectType::Procedure
            )
        })
        .map(|o| o.qualified_name())
        .collect();

    let dependent_objects =
        scan_dependent_objects(objects, engine, root_obj, &known_routines, &known_tables);

    let join_path = resolved_target.as_deref().and_then(|target_qname| {
        find_shortest_join_path(&root_qname, target_qname, &all_edges, depth_limit)
    });

    let mermaid_diagram = render_table_dependency_mermaid(
        &root_qname,
        &outbound_foreign_keys,
        &inbound_foreign_keys,
        &dependent_objects,
        join_path.as_ref(),
    );

    Ok(TableDependencyReport {
        connection: connection.to_string(),
        table_name: root_qname,
        target_table: resolved_target,
        max_depth: depth_limit,
        outbound_foreign_keys,
        inbound_foreign_keys,
        transitive_tables: transitive_set.into_iter().collect(),
        dependent_objects,
        join_path,
        mermaid_diagram,
    })
}

/// Discover catalog objects via `DatabaseAdapter` and run `trace_table_dependencies`.
pub async fn trace_table_dependencies_via_adapter(
    adapter: &dyn DatabaseAdapter,
    connection: &str,
    table_name: &str,
    target_table: Option<&str>,
    max_depth: usize,
) -> DbMcpResult<TableDependencyReport> {
    let request = CatalogRequest {
        connection: connection.to_string(),
        schema_pattern: None,
        name_pattern: None,
        object_types: Vec::new(),
        detail_level: CatalogDetailLevel::Full,
        limit: 10_000,
        offset: 0,
    };
    let response = adapter.discover(request).await?;
    let engine = adapter.capabilities().engine;
    trace_table_dependencies(
        &response.objects,
        engine,
        connection,
        table_name,
        target_table,
        max_depth,
    )
}

/// Build a stored procedure and function call graph (`ProcedureCallGraphReport`) with caller/callee
/// edges, table read/write touchpoints, transitive call chains, and cycle detection.
pub fn build_procedure_call_graph(
    objects: &[CatalogObject],
    engine: DatabaseEngine,
    connection: &str,
    root_procedure: Option<&str>,
    direction: &str,
    max_depth: usize,
) -> DbMcpResult<ProcedureCallGraphReport> {
    let depth_limit = if max_depth == 0 { 5 } else { max_depth };
    let norm_direction = match direction.trim().to_ascii_lowercase().as_str() {
        "" | "both" | "all" => "both",
        "callees" | "downstream" | "out" | "outbound" => "callees",
        "callers" | "upstream" | "in" | "inbound" => "callers",
        other => {
            return Err(DbMcpError::InvalidArgument(format!(
                "Invalid call graph direction '{}'; expected 'callees', 'callers', or 'both'",
                other
            )));
        }
    };

    let routine_objs: Vec<&CatalogObject> = objects
        .iter()
        .filter(|o| {
            matches!(
                o.object_type,
                CatalogObjectType::Function | CatalogObjectType::Procedure
            )
        })
        .collect();

    let table_objs: Vec<&CatalogObject> = objects
        .iter()
        .filter(|o| o.object_type == CatalogObjectType::Table)
        .collect();

    let known_routines: Vec<String> = routine_objs.iter().map(|r| r.qualified_name()).collect();
    let known_tables: Vec<String> = table_objs.iter().map(|t| t.qualified_name()).collect();

    let resolved_root = match root_procedure.map(str::trim).filter(|s| !s.is_empty()) {
        Some(root_raw) => {
            let root_obj =
                resolve_routine_object(&routine_objs, root_raw, None).ok_or_else(|| {
                    DbMcpError::InvalidArgument(format!(
                        "Procedure or function '{}' was not found in connection '{}'",
                        root_raw, connection
                    ))
                })?;
            Some(root_obj.qualified_name())
        }
        None => None,
    };

    // Map each routine qualified_name -> ProcedureNode and collect direct call kinds
    let mut nodes_map: BTreeMap<String, ProcedureNode> = BTreeMap::new();
    // (caller, callee) -> call_kind
    let mut direct_edges_map: BTreeMap<(String, String), String> = BTreeMap::new();

    for r_obj in &routine_objs {
        let qname = r_obj.qualified_name();
        nodes_map.insert(
            qname.clone(),
            ProcedureNode {
                schema: r_obj.schema.clone(),
                name: r_obj.name.clone(),
                qualified_name: qname,
                routine_kind: r_obj.object_type,
                definition: r_obj.definition.clone(),
                direct_callees: Vec::new(),
                direct_callers: Vec::new(),
                tables_read: Vec::new(),
                tables_written: Vec::new(),
            },
        );
    }

    for r_obj in &routine_objs {
        let caller_qname = r_obj.qualified_name();
        let def_sql = r_obj.definition.as_deref().unwrap_or("");
        let analysis = analyze_routine_definition(
            engine,
            &caller_qname,
            def_sql,
            &known_routines,
            &known_tables,
        );

        let mut callees_set = BTreeSet::new();
        for call_ref in analysis.calls {
            let callee_qname =
                resolve_routine_object(&routine_objs, &call_ref.callee, Some(&r_obj.schema))
                    .map(|target| target.qualified_name())
                    .unwrap_or_else(|| call_ref.callee.clone());

            callees_set.insert(callee_qname.clone());
            direct_edges_map.insert(
                (caller_qname.clone(), callee_qname.clone()),
                call_ref.call_kind,
            );

            // Ensure external/unregistered callee still has a stub node if referenced
            nodes_map.entry(callee_qname.clone()).or_insert_with(|| {
                let (schema, name) = callee_qname
                    .rsplit_once('.')
                    .unwrap_or(("", callee_qname.as_str()));
                ProcedureNode {
                    schema: schema.to_owned(),
                    name: name.to_owned(),
                    qualified_name: callee_qname,
                    routine_kind: CatalogObjectType::Procedure,
                    definition: None,
                    direct_callees: Vec::new(),
                    direct_callers: Vec::new(),
                    tables_read: Vec::new(),
                    tables_written: Vec::new(),
                }
            });
        }

        if let Some(node) = nodes_map.get_mut(&caller_qname) {
            node.direct_callees = callees_set.into_iter().collect();
            node.tables_read = analysis.tables_read;
            node.tables_written = analysis.tables_written;
        }
    }

    // Populate direct_callers from direct_edges_map
    for (caller, callee) in direct_edges_map.keys() {
        if let Some(callee_node) = nodes_map.get_mut(callee) {
            if !callee_node.direct_callers.contains(caller) {
                callee_node.direct_callers.push(caller.clone());
                callee_node.direct_callers.sort();
            }
        }
    }

    // Filter nodes and compute edges according to `resolved_root` and `norm_direction`
    let (included_node_names, edges) = if let Some(ref root_qname) = resolved_root {
        let mut included = BTreeSet::new();
        let mut collected_edges = BTreeMap::<(String, String), ProcedureCallEdge>::new();
        included.insert(root_qname.clone());

        if norm_direction == "callees" || norm_direction == "both" {
            let mut queue: VecDeque<(String, usize)> = VecDeque::new();
            let mut visited = BTreeSet::new();
            visited.insert(root_qname.clone());
            queue.push_back((root_qname.clone(), 0));

            while let Some((curr, depth)) = queue.pop_front() {
                if depth >= depth_limit {
                    continue;
                }
                if let Some(node) = nodes_map.get(&curr) {
                    for callee in &node.direct_callees {
                        let call_kind = direct_edges_map
                            .get(&(curr.clone(), callee.clone()))
                            .cloned()
                            .unwrap_or_else(|| "CALL".to_string());
                        collected_edges
                            .entry((curr.clone(), callee.clone()))
                            .or_insert(ProcedureCallEdge {
                                caller: curr.clone(),
                                callee: callee.clone(),
                                call_kind,
                                depth: depth + 1,
                            });
                        included.insert(callee.clone());
                        if visited.insert(callee.clone()) {
                            queue.push_back((callee.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        if norm_direction == "callers" || norm_direction == "both" {
            let mut queue: VecDeque<(String, usize)> = VecDeque::new();
            let mut visited = BTreeSet::new();
            visited.insert(root_qname.clone());
            queue.push_back((root_qname.clone(), 0));

            while let Some((curr, depth)) = queue.pop_front() {
                if depth >= depth_limit {
                    continue;
                }
                if let Some(node) = nodes_map.get(&curr) {
                    for caller in &node.direct_callers {
                        let call_kind = direct_edges_map
                            .get(&(caller.clone(), curr.clone()))
                            .cloned()
                            .unwrap_or_else(|| "CALL".to_string());
                        collected_edges
                            .entry((caller.clone(), curr.clone()))
                            .or_insert(ProcedureCallEdge {
                                caller: caller.clone(),
                                callee: curr.clone(),
                                call_kind,
                                depth: depth + 1,
                            });
                        included.insert(caller.clone());
                        if visited.insert(caller.clone()) {
                            queue.push_back((caller.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        let mut edge_list: Vec<ProcedureCallEdge> = collected_edges.into_values().collect();
        edge_list.sort_by(|a, b| {
            a.depth
                .cmp(&b.depth)
                .then_with(|| a.caller.cmp(&b.caller))
                .then_with(|| a.callee.cmp(&b.callee))
        });
        (included, edge_list)
    } else {
        let included: BTreeSet<String> = nodes_map.keys().cloned().collect();
        let mut edge_list: Vec<ProcedureCallEdge> = direct_edges_map
            .iter()
            .map(|((caller, callee), call_kind)| ProcedureCallEdge {
                caller: caller.clone(),
                callee: callee.clone(),
                call_kind: call_kind.clone(),
                depth: 1,
            })
            .collect();
        edge_list.sort_by(|a, b| {
            a.caller
                .cmp(&b.caller)
                .then_with(|| a.callee.cmp(&b.callee))
        });
        (included, edge_list)
    };

    let nodes: Vec<ProcedureNode> = included_node_names
        .iter()
        .filter_map(|name| nodes_map.get(name).cloned())
        .collect();

    let (call_chains, cycles) = compute_call_chains_and_cycles(
        &nodes_map,
        &included_node_names,
        resolved_root.as_deref(),
        norm_direction,
        depth_limit,
    );
    let has_cycles = !cycles.is_empty();

    let mermaid_diagram = render_procedure_call_graph_mermaid(&nodes, &edges);

    Ok(ProcedureCallGraphReport {
        connection: connection.to_string(),
        root_procedure: resolved_root,
        direction: norm_direction.to_string(),
        max_depth: depth_limit,
        nodes,
        edges,
        call_chains,
        cycles,
        has_cycles,
        mermaid_diagram,
    })
}

fn compute_call_chains_and_cycles(
    nodes_map: &BTreeMap<String, ProcedureNode>,
    included_nodes: &BTreeSet<String>,
    root_procedure: Option<&str>,
    direction: &str,
    max_depth: usize,
) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let mut call_chains: Vec<Vec<String>> = Vec::new();
    let mut cycles_set: BTreeSet<Vec<String>> = BTreeSet::new();

    // Determine start nodes for downstream path & cycle exploration
    let start_nodes: Vec<String> = if let Some(root) = root_procedure {
        if direction == "callers" {
            // For upstream-only queries, start from the furthest discovered upstream callers
            let mut upstream_starts: Vec<String> = included_nodes
                .iter()
                .filter(|n| {
                    nodes_map
                        .get(*n)
                        .map(|node| {
                            node.direct_callers
                                .iter()
                                .all(|c| !included_nodes.contains(c) || c == *n)
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            if upstream_starts.is_empty() {
                upstream_starts.push(root.to_string());
            }
            upstream_starts
        } else {
            vec![root.to_string()]
        }
    } else {
        // Entry points with no callers, plus any node that participates in calls
        let mut roots: Vec<String> = included_nodes
            .iter()
            .filter(|n| {
                nodes_map
                    .get(*n)
                    .map(|node| node.direct_callers.is_empty() && !node.direct_callees.is_empty())
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if roots.is_empty() {
            roots = included_nodes.iter().cloned().collect();
        }
        roots
    };

    for start in &start_nodes {
        let mut stack: Vec<(String, Vec<String>)> = vec![(start.clone(), vec![start.clone()])];
        while let Some((curr, path)) = stack.pop() {
            let callees: Vec<String> = nodes_map
                .get(&curr)
                .map(|n| {
                    n.direct_callees
                        .iter()
                        .filter(|c| included_nodes.contains(*c))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            if callees.is_empty() || path.len() > max_depth {
                if path.len() > 1 {
                    call_chains.push(path);
                }
                continue;
            }

            let mut extended = false;
            for callee in callees.into_iter().rev() {
                if let Some(pos) = path.iter().position(|p| p == &callee) {
                    let mut cycle: Vec<String> = path[pos..].to_vec();
                    cycle.push(callee.clone());
                    cycles_set.insert(canonicalize_cycle(&cycle));
                    let mut cyc_path = path.clone();
                    cyc_path.push(callee);
                    call_chains.push(cyc_path);
                } else if path.len() <= max_depth {
                    let mut next_path = path.clone();
                    next_path.push(callee.clone());
                    stack.push((callee, next_path));
                    extended = true;
                }
            }

            if !extended && path.len() > 1 {
                call_chains.push(path);
            }
        }
    }

    // Also run cycle detection across all included nodes so cycles in disconnected components are caught
    for node_name in included_nodes {
        let mut stack: Vec<(String, Vec<String>)> =
            vec![(node_name.clone(), vec![node_name.clone()])];
        while let Some((curr, path)) = stack.pop() {
            if path.len() > max_depth + 1 {
                continue;
            }
            if let Some(node) = nodes_map.get(&curr) {
                for callee in &node.direct_callees {
                    if !included_nodes.contains(callee) {
                        continue;
                    }
                    if callee == node_name {
                        let mut cycle = path.clone();
                        cycle.push(callee.clone());
                        cycles_set.insert(canonicalize_cycle(&cycle));
                    } else if !path.contains(callee) {
                        let mut next_path = path.clone();
                        next_path.push(callee.clone());
                        stack.push((callee.clone(), next_path));
                    }
                }
            }
        }
    }

    call_chains.sort();
    call_chains.dedup();

    let cycles: Vec<Vec<String>> = cycles_set.into_iter().collect();
    (call_chains, cycles)
}

/// Rotate a closed cycle `[A, B, C, A]` so its lexicographically smallest node comes first.
fn canonicalize_cycle(cycle: &[String]) -> Vec<String> {
    if cycle.len() <= 2 {
        return cycle.to_vec();
    }
    let body = &cycle[..cycle.len() - 1];
    let min_idx = body
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.cmp(b))
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let mut rotated = Vec::with_capacity(cycle.len());
    rotated.extend_from_slice(&body[min_idx..]);
    rotated.extend_from_slice(&body[..min_idx]);
    rotated.push(rotated[0].clone());
    rotated
}

fn render_procedure_call_graph_mermaid(
    nodes: &[ProcedureNode],
    edges: &[ProcedureCallEdge],
) -> String {
    let mut lines = vec!["flowchart TD".to_string()];
    let mut declared_nodes = BTreeSet::new();
    let mut declared_edges = BTreeSet::new();

    for node in nodes {
        let id = sanitize_mermaid_id("proc", &node.qualified_name);
        if declared_nodes.insert(id.clone()) {
            lines.push(format!(
                "    {id}[\"{} ({})\"]",
                node.qualified_name,
                node.routine_kind.as_str()
            ));
        }
        for tbl_read in &node.tables_read {
            let tbl_id = sanitize_mermaid_id("tbl", tbl_read);
            if declared_nodes.insert(tbl_id.clone()) {
                lines.push(format!("    {tbl_id}[(\"{tbl_read}\")]"));
            }
            let edge_line = format!("    {id} -.->|\"read\"| {tbl_id}");
            if declared_edges.insert(edge_line.clone()) {
                lines.push(edge_line);
            }
        }
        for tbl_written in &node.tables_written {
            let tbl_id = sanitize_mermaid_id("tbl", tbl_written);
            if declared_nodes.insert(tbl_id.clone()) {
                lines.push(format!("    {tbl_id}[(\"{tbl_written}\")]"));
            }
            let edge_line = format!("    {id} ==>|\"write\"| {tbl_id}");
            if declared_edges.insert(edge_line.clone()) {
                lines.push(edge_line);
            }
        }
    }

    for edge in edges {
        let caller_id = sanitize_mermaid_id("proc", &edge.caller);
        let callee_id = sanitize_mermaid_id("proc", &edge.callee);
        let edge_line = format!("    {caller_id} -->|\"{}\"| {callee_id}", edge.call_kind);
        if declared_edges.insert(edge_line.clone()) {
            lines.push(edge_line);
        }
    }

    lines.join("\n")
}

/// Discover catalog objects via `DatabaseAdapter` and run `build_procedure_call_graph`.
pub async fn build_procedure_call_graph_via_adapter(
    adapter: &dyn DatabaseAdapter,
    connection: &str,
    root_procedure: Option<&str>,
    direction: &str,
    max_depth: usize,
) -> DbMcpResult<ProcedureCallGraphReport> {
    let request = CatalogRequest {
        connection: connection.to_string(),
        schema_pattern: None,
        name_pattern: None,
        object_types: Vec::new(),
        detail_level: CatalogDetailLevel::Full,
        limit: 10_000,
        offset: 0,
    };
    let response = adapter.discover(request).await?;
    let engine = adapter.capabilities().engine;
    build_procedure_call_graph(
        &response.objects,
        engine,
        connection,
        root_procedure,
        direction,
        max_depth,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_mcp_core::{ColumnSpec, ForeignKeySpec};

    fn sample_lineage_catalog() -> Vec<CatalogObject> {
        vec![
            CatalogObject {
                schema: "public".to_string(),
                name: "users".to_string(),
                object_type: CatalogObjectType::Table,
                comment: None,
                estimated_rows: Some(100),
                size_bytes: None,
                columns: vec![ColumnSpec {
                    name: "id".to_string(),
                    data_type: "integer".to_string(),
                    nullable: false,
                    default_value: None,
                    is_primary_key: true,
                    comment: None,
                    ordinal_position: 1,
                }],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some("CREATE TABLE public.users (id INTEGER PRIMARY KEY);".to_string()),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "orders".to_string(),
                object_type: CatalogObjectType::Table,
                comment: None,
                estimated_rows: Some(500),
                size_bytes: None,
                columns: vec![
                    ColumnSpec {
                        name: "id".to_string(),
                        data_type: "integer".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: true,
                        comment: None,
                        ordinal_position: 1,
                    },
                    ColumnSpec {
                        name: "user_id".to_string(),
                        data_type: "integer".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 2,
                    },
                ],
                indexes: vec![],
                foreign_keys: vec![ForeignKeySpec {
                    name: Some("fk_orders_user_id".to_string()),
                    columns: vec!["user_id".to_string()],
                    referenced_table: "public.users".to_string(),
                    referenced_columns: vec!["id".to_string()],
                    on_delete: Some("CASCADE".to_string()),
                    on_update: None,
                }],
                definition: Some(
                    "CREATE TABLE public.orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES public.users(id));"
                        .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "order_items".to_string(),
                object_type: CatalogObjectType::Table,
                comment: None,
                estimated_rows: Some(1500),
                size_bytes: None,
                columns: vec![
                    ColumnSpec {
                        name: "id".to_string(),
                        data_type: "integer".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: true,
                        comment: None,
                        ordinal_position: 1,
                    },
                    ColumnSpec {
                        name: "order_id".to_string(),
                        data_type: "integer".to_string(),
                        nullable: false,
                        default_value: None,
                        is_primary_key: false,
                        comment: None,
                        ordinal_position: 2,
                    },
                ],
                indexes: vec![],
                foreign_keys: vec![ForeignKeySpec {
                    name: Some("fk_order_items_order_id".to_string()),
                    columns: vec!["order_id".to_string()],
                    referenced_table: "orders".to_string(),
                    referenced_columns: vec!["id".to_string()],
                    on_delete: Some("CASCADE".to_string()),
                    on_update: None,
                }],
                definition: None,
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "audit_logs".to_string(),
                object_type: CatalogObjectType::Table,
                comment: None,
                estimated_rows: Some(2000),
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: None,
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "order_summary_view".to_string(),
                object_type: CatalogObjectType::View,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    "CREATE VIEW public.order_summary_view AS SELECT o.id, u.id AS user_id FROM public.orders o JOIN public.users u ON o.user_id = u.id;"
                        .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "trg_orders_audit".to_string(),
                object_type: CatalogObjectType::Trigger,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    "CREATE TRIGGER trg_orders_audit AFTER INSERT OR UPDATE ON public.orders FOR EACH ROW EXECUTE FUNCTION public.record_order_audit();"
                        .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "checkout_order".to_string(),
                object_type: CatalogObjectType::Procedure,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    r#"
                    CREATE OR REPLACE PROCEDURE public.checkout_order(p_order_id INT)
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        CALL public.reserve_inventory(p_order_id);
                        UPDATE public.orders SET status = 'completed' WHERE id = p_order_id;
                    END;
                    $$;
                    "#
                    .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "reserve_inventory".to_string(),
                object_type: CatalogObjectType::Procedure,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    r#"
                    CREATE OR REPLACE PROCEDURE public.reserve_inventory(p_order_id INT)
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        SELECT * FROM public.order_items WHERE order_id = p_order_id;
                        PERFORM public.record_order_audit(p_order_id);
                    END;
                    $$;
                    "#
                    .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "record_order_audit".to_string(),
                object_type: CatalogObjectType::Function,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    r#"
                    CREATE OR REPLACE FUNCTION public.record_order_audit(p_order_id INT)
                    RETURNS VOID LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        INSERT INTO public.audit_logs (order_id)
                        SELECT id FROM public.orders WHERE id = p_order_id;
                    END;
                    $$;
                    "#
                    .to_string(),
                ),
            },
        ]
    }

    #[test]
    fn test_trace_table_dependencies_fks_dependents_and_multihop_join_path() {
        let catalog = sample_lineage_catalog();

        // 1. Inspect `orders` direct FKs and dependent objects
        let orders_report = trace_table_dependencies(
            &catalog,
            DatabaseEngine::Postgres,
            "pg-dev",
            "orders",
            None,
            3,
        )
        .unwrap();

        assert_eq!(orders_report.table_name, "public.orders");
        assert_eq!(orders_report.outbound_foreign_keys.len(), 1);
        assert_eq!(
            orders_report.outbound_foreign_keys[0].to_table,
            "public.users"
        );
        assert_eq!(orders_report.inbound_foreign_keys.len(), 1);
        assert_eq!(
            orders_report.inbound_foreign_keys[0].from_table,
            "public.order_items"
        );

        // Dependent view, trigger, procedure, and function
        assert!(orders_report
            .dependent_objects
            .iter()
            .any(|d| d.qualified_name == "public.order_summary_view"
                && d.object_type == CatalogObjectType::View
                && d.access_mode == "read"));
        assert!(orders_report
            .dependent_objects
            .iter()
            .any(|d| d.qualified_name == "public.trg_orders_audit"
                && d.object_type == CatalogObjectType::Trigger));
        assert!(orders_report
            .dependent_objects
            .iter()
            .any(|d| d.qualified_name == "public.checkout_order"
                && d.object_type == CatalogObjectType::Procedure
                && d.access_mode == "write"));
        assert!(orders_report
            .dependent_objects
            .iter()
            .any(|d| d.qualified_name == "public.record_order_audit"
                && d.object_type == CatalogObjectType::Function
                && d.access_mode == "read"));

        // 2. Multi-hop join path from `users` -> `orders` -> `order_items`
        let join_report = trace_table_dependencies(
            &catalog,
            DatabaseEngine::Postgres,
            "pg-dev",
            "users",
            Some("order_items"),
            3,
        )
        .unwrap();

        let join_path = join_report.join_path.expect("expected shortest join path");
        assert_eq!(join_path.source_table, "public.users");
        assert_eq!(join_path.target_table, "public.order_items");
        assert_eq!(join_path.hops.len(), 2);
        assert_eq!(
            join_path.synthesized_join_sql,
            "SELECT * FROM public.users JOIN public.orders ON public.users.id = public.orders.user_id JOIN public.order_items ON public.orders.id = public.order_items.order_id"
        );
        assert!(join_report.mermaid_diagram.contains("flowchart LR"));
    }

    #[test]
    fn test_build_procedure_call_graph_chains_and_upstream_callers() {
        let catalog = sample_lineage_catalog();

        // Downstream call graph from `checkout_order`
        let downstream = build_procedure_call_graph(
            &catalog,
            DatabaseEngine::Postgres,
            "pg-dev",
            Some("checkout_order"),
            "callees",
            5,
        )
        .unwrap();

        assert_eq!(
            downstream.root_procedure.as_deref(),
            Some("public.checkout_order")
        );
        assert_eq!(downstream.nodes.len(), 3);
        assert_eq!(downstream.edges.len(), 2);
        assert_eq!(
            downstream.call_chains,
            vec![vec![
                "public.checkout_order".to_string(),
                "public.reserve_inventory".to_string(),
                "public.record_order_audit".to_string(),
            ]]
        );
        assert!(!downstream.has_cycles);
        assert!(downstream.mermaid_diagram.contains("flowchart TD"));

        // Upstream callers of `record_order_audit`
        let upstream = build_procedure_call_graph(
            &catalog,
            DatabaseEngine::Postgres,
            "pg-dev",
            Some("record_order_audit"),
            "callers",
            5,
        )
        .unwrap();

        assert_eq!(upstream.nodes.len(), 3);
        assert!(upstream
            .edges
            .iter()
            .any(|e| e.caller == "public.reserve_inventory"
                && e.callee == "public.record_order_audit"));
        assert!(
            upstream
                .edges
                .iter()
                .any(|e| e.caller == "public.checkout_order"
                    && e.callee == "public.reserve_inventory")
        );
    }

    #[test]
    fn test_procedure_call_graph_cycle_detection() {
        let cyclic_catalog = vec![
            CatalogObject {
                schema: "public".to_string(),
                name: "proc_alpha".to_string(),
                object_type: CatalogObjectType::Procedure,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    "CREATE PROCEDURE public.proc_alpha() AS $$ BEGIN CALL public.proc_beta(); END; $$ LANGUAGE plpgsql;"
                        .to_string(),
                ),
            },
            CatalogObject {
                schema: "public".to_string(),
                name: "proc_beta".to_string(),
                object_type: CatalogObjectType::Procedure,
                comment: None,
                estimated_rows: None,
                size_bytes: None,
                columns: vec![],
                indexes: vec![],
                foreign_keys: vec![],
                definition: Some(
                    "CREATE PROCEDURE public.proc_beta() AS $$ BEGIN CALL public.proc_alpha(); END; $$ LANGUAGE plpgsql;"
                        .to_string(),
                ),
            },
        ];

        let report = build_procedure_call_graph(
            &cyclic_catalog,
            DatabaseEngine::Postgres,
            "pg-dev",
            None,
            "both",
            5,
        )
        .unwrap();

        assert!(report.has_cycles);
        assert_eq!(
            report.cycles,
            vec![vec![
                "public.proc_alpha".to_string(),
                "public.proc_beta".to_string(),
                "public.proc_alpha".to_string(),
            ]]
        );
    }
}
