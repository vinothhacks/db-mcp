//! Deterministic candidate extraction from the (policy-filtered) catalog.
//!
//! Output is always `Discovered` candidates. Nothing produced here can generate SQL until a
//! human reviewer certifies and publishes it.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use db_mcp_catalog::build_procedure_call_graph;
use db_mcp_core::{CatalogObject, CatalogObjectType, ColumnSpec, DatabaseEngine};
use regex::Regex;
use serde::Serialize;

use crate::model::{
    base_table_name, slug, Aggregation, Cardinality, ColumnDependency, Definition, DefinitionBody,
    DefinitionFlags, DefinitionKind, DefinitionStatus, Evidence, EvidenceStrength,
    RelationshipSource,
};

/// Inputs that scope one discovery run.
#[derive(Debug, Clone)]
pub struct DiscoveryScope {
    pub tenant_id: String,
    pub connection: String,
    pub engine: DatabaseEngine,
    pub schema_fingerprint: String,
    /// Principal recorded as `proposed_by` (it can never review these candidates itself).
    pub principal: String,
    /// Configured sensitive column names (`col` or `table.col`).
    pub sensitive_columns: Vec<String>,
    pub include_inferred_joins: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiscoveryReport {
    pub candidates: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub warnings: Vec<String>,
}

/// Humanize `order_items` -> `order items`.
pub fn humanize(identifier: &str) -> String {
    crate::retrieval::tokenize_raw(identifier).join(" ")
}

/// Naive English singularization of the last word.
pub fn singular(phrase: &str) -> String {
    let mut words: Vec<String> = phrase.split_whitespace().map(ToOwned::to_owned).collect();
    if let Some(last) = words.last_mut() {
        let w = last.clone();
        *last = if w.len() > 4 && w.ends_with("ies") {
            format!("{}y", &w[..w.len() - 3])
        } else if w.len() > 4 && (w.ends_with("sses") || w.ends_with("ches") || w.ends_with("shes") || w.ends_with("xes")) {
            w[..w.len() - 2].to_string()
        } else if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") && !w.ends_with("us") {
            w[..w.len() - 1].to_string()
        } else {
            w
        };
    }
    words.join(" ")
}

fn is_numeric_type(data_type: &str) -> bool {
    let t = data_type.to_ascii_lowercase();
    ["int", "real", "numeric", "decimal", "float", "double", "money", "number", "bigint", "smallint"]
        .iter()
        .any(|k| t.contains(k))
}

fn type_family(data_type: &str) -> &'static str {
    let t = data_type.to_ascii_lowercase();
    if is_numeric_type(&t) {
        "number"
    } else if t.contains("char") || t.contains("text") || t.contains("string") || t.contains("uuid") {
        "text"
    } else if t.contains("date") || t.contains("time") {
        "temporal"
    } else if t.contains("bool") {
        "bool"
    } else {
        "other"
    }
}

/// True when `a` and `b` can be compared in a join predicate.
pub fn types_compatible(a: &str, b: &str) -> bool {
    let (fa, fb) = (type_family(a), type_family(b));
    fa == fb || fa == "other" || fb == "other"
}

pub fn is_sensitive(table: &str, column: &str, sensitive: &[String]) -> bool {
    let t = base_table_name(table);
    let c = column.to_ascii_lowercase();
    sensitive.iter().any(|s| {
        let s = s.trim().to_ascii_lowercase();
        s == c || s == format!("{t}.{c}") || s.ends_with(&format!(".{t}.{c}"))
    })
}

fn measure_regex() -> Regex {
    Regex::new(r"(?i)(amount|total|price|cost|qty|quantity|count|cents|value|revenue|balance|fee|weight|volume|score)")
        .expect("static regex")
}

#[allow(clippy::too_many_arguments)]
fn candidate(
    scope: &DiscoveryScope,
    def_id: String,
    name: String,
    synonyms: Vec<String>,
    description: Option<String>,
    body: DefinitionBody,
    depends_on: Vec<ColumnDependency>,
    evidence: Vec<Evidence>,
    strength: EvidenceStrength,
    flags: DefinitionFlags,
) -> Definition {
    let now = Utc::now();
    let mut syn: Vec<String> = synonyms
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(&name))
        .collect();
    syn.sort();
    syn.dedup();
    let mut def = Definition {
        def_id,
        version: 1,
        tenant_id: scope.tenant_id.clone(),
        connection: scope.connection.clone(),
        kind: body.kind(),
        name,
        synonyms: syn,
        description,
        body,
        depends_on,
        evidence,
        strength,
        status: DefinitionStatus::Discovered,
        flags,
        content_hash: String::new(),
        schema_fingerprint: scope.schema_fingerprint.clone(),
        proposed_by: scope.principal.clone(),
        created_at: now,
        updated_at: now,
    };
    def.content_hash = def.compute_content_hash();
    def
}

fn col_dep(table: &str, col: &ColumnSpec) -> ColumnDependency {
    ColumnDependency {
        table: table.to_string(),
        column: Some(col.name.clone()),
        data_type: Some(col.data_type.clone()),
    }
}

/// Resolve a referenced table name (possibly unqualified) to a catalog table's qualified name.
fn resolve_table<'a>(tables: &[&'a CatalogObject], raw: &str, preferred_schema: &str) -> Option<&'a CatalogObject> {
    let raw_l = raw.trim_matches('"').to_ascii_lowercase();
    tables
        .iter()
        .find(|t| t.qualified_name().eq_ignore_ascii_case(&raw_l))
        .or_else(|| {
            tables
                .iter()
                .find(|t| t.schema.eq_ignore_ascii_case(preferred_schema) && t.name.eq_ignore_ascii_case(&base_table_name(&raw_l)))
        })
        .or_else(|| tables.iter().find(|t| t.name.eq_ignore_ascii_case(&base_table_name(&raw_l))))
        .copied()
}

/// Build candidate definitions from catalog objects that already passed the restricted filter.
pub fn discover(objects: &[CatalogObject], scope: &DiscoveryScope) -> (Vec<Definition>, DiscoveryReport) {
    let mut report = DiscoveryReport::default();
    let tables: Vec<&CatalogObject> = objects
        .iter()
        .filter(|o| matches!(o.object_type, CatalogObjectType::Table | CatalogObjectType::View | CatalogObjectType::MaterializedView))
        .collect();
    let measure_re = measure_regex();
    let mut out: Vec<Definition> = Vec::new();

    // Routine touchpoints as evidence (never as definitions on their own).
    let mut routine_evidence: BTreeMap<String, Vec<Evidence>> = BTreeMap::new();
    if objects
        .iter()
        .any(|o| matches!(o.object_type, CatalogObjectType::Function | CatalogObjectType::Procedure))
    {
        match build_procedure_call_graph(objects, scope.engine, &scope.connection, None, "both", 5) {
            Ok(graph) => {
                for node in graph.nodes {
                    for (tables_touched, mode) in [(&node.tables_read, "reads"), (&node.tables_written, "writes")] {
                        for t in tables_touched {
                            routine_evidence.entry(base_table_name(t)).or_default().push(Evidence {
                                source_kind: "routine".to_string(),
                                reference: node.qualified_name.clone(),
                                detail: Some(format!("{} {mode} this table (static analysis; dynamic SQL not covered)", node.qualified_name)),
                            });
                        }
                    }
                }
            }
            Err(e) => report.warnings.push(format!("routine analysis skipped: {e}")),
        }
    }

    for table in &tables {
        let qualified = table.qualified_name();
        let human = humanize(&table.name);
        let single = singular(&human);
        let is_view = !matches!(table.object_type, CatalogObjectType::Table);
        let mut evidence = vec![Evidence {
            source_kind: table.object_type.as_str().to_string(),
            reference: qualified.clone(),
            detail: table.comment.as_ref().map(|c| format!("catalog comment (untrusted): {c}")),
        }];
        if let Some(extra) = routine_evidence.get(&base_table_name(&table.name)) {
            evidence.extend(extra.iter().cloned());
        }
        evidence.sort();
        evidence.dedup();

        // Entity
        out.push(candidate(
            scope,
            format!("entity:{}", qualified.to_ascii_lowercase()),
            single.clone(),
            vec![table.name.clone(), human.clone()],
            table.comment.clone(),
            DefinitionBody::Entity { table: qualified.clone() },
            vec![ColumnDependency { table: qualified.clone(), column: None, data_type: None }],
            evidence,
            EvidenceStrength::Declared,
            DefinitionFlags::default(),
        ));

        // Row count metric (views included; grain = one row of the object)
        out.push(candidate(
            scope,
            format!("metric:{}.count", qualified.to_ascii_lowercase()),
            format!("{single} count"),
            vec![format!("number of {human}"), format!("count of {human}"), format!("{human} count")],
            Some(format!("COUNT(*) over {qualified}; grain: one row per {single}")),
            DefinitionBody::Metric {
                base_table: qualified.clone(),
                aggregation: Aggregation::Count,
                column: None,
                default_filters: Vec::new(),
                unit: Some("rows".to_string()),
                grain: Some(single.clone()),
            },
            vec![ColumnDependency { table: qualified.clone(), column: None, data_type: None }],
            vec![Evidence { source_kind: "catalog".to_string(), reference: qualified.clone(), detail: None }],
            EvidenceStrength::Declared,
            DefinitionFlags::default(),
        ));

        let fk_columns: BTreeSet<String> = table
            .foreign_keys
            .iter()
            .flat_map(|fk| fk.columns.iter().map(|c| c.to_ascii_lowercase()))
            .collect();

        for col in &table.columns {
            let sensitive = is_sensitive(&qualified, &col.name, &scope.sensitive_columns);
            let col_human = humanize(&col.name);
            // Attribute
            out.push(candidate(
                scope,
                format!("attribute:{}.{}", qualified.to_ascii_lowercase(), col.name.to_ascii_lowercase()),
                format!("{single} {col_human}"),
                vec![col_human.clone(), format!("{}.{}", table.name, col.name)],
                col.comment.clone(),
                DefinitionBody::Attribute {
                    table: qualified.clone(),
                    column: col.name.clone(),
                    unit: if col.name.to_ascii_lowercase().ends_with("_cents") { Some("cents".to_string()) } else { None },
                },
                vec![col_dep(&qualified, col)],
                vec![Evidence {
                    source_kind: "column".to_string(),
                    reference: format!("{qualified}.{}", col.name),
                    detail: Some(format!("type {}, nullable {}", col.data_type, col.nullable)),
                }],
                EvidenceStrength::Declared,
                DefinitionFlags { sensitive, ..Default::default() },
            ));

            // Measure (SUM) candidates
            let lname = col.name.to_ascii_lowercase();
            if !sensitive
                && !is_view
                && is_numeric_type(&col.data_type)
                && !col.is_primary_key
                && !lname.ends_with("_id")
                && !fk_columns.contains(&lname)
                && measure_re.is_match(&col.name)
            {
                out.push(candidate(
                    scope,
                    format!("metric:{}.{}.sum", qualified.to_ascii_lowercase(), lname),
                    format!("{single} {col_human}"),
                    vec![format!("total {col_human}"), format!("sum of {col_human}"), col_human.clone()],
                    Some(format!("SUM({}) over {qualified}; grain: {single}", col.name)),
                    DefinitionBody::Metric {
                        base_table: qualified.clone(),
                        aggregation: Aggregation::Sum,
                        column: Some(col.name.clone()),
                        default_filters: Vec::new(),
                        unit: if lname.ends_with("_cents") { Some("cents".to_string()) } else { None },
                        grain: Some(single.clone()),
                    },
                    vec![col_dep(&qualified, col)],
                    vec![Evidence { source_kind: "column".to_string(), reference: format!("{qualified}.{}", col.name), detail: Some("numeric measure name pattern".to_string()) }],
                    EvidenceStrength::Naming,
                    DefinitionFlags::default(),
                ));
            }
        }

        // Declared FK relationships
        for fk in &table.foreign_keys {
            let Some(target) = resolve_table(&tables, &fk.referenced_table, &table.schema) else {
                report.warnings.push(format!("FK on {qualified} references unknown or hidden table {}", fk.referenced_table));
                continue;
            };
            let to_q = target.qualified_name();
            let to_cols: Vec<String> = if fk.referenced_columns.is_empty() {
                target.columns.iter().filter(|c| c.is_primary_key).map(|c| c.name.clone()).collect()
            } else {
                fk.referenced_columns.clone()
            };
            if to_cols.len() != fk.columns.len() || to_cols.is_empty() {
                report.warnings.push(format!("FK on {qualified} -> {to_q} has unresolved column pairs"));
                continue;
            }
            let pairs: Vec<(String, String)> = fk.columns.iter().cloned().zip(to_cols.iter().cloned()).collect();
            let mut deps: Vec<ColumnDependency> = Vec::new();
            for (fc, tc) in &pairs {
                if let Some(c) = table.columns.iter().find(|c| c.name.eq_ignore_ascii_case(fc)) {
                    deps.push(col_dep(&qualified, c));
                }
                if let Some(c) = target.columns.iter().find(|c| c.name.eq_ignore_ascii_case(tc)) {
                    deps.push(col_dep(&to_q, c));
                }
            }
            let from_h = singular(&humanize(&table.name));
            let to_h = singular(&humanize(&target.name));
            out.push(candidate(
                scope,
                format!(
                    "relationship:{}({})->{}",
                    qualified.to_ascii_lowercase(),
                    fk.columns.join(",").to_ascii_lowercase(),
                    to_q.to_ascii_lowercase()
                ),
                format!("{from_h} belongs to {to_h}"),
                vec![format!("{to_h} {}", humanize(&table.name)), format!("{from_h} {to_h}")],
                None,
                DefinitionBody::Relationship {
                    from_table: qualified.clone(),
                    to_table: to_q.clone(),
                    column_pairs: pairs,
                    cardinality: Cardinality::ManyToOne,
                    source: RelationshipSource::DeclaredFk,
                },
                deps,
                vec![Evidence {
                    source_kind: "foreign_key".to_string(),
                    reference: fk.name.clone().unwrap_or_else(|| format!("{qualified}.fk")),
                    detail: Some("declared constraint: proves structure, not business meaning".to_string()),
                }],
                EvidenceStrength::Declared,
                DefinitionFlags::default(),
            ));
        }

        // Inferred `<x>_id` joins (never auto-certified)
        if scope.include_inferred_joins && !is_view {
            for col in &table.columns {
                let lname = col.name.to_ascii_lowercase();
                if col.is_primary_key || fk_columns.contains(&lname) || !lname.ends_with("_id") || lname.len() <= 3 {
                    continue;
                }
                let stem = &lname[..lname.len() - 3];
                let matches: Vec<&&CatalogObject> = tables
                    .iter()
                    .filter(|t| {
                        let n = t.name.to_ascii_lowercase();
                        (n == stem || n == format!("{stem}s") || n == format!("{stem}es") || singular(&n) == stem)
                            && matches!(t.object_type, CatalogObjectType::Table)
                            && t.qualified_name() != qualified
                    })
                    .collect();
                if matches.len() != 1 {
                    continue;
                }
                let target = matches[0];
                let pks: Vec<&ColumnSpec> = target.columns.iter().filter(|c| c.is_primary_key).collect();
                if pks.len() != 1 || !types_compatible(&col.data_type, &pks[0].data_type) {
                    continue;
                }
                let to_q = target.qualified_name();
                out.push(candidate(
                    scope,
                    format!("relationship:{}({})->{}", qualified.to_ascii_lowercase(), lname, to_q.to_ascii_lowercase()),
                    format!("{} references {} (inferred)", singular(&humanize(&table.name)), singular(&humanize(&target.name))),
                    Vec::new(),
                    Some("Inferred from column naming and type compatibility; no declared constraint. Requires domain review.".to_string()),
                    DefinitionBody::Relationship {
                        from_table: qualified.clone(),
                        to_table: to_q.clone(),
                        column_pairs: vec![(col.name.clone(), pks[0].name.clone())],
                        cardinality: Cardinality::ManyToOne,
                        source: RelationshipSource::Inferred,
                    },
                    vec![col_dep(&qualified, col), col_dep(&to_q, pks[0])],
                    vec![Evidence {
                        source_kind: "naming".to_string(),
                        reference: format!("{qualified}.{}", col.name),
                        detail: Some(format!("matches primary key {}.{} by name and type", to_q, pks[0].name)),
                    }],
                    EvidenceStrength::Naming,
                    DefinitionFlags { inferred: true, ..Default::default() },
                ));
            }
        }
    }

    // Flag same-label metrics as ambiguous.
    let mut label_counts: BTreeMap<String, usize> = BTreeMap::new();
    for d in out.iter().filter(|d| d.kind == DefinitionKind::Metric) {
        *label_counts.entry(slug(&d.name)).or_default() += 1;
    }
    for d in out.iter_mut().filter(|d| d.kind == DefinitionKind::Metric) {
        if label_counts.get(&slug(&d.name)).copied().unwrap_or(0) > 1 {
            d.flags.ambiguous = true;
            d.content_hash = d.compute_content_hash();
        }
    }

    report.candidates = out.len();
    for d in &out {
        *report.by_kind.entry(d.kind.as_str().to_string()).or_default() += 1;
    }
    (out, report)
}
