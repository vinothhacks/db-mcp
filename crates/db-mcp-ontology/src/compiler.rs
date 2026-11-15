//! Certified natural-language question -> typed, parameterized, validated SQL plan.
//!
//! Only definitions from the pinned published revision are used. The compiler never accepts
//! model-written SQL: it assembles statements from typed definition parts and then re-validates
//! the result with the dialect-aware SQL analyzer before anything can execute.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use db_mcp_core::{DatabaseEngine, SqlStatementClass};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::model::{
    base_table_name, sha256_hex, slug, Aggregation, Cardinality, Definition, DefinitionBody,
    DefinitionKind, FilterOp, OntologyRevision,
};
use crate::retrieval::{normalized_phrase, rank, tokenize, ScoredDefinition};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Answerable,
    NotAnswerable,
    Ambiguous,
    Stale,
}

#[derive(Debug, Clone, Serialize)]
pub struct UsedDefinition {
    pub def_id: String,
    pub version: u32,
    pub name: String,
    pub content_hash: String,
}

impl From<&Definition> for UsedDefinition {
    fn from(d: &Definition) -> Self {
        Self {
            def_id: d.def_id.clone(),
            version: d.version,
            name: d.name.clone(),
            content_hash: d.content_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateSummary {
    pub def_id: String,
    pub name: String,
    pub score: f64,
    pub status: String,
}

impl From<&ScoredDefinition> for CandidateSummary {
    fn from(s: &ScoredDefinition) -> Self {
        Self {
            def_id: s.definition.def_id.clone(),
            name: s.definition.name.clone(),
            score: s.score,
            status: s.definition.status.as_str().to_string(),
        }
    }
}

/// Result of planning. `sql`/`params`/`plan_hash` are present only when `status == answerable`.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticPlan {
    pub status: PlanStatus,
    pub question: String,
    pub question_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_schema_fingerprint: Option<String>,
    pub schema_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sql: Option<String>,
    pub params: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<UsedDefinition>,
    pub dimensions: Vec<UsedDefinition>,
    pub filters: Vec<UsedDefinition>,
    pub relationships: Vec<UsedDefinition>,
    pub tables: Vec<String>,
    pub missing: Vec<String>,
    pub candidates: Vec<CandidateSummary>,
    pub assumptions: Vec<String>,
    pub limitations: Vec<String>,
    /// `rule_based_calculation` for answerable plans: values follow certified definitions, they are
    /// not observations of causes.
    pub result_kind: String,
}

impl SemanticPlan {
    fn new(question: &str, revision: Option<&OntologyRevision>, fingerprint: &str) -> Self {
        Self {
            status: PlanStatus::NotAnswerable,
            question: question.to_string(),
            question_hash: sha256_hex(question.trim().to_ascii_lowercase().as_bytes()),
            revision_id: revision.map(|r| r.revision_id.clone()),
            revision_schema_fingerprint: revision.map(|r| r.schema_fingerprint.clone()),
            schema_fingerprint: fingerprint.to_string(),
            sql: None,
            params: Vec::new(),
            plan_hash: None,
            metric: None,
            dimensions: Vec::new(),
            filters: Vec::new(),
            relationships: Vec::new(),
            tables: Vec::new(),
            missing: Vec::new(),
            candidates: Vec::new(),
            assumptions: Vec::new(),
            limitations: Vec::new(),
            result_kind: "none".to_string(),
        }
    }

    fn refuse(mut self, status: PlanStatus, missing: impl Into<String>) -> Self {
        self.status = status;
        self.missing.push(missing.into());
        self.sql = None;
        self.params.clear();
        self.plan_hash = None;
        self
    }

    pub fn is_answerable(&self) -> bool {
        self.status == PlanStatus::Answerable
    }

    pub fn all_used(&self) -> Vec<&UsedDefinition> {
        self.metric
            .iter()
            .chain(self.dimensions.iter())
            .chain(self.filters.iter())
            .chain(self.relationships.iter())
            .collect()
    }
}

/// Inputs for one planning call.
pub struct PlanRequest<'a> {
    pub question: &'a str,
    pub engine: DatabaseEngine,
    pub max_rows: usize,
    pub revision: Option<&'a OntologyRevision>,
    /// Published definitions of the pinned revision (already certification-verified).
    pub published: &'a [Definition],
    /// Definitions of the revision that drifted out of validity.
    pub stale: &'a [Definition],
    pub schema_fingerprint: &'a str,
}

fn split_question(question: &str) -> (String, Vec<String>) {
    let re = Regex::new(r"(?i)\b(?:grouped by|broken down by|split by|for each|by|per)\b").expect("static regex");
    let lower = question.trim().trim_end_matches('?').to_string();
    match re.find(&lower) {
        Some(m) => {
            let metric = lower[..m.start()].trim().to_string();
            let dims_raw = lower[m.end()..].to_string();
            let dims = Regex::new(r"(?i),|\band\b|&")
                .expect("static regex")
                .split(&dims_raw)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (metric, dims)
        }
        None => (lower, Vec::new()),
    }
}

fn is_simple_ident(part: &str) -> bool {
    let mut chars = part.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Quote an identifier only when needed (keeps statements portable to the simulated engines).
pub fn quote_ident(name: &str, engine: DatabaseEngine) -> String {
    if is_simple_ident(name) {
        return name.to_string();
    }
    match engine {
        DatabaseEngine::MySql => format!("`{}`", name.replace('`', "``")),
        _ => format!("\"{}\"", name.replace('"', "\"\"")),
    }
}

fn quote_table(qualified: &str, engine: DatabaseEngine) -> String {
    qualified
        .split('.')
        .map(|p| quote_ident(p, engine))
        .collect::<Vec<_>>()
        .join(".")
}

fn placeholder(n: usize, engine: DatabaseEngine) -> String {
    match engine {
        DatabaseEngine::Sqlite => format!("?{n}"),
        DatabaseEngine::Postgres => format!("${n}"),
        DatabaseEngine::MySql => "?".to_string(),
    }
}

#[derive(Debug, Clone)]
struct Edge {
    to: String,
    pairs: Vec<(String, String)>, // (column on `from` node, column on `to` node)
    cardinality: Cardinality,
    def_index: usize,
}

fn table_key(t: &str) -> String {
    t.trim_matches('"').to_ascii_lowercase()
}

fn build_graph(rels: &[&Definition]) -> BTreeMap<String, Vec<Edge>> {
    let mut graph: BTreeMap<String, Vec<Edge>> = BTreeMap::new();
    for (i, def) in rels.iter().enumerate() {
        if let DefinitionBody::Relationship { from_table, to_table, column_pairs, cardinality, .. } = &def.body {
            graph.entry(table_key(from_table)).or_default().push(Edge {
                to: table_key(to_table),
                pairs: column_pairs.clone(),
                cardinality: *cardinality,
                def_index: i,
            });
            graph.entry(table_key(to_table)).or_default().push(Edge {
                to: table_key(from_table),
                pairs: column_pairs.iter().map(|(a, b)| (b.clone(), a.clone())).collect(),
                cardinality: cardinality.reversed(),
                def_index: i,
            });
        }
    }
    for edges in graph.values_mut() {
        edges.sort_by(|a, b| a.to.cmp(&b.to).then(a.def_index.cmp(&b.def_index)));
    }
    graph
}

/// Shortest path (fewest hops) from `from` to `to`: list of (from_node, edge).
fn shortest_path(graph: &BTreeMap<String, Vec<Edge>>, from: &str, to: &str) -> Option<Vec<(String, Edge)>> {
    if from == to {
        return Some(Vec::new());
    }
    let mut prev: BTreeMap<String, (String, Edge)> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::from([from.to_string()]);
    let mut queue = VecDeque::from([from.to_string()]);
    while let Some(node) = queue.pop_front() {
        for edge in graph.get(&node).into_iter().flatten() {
            if seen.insert(edge.to.clone()) {
                prev.insert(edge.to.clone(), (node.clone(), edge.clone()));
                if edge.to == to {
                    let mut path = Vec::new();
                    let mut cur = to.to_string();
                    while let Some((p, e)) = prev.get(&cur) {
                        path.push((p.clone(), e.clone()));
                        cur = p.clone();
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back(edge.to.clone());
            }
        }
    }
    None
}

fn exact_phrase(def: &Definition, question_norm: &str) -> bool {
    std::iter::once(&def.name)
        .chain(def.synonyms.iter())
        .map(|p| normalized_phrase(p))
        .any(|p| !p.is_empty() && question_norm.contains(&p))
}

/// Validate a compiled statement: one read-only SELECT over allowlisted tables only.
pub fn validate_generated_sql(engine: DatabaseEngine, sql: &str, allowed_tables: &[String]) -> Result<(), String> {
    let analysis = db_mcp_sql::parse_and_analyze_sql(engine, sql).map_err(|e| format!("parse failed: {e}"))?;
    if analysis.statement_count != 1 || analysis.is_multi_statement {
        return Err("compiled SQL must be exactly one statement".to_string());
    }
    if analysis.overall_class != SqlStatementClass::Read
        || analysis.has_writes
        || analysis.has_ddl
        || analysis.has_cte_write
    {
        return Err("compiled SQL must be read-only".to_string());
    }
    if analysis.statements.first().map(|s| s.statement_kind.as_str()) != Some("SELECT") {
        return Err("compiled SQL must be a SELECT".to_string());
    }
    if analysis.has_privileged_functions {
        return Err(format!("privileged functions are not allowed: {:?}", analysis.privileged_functions));
    }
    if !analysis.parse_warnings.is_empty() {
        return Err(format!("analyzer warnings: {:?}", analysis.parse_warnings));
    }
    let allowed: BTreeSet<String> = allowed_tables.iter().map(|t| base_table_name(t)).collect();
    for t in &analysis.referenced_tables {
        if !allowed.contains(&base_table_name(t)) {
            return Err(format!("table '{t}' is not part of the certified plan"));
        }
    }
    Ok(())
}

/// Plan a question against the pinned published ontology.
pub fn plan(req: &PlanRequest<'_>) -> SemanticPlan {
    let mut plan = SemanticPlan::new(req.question, req.revision, req.schema_fingerprint);
    let Some(revision) = req.revision else {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            "no published ontology revision for this connection (discover, propose, review and publish first)",
        );
    };
    if revision.schema_fingerprint != req.schema_fingerprint {
        plan.limitations.push(format!(
            "schema changed since revision {} was published ({} -> {}); every used definition was re-checked against the live catalog",
            revision.revision_id, revision.schema_fingerprint, req.schema_fingerprint
        ));
    }
    let (metric_part, dim_parts) = split_question(req.question);
    let metric_query = if tokenize(&metric_part).is_empty() { req.question.to_string() } else { metric_part.clone() };
    let question_norm = normalized_phrase(&metric_query);
    let q_tokens: BTreeSet<String> = tokenize(&metric_query).into_iter().collect();

    let by_kind = |defs: &[Definition], kind: DefinitionKind| -> Vec<Definition> {
        defs.iter().filter(|d| d.kind == kind).cloned().collect()
    };
    let live_metrics = by_kind(req.published, DefinitionKind::Metric);
    let stale_metrics = by_kind(req.stale, DefinitionKind::Metric);

    // ---- metric ----
    let mut metric_pool = live_metrics.clone();
    metric_pool.extend(stale_metrics.iter().cloned());
    let ranked = rank(&metric_query, &metric_pool);
    plan.candidates = ranked.iter().take(5).map(CandidateSummary::from).collect();
    let Some(top) = ranked.first() else {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!("no certified metric matches '{metric_query}'"),
        );
    };
    if stale_metrics.iter().any(|s| s.def_id == top.definition.def_id && s.version == top.definition.version) {
        return plan.refuse(
            PlanStatus::Stale,
            format!(
                "metric '{}' ({} v{}) is stale after a schema change and needs re-certification",
                top.definition.name, top.definition.def_id, top.definition.version
            ),
        );
    }
    // A match on generic words alone ("number of ...", "total ...") says nothing about WHAT is
    // measured; refusing beats answering a different question.
    const GENERIC: &[&str] = &["number", "count", "total", "sum", "average", "avg", "amount", "much", "value", "all"];
    if top.matched_terms.iter().all(|t| GENERIC.contains(&t.as_str())) {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!(
                "no certified metric matches the subject of '{metric_query}' (only generic words matched: {})",
                top.matched_terms.join(", ")
            ),
        );
    }
    let top_phrase = exact_phrase(&top.definition, &question_norm);
    let rivals: Vec<&ScoredDefinition> = ranked
        .iter()
        .skip(1)
        .filter(|r| {
            r.definition.def_id != top.definition.def_id
                && ((top_phrase && exact_phrase(&r.definition, &question_norm))
                    || (r.score - top.score).abs() < 1e-9)
        })
        .collect();
    if top.definition.flags.ambiguous || !rivals.is_empty() {
        let names: Vec<String> = std::iter::once(top)
            .chain(rivals.iter().copied())
            .map(|r| format!("{} ({})", r.definition.name, r.definition.def_id))
            .collect();
        return plan.refuse(
            PlanStatus::Ambiguous,
            format!("'{metric_query}' matches several certified metrics: {}; name one explicitly", names.join(", ")),
        );
    }
    if let Some(second) = ranked.get(1) {
        plan.assumptions.push(format!(
            "selected metric '{}' (score {}) over '{}' (score {})",
            top.definition.name, top.score, second.definition.name, second.score
        ));
    }
    let metric = top.definition.clone();
    let DefinitionBody::Metric { base_table, aggregation, column, default_filters, unit, grain } = &metric.body else {
        return plan.refuse(PlanStatus::NotAnswerable, "selected definition is not a metric");
    };
    let base = table_key(base_table);

    // ---- relationship graph (live only) ----
    let live_rels: Vec<&Definition> = req.published.iter().filter(|d| d.kind == DefinitionKind::Relationship).collect();
    let stale_rels: Vec<&Definition> = req.stale.iter().filter(|d| d.kind == DefinitionKind::Relationship).collect();
    let graph = build_graph(&live_rels);

    // Resolves a path from base and refuses fan-out.
    let mut needed: Vec<(String, String)> = Vec::new(); // (table, purpose)
    let route = |target: &str| -> Result<Vec<(String, Edge)>, (PlanStatus, String)> {
        let path = match shortest_path(&graph, &base, target) {
            Some(p) => p,
            None => {
                let stale_hit = stale_rels.iter().any(|d| d.body.tables().iter().any(|t| table_key(t) == target));
                return Err(if stale_hit {
                    (PlanStatus::Stale, format!("the certified relationship reaching {target} is stale after a schema change"))
                } else {
                    (PlanStatus::NotAnswerable, format!("no certified relationship connects {base} to {target}"))
                });
            }
        };
        if let Some((from, edge)) = path.iter().find(|(_, e)| e.cardinality.fans_out()) {
            return Err((
                PlanStatus::NotAnswerable,
                format!(
                    "multiplicative join: {from} -> {} is one-to-many relative to the metric grain ({}), so '{}' would be double counted; refusing instead of returning inflated numbers",
                    edge.to,
                    grain.clone().unwrap_or_else(|| base.clone()),
                    metric.name
                ),
            ));
        }
        Ok(path)
    };

    // ---- filters ----
    let mut filters: Vec<Definition> = Vec::new();
    for f_id in default_filters {
        match req.published.iter().find(|d| &d.def_id == f_id && d.kind == DefinitionKind::Filter) {
            Some(f) => filters.push(f.clone()),
            None => {
                return plan.refuse(PlanStatus::Stale, format!("default filter {f_id} of metric '{}' is not published", metric.name));
            }
        }
    }
    for f in req.published.iter().filter(|d| d.kind == DefinitionKind::Filter) {
        if filters.iter().any(|x| x.def_id == f.def_id) {
            continue;
        }
        let DefinitionBody::Filter { table, .. } = &f.body else { continue };
        let entity_tokens: BTreeSet<String> = tokenize(&base_table_name(table)).into_iter().collect();
        let distinctive: BTreeSet<String> = tokenize(&f.name).into_iter().filter(|t| !entity_tokens.contains(t)).collect();
        let by_name = !distinctive.is_empty() && distinctive.iter().all(|t| q_tokens.contains(t));
        let by_synonym = f.synonyms.iter().any(|s| {
            let p = normalized_phrase(s);
            !p.is_empty() && question_norm.contains(&p)
        });
        if by_name || by_synonym {
            filters.push(f.clone());
        }
    }
    for f in &filters {
        if let DefinitionBody::Filter { table, .. } = &f.body {
            needed.push((table_key(table), format!("filter {}", f.name)));
        }
    }

    // ---- dimensions ----
    let attributes: Vec<Definition> = req
        .published
        .iter()
        .filter(|d| d.kind == DefinitionKind::Attribute && !d.flags.sensitive)
        .cloned()
        .collect();
    let stale_attrs = by_kind(req.stale, DefinitionKind::Attribute);
    let mut dims: Vec<Definition> = Vec::new();
    for phrase in &dim_parts {
        let mut pool = attributes.clone();
        pool.extend(stale_attrs.iter().cloned());
        let ranked = rank(phrase, &pool);
        let Some(best) = ranked.first() else {
            if req.published.iter().any(|d| d.kind == DefinitionKind::Attribute && d.flags.sensitive && !rank(phrase, std::slice::from_ref(d)).is_empty()) {
                return plan.refuse(PlanStatus::NotAnswerable, format!("'{phrase}' maps to a sensitive column, which cannot be used as a grouping dimension"));
            }
            return plan.refuse(PlanStatus::NotAnswerable, format!("no certified attribute matches dimension '{phrase}'"));
        };
        // Among near-ties prefer the attribute reachable with the fewest joins.
        let close: Vec<&ScoredDefinition> = ranked.iter().filter(|r| r.score >= best.score * 0.9).collect();
        let chosen = close
            .iter()
            .min_by_key(|r| {
                let t = r.definition.body.tables().first().map(|t| table_key(t)).unwrap_or_default();
                shortest_path(&graph, &base, &t).map(|p| p.len()).unwrap_or(usize::MAX)
            })
            .copied()
            .unwrap_or(best);
        if stale_attrs.iter().any(|s| s.def_id == chosen.definition.def_id && s.version == chosen.definition.version) {
            return plan.refuse(PlanStatus::Stale, format!("dimension '{}' is stale after a schema change", chosen.definition.name));
        }
        if let DefinitionBody::Attribute { table, .. } = &chosen.definition.body {
            needed.push((table_key(table), format!("dimension {}", chosen.definition.name)));
        }
        dims.push(chosen.definition.clone());
    }

    // ---- join paths ----
    let mut alias_of: BTreeMap<String, String> = BTreeMap::from([(base.clone(), "t0".to_string())]);
    let mut table_names: BTreeMap<String, String> = BTreeMap::from([(base.clone(), base_table.clone())]);
    let mut joins: Vec<String> = Vec::new();
    let mut used_rels: BTreeSet<usize> = BTreeSet::new();
    for (target, _purpose) in &needed {
        let path = match route(target) {
            Ok(p) => p,
            Err((status, why)) => return plan.refuse(status, why),
        };
        for (from, edge) in path {
            if alias_of.contains_key(&edge.to) {
                continue;
            }
            let alias = format!("t{}", alias_of.len());
            let from_alias = alias_of.get(&from).cloned().unwrap_or_else(|| "t0".to_string());
            let rel_def = live_rels[edge.def_index];
            let to_display = rel_def
                .body
                .tables()
                .into_iter()
                .find(|t| table_key(t) == edge.to)
                .unwrap_or_else(|| edge.to.clone());
            let on = edge
                .pairs
                .iter()
                .map(|(fc, tc)| format!("{alias}.{} = {from_alias}.{}", quote_ident(tc, req.engine), quote_ident(fc, req.engine)))
                .collect::<Vec<_>>()
                .join(" AND ");
            joins.push(format!("JOIN {} {alias} ON {on}", quote_table(&to_display, req.engine)));
            alias_of.insert(edge.to.clone(), alias);
            table_names.insert(edge.to.clone(), to_display);
            used_rels.insert(edge.def_index);
        }
    }

    // ---- SQL ----
    let mut select = Vec::new();
    let mut group_by = Vec::new();
    for d in &dims {
        if let DefinitionBody::Attribute { table, column, .. } = &d.body {
            let a = &alias_of[&table_key(table)];
            let expr = format!("{a}.{}", quote_ident(column, req.engine));
            select.push(format!("{expr} AS {}", quote_ident(&slug(&d.name), req.engine)));
            group_by.push(expr);
        }
    }
    let metric_alias = quote_ident(&slug(&metric.name), req.engine);
    let metric_expr = match (aggregation, column) {
        (Aggregation::Count, None) => "COUNT(*)".to_string(),
        (Aggregation::CountDistinct, Some(c)) => format!("COUNT(DISTINCT t0.{})", quote_ident(c, req.engine)),
        (agg, Some(c)) => format!("{}(t0.{})", agg.sql_function(), quote_ident(c, req.engine)),
        (_, None) => return plan.refuse(PlanStatus::NotAnswerable, "metric has no column to aggregate"),
    };
    select.push(format!("{metric_expr} AS {metric_alias}"));
    let mut params: Vec<Value> = Vec::new();
    let mut wheres = Vec::new();
    for f in &filters {
        if let DefinitionBody::Filter { table, column, operator, value } = &f.body {
            let a = &alias_of[&table_key(table)];
            let col = format!("{a}.{}", quote_ident(column, req.engine));
            match operator {
                FilterOp::IsNull | FilterOp::IsNotNull => wheres.push(format!("{col} {}", operator.sql())),
                FilterOp::In => {
                    let items = value.as_array().cloned().unwrap_or_default();
                    if items.is_empty() {
                        return plan.refuse(PlanStatus::NotAnswerable, format!("filter '{}' has an empty IN list", f.name));
                    }
                    let mut ph = Vec::new();
                    for v in items {
                        params.push(v);
                        ph.push(placeholder(params.len(), req.engine));
                    }
                    wheres.push(format!("{col} IN ({})", ph.join(", ")));
                }
                op => {
                    params.push(value.clone());
                    wheres.push(format!("{col} {} {}", op.sql(), placeholder(params.len(), req.engine)));
                }
            }
        }
    }
    let mut sql = format!("SELECT {} FROM {} t0", select.join(", "), quote_table(base_table, req.engine));
    for j in &joins {
        sql.push(' ');
        sql.push_str(j);
    }
    if !wheres.is_empty() {
        sql.push_str(&format!(" WHERE {}", wheres.join(" AND ")));
    }
    if !group_by.is_empty() {
        sql.push_str(&format!(" GROUP BY {} ORDER BY {metric_alias} DESC", group_by.join(", ")));
    }
    sql.push_str(&format!(" LIMIT {}", req.max_rows.clamp(1, 10_000)));

    let tables: Vec<String> = table_names.values().cloned().collect();
    if let Err(why) = validate_generated_sql(req.engine, &sql, &tables) {
        return plan.refuse(PlanStatus::NotAnswerable, format!("compiled SQL failed validation: {why}"));
    }

    // ---- assemble ----
    plan.metric = Some(UsedDefinition::from(&metric));
    plan.dimensions = dims.iter().map(UsedDefinition::from).collect();
    plan.filters = filters.iter().map(UsedDefinition::from).collect();
    plan.relationships = used_rels.iter().map(|i| UsedDefinition::from(live_rels[*i])).collect();
    plan.tables = tables;
    if let Some(u) = unit {
        plan.limitations.push(format!("'{}' is expressed in {u}", metric.name));
    }
    if live_rels.iter().enumerate().any(|(i, d)| {
        used_rels.contains(&i) && matches!(d.body, DefinitionBody::Relationship { source: crate::model::RelationshipSource::Inferred, .. })
    }) {
        plan.limitations.push("uses an inferred (non-FK) relationship certified by a reviewer".to_string());
    }
    if filters.is_empty() && default_filters.is_empty() {
        plan.assumptions.push("no certified filter matched the question; all rows of the metric grain are included".to_string());
    }
    let defs_sig = plan
        .all_used()
        .iter()
        .map(|u| format!("{}@{}#{}", u.def_id, u.version, u.content_hash))
        .collect::<Vec<_>>()
        .join(",");
    plan.plan_hash = Some(sha256_hex(
        format!(
            "v1|sql={sql}|params={}|rev={}|schema={}|defs={defs_sig}",
            serde_json::to_string(&params).unwrap_or_default(),
            revision.revision_id,
            req.schema_fingerprint
        )
        .as_bytes(),
    ));
    plan.sql = Some(sql);
    plan.params = params;
    plan.status = PlanStatus::Answerable;
    plan.result_kind = "rule_based_calculation".to_string();
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_metric_and_dimensions() {
        let (m, d) = split_question("Total order value by user role and status?");
        assert_eq!(m, "Total order value");
        assert_eq!(d, vec!["user role", "status"]);
    }

    #[test]
    fn quoting_is_minimal_and_engine_specific() {
        assert_eq!(quote_ident("orders", DatabaseEngine::Sqlite), "orders");
        assert_eq!(quote_ident("Order Items", DatabaseEngine::Postgres), "\"Order Items\"");
        assert_eq!(quote_ident("a`b", DatabaseEngine::MySql), "`a``b`");
    }

    #[test]
    fn validator_rejects_unsafe_sql() {
        let allowed = vec!["main.orders".to_string()];
        assert!(validate_generated_sql(DatabaseEngine::Sqlite, "SELECT COUNT(*) AS n FROM main.orders t0 LIMIT 5", &allowed).is_ok());
        assert!(validate_generated_sql(DatabaseEngine::Sqlite, "SELECT 1 FROM main.orders; DROP TABLE users", &allowed).is_err());
        assert!(validate_generated_sql(DatabaseEngine::Sqlite, "SELECT * FROM main.users", &allowed).is_err());
        assert!(validate_generated_sql(DatabaseEngine::Sqlite, "DELETE FROM main.orders", &allowed).is_err());
        assert!(validate_generated_sql(DatabaseEngine::Postgres, "SELECT pg_read_file('/etc/passwd') FROM orders", &allowed).is_err());
        assert!(validate_generated_sql(
            DatabaseEngine::Postgres,
            "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
            &allowed
        )
        .is_err());
    }
}
