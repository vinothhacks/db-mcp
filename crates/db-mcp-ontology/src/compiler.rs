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
use crate::retrieval::{normalized_phrase, rank, stem, tokenize, tokenize_raw, ScoredDefinition};

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

/// A question split into the parts the compiler resolves separately.
#[derive(Debug, Default, PartialEq)]
struct QuestionParts {
    /// Text before the first grouping marker: the metric plus any inline filter words
    /// ("count of completed orders").
    metric: String,
    /// Grouping phrases after `by` / `per` / `for each` ..., with trailing filter clauses removed.
    dimensions: Vec<String>,
    /// Filter clauses that trail the grouping phrases ("for completed orders", "where ...",
    /// "..., completed orders only"), keyword included so negations stay visible.
    clauses: Vec<String>,
}

fn split_question(question: &str) -> QuestionParts {
    let re =
        Regex::new(r"(?i)\b(?:grouped by|broken down by|split by|for each|for every|by|per)\b")
            .expect("static regex");
    let lower = question.trim().trim_end_matches('?').trim().to_string();
    let Some(m) = re.find(&lower) else {
        return QuestionParts {
            metric: lower,
            ..QuestionParts::default()
        };
    };
    let metric = lower[..m.start()].trim().to_string();
    let tail = &lower[m.end()..];
    // The first filter keyword ends the grouping phrases: "by user role for completed orders".
    // "for each" / "for every" are grouping markers, not filters.
    let clause_re = Regex::new(
        r"(?i)\bfor\s+(?:each|every)\b|\b(?:for|where|whose|with|without|having|only|excluding|except|among|from|in|on|during|since|before|after|between|that|which|who|when|while|not)\b",
    )
    .expect("static regex");
    let cut = clause_re
        .find_iter(tail)
        .find(|c| {
            let w = c.as_str().to_ascii_lowercase();
            !(w.starts_with("for") && w.len() > 3)
        })
        .map(|c| c.start());
    let (dims_raw, mut clauses) = match cut {
        Some(i) => (&tail[..i], vec![tail[i..].trim().to_string()]),
        None => (tail, Vec::new()),
    };
    let mut dimensions: Vec<String> = Regex::new(
        r"(?i),|;|&|\band\b|\bfor\s+(?:each|every)\b|\b(?:grouped by|broken down by|split by|by|per)\b",
    )
    .expect("static regex")
    .split(dims_raw)
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .collect();
    // Postfix "only" ("by user role, completed orders only") turns the last phrase into a filter.
    if clauses.len() == 1 && clauses[0].eq_ignore_ascii_case("only") {
        if let Some(last) = dimensions.pop() {
            clauses[0] = format!("{last} only");
        }
    }
    QuestionParts {
        metric,
        dimensions,
        clauses,
    }
}

/// Words that never restrict or redefine an answer: question scaffolding, measure verbs,
/// filter-clause keywords (their content is still checked) and aggregation words for the
/// aggregation the metric already has. Compared after stemming.
const NEUTRAL: &[&str] = &[
    "total",
    "sum",
    "number",
    "count",
    "amount",
    "overall",
    "altogether",
    "combined",
    "grand",
    "show",
    "list",
    "give",
    "tell",
    "get",
    "find",
    "return",
    "display",
    "calculate",
    "compute",
    "report",
    "can",
    "could",
    "would",
    "will",
    "you",
    "i",
    "we",
    "our",
    "us",
    "my",
    "want",
    "need",
    "know",
    "see",
    "sold",
    "placed",
    "made",
    "bought",
    "purchased",
    "spent",
    "earned",
    "generated",
    "recorded",
    "have",
    "has",
    "had",
    "been",
    "being",
    "exist",
    "where",
    "whose",
    "having",
    "only",
    "when",
    "breakdown",
];

/// Generic measure words that do not identify WHAT a metric measures.
const MEASURE_GENERIC: &[&str] = &["total", "sum", "count", "number", "amount"];

/// An aggregation the question explicitly asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggRequest {
    Avg,
    Min,
    Max,
    Median,
    Distinct,
}

impl AggRequest {
    fn from_word(word: &str) -> Option<Self> {
        match word {
            "average" | "averages" | "avg" | "mean" => Some(Self::Avg),
            "min" | "minimum" | "lowest" | "smallest" => Some(Self::Min),
            "max" | "maximum" | "highest" | "largest" | "biggest" => Some(Self::Max),
            "median" => Some(Self::Median),
            "distinct" | "unique" => Some(Self::Distinct),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Avg => "an average",
            Self::Min => "a minimum",
            Self::Max => "a maximum",
            Self::Median => "a median",
            Self::Distinct => "a distinct count",
        }
    }

    fn satisfied_by(self, agg: Aggregation) -> bool {
        match self {
            Self::Avg => agg == Aggregation::Avg,
            Self::Min => agg == Aggregation::Min,
            Self::Max => agg == Aggregation::Max,
            Self::Median => false,
            Self::Distinct => agg == Aggregation::CountDistinct,
        }
    }
}

fn aggregation_label(agg: Aggregation) -> &'static str {
    match agg {
        Aggregation::Sum => "a sum",
        Aggregation::Count => "a count",
        Aggregation::CountDistinct => "a distinct count",
        Aggregation::Avg => "an average",
        Aggregation::Min => "a minimum",
        Aggregation::Max => "a maximum",
    }
}

fn is_neutral(token: &str) -> bool {
    NEUTRAL.iter().any(|w| stem(w) == token) || AggRequest::from_word(token).is_some()
}

/// Every word a certified definition stands for: name, synonyms, table, column and (for
/// filters) the literal value. Free-text descriptions are not semantics and do not count.
fn definition_terms(def: &Definition) -> BTreeSet<String> {
    let mut texts: Vec<String> = std::iter::once(def.name.clone())
        .chain(def.synonyms.iter().cloned())
        .collect();
    match &def.body {
        DefinitionBody::Entity { table } => texts.push(base_table_name(table)),
        DefinitionBody::Attribute { table, column, .. } => {
            texts.push(base_table_name(table));
            texts.push(column.clone());
        }
        DefinitionBody::Filter {
            table,
            column,
            value,
            ..
        } => {
            texts.push(base_table_name(table));
            texts.push(column.clone());
            let values = match value {
                Value::Array(items) => items.clone(),
                other => vec![other.clone()],
            };
            for v in values {
                match v {
                    Value::String(s) => texts.push(s),
                    Value::Number(n) => texts.push(n.to_string()),
                    Value::Bool(b) => texts.push(b.to_string()),
                    _ => {}
                }
            }
        }
        DefinitionBody::Metric {
            base_table, column, ..
        } => {
            texts.push(base_table_name(base_table));
            if let Some(c) = column {
                texts.push(c.clone());
            }
        }
        DefinitionBody::Relationship {
            from_table,
            to_table,
            ..
        } => {
            texts.push(base_table_name(from_table));
            texts.push(base_table_name(to_table));
        }
    }
    texts.iter().flat_map(|t| tokenize(t)).collect()
}

/// Words that identify what a definition is about beyond its table and generic measure words
/// (`role` for "user role", `quantity` for "order item quantity").
fn identifying_terms(def: &Definition) -> BTreeSet<String> {
    let table_tokens: BTreeSet<String> = def
        .body
        .tables()
        .iter()
        .flat_map(|t| tokenize(&base_table_name(t)))
        .collect();
    let mut texts: Vec<String> = std::iter::once(def.name.clone())
        .chain(def.synonyms.iter().cloned())
        .collect();
    match &def.body {
        DefinitionBody::Attribute { column, .. } | DefinitionBody::Filter { column, .. } => {
            texts.push(column.clone())
        }
        DefinitionBody::Metric {
            column: Some(c), ..
        } => texts.push(c.clone()),
        _ => {}
    }
    texts
        .iter()
        .flat_map(|t| tokenize(t))
        .filter(|t| !table_tokens.contains(t) && !MEASURE_GENERIC.iter().any(|g| stem(g) == *t))
        .collect()
}

/// The text names the definition: a name/synonym phrase appears verbatim, or one of its
/// identifying words does.
fn names_definition(def: &Definition, text_norm: &str, text_tokens: &BTreeSet<String>) -> bool {
    exact_phrase(def, text_norm)
        || identifying_terms(def)
            .iter()
            .any(|t| text_tokens.contains(t))
}

/// Original words of `text` whose stems are in `stems`, in order, deduplicated.
fn original_words(text: &str, stems: &BTreeSet<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in tokenize_raw(text) {
        let s = stem(&w);
        if stems.contains(&s) && !out.contains(&w) {
            out.push(w);
        }
    }
    out
}

fn quoted(words: &[String]) -> String {
    words
        .iter()
        .map(|w| format!("'{w}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A certified filter matches when all distinctive words of its name (beyond the table name)
/// appear, or one of its synonyms appears verbatim.
fn filter_matches(f: &Definition, text_norm: &str, text_tokens: &BTreeSet<String>) -> bool {
    let DefinitionBody::Filter { table, .. } = &f.body else {
        return false;
    };
    let entity_tokens: BTreeSet<String> = tokenize(&base_table_name(table)).into_iter().collect();
    let distinctive: BTreeSet<String> = tokenize(&f.name)
        .into_iter()
        .filter(|t| !entity_tokens.contains(t))
        .collect();
    let by_name = !distinctive.is_empty() && distinctive.iter().all(|t| text_tokens.contains(t));
    let by_synonym = f.synonyms.iter().any(|s| {
        let p = normalized_phrase(s);
        !p.is_empty() && text_norm.contains(&p)
    });
    by_name || by_synonym
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
        DatabaseEngine::SqlServer => format!("[{}]", name.replace(']', "]]")),
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
        DatabaseEngine::SqlServer => format!("@P{n}"),
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
        if let DefinitionBody::Relationship {
            from_table,
            to_table,
            column_pairs,
            cardinality,
            ..
        } = &def.body
        {
            graph.entry(table_key(from_table)).or_default().push(Edge {
                to: table_key(to_table),
                pairs: column_pairs.clone(),
                cardinality: *cardinality,
                def_index: i,
            });
            graph.entry(table_key(to_table)).or_default().push(Edge {
                to: table_key(from_table),
                pairs: column_pairs
                    .iter()
                    .map(|(a, b)| (b.clone(), a.clone()))
                    .collect(),
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
fn shortest_path(
    graph: &BTreeMap<String, Vec<Edge>>,
    from: &str,
    to: &str,
) -> Option<Vec<(String, Edge)>> {
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
pub fn validate_generated_sql(
    engine: DatabaseEngine,
    sql: &str,
    allowed_tables: &[String],
) -> Result<(), String> {
    let analysis =
        db_mcp_sql::parse_and_analyze_sql(engine, sql).map_err(|e| format!("parse failed: {e}"))?;
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
    if analysis
        .statements
        .first()
        .map(|s| s.statement_kind.as_str())
        != Some("SELECT")
    {
        return Err("compiled SQL must be a SELECT".to_string());
    }
    if analysis.has_privileged_functions {
        return Err(format!(
            "privileged functions are not allowed: {:?}",
            analysis.privileged_functions
        ));
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
    // Comparison operators carry semantics (`!=`, `<`) that name-based filter matching cannot honour.
    if let Some(op) = ["!=", "<>", "≠", "<=", ">=", "≤", "≥", "<", ">"]
        .iter()
        .find(|op| req.question.contains(**op))
    {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!(
                "the question uses the comparison operator '{op}'; certified filters are matched by name, so comparisons and negations cannot be honoured (name a certified filter instead)"
            ),
        );
    }
    let parts = split_question(req.question);
    let metric_part = parts.metric.clone();
    let dim_parts = parts.dimensions;
    let metric_query = if tokenize(&metric_part).is_empty() {
        req.question.to_string()
    } else {
        metric_part.clone()
    };
    let question_norm = normalized_phrase(&metric_query);
    // Everything that can restrict the answer: the metric phrase plus trailing filter clauses.
    // Certified filters are matched against all of it; dimension phrases are resolved on their own.
    let restrict_text = std::iter::once(metric_query.clone())
        .chain(parts.clauses.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let restrict_norm = normalized_phrase(&restrict_text);
    let q_tokens: BTreeSet<String> = tokenize(&restrict_text).into_iter().collect();

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
    if stale_metrics
        .iter()
        .any(|s| s.def_id == top.definition.def_id && s.version == top.definition.version)
    {
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
    const GENERIC: &[&str] = &[
        "number", "count", "total", "sum", "average", "avg", "amount", "much", "value", "all",
    ];
    if top
        .matched_terms
        .iter()
        .all(|t| GENERIC.contains(&t.as_str()))
    {
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
            format!(
                "'{metric_query}' matches several certified metrics: {}; name one explicitly",
                names.join(", ")
            ),
        );
    }
    if let Some(second) = ranked.get(1) {
        plan.assumptions.push(format!(
            "selected metric '{}' (score {}) over '{}' (score {})",
            top.definition.name, top.score, second.definition.name, second.score
        ));
    }
    let metric = top.definition.clone();
    let DefinitionBody::Metric {
        base_table,
        aggregation,
        column,
        default_filters,
        unit,
        grain,
    } = &metric.body
    else {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            "selected definition is not a metric",
        );
    };
    let base = table_key(base_table);

    // ---- the metric must compute what was asked ----
    // An explicit aggregation word ("average", "max", "distinct", ...) must match the certified
    // aggregation, unless the word is part of the metric's own certified name or synonyms.
    let metric_words: BTreeSet<String> = std::iter::once(&metric.name)
        .chain(metric.synonyms.iter())
        .flat_map(|t| tokenize_raw(t))
        .collect();
    for word in tokenize_raw(&restrict_text) {
        if metric_words.contains(&word) {
            continue;
        }
        if let Some(want) = AggRequest::from_word(&word) {
            if !want.satisfied_by(*aggregation) {
                return plan.refuse(
                    PlanStatus::NotAnswerable,
                    format!(
                        "certified metric '{}' is {}, not {} ('{word}' in the question); refusing instead of returning a different aggregation",
                        metric.name,
                        aggregation_label(*aggregation),
                        want.label()
                    ),
                );
            }
        }
    }
    // A column measure must be named: "how many order items" or "total orders" says nothing about
    // summing quantity or order totals.
    if matches!(
        aggregation,
        Aggregation::Sum | Aggregation::Avg | Aggregation::Min | Aggregation::Max
    ) && !names_definition(&metric, &restrict_norm, &q_tokens)
    {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!(
                "the question does not name what certified metric '{}' measures ({} of {}); refusing instead of guessing the measure",
                metric.name,
                aggregation_label(*aggregation),
                column.clone().unwrap_or_default()
            ),
        );
    }

    // ---- relationship graph (live only) ----
    let live_rels: Vec<&Definition> = req
        .published
        .iter()
        .filter(|d| d.kind == DefinitionKind::Relationship)
        .collect();
    let stale_rels: Vec<&Definition> = req
        .stale
        .iter()
        .filter(|d| d.kind == DefinitionKind::Relationship)
        .collect();
    let graph = build_graph(&live_rels);

    // Resolves a path from base and refuses fan-out.
    let mut needed: Vec<(String, String)> = Vec::new(); // (table, purpose)
    let route = |target: &str| -> Result<Vec<(String, Edge)>, (PlanStatus, String)> {
        let path = match shortest_path(&graph, &base, target) {
            Some(p) => p,
            None => {
                let stale_hit = stale_rels
                    .iter()
                    .any(|d| d.body.tables().iter().any(|t| table_key(t) == target));
                return Err(if stale_hit {
                    (PlanStatus::Stale, format!("the certified relationship reaching {target} is stale after a schema change"))
                } else {
                    (
                        PlanStatus::NotAnswerable,
                        format!("no certified relationship connects {base} to {target}"),
                    )
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
        match req
            .published
            .iter()
            .find(|d| &d.def_id == f_id && d.kind == DefinitionKind::Filter)
        {
            Some(f) => filters.push(f.clone()),
            None => {
                return plan.refuse(
                    PlanStatus::Stale,
                    format!(
                        "default filter {f_id} of metric '{}' is not published",
                        metric.name
                    ),
                );
            }
        }
    }
    let mut asked_filters = 0usize;
    for f in req
        .published
        .iter()
        .filter(|d| d.kind == DefinitionKind::Filter)
    {
        if filters.iter().any(|x| x.def_id == f.def_id) {
            continue;
        }
        if filter_matches(f, &restrict_norm, &q_tokens) {
            filters.push(f.clone());
            asked_filters += 1;
        }
    }
    if let Some(s) = req.stale.iter().find(|d| {
        d.kind == DefinitionKind::Filter
            && !filters.iter().any(|x| x.def_id == d.def_id)
            && filter_matches(d, &restrict_norm, &q_tokens)
    }) {
        return plan.refuse(
            PlanStatus::Stale,
            format!(
                "filter '{}' ({} v{}) is stale after a schema change and needs re-certification",
                s.name, s.def_id, s.version
            ),
        );
    }
    // Certified filters are always ANDed: "completed or pending" must not become "completed and pending".
    let certified_words: BTreeSet<String> = std::iter::once(&metric)
        .chain(filters.iter())
        .flat_map(|d| std::iter::once(&d.name).chain(d.synonyms.iter()))
        .flat_map(|t| tokenize_raw(t))
        .collect();
    let disjunction = tokenize_raw(&restrict_text)
        .into_iter()
        .find(|w| matches!(w.as_str(), "or" | "either" | "nor") && !certified_words.contains(w));
    if let (Some(word), true) = (disjunction, asked_filters > 0) {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!("the question combines filters with '{word}'; certified filters are always combined with AND, so ask for each filter separately"),
        );
    }
    for (i, a) in filters.iter().enumerate() {
        for b in &filters[i + 1..] {
            let (
                DefinitionBody::Filter {
                    table: ta,
                    column: ca,
                    operator: oa,
                    ..
                },
                DefinitionBody::Filter {
                    table: tb,
                    column: cb,
                    operator: ob,
                    ..
                },
            ) = (&a.body, &b.body)
            else {
                continue;
            };
            let exclusive = |op: &FilterOp| {
                matches!(
                    op,
                    FilterOp::Eq | FilterOp::In | FilterOp::IsNull | FilterOp::IsNotNull
                )
            };
            if table_key(ta) == table_key(tb)
                && ca.eq_ignore_ascii_case(cb)
                && (exclusive(oa) || exclusive(ob))
            {
                return plan.refuse(
                    PlanStatus::NotAnswerable,
                    format!(
                        "certified filters '{}' and '{}' both constrain {}.{}; combining them with AND would answer a different question, so refusing",
                        a.name, b.name, base_table_name(ta), ca
                    ),
                );
            }
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
            if req.published.iter().any(|d| {
                d.kind == DefinitionKind::Attribute
                    && d.flags.sensitive
                    && !rank(phrase, std::slice::from_ref(d)).is_empty()
            }) {
                return plan.refuse(PlanStatus::NotAnswerable, format!("'{phrase}' maps to a sensitive column, which cannot be used as a grouping dimension"));
            }
            return plan.refuse(
                PlanStatus::NotAnswerable,
                format!("no certified attribute matches dimension '{phrase}'"),
            );
        };
        let phrase_norm = normalized_phrase(phrase);
        let phrase_tokens: BTreeSet<String> = tokenize(phrase).into_iter().collect();
        let uncovered = |d: &Definition| -> BTreeSet<String> {
            let terms = definition_terms(d);
            phrase_tokens
                .iter()
                .filter(|t| !terms.contains(*t) && !is_neutral(t))
                .cloned()
                .collect()
        };
        // Prefer an attribute the phrase names with no words left over.
        // Among near-ties prefer the attribute reachable with the fewest joins.
        let close: Vec<&ScoredDefinition> = ranked
            .iter()
            .filter(|r| r.score >= best.score * 0.9)
            .collect();
        let chosen = close
            .iter()
            .min_by_key(|r| {
                let named = names_definition(&r.definition, &phrase_norm, &phrase_tokens);
                let t = r
                    .definition
                    .body
                    .tables()
                    .first()
                    .map(|t| table_key(t))
                    .unwrap_or_default();
                (
                    !named,
                    uncovered(&r.definition).len(),
                    shortest_path(&graph, &base, &t)
                        .map(|p| p.len())
                        .unwrap_or(usize::MAX),
                )
            })
            .copied()
            .unwrap_or(best);
        // "by user" must not silently become "by user role"; "by user role for x" must not drop x.
        if !names_definition(&chosen.definition, &phrase_norm, &phrase_tokens) {
            return plan.refuse(
                PlanStatus::NotAnswerable,
                format!(
                    "no certified attribute matches dimension '{phrase}' (closest is '{}', which the phrase does not name)",
                    chosen.definition.name
                ),
            );
        }
        let rest = uncovered(&chosen.definition);
        if !rest.is_empty() {
            return plan.refuse(
                PlanStatus::NotAnswerable,
                format!(
                    "no certified attribute covers {} in dimension '{phrase}' (closest is '{}'); refusing instead of grouping by something else",
                    quoted(&original_words(phrase, &rest)),
                    chosen.definition.name
                ),
            );
        }
        if stale_attrs
            .iter()
            .any(|s| s.def_id == chosen.definition.def_id && s.version == chosen.definition.version)
        {
            return plan.refuse(
                PlanStatus::Stale,
                format!(
                    "dimension '{}' is stale after a schema change",
                    chosen.definition.name
                ),
            );
        }
        if let DefinitionBody::Attribute { table, .. } = &chosen.definition.body {
            needed.push((
                table_key(table),
                format!("dimension {}", chosen.definition.name),
            ));
        }
        dims.push(chosen.definition.clone());
    }

    // ---- every restricting word must be covered by a used definition ----
    // A word no certified metric, filter or dimension accounts for ("pending", "2025", "not",
    // "admin") would otherwise be dropped silently and the answer would cover all rows.
    let mut covered: BTreeSet<String> = definition_terms(&metric);
    for d in filters.iter().chain(dims.iter()) {
        covered.extend(definition_terms(d));
    }
    let leftover: BTreeSet<String> = q_tokens
        .iter()
        .filter(|t| !covered.contains(*t) && !is_neutral(t))
        .cloned()
        .collect();
    if !leftover.is_empty() {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!(
                "no certified filter, dimension or metric covers {} in the question; refusing instead of answering without it",
                quoted(&original_words(&restrict_text, &leftover))
            ),
        );
    }

    // ---- join paths ----
    let mut alias_of: BTreeMap<String, String> = BTreeMap::from([(base.clone(), "t0".to_string())]);
    let mut table_names: BTreeMap<String, String> =
        BTreeMap::from([(base.clone(), base_table.clone())]);
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
            let from_alias = alias_of
                .get(&from)
                .cloned()
                .unwrap_or_else(|| "t0".to_string());
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
                .map(|(fc, tc)| {
                    format!(
                        "{alias}.{} = {from_alias}.{}",
                        quote_ident(tc, req.engine),
                        quote_ident(fc, req.engine)
                    )
                })
                .collect::<Vec<_>>()
                .join(" AND ");
            joins.push(format!(
                "JOIN {} {alias} ON {on}",
                quote_table(&to_display, req.engine)
            ));
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
            select.push(format!(
                "{expr} AS {}",
                quote_ident(&slug(&d.name), req.engine)
            ));
            group_by.push(expr);
        }
    }
    let metric_alias = quote_ident(&slug(&metric.name), req.engine);
    let metric_expr = match (aggregation, column) {
        (Aggregation::Count, None) => "COUNT(*)".to_string(),
        (Aggregation::CountDistinct, Some(c)) => {
            format!("COUNT(DISTINCT t0.{})", quote_ident(c, req.engine))
        }
        (agg, Some(c)) => format!("{}(t0.{})", agg.sql_function(), quote_ident(c, req.engine)),
        (_, None) => {
            return plan.refuse(
                PlanStatus::NotAnswerable,
                "metric has no column to aggregate",
            )
        }
    };
    select.push(format!("{metric_expr} AS {metric_alias}"));
    let mut params: Vec<Value> = Vec::new();
    let mut wheres = Vec::new();
    for f in &filters {
        if let DefinitionBody::Filter {
            table,
            column,
            operator,
            value,
        } = &f.body
        {
            let a = &alias_of[&table_key(table)];
            let col = format!("{a}.{}", quote_ident(column, req.engine));
            match operator {
                FilterOp::IsNull | FilterOp::IsNotNull => {
                    wheres.push(format!("{col} {}", operator.sql()))
                }
                FilterOp::In => {
                    let items = value.as_array().cloned().unwrap_or_default();
                    if items.is_empty() {
                        return plan.refuse(
                            PlanStatus::NotAnswerable,
                            format!("filter '{}' has an empty IN list", f.name),
                        );
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
                    wheres.push(format!(
                        "{col} {} {}",
                        op.sql(),
                        placeholder(params.len(), req.engine)
                    ));
                }
            }
        }
    }
    let row_cap = req.max_rows.clamp(1, 10_000);
    // T-SQL has no LIMIT: the row cap is `SELECT TOP (n)`.
    let top = if req.engine == DatabaseEngine::SqlServer {
        format!("TOP ({row_cap}) ")
    } else {
        String::new()
    };
    let mut sql = format!(
        "SELECT {top}{} FROM {} t0",
        select.join(", "),
        quote_table(base_table, req.engine)
    );
    for j in &joins {
        sql.push(' ');
        sql.push_str(j);
    }
    if !wheres.is_empty() {
        sql.push_str(&format!(" WHERE {}", wheres.join(" AND ")));
    }
    if !group_by.is_empty() {
        sql.push_str(&format!(
            " GROUP BY {} ORDER BY {metric_alias} DESC",
            group_by.join(", ")
        ));
    }
    if req.engine != DatabaseEngine::SqlServer {
        sql.push_str(&format!(" LIMIT {row_cap}"));
    }

    let tables: Vec<String> = table_names.values().cloned().collect();
    if let Err(why) = validate_generated_sql(req.engine, &sql, &tables) {
        return plan.refuse(
            PlanStatus::NotAnswerable,
            format!("compiled SQL failed validation: {why}"),
        );
    }

    // ---- assemble ----
    plan.metric = Some(UsedDefinition::from(&metric));
    plan.dimensions = dims.iter().map(UsedDefinition::from).collect();
    plan.filters = filters.iter().map(UsedDefinition::from).collect();
    plan.relationships = used_rels
        .iter()
        .map(|i| UsedDefinition::from(live_rels[*i]))
        .collect();
    plan.tables = tables;
    if let Some(u) = unit {
        plan.limitations
            .push(format!("'{}' is expressed in {u}", metric.name));
    }
    if live_rels.iter().enumerate().any(|(i, d)| {
        used_rels.contains(&i)
            && matches!(
                d.body,
                DefinitionBody::Relationship {
                    source: crate::model::RelationshipSource::Inferred,
                    ..
                }
            )
    }) {
        plan.limitations
            .push("uses an inferred (non-FK) relationship certified by a reviewer".to_string());
    }
    if filters.is_empty() && default_filters.is_empty() {
        plan.assumptions.push(
            "no certified filter matched the question; all rows of the metric grain are included"
                .to_string(),
        );
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
        let p = split_question("Total order value by user role and status?");
        assert_eq!(p.metric, "Total order value");
        assert_eq!(p.dimensions, vec!["user role", "status"]);
        assert!(p.clauses.is_empty());
    }

    #[test]
    fn trailing_filter_clauses_are_not_dimensions() {
        let p = split_question("total order value by user role for completed orders");
        assert_eq!(p.metric, "total order value");
        assert_eq!(p.dimensions, vec!["user role"]);
        assert_eq!(p.clauses, vec!["for completed orders"]);

        let p = split_question(
            "order value by user role where status is completed and created in 2025",
        );
        assert_eq!(p.dimensions, vec!["user role"]);
        assert_eq!(
            p.clauses,
            vec!["where status is completed and created in 2025"]
        );

        let p = split_question("order value by user role, completed orders only");
        assert_eq!(p.dimensions, vec!["user role"]);
        assert_eq!(p.clauses, vec!["completed orders only"]);

        // "for each" groups; it does not start a filter clause.
        let p = split_question("order value per user role for each sku");
        assert_eq!(p.dimensions, vec!["user role", "sku"]);
        assert!(p.clauses.is_empty());

        // No grouping marker: the whole question is the metric phrase (filters matched inside it).
        let p = split_question("count of completed orders");
        assert_eq!(p.metric, "count of completed orders");
        assert!(p.dimensions.is_empty() && p.clauses.is_empty());
    }

    fn def(def_id: &str, kind: &str, name: &str, synonyms: &[&str], body: Value) -> Definition {
        serde_json::from_value(serde_json::json!({
            "def_id": def_id, "version": 1, "tenant_id": "default", "connection": "c", "kind": kind,
            "name": name, "synonyms": synonyms, "body": body, "strength": "declared", "status": "published",
            "content_hash": format!("h-{def_id}"), "schema_fingerprint": "fp", "proposed_by": "agent",
            "created_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"
        }))
        .unwrap()
    }

    /// Mirrors the golden fixture ontology (research/ontology/golden-local-sqlite.json).
    fn golden_defs() -> Vec<Definition> {
        use serde_json::json;
        vec![
            def(
                "metric:order_value",
                "metric",
                "order value",
                &["order total", "sales", "revenue"],
                json!({"type": "metric", "base_table": "main.orders", "aggregation": "sum", "column": "total_cents", "unit": "cents", "grain": "order"}),
            ),
            def(
                "metric:main.orders.count",
                "metric",
                "order count",
                &["number of orders", "count of orders", "orders count"],
                json!({"type": "metric", "base_table": "main.orders", "aggregation": "count", "unit": "rows", "grain": "order"}),
            ),
            def(
                "metric:main.order_items.quantity.sum",
                "metric",
                "order item quantity",
                &["total quantity", "sum of quantity", "quantity"],
                json!({"type": "metric", "base_table": "main.order_items", "aggregation": "sum", "column": "quantity", "grain": "order item"}),
            ),
            def(
                "filter:completed_order",
                "filter",
                "completed order",
                &["fulfilled order"],
                json!({"type": "filter", "table": "main.orders", "column": "status", "operator": "eq", "value": "completed"}),
            ),
            def(
                "attribute:main.users.role",
                "attribute",
                "user role",
                &["role", "users.role"],
                json!({"type": "attribute", "table": "main.users", "column": "role"}),
            ),
            def(
                "attribute:main.order_items.sku",
                "attribute",
                "order item sku",
                &["sku", "order_items.sku"],
                json!({"type": "attribute", "table": "main.order_items", "column": "sku"}),
            ),
            def(
                "relationship:main.orders(user_id)->main.users",
                "relationship",
                "order user",
                &[],
                json!({"type": "relationship", "from_table": "main.orders", "to_table": "main.users", "column_pairs": [["user_id", "id"]], "cardinality": "many_to_one", "source": "declared_fk"}),
            ),
            def(
                "relationship:main.order_items(order_id)->main.orders",
                "relationship",
                "order item order",
                &[],
                json!({"type": "relationship", "from_table": "main.order_items", "to_table": "main.orders", "column_pairs": [["order_id", "id"]], "cardinality": "many_to_one", "source": "declared_fk"}),
            ),
        ]
    }

    fn revision() -> OntologyRevision {
        serde_json::from_value(serde_json::json!({
            "revision_id": "rev_1", "tenant_id": "default", "connection": "c", "seq": 1, "content_hash": "x",
            "schema_fingerprint": "fp", "def_refs": [], "published_by": "reviewer", "published_at": "2025-01-01T00:00:00Z"
        }))
        .unwrap()
    }

    fn plan_with(defs: &[Definition], question: &str) -> SemanticPlan {
        let rev = revision();
        plan(&PlanRequest {
            question,
            engine: DatabaseEngine::Sqlite,
            max_rows: 200,
            revision: Some(&rev),
            published: defs,
            stale: &[],
            schema_fingerprint: "fp",
        })
    }

    fn ask(question: &str) -> SemanticPlan {
        plan_with(&golden_defs(), question)
    }

    #[test]
    fn filter_clause_after_dimension_is_applied() {
        for q in [
            "total order value by user role for completed orders",
            "total order value by user role where status is completed",
            "total order value by user role with completed orders",
            "total order value by user role, completed orders only",
            "total order value by user role for fulfilled orders?",
        ] {
            let p = ask(q);
            assert!(p.is_answerable(), "{q}: {:?}", p.missing);
            let sql = p.sql.clone().unwrap();
            assert!(
                sql.contains("WHERE t0.status = ?1") && sql.contains("GROUP BY t1.role"),
                "{q}: {sql}"
            );
            assert_eq!(p.params, vec![Value::from("completed")], "{q}");
            assert_eq!(
                p.filters
                    .iter()
                    .map(|f| f.def_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["filter:completed_order"]
            );
            assert_eq!(
                p.dimensions
                    .iter()
                    .map(|d| d.def_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["attribute:main.users.role"]
            );
        }
        // Filter on a joined table, grouped by a base-table attribute.
        let p = ask("total quantity by sku for completed orders");
        assert!(p.is_answerable(), "{:?}", p.missing);
        let sql = p.sql.unwrap();
        assert!(
            sql.contains("JOIN main.orders t1 ON t1.id = t0.order_id"),
            "{sql}"
        );
        assert!(
            sql.contains("WHERE t1.status = ?1") && sql.contains("GROUP BY t0.sku"),
            "{sql}"
        );
    }

    #[test]
    fn sqlserver_plans_use_top_and_named_parameters() {
        let rev = revision();
        let defs = golden_defs();
        for q in [
            "count of completed orders by user role",
            "total order value for completed orders",
        ] {
            let p = plan(&PlanRequest {
                question: q,
                engine: DatabaseEngine::SqlServer,
                max_rows: 50,
                revision: Some(&rev),
                published: &defs,
                stale: &[],
                schema_fingerprint: "fp",
            });
            assert!(p.is_answerable(), "{q}: {:?}", p.missing);
            let sql = p.sql.clone().unwrap();
            assert!(sql.starts_with("SELECT TOP (50) "), "{sql}");
            assert!(!sql.contains("LIMIT"), "{sql}");
            assert!(sql.contains("@P1"), "{sql}");
        }
    }

    #[test]
    fn existing_answerable_questions_still_answer() {
        for q in [
            "total order value by user role",
            "count of completed orders",
            "count of fulfilled orders",
            "quantity sold by sku",
            "total order value for completed orders",
            "what is the order value for orders with status completed",
            "total quantity sold for completed orders",
            "order value by role of user",
            "count of completed orders by user role",
        ] {
            let p = ask(q);
            assert!(p.is_answerable(), "{q}: {:?}", p.missing);
        }
    }

    #[test]
    fn unmatched_filter_words_refuse_instead_of_answering_all_rows() {
        for (q, word) in [
            ("total order value for pending orders", "'pending'"),
            ("count of pending orders", "'pending'"),
            (
                "total order value by user role for pending orders",
                "'pending'",
            ),
            ("count of orders that are not completed", "'not'"),
            ("count of non-completed orders", "'non'"),
            ("count of orders excluding completed orders", "'excluding'"),
            ("total order value in 2025", "'2025'"),
            (
                "total order value by user role for completed orders in 2025",
                "'2025'",
            ),
            ("total order value of admin users", "'admin'"),
            ("top 5 order value", "'top', '5'"),
        ] {
            let p = ask(q);
            assert_eq!(p.status, PlanStatus::NotAnswerable, "{q}: {:?}", p.sql);
            assert!(p.sql.is_none(), "{q}");
            assert!(
                p.missing.iter().any(|m| m.contains(word)),
                "{q}: {:?}",
                p.missing
            );
        }
        let p = ask("count of orders where status != completed");
        assert_eq!(p.status, PlanStatus::NotAnswerable);
        assert!(p.missing[0].contains("'!='"), "{:?}", p.missing);
    }

    #[test]
    fn aggregation_mismatch_refuses() {
        for (q, why) in [
            (
                "average order value",
                "certified metric 'order value' is a sum, not an average",
            ),
            ("mean order value by user role", "is a sum, not an average"),
            (
                "avg order value for completed orders",
                "is a sum, not an average",
            ),
            ("max order value", "is a sum, not a maximum"),
            ("lowest order value", "is a sum, not a minimum"),
            ("median order value", "is a sum, not a median"),
            (
                "count of distinct orders",
                "is a count, not a distinct count",
            ),
        ] {
            let p = ask(q);
            assert_eq!(p.status, PlanStatus::NotAnswerable, "{q}: {:?}", p.sql);
            assert!(
                p.missing.iter().any(|m| m.contains(why)),
                "{q}: {:?}",
                p.missing
            );
        }
        // The certified aggregation itself is fine.
        let mut defs = golden_defs();
        defs[0] = def(
            "metric:order_value",
            "metric",
            "order value",
            &["order total"],
            serde_json::json!({"type": "metric", "base_table": "main.orders", "aggregation": "avg", "column": "total_cents"}),
        );
        let p = plan_with(&defs, "average order value");
        assert!(p.is_answerable(), "{:?}", p.missing);
        assert!(p.sql.unwrap().contains("AVG(t0.total_cents)"));
        let p = plan_with(&defs, "max order value");
        assert!(
            p.missing
                .iter()
                .any(|m| m.contains("is an average, not a maximum")),
            "{:?}",
            p.missing
        );
    }

    #[test]
    fn unnamed_measures_and_dimensions_refuse() {
        // Sum of quantity is not "how many order items"; sum of totals is not "total orders".
        for q in ["how many order items", "total orders by user role"] {
            let p = ask(q);
            assert_eq!(p.status, PlanStatus::NotAnswerable, "{q}: {:?}", p.sql);
            assert!(
                p.missing[0].contains("does not name what certified metric"),
                "{q}: {:?}",
                p.missing
            );
        }
        // "by user" is not "by user role"; an extra grouping must not be dropped.
        let p = ask("order value by user");
        assert_eq!(p.status, PlanStatus::NotAnswerable, "{:?}", p.sql);
        assert!(
            p.missing[0].contains("no certified attribute"),
            "{:?}",
            p.missing
        );
        let p = ask("order count per user role for each sku");
        assert_eq!(p.status, PlanStatus::NotAnswerable, "{:?}", p.sql);
    }

    #[test]
    fn disjunctive_or_conflicting_filters_refuse() {
        let mut defs = golden_defs();
        defs.push(def("filter:pending_order", "filter", "pending order", &[],
            serde_json::json!({"type": "filter", "table": "main.orders", "column": "status", "operator": "eq", "value": "pending"})));
        let p = plan_with(&defs, "count of pending orders");
        assert!(p.is_answerable(), "{:?}", p.missing);
        assert_eq!(p.params, vec![Value::from("pending")]);
        let p = plan_with(&defs, "total order value for completed or pending orders");
        assert_eq!(p.status, PlanStatus::NotAnswerable, "{:?}", p.sql);
        assert!(p.missing[0].contains("'or'"), "{:?}", p.missing);
        let p = plan_with(&defs, "total order value for completed and pending orders");
        assert_eq!(p.status, PlanStatus::NotAnswerable, "{:?}", p.sql);
        assert!(
            p.missing[0].contains("both constrain orders.status"),
            "{:?}",
            p.missing
        );
    }

    #[test]
    fn quoting_is_minimal_and_engine_specific() {
        assert_eq!(quote_ident("orders", DatabaseEngine::Sqlite), "orders");
        assert_eq!(
            quote_ident("Order Items", DatabaseEngine::Postgres),
            "\"Order Items\""
        );
        assert_eq!(quote_ident("a`b", DatabaseEngine::MySql), "`a``b`");
        assert_eq!(
            quote_ident("Order Items", DatabaseEngine::SqlServer),
            "[Order Items]"
        );
        assert_eq!(quote_ident("a]b", DatabaseEngine::SqlServer), "[a]]b]");
        assert_eq!(placeholder(2, DatabaseEngine::SqlServer), "@P2");
    }

    #[test]
    fn validator_rejects_unsafe_sql() {
        let allowed = vec!["main.orders".to_string()];
        assert!(validate_generated_sql(
            DatabaseEngine::Sqlite,
            "SELECT COUNT(*) AS n FROM main.orders t0 LIMIT 5",
            &allowed
        )
        .is_ok());
        assert!(validate_generated_sql(
            DatabaseEngine::Sqlite,
            "SELECT 1 FROM main.orders; DROP TABLE users",
            &allowed
        )
        .is_err());
        assert!(validate_generated_sql(
            DatabaseEngine::Sqlite,
            "SELECT * FROM main.users",
            &allowed
        )
        .is_err());
        assert!(validate_generated_sql(
            DatabaseEngine::Sqlite,
            "DELETE FROM main.orders",
            &allowed
        )
        .is_err());
        assert!(validate_generated_sql(
            DatabaseEngine::Postgres,
            "SELECT pg_read_file('/etc/passwd') FROM orders",
            &allowed
        )
        .is_err());
        assert!(validate_generated_sql(
            DatabaseEngine::Postgres,
            "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
            &allowed
        )
        .is_err());
    }
}
