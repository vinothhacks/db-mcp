//! Golden-question evaluation with hard refusal gates.

use serde::{Deserialize, Serialize};

use crate::compiler::{PlanStatus, SemanticPlan};

/// Expected outcome for one golden question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenExpectation {
    /// `answerable`, `not_answerable`, `ambiguous` or `stale`.
    pub status: String,
    /// Expected metric `def_id` (answerable cases).
    #[serde(default)]
    pub metric: Option<String>,
    /// Expected dimension `def_id`s, in order.
    #[serde(default)]
    pub dimensions: Vec<String>,
    /// Expected filter `def_id`s (any order).
    #[serde(default)]
    pub filters: Vec<String>,
    /// Substrings the compiled SQL must contain.
    #[serde(default)]
    pub sql_contains: Vec<String>,
    /// Substring that must appear in at least one `missing` reason (refusal cases).
    #[serde(default)]
    pub reason_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenCase {
    pub id: String,
    pub question: String,
    pub expect: GoldenExpectation,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub passed: bool,
    pub status: String,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub total: usize,
    pub passed: usize,
    pub refusal_cases: usize,
    pub refusal_passed: usize,
    pub answerable_cases: usize,
    pub term_retrieval_correct: usize,
    /// Every answerable plan used only pinned, published definitions (asserted by construction;
    /// counted here so the gate is visible in reports).
    pub sql_from_published_only: bool,
    pub gates: Vec<GateResult>,
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateResult {
    pub name: String,
    pub threshold: String,
    pub actual: String,
    pub passed: bool,
}

impl EvalReport {
    pub fn all_gates_passed(&self) -> bool {
        self.gates.iter().all(|g| g.passed)
    }
}

fn status_name(s: PlanStatus) -> &'static str {
    match s {
        PlanStatus::Answerable => "answerable",
        PlanStatus::NotAnswerable => "not_answerable",
        PlanStatus::Ambiguous => "ambiguous",
        PlanStatus::Stale => "stale",
    }
}

fn check(case: &GoldenCase, plan: &SemanticPlan) -> (Vec<String>, bool) {
    let mut failures = Vec::new();
    let got = status_name(plan.status);
    if got != case.expect.status {
        failures.push(format!("status {got} != expected {} ({:?})", case.expect.status, plan.missing));
    }
    let mut retrieval_ok = true;
    if let Some(m) = &case.expect.metric {
        if plan.metric.as_ref().map(|u| &u.def_id) != Some(m) {
            retrieval_ok = false;
            failures.push(format!("metric {:?} != expected {m}", plan.metric.as_ref().map(|u| &u.def_id)));
        }
    }
    let dims: Vec<&String> = plan.dimensions.iter().map(|d| &d.def_id).collect();
    if !case.expect.dimensions.is_empty() && dims != case.expect.dimensions.iter().collect::<Vec<_>>() {
        retrieval_ok = false;
        failures.push(format!("dimensions {dims:?} != expected {:?}", case.expect.dimensions));
    }
    for f in &case.expect.filters {
        if !plan.filters.iter().any(|u| &u.def_id == f) {
            retrieval_ok = false;
            failures.push(format!("missing filter {f}"));
        }
    }
    let sql = plan.sql.clone().unwrap_or_default();
    for needle in &case.expect.sql_contains {
        if !sql.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()) {
            failures.push(format!("SQL lacks '{needle}': {sql}"));
        }
    }
    if let Some(r) = &case.expect.reason_contains {
        if !plan.missing.iter().any(|m| m.to_ascii_lowercase().contains(&r.to_ascii_lowercase())) {
            failures.push(format!("no refusal reason contains '{r}': {:?}", plan.missing));
        }
    }
    (failures, retrieval_ok)
}

/// Run golden cases through `planner` and compute gates.
pub fn evaluate(cases: &[GoldenCase], mut planner: impl FnMut(&GoldenCase) -> SemanticPlan) -> EvalReport {
    let mut results = Vec::new();
    let (mut refusal_cases, mut refusal_passed, mut answerable, mut retrieval_ok_count) = (0, 0, 0, 0);
    let mut published_only = true;
    for case in cases {
        let plan = planner(case);
        let (failures, retrieval_ok) = check(case, &plan);
        let passed = failures.is_empty();
        if case.expect.status == "answerable" {
            answerable += 1;
            if retrieval_ok {
                retrieval_ok_count += 1;
            }
            if plan.is_answerable() && plan.revision_id.is_none() {
                published_only = false;
            }
        } else {
            refusal_cases += 1;
            if passed {
                refusal_passed += 1;
            }
        }
        results.push(CaseResult {
            id: case.id.clone(),
            passed,
            status: status_name(plan.status).to_string(),
            failures,
        });
    }
    let passed = results.iter().filter(|r| r.passed).count();
    let retrieval_rate = if answerable == 0 { 1.0 } else { retrieval_ok_count as f64 / answerable as f64 };
    let gates = vec![
        GateResult {
            name: "unanswerable/stale/ambiguous/fan-out cases refuse".to_string(),
            threshold: "100%".to_string(),
            actual: format!("{refusal_passed}/{refusal_cases}"),
            passed: refusal_passed == refusal_cases,
        },
        GateResult {
            name: "correct term retrieval on answerable cases".to_string(),
            threshold: ">= 95%".to_string(),
            actual: format!("{:.1}%", retrieval_rate * 100.0),
            passed: retrieval_rate >= 0.95,
        },
        GateResult {
            name: "SQL generated only from pinned published definitions".to_string(),
            threshold: "100%".to_string(),
            actual: published_only.to_string(),
            passed: published_only,
        },
        GateResult {
            name: "all golden cases".to_string(),
            threshold: "100%".to_string(),
            actual: format!("{passed}/{}", results.len()),
            passed: passed == results.len(),
        },
    ];
    EvalReport {
        total: results.len(),
        passed,
        refusal_cases,
        refusal_passed,
        answerable_cases: answerable,
        term_retrieval_correct: retrieval_ok_count,
        sql_from_published_only: published_only,
        gates,
        cases: results,
    }
}
