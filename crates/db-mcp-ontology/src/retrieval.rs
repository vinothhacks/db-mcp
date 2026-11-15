//! Deterministic lexical retrieval over ontology definitions (no embeddings, no network).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::model::{Definition, DefinitionBody};

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "of", "for", "in", "on", "to", "and", "or", "is", "are", "was", "were", "be",
    "what", "which", "who", "how", "show", "me", "give", "list", "get", "find", "please", "with",
    "from", "by", "per", "each", "every", "all", "do", "does", "did", "that", "this", "these",
    "those", "there", "their", "its", "it", "as", "at", "much", "many", "s",
];

/// Split snake_case, camelCase and punctuation, lowercase, drop stopwords, and stem lightly.
pub fn tokenize(text: &str) -> Vec<String> {
    tokenize_raw(text)
        .into_iter()
        .filter(|t| !STOPWORDS.contains(&t.as_str()))
        .map(|t| stem(&t))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Split snake_case, camelCase and punctuation into lowercase words (no stemming).
pub fn tokenize_raw(text: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(text.len() + 8);
    let mut prev_lower = false;
    for c in text.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            spaced.push(' ');
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        if c.is_ascii_alphanumeric() {
            spaced.push(c.to_ascii_lowercase());
        } else {
            spaced.push(' ');
        }
    }
    spaced.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Light suffix stemmer: enough to match plural/singular and simple verb forms.
pub fn stem(token: &str) -> String {
    let t = token;
    if t.len() > 4 && t.ends_with("ies") {
        return format!("{}y", &t[..t.len() - 3]);
    }
    for suf in ["sses", "ches", "shes", "xes"] {
        if t.len() > suf.len() + 1 && t.ends_with(suf) {
            return t[..t.len() - 2].to_string();
        }
    }
    if t.len() > 5 && t.ends_with("ing") {
        return t[..t.len() - 3].to_string();
    }
    if t.len() > 5 && t.ends_with("ed") {
        return t[..t.len() - 2].to_string();
    }
    if t.len() > 3 && t.ends_with('s') && !t.ends_with("ss") && !t.ends_with("us") {
        return t[..t.len() - 1].to_string();
    }
    t.to_string()
}

/// One ranked match.
#[derive(Debug, Clone, Serialize)]
pub struct ScoredDefinition {
    pub score: f64,
    pub matched_terms: Vec<String>,
    pub definition: Definition,
}

/// Field-weighted bag of tokens for a definition.
fn weighted_tokens(def: &Definition) -> BTreeMap<String, f64> {
    let mut weights: BTreeMap<String, f64> = BTreeMap::new();
    let mut add = |text: &str, w: f64| {
        for t in tokenize(text) {
            let e = weights.entry(t).or_insert(0.0);
            if w > *e {
                *e = w;
            }
        }
    };
    add(&def.name, 3.0);
    for s in &def.synonyms {
        add(s, 2.5);
    }
    match &def.body {
        DefinitionBody::Attribute { table, column, .. } | DefinitionBody::Filter { table, column, .. } => {
            add(column, 1.5);
            add(table, 0.75);
        }
        DefinitionBody::Metric { base_table, column, .. } => {
            if let Some(c) = column {
                add(c, 1.5);
            }
            add(base_table, 0.75);
        }
        DefinitionBody::Entity { table } => add(table, 1.5),
        DefinitionBody::Relationship { from_table, to_table, .. } => {
            add(from_table, 1.0);
            add(to_table, 1.0);
        }
    }
    if let Some(d) = &def.description {
        add(d, 0.5);
    }
    weights
}

/// Rank `candidates` against `query`. Scores are relative (IDF-weighted field matches plus a
/// phrase bonus); they are evidence for ranking, never a confidence to publish.
pub fn rank(query: &str, candidates: &[Definition]) -> Vec<ScoredDefinition> {
    let q_tokens: BTreeSet<String> = tokenize(query).into_iter().collect();
    if q_tokens.is_empty() {
        return Vec::new();
    }
    let docs: Vec<BTreeMap<String, f64>> = candidates.iter().map(weighted_tokens).collect();
    let n = docs.len().max(1) as f64;
    let mut df: BTreeMap<&str, usize> = BTreeMap::new();
    for doc in &docs {
        for t in doc.keys() {
            *df.entry(t.as_str()).or_default() += 1;
        }
    }
    let q_norm = normalized_phrase(query);
    let mut out = Vec::new();
    for (def, doc) in candidates.iter().zip(docs.iter()) {
        let mut score = 0.0;
        let mut matched = Vec::new();
        for t in &q_tokens {
            if let Some(w) = doc.get(t) {
                let idf = (1.0 + n / (*df.get(t.as_str()).unwrap_or(&1) as f64)).ln();
                score += w * idf;
                matched.push(t.clone());
            }
        }
        if score <= 0.0 {
            continue;
        }
        // Phrase bonus: the full name or a synonym appears verbatim in the question.
        let phrases = std::iter::once(&def.name).chain(def.synonyms.iter());
        if phrases
            .map(|p| normalized_phrase(p))
            .any(|p| !p.is_empty() && q_norm.contains(&p))
        {
            score += 2.0;
        }
        // Coverage: share of the definition's name tokens present in the question.
        let name_tokens: BTreeSet<String> = tokenize(&def.name).into_iter().collect();
        if !name_tokens.is_empty() {
            let covered = name_tokens.iter().filter(|t| q_tokens.contains(*t)).count() as f64;
            score += covered / name_tokens.len() as f64;
        }
        out.push(ScoredDefinition {
            score: (score * 1000.0).round() / 1000.0,
            matched_terms: matched,
            definition: def.clone(),
        });
    }
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.definition.def_id.cmp(&b.definition.def_id))
    });
    out
}

/// Space-joined stemmed tokens, used for phrase containment checks.
pub fn normalized_phrase(text: &str) -> String {
    format!(" {} ", tokenize(text).join(" "))
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_splits_and_stems() {
        assert_eq!(tokenize("OrderItems by user_role"), vec!["order", "item", "user", "role"]);
        assert_eq!(tokenize("categories"), vec!["category"]);
        assert_eq!(tokenize("Completed orders"), vec!["complet", "order"]);
        assert_eq!(stem("status"), "status");
    }
}
