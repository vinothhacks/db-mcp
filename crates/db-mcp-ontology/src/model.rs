//! Typed ontology domain model: definitions, lifecycle, certifications, revisions and evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Kind of semantic definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    Entity,
    Attribute,
    Relationship,
    Metric,
    Filter,
}

impl DefinitionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Attribute => "attribute",
            Self::Relationship => "relationship",
            Self::Metric => "metric",
            Self::Filter => "filter",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "entity" | "entities" | "term" => Some(Self::Entity),
            "attribute" | "attributes" | "dimension" | "column" => Some(Self::Attribute),
            "relationship" | "relationships" | "join" => Some(Self::Relationship),
            "metric" | "metrics" | "measure" => Some(Self::Metric),
            "filter" | "filters" | "segment" => Some(Self::Filter),
            _ => None,
        }
    }
}

/// Lifecycle status of one definition version.
///
/// `Discovered -> Proposed -> InReview -> Certified -> Published -> Stale/Deprecated`, or `Rejected`.
/// Only `Published` content can generate SQL; `Stale` content fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionStatus {
    Discovered,
    Proposed,
    InReview,
    Certified,
    Published,
    Stale,
    Deprecated,
    Rejected,
}

impl DefinitionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Proposed => "proposed",
            Self::InReview => "in_review",
            Self::Certified => "certified",
            Self::Published => "published",
            Self::Stale => "stale",
            Self::Deprecated => "deprecated",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "discovered" => Some(Self::Discovered),
            "proposed" => Some(Self::Proposed),
            "in_review" | "inreview" => Some(Self::InReview),
            "certified" => Some(Self::Certified),
            "published" => Some(Self::Published),
            "stale" => Some(Self::Stale),
            "deprecated" => Some(Self::Deprecated),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Explicit transition table. Anything not listed is refused.
    pub fn can_transition_to(&self, next: DefinitionStatus) -> bool {
        use DefinitionStatus::*;
        matches!(
            (self, next),
            (Discovered, Proposed | InReview | Certified | Rejected | Stale)
                | (Proposed, InReview | Certified | Rejected | Stale)
                | (InReview, Certified | Rejected | Stale)
                | (Certified, Published | Rejected | Stale | Deprecated)
                | (Published, Stale | Deprecated)
                | (Stale, Deprecated)
        )
    }

    /// Statuses that may still be reviewed (approved or rejected).
    pub fn is_reviewable(&self) -> bool {
        matches!(self, Self::Discovered | Self::Proposed | Self::InReview)
    }
}

/// Relative cardinality of a relationship, read `from_table -> to_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cardinality {
    ManyToOne,
    OneToMany,
    OneToOne,
    ManyToMany,
}

impl Cardinality {
    /// Cardinality when the edge is walked in the opposite direction.
    pub fn reversed(&self) -> Self {
        match self {
            Self::ManyToOne => Self::OneToMany,
            Self::OneToMany => Self::ManyToOne,
            other => *other,
        }
    }

    /// True when walking this direction can multiply rows of the source side.
    pub fn fans_out(&self) -> bool {
        matches!(self, Self::OneToMany | Self::ManyToMany)
    }
}

/// Where a relationship came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipSource {
    DeclaredFk,
    Inferred,
    Manual,
}

/// Aggregation applied by a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Sum,
    Count,
    CountDistinct,
    Avg,
    Min,
    Max,
}

impl Aggregation {
    pub fn sql_function(&self) -> &'static str {
        match self {
            Self::Sum => "SUM",
            Self::Count | Self::CountDistinct => "COUNT",
            Self::Avg => "AVG",
            Self::Min => "MIN",
            Self::Max => "MAX",
        }
    }
}

/// Comparison used by a certified filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    IsNull,
    IsNotNull,
}

impl FilterOp {
    pub fn sql(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "<>",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::In => "IN",
            Self::IsNull => "IS NULL",
            Self::IsNotNull => "IS NOT NULL",
        }
    }
}

/// Structured, SQL-free body of a definition. Free-form SQL is never stored: the compiler builds
/// statements only from these typed parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DefinitionBody {
    Entity {
        table: String,
    },
    Attribute {
        table: String,
        column: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
    Relationship {
        from_table: String,
        to_table: String,
        /// `(from_column, to_column)` pairs.
        column_pairs: Vec<(String, String)>,
        cardinality: Cardinality,
        source: RelationshipSource,
    },
    Metric {
        base_table: String,
        aggregation: Aggregation,
        /// Column aggregated; `None` only for `COUNT(*)`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        column: Option<String>,
        /// `def_id`s of certified filters always applied (e.g. "active only").
        #[serde(default)]
        default_filters: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grain: Option<String>,
    },
    Filter {
        table: String,
        column: String,
        operator: FilterOp,
        #[serde(default)]
        value: serde_json::Value,
    },
}

impl DefinitionBody {
    pub fn kind(&self) -> DefinitionKind {
        match self {
            Self::Entity { .. } => DefinitionKind::Entity,
            Self::Attribute { .. } => DefinitionKind::Attribute,
            Self::Relationship { .. } => DefinitionKind::Relationship,
            Self::Metric { .. } => DefinitionKind::Metric,
            Self::Filter { .. } => DefinitionKind::Filter,
        }
    }

    /// Tables this body touches.
    pub fn tables(&self) -> Vec<String> {
        match self {
            Self::Entity { table } | Self::Attribute { table, .. } | Self::Filter { table, .. } => {
                vec![table.clone()]
            }
            Self::Relationship {
                from_table,
                to_table,
                ..
            } => vec![from_table.clone(), to_table.clone()],
            Self::Metric { base_table, .. } => vec![base_table.clone()],
        }
    }
}

/// A column a definition depends on, with the type observed when it was defined.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ColumnDependency {
    pub table: String,
    /// `None` = the table itself must exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
}

/// Evidence for a definition (catalog object, FK constraint, routine touch, reviewer note).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Evidence {
    pub source_kind: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Qualitative evidence strength. Never a permission to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// Declared catalog structure (FK constraint, table, column).
    Declared,
    /// Compatible keys/types without a declared constraint.
    Structural,
    /// Naming similarity only.
    Naming,
    /// Supplied by a person without machine evidence.
    Manual,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionFlags {
    /// Touches a configured sensitive column. Never used as a filter or grouping dimension.
    #[serde(default)]
    pub sensitive: bool,
    /// Another definition shares the same normalized label.
    #[serde(default)]
    pub ambiguous: bool,
    /// Inferred (not declared) structure; requires explicit human review.
    #[serde(default)]
    pub inferred: bool,
}

/// One immutable version of a semantic definition. Only `status` changes after insertion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Definition {
    pub def_id: String,
    pub version: u32,
    pub tenant_id: String,
    pub connection: String,
    pub kind: DefinitionKind,
    pub name: String,
    #[serde(default)]
    pub synonyms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub body: DefinitionBody,
    #[serde(default)]
    pub depends_on: Vec<ColumnDependency>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    pub strength: EvidenceStrength,
    pub status: DefinitionStatus,
    #[serde(default)]
    pub flags: DefinitionFlags,
    pub content_hash: String,
    pub schema_fingerprint: String,
    pub proposed_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Definition {
    /// SHA-256 over the semantic content (kind, name, synonyms, description, body, dependencies).
    /// Status, version, evidence and timestamps are excluded so re-discovery is idempotent.
    pub fn compute_content_hash(&self) -> String {
        let mut synonyms = self.synonyms.clone();
        synonyms.sort();
        synonyms.dedup();
        let mut deps = self.depends_on.clone();
        deps.sort();
        let canonical = serde_json::json!({
            "kind": self.kind,
            "name": self.name,
            "synonyms": synonyms,
            "description": self.description,
            "body": self.body,
            "depends_on": deps,
        });
        sha256_hex(canonical.to_string().as_bytes())
    }

    pub fn reference(&self) -> DefinitionRef {
        DefinitionRef {
            def_id: self.def_id.clone(),
            version: self.version,
            content_hash: self.content_hash.clone(),
        }
    }
}

/// Pointer to one exact definition version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DefinitionRef {
    pub def_id: String,
    pub version: u32,
    pub content_hash: String,
}

/// Review actions available on the admin channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    Approve,
    Reject,
    Deprecate,
}

impl ReviewAction {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "approve" | "certify" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            "deprecate" => Some(Self::Deprecate),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Deprecate => "deprecate",
        }
    }
}

/// Reviewer sign-off bound to one exact artifact version and schema fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certification {
    pub cert_id: String,
    pub tenant_id: String,
    pub connection: String,
    pub def_id: String,
    pub version: u32,
    pub content_hash: String,
    pub schema_fingerprint: String,
    pub reviewer: String,
    pub reviewer_role: String,
    pub transport: String,
    pub action: ReviewAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub cert_hash: String,
    /// HMAC-SHA256 of `cert_hash` keyed with `ontology.review_key`, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl Certification {
    pub fn compute_cert_hash(&self) -> String {
        let payload = format!(
            "v1|tenant={}|conn={}|def={}|ver={}|content={}|schema={}|reviewer={}|action={}|at={}|exp={}",
            self.tenant_id,
            self.connection,
            self.def_id,
            self.version,
            self.content_hash,
            self.schema_fingerprint,
            self.reviewer.to_ascii_lowercase(),
            self.action.as_str(),
            self.at.to_rfc3339(),
            self.expires_at.to_rfc3339(),
        );
        sha256_hex(payload.as_bytes())
    }
}

/// Immutable published ontology snapshot used to pin plans.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyRevision {
    pub revision_id: String,
    pub tenant_id: String,
    pub connection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub seq: u64,
    pub content_hash: String,
    pub schema_fingerprint: String,
    pub def_refs: Vec<DefinitionRef>,
    pub published_by: String,
    pub published_at: DateTime<Utc>,
}

impl OntologyRevision {
    pub fn compute_content_hash(def_refs: &[DefinitionRef]) -> String {
        let mut refs = def_refs.to_vec();
        refs.sort();
        let joined = refs
            .iter()
            .map(|r| format!("{}@{}#{}", r.def_id, r.version, r.content_hash))
            .collect::<Vec<_>>()
            .join("|");
        sha256_hex(joined.as_bytes())
    }

    pub fn contains(&self, def: &Definition) -> bool {
        self.def_refs
            .iter()
            .any(|r| r.def_id == def.def_id && r.version == def.version && r.content_hash == def.content_hash)
    }
}

/// Record of a question answered (or refused) from the ontology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuestionEvidence {
    pub evidence_id: String,
    pub tenant_id: String,
    pub connection: String,
    pub question_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    pub def_refs: Vec<DefinitionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_hash: Option<String>,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned_rows: Option<usize>,
    pub principal: String,
    pub at: DateTime<Utc>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256 (RFC 2104) without an extra crate dependency.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    hex::encode(outer.finalize())
}

/// Lowercase, schema-free table name used for matching (`main.Orders` -> `orders`).
pub fn base_table_name(table: &str) -> String {
    table
        .rsplit('.')
        .next()
        .unwrap_or(table)
        .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
        .to_ascii_lowercase()
}

/// Stable slug used inside generated ids and SQL aliases.
pub fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut last_us = false;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_us = false;
        } else if !last_us && !out.is_empty() {
            out.push('_');
            last_us = true;
        }
    }
    out.trim_end_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn transition_table_is_explicit() {
        use DefinitionStatus::*;
        assert!(Proposed.can_transition_to(Certified));
        assert!(Certified.can_transition_to(Published));
        assert!(Published.can_transition_to(Stale));
        assert!(!Published.can_transition_to(Certified));
        assert!(!Rejected.can_transition_to(Published));
        assert!(!Stale.can_transition_to(Published));
        assert!(!Discovered.can_transition_to(Published));
    }

    #[test]
    fn cardinality_fan_out() {
        assert!(!Cardinality::ManyToOne.fans_out());
        assert!(Cardinality::ManyToOne.reversed().fans_out());
    }
}
