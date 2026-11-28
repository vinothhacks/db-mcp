//! Proposal, certification, publishing and schema-drift invalidation.
//!
//! Separation of duties: reviewers must hold an admin/dba role, must not be an agent principal,
//! and can never review a definition they (or a discovery run they started) proposed.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Duration, Utc};
use db_mcp_core::{CallerIdentity, CatalogObject, CatalogObjectType, DbMcpError, DbMcpResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::discovery::{is_sensitive, types_compatible};
use crate::model::{
    base_table_name, hmac_sha256_hex, slug, Certification, ColumnDependency, Definition,
    DefinitionBody, DefinitionFlags, DefinitionKind, DefinitionRef, DefinitionStatus, Evidence,
    EvidenceStrength, OntologyRevision, ReviewAction,
};
use crate::store::OntologyStore;

/// Service options derived from `[ontology]` config.
#[derive(Debug, Clone)]
pub struct GovernanceOptions {
    pub tenant_id: String,
    /// Resolved HMAC key for certifications (from `ontology.review_key`).
    pub review_key: Option<Vec<u8>>,
    pub certification_ttl_days: i64,
}

impl Default for GovernanceOptions {
    fn default() -> Self {
        Self {
            tenant_id: "default".to_string(),
            review_key: None,
            certification_ttl_days: 180,
        }
    }
}

/// Agent-supplied draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalInput {
    /// Existing definition to revise; `None` creates a new id from kind + name.
    #[serde(default)]
    pub def_id: Option<String>,
    /// Required when revising: optimistic concurrency guard.
    #[serde(default)]
    pub expected_version: Option<u32>,
    pub name: String,
    #[serde(default)]
    pub synonyms: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub body: DefinitionBody,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MergeReport {
    pub inserted: usize,
    pub new_versions: usize,
    pub unchanged: usize,
    /// Candidates differing from certified/published content: stored as a new `Discovered`
    /// version for review; the certified version stays in force.
    pub pending_review_changes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftReport {
    pub checked: usize,
    pub newly_stale: Vec<StaleDefinition>,
    pub already_stale: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaleDefinition {
    pub def_id: String,
    pub version: u32,
    pub reasons: Vec<String>,
}

/// Governance façade over the store.
#[derive(Debug, Clone)]
pub struct OntologyService {
    pub store: OntologyStore,
    pub options: GovernanceOptions,
}

fn denied(code: &str, message: impl Into<String>, next: Option<&str>) -> DbMcpError {
    DbMcpError::PolicyDenied {
        code: code.to_string(),
        message: message.into(),
        next_action: next.map(ToOwned::to_owned),
    }
}

fn find_table<'a>(objects: &'a [CatalogObject], table: &str) -> Option<&'a CatalogObject> {
    let t = table.trim_matches('"').to_ascii_lowercase();
    objects
        .iter()
        .filter(|o| {
            matches!(
                o.object_type,
                CatalogObjectType::Table
                    | CatalogObjectType::View
                    | CatalogObjectType::MaterializedView
            )
        })
        .find(|o| o.qualified_name().eq_ignore_ascii_case(&t))
        .or_else(|| {
            objects
                .iter()
                .filter(|o| {
                    matches!(
                        o.object_type,
                        CatalogObjectType::Table
                            | CatalogObjectType::View
                            | CatalogObjectType::MaterializedView
                    )
                })
                .find(|o| o.name.eq_ignore_ascii_case(&base_table_name(&t)))
        })
}

impl OntologyService {
    pub fn new(store: OntologyStore, options: GovernanceOptions) -> Self {
        Self { store, options }
    }

    fn tenant(&self) -> &str {
        &self.options.tenant_id
    }

    /// Store discovery candidates idempotently. Certified/published content is never replaced.
    pub fn merge_discovered(&self, candidates: Vec<Definition>) -> DbMcpResult<MergeReport> {
        let mut report = MergeReport::default();
        for mut cand in candidates {
            let versions = self
                .store
                .versions(self.tenant(), &cand.connection, &cand.def_id)?;
            match versions.last() {
                None => {
                    cand.version = 1;
                    self.store.insert_definition(&cand)?;
                    report.inserted += 1;
                }
                Some(latest) => {
                    if versions.iter().any(|v| v.content_hash == cand.content_hash) {
                        report.unchanged += 1;
                        continue;
                    }
                    let protected = versions.iter().any(|v| {
                        matches!(
                            v.status,
                            DefinitionStatus::Certified
                                | DefinitionStatus::Published
                                | DefinitionStatus::Proposed
                                | DefinitionStatus::InReview
                        )
                    });
                    cand.version = latest.version + 1;
                    self.store.insert_definition(&cand)?;
                    if protected {
                        report.pending_review_changes += 1;
                    } else {
                        report.new_versions += 1;
                    }
                }
            }
        }
        Ok(report)
    }

    /// Validate a draft against the policy-visible catalog and compute its dependencies.
    pub fn validate_body(
        &self,
        body: &DefinitionBody,
        objects: &[CatalogObject],
        sensitive_columns: &[String],
    ) -> DbMcpResult<(Vec<ColumnDependency>, DefinitionFlags, String)> {
        let mut deps = Vec::new();
        let mut flags = DefinitionFlags::default();
        let mut column = |table: &str, col: &str, role: &str| -> DbMcpResult<(String, String)> {
            let obj = find_table(objects, table).ok_or_else(|| {
                denied(
                    "ONTOLOGY_UNKNOWN_OBJECT",
                    format!("Table '{table}' does not exist or is restricted on this connection"),
                    Some("search_objects"),
                )
            })?;
            let q = obj.qualified_name();
            let spec = obj
                .columns
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(col))
                .ok_or_else(|| {
                    denied(
                        "ONTOLOGY_UNKNOWN_OBJECT",
                        format!("Column '{col}' does not exist on '{q}'"),
                        Some("describe_object"),
                    )
                })?;
            if is_sensitive(&q, &spec.name, sensitive_columns) {
                if role != "attribute" {
                    return Err(denied(
                        "ONTOLOGY_SENSITIVE_COLUMN",
                        format!(
                            "Sensitive column '{q}.{}' cannot be used as {role}",
                            spec.name
                        ),
                        None,
                    ));
                }
                flags.sensitive = true;
            }
            deps.push(ColumnDependency {
                table: q.clone(),
                column: Some(spec.name.clone()),
                data_type: Some(spec.data_type.clone()),
            });
            Ok((q, spec.data_type.clone()))
        };
        let canonical_table =
            |table: &str| -> DbMcpResult<String> {
                find_table(objects, table)
                    .map(|o| o.qualified_name())
                    .ok_or_else(|| {
                        denied(
                    "ONTOLOGY_UNKNOWN_OBJECT",
                    format!("Table '{table}' does not exist or is restricted on this connection"),
                    Some("search_objects"),
                )
                    })
            };
        let normalized_table: String;
        match body {
            DefinitionBody::Entity { table } => {
                normalized_table = canonical_table(table)?;
                deps.push(ColumnDependency {
                    table: normalized_table.clone(),
                    column: None,
                    data_type: None,
                });
            }
            DefinitionBody::Attribute {
                table, column: c, ..
            } => {
                normalized_table = column(table, c, "attribute")?.0;
            }
            DefinitionBody::Filter {
                table,
                column: c,
                operator,
                value,
            } => {
                normalized_table = column(table, c, "filter")?.0;
                let needs_value = !matches!(
                    operator,
                    crate::model::FilterOp::IsNull | crate::model::FilterOp::IsNotNull
                );
                if needs_value && value.is_null() {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        "Filter requires a value",
                        None,
                    ));
                }
                if matches!(operator, crate::model::FilterOp::In) && !value.is_array() {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        "IN filter requires an array value",
                        None,
                    ));
                }
                if value.is_object()
                    || value
                        .as_array()
                        .map(|a| a.iter().any(|v| v.is_object() || v.is_array()))
                        .unwrap_or(false)
                {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        "Filter values must be scalars",
                        None,
                    ));
                }
            }
            DefinitionBody::Metric {
                base_table,
                aggregation,
                column: c,
                ..
            } => {
                normalized_table = canonical_table(base_table)?;
                match c {
                    Some(c) => {
                        column(base_table, c, "metric")?;
                    }
                    None => {
                        if !matches!(aggregation, crate::model::Aggregation::Count) {
                            return Err(denied(
                                "ONTOLOGY_INVALID_DEFINITION",
                                "Only COUNT may omit the metric column",
                                None,
                            ));
                        }
                        deps.push(ColumnDependency {
                            table: normalized_table.clone(),
                            column: None,
                            data_type: None,
                        });
                    }
                }
            }
            DefinitionBody::Relationship {
                from_table,
                to_table,
                column_pairs,
                ..
            } => {
                if column_pairs.is_empty() {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        "Relationship needs at least one column pair",
                        None,
                    ));
                }
                normalized_table = canonical_table(from_table)?;
                for (fc, tc) in column_pairs {
                    let (_, ft) = column(from_table, fc, "join key")?;
                    let (_, tt) = column(to_table, tc, "join key")?;
                    if !types_compatible(&ft, &tt) {
                        return Err(denied(
                            "ONTOLOGY_INVALID_DEFINITION",
                            format!("Join key types are incompatible: {ft} vs {tt}"),
                            None,
                        ));
                    }
                }
            }
        }
        deps.sort();
        deps.dedup();
        Ok((deps, flags, normalized_table))
    }

    /// Rewrite table and column references to their catalog spelling (`orders` -> `main.orders`)
    /// so proposals and discovered definitions share one identity.
    pub fn canonicalize_body(
        &self,
        body: &DefinitionBody,
        objects: &[CatalogObject],
    ) -> DbMcpResult<DefinitionBody> {
        let table = |t: &str| -> DbMcpResult<&CatalogObject> {
            find_table(objects, t).ok_or_else(|| {
                denied(
                    "ONTOLOGY_UNKNOWN_OBJECT",
                    format!("Table '{t}' does not exist or is restricted on this connection"),
                    Some("search_objects"),
                )
            })
        };
        let col = |obj: &CatalogObject, c: &str| -> String {
            obj.columns
                .iter()
                .find(|x| x.name.eq_ignore_ascii_case(c))
                .map(|x| x.name.clone())
                .unwrap_or_else(|| c.to_string())
        };
        Ok(match body {
            DefinitionBody::Entity { table: t } => DefinitionBody::Entity {
                table: table(t)?.qualified_name(),
            },
            DefinitionBody::Attribute {
                table: t,
                column,
                unit,
            } => {
                let o = table(t)?;
                DefinitionBody::Attribute {
                    table: o.qualified_name(),
                    column: col(o, column),
                    unit: unit.clone(),
                }
            }
            DefinitionBody::Filter {
                table: t,
                column,
                operator,
                value,
            } => {
                let o = table(t)?;
                DefinitionBody::Filter {
                    table: o.qualified_name(),
                    column: col(o, column),
                    operator: *operator,
                    value: value.clone(),
                }
            }
            DefinitionBody::Metric {
                base_table,
                aggregation,
                column,
                default_filters,
                unit,
                grain,
            } => {
                let o = table(base_table)?;
                DefinitionBody::Metric {
                    base_table: o.qualified_name(),
                    aggregation: *aggregation,
                    column: column.as_ref().map(|c| col(o, c)),
                    default_filters: default_filters.clone(),
                    unit: unit.clone(),
                    grain: grain.clone(),
                }
            }
            DefinitionBody::Relationship {
                from_table,
                to_table,
                column_pairs,
                cardinality,
                source,
            } => {
                let f = table(from_table)?;
                let t = table(to_table)?;
                DefinitionBody::Relationship {
                    from_table: f.qualified_name(),
                    to_table: t.qualified_name(),
                    column_pairs: column_pairs
                        .iter()
                        .map(|(a, b)| (col(f, a), col(t, b)))
                        .collect(),
                    cardinality: *cardinality,
                    // Agent drafts are manual unless they reproduce a declared FK verbatim.
                    source: match source {
                        crate::model::RelationshipSource::DeclaredFk => {
                            crate::model::RelationshipSource::Manual
                        }
                        other => *other,
                    },
                }
            }
        })
    }

    /// Record an agent draft as `Proposed` (new definition or new version of an existing one).
    pub fn propose(
        &self,
        caller: &CallerIdentity,
        connection: &str,
        input: ProposalInput,
        objects: &[CatalogObject],
        sensitive_columns: &[String],
        schema_fingerprint: &str,
    ) -> DbMcpResult<Definition> {
        let name = input.name.trim().to_string();
        if name.is_empty() || name.len() > 200 {
            return Err(DbMcpError::InvalidArgument(
                "definition name must be 1-200 characters".to_string(),
            ));
        }
        if input.synonyms.len() > 50 || input.synonyms.iter().any(|s| s.len() > 200) {
            return Err(DbMcpError::InvalidArgument(
                "at most 50 synonyms of up to 200 characters".to_string(),
            ));
        }
        let mut input = input;
        input.body = self.canonicalize_body(&input.body, objects)?;
        let (mut deps, flags, _) = self.validate_body(&input.body, objects, sensitive_columns)?;
        let kind = input.body.kind();
        if let DefinitionBody::Metric {
            default_filters, ..
        } = &input.body
        {
            for f in default_filters {
                let filter = self
                    .store
                    .latest(self.tenant(), connection, f)?
                    .ok_or_else(|| {
                        denied(
                            "ONTOLOGY_UNKNOWN_OBJECT",
                            format!("Default filter '{f}' does not exist"),
                            Some("search_terms"),
                        )
                    })?;
                if filter.kind != DefinitionKind::Filter {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        format!("'{f}' is not a filter"),
                        None,
                    ));
                }
                deps.extend(filter.depends_on.clone());
            }
            deps.sort();
            deps.dedup();
        }
        let (def_id, version) = match &input.def_id {
            Some(id) => {
                let latest = self
                    .store
                    .latest(self.tenant(), connection, id)?
                    .ok_or_else(|| {
                        denied(
                            "ONTOLOGY_UNKNOWN_OBJECT",
                            format!("Definition '{id}' does not exist"),
                            Some("search_terms"),
                        )
                    })?;
                if latest.kind != kind {
                    return Err(denied(
                        "ONTOLOGY_INVALID_DEFINITION",
                        "A revision cannot change the definition kind",
                        None,
                    ));
                }
                match input.expected_version {
                    Some(v) if v == latest.version => (id.clone(), latest.version + 1),
                    Some(v) => {
                        return Err(denied(
                            "ONTOLOGY_VERSION_CONFLICT",
                            format!(
                                "expected_version {v} but '{id}' is at version {}",
                                latest.version
                            ),
                            Some("describe_term"),
                        ))
                    }
                    None => {
                        return Err(DbMcpError::InvalidArgument(
                            "expected_version is required when revising an existing definition"
                                .to_string(),
                        ))
                    }
                }
            }
            None => {
                let id = format!("{}:{}", kind.as_str(), slug(&name));
                if let Some(existing) = self.store.latest(self.tenant(), connection, &id)? {
                    return Err(denied(
                        "ONTOLOGY_VERSION_CONFLICT",
                        format!("Definition '{id}' already exists at version {}; pass def_id and expected_version to revise it", existing.version),
                        Some("describe_term"),
                    ));
                }
                (id, 1)
            }
        };
        let now = Utc::now();
        let mut def = Definition {
            def_id,
            version,
            tenant_id: self.tenant().to_string(),
            connection: connection.to_string(),
            kind,
            name,
            synonyms: input
                .synonyms
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            description: input.description,
            body: input.body,
            depends_on: deps,
            evidence: vec![Evidence {
                source_kind: "proposal".to_string(),
                reference: caller.principal.clone(),
                detail: Some(format!(
                    "proposed via {} by role {}",
                    caller.transport, caller.role
                )),
            }],
            strength: EvidenceStrength::Manual,
            status: DefinitionStatus::Proposed,
            flags,
            content_hash: String::new(),
            schema_fingerprint: schema_fingerprint.to_string(),
            proposed_by: caller.principal.clone(),
            created_at: now,
            updated_at: now,
        };
        def.content_hash = def.compute_content_hash();
        self.store.insert_definition(&def)?;
        Ok(def)
    }

    fn ensure_reviewer(&self, reviewer: &CallerIdentity, def: &Definition) -> DbMcpResult<()> {
        if reviewer.is_agent() || !reviewer.is_admin() {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "Principal '{}' with role '{}' cannot review ontology definitions; an admin or dba reviewer is required",
                reviewer.principal, reviewer.role
            )));
        }
        if def.proposed_by.eq_ignore_ascii_case(&reviewer.principal) {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "'{}' proposed {} v{} and cannot review it",
                reviewer.principal, def.def_id, def.version
            )));
        }
        Ok(())
    }

    /// Approve (certify), reject or deprecate one exact definition version.
    pub fn review(
        &self,
        reviewer: &CallerIdentity,
        connection: &str,
        def_id: &str,
        version: u32,
        action: ReviewAction,
        reason: Option<String>,
    ) -> DbMcpResult<(Definition, Certification)> {
        let def = self
            .store
            .get_version(self.tenant(), connection, def_id, version)?
            .ok_or_else(|| {
                denied(
                    "ONTOLOGY_UNKNOWN_OBJECT",
                    format!("Definition '{def_id}' v{version} not found on '{connection}'"),
                    None,
                )
            })?;
        self.ensure_reviewer(reviewer, &def)?;
        if def.content_hash != def.compute_content_hash() {
            return Err(DbMcpError::ApprovalHashMismatch(format!(
                "Stored content of {def_id} v{version} does not match its content hash"
            )));
        }
        let target = match action {
            ReviewAction::Approve => {
                if !def.status.is_reviewable() {
                    return Err(denied(
                        "ONTOLOGY_INVALID_TRANSITION",
                        format!(
                            "{def_id} v{version} is {} and cannot be approved",
                            def.status.as_str()
                        ),
                        None,
                    ));
                }
                DefinitionStatus::Certified
            }
            ReviewAction::Reject => DefinitionStatus::Rejected,
            ReviewAction::Deprecate => DefinitionStatus::Deprecated,
        };
        let updated = self.store.transition(
            self.tenant(),
            connection,
            def_id,
            version,
            def.status,
            target,
        )?;
        let now = Utc::now();
        let mut cert = Certification {
            cert_id: format!("cert_{}", Uuid::new_v4().simple()),
            tenant_id: self.tenant().to_string(),
            connection: connection.to_string(),
            def_id: def_id.to_string(),
            version,
            content_hash: def.content_hash.clone(),
            schema_fingerprint: def.schema_fingerprint.clone(),
            reviewer: reviewer.principal.clone(),
            reviewer_role: reviewer.role.clone(),
            transport: reviewer.transport.clone(),
            action,
            reason,
            at: now,
            expires_at: now + Duration::days(self.options.certification_ttl_days.max(1)),
            cert_hash: String::new(),
            hmac: None,
        };
        cert.cert_hash = cert.compute_cert_hash();
        cert.hmac = self
            .options
            .review_key
            .as_ref()
            .map(|k| hmac_sha256_hex(k, cert.cert_hash.as_bytes()));
        self.store.insert_certification(&cert)?;
        Ok((updated, cert))
    }

    /// Verify the approval behind a certified/published version (hash, HMAC, expiry, reviewer).
    pub fn verify_certification(&self, def: &Definition) -> DbMcpResult<Certification> {
        let certs = self
            .store
            .certifications(self.tenant(), &def.connection, &def.def_id)?;
        let cert = certs
            .into_iter()
            .filter(|c| c.version == def.version && c.action == ReviewAction::Approve)
            .last()
            .ok_or_else(|| {
                denied(
                    "ONTOLOGY_CERTIFICATION_INVALID",
                    format!("{} v{} has no approval record", def.def_id, def.version),
                    Some("Ask a reviewer to certify it: db-mcp ontology review"),
                )
            })?;
        let invalid = |why: &str| {
            denied(
                "ONTOLOGY_CERTIFICATION_INVALID",
                format!(
                    "Certification of {} v{} is invalid: {why}",
                    def.def_id, def.version
                ),
                Some("Re-certify the definition"),
            )
        };
        if cert.content_hash != def.content_hash || def.content_hash != def.compute_content_hash() {
            return Err(invalid("content changed after certification"));
        }
        if cert.cert_hash != cert.compute_cert_hash() {
            return Err(invalid("certification record was altered"));
        }
        if let Some(key) = &self.options.review_key {
            match &cert.hmac {
                Some(h) if *h == hmac_sha256_hex(key, cert.cert_hash.as_bytes()) => {}
                _ => return Err(invalid("HMAC signature missing or wrong")),
            }
        }
        if cert.expires_at < Utc::now() {
            return Err(invalid("certification expired"));
        }
        if cert.reviewer.eq_ignore_ascii_case(&def.proposed_by) {
            return Err(invalid("reviewer equals proposer"));
        }
        Ok(cert)
    }

    /// Publish every certified definition (plus still-valid published ones) as a new revision.
    pub fn publish(
        &self,
        reviewer: &CallerIdentity,
        connection: &str,
        schema_fingerprint: Option<&str>,
    ) -> DbMcpResult<OntologyRevision> {
        if reviewer.is_agent() || !reviewer.is_admin() {
            return Err(DbMcpError::SelfApprovalForbidden(format!(
                "Principal '{}' with role '{}' cannot publish the ontology",
                reviewer.principal, reviewer.role
            )));
        }
        let all = self.store.all_versions(self.tenant(), connection)?;
        let mut by_id: BTreeMap<String, Vec<Definition>> = BTreeMap::new();
        for d in all {
            by_id.entry(d.def_id.clone()).or_default().push(d);
        }
        let mut transitions: Vec<(String, u32, DefinitionStatus, DefinitionStatus)> = Vec::new();
        let mut refs: Vec<DefinitionRef> = Vec::new();
        let mut fingerprints: BTreeMap<String, usize> = BTreeMap::new();
        for (def_id, versions) in by_id {
            let newest_certified = versions
                .iter()
                .filter(|v| v.status == DefinitionStatus::Certified)
                .max_by_key(|v| v.version);
            let published = versions
                .iter()
                .filter(|v| v.status == DefinitionStatus::Published)
                .max_by_key(|v| v.version);
            let chosen = match (newest_certified, published) {
                (Some(c), Some(p)) if c.version > p.version => {
                    transitions.push((
                        def_id.clone(),
                        p.version,
                        DefinitionStatus::Published,
                        DefinitionStatus::Deprecated,
                    ));
                    Some(c)
                }
                (Some(c), None) => Some(c),
                (_, Some(p)) => Some(p),
                (None, None) => None,
            };
            let Some(chosen) = chosen else { continue };
            self.verify_certification(chosen)?;
            if chosen.status == DefinitionStatus::Certified {
                transitions.push((
                    def_id.clone(),
                    chosen.version,
                    DefinitionStatus::Certified,
                    DefinitionStatus::Published,
                ));
            }
            *fingerprints
                .entry(chosen.schema_fingerprint.clone())
                .or_default() += 1;
            refs.push(chosen.reference());
        }
        if refs.is_empty() {
            return Err(denied(
                "ONTOLOGY_NOTHING_TO_PUBLISH",
                format!("No certified definitions on '{connection}'"),
                Some("Review definitions first: db-mcp ontology review"),
            ));
        }
        refs.sort();
        let previous = self.store.latest_revision(self.tenant(), connection)?;
        let content_hash = OntologyRevision::compute_content_hash(&refs);
        if let Some(prev) = &previous {
            if prev.content_hash == content_hash && transitions.is_empty() {
                return Ok(prev.clone());
            }
        }
        let fingerprint = schema_fingerprint
            .map(ToOwned::to_owned)
            .or_else(|| {
                fingerprints
                    .into_iter()
                    .max_by_key(|(_, n)| *n)
                    .map(|(f, _)| f)
            })
            .unwrap_or_default();
        let revision = OntologyRevision {
            revision_id: format!("rev_{}", &Uuid::new_v4().simple().to_string()[..16]),
            tenant_id: self.tenant().to_string(),
            connection: connection.to_string(),
            parent: previous.as_ref().map(|p| p.revision_id.clone()),
            seq: previous.as_ref().map(|p| p.seq).unwrap_or(0) + 1,
            content_hash,
            schema_fingerprint: fingerprint,
            def_refs: refs,
            published_by: reviewer.principal.clone(),
            published_at: Utc::now(),
        };
        self.store.publish_atomically(&transitions, &revision)?;
        Ok(revision)
    }

    /// Mark certified/published definitions whose dependencies vanished or changed type as `Stale`.
    pub fn check_drift(
        &self,
        connection: &str,
        objects: &[CatalogObject],
    ) -> DbMcpResult<DriftReport> {
        let mut report = DriftReport {
            checked: 0,
            newly_stale: Vec::new(),
            already_stale: 0,
        };
        for status in [DefinitionStatus::Published, DefinitionStatus::Certified] {
            for def in self.store.by_status(self.tenant(), connection, status)? {
                report.checked += 1;
                let reasons = dependency_problems(&def.depends_on, objects);
                if reasons.is_empty() {
                    continue;
                }
                // A concurrent transition (another request marked it stale first) is not an error.
                if self
                    .store
                    .transition(
                        self.tenant(),
                        connection,
                        &def.def_id,
                        def.version,
                        def.status,
                        DefinitionStatus::Stale,
                    )
                    .is_ok()
                {
                    report.newly_stale.push(StaleDefinition {
                        def_id: def.def_id.clone(),
                        version: def.version,
                        reasons,
                    });
                }
            }
        }
        let total_stale = self
            .store
            .by_status(self.tenant(), connection, DefinitionStatus::Stale)?
            .len();
        report.already_stale = total_stale.saturating_sub(report.newly_stale.len());
        Ok(report)
    }

    /// Published definitions belonging to the latest revision (fails closed on any invalid one).
    pub fn published_set(
        &self,
        connection: &str,
    ) -> DbMcpResult<(Option<OntologyRevision>, Vec<Definition>, Vec<Definition>)> {
        let revision = self.store.latest_revision(self.tenant(), connection)?;
        let Some(rev) = revision else {
            return Ok((None, Vec::new(), Vec::new()));
        };
        let wanted: BTreeSet<(String, u32)> = rev
            .def_refs
            .iter()
            .map(|r| (r.def_id.clone(), r.version))
            .collect();
        let mut live = Vec::new();
        let mut stale = Vec::new();
        for def in self.store.all_versions(self.tenant(), connection)? {
            if !wanted.contains(&(def.def_id.clone(), def.version)) {
                continue;
            }
            match def.status {
                DefinitionStatus::Published if rev.contains(&def) => live.push(def),
                DefinitionStatus::Stale => stale.push(def),
                _ => {}
            }
        }
        Ok((Some(rev), live, stale))
    }
}

/// Explain why dependencies no longer hold against the current catalog.
pub fn dependency_problems(deps: &[ColumnDependency], objects: &[CatalogObject]) -> Vec<String> {
    let mut problems = Vec::new();
    for dep in deps {
        let Some(table) = find_table(objects, &dep.table) else {
            problems.push(format!(
                "table {} no longer exists (or is now restricted)",
                dep.table
            ));
            continue;
        };
        if let Some(col) = &dep.column {
            match table
                .columns
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(col))
            {
                None => problems.push(format!("column {}.{} no longer exists", dep.table, col)),
                Some(spec) => {
                    if let Some(expected) = &dep.data_type {
                        if !spec.data_type.trim().eq_ignore_ascii_case(expected.trim()) {
                            problems.push(format!(
                                "column {}.{} changed type {} -> {}",
                                dep.table, col, expected, spec.data_type
                            ));
                        }
                    }
                }
            }
        }
    }
    problems
}
