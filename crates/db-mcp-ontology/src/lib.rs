//! DB-MCP governed ontology (semantic layer).
//!
//! A versioned, certified control plane over the existing catalog and executor:
//! - [`discovery`] extracts deterministic candidates from the policy-filtered catalog;
//! - [`governance`] handles proposals, human certification, publishing and drift invalidation;
//! - [`retrieval`] ranks terms lexically (no embeddings, no network);
//! - [`compiler`] turns a question into a validated, parameterized SQL plan using only the
//!   pinned published revision; execution stays with the governed executor;
//! - [`eval`] scores golden question sets with hard refusal gates.

pub mod compiler;
pub mod discovery;
pub mod eval;
pub mod governance;
pub mod model;
pub mod retrieval;
pub mod store;

pub use compiler::{plan, validate_generated_sql, PlanRequest, PlanStatus, SemanticPlan};
pub use discovery::{discover, DiscoveryReport, DiscoveryScope};
pub use eval::{evaluate, EvalReport, GoldenCase};
pub use governance::{DriftReport, GovernanceOptions, MergeReport, OntologyService, ProposalInput};
pub use model::*;
pub use retrieval::{rank, tokenize, ScoredDefinition};
pub use store::OntologyStore;
