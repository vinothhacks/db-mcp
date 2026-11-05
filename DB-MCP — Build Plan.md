# DB-MCP MCP — Build Plan

A self-hosted Rust database MCP server that combines:

- **DBHub** — compact agent interface (schema search + bounded SQL execution)
- **Postgres MCP Pro** — PostgreSQL diagnostics (health, plans, index analysis)
- **Google MCP Toolbox for Databases** — declarative, configurable named tools
- **Bytebase MCP** — governance (identity, policy, approvals, changes, audit)

Target users: **coding agents** (self-hosted deployment, stdio + HTTP transports).

Investigation assistant: [REA](https://github.com/morluto/rea) — used during investigation and verification only, never as a production dependency or runtime component.

---

## 1. Product Boundary

> A locally deployable database control plane that lets coding agents discover schemas, execute bounded queries, diagnose PostgreSQL performance, invoke curated operations, and propose or execute governed database changes.

### Three distinct objectives

| Objective | Meaning |
|---|---|
| Native Rust implementation | MCP server, policy engine, execution pipeline, adapters, workflow services run in Rust |
| Self-hosted operation | Credentials, configuration, approval state, and audit storage remain under your control |
| Feature convergence | Reproduce selected capabilities from the four projects, with an explicit parity matrix (not an undefined promise of "everything") |

### Explicit non-goals / caveats

- Rust-only **dependency universe** is not required. Database servers, extensions, identity providers can remain external. A zero-non-Rust-runtime requirement is a separate constraint to document if needed.
- Self-hosted infrastructure ≠ model privacy. Results returned to a cloud-hosted coding agent still go to its model provider (REA's docs make the same local-vs-agent-provider distinction).
- Feature parity is continuing roadmap work, not an MVP claim — Toolbox covers many engines; Bytebase is a full governance platform.

---

## 2. Reference Feature Matrix

| Reference | Capabilities to study | Implementation destination |
|---|---|---|
| DBHub | Multi-connection config, schema search, progressive disclosure, SQL execution, explain/health (optional tools), parameterized custom tools, TLS/SSH, timeouts/limits | Core agent experience + connection layer |
| Postgres MCP Pro | Health diagnostics, query plans, workload/index analysis, hypothetical-index evaluation, restricted execution | PostgreSQL intelligence module |
| Google MCP Toolbox | Declarative tool definitions, database adapters, pooling, auth integration, OpenTelemetry | Tool registry + operational infra |
| Bytebase | Identity-scoped access, SQL review, approvals, change proposals, rollout state, masking, audit | Governance + change-control modules |

### Notes per reference

- **DBHub**: already includes optional explain and health tools beyond its two default tools — confirm exact tool surface at the pinned commit.
- **Postgres MCP Pro**: PostgreSQL-only; tuning/diagnostics are the real upgrade, not generic SQL.
- **Toolbox**: governs which *operations* agents can invoke; capability depends on the tools you expose.
- **Bytebase**: MCP is an interface to a larger platform. Masking and advanced approvals are **edition-dependent** (Enterprise). Never assume every write requires approval — verify the actual execution path.

### Capability tracking schema (the real scope definition)

```text
Capability ID
Reference project + pinned commit
Edition / license boundary
Database engines supported
Observed inputs and outputs
Required privileges / extensions
Error and cancellation behavior
Security assumptions
Rust implementation design
Acceptance tests
Parity status
```

Status flow: `Uninvestigated → Specified → Implemented → Verified → Released`

---

## 3. REA-Assisted Investigation Workflow

### Step A — Pin and isolate references

```text
reference/
  dbhub/
  postgres-mcp/
  mcp-toolbox/
  bytebase/

research/
  provenance/
  licenses/
  traces/
  contracts/
  fixtures/
  findings/
```

Per reference:

1. Pin a commit; record provenance.
2. Inventory licenses and third-party dependencies.
3. Start against disposable databases with synthetic data.
4. Record advertised MCP tools and schemas.
5. Exercise normal, invalid, cancelled, and unauthorized calls.
6. Trace implementation behind representative calls.

Source review comes first (all four publish source). Use REA where its static/runtime evidence adds something. REA's JS inspection workflow is directly relevant to JS artifacts; do **not** assume equivalent source-semantic analysis for Python or Go.

### Step B — Trace specific features, not entire products

Template investigation prompt:

```text
For the pinned <PROJECT> revision, trace <FEATURE> from MCP input
validation to database interaction and response formatting.

Produce:
- entry point and call path
- files and symbols
- query construction
- pagination and output limits
- permission checks
- error behavior
- test fixtures
- evidence and unresolved questions

Use source inspection first.
Use REA only where its supported analysis adds evidence.
Do not infer behavior that has not been observed or read.
```

Repeat for:

- [ ] DBHub `search_objects` (metadata queries, pagination, limits)
- [ ] DBHub execution path (timeouts, TLS/SSH, custom tools)
- [ ] Postgres MCP Pro index recommendations + hypothetical indexes
- [ ] Toolbox parameter binding and tool registration
- [ ] Bytebase proposal → review → execution transitions
- [ ] Cancellation and timeout behavior across all four

### Step C — Create contract fixtures

Per investigated feature, capture:

```text
Request
Caller identity and permissions
Database fixture
Expected response shape
Expected database effects
Expected audit events
Expected denied behavior
Known differences allowed in your implementation
```

Then implement Rust against the contracts.

### Role of REA in the architecture

```text
Development:
  References → source review / REA → contracts → Rust implementation

Production:
  Coding agent → Rust MCP server → policy → database
```

REA must **not** be part of the runtime request path.

### Licensing gate

Review licenses at pinned revisions before copying or porting code. Rust translation does not remove original obligations. Bytebase ships both `LICENSE` and `LICENSE.enterprise` — public source ≠ uniform reuse permission. Prefer independent implementation from documented requirements; get legal review where needed.

---

## 4. Rust Architecture

Start with a **modular monolith**, not microservices.

```text
Coding agents
    │
    ├── stdio: local development
    └── Streamable HTTP: shared self-hosted service
             │
      MCP transport / identity
             │
      Tool registry + validation
             │
      Policy and SQL analysis
             │
      Execution / change workflow
             │
      Database adapter interface
             │
      PostgreSQL / MySQL / SQLite / other engines

Cross-cutting:
  secrets · audit · telemetry · quotas · cancellation · result controls
```

Protocol foundation: official Rust MCP SDK **`rmcp`** (Tokio-based; pin a release, verify transports in compat tests).

### Proposed workspace

```text
crates/
  DB-MCP-server/          executable, configuration, lifecycle
  DB-MCP-mcp/             protocol handlers and tool schemas
  DB-MCP-core/            shared domain types and execution contracts
  DB-MCP-policy/          authorization, risk, approval requirements
  DB-MCP-sql/             dialect-aware parsing and classification
  DB-MCP-executor/        deadlines, transactions, cancellation, quotas
  DB-MCP-catalog/         schema discovery, snapshots, diffs
  DB-MCP-tools/           declarative parameterized tools
  DB-MCP-postgres/        PostgreSQL adapter
  DB-MCP-mysql/           MySQL/MariaDB adapter
  DB-MCP-sqlite/          SQLite adapter
  DB-MCP-pg-insights/     PostgreSQL health and tuning
  DB-MCP-changes/         proposals, approvals, rollout state
  DB-MCP-audit/           event persistence and export
  DB-MCP-secrets/         credential-provider abstraction

tests/
  contracts/
  integration/
  security/
  agents/
  performance/
```

Supporting candidates: Tokio, Serde, tracing, suitable HTTP stack. Evaluate DB drivers and SQL parsers via a short spike before committing — dialect coverage, cancellation, TLS, type fidelity, and maintenance matter more than one uniform library.

### Adapter design

```rust
trait DatabaseAdapter {
    fn capabilities(&self) -> DatabaseCapabilities;

    // Async signatures and streaming details omitted.
    fn discover(&self, request: CatalogRequest);
    fn execute(&self, request: AuthorizedQuery);
    fn explain(&self, request: ExplainRequest);
    fn cancel(&self, execution: ExecutionId);
}
```

Engine-specific extensions:

```text
PostgresHealthProvider
PostgresIndexAdvisor
SchemaDiffProvider
TransactionalDdlProvider
```

A capability registry tells the agent which features exist per connection — and why others are unavailable.

---

## 5. MCP Interface Design

Keep the baseline small; offer stable, explicit tool profiles.

| Profile | Tools |
|---|---|
| Explore | `list_connections`, `search_objects`, `describe_object` |
| Query | `execute_query`, `explain_query`, `run_named_tool` |
| Diagnose | `database_health`, `analyze_workload`, `recommend_indexes` |
| Change | `propose_change`, `get_change`, `apply_change` |
| Schema | `capture_schema`, `diff_schema` |

### Response shapes

Success:

```json
{
  "request_id": "req_123",
  "connection": "app-dev",
  "status": "ok",
  "columns": [],
  "rows": [],
  "returned_rows": 0,
  "truncated": false,
  "warnings": [],
  "schema_version": "snapshot_42"
}
```

Denial (actionable, no secret leakage):

```json
{
  "status": "denied",
  "code": "APPROVAL_REQUIRED",
  "message": "Production schema changes require an approved proposal.",
  "next_action": "propose_change"
}
```

### Interface requirements

- Progressive schema disclosure instead of dumping the entire catalog
- Explicit row, byte, and execution-time budgets
- Parameter binding for curated tools
- Structured errors with retryability
- Clear distinctions: empty result vs truncation vs failure vs cancellation
- Treat comments, object names, and row values as **untrusted data**, not agent instructions
- Database credentials never appear in tool responses or agent config

---

## 6. Governance as Part of the Execution Path

```text
Authenticate principal
  → authorize connection and operation
  → validate arguments
  → parse every statement using the correct dialect
  → classify effects and sensitive access
  → evaluate policy
  → require proposal / approval when necessary
  → acquire bounded connection
  → apply database-side restrictions
  → execute with deadline and cancellation
  → enforce result disclosure controls
  → persist completion audit event
```

### Operating modes

| Mode | Intended behavior |
|---|---|
| Development | Explicitly allowed writes on disposable or developer-owned databases |
| Read-only | Restricted DB role plus transaction/session controls |
| Governed production | Approved operations and reviewed changes, narrowly scoped exceptions |

Do not rely on keyword filters or the parser alone — combine semantic checks with database privileges and operational limits.

### Security acceptance tests

- Multi-statement requests
- Writes hidden in CTEs or routines
- Privileged / side-effecting functions
- Cross-schema and cross-connection access
- Tenant context leaking through pooled sessions
- Long-running queries and lock waits
- Cancellation that doesn't actually stop DB work
- Data disclosure through expressions, aliases, JSON, exports
- Approval replay and SQL changed after approval

### Approval binding

Bind approvals to the exact action:

```text
Hash of SQL + parameter values + target database identity
+ proposing principal + policy revision + relevant schema fingerprint
+ expiry + execution constraints
```

At execution time:

1. Recheck authorization
2. Check expiry and approval identity
3. Verify the proposal has not changed
4. Revalidate schema and policy assumptions
5. Atomically claim the approved execution
6. Execute and record the outcome

Rules:

- The coding agent must not approve its own production changes (separate admin interface or CLI).
- Do not promise universally reversible migrations — record whether each op is transactional, has a tested compensating migration, or needs backup-based recovery.

---

## 7. Masking as a Separate Security Project

Do **not** implement masking as "replace values in columns named email."

### Initial governed release

- Prefer database views and least-privilege roles
- Expose approved parameterized tools for sensitive data
- Deny unrestricted SQL where result provenance can't be determined safely
- Redact secrets from logs, plans, errors, audit payloads

### Later

Add broader result masking with explicit handling of derived expressions, aliases, aggregates, joins, engine-specific types.

Note: Bytebase's masking requires its Enterprise plan — reproducing its MCP endpoint grants nothing; this must be an independent implementation.

---

## 8. PostgreSQL Intelligence — Incremental Delivery

1. Schema and index inspection
2. Plain `EXPLAIN` collection + structured plan parsing
3. Health checks with findings and supporting evidence
4. Workload collection (where supported and authorized)
5. Heuristic index candidates
6. Hypothetical-index evaluation (where an approved extension is available)
7. Workload-aware ranking and regression validation

Every recommendation must include:

```text
Observed issue
Evidence and collection timestamp
Relevant queries
Suggested change
Estimated benefit and assumptions
Write/storage trade-offs
Required privileges/extensions
Validation procedure
Recovery considerations
```

Execution-based plan collection is a distinct permission, not a harmless explain variant. Never auto-create recommended indexes in production.

---

## 9. Phased Build Plan

Planning estimates (not commitments) — assumes two experienced Rust/backend engineers, agent assistance, part-time DB/security review.

| Phase | Est. duration | Deliverable | Exit gate |
|---|---:|---|---|
| 0. Investigation | 1–2 weeks | Pinned refs, license inventory, feature matrix, initial contracts | Representative end-to-end traces from all four |
| 1. Rust vertical slice | 2–3 weeks | MCP server, PG discovery + bounded read queries | Agent completes a real schema-to-code task |
| 2. Execution hardening | 2–3 weeks | Deadlines, cancellation, limits, audit, role isolation | Adversarial read-only tests pass |
| 3. Configurable tools + engines | 3–4 weeks | Named tools, MySQL/MariaDB + SQLite | Adapter contract suite passes |
| 4. PostgreSQL intelligence | 3–5 weeks | Health, plans, workload + index recommendations | Findings validated against controlled fixtures |
| 5. Governed changes | 4–6 weeks | Identity, policy, proposals, approvals, execution state | Approval replay + mutation tests pass |
| 6. Production hardening | 3–5 weeks | Deployment, backups, recovery drills, quotas, telemetry | Operational + security release review |

Work can overlap after the first vertical slice.

### First usable milestone

```text
One Rust executable
PostgreSQL support
stdio and authenticated HTTP deployment paths
Schema search and object inspection
Bounded read-only query execution
Plain explain
Parameterized named tools
Structured audit events
Container deployment
Coding-agent compatibility tests
```

---

## 10. Coding-Agent Organization

### Agent roles

| Role | Responsibility |
|---|---|
| Investigator | Source tracing and REA-backed evidence |
| Contract author | Behavioral specifications and fixtures |
| Rust implementer | One module or adapter at a time |
| Security reviewer | Adversarial tests and authorization review |
| Integration evaluator | Reference comparisons and agent task evaluation |

Keep final review of sensitive governance features outside the agent that wrote them.

### Repository rules

```text
No unsupported feature-parity claims.
No source copying without license/provenance review.
Every tool must have authorization, limits, cancellation semantics,
and audit behavior documented.
Every fix must add a regression test.
Unknown dialect behavior fails closed in governed mode.
Database output is untrusted content.
No production write capability enabled by default.
```

### Evaluation (outcomes, not just protocol correctness)

- Contract tests vs pinned reference behavior (where equivalence intended)
- Integration tests against real database instances
- Property/fuzz tests for SQL classification and policy boundaries
- Crash tests around approval + execution state transitions
- Agent tasks (e.g. "inspect schema and implement a correct repository method")
- Performance: tool-definition tokens, schema-discovery tokens, latency, pool saturation, cancellation delay, audit overhead

Set benchmark targets after measuring a baseline. Rust alone is not evidence of better performance.

---

## 11. Starting Decision

Build **PostgreSQL-first**, with a multi-engine adapter boundary from day one. Preserve DBHub's compact interaction style; add Toolbox-like named operations; then layer PostgreSQL diagnostics and independently implemented governance.

First concrete deliverable — evidence-backed spec + one working Rust vertical slice:

```text
Agent discovers a table
  → inspects columns and indexes
  → runs a bounded parameterized read
  → receives structured results
  → leaves an attributable audit trail
```

Once that path is reliable, expand into diagnosis and reviewed changes.
