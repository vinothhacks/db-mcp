# DB-MCP governed ontology: security model

## Trust boundaries

| Actor | Can | Cannot |
|---|---|---|
| Agent (MCP, any role) | discover candidates, propose drafts, search, describe, plan, ask | certify, reject, publish, run untyped SQL through the ontology |
| Reviewer (CLI or `/admin/ontology/*` with admin token, role admin/dba) | certify / reject / deprecate one exact version, publish | certify a definition they proposed or whose discovery run they started |
| Server | verify certifications at plan time, mark drifted definitions stale | execute anything outside the governed executor |

## Controls

- **Separation of duties.** Review requires `role` admin or dba, a non-agent role, and a principal
  different from `proposed_by` (case-insensitive). Violations return `SELF_APPROVAL_FORBIDDEN` and
  are audited.
- **No agent-visible review path.** The 8 ontology MCP tools contain no review or publish
  operation. HTTP admin endpoints require `http.admin_token` and return `403
  ADMIN_TOKEN_NOT_CONFIGURED` when it is not set, so a missing token never opens them.
- **Certification binding.** `cert_hash = sha256(v1|tenant|connection|def_id|version|content_hash|
  schema_fingerprint|reviewer|action|at|expires_at)`. When `ontology.review_key` is configured the
  hash is also HMAC-SHA256 signed, so a forged row written directly into the store fails
  verification. Without a key, integrity relies on store file permissions.
- **Fail closed at use time.** Every plan re-checks content hash, certification hash, HMAC, expiry
  and reviewer != proposer for each definition it uses (`ONTOLOGY_CERTIFICATION_INVALID`).
- **Typed bodies, validated SQL.** Definitions store table/column names, aggregations and filter
  operators, never SQL text. Compiled statements must be a single read-only `SELECT` over exactly
  the plan's tables, with no privileged functions; literal filter values are bound parameters.
- **Restricted tables** are removed before discovery, search, describe, relationship tracing and
  planning. Proposals referencing them fail with `ONTOLOGY_UNKNOWN_OBJECT`.
- **Sensitive columns** may be described as attributes (flagged `sensitive`) but cannot be used as
  filters, metrics, join keys or grouping dimensions. Result redaction still applies at execution.
- **Drift.** Dropped, renamed or retyped dependencies mark definitions `stale`; stale definitions
  never generate SQL, publish is refused while certified content is stale, and a pinned
  `plan_hash` stops matching (`ONTOLOGY_PLAN_MISMATCH`).
- **Untrusted text.** Catalog comments and routine bodies are stored as evidence/description and
  returned under `_meta.provenance.untrusted_content = true`; they never influence SQL.
- **Audit.** Every ontology tool call, denial, review and publish is recorded (tool names
  `ontology_review:<action>`, `ontology_publish`, `ask_semantic_question:<metric>`), with
  literal-free SQL fingerprints.
- **No egress.** Discovery and planning are deterministic and local. The binary contains no HTTP
  client or model SDK (see `research/findings/ontology-rea-verification.md`).

## Residual risks

- Over HTTP, `x-mcp-principal` / `x-mcp-role` are asserted by whoever holds the agent bearer token.
  Review is therefore restricted to the admin token and the CLI, not to MCP roles.
- The admin token is shared: separation of duties distinguishes reviewer *names*, not individual
  credentials. Use per-person tokens behind a gateway if that matters.
- Without `review_key`, anyone with write access to the ontology SQLite file can forge a
  consistent certification. Set `review_key` in production and keep the store private.
- Lexical planning can pick a certified metric for a loosely phrased question; plans always state
  the chosen definitions and alternatives so the agent or user can check them.
