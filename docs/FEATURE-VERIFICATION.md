# Feature verification report (2026-11-06)

Independent black-box verification of DB-MCP, one tester per feature, against the release binary on Windows 11
(SQLite live; PostgreSQL and MySQL via the embedded offline simulation). Each tester wrote a self-contained suite under
`npm/test/features/`; checks that encode correct behaviour but currently fail are tagged `KNOWN-BUG` with the ids below.

Baseline: `cargo test --workspace` 75/75, `npm test` 3/3 suites, `npm run verify:features` all checks.

| # | Feature | Suite | Checks | Status |
|---|---|---|---|---|
| F01 | MCP protocol and transports | `01-protocol.test.js` | 53/61 | 6 bugs, 2 fixed (B1 auth fail-open fixed in this release) |
| F02 | Explore: list/search/describe | `02-explore.test.js` | 73/108 | 10 defects, mostly envelope counts, validation, audit |
| F03 | trace_table_dependencies | `03-table-dependencies.test.js` | 80/87 | correct and fast (~37 ms); 4 minor/medium bugs |
| F04 | get_procedure_call_graph | `04-procedure-call-graph.test.js` | 42/48 | correct on all engines; DDL splitting bugs (`$$`, `DELIMITER`) |
| F07 | run_named_tool | `07-named-tools.test.js` | 54/60 | core contract solid; 5 small defects |
| F08 | database_health / analyze_workload | `08-health-workload.test.js` | 31/43 | metrics are defaults in simulation and not disclosed |
| F09 | recommend_indexes | `09-recommend-indexes.test.js` | 39/62 | heuristic advisor works; honesty/gating/policy gaps |
| F10 | Governed change workflow | `10-change-governance.test.js` | 66/91 | lifecycle, hash binding, replay, drift OK; 2 critical bugs fixed in this release |
| F11 | capture_schema / diff_schema | `11-schema-snapshot-diff.test.js` | 36/51 | snapshots deterministic; diff misses triggers/routines/FKs |
| F12 | Audit trail | `12-audit-trail.test.js` | 40/67 | chain and stores work; coverage gaps |
| F05 | execute_query | not completed (tester interrupted by API limits) | | covered by `npm test` and `feature-smoke.js` |
| F06 | explain_query / SQL guards | not completed | | multi-statement, mutating CTE, privileged function denials covered by Rust and smoke suites |
| F13 | Config, secrets, policy | not completed | | early finding: config structs lack `deny_unknown_fields` |
| F14 | Install and packaging | not completed | | launcher unit tests pass (`launcher.test.js`) |
| F15 | Adapters and live fallback | not completed | | see "simulation disclosure" below |

## v0.2.0 update (2026-11-15)

Fixed before adding the ontology (they were prerequisites for it):

- Audit coverage: every tool call, denial and admin action (CLI and HTTP approvals, ontology review and publish) now produces exactly one audit event (F12-01/02/03, F02-08, F07 NT-03, F10-06).
- Audit privacy: persisted SQL is a literal-free fingerprint and `sql_hash` is computed over it (F12-04, F08-05, F10-08). JSONL appends read only the file tail.
- Restricted tables are removed before pagination, lineage, snapshots, diffs and diagnostics output (F02-02, F03-2, F11-02, F08-06, F09-20).
- PostgreSQL/MySQL responses carry an explicit simulated-backend warning (F02-05, F08-03, F09-01).
- `returned_rows` reflects data payloads (F02-01, F11-07); schema fingerprints ignore row counts (F11-01).
- `/admin/*` endpoints return 403 when no admin token is configured.

New feature F16, governed ontology: `npm/test/features/16-ontology.test.js` 15/15, Rust `crates/db-mcp-server/tests/ontology_golden.rs` (golden gates 8/8), e2e suite 4/4, smoke 53/53. REA evidence: `research/findings/ontology-rea-verification.md`.

Still open from the list below: forgeable change approvals without a key (F10-03), `propose_change` policy bypass (F10-04), routine DDL splitting (F04-02/03), stdio invalid UTF-8 (F01-B2), diff coverage for triggers/routines/FKs (F11-03/04), index advisor quality and gating (F09).

## Fixed in this release

- Windows stack overflow in `tools/call` (server ran tool futures on the 1 MiB main thread).
- F01-B1: HTTP authentication failed open when `auth_token = "env:VAR"` could not be resolved; the server now refuses to start.
- F10-01: `execute_query` accepted any `change_id` and bypassed GovernedProduction approval; the argument is now rejected with `USE_APPLY_CHANGE`.
- F10-05: unvalidated `ttl_seconds` could crash the server; it is now bounded to 1..30 days.

## Known issues (prioritised backlog)

**High**
- Audit coverage: `list_connections`, `search_objects`, `describe_object`, `database_health`, `analyze_workload`, `recommend_indexes`, `get_change`, `capture_schema`, `diff_schema`, approvals (CLI and HTTP) and most denial paths emit no audit event (F12-01/02/03, F02-08, F07 NT-03, F10-06). Fix centrally in `call_tool`.
- Simulation disclosure: when a PostgreSQL/MySQL DSN is unreachable the embedded simulation answers with `warnings: []`; diagnostics report default telemetry and `hypopg_validated: true` without evaluation (F08-03, F09-01/02, F02-05). Add an `is_simulated` capability and warnings on every response.
- Restricted tables leak through lineage, snapshots, workload and index advice (F03-2, F11-02, F08-06, F09-20); `propose_change` bypasses connection policy (F10-04); approval records are unkeyed and can be forged by anyone with write access to `changes.db` (F10-03).
- Literals (including PII and secrets) persist in `normalized_sql` and workload fingerprints (F12-04, F08-05, F10-08).
- Routine DDL splitting: a `$$`-quoted routine swallows preceding `BEGIN...END` routines; MySQL `DELIMITER` aborts startup (F04-02/03).
- Schema fingerprint hashes `estimated_rows`, so data changes alter `schema_version` and drift checks (F11-01).
- Invalid UTF-8 on stdin terminates the stdio server (F01-B2); corrupt audit JSONL turns executed writes into `STORAGE_ERROR` (F12-06).

**Medium**
- `returned_rows`/`columns`/`rows` are empty for data-shaped responses (F02-01, F11-07); lenient argument validation (limits, depth, enums, `top_n`, `max_recommendations`); restricted filtering after pagination leaks counts (F02-02); phantom demo routines seeded in simulated catalogs (F02-06); diff ignores triggers/routines/FKs and emits Postgres-only DDL (F11-03/04); FK candidates outrank query-derived index recommendations (F09-03/05); MySQL not gated for health/index advice (F08-01, F09-19); second approval overwrites the first (F10-02).

**Low**
- JSON-RPC code details (-32600 vs -32700, id-less requests answered, notifications over HTTP return 200 not 202, no `WWW-Authenticate`), missing `next_action` on `INVALID_ARGUMENT`, misc. message quality.

Full per-check detail is printed by each suite; run `node npm/test/features/<suite>` from the repo root.
