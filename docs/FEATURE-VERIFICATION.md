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

## v0.2.2 verification and fix pass (2026-11-16)

Fourteen independent verifier agents (one per feature) re-ran every suite against the v0.2.1 release binary and
explored beyond it. Their findings were fixed in seven phases, each on its own branch and worktree, each green on
its own before it was merged (a fault stays in the phase that caused it). The merged result was then re-gated.

| # | Feature | Suite result (v0.2.2) | Remaining known bugs |
|---|---|---|---|
| F01 | Protocol and transports | 61/61 | none |
| F02 | Explore | 108/108 | none |
| F03 | trace_table_dependencies | 86 pass, 1 xfail | F03-1 (read inside UPDATE reported as write) |
| F04 | get_procedure_call_graph | 46/48 | F04-01 (CALL in a string literal), F04-04 (stub naming) |
| F05 | execute_query | 99/104 | F05-B3 cancellation, F05-B5 rows_affected, F05-B6 u64 bind, F05-B7 pg-sim `$n` order |
| F06 | SQL guards / explain | 363/366 | F06-B4/B5/B8 (error-code and next_action polish) |
| F07 | run_named_tool | 60/60 | none |
| F08 | Health / workload | 41/43 | F08-08 (pg_stat_statements source), F08-12 (history lost on restart) |
| F09 | recommend_indexes | 51 pass, 11 xfail | advisor quality items F09-04, F09-06..14 |
| F10 | Governed changes | 96/96 | none |
| F11 | Snapshot / diff | 49/51 | F11-07 (summary row contract), F11-08 (empty pattern warning) |
| F12 | Audit trail | 67/67 | none |
| F13 | Config, secrets, policy | 79/79 | none |
| F14 | Install and packaging | 62/62 | none |
| F15 | Adapters and simulation | 49 pass, 17 known | PostgreSQL/MySQL dialect gaps of the embedded simulation (F15-04..12, F15-14, F15-16..18, F15-20) |
| F16 | Governed ontology | 16/16, golden 17/17 | none |

Also green: `cargo test --workspace --release`, `npm test` (launcher 8/8, e2e 4/4), `db-mcp selftest` 58/58.

Fixed in this pass:

- **Security.** Sensitive columns could leak through an alias, an expression, a subquery re-alias or a UNION position
  (F05-B2/F06-B3); output provenance is now tracked and such queries are denied
  (`SENSITIVE_COLUMN_FORBIDDEN`, `UNPROVENANCED_SENSITIVE_QUERY`). A wildcard is refused only when the live catalog
  shows that a source table holds a sensitive column. Connection `allowed_roles` can no longer be bypassed by a
  self-asserted `dba`/`admin` role (F13-B11). `readfile`, `writefile`, `edit` and `set_config` are privileged
  functions, and bareword `PRAGMA` writes need an admin (F06-B7, F05-B8). `EXPLAIN ANALYZE` through execute_query
  follows `allow_explain_analyze` (F06-B1).
- **Governed changes.** `propose_change` and `apply_change` enforce the same connection policy as execute_query
  (F10-04). An approval is accepted only once, from the `proposed` state (F10-02). Approval records carry an
  HMAC-SHA256 MAC keyed by `changes.approval_key` or `DB_MCP_APPROVAL_KEY`. On GovernedProduction connections,
  `apply_change` refuses changes when no key is configured (F10-03).
- **Config.** Unknown keys are rejected, so a typo such as `read_onli` can no longer silently leave a connection
  writable (F13-B1). Unresolvable `env:` DSNs fail startup, `file:` secret references work, and further bounds are
  validated (F13-B2/B3/B6/B7/B9/B10). The `db-mcp init` starter config validates with no environment variables.
- **Audit.** Concurrent writers keep both hash chains intact (F12-09). GovernedProduction refuses to run without a
  durable audit sink (F12-07). The new `db-mcp verify-audit --config <file>` command checks both chains (F12-05).
- **Protocol.** Invalid UTF-8 no longer stops the stdio server (F01-B2). JSON-RPC error codes follow the spec (F01-B4/B5).
  HTTP notifications return 202, and a 401 carries `WWW-Authenticate` (F01-B3/B6).
- **Explore, lineage, diagnostics.** Arguments are validated strictly (F02-03/04, F03-4, F04-05, F08-07, F09-15..17).
  `describe_object` and `name_pattern` fixes (F02-07/09/10). Diagnostics are gated by adapter capability on MySQL
  (F08-01, F09-19). SQLite health is honest (F08-02). The simulation no longer reports `hypopg_validated` (F09-02).
  Query-derived index candidates come first (F09-03/05). SQLite index DDL is valid (F09-18). `list_connections`
  flags simulated connections (F15-01).
- **Routines and schema diff.** Dollar-quoted and `BEGIN...END` routines split correctly (F04-02). MySQL `DELIMITER`
  is supported (F04-03). The MySQL simulation no longer contains phantom routines (F02-06). `diff_schema` covers
  routines, triggers, foreign keys and primary keys, with per-engine DDL (F11-03/04/05/06/09/01).
- **Named tools.** Duplicate names and placeholder/parameter mismatches are rejected at load (NT-01/02). A
  non-object `arguments` value is rejected (NT-05).
- **Ontology.** The planner now refuses instead of guessing. Before this pass, 13 of 51 probe questions got a wrong
  number. Causes: a filter dropped after a dimension, uncertified filter words ignored, negations and `or`
  compiled wrongly, `average` answered as a sum, and undeclared measures. All 51 now match direct SQL or are refused
  with a reason. The golden set grew from 8 to 17 cases.
- **Install.** The launcher fails closed when a release checksum is missing (F14-02; override with
  `DB_MCP_ALLOW_UNVERIFIED=1`). The Dockerfile and `rust-version` were aligned with the lock file (1.89). Compose
  runs only db-mcp (F14-07). `db-mcp --help` works without a binary. New `db-mcp selftest` runs the end-to-end
  feature check on an isolated copy of the example config.

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
