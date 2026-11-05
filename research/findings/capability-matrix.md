# DB-MCP Capability Matrix and REA Investigation Findings

## 1. REA MCP Static & Artifact Analysis Evidence Summary

During Phase 0, we unpacked `@bytebase/dbhub@1.5.0` into `reference/dbhub/` and constructed the SQLite fixture at `research/fixtures/sample.db`, then executed the `user-rea` MCP tools:

- **`analyze_javascript_application` (`reference/dbhub`)**:
  - **Parent Evidence ID**: `ev_4667521bc0c09533da5e644f176fac07f0164fa7dd9a1a57454ebe9c7e017bab`
  - **Summary View Evidence ID**: `ev_e0829f482235dc3cf5e3569b86c675faaa362602aaa449972e562bd8e2da30c2`
  - **Root Artifact SHA-256**: `54faee3eb8fe59cdad5ad1b1e74faf20ff8387bb6ea8f6530f3cd7e1cd1fdb96`
  - **Analyzed Core Server & Connector Bundles**: `dist/index.js`, `dist/postgres-KCFNDQLG.js`, `dist/sqlite-WKY6543Q.js`, `dist/mysql-ZXO4TWLG.js` (`125,073` text bytes read, `15,319` visited AST nodes, `0` parse failures).
  - **Extracted Semantic Graph Relations**:
    - `data-flow`: `7,189` retained relations
    - `object-flow`: `1,036` retained relations
    - `call-flow`: `726` retained relations
    - `closure`: `536` retained relations
    - `promise-ownership`: `136` retained relations
    - `boundary` (JSON/Zod parse & validation boundaries): `25` retained relations
    - `event`: `8` retained relations
    - `timer`: `3` retained relations
    - `configuration`: `2` retained relations
- **`inspect_sqlite_database` (`research/fixtures/sample.db`)**:
  - Invoked against `d:\research 1\mcp\DB\research\fixtures\sample.db` (`36,864` bytes, seeded with `users`, `orders`, `schema_migrations`, `idx_orders_user_id`, and `idx_orders_status_created`).
  - Recorded runtime capability check: the host Node.js `v24.19.0` build exposes `node:sqlite` `DatabaseSync` without the `DatabaseSync.limits` property required by REA's isolated SQLite worker (`code: "capability_unavailable"`, `provider_id: "sqlite"`). This finding directly motivates DB-MCP's native Rust `rusqlite` adapter (`db-mcp-sqlite`) with deterministic row/byte limits and interrupt handles rather than relying on experimental Node SQLite limits.
- **`export_evidence_bundle`**:
  - Exported canonical byte-stable evidence bundle to `d:\research 1\mcp\DB\research\traces\rea-evidence.json` (`18,494,698` bytes, `2` evidence records, `0` export unknowns).

---

## 2. Source & Semantic Trace Findings from Reference Artifacts

### Trace A: DBHub `search_objects` (`dist/index.js:333-815`)
- **Entrypoint & Registration**: `registerSearchObjectsTool` (`dist/index.js:1355`) registers `search_objects` (or `search_objects_<source_id>` when multiple sources are configured) with `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`.
- **Input Validation (`searchDatabaseObjectsSchema`, `dist/index.js:334-341`)**:
  - `object_type`: enum `["schema", "table", "view", "column", "procedure", "function", "index"]`
  - `pattern`: optional SQL `LIKE` pattern (default `"%"`), converted to case-insensitive regex via `likePatternToRegex` (`%` -> `.*`, `_` -> `.`)
  - `schema`: optional schema filter (validated against `connector.getSchemas()`; returns `SCHEMA_NOT_FOUND` if missing)
  - `table`: optional table filter (requires `schema`, otherwise returns `SCHEMA_REQUIRED`; restricted to `object_type` in `["column", "index"]`, otherwise returns `INVALID_TABLE_FILTER`)
  - `detail_level`: enum `["names", "summary", "full"]` (default `"names"`)
  - `limit`: positive integer `<= 1000` (default `100`)
- **Progressive Disclosure & Truncation**:
  - `names`: returns only `{ name, schema }` (or `{ name, table, schema }` for columns/indexes).
  - `summary`: fetches column count, estimated/exact row count, and table comment.
  - `full`: fetches columns (`name`, `type`, `nullable`, `default`, `description`) and indexes (`name`, `columns`, `unique`, `primary`).
  - Sets `truncated: results.length === limit`.

### Trace B: DBHub SQL Classification, Read-Only Enforcement, and Cancellation (`dist/index.js:110-155`, `dist/chunk-55X2VY5D.js:1-182`, `dist/postgres-KCFNDQLG.js:699-825`, `dist/sqlite-WKY6543Q.js:337-419`)
- **Keyword & Escape-Hatch Classification (`dist/chunk-55X2VY5D.js`)**:
  - Strips comments and string literals first (`stripCommentsAndStrings`), splits multi-statement batches (`splitSQLStatements`), and evaluates every statement.
  - Blocks mutating CTEs (`firstWord === "with" && hasMutatingKeyword(cleanedSQL, connectorType)`).
  - Blocks `SELECT ... INTO` (`selectIntoPattern`).
  - Blocks engine-specific escape-hatch functions even inside `SELECT`:
    - PostgreSQL: `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `set_config`
    - MySQL/MariaDB: `load_file`, `get_lock`, `release_lock`, `release_all_locks`
    - SQLite: `PRAGMA` with `=` assignment or non-whitelisted paren pragmas (only `table_info`, `index_info`, `index_list`, `foreign_key_list` permitted)
- **Database-Side Read-Only & Row Limiting**:
  - PostgreSQL (`dist/postgres-KCFNDQLG.js:714-766`): wraps read-only execution in `BEGIN READ ONLY ... COMMIT` (with `rollbackQuietly` on error). On client-side timeout, discards the connection (`client.release(true)`) and issues `SELECT pg_cancel_backend($1)` on a separate pooled connection (`cancelBackend`, lines `813-824`).
  - SQLite (`dist/sqlite-WKY6543Q.js:340-417`): sets `PRAGMA query_only = ON` before execution and resets `PRAGMA query_only = OFF` in `finally`.
  - Row limiting (`SQLRowLimiter.applyMaxRowsWithTruncationProbe`): rewrites `LIMIT` with an `N + 1` probe so `truncated: true` is emitted only when a `max_rows` cap actually cut off rows (`dist/index.js:230-234`).

### Trace C: DBHub `explain_sql` and `health_check` (`dist/index.js:818-958`, `dist/postgres-KCFNDQLG.js:535-593`)
- **`explain_sql`**:
  - Rejects multi-statement inputs (`statements.length !== 1`).
  - Rejects leading `EXPLAIN` or `ANALYZE` options (`explain_sql does not support ANALYZE (it must never execute the statement)`).
  - Prepends `EXPLAIN QUERY PLAN` for SQLite and `EXPLAIN` for PostgreSQL/MySQL, executing with `{ readonly: true }`.
- **`health_check`**:
  - Queries `pg_stat_activity` (total, active, idle, idle in transaction, longest active/idle seconds), `SHOW max_connections`, and `pg_stat_database` (`blks_hit`, `blks_read`, `hit_ratio_pct`).

### Trace D: Custom Parameterized Tools (`dist/index.js:1196-1316`)
- Validates tool parameters via generated Zod schemas supporting `string`, `integer`, `float`, `boolean`, `array`, and `allowed_values` enums.
- Maps named arguments to positional bind parameters (`mapArgumentsToArray`) and executes with bound parameters — never interpolating user strings into SQL text.

---

## 3. DB-MCP Convergence Capability Matrix (14 Tools Across 5 Profiles)

| Capability ID | Tool Name | Profile | Reference Lineage | Engines Supported | Security & Governance Controls | Parity / Target Status |
|---|---|---|---|---|---|---|
| `CAP-EXPLORE-01` | `list_connections` | Explore | DBHub + Bytebase | PostgreSQL, MySQL, SQLite | Caller role filtering; DSN/password redaction (`db-mcp-secrets`); reports per-connection capabilities and operating mode | `Specified` |
| `CAP-EXPLORE-02` | `search_objects` | Explore | DBHub (`search_objects`) | PostgreSQL, MySQL, SQLite | Read-only catalog query; progressive `detail_level` (`names`, `summary`, `full`); bounded `limit` (max 1000) with `truncated` flag | `Specified` |
| `CAP-EXPLORE-03` | `describe_object` | Explore | DBHub + Postgres MCP Pro | PostgreSQL, MySQL, SQLite | Detailed inspection of table/view/routine columns, indexes, constraints, foreign keys, and stats; marks comments as untrusted data | `Specified` |
| `CAP-QUERY-01` | `execute_query` | Query | DBHub (`execute_sql`) + Bytebase | PostgreSQL, MySQL, SQLite | Dialect AST parser (`db-mcp-sql`); blocks multi-statement batches, mutating CTEs, and privileged functions in `ReadOnly`/`GovernedProduction`; enforces timeout, row cap, byte budget, and audit trail | `Specified` |
| `CAP-QUERY-02` | `explain_query` | Query | DBHub (`explain_sql`) + Postgres MCP Pro | PostgreSQL, MySQL, SQLite | Single-statement AST check; rejects `ANALYZE` unless explicitly authorized; uses `EXPLAIN (FORMAT JSON)` on PG, `EXPLAIN FORMAT=JSON` on MySQL, `EXPLAIN QUERY PLAN` on SQLite | `Specified` |
| `CAP-QUERY-03` | `run_named_tool` | Query | Google MCP Toolbox + DBHub custom tools | PostgreSQL, MySQL, SQLite | Strict parameter type + `allowed_values` validation; bound positional parameters (`$1` / `?`) with zero SQL string interpolation; per-tool read-only & `max_rows` enforcement | `Specified` |
| `CAP-DIAG-01` | `database_health` | Diagnose | Postgres MCP Pro + DBHub (`health_check`) | PostgreSQL (primary), SQLite/MySQL (connection/pragma summary) | Read-only diagnostic queries covering connection saturation, buffer cache hit ratio, dead tuple bloat, invalid indexes, and long-running queries | `Specified` |
| `CAP-DIAG-02` | `analyze_workload` | Diagnose | Postgres MCP Pro | PostgreSQL (with SQLite/audit fallback) | Reads `pg_stat_statements` (when extension present) or execution audit metrics; normalizes query fingerprints and ranks top queries by total/mean latency and I/O | `Specified` |
| `CAP-DIAG-03` | `recommend_indexes` | Diagnose | Postgres MCP Pro | PostgreSQL (heuristic + HypoPG), SQLite (heuristic) | Extracts WHERE/JOIN/ORDER BY predicates via `db-mcp-sql`, proposes composite B-Tree indexes, evaluates virtual indexes via HypoPG when available, and emits full trade-off + validation evidence | `Specified` |
| `CAP-CHANGE-01` | `propose_change` | Change | Bytebase (clean-room) | PostgreSQL, MySQL, SQLite | Parses DDL/DML change, records rollback/transactionality classification, computes current `schema_version` fingerprint, and mints a pending proposal with cryptographic approval binding hash | `Specified` |
| `CAP-CHANGE-02` | `get_change` | Change | Bytebase (clean-room) | PostgreSQL, MySQL, SQLite | Returns proposal state (`PendingApproval`, `Approved`, `Applied`, `Rejected`, `Expired`), approval hash, proposing principal, approver, and verification metadata | `Specified` |
| `CAP-CHANGE-03` | `apply_change` | Change | Bytebase (clean-room) | PostgreSQL, MySQL, SQLite | Enforces separation of duties (`SELF_APPROVAL_FORBIDDEN`), atomic single-use claim (`APPROVAL_ALREADY_CONSUMED`), hash verification (`APPROVAL_HASH_MISMATCH`), and schema drift check (`SCHEMA_DRIFT_DETECTED`) | `Specified` |
| `CAP-SCHEMA-01` | `capture_schema` | Schema | Bytebase + DBHub | PostgreSQL, MySQL, SQLite | Captures deterministic normalized schema snapshot (tables, columns, indexes, constraints, views) with canonical SHA-256 `schema_version` (`snapshot_<hash>`) | `Specified` |
| `CAP-SCHEMA-02` | `diff_schema` | Schema | Bytebase (clean-room) | PostgreSQL, MySQL, SQLite | Computes structural diff between two captured snapshots or live connection vs snapshot (added/removed/modified tables, columns, and indexes) | `Specified` |
