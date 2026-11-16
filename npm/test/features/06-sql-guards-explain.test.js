#!/usr/bin/env node
"use strict";
/**
 * F06 - explain_query + dialect-aware SQL classifier / adversarial security guards.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *   node npm/test/features/06-sql-guards-explain.test.js
 *
 * - Spawns the prebuilt db-mcp server over stdio against private isolated configs
 *   (never touches config/db-mcp.example.toml or research/ fixtures).
 * - One line per check. Assertions encode the CORRECT behaviour; checks that currently
 *   fail because of a known defect are tagged `// KNOWN-BUG: F06-Bn` and reported as
 *   XFAIL (they do not affect the exit code; an XPASS means the bug was fixed and the
 *   marker should be removed). Any other failure => exit code 1.
 *
 * Connections exercised (from the example config):
 *   analytics-mysql  ReadOnly            (simulated MySQL)
 *   prod-postgres    GovernedProduction  (simulated Postgres)
 *   local-sqlite     Development         (real SQLite file, isolated copy)
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
process.chdir(REPO_ROOT);
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));

// ---------------------------------------------------------------------------
// Denial codes (crates/db-mcp-policy/src/lib.rs, crates/db-mcp-core/src/lib.rs)
// ---------------------------------------------------------------------------
const M = "MULTI_STATEMENT_FORBIDDEN";
const P = "PRIVILEGED_FUNCTION_FORBIDDEN";
const R = "MUTATION_NOT_ALLOWED_IN_READ_ONLY";
const A = "APPROVAL_REQUIRED";
const U = "UNKNOWN_SQL_IN_GOVERNED_MODE";
const X = "ANALYZE_EXPLAIN_FORBIDDEN";
const RT = "RESTRICTED_TABLE_FORBIDDEN";
const INV = "INVALID_ARGUMENT";
const OK = "ok";
const SKIP = null;
// "fail closed": must be denied by the policy layer before the adapter sees it.
const CLOSED_RO = [R, P, U, M];
const CLOSED_GOV = [A, P, U, M];

const MYSQL = "analytics-mysql";
const PG = "prod-postgres";
const SQLITE = "local-sqlite";
const CONNS = [MYSQL, PG, SQLITE];

// ---------------------------------------------------------------------------
// Tally / reporting
// ---------------------------------------------------------------------------
const tally = { pass: 0, fail: 0, xfail: 0, xpass: 0 };
const failures = [];
async function check(name, fn, knownBug) {
  try {
    await fn();
    if (knownBug) {
      tally.xpass += 1;
      console.log(`[XPASS] ${name}  (KNOWN-BUG ${knownBug} appears fixed - remove marker)`);
    } else {
      tally.pass += 1;
      console.log(`[PASS] ${name}`);
    }
  } catch (err) {
    const msg = (err && err.message ? err.message : String(err)).split("\n")[0];
    if (knownBug) {
      tally.xfail += 1;
      console.log(`[XFAIL] ${name}  (KNOWN-BUG ${knownBug}) -> ${msg}`);
    } else {
      tally.fail += 1;
      failures.push(`${name}: ${msg}`);
      console.log(`[FAIL] ${name} -> ${msg}`);
    }
  }
}

// ---------------------------------------------------------------------------
// MCP session helpers
// ---------------------------------------------------------------------------
const children = [];
async function openSession(configPath) {
  const client = createClient({ config: configPath, principal: "local-agent", role: "agent", timeoutMs: 30000 });
  children.push(client.child);
  const init = await client.rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "f06-sql-guards", version: "0.1.0" },
  });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  client.notify("notifications/initialized", {});
  const call = async (tool, args) => {
    const resp = await client.rpc("tools/call", { name: tool, arguments: args });
    if (resp.error) return { status: "rpc_error", code: `RPC_${resp.error.code}`, message: resp.error.message, isError: true };
    const sc = resp.result.structuredContent || {};
    return { ...sc, isError: resp.result.isError === true };
  };
  const close = () =>
    new Promise((resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      client.child.once("exit", finish);
      client.close();
      setTimeout(() => { try { client.child.kill(); } catch {} finish(); }, 3000);
    });
  return { call, close };
}

function expectOutcome(label, res, exp) {
  if (exp === OK) {
    assert.equal(res.status, "ok", `${label}: expected status=ok, got ${res.status}/${res.code}: ${res.message}`);
    assert.equal(res.isError, false, `${label}: isError must be false on ok`);
  } else {
    const codes = [].concat(exp);
    assert.equal(res.status, "denied", `${label}: expected status=denied, got ${res.status} (${res.code}) ${res.message || ""}`);
    assert.ok(codes.includes(res.code), `${label}: expected code in [${codes.join(",")}], got ${res.code}: ${res.message}`);
    assert.equal(res.isError, true, `${label}: isError must be true on denial`);
  }
}

const denied = []; // { request_id, code, tool, conn } for audit cross-check
function remember(tool, conn, res) {
  if (res && res.status === "denied" && res.request_id) denied.push({ request_id: res.request_id, code: res.code, tool, conn });
}

// ---------------------------------------------------------------------------
// Isolated configs
// ---------------------------------------------------------------------------
// Seed tables whose names/columns contain mutation keywords (false-positive probes).
// Must be idempotent: init_sql re-runs on every server spawn against the same sample.db.
const seedTransform = (t) =>
  t.replace(
    /CREATE TABLE (IF NOT EXISTS )?internal_secrets \(/g,
    "CREATE TABLE IF NOT EXISTS deleted_items (id INTEGER PRIMARY KEY, update_count INTEGER, sleep INTEGER);\n" +
      "CREATE TABLE IF NOT EXISTS update_log (id INTEGER PRIMARY KEY);\n" +
      "CREATE TABLE $1internal_secrets ("
  );
const multiTransform = (t) => seedTransform(t).replace(/allow_multi_statement = false/g, "allow_multi_statement = true");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "f06-sql-guards-"));
const cfgMain = makeIsolatedConfig({ dir: path.join(tmpRoot, "main"), transform: seedTransform });
const cfgMulti = makeIsolatedConfig({ dir: path.join(tmpRoot, "multi"), transform: multiTransform });

// ---------------------------------------------------------------------------
// execute_query matrix: payload x connection -> expected outcome
// ---------------------------------------------------------------------------
// value: OK | "<CODE>" | [codes...] | SKIP ; optional bug: KNOWN-BUG id (applies to every cell)
const MATRIX = [
  // --- false positives: legitimate reads must pass on ReadOnly/Governed ---
  { id: "fp_cte", sql: "WITH c AS (SELECT id FROM users) SELECT * FROM c", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_window", sql: "SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn FROM users", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_exists", sql: "SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id)", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_union_all", sql: "SELECT id FROM users UNION ALL SELECT id FROM orders", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_group_having", sql: "SELECT status, COUNT(*) FROM orders GROUP BY status HAVING COUNT(*) > 0", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_case", sql: "SELECT CASE WHEN status='completed' THEN 1 ELSE 0 END AS done FROM orders", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_string_delete", sql: "SELECT 'DELETE FROM users' AS s", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_insert_in_string", sql: "SELECT id FROM users WHERE email <> 'INSERT INTO x VALUES (1)'", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_col_update_count", sql: "SELECT update_count FROM deleted_items", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_col_named_sleep", sql: "SELECT sleep FROM deleted_items", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_alias_pg_sleep", sql: "SELECT 1 AS pg_sleep", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_deleted_items_cte", sql: "WITH deleted AS (SELECT * FROM deleted_items) SELECT * FROM deleted", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_tbl_update_log", sql: "SELECT * FROM update_log", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_count", sql: "SELECT COUNT(*) FROM users", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_limit_offset", sql: "SELECT id FROM users ORDER BY id LIMIT 1 OFFSET 1", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_json", sql: "SELECT json_extract('{\"a\":1}', '$.a') AS a", mysql: OK, pg: OK, sqlite: OK },
  { id: "fp_json_pg", sql: "SELECT '{\"a\":1}'::json -> 'a' AS a", mysql: SKIP, pg: OK, sqlite: SKIP },
  { id: "fp_with_recursive", sql: "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<5) SELECT n FROM c", mysql: OK, pg: OK, sqlite: OK },

  // --- multi-statement ---
  { id: "ms_drop", sql: "SELECT 1; DROP TABLE users", mysql: M, pg: M, sqlite: M },
  { id: "ms_two_selects", sql: "SELECT 1; SELECT 2", mysql: M, pg: M, sqlite: M },
  { id: "ms_trailing_semicolon", sql: "SELECT 1;", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_trailing_semicolon_ws", sql: "SELECT 1;   \n", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_double_semicolon", sql: "SELECT 1;;", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_semicolon_in_string", sql: "SELECT ';' AS s", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_semicolon_in_line_comment", sql: "SELECT 1 -- ; DROP TABLE users\n", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_semicolon_in_block_comment", sql: "SELECT /* ; DROP TABLE users; */ 1", mysql: OK, pg: OK, sqlite: OK },
  { id: "ms_do_block", sql: "DO $$ BEGIN DELETE FROM users; END $$", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: M },
  { id: "ms_create_trigger", sql: "CREATE TRIGGER t AFTER INSERT ON users BEGIN DELETE FROM users; END", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: M },

  // --- mutating CTEs / DML / DDL / admin on ReadOnly + Governed (sqlite Development: skipped when destructive) ---
  { id: "cte_delete", sql: "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", mysql: R, pg: A, sqlite: SKIP },
  { id: "cte_nested_update", sql: "WITH a AS (WITH b AS (UPDATE orders SET status='x' RETURNING id) SELECT * FROM b) SELECT * FROM a", mysql: R, pg: A, sqlite: SKIP },
  { id: "insert_select", sql: "INSERT INTO audit_logs (order_id, event_type, created_at) SELECT id, 'x', created_at FROM orders", mysql: R, pg: A, sqlite: SKIP },
  { id: "select_into", sql: "SELECT * INTO new_table FROM users", mysql: R, pg: A, sqlite: SKIP },
  { id: "create_table_as", sql: "CREATE TABLE t2 AS SELECT * FROM users", mysql: R, pg: A, sqlite: SKIP },
  { id: "merge", sql: "MERGE INTO inventory i USING orders o ON i.sku = 'x' WHEN MATCHED THEN UPDATE SET reserved_qty = 1", mysql: R, pg: A, sqlite: SKIP },
  { id: "replace_into", sql: "REPLACE INTO inventory (sku, available_qty) VALUES ('x', 1)", mysql: R, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "upsert_on_conflict", sql: "INSERT INTO inventory (sku, available_qty) VALUES ('x',1) ON CONFLICT (sku) DO UPDATE SET available_qty = 2", mysql: R, pg: A, sqlite: SKIP },
  { id: "truncate", sql: "TRUNCATE TABLE orders", mysql: R, pg: A, sqlite: SKIP },
  { id: "alter_table", sql: "ALTER TABLE users ADD COLUMN x TEXT", mysql: R, pg: A, sqlite: SKIP },
  { id: "drop_table", sql: "DROP TABLE users", mysql: R, pg: A, sqlite: SKIP },
  { id: "update_plain", sql: "UPDATE users SET role='admin' WHERE id=2", mysql: R, pg: A, sqlite: SKIP },
  { id: "delete_plain", sql: "DELETE FROM users WHERE id=2", mysql: R, pg: A, sqlite: SKIP },
  { id: "create_index", sql: "CREATE INDEX idx_x ON users(email)", mysql: R, pg: A, sqlite: SKIP },
  { id: "create_temp_table", sql: "CREATE TEMP TABLE tmp AS SELECT 1", mysql: R, pg: A, sqlite: SKIP },
  { id: "begin", sql: "BEGIN", mysql: R, pg: A, sqlite: SKIP },
  { id: "commit", sql: "COMMIT", mysql: R, pg: A, sqlite: SKIP },
  { id: "call_procedure", sql: "CALL reserve_inventory(101)", mysql: R, pg: A, sqlite: SKIP },
  { id: "execute_prepared", sql: "EXECUTE p", mysql: R, pg: A, sqlite: SKIP },
  { id: "explain_delete_via_execute", sql: "EXPLAIN DELETE FROM users", mysql: R, pg: A, sqlite: SKIP },
  { id: "explain_analyze_delete_via_execute", sql: "EXPLAIN ANALYZE DELETE FROM users", mysql: R, pg: A, sqlite: SKIP },
  { id: "grant", sql: "GRANT ALL ON users TO public", mysql: [R, P], pg: P, sqlite: P },
  { id: "copy_to_program", sql: "COPY users TO PROGRAM 'cat > /tmp/x'", mysql: [R, P], pg: P, sqlite: P },
  { id: "copy_from_program", sql: "COPY users FROM PROGRAM 'id'", mysql: [R, P], pg: P, sqlite: P },
  { id: "attach_database", sql: "ATTACH DATABASE '/tmp/x.db' AS x", mysql: P, pg: P, sqlite: P },
  { id: "pragma_writable_schema", sql: "PRAGMA writable_schema=1", mysql: [R, P], pg: P, sqlite: P },
  { id: "vacuum", sql: "VACUUM", mysql: [R, P], pg: P, sqlite: P },
  { id: "set_role", sql: "SET ROLE postgres", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "set_statement_timeout", sql: "SET statement_timeout = 1", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "set_global", sql: "SET GLOBAL general_log = 1", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "lock_table", sql: "LOCK TABLE users IN ACCESS EXCLUSIVE MODE", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "create_role", sql: "CREATE ROLE evil SUPERUSER", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "alter_system", sql: "ALTER SYSTEM SET work_mem = '1GB'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "create_extension", sql: "CREATE EXTENSION IF NOT EXISTS dblink", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "security_label", sql: "SECURITY LABEL ON TABLE users IS 'x'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "comment_on", sql: "COMMENT ON TABLE users IS 'x'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "reindex", sql: "REINDEX TABLE users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "cluster", sql: "CLUSTER users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "listen", sql: "LISTEN chan", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "notify", sql: "NOTIFY chan, 'x'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "discard_all", sql: "DISCARD ALL", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "prepare", sql: "PREPARE p AS DELETE FROM users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "deallocate", sql: "DEALLOCATE p", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "flush_privileges", sql: "FLUSH PRIVILEGES", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "select_into_outfile", sql: "SELECT * FROM users INTO OUTFILE '/tmp/x'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "select_into_dumpfile", sql: "SELECT * FROM users INTO DUMPFILE '/tmp/x'", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "handler_open", sql: "HANDLER users OPEN", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "load_data_infile", sql: "LOAD DATA INFILE '/etc/passwd' INTO TABLE users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },

  // --- privileged / side-effecting functions (global list, engine-agnostic) ---
  { id: "pg_sleep", sql: "SELECT pg_sleep(1)", mysql: P, pg: P, sqlite: P },
  { id: "pg_read_file", sql: "SELECT pg_read_file('/etc/passwd')", mysql: P, pg: P, sqlite: P },
  { id: "pg_ls_dir", sql: "SELECT pg_ls_dir('/')", mysql: P, pg: P, sqlite: P },
  { id: "lo_import", sql: "SELECT lo_import('/etc/passwd')", mysql: P, pg: P, sqlite: P },
  { id: "dblink", sql: "SELECT * FROM dblink('dbname=x','SELECT 1') AS t(a int)", mysql: P, pg: P, sqlite: P },
  { id: "pg_terminate_backend", sql: "SELECT pg_terminate_backend(1)", mysql: P, pg: P, sqlite: P },
  { id: "pg_advisory_lock", sql: "SELECT pg_advisory_lock(1)", mysql: P, pg: P, sqlite: P },
  { id: "load_file", sql: "SELECT LOAD_FILE('/etc/passwd')", mysql: P, pg: P, sqlite: P },
  { id: "sys_exec", sql: "SELECT sys_exec('id')", mysql: P, pg: P, sqlite: P },
  { id: "sleep", sql: "SELECT sleep(1)", mysql: P, pg: P, sqlite: P },
  { id: "benchmark", sql: "SELECT benchmark(1000000, md5('x'))", mysql: P, pg: P, sqlite: P },
  { id: "load_extension", sql: "SELECT load_extension('/tmp/evil.so')", mysql: P, pg: P, sqlite: P },
  { id: "priv_case_insensitive", sql: "SELECT PG_READ_FILE('/etc/passwd')", mysql: P, pg: P, sqlite: P },
  { id: "priv_schema_qualified", sql: "SELECT pg_catalog.pg_read_file('/etc/passwd')", mysql: P, pg: P, sqlite: P },
  { id: "priv_quoted_identifier", sql: "SELECT \"pg_read_file\"('/etc/passwd')", mysql: [P, U], pg: P, sqlite: P },
  { id: "priv_space_before_paren", sql: "SELECT pg_sleep (1)", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_subquery", sql: "SELECT id FROM users WHERE id = (SELECT length(pg_read_file('/etc/passwd')))", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_cte", sql: "WITH x AS (SELECT pg_read_file('/etc/passwd') AS f) SELECT f FROM x", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_case", sql: "SELECT CASE WHEN 1=1 THEN pg_sleep(1) ELSE 0 END", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_lateral", sql: "SELECT * FROM users u, LATERAL (SELECT pg_sleep(1)) l", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_from", sql: "SELECT * FROM pg_ls_dir('/')", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_where", sql: "SELECT 1 FROM users WHERE pg_sleep(1) IS NULL", mysql: P, pg: P, sqlite: P },
  { id: "priv_in_order_by", sql: "SELECT id FROM users ORDER BY pg_sleep(1)", mysql: P, pg: P, sqlite: P },
  // SQLite fileio extension + Postgres set_config are on PRIVILEGED_FUNCTIONS (F06-B7 fixed)
  { id: "sqlite_readfile", sql: "SELECT readfile('/etc/passwd')", mysql: P, pg: SKIP, sqlite: P },
  { id: "sqlite_writefile", sql: "SELECT writefile('/tmp/x', 'abc')", mysql: P, pg: SKIP, sqlite: P },
  { id: "sqlite_edit", sql: "SELECT edit('x', 'vi')", mysql: P, pg: SKIP, sqlite: P },
  { id: "pg_set_config", sql: "SELECT set_config('search_path', 'evil', false)", mysql: SKIP, pg: P, sqlite: SKIP },

  // --- parser bypass attempts / dialect edge cases ---
  { id: "bypass_comment_no_space", sql: "SELECT/**/1", mysql: OK, pg: OK, sqlite: OK },
  { id: "bypass_dashdash_newline", sql: "SELECT 1 --\n, 2", mysql: OK, pg: OK, sqlite: OK },
  { id: "bypass_homoglyph_select", sql: "SELECT 1 UNION SELEСT password_hash FROM users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "bypass_garbage", sql: "FOOBAR_VENDOR_COMMAND table_x WITH MAGIC", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "dialect_table_users", sql: "TABLE users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "dialect_describe", sql: "DESCRIBE users", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: SKIP },
  { id: "dialect_values", sql: "VALUES (1)", mysql: OK, pg: OK, sqlite: OK },
  { id: "dialect_backticks_on_pg", sql: "SELECT `id` FROM `users`", mysql: OK, pg: CLOSED_GOV, sqlite: OK },
  { id: "dialect_explain_select_via_execute", sql: "EXPLAIN SELECT 1", mysql: OK, pg: OK, sqlite: OK },
  { id: "dialect_pragma_read", sql: "PRAGMA table_info(users)", mysql: CLOSED_RO, pg: CLOSED_GOV, sqlite: OK },
  // allow_explain_analyze=false also governs execute_query("EXPLAIN ANALYZE ...") (F06-B1 fixed).
  { id: "explain_analyze_select_via_execute", sql: "EXPLAIN ANALYZE SELECT id FROM users", mysql: X, pg: X, sqlite: SKIP },
];

// ---------------------------------------------------------------------------
async function runMatrix(sessions) {
  console.log("\n## 1. execute_query matrix (payload x connection)");
  const key = { [MYSQL]: "mysql", [PG]: "pg", [SQLITE]: "sqlite" };
  for (const conn of CONNS) {
    for (const row of MATRIX) {
      const exp = row[key[conn]];
      if (exp === SKIP) continue;
      await check(
        `${conn} execute ${row.id} -> ${exp === OK ? "ok" : [].concat(exp).join("|")}`,
        async () => {
          const res = await sessions[conn].call("execute_query", { connection: conn, sql: row.sql });
          remember("execute_query", conn, res);
          expectOutcome(row.id, res, exp);
        },
        row.bug
      );
    }
  }
}

async function runDevelopmentFallthrough(s) {
  console.log("\n## 2. Development mode fall-through (local-sqlite, non-destructive)");
  await check(`${SQLITE} DDL allowed in Development (CREATE TABLE ... AS SELECT)`, async () => {
    const res = await s.call("execute_query", { connection: SQLITE, sql: "CREATE TABLE f06_dev_probe AS SELECT 1 AS x" });
    expectOutcome("ctas-dev", res, OK);
  });
  await check(`${SQLITE} Unknown construct in Development reaches adapter (not policy-denied)`, async () => {
    const res = await s.call("execute_query", { connection: SQLITE, sql: "FOOBAR_VENDOR_COMMAND table_x WITH MAGIC" });
    assert.equal(res.status, "denied");
    assert.equal(res.code, "ADAPTER_ERROR", `expected adapter syntax error, got ${res.code}`);
  });
  await check(`${SQLITE} admin statement still denied for non-admin in Development (PRAGMA writable_schema)`, async () => {
    const res = await s.call("execute_query", { connection: SQLITE, sql: "PRAGMA writable_schema=1" });
    expectOutcome("pragma-dev", res, P);
  });
  await check(`${SQLITE} cleanup probe table`, async () => {
    const res = await s.call("execute_query", { connection: SQLITE, sql: "DROP TABLE f06_dev_probe" });
    expectOutcome("drop-dev", res, OK);
  });
}

async function runSensitiveProjectionBypass(s) {
  console.log("\n## 3. Projection-alias / UNION disclosure bypass (cross-feature with result redaction)");
  const leaks = (res) => JSON.stringify(res.rows || []).includes("hash_");
  await check(`${MYSQL} baseline: SELECT password_hash is redacted`, async () => {
    const res = await s.call("execute_query", { connection: MYSQL, sql: "SELECT password_hash FROM users" });
    expectOutcome("baseline", res, OK);
    assert.equal(leaks(res), false, "password_hash values leaked without alias");
  });
  // Redaction keys on result column *names*; aliasing or UNION would hide the name, so policy denies
  // a sensitive column that is renamed before it can reach the result (fail closed).
  await check(`${MYSQL} alias bypass: SELECT password_hash AS x is denied, never returned raw`, async () => {
    const res = await s.call("execute_query", { connection: MYSQL, sql: "SELECT password_hash AS x FROM users" });
    assert.equal(leaks(res), false, `raw hashes returned: ${JSON.stringify(res.rows)}`);
    expectOutcome("alias", res, "SENSITIVE_COLUMN_FORBIDDEN");
  });
  await check(`${MYSQL} UNION bypass: SELECT 1 UNION SELECT password_hash is denied, never returned raw`, async () => {
    const res = await s.call("execute_query", { connection: MYSQL, sql: "SELECT 1 UNION SELECT password_hash FROM users" });
    assert.equal(leaks(res), false, `raw hashes returned: ${JSON.stringify(res.rows)}`);
    expectOutcome("union", res, "SENSITIVE_COLUMN_FORBIDDEN");
  });
  await check(`${PG} alias / expression bypass on the pg simulation is denied`, async () => {
    for (const sql of ["SELECT password_hash AS x FROM users", "SELECT upper(password_hash) AS u FROM users"]) {
      const res = await s.call("execute_query", { connection: PG, sql });
      assert.equal(leaks(res), false, `raw hashes returned: ${JSON.stringify(res.rows)}`);
      expectOutcome(sql, res, "SENSITIVE_COLUMN_FORBIDDEN");
    }
  });
}

async function runExplain(sessions) {
  console.log("\n## 4. explain_query shapes, analyze flag, params, errors, mutation refusal");
  const planMentionsUsers = (data) => {
    const blob = `${data.raw_plan}\n${JSON.stringify(data.structured_plan)}\n${(data.index_scans || []).join(",")}`;
    return /users/i.test(blob);
  };
  for (const conn of CONNS) {
    const s = sessions[conn];
    await check(`${conn} explain json shape`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT id, email FROM users WHERE id = 1", format: "json" });
      remember("explain_query", conn, res);
      expectOutcome("explain-json", res, OK);
      const d = res.data;
      assert.ok(d && typeof d === "object", "data missing");
      assert.equal(d.format, "json");
      assert.equal(d.analyze, false);
      assert.equal(typeof d.raw_plan, "string");
      assert.doesNotThrow(() => JSON.parse(d.raw_plan), "json raw_plan must be parseable JSON");
      assert.ok(d.structured_plan && typeof d.structured_plan === "object", "structured_plan must be object/array");
      assert.ok(Array.isArray(d.seq_scans) && Array.isArray(d.index_scans) && Array.isArray(d.warnings));
      assert.equal(typeof d.estimated_cost, "number");
      assert.equal(res.schema_version, "snapshot_explain");
      assert.equal(res._meta && res._meta.provenance && res._meta.provenance.source_kind, "explain_plan");
      assert.equal(res._meta.provenance.untrusted_content, true);
      assert.ok(planMentionsUsers(d), `plan should mention table users: ${d.raw_plan}`);
      assert.ok(d.index_scans.length >= 1, "PK lookup should be reported as index scan");
    });
    await check(`${conn} explain text shape`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT id, email FROM users WHERE id = 1", format: "text" });
      expectOutcome("explain-text", res, OK);
      const d = res.data;
      assert.equal(d.format, "text");
      assert.equal(typeof d.raw_plan, "string");
      assert.throws(() => JSON.parse(d.raw_plan), "text raw_plan must not be JSON");
      assert.ok(planMentionsUsers(d), `text plan should mention users: ${d.raw_plan}`);
    });
    await check(`${conn} explain default format is json`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT id FROM users" });
      expectOutcome("explain-default", res, OK);
      assert.equal(res.data.format, "json");
    });
    await check(`${conn} explain seq scan detected for unindexed predicate`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT id FROM orders WHERE status = 'pending'", format: "json" });
      expectOutcome("explain-seq", res, OK);
      assert.ok(res.data.seq_scans.length >= 1 || res.data.warnings.length >= 1, `expected seq scan or warning: ${JSON.stringify(res.data)}`);
    });
    await check(`${conn} explain with bound params`, async () => {
      const sql = conn === PG ? "SELECT id FROM users WHERE id = $1" : "SELECT id FROM users WHERE id = ?";
      const res = await s.call("explain_query", { connection: conn, sql, params: [1], format: "text" });
      expectOutcome("explain-params", res, OK);
      assert.equal(res.data.sql, sql);
    });
    const analyzeAllowed = conn === SQLITE; // allow_explain_analyze = true only on local-sqlite in the example config
    await check(`${conn} explain analyze=true -> ${analyzeAllowed ? "ok (static plan warning)" : X}`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT id FROM users WHERE id = 1", format: "json", analyze: true });
      remember("explain_query", conn, res);
      if (analyzeAllowed) {
        expectOutcome("analyze", res, OK);
        assert.equal(res.data.analyze, true);
        assert.ok(res.data.warnings.some((w) => /static|without executing/i.test(w)), "SQLite must warn that plan is static");
      } else {
        expectOutcome("analyze", res, X);
        assert.equal(res.next_action, "explain_query");
      }
    });
    await check(`${conn} explain SQL already prefixed with EXPLAIN -> clean INVALID_ARGUMENT`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "EXPLAIN SELECT 1", format: "text" });
      expectOutcome("explain-prefix", res, INV);
    });
    await check(`${conn} explain of EXPLAIN ANALYZE text -> ${analyzeAllowed ? INV : X}`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "EXPLAIN ANALYZE SELECT 1", format: "text" });
      expectOutcome("explain-analyze-text", res, analyzeAllowed ? INV : X);
    });
    await check(`${conn} explain multi-statement -> ${M}`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT 1; DROP TABLE users", format: "text" });
      remember("explain_query", conn, res);
      expectOutcome("explain-multi", res, M);
    });
    await check(`${conn} explain privileged function -> ${P}`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT pg_read_file('/etc/passwd')", format: "text" });
      remember("explain_query", conn, res);
      expectOutcome("explain-priv", res, P);
    });
    await check(`${conn} explain missing sql -> ${INV}`, async () => {
      const res = await s.call("explain_query", { connection: conn, format: "text" });
      expectOutcome("explain-nosql", res, INV);
    });
    const mutExp = conn === MYSQL ? R : conn === PG ? A : undefined;
    await check(`${conn} explain of DELETE is refused${mutExp ? ` -> ${mutExp}` : " (adapter READONLY_VIOLATION in Development)"}`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "DELETE FROM users WHERE id = 1", format: "json" });
      remember("explain_query", conn, res);
      if (mutExp) expectOutcome("explain-delete", res, mutExp);
      else { assert.equal(res.status, "denied"); assert.ok(["READONLY_VIOLATION", R, A].includes(res.code), res.code); }
    });
    await check(`${conn} explain of mutating CTE is refused`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", format: "json" });
      assert.equal(res.status, "denied", JSON.stringify(res).slice(0, 200));
      assert.ok(["READONLY_VIOLATION", R, A].includes(res.code), res.code);
    });
    if (conn !== MYSQL) {
      await check(`${conn} explain of restricted table -> ${RT}`, async () => {
        const res = await s.call("explain_query", { connection: conn, sql: "SELECT * FROM internal_secrets", format: "json" });
        remember("explain_query", conn, res);
        expectOutcome("explain-restricted", res, RT);
      });
    }
    const invalidExp = conn === SQLITE ? ["SQL_PARSE_ERROR", INV, "UNKNOWN_SQL_CONSTRUCT", U] : U;
    // SQLite adapter folds Unknown class into READONLY_VIOLATION (crates/db-mcp-sqlite/src/lib.rs:1235) -> misleading code.
    await check(`${conn} explain of unparseable SQL -> clean parse/unknown code`, async () => {
      const res = await s.call("explain_query", { connection: conn, sql: "SELECT FROM WHERE", format: "text" });
      expectOutcome("explain-invalid", res, invalidExp);
    }, conn === SQLITE ? "F06-B4" : undefined); // KNOWN-BUG: F06-B4 (local-sqlite only)
  }

  console.log("\n## 5. explain never mutates data (local-sqlite row counts before/after)");
  const s = sessions[SQLITE];
  const count = async () => (await s.call("execute_query", { connection: SQLITE, sql: "SELECT COUNT(*) AS n FROM audit_logs" })).rows[0][0];
  const before = await count();
  for (const [label, args] of [
    ["EXPLAIN INSERT (analyze=false)", { sql: "INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (101, 'F06', 'now')", format: "json" }],
    ["EXPLAIN INSERT (analyze=true)", { sql: "INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (101, 'F06', 'now')", format: "json", analyze: true }],
    ["EXPLAIN DELETE (analyze=true)", { sql: "DELETE FROM audit_logs", format: "text", analyze: true }],
    ["EXPLAIN CALL proc", { sql: "CALL reserve_inventory(101)", format: "json" }],
  ]) {
    await check(`${SQLITE} ${label} is refused even in Development`, async () => {
      const res = await s.call("explain_query", { connection: SQLITE, ...args });
      remember("explain_query", SQLITE, res);
      assert.equal(res.status, "denied", JSON.stringify(res).slice(0, 200));
      assert.equal(res.isError, true);
    });
  }
  await check(`${SQLITE} audit_logs row count unchanged after explain attempts (${before})`, async () => {
    assert.equal(await count(), before);
  });
}

async function runMultiStatementAllowed() {
  console.log("\n## 6. allow_multi_statement = true behaviour");
  const s = {};
  for (const c of CONNS) s[c] = await openSession(cfgMulti.configPath);
  try {
    await check(`${MYSQL} multi allowed: batch classified by worst statement (SELECT; DROP -> ${R})`, async () => {
      const res = await s[MYSQL].call("execute_query", { connection: MYSQL, sql: "SELECT 1; DROP TABLE users" });
      expectOutcome("worst", res, R);
    });
    await check(`${MYSQL} multi allowed: privileged function in 2nd statement -> ${P}`, async () => {
      const res = await s[MYSQL].call("execute_query", { connection: MYSQL, sql: "SELECT 1; SELECT pg_sleep(1)" });
      expectOutcome("priv2", res, P);
    });
    await check(`${PG} multi allowed: SELECT; DELETE -> ${A}`, async () => {
      const res = await s[PG].call("execute_query", { connection: PG, sql: "SELECT 1; DELETE FROM users" });
      expectOutcome("gov", res, A);
    });
    await check(`${MYSQL} multi allowed: two SELECTs accepted`, async () => {
      const res = await s[MYSQL].call("execute_query", { connection: MYSQL, sql: "SELECT 1 AS a; SELECT 2 AS b" });
      expectOutcome("two", res, OK);
    });
    await check(`${MYSQL} multi allowed: explain_query still single-statement only`, async () => {
      const res = await s[MYSQL].call("explain_query", { connection: MYSQL, sql: "SELECT 1; SELECT 2", format: "text" });
      expectOutcome("explain-multi-allowed", res, [INV, M]);
    });
    // Adapters prepare only the first statement (e.g. crates/db-mcp-sqlite/src/lib.rs:1364 conn.prepare) and
    // silently discard the tail: no warning, no error, no second result set.
    await check(`${SQLITE} multi allowed: trailing statements are executed or explicitly reported`, async () => { // KNOWN-BUG: F06-B2
      const res = await s[SQLITE].call("execute_query", { connection: SQLITE, sql: "SELECT 1 AS a; SELECT 2 AS b" });
      expectOutcome("tail", res, OK);
      const names = (res.columns || []).map((c) => c.name);
      const secondExecuted = names.includes("b");
      const reported = (res.warnings || []).some((w) => /statement/i.test(w));
      assert.ok(secondExecuted || reported, `second statement silently dropped: columns=${names} warnings=${JSON.stringify(res.warnings)}`);
    }, "F06-B2");
    await check(`${SQLITE} multi allowed: DML in the middle of a batch is applied or explicitly reported`, async () => { // KNOWN-BUG: F06-B2
      const n = async () => (await s[SQLITE].call("execute_query", { connection: SQLITE, sql: "SELECT COUNT(*) FROM orders" })).rows[0][0];
      const before = await n();
      const res = await s[SQLITE].call("execute_query", { connection: SQLITE, sql: `SELECT 1; INSERT INTO orders (id, user_id, status, total_cents, created_at) VALUES (${900 + before}, 1, 'f06', 1, 'now'); SELECT 2` });
      expectOutcome("batch", res, OK);
      const after = await n();
      const reported = (res.warnings || []).some((w) => /statement/i.test(w));
      assert.ok(after === before + 1 || reported, `INSERT silently dropped (before=${before} after=${after}) warnings=${JSON.stringify(res.warnings)}`);
    }, "F06-B2");
  } finally {
    for (const c of CONNS) await s[c].close();
  }
}

async function runEnvelope(sessions) {
  console.log("\n## 7. Denial envelope hygiene");
  const isoDir = cfgMain.dir.replace(/\\/g, "/");
  const noSecrets = (text) => {
    const t = String(text || "");
    assert.ok(!t.includes(isoDir) && !/[A-Za-z]:\\/.test(t) && !t.includes("sqlite://") && !/hash_(alice|bob)/.test(t) && !/postgres:\/\/|mysql:\/\//.test(t), `message leaks path/DSN/secret: ${t}`);
  };
  const cases = [
    [MYSQL, "SELECT pg_read_file('/etc/passwd')", P, "remove_privileged_function"],
    [MYSQL, "SELECT 1; DROP TABLE users", M, "split_statements"],
    [MYSQL, "DELETE FROM users", R, "propose_change"],
    [MYSQL, "FOOBAR_VENDOR_COMMAND x", U, "rewrite_standard_sql"],
    [PG, "DELETE FROM users", A, "propose_change"],
  ];
  for (const [conn, sql, code, next] of cases) {
    await check(`${conn} envelope for ${code}: status/code/message/next_action/request_id/retryable`, async () => {
      const res = await sessions[conn].call("execute_query", { connection: conn, sql });
      remember("execute_query", conn, res);
      expectOutcome("env", res, code);
      assert.equal(typeof res.request_id, "string");
      assert.equal(res.connection, conn);
      assert.equal(res.retryable, false);
      assert.equal(typeof res.message, "string");
      assert.ok(res.message.includes(code), "message should carry the code");
      noSecrets(res.message);
      assert.equal(res.next_action, next);
    });
  }
  // PrivilegeOrAdmin statement denials carry no next_action (crates/db-mcp-policy/src/lib.rs:686-701).
  await check(`${PG} admin-statement denial carries a helpful next_action`, async () => { // KNOWN-BUG: F06-B8
    const res = await sessions[PG].call("execute_query", { connection: PG, sql: "COPY users TO PROGRAM 'id'" });
    expectOutcome("admin", res, P);
    assert.equal(typeof res.next_action, "string", "next_action missing on admin denial");
  }, "F06-B8");
  await check(`${MYSQL} adapter-level errors never echo DSN/paths`, async () => {
    const res = await sessions[MYSQL].call("execute_query", { connection: MYSQL, sql: "SELECT * FROM no_such_table_f06" });
    assert.equal(res.status, "denied");
    assert.equal(res.code, "ADAPTER_ERROR");
    noSecrets(res.message);
  });
}

async function runAudit() {
  console.log("\n## 8. Audit trail for denials (isolated audit.jsonl)");
  const auditPath = path.join(cfgMain.dir, "audit.jsonl");
  let lines = [];
  await check(`audit.jsonl exists and parses`, async () => {
    assert.ok(fs.existsSync(auditPath), auditPath);
    lines = fs.readFileSync(auditPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(lines.length > 50, `only ${lines.length} audit lines`);
  });
  const byReq = new Map(lines.map((l) => [l.request_id, l]));
  const policyCodes = new Set([M, P, R, A, U, X, RT]);
  const policyDenials = denied.filter((d) => policyCodes.has(d.code));
  await check(`every policy denial (${policyDenials.length}) has an audit entry with matching denial_code and decision denied/requires_approval`, async () => {
    const missing = [];
    for (const d of policyDenials) {
      const e = byReq.get(d.request_id);
      if (!e) { missing.push(`${d.tool}/${d.conn}/${d.code}: no entry`); continue; }
      const okDecision = d.code === A ? e.decision === "requires_approval" : e.decision === "denied";
      if (!okDecision || e.denial_code !== d.code || e.tool_name !== d.tool) missing.push(`${d.request_id}: ${e.tool_name}/${e.decision}/${e.denial_code} vs ${d.tool}/${d.code}`);
    }
    assert.equal(missing.length, 0, missing.slice(0, 5).join("; "));
  });
  await check(`explain_query denials are audited with tool_name=explain_query`, async () => {
    const n = lines.filter((l) => l.tool_name === "explain_query" && l.decision === "denied").length;
    assert.ok(n >= 6, `only ${n} denied explain_query audit entries`);
  });
  await check(`audit entries carry hash chain, sql_hash and normalized_sql for denials`, async () => {
    const e = lines.find((l) => l.decision === "denied" && l.denial_code === P && /pg_read_file/.test(l.normalized_sql || ""));
    assert.ok(e, "no denied pg_read_file audit entry");
    assert.equal(typeof e.chain_hash, "string");
    assert.equal(typeof e.prev_hash, "string");
    assert.equal(typeof e.sql_hash, "string");
    assert.equal(e.statement_class, "privilege_or_admin");
  });
  await check(`audit never records the isolated config path or DSN`, async () => {
    const raw = fs.readFileSync(auditPath, "utf8");
    assert.ok(!raw.includes("sqlite://") && !raw.includes(cfgMain.dir.replace(/\\/g, "/")) && !raw.includes(cfgMain.dir.replace(/\\/g, "\\\\")));
  });
  // Executor maps every adapter error (incl. DbMcpError::PolicyDenied READONLY_VIOLATION) to decision=failed
  // (crates/db-mcp-executor/src/lib.rs:682-712); a refused explain of a mutation should read as a denial.
  await check(`${SQLITE} refused explain-of-mutation is audited as decision=denied`, async () => { // KNOWN-BUG: F06-B5
    const d = denied.find((x) => x.conn === SQLITE && x.tool === "explain_query" && x.code === "READONLY_VIOLATION");
    assert.ok(d, "no READONLY_VIOLATION explain denial captured");
    const e = byReq.get(d.request_id);
    assert.ok(e, "no audit entry");
    assert.equal(e.decision, "denied", `decision=${e.decision}`);
  }, "F06-B5");
  await check(`${MYSQL} execute_query EXPLAIN ANALYZE is audited as a policy denial (not an adapter failure)`, async () => {
    const e = lines.find((l) => l.connection === MYSQL && l.tool_name === "execute_query" && /^EXPLAIN ANALYZE SELECT/i.test(l.normalized_sql || ""));
    assert.ok(e, "no audit entry for EXPLAIN ANALYZE");
    assert.equal(e.decision, "denied", `decision=${e.decision} denial_code=${e.denial_code}`);
    assert.equal(e.denial_code, X);
  });
}

// ---------------------------------------------------------------------------
async function main() {
  console.log(`F06 SQL guards / explain_query verification`);
  console.log(`isolated configs: ${cfgMain.configPath} | ${cfgMulti.configPath}`);
  const sessions = {};
  try {
    for (const c of CONNS) sessions[c] = await openSession(cfgMain.configPath);
    await runMatrix(sessions);
    await runDevelopmentFallthrough(sessions[SQLITE]);
    await runSensitiveProjectionBypass(sessions[MYSQL]);
    await runExplain(sessions);
    await runEnvelope(sessions);
    for (const c of CONNS) { await sessions[c].close(); delete sessions[c]; }
    await runMultiStatementAllowed();
    await runAudit();
  } finally {
    for (const c of Object.keys(sessions)) { try { await sessions[c].close(); } catch {} }
    for (const ch of children) { try { if (ch.exitCode === null) ch.kill(); } catch {} }
    setTimeout(() => { try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {} }, 500);
  }
  const total = tally.pass + tally.fail + tally.xfail + tally.xpass;
  console.log(`\n== F06 summary: ${tally.pass} passed, ${tally.fail} failed, ${tally.xfail} xfail (known bugs), ${tally.xpass} xpass, ${total} checks ==`);
  if (failures.length) { console.log("Failures:"); for (const f of failures) console.log(`  - ${f}`); }
  process.exitCode = tally.fail === 0 ? 0 : 1;
}

main().catch((err) => {
  console.error(`[F06] fatal: ${err && err.stack ? err.stack : err}`);
  for (const ch of children) { try { ch.kill(); } catch {} }
  process.exitCode = 1;
});
