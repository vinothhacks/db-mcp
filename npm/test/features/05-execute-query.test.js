#!/usr/bin/env node
"use strict";
/**
 * F05 - execute_query: bounded, policy-governed SQL execution.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *   node npm/test/features/05-execute-query.test.js
 *
 * Every check runs against private isolated configs (see scripts/make-isolated-config.js);
 * nothing under config/ or research/ is touched. One line is printed per check.
 * Assertions encode the CORRECT behaviour; checks that currently fail because of a known
 * defect are tagged `// KNOWN-BUG: F05-Bn` (and labelled in the output) rather than weakened.
 *
 * Exit code: 0 when every check passes, 1 otherwise.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.resolve(__dirname, "..", "..", "..");
const { createClient } = require(path.join(REPO, "scripts", "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(REPO, "scripts", "make-isolated-config.js"));
process.chdir(REPO);

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------
const results = [];
const allMessages = []; // every message/warning string seen, scanned for leaks at the end
const clients = [];
let isoDir = null;

async function check(name, fn, knownBug) {
  try {
    const detail = await fn();
    results.push({ name, ok: true, knownBug });
    console.log(`PASS  ${name}${knownBug ? `  (tagged ${knownBug} but passing - re-check)` : ""}${detail ? "  :: " + detail : ""}`);
  } catch (err) {
    results.push({ name, ok: false, knownBug, err });
    const msg = (err && err.message ? err.message : String(err)).split("\n")[0].slice(0, 260);
    console.log(`FAIL  ${name}${knownBug ? `  [KNOWN-BUG ${knownBug}]` : ""}  :: ${msg}`);
  }
}

const INIT = { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f05-test", version: "0" } };
async function openClient(config, principal, role) {
  const c = createClient({ config, principal, role, timeoutMs: 60000 });
  clients.push(c);
  const init = await c.rpc("initialize", INIT);
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  c.notify("notifications/initialized", {});
  return c;
}

/** Call execute_query and return { payload, raw } (payload = structuredContent). */
async function eq(c, args) {
  const resp = await c.rpc("tools/call", { name: "execute_query", arguments: args });
  if (resp.error) throw new Error(`JSON-RPC error: ${JSON.stringify(resp.error)}`);
  const payload = resp.result.structuredContent;
  if (payload && typeof payload.message === "string") allMessages.push(payload.message);
  if (payload && Array.isArray(payload.warnings)) allMessages.push(...payload.warnings);
  return { payload, raw: resp.result };
}

/** Send a raw JSON-RPC line (to control numeric literal digits exactly) and await the reply. */
function rawCall(c, id, argsJson, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const line = `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"execute_query","arguments":${argsJson}}}\n`;
    const start = c.notifications.length;
    c.child.stdin.write(line);
    const deadline = Date.now() + timeoutMs;
    const iv = setInterval(() => {
      const m = c.notifications.slice(start).find((n) => n.id === id || n.id === null);
      if (m) { clearInterval(iv); resolve(m); }
      else if (Date.now() > deadline) { clearInterval(iv); reject(new Error("raw call timed out")); }
    }, 15);
  });
}

function okEnvelope(p, label = "") {
  assert.equal(p.status, "ok", `${label} expected ok, got ${JSON.stringify(p).slice(0, 300)}`);
  for (const k of ["request_id", "connection", "status", "columns", "rows", "returned_rows", "truncated", "warnings", "schema_version", "_meta"]) {
    assert.ok(k in p, `${label} envelope missing '${k}'`);
  }
  assert.equal(p._meta.provenance.untrusted_content, true, `${label} _meta.provenance.untrusted_content`);
  assert.equal(typeof p.schema_version, "string");
  assert.equal(p.returned_rows, p.rows.length, `${label} returned_rows must equal rows.length`);
  for (const col of p.columns) {
    assert.equal(typeof col.name, "string");
    assert.equal(typeof col.data_type, "string");
    assert.equal(typeof col.redacted, "boolean");
  }
  return p;
}
function denied(p, codes, label = "") {
  assert.equal(p.status, "denied", `${label} expected denied, got ${JSON.stringify(p).slice(0, 300)}`);
  const list = Array.isArray(codes) ? codes : [codes];
  assert.ok(list.includes(p.code), `${label} expected code in [${list}], got ${p.code} (${p.message})`);
  assert.equal(typeof p.message, "string");
  assert.equal(typeof p.retryable, "boolean");
  return p;
}
const colNames = (p) => p.columns.map((c) => c.name);
const flat = (p) => p.rows.flat();

// ---------------------------------------------------------------------------------------------
// Isolated configuration
// ---------------------------------------------------------------------------------------------
function sqliteConnectionBlock(id, overrides = {}) {
  const base = {
    mode: "Development", timeout_ms: 10000, max_rows: 500, max_bytes: 1048576,
    deny_sensitive_column_access: false, unrestricted_sql_provenance: false,
    sensitive_tables: "[]", allowed_roles: '["*"]', allowed_principals: '["*"]',
  };
  const o = { ...base, ...overrides };
  return `
[[connections]]
id = "${id}"
engine = "Sqlite"
dsn = "sqlite://__ISO_DIR__/${id}.db"
mode = "${o.mode}"
read_only = false
description = "F05 test connection ${id}"
default_schema = "main"
timeout_ms = ${o.timeout_ms}
max_rows = ${o.max_rows}
max_bytes = ${o.max_bytes}
allow_multi_statement = false
allow_explain_analyze = true
restricted_tables = ["internal_secrets"]
sensitive_tables = ${o.sensitive_tables}
sensitive_columns = ["password_hash", "api_key", "secret_token"]
deny_sensitive_column_access = ${o.deny_sensitive_column_access}
unrestricted_sql_provenance = ${o.unrestricted_sql_provenance}
allowed_roles = ${o.allowed_roles}
allowed_principals = ${o.allowed_principals}
init_sql = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, status TEXT NOT NULL, total_cents INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS big (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
INSERT OR IGNORE INTO users (id, email, role, password_hash, created_at) VALUES (1, 'alice@example.com', 'admin', 'hash_alice_secret', '2025-01-01T00:00:00Z'), (2, 'bob@example.com', 'customer', 'hash_bob_secret', '2025-01-02T00:00:00Z');
WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM s WHERE x < 50) INSERT OR IGNORE INTO big (id, payload) SELECT x, 'row-' || x || '-' || hex(randomblob(16)) FROM s;
"""
`;
}

function buildMainConfig() {
  const seed = [
    "DROP TABLE IF EXISTS big;",
    "CREATE TABLE big (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);",
    "WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM s WHERE x < 2000) INSERT INTO big (id, payload) SELECT x, 'row-' || x || '-' || hex(randomblob(16)) FROM s;",
    "CREATE VIEW active_user_orders AS",
  ].join("\n");
  const extra =
    sqliteConnectionBlock("slow-sqlite", { timeout_ms: 1000, max_bytes: 300 }) +
    sqliteConnectionBlock("deny-sqlite", { deny_sensitive_column_access: true }) +
    sqliteConnectionBlock("prov-sqlite", { unrestricted_sql_provenance: true, sensitive_tables: '["users"]' }) +
    sqliteConnectionBlock("principal-sqlite", { allowed_principals: '["alice"]' }) +
    sqliteConnectionBlock("role-sqlite", { allowed_roles: '["dba"]' });
  const { configPath, dir } = makeIsolatedConfig({
    transform: (text) => text
      .replace(/CREATE VIEW active_user_orders AS/, seed)
      .replace("[[named_tools]]", extra + "\n[[named_tools]]"),
  });
  const posixDir = dir.replace(/\\/g, "/");
  fs.writeFileSync(configPath, fs.readFileSync(configPath, "utf8").replace(/__ISO_DIR__/g, posixDir));
  isoDir = dir;
  return configPath;
}

function buildUnreachableDsnConfig() {
  return makeIsolatedConfig({
    transform: (t) => t
      .replace('dsn = "postgres://localhost:5432/app_prod"', 'dsn = "postgres://10.255.255.1:5432/app_prod"')
      .replace('dsn = "mysql://localhost:3306/analytics"', 'dsn = "mysql://10.255.255.1:3306/analytics"'),
  }).configPath;
}

const L = "local-sqlite";
const P = "prod-postgres";
const M = "analytics-mysql";
const SLOW_1S = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 6000000) SELECT count(*) AS n FROM c";
const SLOW_3S = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 18000000) SELECT count(*) AS n FROM c";

// ---------------------------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------------------------
async function sectionParams(c) {
  await check("1.01 positional ?1 binds int, float and quoted string", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT ?1 AS a, ?2 AS b, ?3 AS c", params: [42, 3.5, "O'Brien"] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[42, 3.5, "O'Brien"]]);
    assert.deepEqual(p.columns.map((x) => x.data_type), ["INTEGER", "REAL", "TEXT"]);
  });
  await check("1.02 unicode + emoji parameter round-trips", async () => {
    const s = "héllo 日本 😀";
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT ?1 AS u, length(?1) AS n", params: [s] });
    okEnvelope(p);
    assert.equal(p.rows[0][0], s);
    assert.equal(p.rows[0][1], 10);
  });
  await check("1.03 100 KB string parameter binds and round-trips", async () => {
    const s = "x".repeat(100 * 1024);
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT length(?1) AS n, ?1 AS s", params: [s] });
    okEnvelope(p);
    assert.equal(p.rows[0][0], 102400);
    assert.equal(p.rows[0][1], s);
  });
  await check("1.04 null and boolean parameters bind (bool -> 0/1 integer)", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT ?1 AS n, typeof(?1) AS tn, ?2 AS t, ?3 AS f, typeof(?2) AS tt", params: [null, true, false] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[null, "null", 1, 0, "integer"]]);
  });
  await check("1.05 nested JSON parameter is serialised as text (not rejected, not expanded)", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT ?1 AS j, typeof(?1) AS t", params: [{ a: [1, 2] }] });
    okEnvelope(p);
    assert.equal(p.rows[0][1], "text");
    assert.deepEqual(JSON.parse(p.rows[0][0]), { a: [1, 2] });
  });
  await check("1.06 anonymous ? placeholders bind in order", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT email FROM users WHERE id = ? AND role = ?", params: [1, "admin"] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [["alice@example.com"]]);
  });
  await check("1.07 too few parameters -> clear denial naming the count", async () => {
    const { payload: p, raw } = await eq(c, { connection: L, sql: "SELECT email FROM users WHERE id = ?1 AND role = ?2", params: [1] });
    denied(p, ["ADAPTER_ERROR", "INVALID_ARGUMENT"]);
    assert.match(p.message, /parameter/i);
    assert.equal(raw.isError, true);
  });
  await check("1.08 too many parameters -> clear denial", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT email FROM users WHERE id = ?1", params: [1, 2] });
    denied(p, ["ADAPTER_ERROR", "INVALID_ARGUMENT"]);
    assert.match(p.message, /parameter/i);
  });
  await check("1.09 SQL injection through a bound parameter is inert", async () => {
    const a = await eq(c, { connection: L, sql: "SELECT id FROM users WHERE id = ?1", params: ["1 OR 1=1"] });
    const b = await eq(c, { connection: L, sql: "SELECT id FROM users WHERE email = ?1", params: ["' OR '1'='1"] });
    okEnvelope(a.payload); okEnvelope(b.payload);
    assert.equal(a.payload.returned_rows, 0);
    assert.equal(b.payload.returned_rows, 0);
    const u = await eq(c, { connection: L, sql: "SELECT count(*) AS n FROM users" });
    assert.equal(u.payload.rows[0][0], 2, "table untouched");
  });
  await check("1.10 non-array `params` is not silently accepted as a successful query", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT ?1 AS a", params: "oops" });
    denied(p, ["ADAPTER_ERROR", "INVALID_ARGUMENT"]);
  });
  await check("1.11 i64::MAX parameter round-trips exactly (raw JSON digits)", async () => {
    const m = await rawCall(c, 9101, '{"connection":"local-sqlite","sql":"SELECT ?1 AS p, typeof(?1) AS t","params":[9223372036854775807]}');
    assert.ok(m.result, JSON.stringify(m.error));
    assert.match(m.result.content[0].text, /"rows":\[\[9223372036854775807,"integer"\]\]/);
  });
  // KNOWN-BUG: F05-B6 - u64 values above i64::MAX wrap to negative (sqlite adapter `u as i64`).
  await check("1.12 integer parameter above i64::MAX is not silently wrapped to a negative number", async () => {
    const m = await rawCall(c, 9102, '{"connection":"local-sqlite","sql":"SELECT ?1 AS p, typeof(?1) AS t","params":[18446744073709551615]}');
    assert.ok(m.result, JSON.stringify(m.error));
    const text = m.result.content[0].text;
    const sc = m.result.structuredContent;
    if (sc.status === "ok") {
      assert.ok(!/"rows":\[\[-1,/.test(text), `u64::MAX bound as -1: ${text.slice(0, 200)}`);
      assert.ok(!/"rows":\[\[-9223372036854775808,/.test(text), "wrapped to i64::MIN");
    } else {
      denied(sc, ["INVALID_ARGUMENT", "ADAPTER_ERROR"]);
    }
  }, "F05-B6");
  await check("1.13 out-of-range numeric literal (1e400) -> JSON-RPC -32700 and server stays alive", async () => {
    const m = await rawCall(c, 9103, '{"connection":"local-sqlite","sql":"SELECT ?1 AS p","params":[1e400]}');
    assert.ok(m.error, "expected a JSON-RPC error");
    assert.equal(m.error.code, -32700);
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1 AS ok" });
    okEnvelope(p);
  });
  await check("1.14 prod-postgres: $1 placeholder binds", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT id, email FROM users WHERE id = $1", params: [1] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[1, "alice@example.com"]]);
  });
  // KNOWN-BUG: F05-B7 - embedded PG engine binds $n by order of appearance, not by number.
  await check("1.15 prod-postgres: $2 before $1 still binds by number", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT id FROM users WHERE id = $2 OR email = $1 ORDER BY id", params: ["bob@example.com", 1] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[1], [2]]);
  }, "F05-B7");
  await check("1.16 prod-postgres: wrong $n count -> clear denial", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT id FROM users WHERE id = $1 AND role = $2", params: [1] });
    denied(p, ["ADAPTER_ERROR", "INVALID_ARGUMENT"]);
  });
  await check("1.17 analytics-mysql: ? placeholder with backtick identifiers binds", async () => {
    const { payload: p } = await eq(c, { connection: M, sql: "SELECT `email` FROM `users` WHERE `id` = ?", params: [2] });
    okEnvelope(p);
    assert.deepEqual(p.rows, [["bob@example.com"]]);
  });
}

async function sectionEncoding(c) {
  await check("2.01 column metadata carries name/data_type/redacted; rows are arrays aligned to columns", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id, email FROM users ORDER BY id" });
    okEnvelope(p);
    assert.deepEqual(colNames(p), ["id", "email"]);
    assert.deepEqual(p.columns.map((x) => x.data_type), ["INTEGER", "TEXT"]);
    assert.ok(p.rows.every((r) => r.length === 2));
  });
  await check("2.02 NULL cells are JSON null", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT NULL AS n, id FROM users WHERE id = 1" });
    okEnvelope(p);
    assert.equal(p.rows[0][0], null);
  });
  await check("2.03 BLOB cells are hex strings with BLOB type", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT X'DEADBEEF' AS b, zeroblob(2) AS z" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [["0xdeadbeef", "0x0000"]]);
    assert.deepEqual(p.columns.map((x) => x.data_type), ["BLOB", "BLOB"]);
  });
  await check("2.04 integers above 2^53 keep exact digits on the wire", async () => {
    const m = await rawCall(c, 9201, '{"connection":"local-sqlite","sql":"SELECT 9007199254740993 AS big, 9223372036854775807 AS mx, -9223372036854775808 AS mn"}');
    assert.ok(m.result, JSON.stringify(m.error));
    assert.match(m.result.content[0].text, /"rows":\[\[9007199254740993,9223372036854775807,-9223372036854775808\]\]/);
  });
  await check("2.05 floats encode as JSON numbers; non-finite REAL does not break the envelope", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1.5 AS f, -0.25 AS g, 1e300*1e300 AS inf" });
    okEnvelope(p);
    assert.equal(p.rows[0][0], 1.5);
    assert.equal(p.rows[0][1], -0.25);
    assert.ok(p.rows[0][2] === null || typeof p.rows[0][2] === "string", "Infinity must become null or a string, never crash");
  });
  await check("2.06 date functions return TEXT", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT date('2025-01-01') AS d, created_at FROM users WHERE id = 1" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [["2025-01-01", "2025-01-01T00:00:00Z"]]);
    assert.equal(p.columns[0].data_type, "TEXT");
  });
  await check("2.07 duplicate output column names are preserved positionally", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1 AS a, 2 AS a, id AS a FROM users ORDER BY id" });
    okEnvelope(p);
    assert.deepEqual(colNames(p), ["a", "a", "a"]);
    assert.deepEqual(p.rows, [[1, 2, 1], [1, 2, 2]]);
  });
  await check("2.08 empty result keeps columns, rows=[], returned_rows=0, truncated=false", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id, email FROM users WHERE id = -1" });
    okEnvelope(p);
    assert.deepEqual(colNames(p), ["id", "email"]);
    assert.deepEqual(p.rows, []);
    assert.equal(p.returned_rows, 0);
    assert.equal(p.truncated, false);
  });
}

async function sectionLimits(c) {
  await check("3.01 connection max_rows (500) caps a 2000-row result, truncated=true with warning", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id" });
    okEnvelope(p);
    assert.equal(p.returned_rows, 500);
    assert.equal(p.truncated, true);
    assert.ok(p.warnings.some((w) => /max_rows/.test(w)), JSON.stringify(p.warnings));
  });
  await check("3.02 request max_rows=5 overrides downward, truncated=true", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id", max_rows: 5 });
    okEnvelope(p);
    assert.deepEqual(flat(p), [1, 2, 3, 4, 5]);
    assert.equal(p.truncated, true);
  });
  await check("3.03 truncated=false when the result has exactly max_rows rows", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id LIMIT 5", max_rows: 5 });
    okEnvelope(p);
    assert.equal(p.returned_rows, 5);
    assert.equal(p.truncated, false);
    assert.deepEqual(p.warnings, []);
  });
  await check("3.04 request max_rows above the connection cap is clamped to the cap", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id", max_rows: 5000 });
    okEnvelope(p);
    assert.equal(p.returned_rows, 500);
    assert.equal(p.truncated, true);
  });
  // F05-B4 fixed: a zero budget override is rejected instead of disabling the cap.
  await check("3.05 request max_rows=0 cannot exceed the connection cap", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id", max_rows: 0 });
    denied(p, "INVALID_ARGUMENT");
  });
  await check("3.06 negative / string / huge max_rows never exceed the cap", async () => {
    for (const v of [-1, "5", 1e18]) {
      const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM big ORDER BY id", max_rows: v });
      if (p.status === "denied") { denied(p, "INVALID_ARGUMENT"); continue; }
      okEnvelope(p);
      assert.ok(p.returned_rows <= 500, `max_rows=${v} returned ${p.returned_rows}`);
    }
  });
  await check("3.07 small max_bytes truncates by bytes with a warning", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id, payload FROM big ORDER BY id", max_bytes: 200 });
    okEnvelope(p);
    assert.equal(p.truncated, true);
    assert.ok(p.returned_rows >= 1 && p.returned_rows < 10, `returned ${p.returned_rows}`);
    assert.ok(p.warnings.some((w) => /max_bytes/.test(w)), JSON.stringify(p.warnings));
    assert.ok(JSON.stringify(p.rows).length < 600);
  });
  await check("3.08 max_bytes=1 yields an ok envelope with zero rows and truncated=true", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id, payload FROM big ORDER BY id", max_bytes: 1 });
    okEnvelope(p);
    assert.equal(p.returned_rows, 0);
    assert.equal(p.truncated, true);
  });
  await check("3.09 connection max_bytes (300 on slow-sqlite) applies without a request override", async () => {
    const { payload: p } = await eq(c, { connection: "slow-sqlite", sql: "SELECT id, payload FROM big ORDER BY id" });
    okEnvelope(p);
    assert.equal(p.truncated, true);
    assert.ok(p.returned_rows < 50, `returned ${p.returned_rows}`);
  });
  await check("3.10 request max_bytes=0 cannot exceed the connection byte budget", async () => {
    const { payload: p } = await eq(c, { connection: "slow-sqlite", sql: "SELECT id, payload FROM big ORDER BY id", max_bytes: 0 });
    denied(p, "INVALID_ARGUMENT");
  });
  await check("3.11 timeout_ms=1 against a slow recursive CTE -> EXECUTION_TIMEOUT (retryable)", async () => {
    const t0 = Date.now();
    const { payload: p, raw } = await eq(c, { connection: L, sql: SLOW_1S, timeout_ms: 1 });
    denied(p, "EXECUTION_TIMEOUT");
    assert.equal(p.retryable, true);
    assert.equal(raw.isError, true);
    assert.ok(Date.now() - t0 < 1500, "timeout must fire promptly");
  });
  await check("3.12 server healthy after timeout: next call succeeds quickly (interrupt handle works)", async () => {
    const t0 = Date.now();
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1 AS ok" });
    okEnvelope(p);
    const ms = Date.now() - t0;
    assert.ok(ms < 1500, `post-timeout call took ${ms}ms`);
    return `${ms}ms`;
  });
  await check("3.13 connection timeout_ms (1000 on slow-sqlite) enforced without override", async () => {
    const t0 = Date.now();
    const { payload: p } = await eq(c, { connection: "slow-sqlite", sql: SLOW_3S });
    denied(p, "EXECUTION_TIMEOUT");
    assert.ok(Date.now() - t0 < 2500);
  });
  await check("3.14 request timeout_ms above the connection cap is clamped", async () => {
    const t0 = Date.now();
    const { payload: p } = await eq(c, { connection: "slow-sqlite", sql: SLOW_3S, timeout_ms: 60000 });
    denied(p, "EXECUTION_TIMEOUT");
    assert.ok(Date.now() - t0 < 2500);
  });
  await check("3.15 request timeout_ms=0 cannot exceed the connection timeout", async () => {
    const t0 = Date.now();
    const { payload: p } = await eq(c, { connection: "slow-sqlite", sql: SLOW_3S, timeout_ms: 0 });
    denied(p, "INVALID_ARGUMENT", `(took ${Date.now() - t0}ms)`);
    assert.ok(Date.now() - t0 < 2500, `ran ${Date.now() - t0}ms past the 1000ms connection cap`);
  });
  await check("3.16 negative timeout_ms is ignored or rejected, never a hang", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1 AS ok", timeout_ms: -5 });
    if (p.status === "denied") { denied(p, "INVALID_ARGUMENT"); return; }
    okEnvelope(p);
  });
}

async function sectionCancellation(config) {
  // Dedicated client so a wedged query cannot disturb the other sections.
  const c = await openClient(config, "cancel-agent", "agent");
  let lastId = null;
  const origWrite = c.child.stdin.write.bind(c.child.stdin);
  c.child.stdin.write = (s, ...rest) => { try { const m = JSON.parse(s); if (m.id !== undefined) lastId = m.id; } catch { /* ignore */ } return origWrite(s, ...rest); };

  // KNOWN-BUG: F05-B3 - stdio loop is sequential and cancel handler keys on the internal req_<uuid> id.
  await check("4.01 notifications/cancelled (MCP requestId) aborts a running query -> EXECUTION_CANCELLED", async () => {
    const t0 = Date.now();
    const pending = c.rpc("tools/call", { name: "execute_query", arguments: { connection: L, sql: SLOW_1S } });
    const id = lastId;
    await new Promise((r) => setTimeout(r, 120));
    c.notify("notifications/cancelled", { requestId: id, reason: "test" });
    c.notify("notifications/cancelled", { requestId: String(id), reason: "test" });
    const resp = await pending;
    const p = resp.result.structuredContent;
    denied(p, "EXECUTION_CANCELLED", `(query finished in ${Date.now() - t0}ms with status ${p.status})`);
  }, "F05-B3");
  // KNOWN-BUG: F05-B3
  await check("4.02 explicit `cancel` request while a query runs reports cancelled=true", async () => {
    const pending = c.rpc("tools/call", { name: "execute_query", arguments: { connection: L, sql: SLOW_1S } });
    const id = lastId;
    await new Promise((r) => setTimeout(r, 120));
    const cancelResp = c.rpc("cancel", { requestId: String(id) });
    await pending;
    const r = (await cancelResp).result;
    assert.equal(r && r.cancelled, true, `cancel returned ${JSON.stringify(r)}`);
  }, "F05-B3");
  await check("4.03 client stays usable after cancellation attempts", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1 AS ok" });
    okEnvelope(p);
  });
}

async function sectionRedaction(c) {
  const redactedOk = (p, idx = 0) => {
    okEnvelope(p);
    assert.equal(p.columns[idx].redacted, true, `column ${idx} not flagged redacted`);
    assert.ok(p.rows.every((r) => r[idx] === "[REDACTED]"), JSON.stringify(p.rows));
    assert.ok(p.warnings.some((w) => /redact/i.test(w)));
    assert.ok(!JSON.stringify(p.rows).includes("hash_alice_secret"), "secret leaked");
  };
  await check("5.01 direct SELECT of password_hash -> [REDACTED] + redacted flag + warning", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT password_hash FROM users" });
    redactedOk(p);
  });
  await check("5.02 SELECT * redacts only the sensitive column", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT * FROM users ORDER BY id" });
    redactedOk(p, 3);
    assert.equal(p.rows[0][1], "alice@example.com");
    assert.equal(p.columns[1].redacted, false);
  });
  await check("5.03 qualified / upper-case / CTE / JOIN projections of password_hash are redacted", async () => {
    for (const sql of [
      "SELECT users.password_hash FROM users",
      "SELECT PASSWORD_HASH FROM users",
      "WITH c AS (SELECT password_hash FROM users) SELECT * FROM c",
      "SELECT u.password_hash, o.id FROM users u JOIN orders o ON o.user_id = u.id",
    ]) {
      const { payload: p } = await eq(c, { connection: L, sql });
      redactedOk(p, 0);
    }
  });
  // Redaction masks by output column name, so a sensitive column that is renamed (alias, expression,
  // subquery re-alias, set-operation position) is denied before execution (fail closed).
  const leak = async (label, sql) => check(label, async () => {
    const { payload: p } = await eq(c, { connection: L, sql });
    const text = JSON.stringify(p.rows || []).toLowerCase();
    assert.ok(!text.includes("hash_alice_secret") && !text.includes("hash_bob_secret"), `sensitive value leaked: ${JSON.stringify(p.rows)}`);
    denied(p, "SENSITIVE_COLUMN_FORBIDDEN", sql);
    assert.equal(p.next_action, "select_sensitive_column_directly");
  });
  await leak("5.04 aliased sensitive column (password_hash AS ph) does not leak", "SELECT password_hash AS ph FROM users");
  await leak("5.05 expression over sensitive column (upper(password_hash)) does not leak", "SELECT upper(password_hash) FROM users");
  await leak("5.06 concatenation with sensitive column does not leak", "SELECT email || ':' || password_hash AS creds FROM users");
  await leak("5.07 sensitive column re-aliased through a subquery does not leak", "SELECT ph FROM (SELECT password_hash AS ph FROM users)");
  await leak("5.07b sensitive column in a later UNION branch does not leak", "SELECT 'x' AS k UNION SELECT password_hash FROM users");
  await check("5.08 output column named like a sensitive column is redacted even for literals", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 'k' AS api_key" });
    redactedOk(p);
  });
  await check("5.09 filtering on a sensitive column is allowed when deny_sensitive_column_access=false", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT id FROM users WHERE password_hash = 'hash_alice_secret'" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[1]]);
  });
  await check("5.10 deny_sensitive_column_access=true denies direct/alias/expr/subquery/predicate/SELECT * references", async () => {
    for (const sql of [
      "SELECT password_hash FROM users",
      "SELECT password_hash AS ph FROM users",
      "SELECT upper(password_hash) AS u FROM users",
      "SELECT ph FROM (SELECT password_hash AS ph FROM users)",
      "SELECT id FROM users WHERE password_hash = 'x'",
      "SELECT * FROM users",
    ]) {
      const { payload: p } = await eq(c, { connection: "deny-sqlite", sql });
      denied(p, "SENSITIVE_COLUMN_FORBIDDEN", sql);
      assert.equal(p.next_action, "run_named_tool");
    }
  });
  await check("5.11 deny_sensitive_column_access=true still allows non-sensitive columns", async () => {
    const { payload: p } = await eq(c, { connection: "deny-sqlite", sql: "SELECT id, email FROM users ORDER BY id" });
    okEnvelope(p);
    assert.equal(p.returned_rows, 2);
  });
  await check("5.12 unverified change_id does not bypass deny_sensitive_column_access", async () => {
    const { payload: p } = await eq(c, { connection: "deny-sqlite", sql: "SELECT password_hash AS ph FROM users", change_id: "bogus-change" });
    denied(p, ["SENSITIVE_COLUMN_FORBIDDEN", "APPROVAL_HASH_MISMATCH", "INVALID_ARGUMENT", "APPROVAL_REQUIRED", "USE_APPLY_CHANGE"]);
  });
  await check("5.13 sensitive_tables without provenance enforcement (prod-postgres users): SELECT * allowed with redaction", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT * FROM users ORDER BY id" });
    redactedOk(p, 3);
  });
  await check("5.14 unrestricted_sql_provenance=true: SELECT * / expressions on a sensitive table are denied, explicit columns allowed", async () => {
    let r = await eq(c, { connection: "prov-sqlite", sql: "SELECT * FROM users" });
    denied(r.payload, "UNPROVENANCED_SENSITIVE_QUERY");
    r = await eq(c, { connection: "prov-sqlite", sql: "SELECT upper(email) FROM users" });
    denied(r.payload, "UNPROVENANCED_SENSITIVE_QUERY");
    r = await eq(c, { connection: "prov-sqlite", sql: "SELECT id, email FROM users ORDER BY id" });
    okEnvelope(r.payload);
    assert.equal(r.payload.returned_rows, 2);
    r = await eq(c, { connection: "prov-sqlite", sql: "SELECT * FROM orders" });
    okEnvelope(r.payload, "non-sensitive table SELECT *");
  });
  await check("5.15 restricted table denied for SELECT/JOIN/schema-qualified/subselect/CASE/quoted/CTE/scalar/EXISTS/INSERT", async () => {
    for (const sql of [
      "SELECT * FROM internal_secrets",
      "SELECT u.id FROM users u JOIN internal_secrets s ON s.id = u.id",
      "SELECT * FROM main.internal_secrets",
      "SELECT id FROM users WHERE id IN (SELECT id FROM internal_secrets)",
      "SELECT * FROM INTERNAL_SECRETS",
      'SELECT * FROM "internal_secrets"',
      "WITH s AS (SELECT * FROM internal_secrets) SELECT * FROM s",
      "SELECT (SELECT secret_value FROM internal_secrets LIMIT 1) AS v",
      "SELECT 1 WHERE EXISTS (SELECT 1 FROM internal_secrets)",
      "INSERT INTO internal_secrets (id, secret_key, secret_value) VALUES (9,'k','v')",
    ]) {
      const { payload: p } = await eq(c, { connection: L, sql });
      denied(p, "RESTRICTED_TABLE_FORBIDDEN", sql);
      assert.equal(typeof p.next_action, "string");
    }
  });
  await check("5.16 restricted table also denied on prod-postgres", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT * FROM internal_secrets" });
    denied(p, "RESTRICTED_TABLE_FORBIDDEN");
  });
}

async function sectionModes(c) {
  // --- Development -------------------------------------------------------------------------
  await check("6.01 Development: INSERT executes and persists", async () => {
    const ins = await eq(c, { connection: L, sql: "INSERT INTO users (id, email, role, password_hash, created_at) VALUES (?1, ?2, 'customer', 'h', '2025-01-01')", params: [3, "carol@example.com"] });
    okEnvelope(ins.payload);
    const sel = await eq(c, { connection: L, sql: "SELECT email FROM users WHERE id = 3" });
    assert.deepEqual(sel.payload.rows, [["carol@example.com"]]);
  });
  // KNOWN-BUG: F05-B5 - QueryResult.rows_affected is dropped by McpSuccessResponse::from_query_result.
  await check("6.02 Development: UPDATE reports the number of affected rows in the envelope", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "UPDATE users SET role = 'customer' WHERE id IN (2, 3)" });
    okEnvelope(p);
    const affected = p.rows_affected ?? p.affected_rows ?? (p.data && (p.data.rows_affected ?? p.data.affected_rows));
    assert.equal(affected, 2, `no affected-row count in envelope keys [${Object.keys(p)}]`);
  }, "F05-B5");
  await check("6.03 Development: DELETE executes and persists", async () => {
    okEnvelope((await eq(c, { connection: L, sql: "DELETE FROM users WHERE id = 3" })).payload);
    const sel = await eq(c, { connection: L, sql: "SELECT count(*) AS n FROM users WHERE id = 3" });
    assert.equal(sel.payload.rows[0][0], 0);
  });
  await check("6.04 Development: DDL (CREATE/INSERT/SELECT/DROP) works and schema_version changes", async () => {
    const before = (await eq(c, { connection: L, sql: "SELECT 1" })).payload.schema_version;
    okEnvelope((await eq(c, { connection: L, sql: "CREATE TABLE t_f05 (id INTEGER PRIMARY KEY, v TEXT)" })).payload);
    okEnvelope((await eq(c, { connection: L, sql: "INSERT INTO t_f05 (v) VALUES ('a'), ('b')" })).payload);
    const sel = await eq(c, { connection: L, sql: "SELECT * FROM t_f05 ORDER BY id" });
    okEnvelope(sel.payload);
    assert.deepEqual(sel.payload.rows, [[1, "a"], [2, "b"]]);
    assert.notEqual(sel.payload.schema_version, before, "schema_version should change after DDL");
    okEnvelope((await eq(c, { connection: L, sql: "DROP TABLE t_f05" })).payload);
    denied((await eq(c, { connection: L, sql: "SELECT * FROM t_f05" })).payload, "ADAPTER_ERROR");
  });
  await check("6.05 Development: INSERT ... RETURNING yields rows", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "INSERT INTO orders (id, user_id, status, total_cents, created_at) VALUES (103, 1, 'pending', 1, 'x') RETURNING id, status" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[103, "pending"]]);
    okEnvelope((await eq(c, { connection: L, sql: "DELETE FROM orders WHERE id = 103" })).payload);
  });
  await check("6.06 Development: ATTACH / VACUUM / load_extension are denied for a non-admin", async () => {
    for (const sql of ["ATTACH DATABASE ':memory:' AS mem", "VACUUM", "SELECT load_extension('x')"]) {
      denied((await eq(c, { connection: L, sql })).payload, "PRIVILEGED_FUNCTION_FORBIDDEN", sql);
    }
  });
  await check("6.07 Development: literal-valued PRAGMA writes are denied for a non-admin", async () => {
    for (const sql of ["PRAGMA journal_mode = 'delete'", "PRAGMA foreign_keys = 0"]) {
      denied((await eq(c, { connection: L, sql })).payload, "PRIVILEGED_FUNCTION_FORBIDDEN", sql);
    }
  });
  await check("6.08 Development: bareword PRAGMA write (journal_mode = WAL) is denied for a non-admin", async () => {
    for (const sql of ["PRAGMA journal_mode = WAL", "/* c */ PRAGMA journal_mode = WAL", "PRAGMA journal_mode(WAL)"]) {
      const { payload: p } = await eq(c, { connection: L, sql });
      denied(p, ["PRIVILEGED_FUNCTION_FORBIDDEN", "UNKNOWN_SQL_IN_GOVERNED_MODE"], sql);
    }
  });
  await check("6.09 Development: read-only PRAGMA is allowed", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "PRAGMA table_info(users)" });
    okEnvelope(p);
    assert.ok(colNames(p).includes("name"));
  });
  await check("6.10 multi-statement batch denied (MULTI_STATEMENT_FORBIDDEN)", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT 1; SELECT 2" });
    denied(p, "MULTI_STATEMENT_FORBIDDEN");
    assert.equal(p.next_action, "split_statements");
  });
  // --- ReadOnly ----------------------------------------------------------------------------
  await check("6.11 ReadOnly: INSERT/UPDATE/DELETE/CREATE/DROP/BEGIN/CTE-write -> MUTATION_NOT_ALLOWED_IN_READ_ONLY", async () => {
    for (const sql of [
      "INSERT INTO users (id, email, role, password_hash, created_at) VALUES (9,'x','y','z','w')",
      "UPDATE users SET role='x' WHERE id=1",
      "DELETE FROM users WHERE id=1",
      "CREATE TABLE zz (id INT)",
      "DROP TABLE users",
      "BEGIN",
      "WITH d AS (DELETE FROM orders RETURNING id) SELECT * FROM d",
    ]) {
      const { payload: p } = await eq(c, { connection: M, sql });
      denied(p, "MUTATION_NOT_ALLOWED_IN_READ_ONLY", sql);
      assert.equal(p.next_action, "propose_change", sql);
    }
  });
  await check("6.12 ReadOnly: VACUUM -> MUTATION_NOT_ALLOWED_IN_READ_ONLY; ATTACH and PRAGMA denied", async () => {
    denied((await eq(c, { connection: M, sql: "VACUUM" })).payload, "MUTATION_NOT_ALLOWED_IN_READ_ONLY");
    denied((await eq(c, { connection: M, sql: "ATTACH DATABASE ':memory:' AS mem" })).payload, ["PRIVILEGED_FUNCTION_FORBIDDEN", "MUTATION_NOT_ALLOWED_IN_READ_ONLY"]);
    denied((await eq(c, { connection: M, sql: "PRAGMA journal_mode = WAL" })).payload, ["UNKNOWN_SQL_IN_GOVERNED_MODE", "MUTATION_NOT_ALLOWED_IN_READ_ONLY", "PRIVILEGED_FUNCTION_FORBIDDEN"]);
  });
  await check("6.13 ReadOnly: reads work and state is untouched after the denied writes", async () => {
    const { payload: p } = await eq(c, { connection: M, sql: "SELECT id, role FROM users ORDER BY id" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [[1, "admin"], [2, "customer"]]);
  });
  await check("6.14 ReadOnly: change_id does not unlock writes (execute_query rejects change_id)", async () => {
    const { payload: p } = await eq(c, { connection: M, sql: "INSERT INTO users (id, email, role, password_hash, created_at) VALUES (9,'x','y','z','w')", change_id: "bogus-change" });
    denied(p, ["MUTATION_NOT_ALLOWED_IN_READ_ONLY", "USE_APPLY_CHANGE"]);
  });
  await check("6.15 ReadOnly/Governed: unparseable SQL fails closed (UNKNOWN_SQL_IN_GOVERNED_MODE)", async () => {
    denied((await eq(c, { connection: M, sql: "SELEC 1" })).payload, "UNKNOWN_SQL_IN_GOVERNED_MODE");
    denied((await eq(c, { connection: P, sql: "SELEC 1" })).payload, "UNKNOWN_SQL_IN_GOVERNED_MODE");
  });
  // --- GovernedProduction ------------------------------------------------------------------
  await check("6.16 Governed: direct UPDATE/DELETE/DDL/CTE-write -> APPROVAL_REQUIRED with next_action propose_change", async () => {
    for (const sql of [
      "UPDATE orders SET status = 'completed' WHERE id = 102",
      "DELETE FROM orders WHERE id = 999",
      "CREATE TABLE pwned (id INT)",
      "WITH d AS (DELETE FROM orders WHERE id = 999 RETURNING id) SELECT * FROM d",
    ]) {
      const { payload: p } = await eq(c, { connection: P, sql });
      denied(p, "APPROVAL_REQUIRED", sql);
      assert.equal(p.next_action, "propose_change", sql);
    }
  });
  await check("6.17 Governed: change_id on execute_query is refused with next_action apply_change", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT 1 AS x", change_id: "bogus-change" });
    denied(p, "USE_APPLY_CHANGE");
    assert.equal(p.next_action, "apply_change");
  });
  await check("6.18 Governed: UPDATE with an unverified change_id is denied", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "UPDATE orders SET status = 'hacked' WHERE id = 102", change_id: "bogus-change" });
    denied(p, ["APPROVAL_REQUIRED", "APPROVAL_HASH_MISMATCH", "INVALID_ARGUMENT", "APPROVAL_EXPIRED", "APPROVAL_ALREADY_CONSUMED", "USE_APPLY_CHANGE"]);
  });
  await check("6.19 Governed: production row unchanged after the bogus change_id attempt", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT status FROM orders WHERE id = 102" });
    okEnvelope(p);
    assert.deepEqual(p.rows, [["pending"]], "row was mutated through execute_query without an approved change");
  });
  await check("6.20 Governed: DDL with an unverified change_id is denied", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "CREATE TABLE pwned (id INT)", change_id: "bogus-change" });
    denied(p, ["APPROVAL_REQUIRED", "APPROVAL_HASH_MISMATCH", "INVALID_ARGUMENT", "USE_APPLY_CHANGE"]);
  });
}

async function sectionRoles(config, c) {
  const intern = await openClient(config, "alice", "intern");
  const admin = await openClient(config, "root", "admin");
  const dba = await openClient(config, "p1", "dba");
  await check("7.01 prod-postgres allowed_roles: role intern denied (UNAUTHORIZED_ROLE), agent allowed", async () => {
    const { payload: p } = await eq(intern, { connection: P, sql: "SELECT 1 AS ok" });
    denied(p, "UNAUTHORIZED_ROLE");
    assert.equal(p.next_action, "list_connections");
    okEnvelope((await eq(c, { connection: P, sql: "SELECT 1 AS ok" })).payload);
  });
  await check("7.02 wildcard allowed_roles: intern allowed on local-sqlite", async () => {
    okEnvelope((await eq(intern, { connection: L, sql: "SELECT 1 AS ok" })).payload);
  });
  await check("7.03 allowed_principals enforced: p1 denied, alice allowed", async () => {
    denied((await eq(c, { connection: "principal-sqlite", sql: "SELECT 1" })).payload, ["UNAUTHORIZED_ROLE", "UNAUTHORIZED_CONNECTION", "UNAUTHORIZED"]);
    okEnvelope((await eq(intern, { connection: "principal-sqlite", sql: "SELECT 1 AS ok" })).payload);
  });
  // allowed_roles is authoritative (F13-B11): a self-asserted admin role is not implicitly allowed.
  await check("7.04 allowed_roles=[dba]: agent and unlisted admin denied, dba allowed", async () => {
    denied((await eq(c, { connection: "role-sqlite", sql: "SELECT 1" })).payload, "UNAUTHORIZED_ROLE");
    okEnvelope((await eq(dba, { connection: "role-sqlite", sql: "SELECT 1 AS ok" })).payload);
    denied((await eq(admin, { connection: "role-sqlite", sql: "SELECT 1" })).payload, "UNAUTHORIZED_ROLE");
  });
  await check("7.05 admin may run literal PRAGMA writes in Development, non-admin may not", async () => {
    okEnvelope((await eq(admin, { connection: L, sql: "PRAGMA journal_mode = 'delete'" })).payload);
    denied((await eq(c, { connection: L, sql: "PRAGMA journal_mode = 'delete'" })).payload, "PRIVILEGED_FUNCTION_FORBIDDEN");
  });
}

async function sectionSimulated(c) {
  await check("8.01 prod-postgres: now()/version()/ILIKE/interval fail cleanly (ADAPTER_ERROR, no panic)", async () => {
    for (const sql of ["SELECT now() AS t", "SELECT version() AS v", "SELECT email FROM users WHERE email ILIKE 'ALICE%'", "SELECT now() - interval '1 day' AS d"]) {
      const { payload: p } = await eq(c, { connection: P, sql });
      denied(p, "ADAPTER_ERROR", sql);
      assert.ok(!/panic|unwrap|RUST_BACKTRACE/i.test(p.message), p.message);
    }
    okEnvelope((await eq(c, { connection: P, sql: "SELECT 1 AS alive" })).payload);
  });
  await check("8.02 prod-postgres: ::casts, LIMIT/OFFSET, public. prefix, string_agg run", async () => {
    let p = (await eq(c, { connection: P, sql: "SELECT '42'::int AS v, 1::text AS s" })).payload;
    okEnvelope(p);
    assert.equal(String(p.rows[0][0]), "42");
    p = (await eq(c, { connection: P, sql: "SELECT id FROM public.users ORDER BY id LIMIT 1 OFFSET 1" })).payload;
    okEnvelope(p);
    assert.deepEqual(p.rows, [[2]]);
    p = (await eq(c, { connection: P, sql: "SELECT string_agg(email, ',') AS e FROM users" })).payload;
    okEnvelope(p);
  });
  await check("8.03 prod-postgres: pg_sleep blocked as privileged function", async () => {
    denied((await eq(c, { connection: P, sql: "SELECT pg_sleep(1)" })).payload, "PRIVILEGED_FUNCTION_FORBIDDEN");
  });
  await check("8.04 analytics-mysql: LIMIT a,b / schema prefix / CONCAT / double-quoted string run; NOW() fails cleanly", async () => {
    let p = (await eq(c, { connection: M, sql: "SELECT id FROM analytics.users ORDER BY id LIMIT 1, 1" })).payload;
    okEnvelope(p);
    assert.deepEqual(p.rows, [[2]]);
    p = (await eq(c, { connection: M, sql: 'SELECT CONCAT(email, "!") AS e FROM users WHERE email = "alice@example.com"' })).payload;
    okEnvelope(p);
    assert.deepEqual(p.rows, [["alice@example.com!"]]);
    denied((await eq(c, { connection: M, sql: "SELECT NOW() AS t" })).payload, "ADAPTER_ERROR");
  });
  await check("8.05 simulated engines: max_rows and timeout enforced too", async () => {
    let p = (await eq(c, { connection: M, sql: "SELECT id FROM users", max_rows: 1 })).payload;
    okEnvelope(p);
    assert.equal(p.truncated, true);
    p = (await eq(c, { connection: P, sql: SLOW_1S, timeout_ms: 1 })).payload;
    denied(p, "EXECUTION_TIMEOUT");
    okEnvelope((await eq(c, { connection: P, sql: "SELECT 1 AS alive" })).payload);
  });
  await check("8.06 unreachable DSN: first and subsequent calls still answer promptly (probe cost recorded)", async () => {
    const cfg = buildUnreachableDsnConfig();
    const t0 = Date.now();
    const u = await openClient(cfg, "p1", "agent");
    const initMs = Date.now() - t0;
    const times = [];
    for (let i = 0; i < 3; i++) {
      const t1 = Date.now();
      const { payload: p } = await eq(u, { connection: P, sql: "SELECT 1 AS x" });
      okEnvelope(p);
      times.push(Date.now() - t1);
    }
    assert.ok(Math.max(...times) < 3000, `calls took ${times}ms`);
    const t2 = Date.now();
    okEnvelope((await eq(u, { connection: M, sql: "SELECT 1 AS x" })).payload);
    const mysqlMs = Date.now() - t2;
    u.close();
    return `init ${initMs}ms, pg calls ${times.join("/")}ms, mysql ${mysqlMs}ms`;
  });
  await check("8.07 observation: simulated-engine results carry no 'simulated' marker (documented, not asserted)", async () => {
    const { payload: p } = await eq(c, { connection: P, sql: "SELECT 1 AS x" });
    okEnvelope(p);
    const flagged = p.warnings.some((w) => /simulat|embedded|offline/i.test(w)) || JSON.stringify(p._meta).match(/simulat/i);
    return flagged ? "flagged" : "NOT flagged";
  });
}

async function sectionHygiene(c) {
  await check("9.01 SQL syntax error in Development -> structured ADAPTER_ERROR, server alive", async () => {
    const { payload: p, raw } = await eq(c, { connection: L, sql: "SELEC * FORM users" });
    denied(p, "ADAPTER_ERROR");
    assert.equal(raw.isError, true);
    assert.match(p.message, /syntax/i);
    okEnvelope((await eq(c, { connection: L, sql: "SELECT 1 AS alive" })).payload);
  });
  await check("9.02 unknown table -> ADAPTER_ERROR naming the table", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "SELECT * FROM nope_table" });
    denied(p, "ADAPTER_ERROR");
    assert.match(p.message, /nope_table/);
  });
  await check("9.03 missing sql / missing connection -> INVALID_ARGUMENT; unknown connection -> CONNECTION_NOT_FOUND", async () => {
    denied((await eq(c, { connection: L })).payload, "INVALID_ARGUMENT");
    denied((await eq(c, { connection: L, sql: "" })).payload, "INVALID_ARGUMENT");
    denied((await eq(c, { sql: "SELECT 1" })).payload, "INVALID_ARGUMENT");
    const { payload: p } = await eq(c, { connection: "nope", sql: "SELECT 1" });
    denied(p, "CONNECTION_NOT_FOUND");
    assert.equal(p.next_action, "list_connections");
  });
  await check("9.04 incomplete SQL / empty-table DDL error paths never panic", async () => {
    denied((await eq(c, { connection: L, sql: "SELECT * FROM users WHERE" })).payload, "ADAPTER_ERROR");
    denied((await eq(c, { connection: L, sql: "CREATE TABLE" })).payload, ["ADAPTER_ERROR", "SQL_PARSE_ERROR", "UNKNOWN_SQL_IN_GOVERNED_MODE"]);
    okEnvelope((await eq(c, { connection: L, sql: "SELECT 1 AS alive" })).payload);
  });
  await check("9.05 no DSN, credential or filesystem path leaks in any message or warning seen during the run", async () => {
    const dir = isoDir ? isoDir.replace(/\\/g, "/").toLowerCase() : null;
    const bad = allMessages.filter((m) => {
      const s = String(m).toLowerCase();
      return s.includes("sqlite://") || s.includes("postgres://") || s.includes("mysql://") || /password\s*=/.test(s) ||
        (dir && (s.includes(dir) || s.includes(dir.replace(/\//g, "\\")))) || s.includes("db-mcp-iso-") || /[a-z]:\\users\\/.test(s);
    });
    assert.deepEqual(bad, [], `leaking messages: ${JSON.stringify(bad).slice(0, 400)}`);
    return `${allMessages.length} messages scanned`;
  });
}

async function sectionEnvelope(c) {
  await check("10.01 ok envelope: full key set, provenance untrusted_content=true, schema_version, execution_time_ms, isError=false", async () => {
    const { payload: p, raw } = await eq(c, { connection: L, sql: "SELECT id FROM users ORDER BY id" });
    okEnvelope(p);
    assert.equal(raw.isError, false);
    assert.match(p.request_id, /^req_[0-9a-f]+$/);
    assert.match(p.schema_version, /^snapshot_/);
    assert.equal(typeof p.execution_time_ms, "number");
    assert.equal(p.connection, L);
    assert.equal(p._meta.provenance.source_connection, L);
    assert.equal(p._meta.provenance.source_kind, "query_rows");
  });
  await check("10.02 denied envelope: isError=true, status/code/message/retryable/request_id/connection", async () => {
    const { payload: p, raw } = await eq(c, { connection: L, sql: "SELECT * FROM internal_secrets" });
    denied(p, "RESTRICTED_TABLE_FORBIDDEN");
    assert.equal(raw.isError, true);
    assert.equal(p.connection, L);
    assert.match(p.request_id, /^req_/);
  });
  await check("10.03 content[0].text is the JSON serialisation of structuredContent", async () => {
    const { payload: p, raw } = await eq(c, { connection: L, sql: "SELECT 1 AS one" });
    assert.equal(raw.content[0].type, "text");
    assert.deepEqual(JSON.parse(raw.content[0].text), p);
  });
  await check("10.04 every ok envelope has schema_version on write statements too", async () => {
    const { payload: p } = await eq(c, { connection: L, sql: "UPDATE users SET role = role WHERE id = 1" });
    okEnvelope(p);
    assert.match(p.schema_version, /^snapshot_/);
    assert.deepEqual(p.columns, []);
    assert.deepEqual(p.rows, []);
  });
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------
async function main() {
  const config = buildMainConfig();
  console.log(`# F05 execute_query - isolated config: ${config}`);
  const c = await openClient(config, "p1", "agent");

  await sectionParams(c);
  await sectionEncoding(c);
  await sectionLimits(c);
  await sectionCancellation(config);
  await sectionRedaction(c);
  await sectionModes(c);
  await sectionRoles(config, c);
  await sectionSimulated(c);
  await sectionHygiene(c);
  await sectionEnvelope(c);
}

function shutdown() {
  for (const cl of clients) { try { cl.close(); } catch { /* ignore */ } }
  setTimeout(() => { for (const cl of clients) { try { cl.child.kill(); } catch { /* ignore */ } } }, 300);
}

main()
  .catch((err) => {
    console.error("FATAL:", err && err.stack ? err.stack : err);
    results.push({ name: "harness", ok: false, err });
  })
  .finally(() => {
    shutdown();
    const passed = results.filter((r) => r.ok).length;
    const failed = results.filter((r) => !r.ok);
    const known = failed.filter((r) => r.knownBug);
    const unexpected = failed.filter((r) => !r.knownBug);
    console.log(`\n# F05 summary: ${passed} passed, ${failed.length} failed (${known.length} tagged KNOWN-BUG, ${unexpected.length} unexpected) of ${results.length} checks`);
    if (known.length) console.log(`# known-bug ids: ${[...new Set(known.map((r) => r.knownBug))].join(", ")}`);
    setTimeout(() => process.exit(failed.length ? 1 : 0), 400);
  });
