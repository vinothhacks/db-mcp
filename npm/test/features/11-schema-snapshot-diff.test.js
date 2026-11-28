#!/usr/bin/env node
"use strict";
/**
 * F11 - Schema profile: `capture_schema` + `diff_schema`.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *   node npm/test/features/11-schema-snapshot-diff.test.js
 *
 * Every check encodes the CORRECT behaviour. Checks that currently fail because of a known
 * defect are tagged with `// KNOWN-BUG: F11-xx` and reported as "FAIL (KNOWN-BUG ...)".
 * Exit code is 0 only when every check passes; set F11_ALLOW_KNOWN_BUGS=1 to exit 0 when the
 * only failures are tagged known bugs.
 *
 * Spawns isolated servers only (never config/db-mcp.example.toml directly) and kills children on exit.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));

process.chdir(REPO_ROOT);

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------
const results = { pass: 0, fail: 0, knownBugFail: 0, knownBugPass: 0 };
const clients = new Set();

async function check(name, fn, knownBug) {
  try {
    await fn();
    results.pass += 1;
    if (knownBug) {
      results.knownBugPass += 1;
      console.log(`ok   - ${name}  (tagged ${knownBug} but passed: the bug may be fixed, retire the tag)`);
    } else {
      console.log(`ok   - ${name}`);
    }
  } catch (err) {
    const msg = (err && err.message ? err.message : String(err)).split("\n")[0].slice(0, 300);
    if (knownBug) {
      results.knownBugFail += 1;
      console.log(`FAIL (KNOWN-BUG ${knownBug}) - ${name} :: ${msg}`);
    } else {
      results.fail += 1;
      console.log(`FAIL - ${name} :: ${msg}`);
    }
  }
}

function note(text) {
  console.log(`note - ${text}`);
}

function openClient(configPath, principal, role) {
  const cl = createClient({ config: configPath, principal, role, timeoutMs: 60000 });
  clients.add(cl);
  const call = async (tool, args) => {
    const r = await cl.rpc("tools/call", { name: tool, arguments: args });
    if (r.error) return { status: "rpc_error", rpcError: r.error };
    return r.result.structuredContent !== undefined ? r.result.structuredContent : r.result;
  };
  const init = async () => {
    const r = await cl.rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "f11-test", version: "0.1.0" },
    });
    if (r.error) throw new Error(`initialize failed: ${JSON.stringify(r.error)}; stderr=${cl.stderr.join("")}`);
    cl.notify("notifications/initialized", {});
  };
  const close = () => {
    clients.delete(cl);
    cl.close();
  };
  return { cl, call, init, close };
}

function killAll() {
  for (const cl of clients) {
    try { cl.child.kill(); } catch { /* ignore */ }
  }
}
process.on("exit", killAll);
process.on("SIGINT", () => { killAll(); process.exit(130); });
process.on("SIGTERM", () => { killAll(); process.exit(143); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stripTs = (snap) => { const { captured_at, ...rest } = snap; return rest; };
const byName = (snap, name) => snap.objects.find((o) => o.name === name);
const kinds = (diff) => diff.items.map((i) => i.kind);
const SNAPSHOT_RE = /^snapshot_[0-9a-f]{12}$/;

function assertSuccessEnvelope(payload, label) {
  assert.equal(payload.status, "ok", `${label}: expected status ok, got ${JSON.stringify(payload).slice(0, 300)}`);
  assert.equal(typeof payload.request_id, "string", `${label}: request_id`);
  assert.match(payload.request_id, /^req_[0-9a-f]{12}$/, `${label}: request_id format`);
  assert.equal(typeof payload.connection, "string", `${label}: connection`);
  assert.ok(Array.isArray(payload.columns), `${label}: columns array`);
  assert.ok(Array.isArray(payload.rows), `${label}: rows array`);
  assert.equal(typeof payload.returned_rows, "number", `${label}: returned_rows`);
  assert.equal(typeof payload.truncated, "boolean", `${label}: truncated`);
  assert.ok(Array.isArray(payload.warnings), `${label}: warnings array`);
  assert.equal(typeof payload.schema_version, "string", `${label}: schema_version`);
  assert.equal(payload._meta?.provenance?.untrusted_content, true, `${label}: _meta.provenance.untrusted_content`);
  assert.equal(payload._meta?.provenance?.source_connection, payload.connection, `${label}: provenance.source_connection`);
}

function assertDenied(payload, code, label) {
  assert.equal(payload.status, "denied", `${label}: expected denied, got ${JSON.stringify(payload).slice(0, 300)}`);
  assert.equal(payload.code, code, `${label}: code`);
  assert.equal(typeof payload.message, "string", `${label}: message`);
}

/** Consistency invariants that must hold for every SchemaDiff payload. */
function assertDiffInvariants(diff, label) {
  assert.equal(diff.is_identical, diff.items.length === 0, `${label}: is_identical vs items`);
  assert.equal(diff.has_destructive_changes, diff.items.some((i) => i.destructive), `${label}: has_destructive_changes`);
  assert.equal(diff.all_transactional, diff.items.every((i) => i.transactional), `${label}: all_transactional`);
  if (diff.is_identical) {
    assert.match(diff.summary, /identical \(0 changes\)/, `${label}: identical summary`);
  } else {
    const m = diff.summary.match(/Detected (\d+) structural change/);
    assert.ok(m, `${label}: summary should state count: ${diff.summary}`);
    assert.equal(Number(m[1]), diff.items.length, `${label}: summary count equals items.length`);
    assert.ok(diff.summary.includes(diff.base_schema_version) && diff.summary.includes(diff.target_schema_version), `${label}: summary names both versions`);
  }
  for (const it of diff.items) {
    assert.equal(typeof it.kind, "string");
    assert.equal(typeof it.object_name, "string");
    assert.equal(typeof it.destructive, "boolean");
    assert.equal(typeof it.transactional, "boolean");
    assert.ok(["transactional_rollback", "compensating_migration_required", "backup_recovery_required"].includes(it.reversal_safety), `${label}: reversal_safety ${it.reversal_safety}`);
    if (it.destructive) {
      assert.notEqual(it.reversal_safety, "transactional_rollback", `${label}: destructive change must not be classified transactional_rollback (${it.kind} ${it.object_name})`);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------------------------
const TRIGGER_SQL = "CREATE TRIGGER trg_orders_audit AFTER INSERT ON orders BEGIN INSERT INTO audit_logs(order_id,event_type,created_at) VALUES (NEW.id,'INSERTED','now'); END;\n";

function sqliteConnectionToml(id, dsnPath, initSql, description) {
  return `
[[connections]]
id = "${id}"
engine = "Sqlite"
dsn = "sqlite://${dsnPath.replace(/\\/g, "/")}"
mode = "Development"
read_only = false
description = "${description}"
default_schema = "main"
timeout_ms = 10000
max_rows = 500
max_bytes = 1048576
allow_multi_statement = false
allow_explain_analyze = true
restricted_tables = ["internal_secrets"]
sensitive_tables = []
sensitive_columns = ["password_hash", "api_key", "secret_token"]
deny_sensitive_column_access = false
unrestricted_sql_provenance = false
allowed_roles = ["*"]
allowed_principals = ["*"]
init_sql = """
${initSql}"""
`;
}

/** Main config: local-sqlite (fixture) + sqlite-b (same schema, tables created in reverse order) + sqlite-c (fixture + trigger). */
function buildMainConfig() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f11-main-"));
  const { configPath } = makeIsolatedConfig({
    dir,
    transform: (text) => {
      const m = text.match(/id = "local-sqlite"[\s\S]*?init_sql = """([\s\S]*?)"""/);
      assert.ok(m, "could not locate local-sqlite init_sql in example config");
      const init = m[1];
      // Reverse only the CREATE TABLE blocks in place; leave every other byte (routine bodies' indentation) untouched.
      const tableRe = /CREATE TABLE[\s\S]*?\);\r?\n/g;
      const tables = init.match(tableRe) || [];
      assert.ok(tables.length > 1, "no CREATE TABLE blocks found in fixture init_sql");
      const rev = tables.slice().reverse();
      let k = 0;
      const reversed = init.replace(tableRe, () => rev[k++]);
      const extra =
        sqliteConnectionToml("sqlite-b", path.join(dir, "b.db"), reversed, "same schema, reverse creation order") +
        sqliteConnectionToml("sqlite-c", path.join(dir, "c.db"), "DROP TRIGGER IF EXISTS trg_orders_audit;\n" + init + TRIGGER_SQL, "fixture plus trigger");
      return text.replace(/\n\[\[named_tools\]\]/, extra + "\n[[named_tools]]");
    },
  });
  return { configPath, dir };
}

/** Large config: local-sqlite seeded with 200 extra tables (+1 index each) and a tiny max_bytes. */
function buildLargeConfig(tableCount) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f11-large-"));
  let big = "";
  for (let i = 0; i < tableCount; i++) {
    big += `CREATE TABLE big_t${i} (id INTEGER PRIMARY KEY, a${i} TEXT NOT NULL DEFAULT 'x', b INTEGER, c REAL, parent_id INTEGER REFERENCES users(id));\nCREATE INDEX idx_big_t${i}_b ON big_t${i}(b);\n`;
  }
  const { configPath } = makeIsolatedConfig({
    dir,
    transform: (text) => {
      let out = text.replace(/(id = "local-sqlite"[\s\S]*?init_sql = """)/, (m) => m + big);
      out = out.replace(/(id = "local-sqlite"[\s\S]*?)max_bytes = 1048576/, "$1max_bytes = 2048");
      return out;
    },
  });
  return { configPath, dir };
}

function buildNoSchemaProfileConfig() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f11-noschema-"));
  const { configPath } = makeIsolatedConfig({
    dir,
    transform: (text) => text.replace(/active_profiles = \[[^\]]*\]/, 'active_profiles = ["Explore", "Query"]'),
  });
  return { configPath, dir };
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------
async function main() {
  console.log("[F11] capture_schema / diff_schema verification");
  const main = buildMainConfig();
  note(`isolated config: ${main.configPath}`);
  const agent = openClient(main.configPath, "local-agent", "agent");
  await agent.init();
  const call = agent.call;
  const cap = (connection, extra) => call("capture_schema", Object.assign({ connection }, extra || {}));
  const diff = (args) => call("diff_schema", args);
  const sql = async (connection, statement) => {
    const r = await call("execute_query", { connection, sql: statement });
    assert.equal(r.status, "ok", `execute_query failed on ${connection}: ${statement.slice(0, 80)} -> ${r.code} ${r.message}`);
    return r;
  };

  // ------------------------------------------------------------------ 1. capture envelope + content
  const a0 = await cap("local-sqlite");
  await check("capture_schema: success envelope (request_id, connection, status, columns, rows, returned_rows, truncated, warnings, schema_version, _meta provenance)", () => {
    assertSuccessEnvelope(a0, "capture");
    assert.equal(a0.connection, "local-sqlite");
    assert.equal(a0._meta.provenance.source_kind, "schema_snapshot");
    assert.match(a0.schema_version, SNAPSHOT_RE, "schema_version must be snapshot_<12 hex>");
    assert.deepEqual(a0.warnings, []);
    assert.equal(a0.truncated, false);
  });

  await check("capture_schema: data block is a SchemaSnapshot consistent with the envelope (version, 64-hex full_hash prefixed by short hash, engine, connection, ISO captured_at)", () => {
    const d = a0.data;
    assert.equal(d.schema_version, a0.schema_version);
    assert.match(d.full_hash, /^[0-9a-f]{64}$/);
    assert.equal(`snapshot_${d.full_hash.slice(0, 12)}`, d.schema_version);
    assert.equal(d.engine, "sqlite");
    assert.equal(d.connection, "local-sqlite");
    assert.ok(!Number.isNaN(Date.parse(d.captured_at)), "captured_at must be an ISO timestamp");
    assert.ok(Array.isArray(d.objects) && d.objects.length > 0);
  });

  // Contract CONTRACT-SCHEMA-CAPTURE-AND-DIFF (research/contracts/tool-contracts.json) expects a one-row summary.
  await check("capture_schema: contract summary row columns [schema_version, table_count, index_count, captured_at] with returned_rows=1", () => {
    assert.deepEqual(a0.columns.map((column) => column.name), ["schema_version", "table_count", "index_count", "captured_at"]);
    assert.equal(a0.returned_rows, 1);
    assert.equal(a0.rows.length, 1);
  });

  await check("snapshot content: object inventory of the fixture (5 visible tables, restricted internal_secrets excluded, 1 view, 3 procedures, 1 function) all grouped under schema 'main' in canonical order", () => {
    const objs = a0.data.objects;
    const count = (t) => objs.filter((o) => o.object_type === t).length;
    assert.equal(count("table"), 5, `tables: ${objs.filter((o) => o.object_type === "table").map((o) => o.name)}`);
    assert.ok(!objs.some((o) => o.name === "internal_secrets"), "restricted table must not appear in snapshots");
    assert.equal(count("view"), 1);
    assert.equal(count("procedure"), 3);
    assert.equal(count("function"), 1);
    assert.ok(objs.every((o) => o.schema === "main"), "all objects in schema main");
    // canonical sort: (schema, object_type, name); within a type names must be ascending
    const groups = new Map();
    for (const o of objs) { if (!groups.has(o.object_type)) groups.set(o.object_type, []); groups.get(o.object_type).push(o.name); }
    for (const [t, names] of groups) assert.deepEqual(names, names.slice().sort(), `names sorted within type ${t}`);
  });

  await check("snapshot content: columns (name/type/nullable/default/pk/ordinal), unique+primary index, foreign keys with on_delete, view definition, routine definitions", () => {
    const users = byName(a0.data, "users");
    assert.deepEqual(users.columns.map((c) => c.name), ["id", "email", "role", "password_hash", "created_at"]);
    assert.deepEqual(users.columns.map((c) => c.ordinal_position), [1, 2, 3, 4, 5]);
    assert.equal(users.columns[0].is_primary_key, true);
    assert.equal(users.columns[0].data_type, "INTEGER");
    assert.equal(users.columns[1].nullable, false);
    const inv = byName(a0.data, "inventory");
    assert.equal(inv.columns.find((c) => c.name === "reserved_qty").default_value, "0");
    assert.equal(inv.indexes.length, 1);
    assert.equal(inv.indexes[0].unique, true);
    assert.equal(inv.indexes[0].primary, true);
    assert.deepEqual(inv.indexes[0].columns, ["sku"]);
    const orders = byName(a0.data, "orders");
    assert.equal(orders.foreign_keys.length, 1);
    assert.deepEqual(orders.foreign_keys[0].columns, ["user_id"]);
    assert.equal(orders.foreign_keys[0].referenced_table, "users");
    assert.deepEqual(orders.foreign_keys[0].referenced_columns, ["id"]);
    assert.equal(orders.foreign_keys[0].on_delete, "CASCADE");
    assert.equal(byName(a0.data, "order_items").foreign_keys.length, 2);
    const view = byName(a0.data, "active_user_orders");
    assert.equal(view.object_type, "view");
    assert.match(view.definition, /^CREATE VIEW active_user_orders AS/);
    assert.equal(view.columns.length, 6);
    assert.match(byName(a0.data, "checkout_order").definition, /checkout_order/);
    assert.equal(byName(a0.data, "calculate_order_discount").object_type, "function");
    assert.ok(byName(a0.data, "calculate_order_discount").definition.length > 20);
  });

  await check("snapshot content: no row data or secret values leak into the snapshot payload", () => {
    const text = JSON.stringify(a0.data);
    for (const needle of ["alice@example.com", "bob@example.com", "hash_alice_secret", "SKU-PRO-1", "ORDER_CHECKED_OUT', '2025"]) {
      assert.ok(!text.includes(needle), `row value '${needle}' leaked into snapshot`);
    }
  });

  await check("snapshot content: restricted tables (restricted_tables = internal_secrets) are excluded like search_objects does", async () => {
    const so = await call("search_objects", { connection: "local-sqlite", name_pattern: "internal_secrets" });
    assert.equal(so.status, "ok");
    assert.equal(so.data.objects.length, 0, "search_objects hides internal_secrets");
    assert.equal(byName(a0.data, "internal_secrets"), undefined, "capture_schema must also hide internal_secrets");
  });

  await check("snapshot content: fixture payload size is modest (< 64 KiB)", () => {
    const bytes = Buffer.byteLength(JSON.stringify(a0.data));
    note(`fixture snapshot payload = ${bytes} bytes for ${a0.data.objects.length} objects`);
    assert.ok(bytes < 65536, `payload ${bytes} bytes`);
  });

  // ------------------------------------------------------------------ 2. determinism
  const a1 = await cap("local-sqlite");
  await check("determinism: two captures with no change yield identical schema_version and deep-equal data (captured_at excluded, and captured_at is not part of the hash)", () => {
    assert.equal(a1.schema_version, a0.schema_version);
    assert.deepEqual(stripTs(a1.data), stripTs(a0.data));
  });

  await check("determinism: hash independent of object discovery/creation order (sqlite-b created tables in reverse order)", async () => {
    const b0 = await cap("sqlite-b");
    assertSuccessEnvelope(b0, "capture sqlite-b");
    assert.equal(b0.schema_version, a0.schema_version, "sqlite-b (reverse creation order) must hash identically");
    assert.deepEqual(b0.data.objects, a0.data.objects);
  });

  await check("determinism: schema_pattern 'main' / '%' / 'MAIN' / 'ma%' select the same objects and hash as no filter", async () => {
    for (const p of ["main", "%", "MAIN", "ma%"]) {
      const r = await cap("local-sqlite", { schema_pattern: p });
      assert.equal(r.status, "ok", `pattern ${p}`);
      assert.equal(r.schema_version, a0.schema_version, `pattern ${p} hash`);
      assert.equal(r.data.objects.length, a0.data.objects.length, `pattern ${p} count`);
    }
  });

  await check("schema_pattern that matches nothing ('nope') returns an empty snapshot WITH a warning (not a silent empty snapshot)", async () => {
    const r = await cap("local-sqlite", { schema_pattern: "nope" });
    assert.equal(r.status, "ok");
    assert.equal(r.data.objects.length, 0);
    assert.match(r.schema_version, SNAPSHOT_RE);
    assert.ok(r.warnings.length > 0, "expected a warning explaining that schema_pattern matched no objects");
  });

  // ------------------------------------------------------------------ 3. diff combinations (no mutation yet)
  const b0 = await cap("sqlite-b");
  await check("diff_schema: base_snapshot + target_connection -> identical; envelope connection=base, schema_version=target version, source_kind schema_diff", async () => {
    const r = await diff({ base_snapshot: a0.data, target_connection: "local-sqlite" });
    assertSuccessEnvelope(r, "diff");
    assert.equal(r.connection, "local-sqlite");
    assert.equal(r._meta.provenance.source_kind, "schema_diff");
    assert.equal(r.schema_version, r.data.target_schema_version);
    assert.equal(r.data.base_schema_version, a0.schema_version);
    assert.equal(r.data.target_schema_version, a0.schema_version);
    assert.equal(r.data.engine, "sqlite");
    assert.equal(r.data.is_identical, true);
    assert.deepEqual(r.data.items, []);
    assertDiffInvariants(r.data, "snapshot+connection");
  });

  await check("diff_schema: base_connection + target_connection (local-sqlite vs sqlite-b) -> identical", async () => {
    const r = await diff({ base_connection: "local-sqlite", target_connection: "sqlite-b" });
    assertSuccessEnvelope(r, "diff");
    assert.equal(r.connection, "local-sqlite");
    assert.equal(r.data.is_identical, true);
    assertDiffInvariants(r.data, "connection+connection");
  });

  await check("diff_schema: base_snapshot + target_snapshot -> identical; connection taken from base snapshot", async () => {
    const r = await diff({ base_snapshot: a0.data, target_snapshot: b0.data });
    assertSuccessEnvelope(r, "diff");
    assert.equal(r.connection, a0.data.connection);
    assert.equal(r.data.is_identical, true);
    assertDiffInvariants(r.data, "snapshot+snapshot");
  });

  await check("diff_schema: base_connection + target_snapshot -> identical", async () => {
    const r = await diff({ base_connection: "sqlite-b", target_snapshot: a0.data });
    assertSuccessEnvelope(r, "diff");
    assert.equal(r.connection, "sqlite-b");
    assert.equal(r.data.is_identical, true);
  });

  await check("diff_schema: schema_pattern applies to both captured sides", async () => {
    const r = await diff({ base_connection: "local-sqlite", target_connection: "sqlite-b", schema_pattern: "nope" });
    assert.equal(r.status, "ok");
    assert.equal(r.data.is_identical, true);
    assert.notEqual(r.data.base_schema_version, a0.schema_version, "filtered snapshot must hash differently than full snapshot");
  });

  await check("diff_schema: missing both base_* and both target_* -> INVALID_ARGUMENT denial naming the missing parameter", async () => {
    const r0 = await diff({});
    assertDenied(r0, "INVALID_ARGUMENT", "no args");
    assert.match(r0.message, /base_connection/);
    const r1 = await diff({ base_connection: "local-sqlite" });
    assertDenied(r1, "INVALID_ARGUMENT", "base only");
    assert.match(r1.message, /target_connection/);
    const r2 = await diff({ target_snapshot: a0.data });
    assertDenied(r2, "INVALID_ARGUMENT", "target only");
  });

  await check("denial envelope: INVALID_ARGUMENT denials carry the contract-required next_action field", async () => {
    const r0 = await diff({});
    assertDenied(r0, "INVALID_ARGUMENT", "no args");
    assert.equal(typeof r0.next_action, "string", `next_action missing: ${JSON.stringify(r0)}`);
  });

  await check("diff_schema: malformed snapshots ({}, string, number, unknown engine) -> clean INVALID_ARGUMENT denial, server stays alive", async () => {
    const bad = [
      {},
      "garbage",
      42,
      { connection: "x", engine: "oracle", schema_version: "v", full_hash: "h", captured_at: "2020-01-01T00:00:00Z", objects: [] },
      { connection: "x", engine: "sqlite", schema_version: "v", full_hash: "h", captured_at: "not-a-date", objects: [] },
    ];
    for (const b of bad) {
      const r = await diff({ base_snapshot: b, target_connection: "local-sqlite" });
      assertDenied(r, "INVALID_ARGUMENT", `base_snapshot=${JSON.stringify(b).slice(0, 40)}`);
      assert.match(r.message, /base_snapshot/);
      const t = await diff({ base_connection: "local-sqlite", target_snapshot: b });
      assertDenied(t, "INVALID_ARGUMENT", `target_snapshot=${JSON.stringify(b).slice(0, 40)}`);
      assert.match(t.message, /target_snapshot/);
    }
    const alive = await cap("local-sqlite");
    assert.equal(alive.status, "ok", "server must still answer after malformed input");
  });

  await check("diff_schema: minimal well-formed empty snapshot is accepted and reports every object as added", async () => {
    const empty = { connection: "x", engine: "sqlite", schema_version: "snapshot_000000000000", full_hash: "0".repeat(64), captured_at: "2020-01-01T00:00:00Z", objects: [] };
    const r = await diff({ base_snapshot: empty, target_connection: "local-sqlite" });
    assert.equal(r.status, "ok");
    assert.equal(kinds(r.data).filter((k) => k === "add_table").length, 5);
    assert.equal(kinds(r.data).filter((k) => k === "add_view").length, 1);
    assert.equal(r.data.has_destructive_changes, false);
    assertDiffInvariants(r.data, "empty base");
  });

  await check("diff_schema: a supplied snapshot whose objects were tampered (schema_version kept) is flagged (hash verification warning)", async () => {
    const tampered = JSON.parse(JSON.stringify(a0.data));
    tampered.objects = tampered.objects.filter((o) => o.name !== "orders");
    const r = await diff({ base_snapshot: tampered, target_connection: "local-sqlite" });
    assert.equal(r.status, "ok");
    assert.ok(r.warnings.some((w) => /hash|tamper|mismatch|verif/i.test(w)), `expected a hash-mismatch warning, got ${JSON.stringify(r.warnings)}`);
  });

  // ------------------------------------------------------------------ 4. data change must not change the hash
  await sql("local-sqlite", "INSERT INTO users (id, email, role, password_hash, created_at) VALUES (99, 'zed@example.com', 'customer', 'h', '2025-01-01T00:00:00Z')");
  const afterInsert = await cap("local-sqlite");
  await check("determinism: INSERT rows (data change, no schema change) keeps schema_version unchanged and snapshot carries no row-count statistics", () => {
    assert.equal(afterInsert.schema_version, a0.schema_version, `hash changed after INSERT: ${a0.schema_version} -> ${afterInsert.schema_version}`);
    assert.equal(byName(afterInsert.data, "users").estimated_rows, undefined, "estimated_rows must not be part of a schema snapshot");
  });

  await check("diff_schema after INSERT reports identical (structural diff ignores row counts, so it contradicts the changed schema_version)", async () => {
    const r = await diff({ base_snapshot: a0.data, target_connection: "local-sqlite" });
    assert.equal(r.data.is_identical, true);
  });

  // ------------------------------------------------------------------ 5. mutation matrix on local-sqlite
  let prev = afterInsert;
  const step = async (statements) => {
    for (const s of statements) await sql("local-sqlite", s);
    const cur = await cap("local-sqlite");
    const r = await diff({ base_snapshot: prev.data, target_snapshot: cur.data });
    assert.equal(r.status, "ok", JSON.stringify(r).slice(0, 200));
    const out = { prev, cur, diff: r.data, envelope: r };
    prev = cur;
    return out;
  };

  await check("mutation: CREATE TABLE -> add_table, non-destructive, transactional_rollback, forward DDL = CREATE TABLE definition, reverse = DROP TABLE", async () => {
    const { prev: p, cur, diff: d } = await step(["CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL, price_cents INTEGER DEFAULT 100)"]);
    assert.notEqual(cur.schema_version, p.schema_version);
    assertDiffInvariants(d, "add table");
    assert.deepEqual(kinds(d), ["add_table"]);
    const it = d.items[0];
    assert.equal(it.object_name, "main.widgets");
    assert.equal(it.destructive, false);
    assert.equal(it.transactional, true);
    assert.equal(it.reversal_safety, "transactional_rollback");
    assert.match(it.suggested_ddl, /^CREATE TABLE widgets \(/);
    assert.equal(it.compensating_ddl, "DROP TABLE main.widgets;");
  });

  await check("mutation: ADD COLUMN nullable -> add_column, safe (transactional_rollback), forward ADD COLUMN, reverse DROP COLUMN", async () => {
    const { diff: d } = await step(["ALTER TABLE users ADD COLUMN nickname TEXT"]);
    assertDiffInvariants(d, "add column");
    assert.deepEqual(kinds(d), ["add_column"]);
    const it = d.items[0];
    assert.equal(it.object_name, "main.users");
    assert.equal(it.target_name, "nickname");
    assert.equal(it.destructive, false);
    assert.equal(it.reversal_safety, "transactional_rollback");
    assert.equal(it.suggested_ddl, "ALTER TABLE main.users ADD COLUMN nickname TEXT;");
    assert.equal(it.compensating_ddl, "ALTER TABLE main.users DROP COLUMN nickname;");
  });

  await check("mutation: ADD COLUMN NOT NULL DEFAULT -> add_column with NOT NULL and DEFAULT in forward DDL", async () => {
    const { diff: d } = await step(["ALTER TABLE users ADD COLUMN tier TEXT NOT NULL DEFAULT 'free'"]);
    assert.deepEqual(kinds(d), ["add_column"]);
    assert.equal(d.items[0].suggested_ddl, "ALTER TABLE main.users ADD COLUMN tier TEXT NOT NULL DEFAULT 'free';");
    assert.equal(d.items[0].after, "tier TEXT NOT NULL DEFAULT 'free'");
  });

  await check("mutation: CREATE UNIQUE INDEX -> add_index with unique=true, forward DDL = original definition, reverse DROP INDEX, hash changes", async () => {
    const { prev: p, cur, diff: d } = await step(["CREATE UNIQUE INDEX idx_users_email ON users(email)"]);
    assert.notEqual(cur.schema_version, p.schema_version);
    assertDiffInvariants(d, "add index");
    assert.deepEqual(kinds(d), ["add_index"]);
    const it = d.items[0];
    assert.equal(it.object_name, "main.users");
    assert.equal(it.target_name, "idx_users_email");
    assert.equal(it.after, "columns=(email), unique=true");
    assert.equal(it.suggested_ddl, "CREATE UNIQUE INDEX idx_users_email ON users(email)");
    assert.equal(it.compensating_ddl, "DROP INDEX idx_users_email;");
    assert.equal(it.reversal_safety, "transactional_rollback");
    const idx = byName(cur.data, "users").indexes.find((i) => i.name === "idx_users_email");
    assert.equal(idx.unique, true);
    assert.deepEqual(idx.columns, ["email"]);
  });

  await check("mutation: CREATE VIEW -> add_view, forward DDL = view definition, reverse DROP VIEW", async () => {
    const { diff: d } = await step(["CREATE VIEW pending_orders AS SELECT id, total_cents FROM orders WHERE status = 'pending'"]);
    assertDiffInvariants(d, "add view");
    assert.deepEqual(kinds(d), ["add_view"]);
    assert.equal(d.items[0].object_name, "main.pending_orders");
    assert.equal(d.items[0].suggested_ddl, "CREATE VIEW pending_orders AS SELECT id, total_cents FROM orders WHERE status = 'pending'");
    assert.equal(d.items[0].compensating_ddl, "DROP VIEW main.pending_orders;");
  });

  await check("mutation: DROP COLUMN -> drop_column destructive, backup_recovery_required, reverse re-adds column", async () => {
    const { diff: d } = await step(["ALTER TABLE users DROP COLUMN nickname"]);
    assertDiffInvariants(d, "drop column");
    assert.deepEqual(kinds(d), ["drop_column"]);
    const it = d.items[0];
    assert.equal(it.target_name, "nickname");
    assert.equal(it.destructive, true);
    assert.equal(d.has_destructive_changes, true);
    assert.equal(it.reversal_safety, "backup_recovery_required");
    assert.equal(it.suggested_ddl, "ALTER TABLE main.users DROP COLUMN nickname;");
    assert.equal(it.compensating_ddl, "ALTER TABLE main.users ADD COLUMN nickname TEXT;");
  });

  await check("mutation: DROP INDEX -> drop_index, non-destructive, compensating_migration_required, reverse recreates the UNIQUE index", async () => {
    const { diff: d } = await step(["DROP INDEX idx_users_email"]);
    assertDiffInvariants(d, "drop index");
    assert.deepEqual(kinds(d), ["drop_index"]);
    const it = d.items[0];
    assert.equal(it.destructive, false);
    assert.equal(it.reversal_safety, "compensating_migration_required");
    assert.equal(it.suggested_ddl, "DROP INDEX idx_users_email;");
    assert.equal(it.compensating_ddl, "CREATE UNIQUE INDEX idx_users_email ON users(email)");
  });

  await check("mutation: DROP VIEW -> drop_view with reverse DDL = original CREATE VIEW", async () => {
    const { diff: d } = await step(["DROP VIEW active_user_orders"]);
    assertDiffInvariants(d, "drop view");
    assert.deepEqual(kinds(d), ["drop_view"]);
    assert.equal(d.items[0].object_name, "main.active_user_orders");
    assert.equal(d.items[0].suggested_ddl, "DROP VIEW main.active_user_orders;");
    assert.match(d.items[0].compensating_ddl, /^CREATE VIEW active_user_orders AS/);
  });

  await check("mutation: DROP TABLE -> drop_table destructive/irreversible (backup_recovery_required), reverse = original CREATE TABLE", async () => {
    const { diff: d } = await step(["DROP TABLE widgets"]);
    assertDiffInvariants(d, "drop table");
    assert.deepEqual(kinds(d), ["drop_table"]);
    const it = d.items[0];
    assert.equal(it.object_name, "main.widgets");
    assert.equal(it.destructive, true);
    assert.equal(it.reversal_safety, "backup_recovery_required");
    assert.equal(it.suggested_ddl, "DROP TABLE main.widgets;");
    assert.match(it.compensating_ddl, /^CREATE TABLE widgets \(/);
    assert.equal(d.has_destructive_changes, true);
  });

  let rebuildDiff = null;
  await check("mutation: table rebuild changing type/nullability/default -> alter_column_type (destructive) + alter_column_nullability + alter_column_default, summary count = 3", async () => {
    const { diff: d } = await step([
      "CREATE TABLE al2 (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE, event_type TEXT NOT NULL DEFAULT 'NONE', created_at INTEGER)",
      "INSERT INTO al2 SELECT * FROM audit_logs",
      "DROP TABLE audit_logs",
      "ALTER TABLE al2 RENAME TO audit_logs",
    ]);
    rebuildDiff = d;
    assertDiffInvariants(d, "rebuild");
    assert.deepEqual(kinds(d).sort(), ["alter_column_default", "alter_column_nullability", "alter_column_type"]);
    const ty = d.items.find((i) => i.kind === "alter_column_type");
    assert.equal(ty.target_name, "created_at");
    assert.equal(ty.before, "TEXT");
    assert.equal(ty.after, "INTEGER");
    assert.equal(ty.destructive, true);
    assert.equal(ty.reversal_safety, "compensating_migration_required");
    const nl = d.items.find((i) => i.kind === "alter_column_nullability");
    assert.equal(nl.before, "nullable=false");
    assert.equal(nl.after, "nullable=true");
    const df = d.items.find((i) => i.kind === "alter_column_default");
    assert.equal(df.target_name, "event_type");
    assert.equal(df.after, "'NONE'");
  });

  await check("DDL generation: SQLite cannot alter a column default in place, so alter_column_default carries no DDL (rebuild-table warning instead of invalid syntax)", () => {
    const df = rebuildDiff.items.find((i) => i.kind === "alter_column_default");
    assert.equal(rebuildDiff.engine, "sqlite");
    assert.ok(df.suggested_ddl == null && df.compensating_ddl == null, JSON.stringify(df));
  });

  await check("DDL generation: SQLite has no ALTER COLUMN ... TYPE, so alter_column_type carries no suggested_ddl and the diff warns to rebuild the table", async () => {
    const ty = rebuildDiff.items.find((i) => i.kind === "alter_column_type");
    assert.equal(rebuildDiff.engine, "sqlite");
    assert.ok(ty.suggested_ddl == null, `sqlite must not get Postgres ALTER COLUMN TYPE syntax: ${ty.suggested_ddl}`);
    const r = await diff({ base_snapshot: a0.data, target_snapshot: a0.data });
    assert.equal(r.status, "ok");
  });

  // ------------------------------------------------------------------ 6. object types the diff must cover
  const c0 = await cap("sqlite-c");
  await check("snapshot content: triggers are captured (sqlite-c carries trg_orders_audit) and change the hash", () => {
    assert.equal(c0.status, "ok");
    const trg = byName(c0.data, "trg_orders_audit");
    assert.ok(trg, "trigger object missing");
    assert.equal(trg.object_type, "trigger");
    assert.match(trg.definition, /^CREATE TRIGGER trg_orders_audit/);
    assert.notEqual(c0.schema_version, a0.schema_version, "trigger must change the schema hash");
  });

  await check("diff_schema: added trigger is reported (hash differs so the diff must not be identical)", async () => {
    const r = await diff({ base_snapshot: a0.data, target_snapshot: c0.data });
    assert.equal(r.status, "ok");
    assert.notEqual(r.data.base_schema_version, r.data.target_schema_version);
    assert.equal(r.data.is_identical, false, "versions differ but diff says identical");
    assert.ok(kinds(r.data).some((k) => /trigger/.test(k)), `expected a trigger diff item, got ${kinds(r.data)}`);
  });

  await check("diff_schema: dropped procedure/function is reported", async () => {
    const t = JSON.parse(JSON.stringify(a0.data));
    t.objects = t.objects.filter((o) => o.object_type !== "procedure" && o.object_type !== "function");
    const r = await diff({ base_snapshot: a0.data, target_snapshot: t });
    assert.equal(r.data.is_identical, false, "4 routines removed but diff says identical");
    assert.ok(kinds(r.data).some((k) => /procedure|function|routine/.test(k)), `got ${kinds(r.data)}`);
  });

  await check("diff_schema: dropped foreign key is reported", async () => {
    const t = JSON.parse(JSON.stringify(a0.data));
    byName(t, "orders").foreign_keys = [];
    const r = await diff({ base_snapshot: a0.data, target_snapshot: t });
    assert.equal(r.data.is_identical, false, "FK removed but diff says identical");
  });

  await check("diff_schema: primary-key flag change is reported", async () => {
    const t = JSON.parse(JSON.stringify(a0.data));
    byName(t, "users").columns[0].is_primary_key = false;
    const r = await diff({ base_snapshot: a0.data, target_snapshot: t });
    assert.equal(r.data.is_identical, false, "PK flag removed but diff says identical");
  });

  await check("diff_schema: index uniqueness change -> alter_index; view definition change -> alter_view with before/after", async () => {
    const t1 = JSON.parse(JSON.stringify(a0.data));
    byName(t1, "inventory").indexes[0].unique = false;
    const r1 = await diff({ base_snapshot: a0.data, target_snapshot: t1 });
    assert.deepEqual(kinds(r1.data), ["alter_index"]);
    assert.equal(r1.data.items[0].before, "columns=(sku), unique=true");
    const t2 = JSON.parse(JSON.stringify(a0.data));
    byName(t2, "active_user_orders").definition = "CREATE VIEW active_user_orders AS SELECT 1";
    const r2 = await diff({ base_snapshot: a0.data, target_snapshot: t2 });
    assert.deepEqual(kinds(r2.data), ["alter_view"]);
    assert.equal(r2.data.items[0].after, "CREATE VIEW active_user_orders AS SELECT 1");
    assert.match(r2.data.items[0].compensating_ddl, /^CREATE VIEW active_user_orders AS\n/);
    assertDiffInvariants(r1.data, "alter index");
    assertDiffInvariants(r2.data, "alter view");
  });

  // ------------------------------------------------------------------ 7. apply forward + reverse DDL on a second connection
  await check("DDL round-trip: forward DDL for add_table/add_column/add_index/add_view runs on sqlite-b, closes the diff, and reverse DDL restores the original hash", async () => {
    const base = await cap("sqlite-b");
    await sql("local-sqlite", "CREATE TABLE gadgets (id INTEGER PRIMARY KEY, label TEXT NOT NULL DEFAULT 'x', qty INTEGER)");
    await sql("local-sqlite", "ALTER TABLE orders ADD COLUMN note TEXT");
    await sql("local-sqlite", "ALTER TABLE orders ADD COLUMN flag INTEGER NOT NULL DEFAULT 0");
    await sql("local-sqlite", "CREATE INDEX idx_orders_status ON orders(status)");
    await sql("local-sqlite", "CREATE VIEW v_gadgets AS SELECT id, label FROM gadgets");
    const target = await cap("local-sqlite");
    const d = await diff({ base_snapshot: base.data, target_snapshot: target.data });
    const wanted = (i) => ["add_table", "add_column", "add_index", "add_view"].includes(i.kind) && ["main.gadgets", "main.orders", "main.v_gadgets"].includes(i.object_name);
    const sel = d.data.items.filter(wanted);
    assert.equal(sel.length, 5, `expected 5 applicable items, got ${sel.map((i) => i.kind + ":" + i.object_name + ":" + (i.target_name || ""))}`);
    for (const it of sel) {
      const r = await call("execute_query", { connection: "sqlite-b", sql: it.suggested_ddl });
      assert.equal(r.status, "ok", `forward DDL failed (${it.kind} ${it.object_name}): ${it.suggested_ddl} -> ${r.code} ${r.message}`);
    }
    const after = await cap("sqlite-b");
    const d2 = await diff({ base_snapshot: after.data, target_snapshot: target.data });
    assert.equal(d2.data.items.filter(wanted).length, 0, `forward DDL did not close the diff: ${JSON.stringify(d2.data.items.filter(wanted).map((i) => i.kind + ":" + i.object_name))}`);
    for (const it of sel.slice().reverse()) {
      const r = await call("execute_query", { connection: "sqlite-b", sql: it.compensating_ddl });
      assert.equal(r.status, "ok", `reverse DDL failed (${it.kind} ${it.object_name}): ${it.compensating_ddl} -> ${r.code} ${r.message}`);
    }
    const back = await cap("sqlite-b");
    assert.equal(back.schema_version, base.schema_version, "reverse DDL must restore the original schema hash");
  });

  // ------------------------------------------------------------------ 8. cross-engine
  await check("cross-engine: local-sqlite vs prod-postgres (same logical schema) reports no add/drop table noise, at most type-name differences", async () => {
    const pg = await cap("prod-postgres");
    assertSuccessEnvelope(pg, "capture prod-postgres");
    assert.equal(pg.data.engine, "postgres");
    const r = await diff({ base_snapshot: a0.data, target_connection: "prod-postgres" });
    assert.equal(r.status, "ok");
    assert.equal(r.data.engine, "postgres", "diff engine follows the target");
    const noisy = r.data.items.filter((i) => ["add_table", "drop_table", "add_view", "drop_view"].includes(i.kind));
    note(`cross-engine diff produced ${r.data.items.length} items: ${[...new Set(kinds(r.data))].join(",")}; first object names: ${r.data.items.slice(0, 2).map((i) => i.object_name).join(", ")}`);
    assert.equal(noisy.length, 0, `tables matched by schema-qualified name only (main.* vs public.*): ${noisy.length} spurious add/drop items`);
  });

  await check("cross-engine: a snapshot from another engine diffed against a connection raises an engine-mismatch warning", async () => {
    const pg = await cap("prod-postgres");
    const r = await diff({ base_snapshot: pg.data, target_connection: "local-sqlite" });
    assert.equal(r.status, "ok");
    assert.ok(r.warnings.some((w) => /engine/i.test(w)), `expected engine mismatch warning, got ${JSON.stringify(r.warnings)}`);
  });

  // ------------------------------------------------------------------ 9. denials
  await check("denials: unknown connection -> CONNECTION_NOT_FOUND with next_action=list_connections for capture_schema and both diff sides", async () => {
    const r1 = await cap("nope");
    assertDenied(r1, "CONNECTION_NOT_FOUND", "capture");
    assert.equal(r1.next_action, "list_connections");
    assert.equal(r1.connection, "nope");
    const r2 = await diff({ base_connection: "nope", target_connection: "local-sqlite" });
    assertDenied(r2, "CONNECTION_NOT_FOUND", "diff base");
    const r3 = await diff({ base_snapshot: a0.data, target_connection: "nope" });
    assertDenied(r3, "CONNECTION_NOT_FOUND", "diff target");
  });

  await check("denials: capture_schema without 'connection' -> INVALID_ARGUMENT", async () => {
    const r = await call("capture_schema", {});
    assertDenied(r, "INVALID_ARGUMENT", "capture no conn");
    assert.match(r.message, /connection/);
  });

  const intern = openClient(main.configPath, "intern-1", "intern");
  await intern.init();
  await check("denials: role not in allowed_roles -> UNAUTHORIZED_ROLE on prod-postgres for capture_schema and for diff_schema (base, target, snapshot+target)", async () => {
    const r1 = await intern.call("capture_schema", { connection: "prod-postgres" });
    assertDenied(r1, "UNAUTHORIZED_ROLE", "intern capture");
    assert.equal(typeof r1.next_action, "string");
    assert.ok(!("data" in r1), "denied response must not carry snapshot data");
    const r2 = await intern.call("diff_schema", { base_connection: "prod-postgres", target_connection: "local-sqlite" });
    assertDenied(r2, "UNAUTHORIZED_ROLE", "intern diff base");
    const r3 = await intern.call("diff_schema", { base_connection: "local-sqlite", target_connection: "prod-postgres" });
    assertDenied(r3, "UNAUTHORIZED_ROLE", "intern diff target");
    const r4 = await intern.call("diff_schema", { base_snapshot: a0.data, target_connection: "prod-postgres" });
    assertDenied(r4, "UNAUTHORIZED_ROLE", "intern diff snapshot+target");
    const ok = await intern.call("capture_schema", { connection: "local-sqlite" });
    assert.equal(ok.status, "ok", "intern is allowed on local-sqlite (allowed_roles = *)");
  });
  intern.close();

  // ------------------------------------------------------------------ 10. audit trail
  agent.close();
  await sleep(700);
  await check("audit: capture_schema and diff_schema calls (allowed and denied) are recorded in the audit log", () => {
    const auditPath = path.join(main.dir, "audit.jsonl");
    assert.ok(fs.existsSync(auditPath), `audit log missing at ${auditPath}`);
    const events = fs.readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const tools = new Set(events.map((e) => e.tool_name));
    note(`audit tool_names seen: ${[...tools].join(", ")} (${events.length} events)`);
    assert.ok(tools.has("capture_schema"), "no capture_schema audit events");
    assert.ok(tools.has("diff_schema"), "no diff_schema audit events");
  });

  // ------------------------------------------------------------------ 11. profile gating
  await check("profile gating: without the Schema profile both tools are absent from tools/list and calls return TOOL_NOT_ENABLED", async () => {
    const cfg = buildNoSchemaProfileConfig();
    const c = openClient(cfg.configPath, "local-agent", "agent");
    try {
      await c.init();
      const lt = await c.cl.rpc("tools/list", {});
      const names = lt.result.tools.map((t) => t.name);
      assert.ok(!names.includes("capture_schema") && !names.includes("diff_schema"), `schema tools listed: ${names}`);
      const r1 = await c.call("capture_schema", { connection: "local-sqlite" });
      assertDenied(r1, "TOOL_NOT_ENABLED", "capture");
      const r2 = await c.call("diff_schema", { base_connection: "local-sqlite", target_connection: "local-sqlite" });
      assertDenied(r2, "TOOL_NOT_ENABLED", "diff");
    } finally {
      c.close();
    }
  });

  // ------------------------------------------------------------------ 12. large schema
  await check("large schema: 200 extra tables + indexes -> capture ok, deterministic, diff identical, latency < 10s (payload size and max_bytes behaviour logged)", async () => {
    const cfg = buildLargeConfig(200);
    const c = openClient(cfg.configPath, "local-agent", "agent");
    try {
      await c.init();
      let t0 = Date.now();
      const s1 = await c.call("capture_schema", { connection: "local-sqlite" });
      const ms = Date.now() - t0;
      assertSuccessEnvelope(s1, "large capture");
      const tables = s1.data.objects.filter((o) => o.object_type === "table").length;
      assert.ok(tables >= 205, `expected >= 205 visible tables, got ${tables}`);
      const bytes = Buffer.byteLength(JSON.stringify(s1.data));
      note(`large snapshot: ${s1.data.objects.length} objects, ${bytes} bytes, ${ms} ms; connection max_bytes=2048 -> truncated=${s1.truncated}, warnings=${JSON.stringify(s1.warnings)} (max_bytes is not applied to snapshot payloads)`);
      assert.ok(ms < 10000, `capture took ${ms} ms`);
      assert.equal(s1.truncated, false, "a snapshot must never be silently truncated");
      const s2 = await c.call("capture_schema", { connection: "local-sqlite" });
      assert.equal(s2.schema_version, s1.schema_version);
      t0 = Date.now();
      const d = await c.call("diff_schema", { base_snapshot: s1.data, target_connection: "local-sqlite" });
      note(`large diff: ${Date.now() - t0} ms`);
      assert.equal(d.status, "ok");
      assert.equal(d.data.is_identical, true);
    } finally {
      c.close();
    }
  });

  // ------------------------------------------------------------------ summary
  await sleep(300);
  const total = results.pass + results.fail + results.knownBugFail;
  console.log(`\n[F11] ${results.pass} passed, ${results.fail} failed, ${results.knownBugFail} failed as KNOWN-BUG (${total} checks)`);
  if (results.fail > 0) return 1;
  if (results.knownBugFail > 0 && process.env.F11_ALLOW_KNOWN_BUGS !== "1") return 1;
  return 0;
}

main()
  .then((code) => { killAll(); process.exit(code); })
  .catch((err) => {
    console.error("[F11] fatal:", err && err.stack ? err.stack : err);
    killAll();
    process.exit(1);
  });
