#!/usr/bin/env node
"use strict";
/**
 * F02 - Explore profile feature verification: list_connections, search_objects, describe_object
 * across local-sqlite (live), prod-postgres and analytics-mysql (embedded simulation).
 *
 * Run from the repo root:  node npm/test/features/02-explore.test.js
 *
 * Self-contained: creates its own isolated config, spawns its own servers, cleans up.
 * Assertions encode the CORRECT behaviour (per research/contracts/tool-contracts.json and the
 * tool schemas). Checks that fail on the current build are tagged `// KNOWN-BUG: F02-xx`;
 * they are reported as FAIL (KNOWN-BUG ...) and still make the exit code non-zero.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));

const CONNECTIONS = [
  { id: "local-sqlite", schema: "main", restricted: true, simulated: false, routinesDefined: true, mode: "development", engine: "sqlite" },
  { id: "prod-postgres", schema: "public", restricted: true, simulated: true, routinesDefined: true, mode: "governed_production", engine: "postgres" },
  { id: "analytics-mysql", schema: "analytics", restricted: false, simulated: true, routinesDefined: true, mode: "read_only", engine: "mysql" },
];
const BASE_TABLES = ["audit_logs", "inventory", "order_items", "orders", "users"];
const RESTRICTED_TABLE = "internal_secrets";
const VIEW = "active_user_orders";
const PROCEDURES = ["checkout_order", "record_order_audit", "reserve_inventory"];
const FUNCTIONS = ["calculate_order_discount"];
const MAX_CALL_MS = 5000;

const results = [];
const clients = [];
let isoDir = null;

async function check(id, title, fn, knownBug) {
  const label = `${id} ${title}`;
  try {
    await fn();
    results.push({ id, ok: true, knownBug });
    console.log(`PASS  ${label}${knownBug ? `  (was KNOWN-BUG ${knownBug}: now fixed)` : ""}`);
  } catch (err) {
    results.push({ id, ok: false, knownBug, err });
    const msg = String(err && err.message ? err.message : err).split("\n")[0].slice(0, 220);
    console.log(`FAIL  ${label}${knownBug ? `  [KNOWN-BUG ${knownBug}]` : ""}  -> ${msg}`);
  }
}

async function openClient(configPath, principal, role) {
  const c = createClient({ config: configPath, principal, role, timeoutMs: 30000 });
  clients.push(c);
  const init = await c.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f02-explore-test", version: "0.1.0" } });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  c.notify("notifications/initialized", {});
  return c;
}

async function callTool(client, name, args) {
  const t0 = Date.now();
  const resp = await client.rpc("tools/call", { name, arguments: args });
  const ms = Date.now() - t0;
  if (resp.error) throw new Error(`JSON-RPC error for ${name}: ${JSON.stringify(resp.error)}`);
  const sc = resp.result.structuredContent !== undefined ? resp.result.structuredContent : JSON.parse(resp.result.content[0].text);
  assert.ok(ms < MAX_CALL_MS, `${name} took ${ms}ms (> ${MAX_CALL_MS}ms)`);
  return { sc, ms, raw: resp.result };
}

function assertSuccessEnvelope(sc, label, expectedConnection) {
  assert.equal(sc.status, "ok", `${label}: expected status ok, got ${JSON.stringify(sc).slice(0, 300)}`);
  assert.equal(typeof sc.request_id, "string", `${label}: request_id`);
  assert.ok(sc.request_id.startsWith("req_"), `${label}: request_id prefix`);
  assert.equal(typeof sc.connection, "string", `${label}: connection`);
  if (expectedConnection) assert.equal(sc.connection, expectedConnection, `${label}: connection echo`);
  assert.ok(Array.isArray(sc.columns), `${label}: columns array`);
  assert.ok(Array.isArray(sc.rows), `${label}: rows array`);
  assert.equal(typeof sc.returned_rows, "number", `${label}: returned_rows number`);
  assert.equal(typeof sc.truncated, "boolean", `${label}: truncated boolean`);
  assert.ok(Array.isArray(sc.warnings), `${label}: warnings array`);
  assert.equal(typeof sc.schema_version, "string", `${label}: schema_version string`);
  assert.equal(sc._meta && sc._meta.provenance && sc._meta.provenance.untrusted_content, true, `${label}: _meta.provenance.untrusted_content`);
  assert.equal(sc._meta.provenance.source_connection, sc.connection, `${label}: provenance.source_connection`);
}

function assertDenied(sc, label, code, nextAction) {
  assert.equal(sc.status, "denied", `${label}: expected denied, got ${JSON.stringify(sc).slice(0, 300)}`);
  assert.equal(typeof sc.code, "string", `${label}: code`);
  assert.equal(typeof sc.message, "string", `${label}: message`);
  if (code) assert.equal(sc.code, code, `${label}: code (message=${sc.message})`);
  if (nextAction !== undefined) assert.equal(sc.next_action, nextAction, `${label}: next_action`);
}

const namesOf = (sc) => sc.data.objects.map((o) => o.name);
const ofType = (sc, type) => sc.data.objects.filter((o) => o.object_type === type).map((o) => o.name).sort();
const sortedEq = (a, b, msg) => assert.deepEqual([...a].sort(), [...b].sort(), msg);

async function main() {
  const iso = makeIsolatedConfig();
  isoDir = iso.dir;
  const configPath = iso.configPath;
  process.chdir(REPO_ROOT);
  console.log(`# F02 explore tests - isolated config: ${configPath}`);

  const agent = await openClient(configPath, "local-agent", "agent");
  const viewer = await openClient(configPath, "bob", "viewer");

  // ---------------------------------------------------------------- tools/list
  await check("TL-01", "tools/list exposes list_connections, search_objects, describe_object with schemas", async () => {
    const resp = await agent.rpc("tools/list", {});
    const tools = resp.result.tools;
    for (const n of ["list_connections", "search_objects", "describe_object"]) {
      const t = tools.find((x) => x.name === n);
      assert.ok(t, `${n} missing from tools/list`);
      assert.equal(t.inputSchema.type, "object");
    }
    const so = tools.find((x) => x.name === "search_objects");
    assert.deepEqual(so.inputSchema.required, ["connection"]);
    assert.deepEqual(tools.find((x) => x.name === "describe_object").inputSchema.required, ["connection", "object_name"]);
    assert.deepEqual(so.inputSchema.properties.detail_level.enum, ["names", "summary", "full"]);
  });

  // ---------------------------------------------------------------- list_connections
  const lc = (await callTool(agent, "list_connections", {})).sc;
  await check("LC-01", "list_connections success envelope", () => assertSuccessEnvelope(lc, "list_connections"));
  await check("LC-02", "list_connections returns all 3 configured connections", () => {
    sortedEq(lc.data.map((c) => c.id), CONNECTIONS.map((c) => c.id));
  });
  await check("LC-03", "each connection has engine/mode/read_only/default_schema/limits/capabilities populated", () => {
    for (const expected of CONNECTIONS) {
      const c = lc.data.find((x) => x.id === expected.id);
      assert.equal(c.engine, expected.engine, `${c.id} engine`);
      assert.equal(c.mode, expected.mode, `${c.id} mode`);
      assert.equal(typeof c.read_only, "boolean", `${c.id} read_only`);
      assert.equal(c.default_schema, expected.schema, `${c.id} default_schema`);
      assert.equal(typeof c.description, "string", `${c.id} description`);
      for (const k of ["max_rows", "max_bytes", "timeout_ms"]) assert.ok(Number.isInteger(c.limits[k]) && c.limits[k] > 0, `${c.id} limits.${k}`);
      assert.equal(typeof c.limits.allow_multi_statement, "boolean");
      assert.equal(c.capabilities.engine, expected.engine, `${c.id} capabilities.engine`);
      for (const k of ["supports_explain", "supports_schema_diff", "supports_transactional_ddl", "supports_parameter_binding"]) assert.equal(typeof c.capabilities[k], "boolean", `${c.id} capabilities.${k}`);
    }
    assert.equal(lc.data.find((x) => x.id === "analytics-mysql").read_only, true);
    assert.equal(lc.data.find((x) => x.id === "local-sqlite").read_only, false);
  });
  await check("LC-04", "list_connections leaks no DSN, password, token or secret values", () => {
    const text = JSON.stringify(lc);
    for (const re of [/postgres(ql)?:\/\//i, /mysql:\/\//i, /sqlite:\/\//i, /"dsn"/i, /password"\s*:/i, /auth_token/i, /admin_token/i, /env:DB_MCP/i, /hash_alice/i, /TOPSECRET/i, /init_sql/i]) {
      assert.ok(!re.test(text), `list_connections output matched ${re}`);
    }
  });
  await check("LC-05", "list_connections returned_rows equals number of connections in data (contract: returned_rows = count)", () => {
    assert.equal(lc.returned_rows, lc.data.length, `returned_rows=${lc.returned_rows} but data has ${lc.data.length} items`);
  }, "F02-01"); // KNOWN-BUG: F02-01 McpSuccessResponse::with_data hardcodes returned_rows=0
  await check("LC-06", "list_connections is role-filtered: viewer does not see prod-postgres (allowed_roles excludes viewer)", async () => {
    const v = (await callTool(viewer, "list_connections", {})).sc;
    assertSuccessEnvelope(v, "viewer list_connections");
    sortedEq(v.data.map((c) => c.id), ["analytics-mysql", "local-sqlite"]);
  });
  await check("LC-07", "list_connections with additional unknown argument still succeeds (lenient) or is denied cleanly", async () => {
    const r = (await callTool(agent, "list_connections", { bogus: 1 })).sc;
    assert.ok(r.status === "ok" || r.status === "denied");
  });

  // ---------------------------------------------------------------- search_objects per connection
  const catalogByConn = {};
  for (const conn of CONNECTIONS) {
    const P = `SO-${conn.engine}`;
    const so = async (args) => (await callTool(agent, "search_objects", { connection: conn.id, ...args })).sc;
    const visibleTables = conn.restricted ? BASE_TABLES : [...BASE_TABLES, RESTRICTED_TABLE];
    const expectedProcs = conn.routinesDefined ? PROCEDURES : [];
    const expectedFuncs = conn.routinesDefined ? FUNCTIONS : [];

    const dflt = await so({});
    const names = await so({ detail_level: "names", limit: 1000 });
    const full = await so({ detail_level: "full", limit: 1000 });
    catalogByConn[conn.id] = { dflt, names, full };

    await check(`${P}-01`, `[${conn.id}] default search envelope ok, schema_version is snapshot_<hash>`, () => {
      assertSuccessEnvelope(dflt, "search_objects", conn.id);
      assert.match(dflt.schema_version, /^snapshot_[0-9a-f]{12}$/);
      assert.equal(dflt._meta.provenance.source_kind, "catalog_search");
      assert.equal(dflt.data.returned_count, dflt.data.objects.length);
      assert.equal(typeof dflt.data.total_count, "number");
      assert.equal(typeof dflt.data.has_more, "boolean");
    });
    await check(`${P}-02`, `[${conn.id}] tables discovered = ${visibleTables.join(",")} (restricted ${conn.restricted ? "hidden" : "visible"}), view ${VIEW}, all in schema ${conn.schema}`, () => {
      sortedEq(ofType(names, "table"), visibleTables);
      sortedEq(ofType(names, "view"), [VIEW]);
      for (const o of names.data.objects) assert.equal(o.schema, conn.schema, `${o.name} schema`);
    });
    await check(`${P}-03`, `[${conn.id}] routines discovered match connection init_sql (procedures=${expectedProcs.length}, functions=${expectedFuncs.length})`, () => {
      sortedEq(ofType(names, "procedure"), expectedProcs);
      sortedEq(ofType(names, "function"), expectedFuncs);
    });
    await check(`${P}-04`, `[${conn.id}] detail levels: default==summary (columns, no definition/indexes); names (bare); full (definition, fks, indexes)`, () => {
      const dTable = dflt.data.objects.find((o) => o.name === "orders");
      assert.ok(dTable.columns.length === 5 && dTable.definition === undefined && dTable.indexes.length === 0 && dTable.foreign_keys.length === 0, "default/summary projection");
      assert.ok(typeof dTable.estimated_rows === "number", "summary keeps estimated_rows");
      const nTable = names.data.objects.find((o) => o.name === "orders");
      assert.ok(nTable.columns.length === 0 && nTable.definition === undefined && nTable.estimated_rows === undefined, "names projection");
      const fTable = full.data.objects.find((o) => o.name === "orders");
      assert.ok(typeof fTable.definition === "string" && fTable.foreign_keys.length === 1, "full projection on orders");
      const fInv = full.data.objects.find((o) => o.name === "inventory");
      assert.ok(fInv.indexes.length >= 1, "full projection exposes indexes on inventory");
      const fView = full.data.objects.find((o) => o.name === VIEW);
      assert.match(fView.definition, /CREATE VIEW/i);
    });
    await check(`${P}-05`, `[${conn.id}] name_pattern substring 'order' == LIKE '%order%' == 'ORDER' (case-insensitive)`, async () => {
      const a = namesOf(await so({ name_pattern: "order", detail_level: "names" }));
      const b = namesOf(await so({ name_pattern: "%order%", detail_level: "names" }));
      const c = namesOf(await so({ name_pattern: "ORDER", detail_level: "names" }));
      assert.ok(a.length > 0);
      assert.deepEqual(a, b);
      assert.deepEqual(a, c);
      for (const n of ["orders", "order_items", VIEW]) assert.ok(a.includes(n), `${n} expected in '%order%' results`);
    });
    await check(`${P}-06`, `[${conn.id}] name_pattern 'users' returns exactly users; 'user_' (LIKE single-char) matches users; no-match returns 0 with has_more=false`, async () => {
      assert.deepEqual(namesOf(await so({ name_pattern: "users", detail_level: "names" })), ["users"]);
      assert.deepEqual(namesOf(await so({ name_pattern: "user_", detail_level: "names" })), ["users"]);
      const none = await so({ name_pattern: "zzz_nomatch" });
      assert.equal(none.data.total_count, 0);
      assert.equal(none.data.objects.length, 0);
      assert.equal(none.data.has_more, false);
    });
    await check(`${P}-07`, `[${conn.id}] prefix pattern 'ord%' returns only objects whose NAME starts with 'ord' (schema says filter on object name)`, async () => {
      const r = namesOf(await so({ name_pattern: "ord%", detail_level: "names" }));
      sortedEq(r, ["order_items", "orders"], `got ${r.join(",")}`);
    });
    await check(`${P}-08`, `[${conn.id}] schema_pattern: '${conn.schema}' and '%' return everything, other schema / nonexistent return 0, case-insensitive`, async () => {
      const all = names.data.objects.length;
      assert.equal((await so({ schema_pattern: conn.schema, detail_level: "names", limit: 1000 })).data.objects.length, all);
      assert.equal((await so({ schema_pattern: conn.schema.toUpperCase(), detail_level: "names", limit: 1000 })).data.objects.length, all);
      assert.equal((await so({ schema_pattern: "%", detail_level: "names", limit: 1000 })).data.objects.length, all);
      assert.equal((await so({ schema_pattern: "no_such_schema", detail_level: "names" })).data.total_count, 0);
      const other = CONNECTIONS.find((c) => c.id !== conn.id).schema;
      assert.equal((await so({ schema_pattern: other, detail_level: "names" })).data.total_count, 0, `schema '${other}' must not match on ${conn.id}`);
    });
    await check(`${P}-09`, `[${conn.id}] object_types filters: table/view/index/function/procedure (+case-insensitive, +multi)`, async () => {
      sortedEq(namesOf(await so({ object_types: ["table"], detail_level: "names" })), visibleTables);
      sortedEq(namesOf(await so({ object_types: ["TABLE"], detail_level: "names" })), visibleTables);
      sortedEq(namesOf(await so({ object_types: ["view"], detail_level: "names" })), [VIEW]);
      const idx = await so({ object_types: ["index"], detail_level: "names" });
      assert.ok(idx.data.objects.length >= 1 && idx.data.objects.every((o) => o.object_type === "index"));
      const procs = await so({ object_types: ["procedure"], detail_level: "names" });
      assert.ok(procs.data.objects.every((o) => o.object_type === "procedure"));
      const fns = await so({ object_types: ["function"], detail_level: "names" });
      assert.ok(fns.data.objects.every((o) => o.object_type === "function"));
      sortedEq(namesOf(await so({ object_types: ["table", "view"], detail_level: "names" })), [...visibleTables, VIEW]);
      for (const t of ["trigger", "schema", "sequence", "materialized_view"]) {
        const r = await so({ object_types: [t], detail_level: "names" });
        assert.ok(r.data.objects.every((o) => o.object_type === t), `${t} filter returned other types`);
      }
    });
    await check(`${P}-10`, `[${conn.id}] object_types plural/alias spellings ('tables','views','proc') filter like the singular (CatalogObjectType::from_str accepts them)`, async () => {
      sortedEq(namesOf(await so({ object_types: ["tables"], detail_level: "names" })), visibleTables);
      sortedEq(namesOf(await so({ object_types: ["views"], detail_level: "names" })), [VIEW]);
    });
    await check(`${P}-11`, `[${conn.id}] object_types with only unknown values is rejected (INVALID_ARGUMENT), not silently unfiltered`, async () => {
      const r = await so({ object_types: ["bogus_type"], detail_level: "names" });
      assertDenied(r, "object_types bogus", "INVALID_ARGUMENT");
    });
    await check(`${P}-12`, `[${conn.id}] pagination limit=3: no dups/gaps, full pages, has_more/next_offset correct, total_count == visible objects`, async () => {
      const expectedAll = namesOf(names);
      const seen = [];
      let offset = 0;
      let pages = 0;
      for (;;) {
        const page = await so({ detail_level: "names", limit: 3, offset });
        pages++;
        assert.ok(pages < 20, "pagination did not terminate");
        assert.equal(page.data.total_count, expectedAll.length, `total_count must equal the number of discoverable objects (got ${page.data.total_count} vs ${expectedAll.length})`);
        seen.push(...namesOf(page));
        if (page.data.has_more) {
          assert.equal(page.data.objects.length, 3, `non-final page at offset ${offset} must be full (got ${page.data.objects.length})`);
          assert.equal(page.data.next_offset, offset + 3);
          offset = page.data.next_offset;
        } else {
          assert.equal(page.data.next_offset, undefined);
          break;
        }
      }
      assert.equal(new Set(seen).size, seen.length, "duplicates across pages");
      sortedEq(seen, expectedAll, "union of pages != full result set (gaps)");
    }, conn.restricted ? "F02-02" : undefined); // KNOWN-BUG: F02-02 restricted tables removed AFTER pagination -> total_count leaks and pages come back short
    await check(`${P}-13`, `[${conn.id}] offset beyond total -> 0 objects, has_more=false; huge limit returns everything`, async () => {
      const r = await so({ detail_level: "names", offset: 1000 });
      assert.equal(r.data.objects.length, 0);
      assert.equal(r.data.has_more, false);
      const big = await so({ detail_level: "names", limit: 1000000000 });
      assert.equal(big.data.objects.length, names.data.objects.length);
      assert.equal(big.data.has_more, false);
    });
    await check(`${P}-14`, `[${conn.id}] envelope returned_rows equals number of objects returned (contract: returned_rows = count)`, () => {
      assert.equal(names.returned_rows, names.data.objects.length, `returned_rows=${names.returned_rows} objects=${names.data.objects.length}`);
    }, "F02-01"); // KNOWN-BUG: F02-01
    if (conn.restricted) {
      await check(`${P}-15`, `[${conn.id}] restricted table is not discoverable: name_pattern 'internal' -> 0 objects AND total_count 0 (no existence leak)`, async () => {
        const r = await so({ name_pattern: "internal" });
        assert.equal(r.data.objects.length, 0);
        assert.equal(r.data.total_count, 0, `total_count=${r.data.total_count} leaks the restricted object`);
      }, "F02-02"); // KNOWN-BUG: F02-02
    }
    if (conn.simulated) {
      await check(`${P}-16`, `[${conn.id}] simulated backend (no live server) is disclosed via a warning on explore responses`, () => {
        const w = dflt.warnings.join(" | ");
        assert.match(w, /simulat|embedded|offline|not reachable|unreachable/i, `warnings=${JSON.stringify(dflt.warnings)}`);
      }, "F02-05"); // KNOWN-BUG: F02-05 ensure_connectivity ignores the probe result; nothing tells the caller the catalog is synthetic
    }
    await check(`${P}-17`, `[${conn.id}] schema_version is stable across search calls`, () => {
      assert.equal(dflt.schema_version, names.schema_version);
      assert.equal(dflt.schema_version, full.schema_version);
    });
  }

  // ---------------------------------------------------------------- search_objects global / argument handling
  await check("SO-G-01", "unknown connection -> denied CONNECTION_NOT_FOUND, next_action=list_connections, request_id present", async () => {
    const r = (await callTool(agent, "search_objects", { connection: "nope" })).sc;
    assertDenied(r, "unknown conn", "CONNECTION_NOT_FOUND", "list_connections");
    assert.equal(r.connection, "nope");
    assert.match(r.request_id, /^req_/);
  });
  await check("SO-G-02", "missing / blank connection -> denied INVALID_ARGUMENT", async () => {
    assertDenied((await callTool(agent, "search_objects", {})).sc, "missing", "INVALID_ARGUMENT");
    assertDenied((await callTool(agent, "search_objects", { connection: "   " })).sc, "blank", "INVALID_ARGUMENT");
  });
  await check("SO-G-03", "viewer role on prod-postgres -> denied UNAUTHORIZED_ROLE for search_objects and describe_object", async () => {
    assertDenied((await callTool(viewer, "search_objects", { connection: "prod-postgres" })).sc, "viewer search", "UNAUTHORIZED_ROLE");
    assertDenied((await callTool(viewer, "describe_object", { connection: "prod-postgres", object_name: "users" })).sc, "viewer describe", "UNAUTHORIZED_ROLE");
    const ok = (await callTool(viewer, "search_objects", { connection: "local-sqlite", detail_level: "names" })).sc;
    assertSuccessEnvelope(ok, "viewer sqlite search", "local-sqlite");
  });
  await check("SO-G-04", "limit=0 / negative / non-integer limit are rejected (INVALID_ARGUMENT) instead of silently becoming 50", async () => {
    for (const limit of [0, -1, "5", 2.5]) {
      const r = (await callTool(agent, "search_objects", { connection: "local-sqlite", limit, detail_level: "names" })).sc;
      assertDenied(r, `limit=${JSON.stringify(limit)}`, "INVALID_ARGUMENT");
    }
  });
  await check("SO-G-05", "unknown detail_level ('bogus', 'FULL') is rejected (schema enum: names|summary|full) instead of silently using the default", async () => {
    assertDenied((await callTool(agent, "search_objects", { connection: "local-sqlite", detail_level: "bogus" })).sc, "detail bogus", "INVALID_ARGUMENT");
    const upper = (await callTool(agent, "search_objects", { connection: "local-sqlite", detail_level: "FULL" })).sc;
    assert.ok(upper.status === "denied" || upper.data.objects.find((o) => o.name === "orders").definition !== undefined, "'FULL' must either be rejected or honoured as full, not silently downgraded to summary");
  });
  await check("SO-G-06", "negative offset is rejected or treated as 0 with a warning (not silently coerced)", async () => {
    const r = (await callTool(agent, "search_objects", { connection: "local-sqlite", offset: -1, detail_level: "names" })).sc;
    assert.ok(r.status === "denied" || r.warnings.length > 0, `offset=-1 silently accepted: ${JSON.stringify(r.warnings)}`);
  });

  // ---------------------------------------------------------------- describe_object per connection
  for (const conn of CONNECTIONS) {
    const P = `DO-${conn.engine}`;
    const d = async (args) => (await callTool(agent, "describe_object", { connection: conn.id, ...args })).sc;

    const users = await d({ object_name: "users" });
    await check(`${P}-01`, `[${conn.id}] describe users: envelope ok, 5 typed columns with nullability/pk/ordinal, DDL definition, estimated_rows`, () => {
      assertSuccessEnvelope(users, "describe users", conn.id);
      assert.equal(users._meta.provenance.source_kind, "catalog_object");
      const o = users.data;
      assert.equal(o.name, "users");
      assert.equal(o.schema, conn.schema);
      assert.equal(o.object_type, "table");
      assert.deepEqual(o.columns.map((c) => c.name), ["id", "email", "role", "password_hash", "created_at"]);
      const id = o.columns[0];
      assert.equal(id.is_primary_key, true);
      assert.equal(id.nullable, false);
      assert.match(id.data_type, /INT/i);
      assert.equal(id.ordinal_position, 1);
      assert.ok(o.columns.slice(1).every((c) => c.is_primary_key === false && c.nullable === false && typeof c.data_type === "string"));
      assert.match(o.definition, /CREATE TABLE users/i);
      assert.equal(o.estimated_rows, 2);
      assert.equal(users.schema_version, catalogByConn[conn.id].dflt.schema_version, "describe schema_version == search schema_version");
    });
    await check(`${P}-02`, `[${conn.id}] describe orders: FK user_id -> users(id) ON DELETE CASCADE; order_items has FKs to orders and inventory`, async () => {
      const o = (await d({ object_name: "orders" })).data;
      assert.equal(o.foreign_keys.length, 1);
      const fk = o.foreign_keys[0];
      assert.deepEqual(fk.columns, ["user_id"]);
      assert.equal(fk.referenced_table, "users");
      assert.deepEqual(fk.referenced_columns, ["id"]);
      assert.equal(fk.on_delete, "CASCADE");
      assert.equal(typeof fk.name, "string");
      const oi = (await d({ object_name: "order_items" })).data;
      sortedEq(oi.foreign_keys.map((f) => f.referenced_table), ["inventory", "orders"]);
      const skuFk = oi.foreign_keys.find((f) => f.referenced_table === "inventory");
      assert.deepEqual(skuFk.columns, ["sku"]);
      assert.deepEqual(skuFk.referenced_columns, ["sku"]);
    });
    await check(`${P}-03`, `[${conn.id}] describe inventory: unique primary index on sku with table_name/columns/index_type; reserved_qty default 0`, async () => {
      const o = (await d({ object_name: "inventory" })).data;
      assert.equal(o.indexes.length, 1);
      const ix = o.indexes[0];
      assert.equal(ix.table_name, "inventory");
      assert.deepEqual(ix.columns, ["sku"]);
      assert.equal(ix.unique, true);
      assert.equal(ix.primary, true);
      assert.match(String(ix.index_type), /btree/i);
      assert.equal(o.columns.find((c) => c.name === "reserved_qty").default_value, "0");
    });
    await check(`${P}-04`, `[${conn.id}] describe view active_user_orders: object_type view, 6 columns, definition is the CREATE VIEW text`, async () => {
      const o = (await d({ object_name: VIEW })).data;
      assert.equal(o.object_type, "view");
      assert.equal(o.columns.length, 6);
      assert.deepEqual(o.columns.map((c) => c.name), ["order_id", "user_id", "email", "status", "total_cents", "created_at"]);
      assert.match(o.definition, /CREATE VIEW active_user_orders/i);
      assert.match(o.definition, /completed/);
      assert.equal(o.foreign_keys.length, 0);
    });
    if (conn.routinesDefined) {
      await check(`${P}-05`, `[${conn.id}] describe procedure record_order_audit and function calculate_order_discount return their definitions`, async () => {
        const p = (await d({ object_name: "record_order_audit" })).data;
        assert.equal(p.object_type, "procedure");
        assert.match(p.definition, /PROCEDURE record_order_audit/i);
        assert.match(p.definition, /INSERT INTO audit_logs/i);
        const f = (await d({ object_name: "calculate_order_discount" })).data;
        assert.equal(f.object_type, "function");
        assert.match(f.definition, /FUNCTION calculate_order_discount/i);
        assert.match(f.definition, /RETURNS/i);
        const co = (await d({ object_name: "checkout_order" })).data;
        assert.match(co.definition, /CALL reserve_inventory/i);
      });
    } else {
      await check(`${P}-05`, `[${conn.id}] describe record_order_audit is NOT FOUND (connection init_sql defines no routines)`, async () => {
        const r = await d({ object_name: "record_order_audit" });
        assertDenied(r, "phantom routine");
      });
    }
    await check(`${P}-06`, `[${conn.id}] describe detail levels: summary keeps columns drops definition/indexes/fks; names drops columns`, async () => {
      const s = (await d({ object_name: "order_items", detail_level: "summary" })).data;
      assert.equal(s.columns.length, 5);
      assert.equal(s.definition, undefined);
      assert.equal(s.foreign_keys.length, 0);
      assert.equal(s.indexes.length, 0);
      const n = (await d({ object_name: "order_items", detail_level: "names" })).data;
      assert.equal(n.columns.length, 0);
      assert.equal(n.estimated_rows, undefined);
      assert.equal(n.name, "order_items");
    });
    await check(`${P}-07`, `[${conn.id}] name resolution: qualified '${conn.schema}.users', schema arg, and case variant 'USERS' all resolve to the same object`, async () => {
      const a = (await d({ object_name: `${conn.schema}.users` })).data;
      const b = (await d({ object_name: "users", schema: conn.schema })).data;
      const c = (await d({ object_name: "USERS" })).data;
      const e = (await d({ object_name: "Users", schema: conn.schema.toUpperCase() })).data;
      for (const o of [a, b, c, e]) {
        assert.equal(o.name, "users");
        assert.equal(o.schema, conn.schema);
        assert.equal(o.columns.length, 5);
      }
    });
    await check(`${P}-08`, `[${conn.id}] schema arg combined with an already-qualified object_name ('${conn.schema}.users' + schema) still resolves`, async () => {
      const r = await d({ object_name: `${conn.schema}.users`, schema: conn.schema });
      assertSuccessEnvelope(r, "schema+qualified", conn.id);
      assert.equal(r.data.name, "users");
    });
    await check(`${P}-09`, `[${conn.id}] wrong schema / other engine's schema / nonexistent object / LIKE pattern -> denied (not found), never a different object`, async () => {
      const other = CONNECTIONS.find((c) => c.id !== conn.id).schema;
      assertDenied(await d({ object_name: "users", schema: "no_such_schema" }), "wrong schema");
      assertDenied(await d({ object_name: `${other}.users` }), "other schema qualified");
      assertDenied(await d({ object_name: "does_not_exist" }), "nonexistent");
      assertDenied(await d({ object_name: "user%" }), "LIKE pattern is not a name");
      assertDenied(await d({ object_name: "sqlite_sequence" }), "internal sqlite objects hidden");
    });
    await check(`${P}-10`, `[${conn.id}] not-found denial carries a next_action (contract denial envelope requires next_action), e.g. search_objects`, async () => {
      const r = await d({ object_name: "does_not_exist" });
      assertDenied(r, "nonexistent");
      assert.equal(typeof r.next_action, "string", `next_action missing on ${r.code}`);
    });
    if (conn.restricted) {
      await check(`${P}-11`, `[${conn.id}] restricted internal_secrets -> RESTRICTED_TABLE for bare, qualified, upper-case, quoted and schema-arg forms`, async () => {
        for (const args of [
          { object_name: RESTRICTED_TABLE },
          { object_name: `${conn.schema}.${RESTRICTED_TABLE}` },
          { object_name: RESTRICTED_TABLE.toUpperCase() },
          { object_name: `"${RESTRICTED_TABLE}"` },
          { object_name: RESTRICTED_TABLE, schema: conn.schema },
        ]) {
          const r = await d(args);
          assertDenied(r, JSON.stringify(args), "RESTRICTED_TABLE");
          assert.equal(typeof r.next_action, "string");
          assert.ok(!JSON.stringify(r).includes("secret_value"), "denial must not leak column metadata");
        }
      });
    } else {
      await check(`${P}-11`, `[${conn.id}] internal_secrets is NOT restricted on this connection (restricted_tables=[]) -> describable`, async () => {
        const r = await d({ object_name: RESTRICTED_TABLE });
        assertSuccessEnvelope(r, "unrestricted internal_secrets", conn.id);
        assert.deepEqual(r.data.columns.map((c) => c.name), ["id", "secret_key", "secret_value"]);
      });
    }
    await check(`${P}-12`, `[${conn.id}] describe envelope returned_rows == 1 (contract: one described object)`, () => {
      assert.equal(users.returned_rows, 1, `returned_rows=${users.returned_rows}`);
    }, "F02-01"); // KNOWN-BUG: F02-01
    await check(`${P}-13`, `[${conn.id}] missing / blank object_name -> INVALID_ARGUMENT; describe an index object works`, async () => {
      assertDenied(await d({}), "missing object_name", "INVALID_ARGUMENT");
      assertDenied(await d({ object_name: "  " }), "blank object_name", "INVALID_ARGUMENT");
      const idxName = catalogByConn[conn.id].names.data.objects.find((o) => o.object_type === "index").name;
      const ix = (await d({ object_name: idxName })).data;
      assert.equal(ix.object_type, "index");
      assert.equal(ix.indexes[0].table_name, "inventory");
    });
    await check(`${P}-14`, `[${conn.id}] describe output leaks no DSN/password values; sensitive column password_hash appears only as a column name`, async () => {
      const text = JSON.stringify(users);
      for (const re of [/postgres(ql)?:\/\//i, /mysql:\/\//i, /sqlite:\/\//i, /hash_alice/i, /hash_bob/i, /TOPSECRET/i]) assert.ok(!re.test(text), `matched ${re}`);
    });
  }

  // ---------------------------------------------------------------- cross-engine parity
  await check("XE-01", "cross-engine parity: sqlite and postgres (same init_sql) expose identical object name/type sets; mysql = same tables + unrestricted internal_secrets, same view, same routines (defined by its init_sql)", () => {
    const sig = (sc) => sc.data.objects.map((o) => `${o.object_type}:${o.name}`).sort();
    assert.deepEqual(sig(catalogByConn["local-sqlite"].names), sig(catalogByConn["prod-postgres"].names));
    const my = sig(catalogByConn["analytics-mysql"].names);
    const expectedMy = [...BASE_TABLES, RESTRICTED_TABLE].map((t) => `table:${t}`).concat([`view:${VIEW}`]).concat(sig(catalogByConn["local-sqlite"].names).filter((s) => s.startsWith("index:") || s.startsWith("procedure:") || s.startsWith("function:"))).sort();
    assert.deepEqual(my, expectedMy);
  });
  await check("XE-02", "cross-engine parity: describe users / orders FK / view identical in structure across engines", () => {
    const pick = (o) => ({ cols: o.columns.map((c) => [c.name, c.nullable, c.is_primary_key]), fks: o.foreign_keys.map((f) => [f.columns, f.referenced_table, f.referenced_columns, f.on_delete]) });
    const [s, p, m] = CONNECTIONS.map((c) => catalogByConn[c.id].full.data.objects.find((o) => o.name === "orders"));
    assert.deepEqual(pick(s), pick(p));
    assert.deepEqual(pick(s), pick(m));
  });

  // ---------------------------------------------------------------- audit (contract CONTRACT-EXPLORE-SEARCH-OBJECTS expects an audit event)
  await check("AU-01", "explore calls are audited: audit.jsonl contains list_connections/search_objects/describe_object events incl. RESTRICTED_TABLE denial", async () => {
    const auditPath = path.join(isoDir, "audit.jsonl");
    let lines = [];
    for (let i = 0; i < 10; i++) {
      try { lines = fs.readFileSync(auditPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { lines = []; }
      if (lines.some((e) => e.tool_name === "search_objects")) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const tools = new Set(lines.map((e) => e.tool_name));
    assert.ok(tools.has("search_objects"), `no search_objects audit event (tools seen: ${[...tools].join(",") || "none"})`);
    assert.ok(tools.has("describe_object"), "no describe_object audit event");
    assert.ok(lines.some((e) => e.tool_name === "describe_object" && e.decision === "denied"), "RESTRICTED_TABLE denial not audited");
  }, "F02-08"); // KNOWN-BUG: F02-08 dispatch_tool never calls log_audit for the three explore tools (trace_table_dependencies does)
}

function cleanup() {
  for (const c of clients) {
    try { c.child.stdin.end(); } catch { /* ignore */ }
    try { c.child.kill(); } catch { /* ignore */ }
  }
  if (isoDir) {
    setTimeout(() => { try { fs.rmSync(isoDir, { recursive: true, force: true }); } catch { /* ignore */ } }, 300).unref();
  }
}

process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });

main()
  .then(() => {
    const passed = results.filter((r) => r.ok).length;
    const failed = results.filter((r) => !r.ok);
    const known = failed.filter((r) => r.knownBug);
    const unexpected = failed.filter((r) => !r.knownBug);
    console.log(`\n# F02 explore: ${passed}/${results.length} checks passed, ${failed.length} failed (${known.length} known-bug: ${[...new Set(known.map((r) => r.knownBug))].sort().join(", ") || "-"}; ${unexpected.length} unexpected: ${unexpected.map((r) => r.id).join(", ") || "-"})`);
    cleanup();
    setTimeout(() => process.exit(failed.length === 0 ? 0 : 1), 400);
  })
  .catch((err) => {
    console.error("F02 explore test aborted:", err);
    cleanup();
    setTimeout(() => process.exit(2), 400);
  });
