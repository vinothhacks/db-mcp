#!/usr/bin/env node
"use strict";
/**
 * F03 - trace_table_dependencies feature verification.
 *
 * Self-contained: spawns private DB-MCP servers on isolated configs (never the shared example
 * config), runs every check through the stdio MCP transport and prints one line per check.
 *
 *   node npm/test/features/03-table-dependencies.test.js
 *
 * Exit code 0 when every check passes or fails only where marked `// KNOWN-BUG: <id>`.
 * KNOWN-BUG checks still assert the CORRECT behaviour; a failure is printed as XFAIL and an
 * unexpected pass as XPASS (meaning the bug was fixed and the marker can be removed).
 */
const assert = require("node:assert/strict");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));

const TOOL = "trace_table_dependencies";
const CONN = "local-sqlite";
const children = [];
let pass = 0;
let fail = 0;
let xfail = 0;
let xpass = 0;
const failures = [];

process.on("exit", () => {
  for (const ch of children) {
    try { ch.kill(); } catch {}
  }
});

function check(name, fn, knownBug) {
  try {
    fn();
    if (knownBug) {
      xpass++;
      console.log(`XPASS [KNOWN-BUG ${knownBug} appears fixed - remove marker] ${name}`);
    } else {
      pass++;
      console.log(`PASS ${name}`);
    }
  } catch (err) {
    const msg = (err && err.message ? err.message : String(err)).split("\n")[0].slice(0, 300);
    if (knownBug) {
      xfail++;
      console.log(`XFAIL [KNOWN-BUG ${knownBug}] ${name} -- ${msg}`);
    } else {
      fail++;
      failures.push(`${name}: ${msg}`);
      console.log(`FAIL ${name} -- ${msg}`);
    }
  }
}

async function startServer(configPath, principal = "local-agent", role = "agent") {
  const client = createClient({ config: configPath, principal, role, timeoutMs: 60000 });
  children.push(client.child);
  const init = await client.rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "f03-table-dependencies", version: "0.1.0" },
  });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)} stderr=${client.stderr.join("")}`);
  client.notify("notifications/initialized", {});
  const call = async (tool, args) => {
    const started = Date.now();
    const resp = await client.rpc("tools/call", { name: tool, arguments: args });
    const ms = Date.now() - started;
    if (resp.error) return { ms, raw: resp, payload: { status: "rpc_error", error: resp.error } };
    const r = resp.result;
    return { ms, raw: r, payload: r.structuredContent !== undefined ? r.structuredContent : r };
  };
  const trace = async (args) => call(TOOL, { connection: CONN, ...args });
  return { client, call, trace };
}

function stopServer(server) {
  try { server.client.child.stdin.end(); } catch {}
  try { server.client.child.kill(); } catch {}
}

// ---------------------------------------------------------------------------------------------
// Fixture DDL injected into local-sqlite init_sql (CRLF-safe anchors; the example config is CRLF)
// ---------------------------------------------------------------------------------------------
const EXTRA_DDL = [
  "DROP TRIGGER IF EXISTS trg_orders_audit;",
  "CREATE TRIGGER trg_orders_audit AFTER UPDATE ON orders BEGIN INSERT INTO audit_logs(order_id,event_type,created_at) VALUES (NEW.id,'UPDATED',datetime('now')); END;",
  "DROP TABLE IF EXISTS employees;",
  "CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT NOT NULL, manager_id INTEGER REFERENCES employees(id) ON DELETE SET NULL);",
  "DROP TABLE IF EXISTS shipments;",
  "DROP TABLE IF EXISTS regions;",
  "CREATE TABLE regions (country TEXT NOT NULL, code TEXT NOT NULL, PRIMARY KEY (country, code));",
  "CREATE TABLE shipments (id INTEGER PRIMARY KEY, country TEXT NOT NULL, region_code TEXT NOT NULL, CONSTRAINT fk_ship_region FOREIGN KEY (country, region_code) REFERENCES regions(country, code) ON UPDATE CASCADE ON DELETE RESTRICT);",
  "DROP TABLE IF EXISTS cyc_a;",
  "DROP TABLE IF EXISTS cyc_b;",
  "CREATE TABLE cyc_a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES cyc_b(id));",
  "CREATE TABLE cyc_b (id INTEGER PRIMARY KEY, a_id INTEGER REFERENCES cyc_a(id));",
  "DROP TABLE IF EXISTS lonely;",
  "CREATE TABLE lonely (id INTEGER PRIMARY KEY, note TEXT);",
];
const CHAIN_LEN = 50;
for (let i = CHAIN_LEN; i >= 1; i--) EXTRA_DDL.push(`DROP TABLE IF EXISTS chain_${i};`);
for (let i = 1; i <= CHAIN_LEN; i++) {
  EXTRA_DDL.push(
    i === 1
      ? "CREATE TABLE chain_1 (id INTEGER PRIMARY KEY);"
      : `CREATE TABLE chain_${i} (id INTEGER PRIMARY KEY, prev_id INTEGER REFERENCES chain_${i - 1}(id));`
  );
}

function makeMainConfig() {
  const anchor = "CREATE OR REPLACE PROCEDURE record_order_audit";
  return makeIsolatedConfig({
    transform: (text) => {
      const idx = text.indexOf(anchor);
      if (idx < 0) throw new Error("fixture anchor not found in example config");
      return text.slice(0, idx) + EXTRA_DDL.join("\n") + "\n" + text.slice(idx);
    },
  }).configPath;
}

function makeRestrictedFkConfig() {
  const re = /CREATE TABLE internal_secrets \(\r?\n\s*id INTEGER PRIMARY KEY,/;
  return makeIsolatedConfig({
    transform: (text) => {
      if (!re.test(text)) throw new Error("internal_secrets anchor not found in example config");
      return text.replace(
        re,
        "CREATE TABLE internal_secrets (\n    id INTEGER PRIMARY KEY,\n    owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
      );
    },
  }).configPath;
}

const edgeKey = (e) => `${e.from_table}(${e.from_columns.join(",")})->${e.to_table}(${e.to_columns.join(",")})`;
const depKey = (d) => `${d.object_type}:${d.qualified_name}:${d.access_mode}`;
const findDep = (report, name) => report.dependent_objects.find((d) => d.name === name);
const mermaidIds = (diagram) => {
  const ids = new Set();
  for (const line of diagram.split("\n").slice(1)) {
    const m = line.match(/^\s+(\S+)/);
    if (m) ids.add(m[1]);
    const edge = line.match(/^\s+(\S+)\s+(?:-->|-\.->)\|.*\|\s+(\S+)\s*$/);
    if (edge) { ids.add(edge[1]); ids.add(edge[2]); }
  }
  return [...ids].map((id) => id.replace(/[[(].*$/, ""));
};

function assertSuccessEnvelope(payload, label) {
  assert.equal(payload.status, "ok", `${label}: expected status ok, got ${JSON.stringify(payload).slice(0, 300)}`);
  assert.equal(typeof payload.request_id, "string");
  assert.equal(payload.connection, CONN);
  assert.ok(Array.isArray(payload.columns));
  assert.ok(Array.isArray(payload.rows));
  assert.equal(typeof payload.returned_rows, "number");
  assert.equal(typeof payload.truncated, "boolean");
  assert.ok(Array.isArray(payload.warnings));
  assert.equal(payload.schema_version, "snapshot_lineage");
  assert.equal(payload._meta?.provenance?.untrusted_content, true);
}

function assertDenied(payload, code, label) {
  assert.equal(payload.status, "denied", `${label}: expected denied, got ${JSON.stringify(payload).slice(0, 300)}`);
  if (Array.isArray(code)) assert.ok(code.includes(payload.code), `${label}: code ${payload.code} not in ${code}`);
  else assert.equal(payload.code, code, `${label}: code`);
  assert.equal(typeof payload.message, "string");
}

async function main() {
  console.log("[F03] trace_table_dependencies verification");
  const mainCfg = makeMainConfig();
  console.log(`[F03] isolated config: ${mainCfg}`);
  const srv = await startServer(mainCfg);
  const { trace, call } = srv;

  // -------------------------------------------------------------------------------------------
  // 1. Envelope + root FK edges (users)
  // -------------------------------------------------------------------------------------------
  const usersRes = await trace({ table_name: "users", target_table: "order_items", max_depth: 3 });
  const users = usersRes.payload.data;
  check("envelope: status/request_id/columns/rows/returned_rows/truncated/warnings/schema_version/_meta", () =>
    assertSuccessEnvelope(usersRes.payload, "users"));
  check("envelope: execution_time_ms is a number", () => assert.equal(typeof usersRes.payload.execution_time_ms, "number"));
  check("envelope: MCP result carries content[] and isError=false", () => {
    assert.ok(Array.isArray(usersRes.raw.content) && usersRes.raw.content.length >= 1);
    assert.equal(usersRes.raw.isError, false);
  });
  check("envelope: data.connection/table_name/target_table/max_depth echo resolved values", () => {
    assert.equal(users.connection, CONN);
    assert.equal(users.table_name, "main.users");
    assert.equal(users.target_table, "main.order_items");
    assert.equal(users.max_depth, 3);
  });
  check("users: no outbound FKs", () => assert.deepEqual(users.outbound_foreign_keys, []));
  check("users: one inbound FK orders(user_id)->users(id)", () =>
    assert.deepEqual(users.inbound_foreign_keys.map(edgeKey), ["main.orders(user_id)->main.users(id)"]));
  check("users: inbound FK carries constraint_name, relationship_kind, on_delete CASCADE, on_update NO ACTION", () => {
    const fk = users.inbound_foreign_keys[0];
    assert.equal(typeof fk.constraint_name, "string");
    assert.ok(fk.constraint_name.length > 0);
    assert.equal(fk.relationship_kind, "foreign_key");
    assert.equal(fk.on_delete, "CASCADE");
    assert.equal(fk.on_update, "NO ACTION");
  });

  // -------------------------------------------------------------------------------------------
  // 2. FK edges for every fixture table
  // -------------------------------------------------------------------------------------------
  const orders = (await trace({ table_name: "orders" })).payload.data;
  const orderItems = (await trace({ table_name: "order_items" })).payload.data;
  const inventory = (await trace({ table_name: "inventory" })).payload.data;
  const auditLogs = (await trace({ table_name: "audit_logs" })).payload.data;

  check("orders: outbound FK -> users with ON DELETE CASCADE", () => {
    assert.deepEqual(orders.outbound_foreign_keys.map(edgeKey), ["main.orders(user_id)->main.users(id)"]);
    assert.equal(orders.outbound_foreign_keys[0].on_delete, "CASCADE");
  });
  check("orders: inbound FKs from audit_logs and order_items (sorted)", () =>
    assert.deepEqual(orders.inbound_foreign_keys.map(edgeKey), [
      "main.audit_logs(order_id)->main.orders(id)",
      "main.order_items(order_id)->main.orders(id)",
    ]));
  check("order_items: outbound FKs -> orders (CASCADE) and inventory(sku) (NO ACTION); no inbound", () => {
    const byTarget = Object.fromEntries(orderItems.outbound_foreign_keys.map((e) => [e.to_table, e]));
    assert.deepEqual(Object.keys(byTarget).sort(), ["main.inventory", "main.orders"]);
    assert.deepEqual(byTarget["main.orders"].from_columns, ["order_id"]);
    assert.equal(byTarget["main.orders"].on_delete, "CASCADE");
    assert.deepEqual(byTarget["main.inventory"].from_columns, ["sku"]);
    assert.deepEqual(byTarget["main.inventory"].to_columns, ["sku"]);
    assert.equal(byTarget["main.inventory"].on_delete, "NO ACTION");
    assert.deepEqual(orderItems.inbound_foreign_keys, []);
  });
  check("inventory: inbound FK from order_items(sku); no outbound", () => {
    assert.deepEqual(inventory.inbound_foreign_keys.map(edgeKey), ["main.order_items(sku)->main.inventory(sku)"]);
    assert.deepEqual(inventory.outbound_foreign_keys, []);
  });
  check("audit_logs: outbound FK -> orders CASCADE; no inbound", () => {
    assert.deepEqual(auditLogs.outbound_foreign_keys.map(edgeKey), ["main.audit_logs(order_id)->main.orders(id)"]);
    assert.equal(auditLogs.outbound_foreign_keys[0].on_delete, "CASCADE");
    assert.deepEqual(auditLogs.inbound_foreign_keys, []);
  });
  check("constraint names are distinct per edge on orders", () => {
    const names = [...orders.outbound_foreign_keys, ...orders.inbound_foreign_keys].map((e) => e.constraint_name);
    assert.equal(new Set(names).size, names.length);
  });

  // -------------------------------------------------------------------------------------------
  // 3. Dependent objects (views, functions, procedures, triggers) and access_mode
  // -------------------------------------------------------------------------------------------
  check("users: view active_user_orders is a read dependent", () =>
    assert.equal(depKey(findDep(users, "active_user_orders")), "view:main.active_user_orders:read"));
  check("users: function calculate_order_discount is a read dependent", () =>
    assert.equal(depKey(findDep(users, "calculate_order_discount")), "function:main.calculate_order_discount:read"));
  // KNOWN-BUG: F03-1  checkout_order only READS users (subquery inside UPDATE orders ... WHERE user_id IN (SELECT ... FROM users)).
  // lineage.rs inspect_statement_for_table marks every referenced table of an UPDATE/INSERT/DELETE as written.
  check("users: procedure checkout_order access_mode is read (it only reads users)", () =>
    assert.equal(findDep(users, "checkout_order")?.access_mode, "read"), "F03-1");
  check("users: dependent_objects contain no false positives", () =>
    assert.deepEqual(users.dependent_objects.map((d) => d.name).sort(), ["active_user_orders", "calculate_order_discount", "checkout_order"]));
  check("users: matched_reference and schema/name/qualified_name are consistent", () => {
    for (const d of users.dependent_objects) {
      assert.equal(d.matched_reference, "users");
      assert.equal(d.schema, "main");
      assert.equal(d.qualified_name, `${d.schema}.${d.name}`);
    }
  });
  check("orders: checkout_order read_write, record_order_audit read, calculate_order_discount read, view read", () => {
    assert.equal(findDep(orders, "checkout_order")?.access_mode, "read_write");
    assert.equal(findDep(orders, "record_order_audit")?.access_mode, "read");
    assert.equal(findDep(orders, "calculate_order_discount")?.access_mode, "read");
    assert.equal(findDep(orders, "active_user_orders")?.access_mode, "read");
  });
  check("orders: trigger trg_orders_audit (AFTER UPDATE ON orders) discovered as dependent", () => {
    const t = findDep(orders, "trg_orders_audit");
    assert.ok(t, "trigger missing");
    assert.equal(t.object_type, "trigger");
    assert.equal(t.access_mode, "read");
  });
  check("audit_logs: record_order_audit writes, trigger trg_orders_audit writes", () => {
    assert.equal(depKey(findDep(auditLogs, "record_order_audit")), "procedure:main.record_order_audit:write");
    assert.equal(depKey(findDep(auditLogs, "trg_orders_audit")), "trigger:main.trg_orders_audit:write");
  });
  check("inventory: reserve_inventory writes inventory", () =>
    assert.deepEqual(inventory.dependent_objects.map(depKey), ["procedure:main.reserve_inventory:write"]));
  check("order_items: reserve_inventory reads order_items", () =>
    assert.deepEqual(orderItems.dependent_objects.map(depKey), ["procedure:main.reserve_inventory:read"]));
  check("dependent_objects sorted by qualified_name", () => {
    const names = orders.dependent_objects.map((d) => d.qualified_name);
    assert.deepEqual(names, [...names].sort());
  });

  // -------------------------------------------------------------------------------------------
  // 4. Transitive radius / max_depth handling
  // -------------------------------------------------------------------------------------------
  const d1 = (await trace({ table_name: "users", max_depth: 1 })).payload.data;
  const d2 = (await trace({ table_name: "users", max_depth: 2 })).payload.data;
  const d3 = (await trace({ table_name: "users", max_depth: 3 })).payload.data;
  const d10 = (await trace({ table_name: "users", max_depth: 10 })).payload.data;
  const d0 = (await trace({ table_name: "users", max_depth: 0 })).payload.data;
  const dOmit = (await trace({ table_name: "users" })).payload.data;
  const dNeg = await trace({ table_name: "users", max_depth: -1 });
  const dStr = await trace({ table_name: "users", max_depth: "2" });

  check("max_depth=1: transitive_tables = [orders]", () => {
    assert.equal(d1.max_depth, 1);
    assert.deepEqual(d1.transitive_tables, ["main.orders"]);
  });
  check("max_depth=2: transitive_tables = [audit_logs, order_items, orders]", () =>
    assert.deepEqual(d2.transitive_tables, ["main.audit_logs", "main.order_items", "main.orders"]));
  check("max_depth=3: transitive_tables adds inventory (3 hops)", () =>
    assert.deepEqual(d3.transitive_tables, ["main.audit_logs", "main.inventory", "main.order_items", "main.orders"]));
  check("max_depth=10: same closure as depth 3 (graph exhausted), max_depth echoed", () => {
    assert.deepEqual(d10.transitive_tables, d3.transitive_tables);
    assert.equal(d10.max_depth, 10);
  });
  check("max_depth omitted: defaults to 3", () => {
    assert.equal(dOmit.max_depth, 3);
    assert.deepEqual(dOmit.transitive_tables, d3.transitive_tables);
  });
  check("max_depth=0: falls back to default depth 3 and reports it", () => {
    assert.equal(d0.max_depth, 3);
    assert.deepEqual(d0.transitive_tables, d3.transitive_tables);
  });
  check("max_depth=-1 is rejected with INVALID_ARGUMENT", () => assertDenied(dNeg.payload, "INVALID_ARGUMENT", "neg"));
  check("max_depth=\"2\" (string) is rejected with INVALID_ARGUMENT", () => assertDenied(dStr.payload, "INVALID_ARGUMENT", "str"));
  check("transitive_tables never contains the root table and is sorted/unique", () => {
    for (const r of [d1, d2, d3, d10, orders, orderItems]) {
      assert.ok(!r.transitive_tables.includes(r.table_name));
      assert.deepEqual(r.transitive_tables, [...new Set(r.transitive_tables)].sort());
    }
  });

  // -------------------------------------------------------------------------------------------
  // 5. Join paths + synthesized SQL executes
  // -------------------------------------------------------------------------------------------
  check("join users->order_items: 2 hops via orders, hop fields populated", () => {
    const jp = users.join_path;
    assert.equal(jp.source_table, "main.users");
    assert.equal(jp.target_table, "main.order_items");
    assert.equal(jp.hops.length, 2);
    assert.deepEqual(jp.hops.map((h) => [h.from_table, h.to_table]), [["main.users", "main.orders"], ["main.orders", "main.order_items"]]);
    for (const h of jp.hops) {
      assert.equal(typeof h.join_condition, "string");
      assert.equal(typeof h.constraint_name, "string");
    }
    assert.equal(jp.hops[0].join_condition, "main.users.id = main.orders.user_id");
  });
  check("join users->order_items: synthesized SQL is the expected JOIN chain", () =>
    assert.equal(users.join_path.synthesized_join_sql,
      "SELECT * FROM main.users JOIN main.orders ON main.users.id = main.orders.user_id JOIN main.order_items ON main.orders.id = main.order_items.order_id"));
  const uInv = (await trace({ table_name: "users", target_table: "inventory" })).payload.data;
  check("join users->inventory: 3 hops ending at inventory", () => {
    assert.equal(uInv.join_path.hops.length, 3);
    assert.equal(uInv.join_path.hops[2].to_table, "main.inventory");
    assert.equal(uInv.join_path.hops[2].join_condition, "main.order_items.sku = main.inventory.sku");
  });
  const oiUsers = (await trace({ table_name: "order_items", target_table: "users" })).payload.data;
  check("join order_items->users: reverse traversal allowed (2 hops, FK direction reversed in ON clause)", () => {
    assert.equal(oiUsers.join_path.hops.length, 2);
    assert.equal(oiUsers.join_path.hops[0].join_condition, "main.order_items.order_id = main.orders.id");
    assert.equal(oiUsers.join_path.hops[1].to_table, "main.users");
  });
  const same = (await trace({ table_name: "users", target_table: "users" })).payload.data;
  check("join users->users: zero hops, SELECT * FROM main.users", () => {
    assert.deepEqual(same.join_path.hops, []);
    assert.equal(same.join_path.synthesized_join_sql, "SELECT * FROM main.users");
  });
  const lonely = (await trace({ table_name: "lonely", target_table: "users" })).payload.data;
  check("join lonely->users: unreachable pair yields join_path=null (no FK edges)", () => {
    assert.equal(lonely.join_path, null);
    assert.deepEqual(lonely.outbound_foreign_keys, []);
    assert.deepEqual(lonely.inbound_foreign_keys, []);
    assert.deepEqual(lonely.transitive_tables, []);
    assert.deepEqual(lonely.dependent_objects, []);
  });
  const d1Join = (await trace({ table_name: "users", target_table: "inventory", max_depth: 1 })).payload.data;
  check("join users->inventory with max_depth=1: path longer than max_depth is not returned", () =>
    assert.equal(d1Join.join_path, null));

  for (const [label, sql] of [
    ["users->inventory", uInv.join_path.synthesized_join_sql],
    ["order_items->users", oiUsers.join_path.synthesized_join_sql],
    ["users->users", same.join_path.synthesized_join_sql],
  ]) {
    const ex = await call("execute_query", { connection: CONN, sql, max_rows: 10 });
    check(`synthesized SQL executes on sqlite (${label}) and returns 2 rows`, () => {
      assert.equal(ex.payload.status, "ok", JSON.stringify(ex.payload).slice(0, 300));
      assert.equal(ex.payload.returned_rows, 2);
    });
  }

  // -------------------------------------------------------------------------------------------
  // 6. Name resolution and denials
  // -------------------------------------------------------------------------------------------
  const qualified = (await trace({ table_name: "main.users", target_table: "main.order_items" })).payload.data;
  check("qualified names main.users / main.order_items resolve identically", () => assert.deepEqual(qualified, users));
  const upper = (await trace({ table_name: "USERS", target_table: "Order_Items" })).payload.data;
  check("case-insensitive resolution (USERS / Order_Items)", () => assert.deepEqual(upper, users));
  const quoted = (await trace({ table_name: "\"users\"" })).payload.data;
  check("quoted identifier \"users\" resolves", () => assert.equal(quoted.table_name, "main.users"));
  const unknownSrc = await trace({ table_name: "no_such_table" });
  check("unknown source table -> denied with not-found message", () => {
    assertDenied(unknownSrc.payload, ["INVALID_ARGUMENT", "OBJECT_NOT_FOUND"], "unknown src");
    assert.match(unknownSrc.payload.message, /no_such_table.*not found/i);
  });
  const unknownTarget = await trace({ table_name: "users", target_table: "no_such_table" });
  check("unknown target table -> denied with not-found message", () => {
    assertDenied(unknownTarget.payload, ["INVALID_ARGUMENT", "OBJECT_NOT_FOUND"], "unknown target");
    assert.match(unknownTarget.payload.message, /no_such_table.*not found/i);
  });
  const viewSrc = await trace({ table_name: "active_user_orders" });
  check("view as table_name -> denied (only tables are traceable)", () =>
    assertDenied(viewSrc.payload, ["INVALID_ARGUMENT", "OBJECT_NOT_FOUND"], "view src"));
  for (const name of ["internal_secrets", "main.internal_secrets", "MAIN.Internal_Secrets", "\"internal_secrets\""]) {
    const r = await trace({ table_name: name });
    check(`restricted source '${name}' -> RESTRICTED_TABLE`, () => assertDenied(r.payload, "RESTRICTED_TABLE", name));
  }
  const restrictedTarget = await trace({ table_name: "users", target_table: "internal_secrets" });
  check("restricted target internal_secrets -> RESTRICTED_TABLE", () => assertDenied(restrictedTarget.payload, "RESTRICTED_TABLE", "target"));
  const emptyName = await trace({ table_name: "   " });
  check("blank table_name -> INVALID_ARGUMENT", () => assertDenied(emptyName.payload, "INVALID_ARGUMENT", "blank"));
  const missingConn = await call(TOOL, { table_name: "users" });
  check("missing connection -> INVALID_ARGUMENT", () => assertDenied(missingConn.payload, "INVALID_ARGUMENT", "missing conn"));
  const badConn = await call(TOOL, { connection: "nope", table_name: "users" });
  check("unknown connection -> CONNECTION_NOT_FOUND", () => assertDenied(badConn.payload, "CONNECTION_NOT_FOUND", "bad conn"));

  // -------------------------------------------------------------------------------------------
  // 7. Edge cases: self-reference, composite FK, cycle, long chain
  // -------------------------------------------------------------------------------------------
  const emp = (await trace({ table_name: "employees", target_table: "employees" })).payload.data;
  check("self-referencing FK employees.manager_id -> employees.id appears outbound and inbound with ON DELETE SET NULL", () => {
    assert.deepEqual(emp.outbound_foreign_keys.map(edgeKey), ["main.employees(manager_id)->main.employees(id)"]);
    assert.deepEqual(emp.inbound_foreign_keys.map(edgeKey), ["main.employees(manager_id)->main.employees(id)"]);
    assert.equal(emp.outbound_foreign_keys[0].on_delete, "SET NULL");
    assert.deepEqual(emp.transitive_tables, []);
  });
  check("self-referencing FK renders a single self-loop in mermaid", () => {
    assert.match(emp.mermaid_diagram, /tbl_main_employees -->\|"FK \(manager_id\)"\| tbl_main_employees/);
    assert.equal((emp.mermaid_diagram.match(/-->/g) || []).length, 1);
  });
  const ship = (await trace({ table_name: "shipments", target_table: "regions" })).payload.data;
  check("composite FK keeps column order, ON UPDATE CASCADE / ON DELETE RESTRICT", () => {
    const fk = ship.outbound_foreign_keys[0];
    assert.deepEqual(fk.from_columns, ["country", "region_code"]);
    assert.deepEqual(fk.to_columns, ["country", "code"]);
    assert.equal(fk.on_update, "CASCADE");
    assert.equal(fk.on_delete, "RESTRICT");
  });
  check("composite FK join condition ANDs every column pair", () =>
    assert.equal(ship.join_path.hops[0].join_condition,
      "main.shipments.country = main.regions.country AND main.shipments.region_code = main.regions.code"));
  const shipExec = await call("execute_query", { connection: CONN, sql: ship.join_path.synthesized_join_sql, max_rows: 5 });
  check("composite-FK synthesized SQL executes", () => assert.equal(shipExec.payload.status, "ok", JSON.stringify(shipExec.payload).slice(0, 200)));
  const cyc = await trace({ table_name: "cyc_a", target_table: "cyc_b", max_depth: 10 });
  check("FK cycle cyc_a<->cyc_b terminates (status ok, 1-hop path, transitive [cyc_b])", () => {
    assert.equal(cyc.payload.status, "ok");
    assert.equal(cyc.payload.data.join_path.hops.length, 1);
    assert.deepEqual(cyc.payload.data.transitive_tables, ["main.cyc_b"]);
    assert.ok(cyc.ms < 5000, `took ${cyc.ms} ms`);
  });
  const chain3 = (await trace({ table_name: "chain_1", max_depth: 3 })).payload.data;
  check("50-table chain, depth 3 from chain_1: exactly chain_2..chain_4", () =>
    assert.deepEqual(chain3.transitive_tables, ["main.chain_2", "main.chain_3", "main.chain_4"]));
  const chainMid = (await trace({ table_name: "chain_25", max_depth: 2 })).payload.data;
  check("50-table chain, depth 2 from chain_25: two tables each direction", () =>
    assert.deepEqual(chainMid.transitive_tables, ["main.chain_23", "main.chain_24", "main.chain_26", "main.chain_27"]));
  const chainFull = await trace({ table_name: "chain_1", target_table: "chain_50", max_depth: 50 });
  check("50-table chain, depth 50: 49 transitive tables and a 49-hop join path", () => {
    assert.equal(chainFull.payload.data.transitive_tables.length, 49);
    assert.equal(chainFull.payload.data.join_path.hops.length, 49);
    assert.ok(chainFull.ms < 5000, `took ${chainFull.ms} ms`);
  });
  const chainExec = await call("execute_query", { connection: CONN, sql: chainFull.payload.data.join_path.synthesized_join_sql, max_rows: 1 });
  check("49-hop synthesized SQL executes", () => assert.equal(chainExec.payload.status, "ok", JSON.stringify(chainExec.payload).slice(0, 200)));
  const chainShort = (await trace({ table_name: "chain_1", target_table: "chain_50", max_depth: 3 })).payload.data;
  check("50-table chain, depth 3 with far target: join_path null", () => assert.equal(chainShort.join_path, null));

  // -------------------------------------------------------------------------------------------
  // 8. Mermaid diagram
  // -------------------------------------------------------------------------------------------
  check("mermaid starts with 'flowchart LR'", () => assert.ok(orders.mermaid_diagram.startsWith("flowchart LR\n")));
  check("mermaid node ids contain no spaces or dots", () => {
    const ids = mermaidIds(orders.mermaid_diagram);
    assert.ok(ids.length >= 5, `too few ids: ${ids}`);
    for (const id of ids) assert.match(id, /^[A-Za-z0-9_]+$/, `bad id ${id}`);
  });
  check("mermaid declares the root, FK neighbours, labelled FK edges and dependent nodes", () => {
    const m = orders.mermaid_diagram;
    assert.ok(m.includes('tbl_main_orders["main.orders"]'));
    assert.ok(m.includes('tbl_main_orders -->|"FK (user_id)"| tbl_main_users'));
    assert.ok(m.includes('tbl_main_order_items -->|"FK (order_id)"| tbl_main_orders'));
    assert.ok(m.includes('view_main_active_user_orders -->|"read"| tbl_main_orders'));
    assert.ok(m.includes('trigger_main_trg_orders_audit(["main.trg_orders_audit (trigger)"])'));
  });
  check("mermaid join path drawn as dotted JOIN edges", () => {
    assert.ok(users.mermaid_diagram.includes('tbl_main_users -.->|"JOIN"| tbl_main_orders'));
    assert.ok(users.mermaid_diagram.includes('tbl_main_orders -.->|"JOIN"| tbl_main_order_items'));
  });
  check("mermaid has no duplicate node declarations", () => {
    const decls = orders.mermaid_diagram.split("\n").filter((l) => /^\s+\S+(\[|\(\[)"/.test(l)).map((l) => l.trim().split(/[[(]/)[0]);
    assert.equal(new Set(decls).size, decls.length);
  });
  const det1 = (await trace({ table_name: "orders", target_table: "inventory", max_depth: 3 })).payload.data;
  const det2 = (await trace({ table_name: "orders", target_table: "inventory", max_depth: 3 })).payload.data;
  check("two identical calls produce identical reports and mermaid", () => assert.deepEqual(det1, det2));

  // -------------------------------------------------------------------------------------------
  // 9. Other engines (simulated prod-postgres / analytics-mysql)
  // -------------------------------------------------------------------------------------------
  const pg = await call(TOOL, { connection: "prod-postgres", table_name: "users", target_table: "order_items" });
  check("prod-postgres: schema public, inbound orders_user_id_fkey, join 2 hops, deps include procedures", () => {
    assert.equal(pg.payload.status, "ok", JSON.stringify(pg.payload).slice(0, 300));
    const d = pg.payload.data;
    assert.equal(d.table_name, "public.users");
    assert.deepEqual(d.inbound_foreign_keys.map(edgeKey), ["public.orders(user_id)->public.users(id)"]);
    assert.equal(d.inbound_foreign_keys[0].constraint_name, "orders_user_id_fkey");
    assert.equal(d.inbound_foreign_keys[0].on_delete, "CASCADE");
    assert.equal(d.join_path.hops.length, 2);
    assert.ok(d.dependent_objects.some((o) => o.object_type === "procedure"));
    assert.ok(d.dependent_objects.some((o) => o.object_type === "view" && o.name === "active_user_orders"));
  });
  const pgExec = await call("execute_query", { connection: "prod-postgres", sql: pg.payload.data.join_path.synthesized_join_sql, max_rows: 5 });
  check("prod-postgres: synthesized SQL executes", () => {
    assert.equal(pgExec.payload.status, "ok", JSON.stringify(pgExec.payload).slice(0, 300));
    assert.equal(pgExec.payload.returned_rows, 2);
  });
  const pgOrders = await call(TOOL, { connection: "prod-postgres", table_name: "orders" });
  check("prod-postgres: orders inbound from audit_logs + order_items, record_order_audit reads orders", () => {
    const d = pgOrders.payload.data;
    assert.deepEqual(d.inbound_foreign_keys.map(edgeKey), ["public.audit_logs(order_id)->public.orders(id)", "public.order_items(order_id)->public.orders(id)"]);
    assert.equal(findDep(d, "record_order_audit")?.access_mode, "read");
  });
  const my = await call(TOOL, { connection: "analytics-mysql", table_name: "users", target_table: "inventory" });
  check("analytics-mysql: schema analytics, inbound FK with constraint name, 3-hop join path", () => {
    assert.equal(my.payload.status, "ok", JSON.stringify(my.payload).slice(0, 300));
    const d = my.payload.data;
    assert.equal(d.table_name, "analytics.users");
    assert.deepEqual(d.inbound_foreign_keys.map(edgeKey), ["analytics.orders(user_id)->analytics.users(id)"]);
    assert.equal(typeof d.inbound_foreign_keys[0].constraint_name, "string");
    assert.equal(d.join_path.hops.length, 3);
    assert.deepEqual(d.transitive_tables, ["analytics.audit_logs", "analytics.inventory", "analytics.order_items", "analytics.orders"]);
  });
  const myExec = await call("execute_query", { connection: "analytics-mysql", sql: my.payload.data.join_path.synthesized_join_sql, max_rows: 5 });
  check("analytics-mysql: synthesized SQL executes", () => {
    assert.equal(myExec.payload.status, "ok", JSON.stringify(myExec.payload).slice(0, 300));
    assert.equal(myExec.payload.returned_rows, 2);
  });
  const myQual = await call(TOOL, { connection: "analytics-mysql", table_name: "analytics.orders" });
  check("analytics-mysql: schema-qualified analytics.orders resolves", () => assert.equal(myQual.payload.data.table_name, "analytics.orders"));

  // -------------------------------------------------------------------------------------------
  // 10. Performance sanity (in-process, same server)
  // -------------------------------------------------------------------------------------------
  const traceMs = [];
  const describeMs = [];
  for (let i = 0; i < 5; i++) {
    traceMs.push((await trace({ table_name: "users", target_table: "order_items", max_depth: 3 })).payload.execution_time_ms);
    describeMs.push((await call("describe_object", { connection: CONN, object_name: "users" })).ms);
  }
  const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
  console.log(`[F03] perf: trace execution_time_ms=${JSON.stringify(traceMs)} (median ${med(traceMs)} ms); describe_object wall=${JSON.stringify(describeMs)} (median ${med(describeMs)} ms); catalog has ${CHAIN_LEN + 11} tables`);
  check("perf: median in-process trace execution_time_ms < 1000 ms on a 61-table catalog", () => assert.ok(med(traceMs) < 1000, `median ${med(traceMs)} ms`));

  stopServer(srv);

  // -------------------------------------------------------------------------------------------
  // 11. Restricted tables must not leak through FK edges (separate fixture: internal_secrets -> users FK)
  // -------------------------------------------------------------------------------------------
  const leakCfg = makeRestrictedFkConfig();
  const srv2 = await startServer(leakCfg);
  const leakUsers = (await srv2.trace({ table_name: "users" })).payload.data;
  const leakOrders = (await srv2.trace({ table_name: "orders", max_depth: 2 })).payload.data;
  const leakSearch = await srv2.call("search_objects", { connection: CONN, name_pattern: "internal" });
  check("baseline: search_objects hides restricted internal_secrets", () =>
    assert.deepEqual((leakSearch.payload.data.objects || []).map((o) => o.name), []));
  // (F03-2 fixed) restricted tables are only checked for table_name/target_table; FK edges, transitive_tables and the
  // mermaid diagram still expose restricted tables (name + FK columns). search_objects/describe_object filter them.
  check("restricted internal_secrets is not exposed in users.inbound_foreign_keys", () =>
    assert.ok(!leakUsers.inbound_foreign_keys.some((e) => /internal_secrets/i.test(e.from_table))));
  check("restricted internal_secrets is not exposed in transitive_tables (users depth 3, orders depth 2)", () => {
    assert.ok(!leakUsers.transitive_tables.some((t) => /internal_secrets/i.test(t)));
    assert.ok(!leakOrders.transitive_tables.some((t) => /internal_secrets/i.test(t)));
  });
  check("restricted internal_secrets is not exposed in the mermaid diagram", () =>
    assert.ok(!/internal_secrets/i.test(leakUsers.mermaid_diagram)));
  stopServer(srv2);

  // -------------------------------------------------------------------------------------------
  // 12. Role authorisation
  // -------------------------------------------------------------------------------------------
  const guest = await startServer(mainCfg, "stranger", "guest");
  const guestPg = await guest.call(TOOL, { connection: "prod-postgres", table_name: "users" });
  check("guest role is denied on prod-postgres (UNAUTHORIZED_ROLE)", () => assertDenied(guestPg.payload, "UNAUTHORIZED_ROLE", "guest"));
  const guestLocal = await guest.call(TOOL, { connection: CONN, table_name: "users" });
  check("guest role allowed on local-sqlite (allowed_roles = *)", () => assert.equal(guestLocal.payload.status, "ok"));
  stopServer(guest);

  console.log(`\n[F03] ${pass} passed, ${fail} failed, ${xfail} known-bug failures (XFAIL), ${xpass} unexpected passes (XPASS)`);
  if (failures.length) {
    console.log("[F03] unexpected failures:");
    for (const f of failures) console.log(`  - ${f}`);
  }
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(`[F03] fatal: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
