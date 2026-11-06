#!/usr/bin/env node
"use strict";
/**
 * F04 - get_procedure_call_graph feature verification.
 *
 * Self-contained: spawns the prebuilt db-mcp-server over stdio with private isolated configs
 * (never serves config/db-mcp.example.toml directly), uses only node:assert, prints one line per
 * check and exits 0 only when every check passes. Checks that encode correct behaviour the current
 * build does not yet satisfy are tagged `// KNOWN-BUG: <id>` (they still fail; they are not weakened).
 *
 *   node npm/test/features/04-procedure-call-graph.test.js
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
process.chdir(REPO_ROOT);
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));

const TOOL = "get_procedure_call_graph";
const CALL_TIMEOUT_MS = 30_000;
const INIT_TIMEOUT_MS = 20_000;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------
const results = [];
const liveClients = new Set();
const tempDirs = [];
let checkNo = 0;

function cleanupAll() {
  for (const c of liveClients) {
    try { c.child.kill(); } catch { /* ignore */ }
  }
  liveClients.clear();
  for (const d of tempDirs) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort; sqlite files may be locked briefly */ }
  }
}
process.on("exit", cleanupAll);
process.on("SIGINT", () => { cleanupAll(); process.exit(130); });

async function check(name, fn, knownBug) {
  const id = String(++checkNo).padStart(2, "0");
  try {
    await fn();
    results.push({ id, name, ok: true, knownBug });
    console.log(`ok   ${id} ${name}${knownBug ? `  (was KNOWN-BUG ${knownBug}; now passing - remove tag)` : ""}`);
  } catch (err) {
    results.push({ id, name, ok: false, knownBug, err });
    const msg = (err && err.message ? err.message : String(err)).split("\n").slice(0, 3).join(" | ");
    console.log(`FAIL ${id} ${name}${knownBug ? `  [KNOWN-BUG ${knownBug}]` : ""}: ${msg}`);
  }
}

function makeConfig(transform) {
  const { configPath, dir } = makeIsolatedConfig(transform ? { transform } : {});
  tempDirs.push(dir);
  return configPath;
}

/** Append `extraSql` to the init_sql block(s) selected by `blockIdx` (0 sqlite, 1 postgres, 2 mysql). */
function appendToInitSql(extraSql, blockIdx = [0, 1, 2], mode = "append") {
  const want = new Set(blockIdx);
  return (text) => {
    let i = -1;
    const out = text.replace(/init_sql = """([\s\S]*?)"""/g, (m, body) => {
      i++;
      if (!want.has(i)) return m;
      return mode === "prepend"
        ? `init_sql = """\n${extraSql}\n${body}"""`
        : `init_sql = """${body}\n${extraSql}\n"""`;
    });
    assert.equal(i, 2, "expected three init_sql blocks in the example config");
    return out;
  };
}

async function openClient(configPath) {
  const client = createClient({ config: configPath, principal: "local-agent", role: "agent", timeoutMs: CALL_TIMEOUT_MS });
  liveClients.add(client);
  const exited = new Promise((_, reject) => {
    client.child.once("exit", (code) => reject(new Error(`server exited early (code ${code}); stderr=${client.stderr.join("").slice(0, 600)}`)));
  });
  const initTimer = new Promise((_, reject) => setTimeout(() => reject(new Error(`initialize timed out after ${INIT_TIMEOUT_MS} ms; stderr=${client.stderr.join("").slice(0, 600)}`)), INIT_TIMEOUT_MS).unref());
  try {
    const init = await Promise.race([
      client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f04-test", version: "0.1.0" } }),
      exited,
      initTimer,
    ]);
    if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
    client.notify("notifications/initialized", {});
  } catch (err) {
    closeClient(client);
    throw err;
  }
  return client;
}

function closeClient(client) {
  if (!liveClients.has(client)) return;
  liveClients.delete(client);
  try { client.close(); } catch { /* ignore */ }
}

/** Call the tool; returns { envelope, data, isError, ms }. JSON-RPC level errors throw. */
async function callGraph(client, args) {
  const t0 = Date.now();
  const resp = await client.rpc("tools/call", { name: TOOL, arguments: args });
  const ms = Date.now() - t0;
  if (resp.error) throw new Error(`JSON-RPC error: ${JSON.stringify(resp.error)}`);
  const r = resp.result;
  const envelope = r.structuredContent !== undefined ? r.structuredContent : JSON.parse(r.content[0].text);
  return { envelope, data: envelope.data || null, isError: !!r.isError, ms };
}

const byName = (nodes, base) => nodes.find((n) => n.name === base || n.qualified_name === base);
const edgeKey = (e) => `${e.caller}>${e.callee}:${e.call_kind}@${e.depth}`;
const baseName = (q) => q.split(".").pop();
const sortedUnique = (xs) => [...new Set(xs)].sort();

// ---------------------------------------------------------------------------------------------
// Fixtures injected through init_sql transforms
// ---------------------------------------------------------------------------------------------
const CYCLE_AND_ROBUSTNESS_SQL = `
CREATE OR REPLACE PROCEDURE proc_a(x INTEGER)
BEGIN
    CALL proc_b(x);
END;
CREATE OR REPLACE PROCEDURE proc_b(x INTEGER)
BEGIN
    CALL proc_a(x);
END;
CREATE OR REPLACE PROCEDURE proc_self(x INTEGER)
BEGIN
    CALL proc_self(x);
END;
CREATE OR REPLACE PROCEDURE exec_target(x INTEGER)
BEGIN
    SELECT 1;
END;
CREATE OR REPLACE PROCEDURE execute_target(x INTEGER)
BEGIN
    SELECT 1;
END;
CREATE OR REPLACE PROCEDURE robust_comments(x INTEGER)
BEGIN
    -- CALL fake_proc_line(x);
    /* CALL fake_proc_block(x); */
    INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (x, 'CALL fake_proc_str()', 'now');
END;
CREATE OR REPLACE PROCEDURE robust_exec(x INTEGER)
BEGIN
    EXEC exec_target(x);
    EXECUTE execute_target(x);
END;
CREATE OR REPLACE PROCEDURE robust_qualified(x INTEGER)
BEGIN
    CALL public.record_order_audit(x, 'Q');
END;
CREATE OR REPLACE PROCEDURE robust_fnexpr(x INTEGER)
BEGIN
    SELECT calculate_order_discount(1);
END;
CREATE OR REPLACE PROCEDURE robust_unknown(x INTEGER)
BEGIN
    CALL totally_unknown_proc(x);
END;
CREATE OR REPLACE PROCEDURE robust_dynamic(x INTEGER)
BEGIN
    EXECUTE 'select id from users where id = 1';
END;
`;

const DOLLAR_FN_SQL = `CREATE FUNCTION dollar_fn() RETURNS void AS $$ BEGIN PERFORM record_order_audit(1, 'x'); END $$ LANGUAGE plpgsql;`;

const DELIMITER_SQL = `
DELIMITER //
CREATE PROCEDURE delim_proc(IN x INT)
BEGIN
    CALL record_order_audit(x, 'D');
END //
DELIMITER ;
`;

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------
async function main() {
  console.log(`# F04 get_procedure_call_graph verification (binary: target/release/db-mcp-server.exe)`);

  // ======================= Section A: baseline fixtures =======================
  const cfgA = makeConfig();
  const a = await openClient(cfgA);
  const PG = "prod-postgres";
  const Q = {
    checkout: "public.checkout_order",
    calc: "public.calculate_order_discount",
    reserve: "public.reserve_inventory",
    record: "public.record_order_audit",
  };

  const callees = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: 5 });

  await check("callees(checkout_order): ok envelope, root resolved to public.checkout_order, direction callees", () => {
    assert.equal(callees.isError, false);
    assert.equal(callees.envelope.status, "ok");
    assert.equal(callees.data.root_procedure, Q.checkout);
    assert.equal(callees.data.direction, "callees");
    assert.equal(callees.data.max_depth, 5);
  });

  await check("callees(checkout_order): node set is exactly the 4 reachable routines", () => {
    assert.deepEqual(sortedUnique(callees.data.nodes.map((n) => n.qualified_name)), [Q.calc, Q.checkout, Q.record, Q.reserve]);
  });

  await check("callees(checkout_order): edges carry correct call_kind (PERFORM vs CALL) and depth", () => {
    assert.deepEqual(sortedUnique(callees.data.edges.map(edgeKey)), sortedUnique([
      `${Q.checkout}>${Q.calc}:PERFORM@1`,
      `${Q.checkout}>${Q.record}:CALL@1`,
      `${Q.checkout}>${Q.reserve}:CALL@1`,
      `${Q.reserve}>${Q.record}:CALL@2`,
    ]));
  });

  await check("callees(checkout_order): call_chains include checkout>reserve>record, all start at root; no cycles", () => {
    const chains = callees.data.call_chains;
    assert.ok(chains.some((c) => c.join(">") === [Q.checkout, Q.reserve, Q.record].join(">")), JSON.stringify(chains));
    assert.ok(chains.every((c) => c[0] === Q.checkout), "every chain starts at root");
    assert.ok(chains.every((c) => c.length >= 2), "chains have at least two hops");
    assert.equal(callees.data.has_cycles, false);
    assert.deepEqual(callees.data.cycles, []);
  });

  await check("callees(checkout_order): direct_callees / direct_callers populated on nodes", () => {
    const n = callees.data.nodes;
    assert.deepEqual(byName(n, "checkout_order").direct_callees, [Q.calc, Q.record, Q.reserve]);
    assert.deepEqual(byName(n, "checkout_order").direct_callers, []);
    assert.deepEqual(byName(n, "record_order_audit").direct_callers, [Q.checkout, Q.reserve]);
    assert.deepEqual(byName(n, "reserve_inventory").direct_callers, [Q.checkout]);
    assert.deepEqual(byName(n, "reserve_inventory").direct_callees, [Q.record]);
    assert.deepEqual(byName(n, "calculate_order_discount").direct_callees, []);
  });

  await check("table touchpoints: tables_read / tables_written exact per routine (INSERT..SELECT, UPDATE subquery, JOIN)", () => {
    const n = callees.data.nodes;
    const tp = (b) => ({ r: byName(n, b).tables_read, w: byName(n, b).tables_written });
    assert.deepEqual(tp("record_order_audit"), { r: ["public.orders"], w: ["public.audit_logs"] });
    assert.deepEqual(tp("reserve_inventory"), { r: ["public.order_items"], w: ["public.inventory"] });
    assert.deepEqual(tp("calculate_order_discount"), { r: ["public.orders", "public.users"], w: [] });
    assert.deepEqual(tp("checkout_order"), { r: ["public.orders", "public.users"], w: ["public.orders"] });
  });

  await check("table touchpoints: no aliases (o/u/oi) leak as tables; every table name schema-qualified", () => {
    for (const node of callees.data.nodes) {
      for (const t of [...node.tables_read, ...node.tables_written]) {
        assert.ok(!["o", "u", "oi"].includes(t), `alias leaked as table: ${t}`);
        assert.match(t, /^public\.[a-z_]+$/, `unqualified or odd table name: ${t}`);
      }
    }
  });

  await check("routine_kind distinguishes function vs procedure", () => {
    const n = callees.data.nodes;
    assert.equal(byName(n, "calculate_order_discount").routine_kind, "function");
    for (const b of ["checkout_order", "reserve_inventory", "record_order_audit"]) assert.equal(byName(n, b).routine_kind, "procedure");
  });

  await check("callers(record_order_audit): both direct callers at depth 1, transitive checkout>reserve at depth 2, chains end at root", async () => {
    const r = await callGraph(a, { connection: PG, procedure_name: "record_order_audit", direction: "callers", max_depth: 5 });
    assert.equal(r.envelope.status, "ok");
    assert.equal(r.data.direction, "callers");
    assert.deepEqual(sortedUnique(r.data.nodes.map((n) => n.qualified_name)), [Q.checkout, Q.record, Q.reserve]);
    assert.deepEqual(sortedUnique(r.data.edges.map(edgeKey)), sortedUnique([
      `${Q.checkout}>${Q.record}:CALL@1`,
      `${Q.reserve}>${Q.record}:CALL@1`,
      `${Q.checkout}>${Q.reserve}:CALL@2`,
    ]));
    assert.deepEqual(byName(r.data.nodes, "record_order_audit").direct_callers, [Q.checkout, Q.reserve]);
    const chains = r.data.call_chains.map((c) => c.join(">"));
    assert.ok(chains.includes(`${Q.checkout}>${Q.record}`), JSON.stringify(chains));
    assert.ok(chains.includes(`${Q.checkout}>${Q.reserve}>${Q.record}`), JSON.stringify(chains));
    assert.ok(r.data.call_chains.every((c) => c[c.length - 1] === Q.record), "upstream chains terminate at the root");
  });

  await check("both(reserve_inventory): one caller + one callee, two edges", async () => {
    const r = await callGraph(a, { connection: PG, procedure_name: "reserve_inventory", direction: "both" });
    assert.equal(r.data.direction, "both");
    assert.deepEqual(sortedUnique(r.data.nodes.map((n) => n.qualified_name)), [Q.checkout, Q.record, Q.reserve]);
    assert.deepEqual(sortedUnique(r.data.edges.map(edgeKey)), sortedUnique([
      `${Q.checkout}>${Q.reserve}:CALL@1`,
      `${Q.reserve}>${Q.record}:CALL@1`,
    ]));
    assert.ok(r.data.call_chains.some((c) => c.join(">") === `${Q.reserve}>${Q.record}`));
  });

  const full1 = await callGraph(a, { connection: PG });
  const full2 = await callGraph(a, { connection: PG });

  await check("full schema graph (no procedure_name): root null, direction both, 4 nodes, 4 depth-1 edges, definitions present", () => {
    assert.equal(full1.envelope.status, "ok");
    assert.equal(full1.data.root_procedure, null);
    assert.equal(full1.data.direction, "both");
    assert.equal(full1.data.nodes.length, 4);
    assert.equal(full1.data.edges.length, 4);
    assert.ok(full1.data.edges.every((e) => e.depth === 1));
    assert.ok(full1.data.nodes.every((n) => typeof n.definition === "string" && n.definition.length > 0), "catalog routines carry their definition");
    assert.equal(full1.data.has_cycles, false);
  });

  await check("full schema graph: deterministic across two identical calls (data + mermaid byte-identical)", () => {
    assert.equal(JSON.stringify(full1.data), JSON.stringify(full2.data));
    assert.equal(full1.data.mermaid_diagram, full2.data.mermaid_diagram);
  });

  await check("envelope: request_id/connection/status/columns/rows/returned_rows/truncated/warnings/schema_version/_meta provenance", () => {
    const e = full1.envelope;
    assert.match(e.request_id, /^req_[0-9a-f]+$/);
    assert.equal(e.connection, PG);
    assert.equal(e.status, "ok");
    assert.deepEqual(e.columns, []);
    assert.deepEqual(e.rows, []);
    assert.equal(e.returned_rows, e.rows.length);
    assert.equal(e.truncated, false);
    assert.ok(Array.isArray(e.warnings));
    assert.equal(e.schema_version, "snapshot_call_graph");
    assert.equal(typeof e.execution_time_ms, "number");
    assert.equal(e._meta.provenance.untrusted_content, true);
    assert.equal(e._meta.provenance.source_kind, "procedure_call_graph");
    assert.equal(e._meta.provenance.source_connection, PG);
    assert.equal(e.data.connection, PG);
  });

  await check("latency: full-schema graph completes well under budget (reports ms)", () => {
    assert.ok(full1.envelope.execution_time_ms < 5000, `execution_time_ms=${full1.envelope.execution_time_ms}`);
    console.log(`     latency: full-schema prod-postgres execution_time_ms=${full1.envelope.execution_time_ms} (rpc round-trip ${full1.ms} ms); second call ${full2.envelope.execution_time_ms} ms`);
  });

  await check("mermaid: flowchart TD, sanitized ids, routine kind in label, call_kind edge labels, read/write table edges", () => {
    const m = callees.data.mermaid_diagram;
    const lines = m.split("\n");
    assert.equal(lines[0], "flowchart TD");
    assert.ok(m.includes('proc_public_checkout_order["public.checkout_order (procedure)"]'));
    assert.ok(m.includes('proc_public_calculate_order_discount["public.calculate_order_discount (function)"]'));
    assert.ok(m.includes('proc_public_checkout_order -->|"PERFORM"| proc_public_calculate_order_discount'));
    assert.ok(m.includes('proc_public_reserve_inventory -->|"CALL"| proc_public_record_order_audit'));
    assert.ok(m.includes('tbl_public_audit_logs[("public.audit_logs")]'));
    assert.ok(m.includes('proc_public_record_order_audit ==>|"write"| tbl_public_audit_logs'));
    assert.ok(m.includes('proc_public_record_order_audit -.->|"read"| tbl_public_orders'));
    for (const l of lines.slice(1)) {
      const ids = l.match(/\b(?:proc|tbl)_[A-Za-z0-9_]+/g) || [];
      assert.ok(ids.length >= 1, `line without node id: ${l}`);
      for (const id of ids) assert.match(id, /^(proc|tbl)_[A-Za-z0-9_]+$/);
    }
    const edgeCount = lines.filter((l) => l.includes("-->|")).length;
    assert.equal(edgeCount, callees.data.edges.length, "one call edge line per edge");
  });

  await check("max_depth=1: only depth-1 edges, chains truncated to two hops, max_depth echoed", async () => {
    const r = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: 1 });
    assert.equal(r.data.max_depth, 1);
    assert.equal(r.data.edges.length, 3);
    assert.ok(r.data.edges.every((e) => e.depth === 1));
    assert.ok(r.data.call_chains.every((c) => c.length <= 2), JSON.stringify(r.data.call_chains));
    assert.ok(r.data.call_chains.some((c) => c.join(">") === `${Q.checkout}>${Q.reserve}`));
  });

  await check("max_depth=2 / omitted / very large: identical 4-edge result; max_depth=0 falls back to default 5", async () => {
    const d2 = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: 2 });
    const dDefault = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees" });
    const dBig = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: 1_000_000 });
    const d0 = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: 0 });
    assert.equal(d2.data.max_depth, 2);
    assert.equal(dDefault.data.max_depth, 5);
    assert.equal(dBig.data.max_depth, 1_000_000);
    assert.equal(d0.data.max_depth, 5, "max_depth=0 is treated as 'use default'");
    for (const r of [d2, dDefault, dBig, d0]) {
      assert.deepEqual(sortedUnique(r.data.edges.map(edgeKey)), sortedUnique(callees.data.edges.map(edgeKey)));
    }
  });

  // KNOWN-BUG: F04-05 - negative / non-integer max_depth is silently coerced to the default (5) instead of being rejected
  await check("max_depth validation: negative or non-integer max_depth is rejected (INVALID_ARGUMENT), not silently defaulted", async () => {
    const neg = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: -1 });
    const str = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "callees", max_depth: "abc" });
    for (const [label, r] of [["-1", neg], ["'abc'", str]]) {
      assert.equal(r.envelope.status, "denied", `max_depth=${label} accepted: status=${r.envelope.status}, effective max_depth=${r.data && r.data.max_depth}`);
      assert.equal(r.envelope.code, "INVALID_ARGUMENT");
    }
  }, "F04-05");

  await check("direction validation: unknown direction -> denied INVALID_ARGUMENT with explanatory message", async () => {
    const r = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "sideways" });
    assert.equal(r.isError, true);
    assert.equal(r.envelope.status, "denied");
    assert.equal(r.envelope.code, "INVALID_ARGUMENT");
    assert.match(r.envelope.message, /direction/i);
    assert.match(r.envelope.message, /callees.*callers.*both/);
  });

  await check("direction aliases: 'CALLEES' and 'downstream' normalize to callees; 'upstream' to callers", async () => {
    const up = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "CALLEES" });
    const down = await callGraph(a, { connection: PG, procedure_name: "checkout_order", direction: "downstream" });
    const upstream = await callGraph(a, { connection: PG, procedure_name: "record_order_audit", direction: "upstream" });
    assert.equal(up.data.direction, "callees");
    assert.equal(down.data.direction, "callees");
    assert.equal(upstream.data.direction, "callers");
  });

  await check("unknown procedure -> denied with a validation code and message naming the routine and connection", async () => {
    const r = await callGraph(a, { connection: PG, procedure_name: "no_such_proc" });
    assert.equal(r.isError, true);
    assert.equal(r.envelope.status, "denied");
    assert.ok(["INVALID_ARGUMENT", "NOT_FOUND", "OBJECT_NOT_FOUND"].includes(r.envelope.code), r.envelope.code);
    assert.match(r.envelope.message, /no_such_proc/);
    assert.match(r.envelope.message, /prod-postgres/);
  });

  await check("name resolution: 'public.checkout_order', 'CHECKOUT_ORDER', 'PUBLIC.Checkout_Order' all resolve to public.checkout_order", async () => {
    for (const name of ["public.checkout_order", "CHECKOUT_ORDER", "PUBLIC.Checkout_Order"]) {
      const r = await callGraph(a, { connection: PG, procedure_name: name, direction: "callees" });
      assert.equal(r.envelope.status, "ok", name);
      assert.equal(r.data.root_procedure, Q.checkout, name);
      assert.deepEqual(sortedUnique(r.data.edges.map(edgeKey)), sortedUnique(callees.data.edges.map(edgeKey)), name);
    }
  });

  await check("empty / whitespace procedure_name behaves like omitted (full graph)", async () => {
    const r1 = await callGraph(a, { connection: PG, procedure_name: "", direction: "callees" });
    const r2 = await callGraph(a, { connection: PG, procedure_name: "   " });
    assert.equal(r1.data.root_procedure, null);
    assert.equal(r2.data.root_procedure, null);
    assert.equal(r1.data.nodes.length, 4);
    assert.equal(r2.data.nodes.length, 4);
  });

  await check("missing connection -> INVALID_ARGUMENT; unknown connection -> CONNECTION_NOT_FOUND", async () => {
    const r1 = await callGraph(a, {});
    const r2 = await callGraph(a, { connection: "nope" });
    assert.equal(r1.envelope.status, "denied");
    assert.equal(r1.envelope.code, "INVALID_ARGUMENT");
    assert.equal(r2.envelope.status, "denied");
    assert.equal(r2.envelope.code, "CONNECTION_NOT_FOUND");
  });

  await check("leaf function as root: callees -> single node, no edges/chains; callers -> checkout_order via PERFORM", async () => {
    const down = await callGraph(a, { connection: PG, procedure_name: "calculate_order_discount", direction: "callees" });
    const up = await callGraph(a, { connection: PG, procedure_name: "calculate_order_discount", direction: "callers" });
    assert.deepEqual(down.data.nodes.map((n) => n.qualified_name), [Q.calc]);
    assert.deepEqual(down.data.edges, []);
    assert.deepEqual(down.data.call_chains, []);
    assert.deepEqual(sortedUnique(up.data.edges.map(edgeKey)), [`${Q.checkout}>${Q.calc}:PERFORM@1`]);
  });

  // ---- engine parity on the same baseline fixtures ----
  const parity = {};
  for (const [conn, schema] of [["local-sqlite", "main"], ["analytics-mysql", "analytics"]]) {
    await check(`engine parity (${conn}): same routines, edges, touchpoints and chains as prod-postgres, schema-prefixed '${schema}.'`, async () => {
      const r = await callGraph(a, { connection: conn });
      parity[conn] = r;
      assert.equal(r.envelope.status, "ok");
      assert.ok(Array.isArray(r.envelope.warnings));
      const names = sortedUnique(r.data.nodes.map((n) => n.qualified_name));
      assert.deepEqual(names, ["calculate_order_discount", "checkout_order", "record_order_audit", "reserve_inventory"].map((b) => `${schema}.${b}`));
      const norm = (e) => `${baseName(e.caller)}>${baseName(e.callee)}@${e.depth}`;
      assert.deepEqual(sortedUnique(r.data.edges.map(norm)), sortedUnique(full1.data.edges.map(norm)));
      // MySQL has no PERFORM; its seeded checkout_order invokes the function as an expression.
      const kindOf = (e) => e.callee.endsWith("calculate_order_discount") ? ["PERFORM", "FUNCTION_EXPR"].includes(e.call_kind) : e.call_kind === "CALL";
      assert.ok(r.data.edges.every(kindOf), JSON.stringify(r.data.edges));
      for (const pgNode of full1.data.nodes) {
        const other = byName(r.data.nodes, pgNode.name);
        assert.ok(other, `${conn} missing ${pgNode.name}`);
        assert.equal(other.routine_kind, pgNode.routine_kind);
        assert.equal(other.schema, schema);
        assert.deepEqual(other.tables_read.map(baseName), pgNode.tables_read.map(baseName), `${conn} ${pgNode.name} tables_read`);
        assert.deepEqual(other.tables_written.map(baseName), pgNode.tables_written.map(baseName), `${conn} ${pgNode.name} tables_written`);
        assert.ok([...other.tables_read, ...other.tables_written].every((t) => t.startsWith(`${schema}.`)), `${conn} unqualified table`);
      }
      assert.deepEqual(r.data.call_chains.map((c) => c.map(baseName).join(">")), full1.data.call_chains.map((c) => c.map(baseName).join(">")));
      assert.equal(r.data.has_cycles, false);
    });
  }

  await check("engine parity: rooted callees query on local-sqlite and analytics-mysql reports depth-2 reserve>record edge", async () => {
    for (const conn of ["local-sqlite", "analytics-mysql"]) {
      const r = await callGraph(a, { connection: conn, procedure_name: "checkout_order", direction: "callees" });
      assert.equal(r.envelope.status, "ok", conn);
      assert.ok(r.data.root_procedure.endsWith(".checkout_order"), conn);
      assert.ok(r.data.edges.some((e) => baseName(e.caller) === "reserve_inventory" && baseName(e.callee) === "record_order_audit" && e.depth === 2), conn);
      assert.equal(r.data.nodes.length, 4, conn);
    }
  });

  closeClient(a);

  // ======================= Section B: cycles + analyzer robustness =======================
  const cfgB = makeConfig(appendToInitSql(CYCLE_AND_ROBUSTNESS_SQL));
  const b = await openClient(cfgB);

  const fullB = await callGraph(b, { connection: PG });
  const nodesB = fullB.data.nodes;
  const edgesB = fullB.data.edges;

  await check("cycles: full graph reports has_cycles=true with canonical [proc_a,proc_b,proc_a] and [proc_self,proc_self]; completes < 30 s", () => {
    assert.equal(fullB.envelope.status, "ok");
    assert.ok(fullB.ms < 30_000, `took ${fullB.ms} ms`);
    assert.equal(fullB.data.has_cycles, true);
    assert.deepEqual(fullB.data.cycles, [
      ["public.proc_a", "public.proc_b", "public.proc_a"],
      ["public.proc_self", "public.proc_self"],
    ]);
    assert.ok(fullB.data.call_chains.every((c) => c.length <= fullB.data.max_depth + 2), "chains terminate");
  });

  await check("cycles: rooted callees(proc_a) -> edge back to root at depth 2, closed chain [a,b,a], cycle canonicalized", async () => {
    const r = await callGraph(b, { connection: PG, procedure_name: "proc_a", direction: "callees" });
    assert.deepEqual(sortedUnique(r.data.edges.map(edgeKey)), ["public.proc_a>public.proc_b:CALL@1", "public.proc_b>public.proc_a:CALL@2"]);
    assert.equal(r.data.has_cycles, true);
    assert.deepEqual(r.data.cycles, [["public.proc_a", "public.proc_b", "public.proc_a"]]);
    const chains = r.data.call_chains.map((c) => c.join(">"));
    assert.ok(chains.includes("public.proc_a>public.proc_b>public.proc_a"), JSON.stringify(chains));
    assert.ok(r.data.call_chains.every((c) => c.length <= 3), "no chain walks the cycle twice");
    const m = r.data.mermaid_diagram;
    assert.ok(m.includes('proc_public_proc_a -->|"CALL"| proc_public_proc_b') && m.includes('proc_public_proc_b -->|"CALL"| proc_public_proc_a'));
  });

  await check("cycles: callees(proc_b) started from the other member yields the same canonical cycle", async () => {
    const r = await callGraph(b, { connection: PG, procedure_name: "proc_b", direction: "callees" });
    assert.deepEqual(r.data.cycles, [["public.proc_a", "public.proc_b", "public.proc_a"]]);
  });

  await check("cycles: self-recursive proc_self -> single node, self edge, cycle [self,self] in both directions, chains terminate", async () => {
    for (const direction of ["callees", "callers"]) {
      const r = await callGraph(b, { connection: PG, procedure_name: "proc_self", direction });
      assert.deepEqual(r.data.nodes.map((n) => n.qualified_name), ["public.proc_self"], direction);
      assert.deepEqual(r.data.edges.map(edgeKey), ["public.proc_self>public.proc_self:CALL@1"], direction);
      assert.deepEqual(r.data.cycles, [["public.proc_self", "public.proc_self"]], direction);
      assert.ok(r.data.call_chains.every((c) => c.length <= 2), direction);
    }
  });

  await check("cycles: max_depth=1000000 on a cyclic graph terminates quickly (< 30 s) with identical cycles", async () => {
    const r = await callGraph(b, { connection: PG, procedure_name: "proc_a", direction: "both", max_depth: 1_000_000 });
    assert.ok(r.ms < 30_000, `took ${r.ms} ms`);
    assert.deepEqual(r.data.cycles, [["public.proc_a", "public.proc_b", "public.proc_a"]]);
    assert.equal(r.data.max_depth, 1_000_000);
  });

  await check("cycles: parity on local-sqlite (main.* cycles detected)", async () => {
    const r = await callGraph(b, { connection: "local-sqlite" });
    assert.equal(r.data.has_cycles, true);
    assert.deepEqual(r.data.cycles, [["main.proc_a", "main.proc_b", "main.proc_a"], ["main.proc_self", "main.proc_self"]]);
  });

  await check("analyzer: CALL inside '--' and '/* */' comments is ignored", () => {
    const all = JSON.stringify({ n: nodesB.map((n) => n.qualified_name), e: edgesB });
    assert.ok(!all.includes("fake_proc_line"), "line-comment CALL leaked");
    assert.ok(!all.includes("fake_proc_block"), "block-comment CALL leaked");
    assert.deepEqual(byName(nodesB, "robust_comments").tables_written, ["public.audit_logs"]);
  });

  // KNOWN-BUG: F04-01 - string literals are not masked before call detection; 'CALL fake_proc_str()' inside a VALUES literal becomes a call edge + stub node
  await check("analyzer: CALL inside a string literal is ignored (no stub node / edge for fake_proc_str)", () => {
    assert.deepEqual(byName(nodesB, "robust_comments").direct_callees, [], `direct_callees=${JSON.stringify(byName(nodesB, "robust_comments").direct_callees)}`);
    assert.ok(!nodesB.some((n) => n.name === "fake_proc_str"), "stub node fake_proc_str present");
    assert.ok(!edgesB.some((e) => e.callee.endsWith("fake_proc_str")), "edge to fake_proc_str present");
  }, "F04-01");

  await check("analyzer: EXEC and EXECUTE <routine>(...) both produce EXEC edges", () => {
    assert.deepEqual(sortedUnique(edgesB.filter((e) => e.caller === "public.robust_exec").map(edgeKey)), [
      "public.robust_exec>public.exec_target:EXEC@1",
      "public.robust_exec>public.execute_target:EXEC@1",
    ]);
  });

  await check("analyzer: schema-qualified CALL public.record_order_audit resolves to the catalog routine (CALL kind)", () => {
    assert.deepEqual(edgesB.filter((e) => e.caller === "public.robust_qualified").map(edgeKey), ["public.robust_qualified>public.record_order_audit:CALL@1"]);
    assert.ok(byName(nodesB, "record_order_audit").direct_callers.includes("public.robust_qualified"));
  });

  await check("analyzer: function used in an expression (SELECT calculate_order_discount(1)) -> FUNCTION_EXPR edge", () => {
    assert.deepEqual(edgesB.filter((e) => e.caller === "public.robust_fnexpr").map(edgeKey), ["public.robust_fnexpr>public.calculate_order_discount:FUNCTION_EXPR@1"]);
  });

  await check("analyzer: call to an unknown routine is kept as an external stub node (definition null) with a CALL edge", () => {
    assert.deepEqual(edgesB.filter((e) => e.caller === "public.robust_unknown").map(edgeKey), ["public.robust_unknown>totally_unknown_proc:CALL@1"]);
    const stub = nodesB.find((n) => n.name === "totally_unknown_proc");
    assert.ok(stub, "stub node missing");
    assert.equal(stub.definition, null);
    assert.deepEqual(stub.direct_callers, ["public.robust_unknown"]);
  });

  // KNOWN-BUG: F04-04 - stub node for an unresolved callee inherits the caller's schema ("public") while its qualified_name is bare ("totally_unknown_proc")
  await check("analyzer: external stub node's schema/name/qualified_name are mutually consistent", () => {
    const stub = nodesB.find((n) => n.name === "totally_unknown_proc");
    assert.ok(stub);
    const expected = stub.schema ? `${stub.schema}.${stub.name}` : stub.name;
    assert.equal(stub.qualified_name, expected, `schema=${JSON.stringify(stub.schema)} name=${stub.name} qualified_name=${stub.qualified_name}`);
  }, "F04-04");

  await check("analyzer: dynamic SQL EXECUTE '<string>' yields no bogus call; routine is still listed as an isolated node", () => {
    const dyn = byName(nodesB, "robust_dynamic");
    assert.ok(dyn, "isolated routine missing from full graph");
    assert.deepEqual(dyn.direct_callees, []);
    assert.deepEqual(dyn.direct_callers, []);
    assert.ok(!edgesB.some((e) => e.caller === "public.robust_dynamic"));
  });

  await check("full graph with cycles: node/edge counts cover every catalog routine plus stubs; isolated routines included", () => {
    const catalogNames = ["calculate_order_discount", "checkout_order", "record_order_audit", "reserve_inventory", "proc_a", "proc_b", "proc_self", "exec_target", "execute_target", "robust_comments", "robust_exec", "robust_qualified", "robust_fnexpr", "robust_unknown", "robust_dynamic"];
    for (const n of catalogNames) assert.ok(byName(nodesB, n), `missing ${n}`);
    assert.ok(nodesB.every((n) => n.routine_kind === "function" || n.routine_kind === "procedure"));
    assert.equal(byName(nodesB, "calculate_order_discount").routine_kind, "function");
  });

  closeClient(b);

  // ======================= Section C: dollar-quoted PL/pgSQL body =======================
  // KNOWN-BUG: F04-02 - a `$$`-quoted routine placed AFTER BEGIN...END routines in init_sql swallows every preceding
  // routine definition (unbounded dollar-quote search in find_routine_ddl_end / find_sqlite_routine_ddl_end).
  const cfgC = makeConfig(appendToInitSql(DOLLAR_FN_SQL));
  const c = await openClient(cfgC);
  for (const [conn, schema] of [["prod-postgres", "public"], ["local-sqlite", "main"], ["analytics-mysql", "analytics"]]) {
    await check(`dollar-quoted function appended to init_sql (${conn}): dollar_fn present with PERFORM edge, baseline routines intact, no bogus self-cycle`, async () => {
      const r = await callGraph(c, { connection: conn });
      assert.equal(r.envelope.status, "ok");
      const names = sortedUnique(r.data.nodes.map((n) => n.qualified_name));
      assert.deepEqual(names, ["calculate_order_discount", "checkout_order", "dollar_fn", "record_order_audit", "reserve_inventory"].map((x) => `${schema}.${x}`));
      assert.ok(r.data.edges.some((e) => e.caller === `${schema}.dollar_fn` && e.callee === `${schema}.record_order_audit` && e.call_kind === "PERFORM"), JSON.stringify(r.data.edges));
      assert.equal(byName(r.data.nodes, "dollar_fn").routine_kind, "function");
      assert.deepEqual(byName(r.data.nodes, "record_order_audit").direct_callees, []);
      assert.equal(r.data.has_cycles, false, `cycles=${JSON.stringify(r.data.cycles)}`);
      assert.ok(byName(r.data.nodes, "record_order_audit").definition.length < 400, "record_order_audit definition swallowed following statements");
    }, conn === "analytics-mysql" ? undefined : "F04-02");
  }
  closeClient(c);

  const cfgC2 = makeConfig(appendToInitSql(DOLLAR_FN_SQL, [0, 1, 2], "prepend"));
  const c2 = await openClient(cfgC2);
  await check("dollar-quoted function PREPENDED to init_sql parses on all engines (shows F04-02 is position-dependent)", async () => {
    for (const [conn, schema] of [["prod-postgres", "public"], ["local-sqlite", "main"], ["analytics-mysql", "analytics"]]) {
      const r = await callGraph(c2, { connection: conn });
      assert.equal(r.data.nodes.length, 5, conn);
      assert.ok(r.data.edges.some((e) => e.caller === `${schema}.dollar_fn` && e.call_kind === "PERFORM"), conn);
      assert.equal(r.data.has_cycles, false, conn);
    }
  });
  closeClient(c2);

  // ======================= Section D: MySQL DELIMITER body =======================
  // KNOWN-BUG: F04-03 - `DELIMITER //` client directives in the MySQL init_sql are passed through to the embedded engine,
  // the adapter fails to bootstrap and the whole server never answers `initialize`.
  await check("MySQL DELIMITER-wrapped procedure in analytics-mysql init_sql: server starts and delim_proc -> record_order_audit edge is reported", async () => {
    const cfgD = makeConfig(appendToInitSql(DELIMITER_SQL, [2]));
    let d;
    try {
      d = await openClient(cfgD);
    } catch (err) {
      throw new Error(`server failed to start with DELIMITER in init_sql: ${err.message.slice(0, 300)}`);
    }
    try {
      const r = await callGraph(d, { connection: "analytics-mysql", procedure_name: "delim_proc", direction: "callees" });
      assert.equal(r.envelope.status, "ok");
      assert.deepEqual(r.data.edges.map(edgeKey), ["analytics.delim_proc>analytics.record_order_audit:CALL@1"]);
    } finally {
      closeClient(d);
    }
  }, "F04-03");

  // ======================= Summary =======================
  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);
  const knownFailed = failed.filter((r) => r.knownBug);
  const unexpectedFailed = failed.filter((r) => !r.knownBug);
  console.log(`\n# ${passed}/${results.length} checks passed; ${failed.length} failed (${knownFailed.length} tagged KNOWN-BUG: ${[...new Set(knownFailed.map((r) => r.knownBug))].join(", ") || "-"}; ${unexpectedFailed.length} unexpected)`);
  cleanupAll();
  // Give the servers a moment to exit before the temp-dir sweep in the exit handler.
  await new Promise((resolve) => setTimeout(resolve, 300));
  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(`FATAL ${err && err.stack ? err.stack : err}`);
  cleanupAll();
  process.exit(1);
});
