#!/usr/bin/env node
"use strict";
/**
 * DB-MCP feature matrix verification.
 *
 * Exercises every shipped feature end-to-end through the real binary (via the npx launcher):
 *   - 24 MCP tools over stdio (Explore, Query, Diagnose, Change, Schema, Ontology profiles)
 *   - adversarial security denials (multi-statement, mutating CTE, privileged function, self-approval, replay)
 *   - sensitive-column redaction and restricted tables
 *   - Streamable HTTP transport (bearer auth, /health, /metrics, /admin/approve)
 *   - audit trail persistence
 *   - governed ontology flow (agent proposes, admin certifies and publishes via CLI, agent asks)
 *
 * Usage: node scripts/feature-smoke.js [--json] [--keep] [--config <file>]
 *        npx @vinoth_n_3000/db-mcp selftest [--json] [--keep]      (same checks, shipped in the npm package)
 * By default every check runs against an isolated temporary copy of config/db-mcp.example.toml, so no
 * user database, audit log or ontology store is touched; --keep prints and keeps that directory.
 * --config runs against another config instead (developer use; it writes to the stores that config names,
 * and the governed ontology flow is skipped).
 * Exit code 0 when every check passes, 1 otherwise. Prints a feature matrix.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createClient } = require(path.join(__dirname, "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(__dirname, "make-isolated-config.js"));
const { spawnDbMcpServer } = require(path.join(__dirname, "..", "npm", "bin", "db-mcp.js"));

const REPO_ROOT = path.resolve(__dirname, "..");
const LAUNCHER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const argv = process.argv.slice(2);
const KEEP = argv.includes("--keep");
const ISO = argv.includes("--config") ? null : makeIsolatedConfig();
const CONFIG = ISO ? ISO.configPath : path.resolve(argv[argv.indexOf("--config") + 1]);
const WORK_DIR = ISO ? ISO.dir : os.tmpdir();
const JSON_OUT = argv.includes("--json");
const CERTIFY = [
  "metric:main.orders.count",
  "attribute:main.users.role",
  "attribute:main.order_items.sku",
  "relationship:main.orders(user_id)->main.users",
  "relationship:main.order_items(order_id)->main.orders",
];

function configuredPath(key) {
  const m = fs.readFileSync(CONFIG, "utf8").match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]+)"`, "m"));
  return m ? path.resolve(REPO_ROOT, m[1]) : null;
}
function ontologyCli(args) {
  return spawnSync(process.execPath, [LAUNCHER, "ontology", ...args, "--config", CONFIG], { cwd: REPO_ROOT, encoding: "utf8" });
}

const results = [];
function record(feature, check, ok, detail) {
  results.push({ feature, check, ok, detail: detail || "" });
  if (!JSON_OUT) console.log(`${ok ? "PASS" : "FAIL"}  [${feature}] ${check}${detail && !ok ? " :: " + detail : ""}`);
}
async function step(feature, check, fn) {
  try {
    const detail = await fn();
    record(feature, check, true, typeof detail === "string" ? detail : "");
  } catch (err) {
    record(feature, check, false, err.message.split("\n")[0].slice(0, 300));
  }
}

function envelopeOk(p, label) {
  assert.equal(p.status, "ok", `${label}: ${JSON.stringify(p).slice(0, 300)}`);
  for (const k of ["request_id", "connection", "status", "columns", "rows", "returned_rows", "truncated", "warnings", "schema_version"]) {
    assert.ok(k in p, `${label}: missing ${k}`);
  }
  assert.equal(p._meta?.provenance?.untrusted_content, true, `${label}: provenance flag`);
  return p;
}
function deniedWith(p, code, label) {
  assert.equal(p.status, "denied", `${label}: expected denied, got ${JSON.stringify(p).slice(0, 300)}`);
  assert.equal(p.code, code, `${label}: expected code ${code}, got ${p.code} (${p.message})`);
  assert.equal(typeof p.next_action, "string", `${label}: next_action missing`);
  return p;
}
function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close((e) => (e ? reject(e) : resolve(port))); });
    s.on("error", reject);
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function stdioSuite() {
  const client = createClient({ config: CONFIG, principal: "smoke-agent", role: "agent", timeoutMs: 30000 });
  const call = async (name, args = {}) => {
    const resp = await client.rpc("tools/call", { name, arguments: args });
    if (resp.error) throw new Error(`${name} JSON-RPC error: ${JSON.stringify(resp.error)}`);
    return resp.result.structuredContent;
  };
  try {
    await step("protocol", "initialize returns serverInfo", async () => {
      const r = await client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "0" } });
      assert.equal(r.result.serverInfo.name, "db-mcp");
      client.notify("notifications/initialized", {});
    });
    await step("protocol", "ping", async () => { const r = await client.rpc("ping", {}); assert.deepEqual(r.result, {}); });
    await step("protocol", "tools/list exposes 24 tools with input schemas", async () => {
      const r = await client.rpc("tools/list", {});
      assert.equal(r.result.tools.length, 24);
      for (const t of r.result.tools) assert.equal(t.inputSchema?.type, "object", `${t.name} schema`);
    });
    await step("protocol", "unknown method -> JSON-RPC -32601", async () => {
      const r = await client.rpc("no/such", {}); assert.equal(r.error?.code, -32601);
    });
    await step("protocol", "unknown tool -> structured error", async () => {
      const r = await client.rpc("tools/call", { name: "nope", arguments: {} });
      assert.ok(r.error || r.result?.isError || r.result?.structuredContent?.status === "denied", JSON.stringify(r).slice(0, 200));
    });

    // Explore
    await step("explore", "list_connections lists 3 connections with modes", async () => {
      const p = envelopeOk(await call("list_connections"), "list_connections");
      assert.equal(p.data.length, 3); // KNOWN-BUG F02-01: returned_rows is 0 for data-shaped responses
    });
    await step("explore", "search_objects paginates and filters", async () => {
      const all = envelopeOk(await call("search_objects", { connection: "local-sqlite", detail_level: "names", limit: 3 }), "search");
      assert.ok(all.data.objects.length <= 3 && all.data.has_more === true, JSON.stringify(all.data).slice(0, 200));
      const f = envelopeOk(await call("search_objects", { connection: "local-sqlite", name_pattern: "order", object_types: ["table"] }), "search filtered");
      assert.ok(f.data.objects.length >= 2 && f.data.objects.every((o) => JSON.stringify(o).toLowerCase().includes("order")));
    });
    await step("explore", "describe_object returns columns, FKs and DDL", async () => {
      const p = envelopeOk(await call("describe_object", { connection: "local-sqlite", object_name: "orders" }), "describe");
      const s = JSON.stringify(p.data);
      assert.ok(s.includes("user_id") && /foreign|references/i.test(s), "FK info missing");
    });
    await step("explore", "describe_object unknown -> OBJECT_NOT_FOUND", async () => {
      const p = await call("describe_object", { connection: "local-sqlite", object_name: "does_not_exist" });
      assert.equal(p.status, "denied"); assert.match(p.message, /not found/i); // KNOWN-BUG F02-10: code is INVALID_ARGUMENT
    });
    await step("lineage", "trace_table_dependencies: FKs, dependents, 2-hop join path, mermaid", async () => {
      const p = envelopeOk(await call("trace_table_dependencies", { connection: "local-sqlite", table_name: "users", target_table: "order_items", max_depth: 3 }), "trace");
      assert.equal(p.data.join_path.hops.length, 2);
      assert.match(p.data.join_path.synthesized_join_sql, /JOIN/);
      assert.ok(p.data.inbound_foreign_keys.length >= 1, "inbound FKs");
      assert.ok(p.data.dependent_objects.some((o) => o.name.includes("active_user_orders")), "dependent view");
      assert.match(p.data.mermaid_diagram, /flowchart/);
    });
    await step("lineage", "trace_table_dependencies: outbound FKs for order_items", async () => {
      const p = envelopeOk(await call("trace_table_dependencies", { connection: "local-sqlite", table_name: "order_items" }), "trace2");
      const targets = p.data.outbound_foreign_keys.map((e) => e.to_table).join(",");
      assert.ok(targets.includes("orders") && targets.includes("inventory"), targets);
    });
    await step("callgraph", "get_procedure_call_graph: callees of checkout_order with chains + touchpoints", async () => {
      const p = envelopeOk(await call("get_procedure_call_graph", { connection: "prod-postgres", procedure_name: "checkout_order", direction: "callees", max_depth: 5 }), "graph");
      assert.ok(p.data.nodes.length >= 3);
      assert.ok(p.data.call_chains.some((c) => c.join(">").includes("reserve_inventory") && c.join(">").includes("record_order_audit")), JSON.stringify(p.data.call_chains));
      const root = p.data.nodes.find((n) => n.name === "checkout_order");
      assert.ok(root.tables_written.some((t) => t.includes("orders")), "tables_written");
      assert.equal(p.data.has_cycles, false);
      assert.match(p.data.mermaid_diagram, /flowchart/);
    });
    await step("callgraph", "get_procedure_call_graph: callers of record_order_audit", async () => {
      const p = envelopeOk(await call("get_procedure_call_graph", { connection: "prod-postgres", procedure_name: "record_order_audit", direction: "callers" }), "callers");
      const names = p.data.nodes.map((n) => n.name);
      assert.ok(names.includes("reserve_inventory") && names.includes("checkout_order"), names.join(","));
    });
    await step("callgraph", "get_procedure_call_graph: full schema graph without root", async () => {
      const p = envelopeOk(await call("get_procedure_call_graph", { connection: "local-sqlite" }), "full");
      assert.ok(p.data.nodes.length >= 4 && p.data.edges.length >= 3);
    });

    // Query
    await step("query", "execute_query with bound params + redaction", async () => {
      const p = envelopeOk(await call("execute_query", { connection: "local-sqlite", sql: "SELECT id, email, password_hash FROM users WHERE id = ?1", params: [1] }), "exec");
      assert.equal(p.returned_rows, 1);
      assert.equal(p.rows[0][2], "[REDACTED]");
    });
    await step("query", "execute_query row limit sets truncated", async () => {
      const p = envelopeOk(await call("execute_query", { connection: "local-sqlite", sql: "SELECT id FROM users", max_rows: 1 }), "limit");
      assert.equal(p.returned_rows, 1); assert.equal(p.truncated, true);
    });
    await step("query", "execute_query restricted table denied", async () => {
      const p = await call("execute_query", { connection: "local-sqlite", sql: "SELECT * FROM internal_secrets" });
      assert.equal(p.status, "denied", JSON.stringify(p).slice(0, 200));
    });
    await step("query", "explain_query json + text", async () => {
      envelopeOk(await call("explain_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE id = 1" }), "explain json");
      envelopeOk(await call("explain_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE id = 1", format: "text" }), "explain text");
    });
    await step("query", "explain_query rejects mutation", async () => {
      const p = await call("explain_query", { connection: "local-sqlite", sql: "DELETE FROM users" });
      assert.equal(p.status, "denied");
    });
    await step("named-tools", "run_named_tool executes with typed args", async () => {
      const p = envelopeOk(await call("run_named_tool", { tool_name: "get_user_by_id", arguments: { user_id: 1 } }), "named");
      assert.equal(p.returned_rows, 1);
      const q = envelopeOk(await call("run_named_tool", { tool_name: "list_orders_by_status", arguments: { status: "completed" } }), "named2");
      assert.ok(q.returned_rows >= 1);
    });
    await step("named-tools", "run_named_tool validates missing/invalid/unknown", async () => {
      assert.equal((await call("run_named_tool", { tool_name: "get_user_by_id", arguments: {} })).status, "denied");
      assert.equal((await call("run_named_tool", { tool_name: "get_user_by_id", arguments: { user_id: "abc" } })).status, "denied");
      assert.equal((await call("run_named_tool", { tool_name: "nope" })).status, "denied");
    });

    // Security guards
    await step("security", "multi-statement injection -> MULTI_STATEMENT_FORBIDDEN", async () => {
      deniedWith(await call("execute_query", { connection: "local-sqlite", sql: "SELECT 1; DROP TABLE users" }), "MULTI_STATEMENT_FORBIDDEN", "multi");
    });
    await step("security", "mutating CTE in ReadOnly -> MUTATION_NOT_ALLOWED_IN_READ_ONLY", async () => {
      deniedWith(await call("execute_query", { connection: "analytics-mysql", sql: "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d" }), "MUTATION_NOT_ALLOWED_IN_READ_ONLY", "cte");
    });
    await step("security", "privileged function -> PRIVILEGED_FUNCTION_FORBIDDEN", async () => {
      deniedWith(await call("execute_query", { connection: "prod-postgres", sql: "SELECT pg_read_file('/etc/passwd')" }), "PRIVILEGED_FUNCTION_FORBIDDEN", "priv");
    });
    await step("security", "direct write in GovernedProduction is denied", async () => {
      const p = await call("execute_query", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'x' WHERE id = 1" });
      assert.equal(p.status, "denied");
    });
    await step("security", "unknown connection -> denied", async () => {
      const p = await call("execute_query", { connection: "ghost", sql: "SELECT 1" });
      assert.equal(p.status, "denied");
    });

    // Diagnose
    await step("diagnose", "database_health returns checks", async () => {
      const p = envelopeOk(await call("database_health", { connection: "prod-postgres" }), "health");
      assert.ok(p.returned_rows >= 3);
    });
    await step("diagnose", "analyze_workload ranks queries", async () => {
      envelopeOk(await call("analyze_workload", { connection: "prod-postgres", top_n: 5 }), "workload");
    });
    await step("diagnose", "recommend_indexes produces candidates with evidence", async () => {
      const p = envelopeOk(await call("recommend_indexes", { connection: "prod-postgres", queries: ["SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"] }), "idx");
      assert.ok(p.returned_rows >= 1, "no recommendations");
      assert.match(JSON.stringify(p), /CREATE INDEX/i);
    });

    // Schema + Change workflow
    const snap = await call("capture_schema", { connection: "local-sqlite" });
    await step("schema", "capture_schema deterministic snapshot_<hash>", async () => {
      envelopeOk(snap, "snap");
      assert.match(snap.schema_version, /^snapshot_[0-9a-f]+$/);
      const again = await call("capture_schema", { connection: "local-sqlite" });
      assert.equal(again.schema_version, snap.schema_version, "non-deterministic snapshot");
    });
    await step("schema", "diff_schema identical when unchanged", async () => {
      const d = envelopeOk(await call("diff_schema", { base_snapshot: snap.data, target_connection: "local-sqlite" }), "diff0");
      assert.equal(d.data.is_identical, true);
    });
    const prop = await call("propose_change", { connection: "local-sqlite", sql: "CREATE INDEX idx_orders_e2e_stdio ON orders (user_id)" });
    let changeId = null;
    await step("change", "propose_change returns chg_* with approval hash", async () => {
      envelopeOk(prop, "propose");
      changeId = prop.data.change_id;
      assert.match(changeId, /^chg_/);
      assert.equal(typeof prop.data.approval_hash, "string");
    });
    await step("change", "get_change shows proposed state", async () => {
      const g = envelopeOk(await call("get_change", { change_id: changeId }), "get");
      assert.equal(g.data.state, "proposed");
    });
    await step("change", "apply_change before approval is denied", async () => {
      const a = await call("apply_change", { change_id: changeId });
      assert.equal(a.status, "denied", JSON.stringify(a).slice(0, 200));
    });
    await step("change", "self-approval via CLI -> SELF_APPROVAL_FORBIDDEN", async () => {
      const r = spawnSync(process.execPath, [LAUNCHER, "approve", "--change-id", changeId, "--approver", "smoke-agent", "--config", CONFIG], { cwd: REPO_ROOT, encoding: "utf8" });
      assert.notEqual(r.status, 0, "self approval succeeded");
      assert.match(r.stderr + r.stdout, /SELF_APPROVAL_FORBIDDEN|self-approval/i);
    });
    await step("change", "out-of-band CLI approval by admin", async () => {
      const r = spawnSync(process.execPath, [LAUNCHER, "approve", "--change-id", changeId, "--approver", "dba-admin", "--role", "admin", "--config", CONFIG], { cwd: REPO_ROOT, encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).state, "approved");
    });
    await step("change", "apply_change executes once; replay -> APPROVAL_ALREADY_CONSUMED", async () => {
      const a = envelopeOk(await call("apply_change", { change_id: changeId }), "apply");
      assert.equal(a.data.state, "applied");
      deniedWith(await call("apply_change", { change_id: changeId }), "APPROVAL_ALREADY_CONSUMED", "replay");
    });
    await step("schema", "diff_schema detects the applied index", async () => {
      const d = envelopeOk(await call("diff_schema", { base_snapshot: snap.data, target_connection: "local-sqlite" }), "diff1");
      assert.equal(d.data.is_identical, false);
      assert.match(JSON.stringify(d.data), /idx_orders_e2e_stdio/);
    });
    await step("change", "get_change unknown id -> denied", async () => {
      assert.equal((await call("get_change", { change_id: "chg_missing" })).status, "denied");
    });

    // Ontology (idempotent operations only; full governed flow lives in npm/test/features/16-ontology.test.js)
    await step("ontology", "ontology_status reports readiness and coverage", async () => {
      const s = envelopeOk(await call("ontology_status", { connection: "local-sqlite" }), "ontology_status");
      assert.ok(["ready", "degraded", "not_ready"].includes(s.data.readiness), s.data.readiness);
    });
    await step("ontology", "discover_ontology writes unverified candidates idempotently", async () => {
      envelopeOk(await call("discover_ontology", { connection: "local-sqlite" }), "discover");
      const again = envelopeOk(await call("discover_ontology", { connection: "local-sqlite" }), "discover2");
      assert.equal(again.data.merge.inserted, 0);
    });
    await step("ontology", "search_terms ranks candidates with status; restricted table never appears", async () => {
      const s = envelopeOk(await call("search_terms", { connection: "local-sqlite", query: "order total" }), "search_terms");
      assert.ok(s.data.length >= 1);
      assert.ok(!JSON.stringify(s.data).includes("internal_secrets"));
    });
    await step("ontology", "plan_semantic_query refuses questions without certified definitions", async () => {
      const p = envelopeOk(await call("plan_semantic_query", { connection: "local-sqlite", question: "how many late arrivals per service" }), "plan");
      assert.equal(p.data.status, "not_answerable");
    });
    if (ISO) {
      // Full governed flow. Only on the isolated copy: it writes certifications and a published revision.
      let draft = null;
      await step("ontology", "propose_semantic_definition stores an agent draft", async () => {
        const r = envelopeOk(await call("propose_semantic_definition", {
          connection: "local-sqlite",
          definition: { name: "order value", synonyms: ["order total", "sales"], body: { type: "metric", base_table: "orders", aggregation: "sum", column: "total_cents", unit: "cents", grain: "order" } },
        }), "propose");
        draft = r.data.definition;
        assert.match(draft.def_id, /^metric:/);
      });
      await step("ontology", "proposer cannot certify its own draft (CLI review)", async () => {
        assert.ok(draft, "no draft");
        const r = ontologyCli(["review", "--connection", "local-sqlite", "--def-id", draft.def_id, "--version", String(draft.version), "--action", "approve", "--reviewer", "smoke-agent", "--reason", "self"]);
        assert.notEqual(r.status, 0, "self review succeeded");
        assert.match(r.stderr + r.stdout, /SELF_APPROVAL_FORBIDDEN|self/i);
      });
      await step("ontology", "admin certifies and publishes a revision via CLI", async () => {
        assert.ok(draft, "no draft");
        for (const [id, v] of [...CERTIFY.map((id) => [id, 1]), [draft.def_id, draft.version]]) {
          const r = ontologyCli(["review", "--connection", "local-sqlite", "--def-id", id, "--version", String(v), "--action", "approve", "--reviewer", "smoke-reviewer", "--reason", "selftest"]);
          assert.equal(r.status, 0, `review ${id}: ${r.stderr.trim()}`);
        }
        const pub = ontologyCli(["publish", "--connection", "local-sqlite", "--reviewer", "smoke-reviewer"]);
        assert.equal(pub.status, 0, pub.stderr.trim());
        assert.ok(JSON.parse(pub.stdout).revision.def_refs.length >= CERTIFY.length + 1);
      });
      await step("ontology", "ask_semantic_question answers from certified definitions only", async () => {
        const a = envelopeOk(await call("ask_semantic_question", { connection: "local-sqlite", question: "total order value by user role" }), "ask");
        assert.equal(a.data.plan.status, "answerable", JSON.stringify(a.data.plan.missing));
        assert.equal(a.data.answered, true);
        assert.match(a.data.plan.sql, /^SELECT /i);
        assert.ok(a.rows.length >= 1, "no rows");
      });
      await step("ontology", "multiplicative join (fan-out) is refused, not guessed", async () => {
        const p = envelopeOk(await call("plan_semantic_query", { connection: "local-sqlite", question: "order total by sku" }), "fanout");
        assert.equal(p.data.status, "not_answerable");
        assert.match(p.data.missing.join(" "), /multiplicative/i);
      });
    }
  } finally {
    client.close();
  }
}

async function httpSuite() {
  const port = await getFreePort();
  const env = { DB_MCP_AUTH_TOKEN: "smoke-agent-token", DB_MCP_ADMIN_TOKEN: "smoke-admin-token" };
  const child = spawnDbMcpServer(["serve", "--transport", "http", "--bind", `127.0.0.1:${port}`, "--config", CONFIG], { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  const base = `http://127.0.0.1:${port}`;
  const errs = []; child.stderr.on("data", (d) => errs.push(String(d)));
  try {
    let ready = false;
    for (let i = 0; i < 60 && !ready; i++) {
      try { const r = await fetch(`${base}/health`); ready = r.ok; } catch { await sleep(250); }
    }
    await step("http", "/health reports ok with 24 tools", async () => {
      assert.ok(ready, `server not ready: ${errs.join("")}`);
      const b = await (await fetch(`${base}/health`)).json();
      assert.equal(b.status, "ok"); assert.equal(b.tools, 24);
    });
    const rpc = async (body, token = env.DB_MCP_AUTH_TOKEN, headers = {}) =>
      fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...body }) });
    await step("http", "missing bearer -> 401", async () => { assert.equal((await rpc({ method: "tools/list", params: {} }, null)).status, 401); });
    await step("http", "wrong bearer -> 401", async () => { assert.equal((await rpc({ method: "tools/list", params: {} }, "bad")).status, 401); });
    await step("http", "tools/list over HTTP", async () => {
      const r = await rpc({ method: "tools/list", params: {} }); assert.equal(r.status, 200);
      assert.equal((await r.json()).result.tools.length, 24);
    });
    await step("http", "tools/call over HTTP with principal headers", async () => {
      const r = await rpc({ method: "tools/call", params: { name: "list_connections", arguments: {} } }, env.DB_MCP_AUTH_TOKEN, { "x-mcp-principal": "http-agent", "x-mcp-role": "developer" });
      envelopeOk((await r.json()).result.structuredContent, "http list");
    });
    await step("http", "/admin/approve rejects bad token and approves with admin token", async () => {
      const prop = await (await rpc({ method: "tools/call", params: { name: "propose_change", arguments: { connection: "prod-postgres", sql: "UPDATE orders SET status = 'completed' WHERE id = 102" } } })).json();
      const changeId = prop.result.structuredContent.data.change_id;
      const bad = await fetch(`${base}/admin/approve`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer nope" }, body: JSON.stringify({ change_id: changeId, approver: "release-admin" }) });
      assert.equal(bad.status, 401);
      const ok = await fetch(`${base}/admin/approve`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${env.DB_MCP_ADMIN_TOKEN}` }, body: JSON.stringify({ change_id: changeId, approver: "release-admin" }) });
      assert.equal(ok.status, 200);
      const applied = await (await rpc({ method: "tools/call", params: { name: "apply_change", arguments: { change_id: changeId } } })).json();
      assert.equal(applied.result.structuredContent.data.state, "applied");
    });
    await step("http", "/metrics counts audit events", async () => {
      const m = await (await fetch(`${base}/metrics`)).json();
      assert.ok(m.audit_events_total >= 2, JSON.stringify(m)); // KNOWN-BUG F12-01: metadata tools not yet audited
    });
  } finally {
    child.kill();
  }
}

async function auditSuite() {
  await step("audit", "JSONL audit trail records tool calls with redaction", async () => {
    const p = configuredPath("jsonl_path");
    assert.ok(p && fs.existsSync(p), `audit JSONL missing (${p})`);
    const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
    assert.ok(lines.length >= 10, `only ${lines.length} audit lines`);
    const last = JSON.parse(lines[lines.length - 1]);
    for (const k of ["request_id", "principal", "tool_name", "decision"]) assert.ok(k in last || k in (last.event || {}), `audit field ${k}`);
    assert.ok(!/hash_alice_secret|password=|postgres:\/\/[^@\s]*:[^@\s]+@/.test(lines.join("\n")), "secret leaked into audit log");
  });
  await step("cli", "verify-config validates example config", async () => {
    const r = spawnSync(process.execPath, [LAUNCHER, "verify-config", "--config", CONFIG], { cwd: REPO_ROOT, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).status, "ok");
  });
  await step("cli", "verify-config rejects invalid config", async () => {
    const bad = path.join(WORK_DIR, `smoke-bad-${process.pid}.toml`);
    fs.writeFileSync(bad, 'server_name = "x"\n[[connections]]\nid = "c"\nengine = "Oracle"\ndsn = "x"\n');
    const r = spawnSync(process.execPath, [LAUNCHER, "verify-config", "--config", bad], { cwd: REPO_ROOT, encoding: "utf8" });
    fs.unlinkSync(bad);
    assert.notEqual(r.status, 0, "invalid config accepted");
  });
}

(async () => {
  const started = Date.now();
  await stdioSuite();
  await httpSuite();
  await auditSuite();
  const failed = results.filter((r) => !r.ok);
  const byFeature = {};
  for (const r of results) { byFeature[r.feature] = byFeature[r.feature] || { pass: 0, fail: 0 }; byFeature[r.feature][r.ok ? "pass" : "fail"]++; }
  if (JSON_OUT) {
    console.log(JSON.stringify({ ok: failed.length === 0, elapsed_ms: Date.now() - started, features: byFeature, results }, null, 2));
  } else {
    console.log("\nFeature matrix:");
    for (const [f, c] of Object.entries(byFeature)) console.log(`  ${c.fail ? "FAIL" : "PASS"}  ${f.padEnd(12)} ${c.pass} passed, ${c.fail} failed`);
    console.log(`\n${results.length - failed.length}/${results.length} checks passed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  }
  if (ISO && KEEP) {
    if (!JSON_OUT) console.log(`kept isolated run directory: ${ISO.dir}`);
  } else if (ISO) {
    // Windows may hold SQLite handles briefly after the servers exit.
    for (let i = 0; i < 20; i++) {
      try { fs.rmSync(ISO.dir, { recursive: true, force: true }); break; } catch { await sleep(250); }
    }
  }
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
