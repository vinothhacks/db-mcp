#!/usr/bin/env node
"use strict";
/**
 * F16 - Governed ontology (semantic layer) end to end over Streamable HTTP + admin channel + CLI.
 *
 * Covers: tool surface (8 agent tools, no review tool), deterministic discovery, typed proposals,
 * separation of duties on /admin/ontology/review (401/403/400/200), publish, certified planning,
 * governed execution, plan pinning, refusal cases, answers equal to direct SQL (trailing filter
 * clauses, uncertified filters and aggregation mismatches refused), restricted/sensitive handling, role denial,
 * simulation disclosure, schema drift -> stale, audit trail, and `db-mcp ontology eval` gates.
 *
 * Run from the repo root: node npm/test/features/16-ontology.test.js   (exit 0 when every check passes)
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const LAUNCHER = path.join(ROOT, "npm", "bin", "db-mcp.js");
const { spawnDbMcpServer } = require(LAUNCHER);
const { makeIsolatedConfig } = require(path.join(ROOT, "scripts", "make-isolated-config.js"));

const AGENT_TOKEN = "f16-agent-token";
const ADMIN_TOKEN = "f16-admin-token";
const results = [];
/** Windows keeps files locked briefly after a child exits: retry, never fail a check on cleanup. */
async function safeRm(target) {
  for (let i = 0; i < 10; i++) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 300));
    }
  }
}
async function check(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`PASS  ${name}`);
  } catch (err) {
    results.push({ name, ok: false });
    console.log(`FAIL  ${name} :: ${String(err.message).split("\n")[0].slice(0, 400)}`);
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close((e) => (e ? reject(e) : resolve(port)));
    });
  });
}

async function startHttp(configPath, env) {
  const port = await freePort();
  const child = spawnDbMcpServer(["serve", "--transport", "http", "--bind", `127.0.0.1:${port}`, "--config", configPath], {
    cwd: ROOT,
    env: { DB_MCP_AUTH_TOKEN: "", DB_MCP_ADMIN_TOKEN: "", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 80; i++) {
    try {
      if ((await fetch(`${base}/health`)).ok) return { child, base, stderr };
    } catch {
      /* not up yet */
    }
    if (child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 150));
  }
  child.kill();
  throw new Error(`server did not start: ${stderr.join("")}`);
}

function client(base, principal = "f16-agent", role = "agent") {
  let id = 0;
  return async (name, args) => {
    const r = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${AGENT_TOKEN}`, "x-mcp-principal": principal, "x-mcp-role": role },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: name === "tools/list" ? "tools/list" : "tools/call", params: name === "tools/list" ? {} : { name, arguments: args } }),
    });
    const body = await r.json();
    return name === "tools/list" ? body.result : body.result.structuredContent;
  };
}

async function admin(base, route, payload, token = ADMIN_TOKEN) {
  const r = await fetch(`${base}/admin/ontology/${route}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(payload),
  });
  let body = null;
  try {
    body = await r.json();
  } catch {
    body = null;
  }
  return { status: r.status, body };
}

const CURATED = [
  "metric:main.orders.count",
  "metric:main.order_items.quantity.sum",
  "attribute:main.users.role",
  "attribute:main.order_items.sku",
  "attribute:main.inventory.sku",
  "relationship:main.orders(user_id)->main.users",
  "relationship:main.order_items(order_id)->main.orders",
  "relationship:main.order_items(sku)->main.inventory",
];

(async () => {
  const { configPath, dir } = makeIsolatedConfig();
  // Separate config for `ontology eval`: receives a copy of the published store before drift tests.
  const evalCfg = makeIsolatedConfig();
  const env = { DB_MCP_AUTH_TOKEN: AGENT_TOKEN, DB_MCP_ADMIN_TOKEN: ADMIN_TOKEN };
  let srv = await startHttp(configPath, env);
  const agent = client(srv.base);
  const proposals = {};
  try {
    await check("surface: 24 tools incl. 8 ontology tools; no review/publish tool for agents", async () => {
      const tools = (await agent("tools/list")).tools.map((t) => t.name);
      assert.equal(tools.length, 24, tools.join(","));
      for (const t of ["ontology_status", "discover_ontology", "search_terms", "describe_term", "trace_semantic_relationships", "propose_semantic_definition", "plan_semantic_query", "ask_semantic_question"]) {
        assert.ok(tools.includes(t), t);
      }
      assert.ok(!tools.some((t) => /review|publish|certify/.test(t)));
    });

    await check("status: not_ready before anything is published", async () => {
      const s = await agent("ontology_status", { connection: "local-sqlite" });
      assert.equal(s.status, "ok");
      assert.equal(s.data.readiness, "not_ready");
    });

    await check("discovery: candidates written, restricted table excluded, idempotent", async () => {
      const d1 = await agent("discover_ontology", { connection: "local-sqlite" });
      assert.equal(d1.status, "ok", JSON.stringify(d1));
      assert.ok(d1.data.candidates > 20);
      assert.ok(d1.warnings.some((w) => /restricted/.test(w)), JSON.stringify(d1.warnings));
      const d2 = await agent("discover_ontology", { connection: "local-sqlite" });
      assert.equal(d2.data.merge.inserted, 0);
      const s = await agent("search_terms", { connection: "local-sqlite", query: "internal secret value" });
      assert.ok(!JSON.stringify(s.data).includes("internal_secrets"));
    });

    await check("proposals: typed metric/filter drafts accepted; sensitive column refused", async () => {
      for (const [key, def] of Object.entries({
        order_value: { name: "order value", synonyms: ["order total", "sales", "revenue"], body: { type: "metric", base_table: "orders", aggregation: "sum", column: "total_cents", unit: "cents" } },
        item_revenue: { name: "item revenue", synonyms: ["revenue"], body: { type: "metric", base_table: "order_items", aggregation: "sum", column: "unit_price_cents" } },
        completed: { name: "completed order", body: { type: "filter", table: "orders", column: "status", operator: "eq", value: "completed" } },
      })) {
        const r = await agent("propose_semantic_definition", { connection: "local-sqlite", definition: def });
        assert.equal(r.status, "ok", JSON.stringify(r));
        assert.equal(r.data.definition.status, "proposed");
        proposals[key] = r.data.definition;
      }
      const bad = await agent("propose_semantic_definition", { connection: "local-sqlite", definition: { name: "pw", body: { type: "filter", table: "users", column: "password_hash", operator: "eq", value: "x" } } });
      assert.equal(bad.code, "ONTOLOGY_SENSITIVE_COLUMN");
    });

    await check("admin review: 401 without/with agent token", async () => {
      const p = { connection: "local-sqlite", def_id: proposals.order_value.def_id, version: 1, action: "approve", reviewer: "rev-1" };
      assert.equal((await admin(srv.base, "review", p, null)).status, 401);
      assert.equal((await admin(srv.base, "review", p, AGENT_TOKEN)).status, 401);
    });

    await check("admin review: proposer cannot certify own draft; agent role cannot review", async () => {
      const own = await admin(srv.base, "review", { connection: "local-sqlite", def_id: proposals.order_value.def_id, version: 1, action: "approve", reviewer: "f16-agent" });
      assert.equal(own.status, 400);
      assert.equal(own.body.code, "SELF_APPROVAL_FORBIDDEN");
      const asAgent = await admin(srv.base, "review", { connection: "local-sqlite", def_id: proposals.order_value.def_id, version: 1, action: "approve", reviewer: "someone", role: "agent" });
      assert.equal(asAgent.body.code, "SELF_APPROVAL_FORBIDDEN");
    });

    await check("admin review + publish over HTTP", async () => {
      const ids = [...CURATED.map((id) => [id, 1]), ...Object.values(proposals).map((d) => [d.def_id, d.version])];
      for (const [def_id, version] of ids) {
        const r = await admin(srv.base, "review", { connection: "local-sqlite", def_id, version, action: "approve", reviewer: "rev-1", reason: "f16" });
        assert.equal(r.status, 200, `${def_id}: ${JSON.stringify(r.body)}`);
        assert.equal(r.body.definition.status, "certified");
      }
      const pub = await admin(srv.base, "publish", { connection: "local-sqlite", reviewer: "rev-1" });
      assert.equal(pub.status, 200, JSON.stringify(pub.body));
      assert.equal(pub.body.revision.def_refs.length, ids.length);
      const s = await agent("ontology_status", { connection: "local-sqlite" });
      assert.equal(s.data.readiness, "ready", JSON.stringify(s.data.reasons));
      fs.copyFileSync(path.join(dir, "ontology.db"), path.join(evalCfg.dir, "ontology.db"));
    });

    let planHash = null;
    await check("plan: answerable with joins, params, provenance; ask executes through the governed executor", async () => {
      const p = await agent("plan_semantic_query", { connection: "local-sqlite", question: "total order value by user role" });
      assert.equal(p.data.status, "answerable", JSON.stringify(p.data.missing));
      assert.match(p.data.sql, /JOIN main\.users t1/);
      assert.equal(p.data.result_kind, "rule_based_calculation");
      planHash = p.data.plan_hash;
      const a = await agent("ask_semantic_question", { connection: "local-sqlite", question: "total order value by user role", plan_hash: planHash });
      assert.equal(a.status, "ok", JSON.stringify(a));
      assert.deepEqual(a.rows, [["admin", 4500], ["customer", 1900]]);
      const c = await agent("ask_semantic_question", { connection: "local-sqlite", question: "count of completed orders" });
      assert.deepEqual(c.rows, [[1]]);
    });

    await check("refusals: fan-out, ambiguity, missing metric, unknown dimension", async () => {
      const q = async (question) => (await agent("plan_semantic_query", { connection: "local-sqlite", question })).data;
      assert.equal((await q("order total by sku")).status, "not_answerable");
      assert.match((await q("order total by sku")).missing.join(" "), /multiplicative join/);
      assert.equal((await q("revenue")).status, "ambiguous");
      assert.equal((await q("how many late arrivals per service")).status, "not_answerable");
      assert.equal((await q("order count by warehouse region")).status, "not_answerable");
    });

    await check("answers equal direct SQL: trailing filter clauses applied; unmatched filters and aggregation mismatches refused", async () => {
      const ask = async (question) => agent("ask_semantic_question", { connection: "local-sqlite", question });
      const truth = async (sql) => (await agent("execute_query", { connection: "local-sqlite", sql })).rows;
      for (const [question, sql] of [
        ["total order value by user role for completed orders", "SELECT u.role, SUM(o.total_cents) FROM orders o JOIN users u ON u.id = o.user_id WHERE o.status = 'completed' GROUP BY u.role ORDER BY 2 DESC"],
        ["total order value where status is completed", "SELECT SUM(total_cents) FROM orders WHERE status = 'completed'"],
        ["total quantity by sku for completed orders", "SELECT i.sku, SUM(i.quantity) FROM order_items i JOIN orders o ON o.id = i.order_id WHERE o.status = 'completed' GROUP BY i.sku ORDER BY 2 DESC"],
      ]) {
        const a = await ask(question);
        assert.equal(a.status, "ok", JSON.stringify(a));
        assert.equal(a.data.answered, true, `${question}: ${JSON.stringify(a.data.plan.missing)}`);
        assert.deepEqual(a.rows, await truth(sql), question);
      }
      assert.deepEqual((await ask("total order value by user role for completed orders")).rows, [["admin", 4500]]);
      for (const [question, why] of [
        ["average order value", /certified metric 'order value' is a sum, not an average/],
        ["total order value for pending orders", /'pending'/],
        ["count of orders that are not completed", /'not'/],
        ["how many order items", /does not name what certified metric/],
      ]) {
        const a = await ask(question);
        assert.equal(a.data.answered, false, `${question}: ${JSON.stringify(a.rows)}`);
        assert.equal(a.data.plan.status, "not_answerable", question);
        assert.match(a.data.plan.missing.join(" "), why, question);
      }
    });

    await check("roles and disclosure: intern denied on prod-postgres; simulated backend disclosed", async () => {
      const intern = client(srv.base, "f16-intern", "intern");
      const d = await intern("ontology_status", { connection: "prod-postgres" });
      assert.equal(d.status, "denied");
      assert.equal(d.code, "UNAUTHORIZED_ROLE");
      const sim = await agent("ontology_status", { connection: "prod-postgres" });
      assert.ok(sim.warnings.some((w) => /simulated/.test(w)), JSON.stringify(sim.warnings));
    });

    await check("drift: renamed dependency -> stale, degraded status, pinned plan refused", async () => {
      const ddl = await agent("execute_query", { connection: "local-sqlite", sql: "ALTER TABLE order_items RENAME COLUMN quantity TO qty" });
      assert.equal(ddl.status, "ok", JSON.stringify(ddl));
      const p = await agent("plan_semantic_query", { connection: "local-sqlite", question: "quantity sold by sku" });
      assert.equal(p.data.status, "stale", JSON.stringify(p.data));
      const s = await agent("ontology_status", { connection: "local-sqlite" });
      assert.equal(s.data.readiness, "degraded");
      const pinned = await agent("ask_semantic_question", { connection: "local-sqlite", question: "total order value by user role", plan_hash: planHash });
      assert.equal(pinned.code, "ONTOLOGY_PLAN_MISMATCH");
    });

    await check("audit: ontology tools and admin actions recorded with transport", async () => {
      const lines = fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l).event || JSON.parse(l));
      const tools = new Set(lines.map((e) => e.tool_name));
      for (const t of ["ontology_status", "discover_ontology", "propose_semantic_definition", "plan_semantic_query", "ontology_publish", "ontology_review:approve"]) assert.ok(tools.has(t), `missing ${t}`);
      assert.ok(lines.some((e) => e.tool_name.startsWith("ask_semantic_question:")));
      assert.ok(lines.some((e) => e.tool_name === "ontology_review:approve" && e.transport === "http-admin" && e.decision === "denied"));
    });
  } finally {
    srv.child.kill();
  }

  await check("admin endpoints fail closed (403) when no admin token is configured", async () => {
    const noAdmin = makeIsolatedConfig({ transform: (t) => t.replace(/^admin_token\s*=.*$/m, "") });
    const s2 = await startHttp(noAdmin.configPath, { DB_MCP_AUTH_TOKEN: AGENT_TOKEN });
    try {
      const r = await admin(s2.base, "publish", { connection: "local-sqlite", reviewer: "x" }, "anything");
      assert.equal(r.status, 403);
      assert.equal(r.body.code, "ADMIN_TOKEN_NOT_CONFIGURED");
    } finally {
      s2.child.kill();
      await safeRm(noAdmin.dir);
    }
  });

  await check("CLI: ontology list/show work; review without persistent storage is refused", async () => {
    const list = spawnSync(process.execPath, [LAUNCHER, "ontology", "list", "--connection", "local-sqlite", "--status", "published", "--config", configPath], { cwd: ROOT, encoding: "utf8" });
    assert.equal(list.status, 0, list.stderr);
    assert.ok(JSON.parse(list.stdout).count >= 8);
    const mem = makeIsolatedConfig({ transform: (t) => t.replace(/^storage_path = ".*ontology\.db"$/m, "") });
    const r = spawnSync(process.execPath, [LAUNCHER, "ontology", "review", "--connection", "local-sqlite", "--def-id", "x", "--version", "1", "--action", "approve", "--reviewer", "r", "--config", mem.configPath], { cwd: ROOT, encoding: "utf8" });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /storage_path/);
    await safeRm(mem.dir);
  });

  await check("CLI: golden evaluation gates pass on a fresh schema", async () => {
    // eval rebuilds the runtime from config (init_sql restores the fixture schema), then plans every golden question.
    const r = spawnSync(process.execPath, [LAUNCHER, "ontology", "eval", "--connection", "local-sqlite", "--cases", path.join(ROOT, "research", "ontology", "golden-local-sqlite.json"), "--config", evalCfg.configPath], { cwd: ROOT, encoding: "utf8", timeout: 120000 });
    const report = JSON.parse(r.stdout || "{}");
    assert.equal(r.status, 0, `${r.stderr}\n${JSON.stringify(report.cases, null, 1)}`);
    assert.ok(report.gates.every((g) => g.passed));
  });

  await safeRm(dir);
  await safeRm(evalCfg.dir);
  const failed = results.filter((r) => !r.ok);
  console.log(`\n[F16] ${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
