#!/usr/bin/env node
"use strict";
/**
 * Build a certified demo ontology on an isolated copy of the example config and ask questions.
 *
 *   node scripts/ontology-demo.js [--keep]
 *
 * Steps (mirrors the real workflow):
 *   agent    : discover_ontology, propose_semantic_definition (MCP over stdio)
 *   reviewer : db-mcp ontology review / publish (out-of-band CLI, different principal)
 *   agent    : plan_semantic_query, ask_semantic_question
 * With --keep the isolated directory (config, sample.db, ontology.db, audit logs) is kept and printed.
 */
const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { createClient } = require(path.join(__dirname, "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(__dirname, "make-isolated-config.js"));

const ROOT = path.resolve(__dirname, "..");
const LAUNCHER = path.join(ROOT, "npm", "bin", "db-mcp.js");
const keep = process.argv.includes("--keep");

const CERTIFY = [
  "metric:main.orders.count",
  "metric:main.order_items.quantity.sum",
  "attribute:main.users.role",
  "attribute:main.order_items.sku",
  "relationship:main.orders(user_id)->main.users",
  "relationship:main.order_items(order_id)->main.orders",
  "relationship:main.order_items(sku)->main.inventory",
];

function cli(configPath, args) {
  const r = spawnSync(process.execPath, [LAUNCHER, "ontology", ...args, "--config", configPath], { cwd: ROOT, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`db-mcp ontology ${args[0]} failed: ${r.stderr.trim()}`);
  return JSON.parse(r.stdout);
}

(async () => {
  const { configPath, dir } = makeIsolatedConfig();
  const client = createClient({ config: configPath, principal: "demo-agent", role: "agent", timeoutMs: 30000 });
  const call = async (name, args) => (await client.rpc("tools/call", { name, arguments: args })).result.structuredContent;
  try {
    await client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "ontology-demo", version: "1" } });
    const disc = await call("discover_ontology", { connection: "local-sqlite" });
    console.log(`discovered ${disc.data.candidates} candidates ${JSON.stringify(disc.data.by_kind)}`);

    const drafts = [
      { name: "order value", synonyms: ["order total", "sales"], body: { type: "metric", base_table: "orders", aggregation: "sum", column: "total_cents", unit: "cents", grain: "order" } },
      { name: "completed order", synonyms: ["fulfilled order"], body: { type: "filter", table: "orders", column: "status", operator: "eq", value: "completed" } },
    ];
    const proposed = [];
    for (const d of drafts) {
      const r = await call("propose_semantic_definition", { connection: "local-sqlite", definition: d });
      if (r.status !== "ok") throw new Error(JSON.stringify(r));
      proposed.push([r.data.definition.def_id, r.data.definition.version]);
      console.log(`proposed ${r.data.definition.def_id} v${r.data.definition.version}`);
    }

    for (const [id, v] of [...CERTIFY.map((id) => [id, 1]), ...proposed]) {
      cli(configPath, ["review", "--connection", "local-sqlite", "--def-id", id, "--version", String(v), "--action", "approve", "--reviewer", "demo-reviewer", "--reason", "demo"]);
    }
    const pub = cli(configPath, ["publish", "--connection", "local-sqlite", "--reviewer", "demo-reviewer"]);
    console.log(`published ${pub.revision.revision_id} with ${pub.revision.def_refs.length} definitions`);

    for (const question of ["total order value by user role", "count of completed orders", "quantity sold by sku", "order total by sku", "how many late arrivals per service"]) {
      const a = await call("ask_semantic_question", { connection: "local-sqlite", question });
      const plan = a.data.plan;
      console.log(`\nQ: ${question}\n   status: ${plan.status}`);
      if (plan.sql) console.log(`   sql:    ${plan.sql}  params=${JSON.stringify(plan.params)}`);
      if (a.data.answered) console.log(`   rows:   ${JSON.stringify(a.rows)}`);
      if (plan.missing.length) console.log(`   why:    ${plan.missing.join("; ")}`);
    }
  } finally {
    client.close();
  }
  if (keep) {
    console.log(`\nkept ${dir}\n  config:   ${configPath}\n  ontology: ${path.join(dir, "ontology.db")}`);
  } else {
    setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 500);
  }
})().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
