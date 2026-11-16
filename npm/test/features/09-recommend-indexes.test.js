#!/usr/bin/env node
"use strict";
/**
 * F09 - recommend_indexes feature verification (self-contained, node:assert only).
 *
 *   node npm/test/features/09-recommend-indexes.test.js            # from repo root
 *   F09_STRICT=1 node npm/test/features/09-recommend-indexes.test.js   # known bugs also fail the run
 *
 * Spawns the prebuilt db-mcp-server binary over stdio against private isolated configs
 * (never config/db-mcp.example.toml itself). One line per check. Exit code 0 when every
 * check that is not tagged KNOWN-BUG passes. Known-bug checks encode the CORRECT behaviour;
 * they are reported as XFAIL while the bug is open and XPASS once it has been fixed
 * (and should then have their tag removed).
 *
 * Known-bug ids (see final report for root causes):
 *   F09-01 no "simulated backend / synthetic cost" warning on prod-postgres
 *   F09-02 hypopg_validated=true although no HypoPG evaluation was ever run (heuristic labelled as validated)
 *   F09-03 FK-derived candidates always emitted, outrank and can displace the query-driven candidate
 *   F09-04 has_hypopg=false output not labelled heuristic; validation_procedure still prescribes HypoPG
 *   F09-05 FK column injected as leading column into query-derived composite (GROUP BY status -> (user_id,status))
 *   F09-06 primary-key column included in composite candidates
 *   F09-07 LIKE with leading wildcard still produces a B-Tree candidate
 *   F09-08 expression predicate lower(col) silently dropped (no functional index, no note)
 *   F09-09 OR predicates merged into one composite index
 *   F09-10 nonexistent column -> bogus candidate, no warning
 *   F09-11 nonexistent table  -> bogus candidate, no warning
 *   F09-12 one bucket per table, no frequency weighting (most frequent predicate not leading)
 *   F09-13 unparseable SQL silently ignored (no warning)
 *   F09-14 workload fallback / pg_stat_statements-unavailable not signalled; synthetic queries shown as observed
 *   F09-15 max_recommendations=0 silently becomes 10
 *   F09-16 negative / non-integer max_recommendations silently default to 5
 *   F09-17 `queries` of wrong JSON type silently ignored (falls back to workload)
 *   F09-18 SQLite DDL uses `ON main.orders` (invalid SQLite syntax)
 *   F09-19 MySQL (supports_index_advisor=false) returns recommendations instead of structured denial
 *   F09-20 restricted_tables policy bypassed (candidate for internal_secrets; workload fallback lists it)
 *   F09-21 no audit event recorded for recommend_indexes
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));

const STRICT = process.env.F09_STRICT === "1";
const counts = { pass: 0, fail: 0, xfail: 0, xpass: 0 };
const clients = [];
const tempDirs = [];

async function check(name, fn, opts = {}) {
  const tag = opts.knownBug ? ` [KNOWN-BUG ${opts.knownBug}]` : "";
  try {
    await fn();
    if (opts.knownBug) { counts.xpass++; console.log(`XPASS ${name}${tag} (bug appears fixed - remove tag)`); }
    else { counts.pass++; console.log(`PASS  ${name}`); }
  } catch (err) {
    const msg = String(err && err.message ? err.message : err).split("\n")[0].slice(0, 260);
    if (opts.knownBug) { counts.xfail++; console.log(`XFAIL ${name}${tag} :: ${msg}`); }
    else { counts.fail++; console.log(`FAIL  ${name} :: ${msg}`); }
  }
}

function pgBlock(text, fn) {
  const i = text.indexOf('id = "prod-postgres"');
  const j = text.indexOf("[[connections]]", i);
  return text.slice(0, i) + fn(text.slice(i, j)) + text.slice(j);
}
function appendPgInitSql(block, sql) {
  const k = block.lastIndexOf('"""');
  return block.slice(0, k) + sql + "\n" + block.slice(k);
}
function isoConfig(label, transform) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `f09-${label}-`));
  tempDirs.push(dir);
  return makeIsolatedConfig({ dir, transform }).configPath;
}
async function connect(configPath) {
  const c = createClient({ config: configPath, principal: "f09-agent", role: "agent", timeoutMs: 60000 });
  clients.push(c);
  const init = await c.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f09", version: "0" } });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  c.notify("notifications/initialized", {});
  const call = async (tool, args) => {
    const resp = await c.rpc("tools/call", { name: tool, arguments: args });
    if (resp.error) throw new Error(`${tool} JSON-RPC error: ${JSON.stringify(resp.error)}`);
    return resp.result.structuredContent;
  };
  return { call, client: c };
}

const ENVELOPE_KEYS = ["request_id", "connection", "status", "columns", "rows", "returned_rows", "truncated", "warnings", "schema_version"];
const EXPECTED_COLUMNS = ["observed_issue", "evidence_timestamp", "relevant_queries", "suggested_ddl", "estimated_benefit", "write_storage_tradeoffs", "required_privileges", "validation_procedure", "recovery_considerations"];
const REC_FIELDS = ["id", "table_name", "columns", "index_type", "observed_issue", "evidence", "collected_at", "relevant_queries", "suggested_ddl", "estimated_benefit", "hypopg_validated", "assumptions", "write_storage_tradeoffs", "required_privileges_extensions", "validation_procedure", "recovery_considerations"];

function okEnvelope(p, label) {
  assert.equal(p.status, "ok", `${label}: expected ok, got ${JSON.stringify(p).slice(0, 300)}`);
  for (const k of ENVELOPE_KEYS) assert.ok(k in p, `${label}: missing envelope key ${k}`);
  assert.equal(p._meta?.provenance?.untrusted_content, true, `${label}: _meta.provenance.untrusted_content`);
  assert.ok(Array.isArray(p.data), `${label}: data must be an array of recommendations`);
  assert.equal(p.returned_rows, p.data.length, `${label}: returned_rows != data.length`);
  assert.equal(p.rows.length, p.data.length, `${label}: rows.length != data.length`);
  return p;
}
const shortTable = (r) => r.table_name.split(".").pop();
const recsFor = (p, table) => p.data.filter((r) => shortTable(r) === table);
const queryDriven = (p) => p.data.filter((r) => r.relevant_queries.some((q) => !q.startsWith("/*")));
const isDenied = (p, codes) => { assert.equal(p.status, "denied", `expected denied, got ${JSON.stringify(p).slice(0, 200)}`); if (codes) assert.ok(codes.includes(p.code), `code ${p.code} not in ${codes}`); return p; };

async function main() {
  // ---- isolated servers -------------------------------------------------------------------
  const cfgDefault = isoConfig("default");                                                   // has_hypopg=true, has_pg_stat_statements=true
  const cfgNoExt = isoConfig("noext", (t) => pgBlock(t, (b) => b.replace("has_hypopg = true", "has_hypopg = false").replace("has_pg_stat_statements = true", "has_pg_stat_statements = false")));
  const cfgSeeded = isoConfig("seeded", (t) => pgBlock(t, (b) => appendPgInitSql(b, "CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);")));
  const auditDir = path.dirname(cfgDefault);

  const d = await connect(cfgDefault);
  const n = await connect(cfgNoExt);
  const s = await connect(cfgSeeded);
  const PG = "prod-postgres";
  const ri = (queries, extra = {}) => d.call("recommend_indexes", Object.assign({ connection: PG, queries }, extra));

  // ---- 0. capabilities ----------------------------------------------------------------------
  let caps = {};
  await check("capabilities: pg advisor+hypopg, sqlite advisor only, mysql none", async () => {
    const lc = await d.call("list_connections", {});
    for (const c of lc.data) caps[c.id] = c.capabilities;
    assert.equal(caps[PG].supports_index_advisor, true);
    assert.equal(caps[PG].supports_hypothetical_indexes, true);
    assert.equal(caps["local-sqlite"].supports_index_advisor, true);
    assert.equal(caps["local-sqlite"].supports_hypothetical_indexes, false);
    assert.equal(caps["analytics-mysql"].supports_index_advisor, false);
  });

  // ---- 1. envelope + contract ---------------------------------------------------------------
  const base = await ri(["SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"], { max_recommendations: 5 });
  await check("envelope: ok, keys, provenance, returned_rows == recommendation count", async () => {
    okEnvelope(base, "base");
    assert.equal(base.connection, PG);
    assert.equal(base.truncated, false);
    assert.match(base.request_id, /^req_/);
    assert.equal(typeof base.schema_version, "string");
  });
  await check("envelope: 9 tabular columns match contract and every row has 9 cells", async () => {
    assert.deepEqual(base.columns.map((c) => c.name), EXPECTED_COLUMNS);
    for (const row of base.rows) assert.equal(row.length, 9);
    base.rows.forEach((row, i) => assert.equal(row[3], base.data[i].suggested_ddl, "row ddl != data ddl"));
  });
  await check("recommendation object: all contract fields present and typed", async () => {
    for (const r of base.data) {
      for (const f of REC_FIELDS) assert.ok(f in r, `missing field ${f}`);
      assert.ok(Array.isArray(r.columns) && r.columns.length > 0, "columns");
      assert.equal(r.index_type, "btree");
      assert.match(r.suggested_ddl, /^CREATE INDEX /);
      assert.ok(typeof r.estimated_cost_reduction_pct === "number" && r.estimated_cost_reduction_pct >= 0 && r.estimated_cost_reduction_pct <= 100, "pct range");
      assert.equal(typeof r.evidence, "object");
      assert.ok(Array.isArray(r.assumptions) && r.assumptions.length > 0, "assumptions");
      assert.ok(Array.isArray(r.required_privileges_extensions) && r.required_privileges_extensions.length > 0);
    }
  });
  await check("equality+equality -> composite (user_id, status) with valid PG CONCURRENTLY DDL", async () => {
    const [o] = recsFor(base, "orders");
    assert.ok(o, "no orders recommendation");
    assert.deepEqual(o.columns, ["user_id", "status"]);
    assert.equal(o.suggested_ddl, "CREATE INDEX CONCURRENTLY idx_orders_user_id_status ON public.orders (user_id, status);");
    assert.match(o.suggested_ddl, /^CREATE INDEX CONCURRENTLY idx_\w+ ON public\.\w+ \([\w, ]+\);$/);
  });
  await check("evidence: relevant_queries cites the submitted query; evidence has baseline/projected cost and table", async () => {
    const [o] = recsFor(base, "orders");
    assert.ok(o.relevant_queries.includes("SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"));
    assert.equal(o.evidence.table, "public.orders");
    assert.equal(typeof o.evidence.baseline_estimated_cost, "number");
    assert.equal(typeof o.evidence.projected_index_cost, "number");
    assert.ok(o.evidence.projected_index_cost < o.evidence.baseline_estimated_cost, "projected cost must be lower");
    assert.ok(Array.isArray(o.evidence.existing_indexes));
  });
  await check("benefit text: percentage and before->after costs consistent with evidence", async () => {
    for (const r of base.data) {
      const m = r.estimated_benefit.match(/~([\d.]+)% \(([\d.]+) -> ([\d.]+)\)/);
      assert.ok(m, `benefit text format: ${r.estimated_benefit}`);
      assert.equal(Number(m[1]), r.estimated_cost_reduction_pct);
      assert.ok(Math.abs(Number(m[2]) - r.evidence.baseline_estimated_cost) < 0.06);
      assert.ok(Math.abs(Number(m[3]) - r.evidence.projected_index_cost) < 0.06);
    }
  });
  await check("trade-offs / validation / recovery texts are substantive", async () => {
    for (const r of base.data) {
      assert.match(r.write_storage_tradeoffs, /INSERT|UPDATE|write/i);
      assert.match(r.write_storage_tradeoffs, /disk|storage|footprint|size/i);
      assert.match(r.validation_procedure, /EXPLAIN|hypopg/i);
      const idxName = r.suggested_ddl.match(/INDEX (?:CONCURRENTLY )?(\w+)/)[1];
      assert.ok(r.recovery_considerations.includes(`DROP INDEX CONCURRENTLY IF EXISTS ${idxName};`), "recovery must name the DROP");
      assert.ok(r.required_privileges_extensions.some((x) => /CREATE privilege|ownership/i.test(x)));
    }
  });
  await check("honesty: no claim that costs were measured on a live database", async () => {
    assert.doesNotMatch(JSON.stringify(base), /measured on (a |the )?live|live (production )?database|actual (plan|cost)/i);
  });
  await check("honesty: prod-postgres response warns that backend is simulated / costs synthetic", async () => {
    assert.ok(base.warnings.some((w) => /simulat|synthetic|not (a )?live/i.test(w)), `warnings=${JSON.stringify(base.warnings)}`);
  });
  await check("honesty: hypopg_validated only true when a hypothetical index was really evaluated", async () => {
    // Correct behaviour: a HypoPG-validated estimate must differ from the pure heuristic estimate
    // (base * 0.08, floor 1.5) that the has_hypopg=false path produces for the same query.
    const sameQ = ["SELECT * FROM users WHERE email = 'a'"];
    const withExt = recsFor(await ri(sameQ), "users")[0];
    const noExt = recsFor(await n.call("recommend_indexes", { connection: PG, queries: sameQ }), "users")[0];
    assert.ok(withExt && noExt, "users recommendation missing");
    if (withExt.hypopg_validated) {
      const heuristicProj = Math.max(withExt.evidence.baseline_estimated_cost * 0.08, 1.5);
      assert.ok(Math.abs(withExt.evidence.projected_index_cost - heuristicProj) > 1e-6
        || withExt.evidence.projected_index_cost !== noExt.evidence.projected_index_cost,
        `hypopg_validated=true but projected cost ${withExt.evidence.projected_index_cost} is exactly the heuristic formula`);
      assert.ok(Object.keys(withExt.evidence).some((k) => /hypopg|hypothetical/i.test(k) && k !== "hypopg_validated"), "no HypoPG measurement in evidence");
    }
  }, { knownBug: "F09-02" });
  await check("has_hypopg=false: hypopg_validated is false on every recommendation", async () => {
    const p = okEnvelope(await n.call("recommend_indexes", { connection: PG, queries: ["SELECT * FROM users WHERE email = 'a'"] }), "noext");
    assert.ok(p.data.length > 0);
    for (const r of p.data) { assert.equal(r.hypopg_validated, false); assert.equal(r.evidence.hypopg_validated, false); }
  });
  await check("has_hypopg=false: output clearly labelled heuristic-only and does not prescribe HypoPG validation", async () => {
    const p = await n.call("recommend_indexes", { connection: PG, queries: ["SELECT * FROM users WHERE email = 'a'"] });
    const [u] = recsFor(p, "users");
    const text = [u.estimated_benefit, ...u.assumptions, ...p.warnings].join(" ");
    assert.match(text, /heuristic|not validated|unvalidated|estimate only/i, "no heuristic label");
    assert.doesNotMatch(u.validation_procedure, /^1\. Verify virtual plan with HypoPG/, "validation procedure prescribes an extension that is not installed");
  }, { knownBug: "F09-04" });

  // ---- 2. candidate quality (users table has no FKs -> clean signal; orders exercises FK merge) --
  await check("range predicate: equality first, range column last (user_id, created_at)", async () => {
    const [o] = recsFor(await ri(["SELECT * FROM orders WHERE user_id = 1 AND created_at > '2025-01-01'"]), "orders");
    assert.deepEqual(o.columns, ["user_id", "created_at"]);
  });
  await check("ORDER BY: equality column then sort column (role, created_at)", async () => {
    const [u] = recsFor(await ri(["SELECT * FROM users WHERE role = 'admin' ORDER BY created_at DESC"]), "users");
    assert.deepEqual(u.columns, ["role", "created_at"]);
  });
  await check("GROUP BY column becomes a candidate (users.role)", async () => {
    const [u] = recsFor(await ri(["SELECT role, count(*) FROM users GROUP BY role"]), "users");
    assert.deepEqual(u.columns, ["role"]);
  });
  await check("GROUP BY on FK table: candidate is (status) only, FK column must not be injected as leading column", async () => {
    const [o] = recsFor(await ri(["SELECT status, count(*) FROM orders GROUP BY status"]), "orders");
    assert.ok(o, "no orders recommendation");
    assert.deepEqual(o.columns, ["status"]);
  }, { knownBug: "F09-05" });
  await check("JOIN key: orders.user_id recommended; users side not (id is PK)", async () => {
    const p = await ri(["SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id WHERE u.email = 'a'"]);
    const [o] = recsFor(p, "orders");
    assert.deepEqual(o.columns, ["user_id"]);
    assert.ok(recsFor(p, "users").length >= 1, "users.email candidate expected");
  });
  await check("PK column never part of a composite (users (email), not (id, email))", async () => {
    const p = await ri(["SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id WHERE u.email = 'a'"]);
    const [u] = recsFor(p, "users");
    assert.deepEqual(u.columns, ["email"]);
    const p2 = await ri(["SELECT * FROM orders WHERE id = 5"]);
    assert.ok(recsFor(p2, "orders").every((r) => !r.columns.includes("id")), "orders.id (PK) recommended");
  }, { knownBug: "F09-06" });
  await check("PK-only predicate on users yields no users recommendation", async () => {
    assert.equal(recsFor(await ri(["SELECT * FROM users WHERE id = 1"]), "users").length, 0);
  });
  await check("IN list -> equality candidate (users.role)", async () => {
    assert.deepEqual(recsFor(await ri(["SELECT * FROM users WHERE role IN ('a','b')"]), "users")[0].columns, ["role"]);
  });
  await check("LIKE 'abc%' (prefix) -> candidate on users.email", async () => {
    assert.deepEqual(recsFor(await ri(["SELECT * FROM users WHERE email LIKE 'abc%'"]), "users")[0].columns, ["email"]);
  });
  await check("LIKE '%abc' (leading wildcard) -> no B-Tree candidate", async () => {
    assert.equal(recsFor(await ri(["SELECT * FROM users WHERE email LIKE '%abc'"]), "users").length, 0);
  }, { knownBug: "F09-07" });
  await check("lower(email) = ... -> no plain-column candidate", async () => {
    const p = await ri(["SELECT * FROM users WHERE lower(email) = 'a'"]);
    assert.equal(recsFor(p, "users").length, 0);
  });
  await check("lower(email) = ... -> functional index suggested or warning explains expression predicate was skipped", async () => {
    const p = await ri(["SELECT * FROM users WHERE lower(email) = 'a'"]);
    const functional = p.data.some((r) => /lower\s*\(/i.test(r.suggested_ddl));
    const warned = p.warnings.some((w) => /expression|function|lower/i.test(w));
    assert.ok(functional || warned, "expression predicate silently dropped");
  }, { knownBug: "F09-08" });
  await check("OR predicates are not merged into a single composite index", async () => {
    const p = await ri(["SELECT * FROM users WHERE role = 'a' OR email = 'b'"]);
    assert.ok(recsFor(p, "users").every((r) => !(r.columns.includes("role") && r.columns.includes("email"))), "composite (role,email) cannot serve an OR");
  }, { knownBug: "F09-09" });
  await check("subquery predicates extracted (orders.user_id and users.role)", async () => {
    const p = await ri(["SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE role = 'admin')"]);
    assert.deepEqual(recsFor(p, "orders")[0].columns, ["user_id"]);
    assert.deepEqual(recsFor(p, "users")[0].columns, ["role"]);
  });
  await check("CTE: predicates resolved to base table, CTE name is not a table", async () => {
    const p = await ri(["WITH recent AS (SELECT * FROM users WHERE created_at > '2025') SELECT * FROM recent WHERE role = 'x'"]);
    assert.deepEqual(recsFor(p, "users")[0].columns, ["role", "created_at"]);
    assert.equal(recsFor(p, "recent").length, 0);
  });
  await check("alias resolved to real table (users AS u)", async () => {
    const p = await ri(["SELECT u.id FROM users AS u WHERE u.role = 'x'"]);
    assert.equal(recsFor(p, "u").length, 0);
    assert.deepEqual(recsFor(p, "users")[0].columns, ["role"]);
  });
  await check("schema-qualified table name resolves (public.users)", async () => {
    const [u] = recsFor(await ri(["SELECT * FROM public.users WHERE email = 'a'"]), "users");
    assert.equal(u.table_name, "public.users");
  });
  await check("IS NULL predicate yields candidate on that column", async () => {
    assert.deepEqual(recsFor(await ri(["SELECT * FROM users WHERE role IS NULL"]), "users")[0].columns, ["role"]);
  });
  await check("BETWEEN after equality (role, created_at)", async () => {
    assert.deepEqual(recsFor(await ri(["SELECT * FROM users WHERE role = 'x' AND created_at BETWEEN '2024' AND '2025'"]), "users")[0].columns, ["role", "created_at"]);
  });
  await check("nonexistent column -> no bogus candidate and a warning", async () => {
    const p = await ri(["SELECT * FROM users WHERE nonexistent_col = 1"]);
    assert.ok(p.data.every((r) => !r.columns.includes("nonexistent_col")), "indexed a column that does not exist");
    assert.ok(p.warnings.some((w) => /nonexistent_col|unknown column|not found/i.test(w)), "no warning");
  }, { knownBug: "F09-10" });
  await check("nonexistent table -> no bogus candidate and a warning", async () => {
    const p = await ri(["SELECT * FROM ghosts WHERE x = 1"]);
    assert.equal(recsFor(p, "ghosts").length, 0, "CREATE INDEX on a table that does not exist");
    assert.ok(p.warnings.some((w) => /ghosts|unknown table|not found/i.test(w)), "no warning");
  }, { knownBug: "F09-11" });
  await check("existing index detected: WHERE user_id = 1 not re-recommended when idx_orders_user exists", async () => {
    const p = okEnvelope(await s.call("recommend_indexes", { connection: PG, queries: ["SELECT * FROM orders WHERE user_id = 1"] }), "seeded");
    assert.equal(recsFor(p, "orders").length, 0);
    assert.equal(p.data.filter((r) => r.columns.includes("user_id") && shortTable(r) === "orders").length, 0);
  });
  await check("existing index listed in evidence and wider composite still proposed (user_id, status)", async () => {
    const p = await s.call("recommend_indexes", { connection: PG, queries: ["SELECT * FROM orders WHERE user_id = 1 AND status = 'x'"] });
    const [o] = recsFor(p, "orders");
    assert.deepEqual(o.columns, ["user_id", "status"]);
    assert.ok(o.evidence.existing_indexes.includes("idx_orders_user"));
  });
  await check("existing FK index: status-only query yields (status) with no FK column injected", async () => {
    const [o] = recsFor(await s.call("recommend_indexes", { connection: PG, queries: ["SELECT * FROM orders WHERE status = 'x'"] }), "orders");
    assert.deepEqual(o.columns, ["status"]);
  });
  await check("multiple queries aggregated: relevant_queries lists each distinct query once", async () => {
    const qs = ["SELECT * FROM users WHERE role = 'a'", "SELECT * FROM users WHERE role = 'b'", "SELECT * FROM users WHERE email = 'x'", "SELECT * FROM users WHERE role = 'a'"];
    const p = await ri(qs);
    const all = recsFor(p, "users").flatMap((r) => r.relevant_queries);
    for (const q of new Set(qs)) assert.ok(all.includes(q), `missing ${q}`);
    assert.equal(all.length, new Set(all).size, "duplicate relevant_queries");
    const ids = p.data.map((r) => r.id);
    assert.equal(ids.length, new Set(ids).size, "duplicate recommendations");
  });
  await check("frequency weighting: most frequent predicate (role x2) leads a candidate", async () => {
    const p = await ri(["SELECT * FROM users WHERE role = 'a'", "SELECT * FROM users WHERE role = 'b'", "SELECT * FROM users WHERE email = 'x'"]);
    assert.ok(recsFor(p, "users").some((r) => r.columns[0] === "role"), `got ${JSON.stringify(recsFor(p, "users").map((r) => r.columns))}`);
  }, { knownBug: "F09-12" });
  await check("UPDATE ... WHERE user_id = 1: predicate still used", async () => {
    assert.deepEqual(recsFor(await ri(["UPDATE orders SET status = 'x' WHERE user_id = 1"]), "orders")[0].columns, ["user_id"]);
  });
  await check("invalid SQL in list: valid query still processed", async () => {
    const p = okEnvelope(await ri(["SELEC garbage FROM", "SELECT * FROM users WHERE email = 'a'"]), "mix");
    assert.deepEqual(recsFor(p, "users")[0].columns, ["email"]);
  });
  await check("invalid SQL in list: warning names the unparseable query", async () => {
    const p = await ri(["SELEC garbage FROM", "SELECT * FROM users WHERE email = 'a'"]);
    assert.ok(p.warnings.some((w) => /pars|invalid|syntax|skipped/i.test(w)), `warnings=${JSON.stringify(p.warnings)}`);
  }, { knownBug: "F09-13" });

  // ---- 3. query-set / limits ----------------------------------------------------------------
  await check("explicit queries: every recommendation is backed by a submitted query (no FK-only noise)", async () => {
    const p = await ri(["SELECT * FROM users WHERE email = 'a'"]);
    assert.ok(p.data.every((r) => r.relevant_queries.some((q) => !q.startsWith("/*"))), `FK-only rows: ${p.data.filter((r) => r.relevant_queries.every((q) => q.startsWith("/*"))).map((r) => r.table_name)}`);
  }, { knownBug: "F09-03" });
  await check("max_recommendations=1 keeps the query-driven candidate", async () => {
    const p = await ri(["SELECT * FROM users WHERE email = 'a'"], { max_recommendations: 1 });
    assert.equal(p.returned_rows, 1);
    assert.equal(shortTable(p.data[0]), "users", `kept ${p.data[0].table_name} instead of users`);
  }, { knownBug: "F09-03" });
  await check("max_recommendations=3 and =100 honoured", async () => {
    const p3 = await ri(["SELECT * FROM users WHERE email = 'a'"], { max_recommendations: 3 });
    assert.ok(p3.returned_rows <= 3);
    const p100 = await ri(["SELECT * FROM users WHERE email = 'a'"], { max_recommendations: 100 });
    assert.ok(p100.returned_rows >= p3.returned_rows && p100.returned_rows <= 100);
  });
  await check("max_recommendations=0 -> zero recommendations or INVALID_ARGUMENT (not silently 10)", async () => {
    const p = await ri([], { max_recommendations: 0 });
    assert.ok(p.status === "denied" || p.returned_rows === 0, `returned ${p.returned_rows}`);
  }, { knownBug: "F09-15" });
  await check("max_recommendations negative / non-integer -> INVALID_ARGUMENT", async () => {
    for (const v of [-1, 2.7, "abc"]) {
      const p = await ri(["SELECT * FROM users WHERE email = 'a'"], { max_recommendations: v });
      assert.equal(p.status, "denied", `max_recommendations=${JSON.stringify(v)} accepted (rows=${p.returned_rows})`);
      assert.equal(p.code, "INVALID_ARGUMENT");
    }
  }, { knownBug: "F09-16" });
  await check("queries omitted / empty -> ok envelope (workload fallback)", async () => {
    okEnvelope(await d.call("recommend_indexes", { connection: PG }), "omitted");
    okEnvelope(await ri([]), "empty");
  });
  await check("workload fallback is signalled (warning / evidence says queries came from workload, not caller)", async () => {
    const p = await ri([]);
    const signalled = p.warnings.some((w) => /workload|pg_stat_statements|no queries/i.test(w)) || p.data.every((r) => r.evidence.source === "workload" || /workload/i.test(r.observed_issue));
    assert.ok(signalled, `warnings=${JSON.stringify(p.warnings)}`);
  }, { knownBug: "F09-14" });
  await check("workload fallback without pg_stat_statements warns that workload data is unavailable/synthetic", async () => {
    const p = await n.call("recommend_indexes", { connection: PG, queries: [] });
    assert.ok(p.status === "denied" || p.warnings.some((w) => /pg_stat_statements|synthetic|unavailable|heuristic/i.test(w)), `warnings=${JSON.stringify(p.warnings)}`);
  }, { knownBug: "F09-14" });
  await check("queries of wrong JSON type -> INVALID_ARGUMENT (not silent workload fallback)", async () => {
    const p1 = await d.call("recommend_indexes", { connection: PG, queries: "SELECT * FROM users WHERE email = 'a'" });
    assert.equal(p1.status, "denied", "string queries accepted");
    const p2 = await d.call("recommend_indexes", { connection: PG, queries: [1, null, { a: 1 }] });
    assert.equal(p2.status, "denied", "non-string array accepted");
  }, { knownBug: "F09-17" });
  await check("50 queries processed under 5s", async () => {
    const qs = []; for (let i = 0; i < 50; i++) qs.push(`SELECT * FROM users WHERE role = 'r${i % 5}' AND created_at > '2025-0${(i % 9) + 1}' ORDER BY email`);
    const t0 = Date.now();
    const p = okEnvelope(await ri(qs), "fifty");
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0}ms`);
    const cols = recsFor(p, "users")[0].columns;
    assert.equal(cols[0], "role", "equality column must lead");
    assert.deepEqual([...cols].sort(), ["created_at", "email", "role"]); // range vs sort order is ambiguous for one B-Tree
  });
  await check("determinism: identical calls -> identical recommendations and order (modulo timestamps)", async () => {
    const qs = ["SELECT * FROM orders WHERE user_id = 1 AND status = 'x'", "SELECT * FROM users WHERE email = 'a'"];
    const strip = (p) => p.data.map((r) => { const c = { ...r }; delete c.collected_at; return c; });
    const a = await ri(qs), b = await ri(qs);
    assert.notEqual(a.request_id, b.request_id);
    assert.deepEqual(strip(a), strip(b));
    assert.deepEqual(a.rows.map((r) => r[3]), b.rows.map((r) => r[3]));
  });
  await check("sensitive-column predicate (password_hash) handled without error", async () => {
    okEnvelope(await ri(["SELECT * FROM users WHERE password_hash = 'x'"]), "sensitive");
  });
  await check("restricted table: no candidate for internal_secrets (policy parity with execute_query/explain_query)", async () => {
    const p = await ri(["SELECT * FROM internal_secrets WHERE secret_key = 'x'"]);
    if (p.status === "ok") assert.equal(recsFor(p, "internal_secrets").length, 0, "recommended an index on a restricted table");
    else isDenied(p, ["RESTRICTED_TABLE_FORBIDDEN", "RESTRICTED_TABLE"]);
    const w = await ri([]);
    assert.equal(recsFor(w, "internal_secrets").length, 0, "workload fallback lists restricted table");
  });

  // ---- 4. engines ---------------------------------------------------------------------------
  let sqliteRec = null;
  await check("local-sqlite: recommendations without HypoPG, SQLite validation text, no CONCURRENTLY", async () => {
    const p = okEnvelope(await d.call("recommend_indexes", { connection: "local-sqlite", queries: ["SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"] }), "sqlite");
    assert.equal(p.connection, "local-sqlite");
    const [o] = recsFor(p, "orders");
    sqliteRec = o;
    assert.deepEqual(o.columns, ["user_id", "status"]);
    for (const r of p.data) { assert.equal(r.hypopg_validated, false); assert.doesNotMatch(r.suggested_ddl, /CONCURRENTLY/); assert.doesNotMatch(r.recovery_considerations, /CONCURRENTLY/); }
    assert.match(o.validation_procedure, /EXPLAIN QUERY PLAN/);
    assert.doesNotMatch(o.validation_procedure, /hypopg/i);
  });
  await check("local-sqlite: suggested DDL is valid SQLite (executes on the fixture)", async () => {
    assert.ok(sqliteRec, "no sqlite recommendation captured");
    const r = await d.call("execute_query", { connection: "local-sqlite", sql: sqliteRec.suggested_ddl });
    assert.equal(r.status, "ok", `${sqliteRec.suggested_ddl} -> ${r.code}: ${r.message}`);
  }, { knownBug: "F09-18" });
  await check("prod-postgres: suggested DDL accepted by propose_change (parses as DDL, compensating DROP)", async () => {
    const [o] = recsFor(base, "orders");
    const r = await d.call("propose_change", { connection: PG, sql: o.suggested_ddl });
    assert.equal(r.status, "ok", JSON.stringify(r).slice(0, 200));
    assert.match(r.data.change_id, /^chg_/);
    assert.equal(r.data.compensating_sql, "DROP INDEX CONCURRENTLY IF EXISTS idx_orders_user_id_status;");
  });
  await check("analytics-mysql (supports_index_advisor=false): structured unsupported denial with next_action", async () => {
    const p = await d.call("recommend_indexes", { connection: "analytics-mysql", queries: ["SELECT * FROM orders WHERE user_id = 1"] });
    assert.equal(p.status, "denied", `got ${p.status} with ${p.returned_rows} rows`);
    assert.match(String(p.code), /UNSUPPORTED|CAPABILITY|NOT_SUPPORTED/);
    assert.equal(typeof p.next_action, "string");
  }, { knownBug: "F09-19" });
  await check("unknown connection -> CONNECTION_NOT_FOUND with next_action", async () => {
    const p = isDenied(await d.call("recommend_indexes", { connection: "nope", queries: ["SELECT 1"] }), ["CONNECTION_NOT_FOUND"]);
    assert.equal(typeof p.next_action, "string");
  });
  await check("missing connection -> INVALID_ARGUMENT", async () => {
    isDenied(await d.call("recommend_indexes", { queries: ["SELECT 1"] }), ["INVALID_ARGUMENT"]);
  });

  // ---- 5. audit -----------------------------------------------------------------------------
  await check("audit: recommend_indexes call recorded in audit trail", async () => {
    await d.call("explain_query", { connection: PG, sql: "SELECT * FROM users WHERE email = 'a'" }); // forces a flush of the sink with a tool known to log
    await new Promise((r) => setTimeout(r, 300));
    const jsonl = fs.readFileSync(path.join(auditDir, "audit.jsonl"), "utf8");
    assert.match(jsonl, /"tool_name":"explain_query"/, "audit sink not writing at all");
    assert.match(jsonl, /"tool_name":"recommend_indexes"/, "no recommend_indexes audit event");
  });
}

async function shutdown() {
  for (const c of clients) { try { c.close(); } catch {} }
  await new Promise((r) => setTimeout(r, 500));
  for (const c of clients) { try { c.child.kill(); } catch {} }
  await new Promise((r) => setTimeout(r, 300));
  for (const dir of tempDirs) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
}

main()
  .catch((err) => { counts.fail++; console.log(`FAIL  harness :: ${err && err.stack ? err.stack.split("\n").slice(0, 3).join(" | ") : err}`); })
  .finally(async () => {
    await shutdown();
    const failed = counts.fail + (STRICT ? counts.xfail : 0);
    console.log(`\nF09 recommend_indexes: PASS ${counts.pass}, FAIL ${counts.fail}, XFAIL(known bugs) ${counts.xfail}, XPASS ${counts.xpass}${STRICT ? " [strict]" : ""}`);
    process.exit(failed > 0 ? 1 : 0);
  });
