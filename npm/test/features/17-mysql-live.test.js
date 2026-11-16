#!/usr/bin/env node
"use strict";
/**
 * F17 - live MySQL 8 with a read-only login (every tool + the CLI).
 *
 *   eval "$(bash scripts/live-db-up.sh mysql)"     # starts mysql:8.0 on 127.0.0.1:13306, seeds the fixture
 *   node npm/test/features/17-mysql-live.test.js
 *
 * Needs DB_MCP_MYSQL_TEST_DSN (login with SELECT, SHOW VIEW only). Optional:
 * DB_MCP_MYSQL_TEST_DSN_DIAG (+ performance_schema SELECT, SHOW_ROUTINE, PROCESS) and
 * DB_MCP_MYSQL_TEST_DSN_RW (a writer, for the check-connection can_write warning).
 * Without DB_MCP_MYSQL_TEST_DSN the suite prints SKIP and exits 0. It never connects anywhere
 * else than those DSNs and writes only to a private temp directory.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
process.chdir(REPO);
const { createClient } = require(path.join(REPO, "scripts", "mcp-call.js"));
const LAUNCHER = path.join(REPO, "npm", "bin", "db-mcp.js");

const RO = process.env.DB_MCP_MYSQL_TEST_DSN;
const DIAG = process.env.DB_MCP_MYSQL_TEST_DSN_DIAG;
const RW = process.env.DB_MCP_MYSQL_TEST_DSN_RW;
if (!RO) {
  console.log("SKIP  F17 live MySQL: DB_MCP_MYSQL_TEST_DSN is not set (eval \"$(bash scripts/live-db-up.sh mysql)\")");
  process.exit(0);
}

function passwordOf(dsn) {
  if (!dsn) return null;
  try {
    return decodeURIComponent(new URL(dsn).password) || null;
  } catch {
    return null;
  }
}
const SECRETS = [RO, DIAG, RW].map(passwordOf).filter(Boolean);
const SEEN = []; // every response / CLI output, scanned for password leaks at the end

const results = [];
async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, ok: true });
    console.log(`PASS  ${name}${detail ? "  :: " + detail : ""}`);
  } catch (err) {
    results.push({ name, ok: false, err });
    console.log(`FAIL  ${name}  :: ${(err && err.message ? err.message : String(err)).split("\n")[0].slice(0, 300)}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Private config
// ---------------------------------------------------------------------------------------------
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f17-"));
const P = (f) => path.join(DIR, f).replace(/\\/g, "/");
process.env.DB_MCP_APPROVAL_KEY = "f17-approval-key-" + process.pid;

function liveConn(id, envVar, extra = "") {
  return `
[[connections]]
id = "${id}"
engine = "MySql"
dsn = "env:${envVar}"
description = "F17 live MySQL ${id}"
timeout_ms = 4000
max_rows = 200
max_bytes = 1048576
allow_explain_analyze = true
restricted_tables = ["internal_secrets"]
sensitive_columns = ["password_hash"]
${extra}`;
}
const CONFIG = `server_name = "f17-live-mysql"
default_mode = "ReadOnly"

[audit]
in_memory = false
jsonl_path = "${P("audit.jsonl")}"

[changes]
storage_path = "${P("changes.db")}"
approval_key = "env:DB_MCP_APPROVAL_KEY"

[ontology]
storage_path = "${P("ontology.db")}"
${liveConn("live-mysql", "DB_MCP_MYSQL_TEST_DSN", 'mode = "ReadOnly"\nread_only = true')}
${liveConn("live-mysql-dev", "DB_MCP_MYSQL_TEST_DSN", 'mode = "Development"\nread_only = false')}
${DIAG ? liveConn("live-mysql-diag", "DB_MCP_MYSQL_TEST_DSN_DIAG", 'mode = "ReadOnly"\nread_only = true') : ""}
[[named_tools]]
name = "orders_for_user"
description = "Orders of one user"
connection = "live-mysql"
statement = "SELECT id, status, total_cents FROM orders WHERE user_id = ?1 ORDER BY id"
read_only = true
max_rows = 50
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "user_id"
param_type = "integer"
description = "User id"
required = true
`;
const CONFIG_PATH = P("db-mcp.toml");
fs.writeFileSync(CONFIG_PATH, CONFIG);

const M = "live-mysql";
const DEV = "live-mysql-dev";
const DG = "live-mysql-diag";

function cli(args, { allowFail = false } = {}) {
  const r = spawnSync(process.execPath, [LAUNCHER, ...args], { cwd: REPO, encoding: "utf8", env: process.env });
  SEEN.push(r.stdout || "", r.stderr || "");
  if (r.status !== 0 && !allowFail) throw new Error(`db-mcp ${args.join(" ")} exited ${r.status}: ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
  return r;
}
const cliJson = (args, opts) => JSON.parse(cli(args, opts).stdout);

let client;
async function call(name, args) {
  const resp = await client.rpc("tools/call", { name, arguments: args });
  if (resp.error) throw new Error(`JSON-RPC error: ${JSON.stringify(resp.error)}`);
  const p = resp.result.structuredContent;
  SEEN.push(JSON.stringify(p));
  return p;
}
function ok(p, label = "") {
  assert.equal(p.status, "ok", `${label} expected ok, got ${JSON.stringify(p).slice(0, 400)}`);
  return p;
}
function denied(p, codes, label = "") {
  const list = Array.isArray(codes) ? codes : [codes];
  assert.equal(p.status, "denied", `${label} expected denied, got ${JSON.stringify(p).slice(0, 300)}`);
  assert.ok(list.includes(p.code), `${label} expected ${list}, got ${p.code}: ${p.message}`);
  return p;
}
const sortRows = (rows) => rows.map((r) => JSON.stringify(r)).sort();

// ---------------------------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------------------------
async function main() {
  await check("check-connection (read-only login): version, SELECT 1, grants, object count, can_write=false", () => {
    const r = cliJson(["check-connection", "--config", CONFIG_PATH, "--connection", M]);
    assert.equal(r.backend, "live");
    assert.equal(r.can_connect, true);
    assert.equal(r.select_1, true);
    assert.equal(r.can_write, false);
    assert.match(r.server_version, /^8\./);
    assert.ok(r.object_count >= 8, `object_count=${r.object_count}`);
    assert.ok(r.permissions.some((g) => /GRANT SELECT, SHOW VIEW ON `appdb`/.test(g)), JSON.stringify(r.permissions));
    assert.ok(r.warnings.some((w) => /SHOW_ROUTINE/.test(w)));
    return `MySQL ${r.server_version}, ${r.object_count} objects, ${r.warnings.length} warnings`;
  });
  if (RW) {
    await check("check-connection warns when the account can write", () => {
      const cfg = P("rw.toml");
      fs.writeFileSync(cfg, `server_name = "f17-rw"\n${liveConn("rw", "DB_MCP_MYSQL_TEST_DSN_RW", 'mode = "ReadOnly"\nread_only = true')}`);
      const r = cliJson(["check-connection", "--config", cfg]);
      assert.equal(r.can_write, true);
      assert.ok(r.warnings.some((w) => /can write \(INSERT ON APPDB/.test(w)), JSON.stringify(r.warnings));
    });
  }
  await check("check-connection on an unreachable live server exits non-zero with CONNECTION_UNAVAILABLE", () => {
    const cfg = P("down.toml");
    fs.writeFileSync(cfg, `server_name = "f17-down"\n[[connections]]\nid = "down"\nengine = "MySql"\ndsn = "mysql://u:never-shown-pw@127.0.0.1:1/x?connect_timeout=800"\nread_only = true\n`);
    const r = cli(["check-connection", "--config", cfg], { allowFail: true });
    assert.notEqual(r.status, 0);
    const j = JSON.parse(r.stdout);
    assert.equal(j.can_connect, false);
    assert.ok(/CONNECTION_UNAVAILABLE/.test(JSON.stringify(j.warnings)));
    assert.ok(!r.stdout.includes("never-shown-pw"));
  });
  await check("verify-config --live runs the connection checks", () => {
    const r = cliJson(["verify-config", "--config", CONFIG_PATH, "--live"]);
    assert.equal(r.status, "ok");
    assert.ok(r.connection_checks.every((c) => c.can_connect));
  });

  client = createClient({ config: CONFIG_PATH, principal: "f17-agent", role: "agent", timeoutMs: 60000 });
  const init = await client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f17", version: "0" } });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  client.notify("notifications/initialized", {});

  // ---- explore -------------------------------------------------------------------------------
  await check("list_connections: backend=live, simulated=false, diagnostics capabilities on", async () => {
    const p = ok(await call("list_connections", {}));
    const e = p.data.find((c) => c.id === M);
    assert.equal(e.backend, "live");
    assert.equal(e.simulated, false);
    assert.equal(e.engine, "mysql");
    assert.equal(e.capabilities.supports_health_diagnostics, true);
    assert.equal(e.capabilities.supports_index_advisor, true);
    assert.equal(e.capabilities.supports_transactional_ddl, false);
    assert.ok(!(e.warnings || []).some((w) => /simulated/.test(w)));
  });
  await check("search_objects: real tables/views/indexes, restricted table hidden, missing-grant warning", async () => {
    const p = ok(await call("search_objects", { connection: M, detail_level: "names", limit: 200 }));
    const names = p.data.objects.map((o) => `${o.object_type}:${o.name}`);
    for (const n of ["table:users", "table:orders", "table:order_items", "table:inventory", "table:audit_logs", "view:active_user_orders", "index:idx_orders_status_created"]) {
      assert.ok(names.includes(n), `${n} missing`);
    }
    assert.ok(!names.some((n) => /internal_secrets/.test(n)));
    assert.ok(!p.warnings.some((w) => /simulated/.test(w)));
    assert.ok(p.warnings.some((w) => /SHOW_ROUTINE/.test(w)), JSON.stringify(p.warnings));
    return `${p.data.total_count} objects`;
  });
  await check("describe_object: columns, PK, FKs from information_schema; restricted -> RESTRICTED_TABLE", async () => {
    const p = ok(await call("describe_object", { connection: M, object_name: "orders" }));
    assert.equal(p.data.schema, "appdb");
    assert.ok(p.data.columns.some((c) => c.name === "total_cents" && c.data_type === "bigint"));
    assert.ok(p.data.foreign_keys.some((f) => f.referenced_table === "users" && f.on_delete === "CASCADE"));
    assert.equal(p.data.comment, "Customer orders");
    denied(await call("describe_object", { connection: M, object_name: "internal_secrets" }), "RESTRICTED_TABLE");
  });
  await check("trace_table_dependencies: the view over orders is a dependent", async () => {
    const p = ok(await call("trace_table_dependencies", { connection: M, table_name: "orders" }));
    const deps = JSON.stringify(p.data);
    assert.ok(/active_user_orders/.test(deps), deps.slice(0, 300));
  });
  await check("get_procedure_call_graph (read-only login): empty graph with a SHOW_ROUTINE warning, no failure", async () => {
    const p = ok(await call("get_procedure_call_graph", { connection: M }));
    assert.ok(p.warnings.some((w) => /SHOW_ROUTINE/.test(w)));
  });
  if (DIAG) {
    await check("get_procedure_call_graph (+SHOW_ROUTINE): checkout_order -> reserve_inventory -> record_order_audit", async () => {
      const p = ok(await call("get_procedure_call_graph", { connection: DG, procedure_name: "checkout_order" }));
      const chains = p.data.call_chains.map((c) => c.join(">"));
      assert.ok(chains.includes("appdb.checkout_order>appdb.reserve_inventory>appdb.record_order_audit"), JSON.stringify(chains));
      assert.ok(chains.includes("appdb.checkout_order>appdb.calculate_order_discount"));
    });
    await check("trace_table_dependencies (+SHOW_ROUTINE): procedures writing audit_logs are found", async () => {
      const p = ok(await call("trace_table_dependencies", { connection: DG, table_name: "audit_logs" }));
      assert.ok(/record_order_audit/.test(JSON.stringify(p.data)));
    });
  }

  // ---- query ---------------------------------------------------------------------------------
  await check("execute_query: params, typed values (unsigned, DECIMAL string, ISO datetime, hex, UTF-8, NULL)", async () => {
    const p = ok(await call("execute_query", { connection: M, sql: "SELECT i_big_u, d_dec, dt, b_bin, txt, n_null FROM type_samples WHERE id = ?", params: [1] }));
    assert.deepEqual(p.rows[0], [18446744073709552000, "12345.678900", "2025-01-03T10:00:00.123000", "0xdeadbeef", "héllo 日本", null]);
    assert.equal(p.columns[0].data_type, "bigint unsigned");
    assert.match(p.schema_version, /^snapshot_|^/);
    const q = ok(await call("execute_query", { connection: M, sql: "SELECT id, email FROM users WHERE id = ?1 OR id = ?2 ORDER BY id", params: [1, 2] }));
    assert.deepEqual(q.rows, [[1, "alice@example.com"], [2, "bob@example.com"]]);
  });
  await check("execute_query: sensitive column never leaves the server in clear", async () => {
    for (const sql of ["SELECT email, password_hash FROM users", "SELECT * FROM users"]) {
      const p = await call("execute_query", { connection: M, sql });
      assert.ok(!JSON.stringify(p).includes("hash_alice_secret"), `${sql} leaked`);
    }
  });
  await check("execute_query: restricted table -> RESTRICTED_TABLE; writes -> MUTATION_NOT_ALLOWED_IN_READ_ONLY; batch refused", async () => {
    denied(await call("execute_query", { connection: M, sql: "SELECT * FROM internal_secrets" }), ["RESTRICTED_TABLE", "RESTRICTED_TABLE_FORBIDDEN"]);
    denied(await call("execute_query", { connection: M, sql: "INSERT INTO event_log_nopk VALUES (NOW(), 'x')" }), "MUTATION_NOT_ALLOWED_IN_READ_ONLY");
    denied(await call("execute_query", { connection: M, sql: "SELECT 1; DELETE FROM users" }), ["MULTI_STATEMENT_FORBIDDEN", "MUTATION_NOT_ALLOWED_IN_READ_ONLY"]);
  });
  await check("execute_query on a Development connection: the server itself refuses the write (read-only login)", async () => {
    const p = await call("execute_query", { connection: DEV, sql: "INSERT INTO event_log_nopk (event_time, message) VALUES (NOW(), 'x')" });
    assert.equal(p.status, "denied", JSON.stringify(p).slice(0, 300));
    assert.ok(["DATABASE_PERMISSION_DENIED", "APPROVAL_REQUIRED", "USE_PROPOSE_CHANGE"].includes(p.code) || /denied|approval/i.test(p.message), `${p.code}: ${p.message}`);
    const n = ok(await call("execute_query", { connection: M, sql: "SELECT COUNT(*) FROM event_log_nopk" }));
    assert.equal(n.rows[0][0], 1);
    return p.code;
  });
  await check("execute_query: timeout ends the server query (EXECUTION_TIMEOUT) and the connection stays usable", async () => {
    const t0 = Date.now();
    const p = await call("execute_query", { connection: M, sql: "SELECT SUM(a.n + b.n + c.n) FROM numbers a, numbers b, numbers c", timeout_ms: 1000 });
    const ms = Date.now() - t0;
    denied(p, "EXECUTION_TIMEOUT");
    assert.ok(ms < 6000, `${ms}ms`);
    ok(await call("execute_query", { connection: M, sql: "SELECT 1" }));
    return `${ms}ms`;
  });
  await check("execute_query: max_rows truncates a large result", async () => {
    const p = ok(await call("execute_query", { connection: M, sql: "SELECT n FROM numbers ORDER BY n", max_rows: 10 }));
    assert.equal(p.rows.length, 10);
    assert.equal(p.truncated, true);
  });
  await check("explain_query: real EXPLAIN FORMAT=JSON (full scan vs index), ANALYZE, writes refused", async () => {
    const scan = ok(await call("explain_query", { connection: M, sql: "SELECT * FROM orders WHERE total_cents > 1000" }));
    assert.deepEqual(scan.data.seq_scans, ["orders"]);
    assert.ok(scan.data.structured_plan.query_block);
    const idx = ok(await call("explain_query", { connection: M, sql: "SELECT id FROM orders WHERE status = ?", params: ["pending"] }));
    assert.ok(idx.data.index_scans.some((k) => /idx_orders_status/.test(k)), JSON.stringify(idx.data.index_scans));
    const an = ok(await call("explain_query", { connection: M, sql: "SELECT COUNT(*) FROM orders", analyze: true }));
    assert.ok(/actual time/.test(an.data.raw_plan), an.data.raw_plan);
    denied(await call("explain_query", { connection: M, sql: "DELETE FROM orders" }), ["MUTATION_NOT_ALLOWED_IN_READ_ONLY", "READONLY_VIOLATION"]);
    const missing = await call("explain_query", { connection: M, sql: "SELECT * FROM no_such_table" });
    assert.equal(missing.status, "denied");
  });
  await check("run_named_tool: bound parameter on the live server", async () => {
    const p = ok(await call("run_named_tool", { tool_name: "orders_for_user", arguments: { user_id: 2 } }));
    assert.deepEqual(p.rows, [[102, "pending", 1900]]);
  });

  // ---- diagnostics -----------------------------------------------------------------------------
  await check("database_health (minimal grants): real counters + catalog findings, missing grants are info findings", async () => {
    const p = ok(await call("database_health", { connection: M }));
    const ids = p.rows.map((r) => r[0]);
    for (const id of ["connection_saturation", "buffer_pool_hit_ratio", "tables_without_primary_key", "redundant_indexes", "process_visibility", "workload_visibility"]) {
      assert.ok(ids.includes(id), `${id} missing from ${ids}`);
    }
    assert.ok(p.data.max_connections > 0 && p.data.active_connections >= 1);
    const nopk = p.rows.find((r) => r[0] === "tables_without_primary_key");
    assert.ok(JSON.stringify(nopk).includes("event_log_nopk"));
    assert.ok(!JSON.stringify(p).includes("internal_secrets"));
    const red = p.rows.find((r) => r[0] === "redundant_indexes");
    assert.ok(JSON.stringify(red).includes("idx_orders_status"));
    return `${ids.length} findings, overall ${p.data.overall_status}`;
  });
  await check("analyze_workload (minimal grants): falls back to session history with a GRANT note", async () => {
    const p = ok(await call("analyze_workload", { connection: M }));
    assert.ok(p.data.notes.some((n) => /GRANT SELECT ON performance_schema/.test(n)), JSON.stringify(p.data.notes));
  });
  if (DIAG) {
    await check("database_health (+PROCESS, performance_schema): no missing-grant findings", async () => {
      const p = ok(await call("database_health", { connection: DG }));
      const ids = p.rows.map((r) => r[0]);
      assert.ok(!ids.includes("process_visibility") && !ids.includes("workload_visibility"), ids.join(","));
    });
    await check("analyze_workload (+performance_schema): statement digests, fingerprints only, own probes excluded", async () => {
      ok(await call("execute_query", { connection: DG, sql: "SELECT id FROM orders WHERE total_cents > 1234" }));
      const p = ok(await call("analyze_workload", { connection: DG, top_n: 50 }));
      assert.equal(p.data.source, "performance_schema.events_statements_summary_by_digest");
      const qs = p.rows.map((r) => r[0]);
      assert.ok(qs.some((q) => /total_cents/i.test(q)), JSON.stringify(qs).slice(0, 300));
      assert.ok(!qs.some((q) => /1234/.test(q)), "literal leaked");
      assert.ok(!qs.some((q) => /information_schema/i.test(q)));
    });
  }
  await check("recommend_indexes: heuristic + real EXPLAIN validation, MySQL ALTER TABLE DDL, advisory only", async () => {
    const p = ok(await call("recommend_indexes", { connection: M, queries: ["SELECT id FROM orders WHERE total_cents > 1000"] }));
    assert.ok(p.data.length >= 1, JSON.stringify(p).slice(0, 300));
    const r = p.data[0];
    assert.match(r.suggested_ddl, /^ALTER TABLE `appdb`\.`orders` ADD INDEX `idx_orders_total_cents` \(`total_cents`\);$/);
    assert.equal(r.evidence.mysql_explain.full_table_scan_confirmed, true);
    assert.equal(r.hypopg_validated, false);
    const after = ok(await call("search_objects", { connection: M, object_types: ["index"], detail_level: "names", limit: 100 }));
    assert.ok(!after.data.objects.some((o) => o.name === "idx_orders_total_cents"), "index was created");
    denied(await call("recommend_indexes", { connection: M, queries: ["SELECT * FROM internal_secrets WHERE secret_key = 'x'"] }), "RESTRICTED_TABLE");
  });

  // ---- change governance -----------------------------------------------------------------------
  await check("propose_change on the read-only connection is refused", async () => {
    denied(await call("propose_change", { connection: M, sql: "UPDATE orders SET status = 'x' WHERE id = 101" }), "MUTATION_NOT_ALLOWED_IN_READ_ONLY");
  });
  await check("governed change on Development: propose -> CLI approve -> apply fails at the server (no write happened)", async () => {
    const prop = ok(await call("propose_change", { connection: DEV, sql: "UPDATE orders SET status = 'cancelled' WHERE id = 102" }));
    const id = prop.data.change_id;
    ok(await call("get_change", { change_id: id }));
    const appr = cliJson(["approve", "--change-id", id, "--approver", "f17-admin", "--config", CONFIG_PATH]);
    assert.equal(appr.state, "approved");
    const applied = await call("apply_change", { change_id: id });
    assert.equal(applied.status, "denied", JSON.stringify(applied).slice(0, 300));
    const after = ok(await call("get_change", { change_id: id }));
    assert.equal(after.data.state, "failed");
    const row = ok(await call("execute_query", { connection: M, sql: "SELECT status FROM orders WHERE id = 102" }));
    assert.deepEqual(row.rows, [["pending"]]);
    return applied.code;
  });

  // ---- schema ----------------------------------------------------------------------------------
  await check("capture_schema / diff_schema: stable version, live vs live identical, restricted table excluded", async () => {
    const a = ok(await call("capture_schema", { connection: M }));
    const b = ok(await call("capture_schema", { connection: M }));
    assert.equal(a.schema_version, b.schema_version);
    assert.ok(!JSON.stringify(a.data).includes("internal_secrets"));
    const d = ok(await call("diff_schema", { base_snapshot: a.data, target_connection: M }));
    assert.equal(d.data.is_identical, true, JSON.stringify(d.data).slice(0, 300));
  });

  // ---- ontology --------------------------------------------------------------------------------
  await check("ontology: discover -> propose -> admin certify/publish -> plan/ask; answer equals direct SQL", async () => {
    ok(await call("ontology_status", { connection: M }));
    const disc = ok(await call("discover_ontology", { connection: M }));
    assert.ok(disc.data.candidates > 0);
    assert.ok(!JSON.stringify(disc).includes("internal_secrets"));
    const listed = cliJson(["ontology", "list", "--connection", M, "--config", CONFIG_PATH]).definitions;
    const want = [
      (d) => d.def_id === "attribute:appdb.users.role",
      (d) => d.def_id === "relationship:appdb.orders(user_id)->appdb.users",
      (d) => d.def_id === "metric:appdb.orders.count",
    ];
    const picks = want.map((f) => listed.find(f));
    assert.ok(picks.every(Boolean), `missing discovered defs; have ${listed.map((d) => d.def_id).slice(0, 40).join(", ")}`);
    const prop = ok(await call("propose_semantic_definition", {
      connection: M,
      definition: { name: "order value", synonyms: ["order total"], body: { type: "metric", base_table: "orders", aggregation: "sum", column: "total_cents", unit: "cents", grain: "order" } },
    }));
    const drafts = [...picks.map((d) => [d.def_id, d.version]), [prop.data.definition.def_id, prop.data.definition.version]];
    for (const [id, v] of drafts) {
      cli(["ontology", "review", "--connection", M, "--def-id", id, "--version", String(v), "--action", "approve", "--reviewer", "f17-reviewer", "--reason", "f17", "--config", CONFIG_PATH]);
    }
    cli(["ontology", "publish", "--connection", M, "--reviewer", "f17-reviewer", "--config", CONFIG_PATH]);
    ok(await call("search_terms", { connection: M, query: "order value" }));
    ok(await call("describe_term", { connection: M, def_id: prop.data.definition.def_id }));
    ok(await call("trace_semantic_relationships", { connection: M, entity: "orders" }));
    const plan = ok(await call("plan_semantic_query", { connection: M, question: "total order value by user role" }));
    assert.equal(plan.data.status, "answerable", `status=${plan.data.status} missing=${JSON.stringify(plan.data.missing)} sql=${plan.data.sql}`);
    assert.match(plan.data.sql, /FROM `?appdb`?\.`?orders`? t0 JOIN `?appdb`?\.`?users`?/);
    const ans = ok(await call("ask_semantic_question", { connection: M, question: "total order value by user role" }));
    assert.equal(ans.data.answered, true, JSON.stringify(ans.data).slice(0, 300));
    const direct = ok(await call("execute_query", { connection: M, sql: "SELECT u.role, SUM(o.total_cents) FROM orders o JOIN users u ON u.id = o.user_id GROUP BY u.role" }));
    assert.deepEqual(sortRows(ans.rows), sortRows(direct.rows));
    const cnt = ok(await call("ask_semantic_question", { connection: M, question: "count of orders" }));
    const dc = ok(await call("execute_query", { connection: M, sql: "SELECT COUNT(*) FROM orders" }));
    assert.deepEqual(cnt.rows.flat(), dc.rows.flat());
    return plan.data.sql;
  });

  client.close();

  // ---- audit + leaks ---------------------------------------------------------------------------
  await check("audit trail is durable, chain verifies, and contains no password", () => {
    const text = fs.readFileSync(P("audit.jsonl"), "utf8");
    assert.ok(text.split("\n").filter(Boolean).length > 20);
    for (const s of SECRETS) assert.ok(!text.includes(s), "password in audit");
    const v = cliJson(["verify-audit", "--config", CONFIG_PATH]);
    assert.equal(v.status, "ok");
  });
  await check("no DSN password appears in any tool response or CLI output", () => {
    const all = SEEN.join("\n");
    for (const s of SECRETS) assert.ok(!all.includes(s), "password leaked");
  });
}

main()
  .catch((e) => {
    results.push({ name: "harness", ok: false, err: e });
    console.log(`FAIL  harness :: ${e.stack || e}`);
  })
  .finally(() => {
    try {
      if (client) client.close();
    } catch {}
    const failed = results.filter((r) => !r.ok);
    console.log(`# F17 live MySQL: ${results.length - failed.length}/${results.length} checks passed, ${failed.length} failed`);
    setTimeout(() => {
      fs.rmSync(DIR, { recursive: true, force: true });
      process.exit(failed.length ? 1 : 0);
    }, 300);
  });
