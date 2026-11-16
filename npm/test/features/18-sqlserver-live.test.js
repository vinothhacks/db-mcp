#!/usr/bin/env node
"use strict";
/**
 * F18 - live Microsoft SQL Server (read-only logins).
 *
 * Needs a server seeded with research/fixtures/sqlserver-live (scripts/live-db-up.sh mssql):
 *   eval "$(bash scripts/live-db-up.sh mssql)"
 *   node npm/test/features/18-sqlserver-live.test.js
 * DB_MCP_MSSQL_TEST_DSN       db_datareader-only login (degraded diagnostics)       - required
 * DB_MCP_MSSQL_FULL_TEST_DSN  + VIEW DEFINITION, SHOWPLAN, VIEW DATABASE STATE,
 *                               VIEW SERVER STATE (full diagnostics, ontology flow)   - optional
 * Without DB_MCP_MSSQL_TEST_DSN the suite prints SKIP and exits 0.
 *
 * Every one of the 24 tools and the check-connection CLI is exercised on the live engine. The
 * suite writes its own temporary config (DSNs stay in env: references) and never connects to
 * any host other than the configured DSNs. Exit code: 0 when every check passes, 1 otherwise.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const LAUNCHER = path.join(REPO, "npm", "bin", "db-mcp.js");
const { createClient } = require(path.join(REPO, "scripts", "mcp-call.js"));
process.chdir(REPO);

const RO_DSN = process.env.DB_MCP_MSSQL_TEST_DSN || "";
const FULL_DSN = process.env.DB_MCP_MSSQL_FULL_TEST_DSN || "";
if (!RO_DSN.trim()) {
  console.log("SKIP  F18 sqlserver-live: set DB_MCP_MSSQL_TEST_DSN (eval \"$(bash scripts/live-db-up.sh mssql)\")");
  process.exit(0);
}

function secretsOf(dsn) {
  const m = /^[a-z]+:\/\/([^:]*):(.*)@[^@]*$/i.exec(dsn.split("?")[0]);
  if (!m) return [];
  const enc = m[2];
  let dec = enc;
  try { dec = decodeURIComponent(enc); } catch {}
  return [enc, dec].filter((s) => s.length >= 4);
}
const SECRETS = [...secretsOf(RO_DSN), ...secretsOf(FULL_DSN), "Secr3tDownPw"];

const results = [];
const seen = []; // every response, scanned for password leaks at the end
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
function skip(name, why) {
  console.log(`SKIP  ${name}  :: ${why}`);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dbmcp-f18-"));
const tomlPath = (p) => p.replace(/\\/g, "/");
const hasFull = !!FULL_DSN.trim();
const conn = (id, envVar, extra) => `
[[connections]]
id = "${id}"
engine = "sqlserver"
dsn = "${envVar}"
default_schema = "dbo"
timeout_ms = 4000
max_rows = 200
restricted_tables = ["internal_secrets"]
sensitive_columns = ["password_hash"]
${extra}`;
const configPath = path.join(dir, "f18.toml");
fs.writeFileSync(
  configPath,
  `server_name = "f18-sqlserver-live"
default_mode = "read_only"

[audit]
in_memory = false
jsonl_path = "${tomlPath(path.join(dir, "audit.jsonl"))}"

[changes]
storage_path = "${tomlPath(path.join(dir, "changes.db"))}"

[ontology]
storage_path = "${tomlPath(path.join(dir, "ontology.db"))}"
${conn("mssql-ro", "env:DB_MCP_MSSQL_TEST_DSN", 'mode = "read_only"\nread_only = true')}
${hasFull ? conn("mssql-full", "env:DB_MCP_MSSQL_FULL_TEST_DSN", 'mode = "read_only"\nread_only = true') : ""}
${conn("mssql-dev", "env:DB_MCP_MSSQL_TEST_DSN", 'mode = "development"\nread_only = false')}
${conn("mssql-down", "env:DB_MCP_F18_DOWN_DSN", 'mode = "read_only"\nread_only = true')}

[[named_tools]]
name = "mssql_user_by_id"
description = "One user by id (SQL Server)"
connection = "mssql-ro"
statement = "SELECT id, email, role FROM dbo.users WHERE id = ?1"
read_only = true
max_rows = 1
[[named_tools.parameters]]
name = "user_id"
param_type = "integer"
description = "user id"
`
);
process.env.DB_MCP_F18_DOWN_DSN = "sqlserver://nobody:Secr3tDownPw@127.0.0.1:1?connectTimeout=2";

const INIT = { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f18-test", version: "0" } };
let client;
async function call(name, args) {
  const resp = await client.rpc("tools/call", { name, arguments: args });
  if (resp.error) throw new Error(`JSON-RPC error: ${JSON.stringify(resp.error)}`);
  seen.push(JSON.stringify(resp.result));
  return resp.result.structuredContent;
}
const ok = (p) => {
  assert.equal(p.status, "ok", JSON.stringify(p).slice(0, 400));
  return p;
};
const denied = (p, code) => {
  assert.equal(p.status, "denied", JSON.stringify(p).slice(0, 400));
  if (code) assert.equal(p.code, code, JSON.stringify(p).slice(0, 400));
  return p;
};
function cli(args) {
  const r = spawnSync(process.execPath, [LAUNCHER, ...args, "--config", configPath], { cwd: REPO, encoding: "utf8", timeout: 120000 });
  seen.push(r.stdout || "", r.stderr || "");
  return r;
}

(async () => {
  client = createClient({ config: configPath, principal: "f18-agent", role: "agent", timeoutMs: 90000 });
  const init = await client.rpc("initialize", INIT);
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  client.notify("notifications/initialized", {});

  await check("tools/list exposes the 24 tools", async () => {
    const r = await client.rpc("tools/list", {});
    assert.equal(r.result.tools.length, 24);
  });

  await check("search_objects lists live tables; restricted internal_secrets is hidden", async () => {
    const p = ok(await call("search_objects", { connection: "mssql-ro", object_types: ["table"], limit: 100 }));
    const names = p.data.objects.map((o) => `${o.schema}.${o.name}`);
    for (const t of ["dbo.users", "dbo.orders", "dbo.order_items", "dbo.inventory", "dbo.audit_logs"]) assert.ok(names.includes(t), names.join(","));
    assert.ok(!names.includes("dbo.internal_secrets"));
    assert.ok(!p.warnings.some((w) => /simulated/.test(w)), "live connection must not carry a simulation warning");
    return `${names.length} tables`;
  });

  await check("list_connections: engine sqlserver, backend live, grants reported after first connect", async () => {
    const p = ok(await call("list_connections", {}));
    const ro = p.data.find((c) => c.id === "mssql-ro");
    assert.equal(ro.engine, "sqlserver");
    assert.equal(ro.backend, "live");
    assert.equal(ro.simulated, false);
    assert.match(ro.capabilities.unavailable_reasons.explain || "", /GRANT SHOWPLAN/);
    assert.match(ro.capabilities.unavailable_reasons.routine_definitions || "", /VIEW DEFINITION/);
  });

  await check("describe_object orders: columns, primary key, foreign key, indexes", async () => {
    const p = ok(await call("describe_object", { connection: "mssql-ro", object_name: "orders", schema: "dbo" }));
    const o = p.data;
    assert.ok(o.columns.find((c) => c.name === "id").is_primary_key);
    assert.equal(o.columns.find((c) => c.name === "status").data_type, "nvarchar(20)");
    assert.equal(o.foreign_keys[0].referenced_table, "dbo.users");
    assert.ok(o.indexes.some((i) => i.primary));
  });

  await check("describe_object refuses the restricted table", async () => {
    denied(await call("describe_object", { connection: "mssql-ro", object_name: "internal_secrets" }), "RESTRICTED_TABLE");
  });

  await check("trace_table_dependencies orders: inbound FKs and join path", async () => {
    const p = ok(await call("trace_table_dependencies", { connection: "mssql-ro", table_name: "dbo.orders", target_table: "dbo.inventory" }));
    const inbound = p.data.inbound_foreign_keys.map((e) => e.from_table).join(",");
    assert.match(inbound, /order_items/);
    assert.match(inbound, /audit_logs/);
    assert.ok(p.data.join_path && p.data.join_path.hops.length >= 2, JSON.stringify(p.data.join_path));
  });

  await check("execute_query: bound @P1 / ? parameters, value mapping, row cap", async () => {
    const a = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT id, email, created_at FROM dbo.users WHERE role = @P1 ORDER BY id", params: ["customer"] }));
    assert.equal(a.returned_rows, 2);
    assert.equal(a.rows[0][2], "2025-01-02T00:00:00");
    const b = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT amount, ref_guid, raw_bytes, is_valid FROM dbo.event_staging WHERE event_id = ?", params: [1] }));
    assert.deepEqual(b.rows[0], ["12.50", "6F9619FF-8B86-D011-B42D-00C04FC964FF", "0xDEAD01", true]);
    const c = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT id FROM dbo.orders ORDER BY id", max_rows: 2 }));
    assert.equal(c.returned_rows, 2);
    assert.equal(c.truncated, true);
    const d = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT TOP (1) [id] FROM [dbo].[orders] WITH (NOLOCK) ORDER BY [id] DESC" }));
    assert.equal(d.rows[0][0], 104);
  });

  await check("execute_query: sensitive column redacted, alias laundering and restricted table denied", async () => {
    const r = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT id, password_hash FROM dbo.users WHERE id = 1" }));
    assert.ok(r.columns.find((c) => c.name === "password_hash").redacted);
    assert.ok(!JSON.stringify(r.rows).includes("hash_alice_secret"));
    denied(await call("execute_query", { connection: "mssql-ro", sql: "SELECT password_hash AS ph FROM dbo.users" }));
    const s = denied(await call("execute_query", { connection: "mssql-ro", sql: "SELECT * FROM [dbo].[internal_secrets]" }));
    assert.match(s.code, /RESTRICTED/);
  });

  await check("writes and T-SQL hazards are refused by policy on the read-only connection", async () => {
    for (const sql of [
      "DELETE FROM dbo.audit_logs",
      "SELECT 1 DELETE FROM dbo.audit_logs",
      "UPDATE dbo.users SET role = 'x'",
      "EXEC sp_who",
      "EXEC xp_cmdshell 'whoami'",
      "SELECT id INTO dbo.users_copy FROM dbo.users",
      "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;', 'SELECT 1')",
      "WAITFOR DELAY '00:00:05'",
      "BEGIN TRAN",
    ]) {
      const p = await call("execute_query", { connection: "mssql-ro", sql });
      assert.equal(p.status, "denied", `${sql} -> ${JSON.stringify(p).slice(0, 200)}`);
    }
  });

  await check("a write allowed by development policy is refused by the server (db_datareader)", async () => {
    const p = denied(await call("execute_query", { connection: "mssql-dev", sql: "INSERT INTO dbo.audit_logs (order_id, event_type, created_at) VALUES (101, 'F18', SYSUTCDATETIME())" }));
    assert.equal(p.code, "SERVER_PERMISSION_DENIED", JSON.stringify(p));
    const n = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT COUNT(*) FROM dbo.audit_logs" }));
    assert.equal(n.rows[0][0], 1);
  });

  await check("timeouts are enforced and the connection recovers", async () => {
    const heavy = "SELECT COUNT_BIG(*) FROM sys.all_columns a CROSS JOIN sys.all_columns b CROSS JOIN sys.all_columns c";
    const t0 = Date.now();
    const p = denied(await call("execute_query", { connection: "mssql-ro", sql: heavy, timeout_ms: 600 }));
    assert.equal(p.code, "EXECUTION_TIMEOUT");
    assert.ok(Date.now() - t0 < 4000, "timeout took too long");
    const again = ok(await call("execute_query", { connection: "mssql-ro", sql: "SELECT COUNT(*) FROM dbo.orders" }));
    assert.equal(again.rows[0][0], 4);
  });

  await check("run_named_tool binds ?1 on SQL Server", async () => {
    const p = ok(await call("run_named_tool", { tool_name: "mssql_user_by_id", arguments: { user_id: 2 } }));
    assert.deepEqual(p.rows[0], [2, "bob@example.com", "customer"]);
  });

  await check("explain_query without SHOWPLAN names the grant; analyze is refused", async () => {
    const p = denied(await call("explain_query", { connection: "mssql-ro", sql: "SELECT id FROM dbo.orders WHERE status = 'completed'" }));
    assert.match(p.message, /GRANT SHOWPLAN/);
    denied(await call("explain_query", { connection: "mssql-ro", sql: "SELECT 1", analyze: true }));
  });

  await check("database_health on db_datareader: catalog findings plus 'needs GRANT' findings", async () => {
    const p = ok(await call("database_health", { connection: "mssql-ro" }));
    const ids = p.data.findings.map((f) => f.check_id);
    for (const id of ["tables_without_primary_key", "heap_tables", "duplicate_indexes", "server_version", "server_state_checks"]) assert.ok(ids.includes(id), ids.join(","));
    assert.equal(p.data.engine, "sqlserver");
    assert.ok(p.data.findings.some((f) => /GRANT VIEW SERVER STATE/.test(f.remediation || "")));
  });

  await check("analyze_workload on db_datareader: no fabricated statistics, grant named", async () => {
    const p = ok(await call("analyze_workload", { connection: "mssql-ro", top_n: 5 }));
    assert.ok(["recorded_workload_history", "unavailable"].includes(p.data.source), p.data.source);
    assert.ok(p.data.notes.some((n) => /VIEW DATABASE STATE|VIEW SERVER STATE/.test(n)), JSON.stringify(p.data.notes));
  });

  await check("recommend_indexes on db_datareader: advisory T-SQL DDL, SHOWPLAN grant named", async () => {
    const p = ok(await call("recommend_indexes", { connection: "mssql-ro", queries: ["SELECT id FROM dbo.orders WHERE status = 'pending'"] }));
    assert.ok(p.warnings.some((w) => /SHOWPLAN/.test(w)), JSON.stringify(p.warnings));
    for (const r of p.data) assert.ok(!/CONCURRENTLY/.test(r.suggested_ddl) && /ON dbo\./.test(r.suggested_ddl), r.suggested_ddl);
  });

  await check("propose_change is refused on the read-only connection", async () => {
    denied(await call("propose_change", { connection: "mssql-ro", sql: "UPDATE dbo.users SET role = 'x' WHERE id = 1" }));
    const g = await call("get_change", { change_id: "chg_missing" });
    assert.notEqual(g.status, "ok");
    const a = await call("apply_change", { change_id: "chg_missing" });
    assert.notEqual(a.status, "ok");
  });

  let roSnapshot;
  await check("capture_schema is deterministic on the live catalog", async () => {
    const a = ok(await call("capture_schema", { connection: "mssql-ro" }));
    const b = ok(await call("capture_schema", { connection: "mssql-ro" }));
    assert.equal(a.data.engine, "sqlserver");
    assert.equal(a.schema_version, b.schema_version);
    roSnapshot = a.data;
  });

  await check("unreachable server fails closed with CONNECTION_UNAVAILABLE (no simulation fallback)", async () => {
    const p = denied(await call("search_objects", { connection: "mssql-down" }), "CONNECTION_UNAVAILABLE");
    assert.match(p.next_action || "", /check-connection/);
    assert.ok(!JSON.stringify(p).includes("Secr3tDownPw"));
  });

  await check("check-connection CLI: read-only login JSON shape, can_write=false", async () => {
    const r = cli(["check-connection", "--connection", "mssql-ro"]);
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    for (const k of ["connection", "engine", "backend", "server_version", "can_connect", "select_1", "object_count", "permissions", "can_write", "warnings"]) assert.ok(k in j, k);
    assert.equal(j.engine, "sqlserver");
    assert.equal(j.backend, "live");
    assert.equal(j.can_connect, true);
    assert.equal(j.select_1, true);
    assert.equal(j.can_write, false);
    assert.ok(j.object_count >= 7);
    assert.ok(j.permissions.includes("role:db_datareader"), j.permissions.join(","));
    return j.server_version;
  });

  await check("check-connection CLI: unreachable server exits non-zero without leaking the password", async () => {
    const r = cli(["check-connection", "--connection", "mssql-down"]);
    assert.notEqual(r.status, 0);
    const j = JSON.parse(r.stdout);
    assert.equal(j.can_connect, false);
    assert.equal(j.error_code, "CONNECTION_UNAVAILABLE");
    assert.ok(!r.stdout.includes("Secr3tDownPw") && !r.stderr.includes("Secr3tDownPw"));
  });

  if (!hasFull) {
    skip("extra-grant checks (explain, full health, Query Store, call graph, ontology)", "set DB_MCP_MSSQL_FULL_TEST_DSN");
  } else {
    await check("full login: procedures visible, call graph checkout_order -> reserve_inventory -> record_order_audit", async () => {
      const p = ok(await call("get_procedure_call_graph", { connection: "mssql-full", procedure_name: "dbo.checkout_order", direction: "downstream" }));
      const edges = p.data.edges.map((e) => `${e.caller}->${e.callee}`.toLowerCase()).join(" ");
      assert.match(edges, /checkout_order->[a-z.]*reserve_inventory/);
      assert.match(edges, /reserve_inventory->[a-z.]*record_order_audit/);
    });

    await check("full login: trace_table_dependencies finds dependent view, trigger and procedures", async () => {
      const p = ok(await call("trace_table_dependencies", { connection: "mssql-full", table_name: "dbo.orders" }));
      const deps = p.data.dependent_objects.map((d) => `${d.object_type}:${d.name}`).join(",");
      assert.match(deps, /view:active_user_orders/);
      assert.match(deps, /procedure:checkout_order/);
      assert.match(deps, /trigger:trg_orders_audit/);
    });

    await check("diff_schema db_datareader vs full: the hidden routines appear as additions", async () => {
      const p = ok(await call("diff_schema", { base_connection: "mssql-ro", target_connection: "mssql-full" }));
      const added = p.data.items.filter((i) => i.kind === "add_routine").map((i) => i.object_name).join(",");
      assert.match(added, /checkout_order/);
      const same = ok(await call("diff_schema", { base_snapshot: roSnapshot, target_connection: "mssql-ro" }));
      assert.equal(same.data.is_identical, true, JSON.stringify(same.data.items).slice(0, 300));
    });

    await check("full login: explain_query returns an estimated plan (cost, scans/seeks, missing-index hint)", async () => {
      const p = ok(await call("explain_query", { connection: "mssql-full", sql: "SELECT o.id, u.email FROM dbo.orders o JOIN dbo.users u ON u.id = o.user_id WHERE o.status = @P1", params: ["completed"] }));
      assert.ok(p.data.estimated_cost > 0);
      assert.ok(p.data.seq_scans.length + p.data.index_scans.length > 0);
      assert.equal(p.data.structured_plan.plan_kind, "estimated");
      const t = ok(await call("explain_query", { connection: "mssql-full", sql: "SELECT id FROM dbo.orders WHERE status = 'pending'", format: "text" }));
      assert.match(t.data.raw_plan, /dbo\.orders/);
    });

    await check("full login: database_health includes server counters and connections", async () => {
      const p = ok(await call("database_health", { connection: "mssql-full" }));
      const ids = p.data.findings.map((f) => f.check_id);
      assert.ok(ids.includes("page_life_expectancy") && ids.includes("connection_saturation"), ids.join(","));
      assert.ok(!ids.includes("server_state_checks"));
      assert.ok(p.data.active_connections >= 1);
    });

    await check("full login: analyze_workload reads Query Store (or the plan cache)", async () => {
      for (let i = 0; i < 3; i++) ok(await call("execute_query", { connection: "mssql-full", sql: "SELECT id, total_cents FROM dbo.orders WHERE status = @P1", params: ["completed"] }));
      const p = ok(await call("analyze_workload", { connection: "mssql-full", top_n: 10 }));
      assert.ok(["query_store", "sys.dm_exec_query_stats"].includes(p.data.source), p.data.source);
      assert.ok(p.data.top_queries.some((q) => /dbo\.orders/i.test(q.normalized_query)), JSON.stringify(p.data.top_queries).slice(0, 300));
      assert.ok(!p.data.top_queries.some((q) => /db-mcp:internal|'completed'/.test(q.normalized_query)), "internal statements or literals leaked");
    });

    await check("full login: recommend_indexes uses optimizer hints with T-SQL DDL (advisory)", async () => {
      const p = ok(await call("recommend_indexes", { connection: "mssql-full", queries: ["SELECT id, total_cents FROM dbo.orders WHERE status = 'pending'"] }));
      assert.ok(p.data.length >= 1, JSON.stringify(p).slice(0, 300));
      const rec = p.data.find((r) => /status/.test(r.columns.join(",")));
      assert.ok(rec, JSON.stringify(p.data.map((r) => r.suggested_ddl)));
      assert.match(rec.suggested_ddl, /^CREATE (NONCLUSTERED )?INDEX \w+ ON dbo\.orders \(status/);
      assert.equal(rec.hypopg_validated, false);
    });

    // ---- ontology: discover -> propose -> admin certify/publish -> plan/ask == direct SQL ----
    await check("ontology on SQL Server: discover, propose, certify + publish (CLI), answers equal direct SQL", async () => {
      ok(await call("ontology_status", { connection: "mssql-full" }));
      const disc = ok(await call("discover_ontology", { connection: "mssql-full" }));
      assert.ok(disc.data.candidates > 0);
      const drafts = [
        { name: "order value", synonyms: ["order total"], body: { type: "metric", base_table: "dbo.orders", aggregation: "sum", column: "total_cents", unit: "cents", grain: "order" } },
        { name: "completed order", synonyms: ["fulfilled order"], body: { type: "filter", table: "dbo.orders", column: "status", operator: "eq", value: "completed" } },
      ];
      const proposed = [];
      for (const d of drafts) {
        const r = ok(await call("propose_semantic_definition", { connection: "mssql-full", definition: d }));
        proposed.push([r.data.definition.def_id, r.data.definition.version]);
      }
      const terms = ok(await call("search_terms", { connection: "mssql-full", query: "orders" }));
      const ids = new Set(terms.data.map((t) => t.def_id));
      const list = cli(["ontology", "list", "--connection", "mssql-full"]);
      assert.equal(list.status, 0, list.stderr);
      const all = JSON.parse(list.stdout);
      const defs = (all.definitions || all).map((d) => d.def_id || d);
      const want = defs.filter((id) => /^metric:dbo\.orders\.count$|^attribute:dbo\.users\.role$|^relationship:dbo\.orders\(user_id\)->dbo\.users$/.test(id));
      assert.equal(want.length, 3, `discovered ids: ${defs.join(", ")}`);
      for (const [id, v] of [...want.map((id) => [id, 1]), ...proposed]) {
        const r = cli(["ontology", "review", "--connection", "mssql-full", "--def-id", id, "--version", String(v), "--action", "approve", "--reviewer", "f18-reviewer", "--reason", "f18"]);
        assert.equal(r.status, 0, `${id}: ${r.stderr}`);
      }
      const pub = cli(["ontology", "publish", "--connection", "mssql-full", "--reviewer", "f18-reviewer"]);
      assert.equal(pub.status, 0, pub.stderr);
      ok(await call("describe_term", { connection: "mssql-full", name: "order value" }));
      ok(await call("trace_semantic_relationships", { connection: "mssql-full", entity: "dbo.orders" }));
      const plan = ok(await call("plan_semantic_query", { connection: "mssql-full", question: "count of completed orders" }));
      assert.match(plan.data.sql, /^SELECT TOP \(\d+\) /);
      assert.ok(!/LIMIT/.test(plan.data.sql));
      const a1 = ok(await call("ask_semantic_question", { connection: "mssql-full", question: "count of completed orders" }));
      const d1 = ok(await call("execute_query", { connection: "mssql-full", sql: "SELECT COUNT(*) FROM dbo.orders WHERE status = 'completed'" }));
      assert.equal(a1.data.answered, true);
      assert.equal(Number(a1.rows[0][0]), Number(d1.rows[0][0]));
      const a2 = ok(await call("ask_semantic_question", { connection: "mssql-full", question: "total order value by user role" }));
      const d2 = ok(await call("execute_query", { connection: "mssql-full", sql: "SELECT u.role, SUM(o.total_cents) FROM dbo.orders o JOIN dbo.users u ON u.id = o.user_id GROUP BY u.role" }));
      const norm = (rows) => rows.map((r) => `${r[0]}=${Number(r[1])}`).sort().join(";");
      assert.equal(norm(a2.rows), norm(d2.rows));
      return `${norm(a2.rows)}`;
    });
  }

  await check("no password appears in any response, CLI output or the audit trail", async () => {
    const audit = fs.existsSync(path.join(dir, "audit.jsonl")) ? fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8") : "";
    const blob = seen.join("\n") + audit;
    for (const s of SECRETS) assert.ok(!blob.includes(s), "a password leaked");
    assert.ok(audit.length > 0, "audit trail is empty");
  });

  client.close();
  const failed = results.filter((r) => !r.ok);
  console.log(`\nF18 sqlserver-live: ${results.length - failed.length}/${results.length} passed`);
  setTimeout(() => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    process.exit(failed.length ? 1 : 0);
  }, 400);
})().catch((e) => {
  console.error(e);
  try { client && client.close(); } catch {}
  process.exit(1);
});
