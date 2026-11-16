#!/usr/bin/env node
"use strict";
/**
 * F08 - Diagnose profile part 1: `database_health` and `analyze_workload`.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *
 *   node npm/test/features/08-health-workload.test.js
 *
 * - Uses its own isolated configs (never serves config/db-mcp.example.toml directly).
 * - One line per check. Assertions encode CORRECT behaviour; checks that currently fail
 *   because of a known defect are tagged `KNOWN-BUG: F08-xx` and reported as such.
 * - Exit code 0 when every non-known-bug check passes; 1 otherwise. A known-bug check
 *   that starts passing is reported as FIXED (so the tag can be removed).
 * - All child server processes are terminated on exit.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const { makeIsolatedConfig } = require(path.join(ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(ROOT, "scripts", "mcp-call.js"));

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
const results = { pass: 0, failUnexpected: 0, failKnown: 0, fixed: 0 };
const children = new Set();
const latencies = [];

function check(name, fn, knownBug) {
  try {
    fn();
    if (knownBug) {
      results.fixed += 1;
      console.log(`FIXED  ${name}  (was ${knownBug}; remove the KNOWN-BUG tag)`);
    } else {
      results.pass += 1;
      console.log(`PASS   ${name}`);
    }
  } catch (err) {
    const msg = String(err && err.message ? err.message : err).split("\n")[0].slice(0, 220);
    if (knownBug) {
      results.failKnown += 1;
      console.log(`FAIL   ${name}  [${knownBug}] ${msg}`);
    } else {
      results.failUnexpected += 1;
      console.log(`FAIL   ${name}  ${msg}`);
    }
  }
}

async function openSession(configPath, opts = {}) {
  const client = createClient({
    config: configPath,
    principal: opts.principal || "local-agent",
    role: opts.role || "agent",
    timeoutMs: 30000,
  });
  children.add(client.child);
  const exited = new Promise((resolve) => client.child.on("exit", resolve));
  const init = await client.rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "f08-health-workload", version: "0.1.0" },
  });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
  client.notify("notifications/initialized", {});
  const call = async (name, args) => {
    const t0 = Date.now();
    const resp = await client.rpc("tools/call", { name, arguments: args });
    const ms = Date.now() - t0;
    latencies.push({ name, connection: args && args.connection, ms });
    if (resp.error) return { rpcError: resp.error, ms };
    const r = resp.result;
    return { ms, isError: !!r.isError, body: r.structuredContent !== undefined ? r.structuredContent : r };
  };
  const listTools = async () => (await client.rpc("tools/list", {})).result.tools.map((t) => t.name);
  const close = async () => {
    client.close();
    await Promise.race([exited, new Promise((r) => setTimeout(r, 3000))]);
    children.delete(client.child);
  };
  return { call, listTools, close };
}

function killAll() {
  for (const c of children) {
    try { c.kill(); } catch { /* ignore */ }
  }
}
process.on("exit", killAll);
process.on("SIGINT", () => { killAll(); process.exit(130); });

function readAuditRecords(dir) {
  const file = path.join(dir, "audit.jsonl");
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function stripVolatile(envelope) {
  const d = JSON.parse(JSON.stringify(envelope));
  delete d.request_id;
  if (d.data) delete d.data.collected_at;
  return JSON.stringify(d);
}

const HEALTH_COLUMNS = ["check_name", "status", "value", "evidence", "recommendation"];
const WORKLOAD_COLUMNS = ["query_fingerprint", "calls", "total_ms", "mean_ms", "rows_returned"];
const SEVERITIES = ["healthy", "info", "warning", "critical"];
const SEVERITY_RANK = { healthy: 0, info: 1, warning: 2, critical: 3 };

function assertSuccessEnvelope(res, toolName, connection) {
  assert.ok(!res.rpcError, `JSON-RPC error: ${JSON.stringify(res.rpcError)}`);
  assert.equal(res.isError, false, `isError=true: ${JSON.stringify(res.body).slice(0, 300)}`);
  const b = res.body;
  assert.equal(b.status, "ok");
  assert.match(b.request_id, /^req_[0-9a-f]{12}$/);
  assert.equal(b.connection, connection);
  assert.ok(Array.isArray(b.columns) && Array.isArray(b.rows) && Array.isArray(b.warnings));
  assert.equal(typeof b.returned_rows, "number");
  assert.equal(b.returned_rows, b.rows.length, "returned_rows must equal rows.length");
  assert.equal(b.truncated, false);
  assert.equal(typeof b.schema_version, "string");
  assert.equal(b._meta.provenance.untrusted_content, true);
  assert.equal(b._meta.provenance.source_kind, toolName);
  assert.equal(b._meta.provenance.source_connection, connection);
}

function assertDenied(res, code, opts = {}) {
  assert.ok(!res.rpcError, `expected structured denial, got JSON-RPC error ${JSON.stringify(res.rpcError)}`);
  assert.equal(res.isError, true, `expected isError=true, body=${JSON.stringify(res.body).slice(0, 300)}`);
  assert.equal(res.body.status, "denied");
  assert.equal(res.body.code, code);
  assert.equal(typeof res.body.message, "string");
  if (opts.nextAction !== false) {
    assert.equal(typeof res.body.next_action, "string", "denial must carry next_action");
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const iso = makeIsolatedConfig({});
  console.log(`# isolated config: ${iso.configPath}`);
  let s = await openSession(iso.configPath);

  // ======================= 1. database_health on prod-postgres =======================
  const pgHealthA = await s.call("database_health", { connection: "prod-postgres" });
  const pgHealthB = await s.call("database_health", { connection: "prod-postgres" });
  const pgH = pgHealthA.body;

  check("health/pg: success envelope (request_id, connection, status, columns, rows, returned_rows, truncated, warnings, schema_version, _meta)", () => {
    assertSuccessEnvelope(pgHealthA, "database_health", "prod-postgres");
    assert.deepEqual(pgH.columns.map((c) => c.name), HEALTH_COLUMNS);
    assert.equal(pgH.schema_version, "snapshot_health");
  });

  check("health/pg: data.findings present, returned_rows == findings.length == 7 checks", () => {
    assert.ok(Array.isArray(pgH.data.findings));
    assert.equal(pgH.returned_rows, pgH.data.findings.length);
    assert.deepEqual(
      pgH.data.findings.map((f) => f.check_id),
      ["buffer_cache_hit_ratio", "connection_saturation", "dead_tuple_bloat", "invalid_indexes", "missing_fk_indexes", "unindexed_large_tables", "long_running_queries"]
    );
  });

  check("health/pg: every row mirrors its finding (check_id, severity, summary, evidence, recommendation text)", () => {
    pgH.rows.forEach((row, i) => {
      const f = pgH.data.findings[i];
      assert.equal(row.length, 5);
      assert.equal(row[0], f.check_id);
      assert.equal(row[1], f.severity);
      assert.equal(row[2], f.summary);
      assert.deepEqual(row[3], f.evidence);
      assert.equal(row[4], f.remediation || "No action needed.");
      assert.ok(SEVERITIES.includes(f.severity), `unknown severity ${f.severity}`);
      assert.equal(typeof f.category, "string");
      if (f.severity !== "healthy") assert.equal(typeof f.remediation, "string", "non-healthy findings need a recommendation");
    });
  });

  check("health/pg: metric values plausible and internally consistent (ratios in 0..1, counts >= 0, utilization = active/max, overall = max severity)", () => {
    const d = pgH.data;
    assert.equal(d.engine, "postgres");
    assert.equal(d.connection, "prod-postgres");
    assert.ok(d.cache_hit_ratio >= 0 && d.cache_hit_ratio <= 1);
    assert.ok(Number.isInteger(d.active_connections) && d.active_connections >= 0);
    assert.ok(Number.isInteger(d.max_connections) && d.max_connections >= 1);
    assert.ok(d.active_connections <= d.max_connections);
    assert.ok(Number.isInteger(d.dead_tuples_total) && d.dead_tuples_total >= 0);
    assert.ok(Number.isInteger(d.long_running_queries) && d.long_running_queries >= 0);
    assert.ok(!Number.isNaN(Date.parse(d.collected_at)));
    const byId = Object.fromEntries(d.findings.map((f) => [f.check_id, f]));
    const cache = byId.buffer_cache_hit_ratio.evidence;
    assert.equal(cache.cache_hit_ratio, d.cache_hit_ratio);
    assert.ok(cache.critical_threshold < cache.warning_threshold && cache.warning_threshold <= 1);
    const conn = byId.connection_saturation.evidence;
    assert.equal(conn.active_connections, d.active_connections);
    assert.equal(conn.max_connections, d.max_connections);
    assert.ok(Math.abs(conn.utilization_ratio - conn.active_connections / conn.max_connections) < 1e-9);
    const bloat = byId.dead_tuple_bloat.evidence;
    assert.equal(bloat.dead_tuples_total, d.dead_tuples_total);
    assert.ok(bloat.max_table_dead_ratio >= 0 && bloat.max_table_dead_ratio <= 1);
    assert.ok(Array.isArray(bloat.bloated_tables));
    const inv = byId.invalid_indexes.evidence;
    assert.equal(inv.invalid_index_count, inv.invalid_indexes.length);
    assert.deepEqual(d.invalid_indexes, inv.invalid_indexes);
    const lrq = byId.long_running_queries.evidence;
    assert.equal(lrq.count, d.long_running_queries);
    assert.equal(lrq.count, lrq.queries.length);
    assert.ok(lrq.max_duration_ms >= 0);
    assert.equal(byId.unindexed_large_tables.evidence.row_threshold, 10000);
    const maxSev = d.findings.reduce((m, f) => Math.max(m, SEVERITY_RANK[f.severity]), 0);
    assert.equal(SEVERITY_RANK[d.overall_status], maxSev);
  });

  check("health/pg: missing_fk_indexes is REAL (derived from the seeded catalog: 4 unindexed FKs)", () => {
    const fk = pgH.data.findings.find((f) => f.check_id === "missing_fk_indexes");
    assert.equal(fk.severity, "warning");
    const pairs = fk.evidence.unindexed_foreign_keys.map((k) => `${k.table}(${k.columns.join(",")})->${k.referenced_table}`).sort();
    assert.deepEqual(pairs, [
      "public.audit_logs(order_id)->orders",
      "public.order_items(order_id)->orders",
      "public.order_items(sku)->inventory",
      "public.orders(user_id)->users",
    ]);
  });

  check("health/pg: deterministic across calls (modulo request_id / collected_at)", () => {
    assertSuccessEnvelope(pgHealthB, "database_health", "prod-postgres");
    assert.equal(stripVolatile(pgHealthA.body), stripVolatile(pgHealthB.body));
  });

  // Simulation honesty: cache_hit_ratio/active_connections/dead_tuples come from
  // HealthTelemetrySnapshot::default() because the live probe (pg_stat_activity,
  // pg_stat_user_tables, current_setting) fails on the embedded simulation and the error is
  // swallowed. The response must say so.
  check("health/pg: response discloses that telemetry is simulated/default, not measured (warning or data.telemetry_source)", () => {
    const text = JSON.stringify(pgH.warnings) + JSON.stringify(pgH.data.telemetry_source || "") + JSON.stringify(pgH.data.source || "");
    assert.match(text, /simulat|synthetic|default|not measured|unavailable|fallback/i,
      `no simulation/default disclosure; warnings=${JSON.stringify(pgH.warnings)}`);
  });

  // ======================= 2. database_health on local-sqlite =======================
  const sqH = await s.call("database_health", { connection: "local-sqlite" });

  check("health/sqlite: success envelope + 7 rows mirroring findings", () => {
    assertSuccessEnvelope(sqH, "database_health", "local-sqlite");
    assert.equal(sqH.body.data.engine, "sqlite");
    assert.equal(sqH.body.returned_rows, sqH.body.data.findings.length);
    sqH.body.rows.forEach((row, i) => assert.equal(row[0], sqH.body.data.findings[i].check_id));
  });

  check("health/sqlite: missing_fk_indexes is REAL for the SQLite fixture (4 unindexed FKs in main.*)", () => {
    const fk = sqH.body.data.findings.find((f) => f.check_id === "missing_fk_indexes");
    const pairs = fk.evidence.unindexed_foreign_keys.map((k) => `${k.table}(${k.columns.join(",")})->${k.referenced_table}`).sort();
    assert.deepEqual(pairs, [
      "main.audit_logs(order_id)->orders",
      "main.order_items(order_id)->orders",
      "main.order_items(sku)->inventory",
      "main.orders(user_id)->users",
    ]);
  });

  check("health/sqlite: no fabricated PostgreSQL-only metrics (buffer cache / pg connections / dead tuples) reported for SQLite", () => {
    const ids = sqH.body.data.findings.map((f) => f.check_id);
    const pgOnly = ids.filter((id) => ["buffer_cache_hit_ratio", "connection_saturation", "dead_tuple_bloat"].includes(id));
    assert.deepEqual(pgOnly, [], `PostgreSQL-only checks reported for SQLite with hardcoded values: ${pgOnly.join(",")}`);
    assert.equal(sqH.body.data.cache_hit_ratio, undefined, "cache_hit_ratio must not be reported for SQLite");
  });

  check("health/sqlite: provides engine-appropriate checks (page_count/db size, journal_mode, integrity/quick_check, foreign_key_check)", () => {
    const ids = sqH.body.data.findings.map((f) => f.check_id).join(" ");
    assert.match(ids, /page|size|journal|integrity|quick_check|foreign_key_check/i, `only generic checks present: ${ids}`);
  });

  // ======================= 2b. database_health on analytics-mysql =======================
  const myH = await s.call("database_health", { connection: "analytics-mysql" });
  const connList = await s.call("list_connections", {});
  const mysqlCaps = connList.body.data.find((c) => c.id === "analytics-mysql").capabilities;

  check("caps: list_connections reports supports_health_diagnostics=false / supports_workload_analysis=false for analytics-mysql", () => {
    assert.equal(mysqlCaps.supports_health_diagnostics, false);
    assert.equal(mysqlCaps.supports_workload_analysis, false);
  });

  check("health/mysql: structured unsupported-capability denial with next_action (not a fabricated report)", () => {
    assert.ok(!myH.rpcError, "must not crash the transport");
    assert.equal(myH.isError, true, `database_health executed on MySQL and returned ${myH.body.returned_rows} fabricated checks (cache_hit_ratio=${myH.body.data && myH.body.data.cache_hit_ratio})`);
    assert.equal(myH.body.status, "denied");
    assert.match(myH.body.code, /UNSUPPORTED|CAPABILITY|NOT_SUPPORTED/i);
    assert.equal(typeof myH.body.next_action, "string");
  });

  check("health/mysql: no transport crash (either denial or envelope is structured JSON)", () => {
    assert.ok(!myH.rpcError);
    assert.ok(myH.body && typeof myH.body.status === "string");
  });

  // ======================= 3. analyze_workload: top_n handling (synthesized source) =======================
  const wlDefault = await s.call("analyze_workload", { connection: "prod-postgres" });
  const wl1 = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 1 });
  const wl5 = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 5 });
  const wl1000 = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 1000 });
  const wl0 = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 0 });
  const wlNeg = await s.call("analyze_workload", { connection: "prod-postgres", top_n: -3 });
  const wlStr = await s.call("analyze_workload", { connection: "prod-postgres", top_n: "5" });

  check("workload/pg: success envelope with contract columns, returned_rows == top_queries.length", () => {
    assertSuccessEnvelope(wlDefault, "analyze_workload", "prod-postgres");
    assert.deepEqual(wlDefault.body.columns.map((c) => c.name), WORKLOAD_COLUMNS);
    assert.equal(wlDefault.body.schema_version, "snapshot_workload");
    assert.equal(wlDefault.body.returned_rows, wlDefault.body.data.top_queries.length);
    assert.ok(wlDefault.body.returned_rows >= 1);
  });

  check("workload/pg: rows mirror top_queries (fingerprint, calls, total_ms, mean_ms, rows) with non-negative numbers and mean == total/calls", () => {
    wlDefault.body.rows.forEach((row, i) => {
      const q = wlDefault.body.data.top_queries[i];
      assert.deepEqual(row, [q.normalized_query, q.calls, q.total_exec_time_ms, q.mean_exec_time_ms, q.rows]);
      assert.ok(q.calls >= 1 && q.total_exec_time_ms >= 0 && q.mean_exec_time_ms >= 0 && q.rows >= 0);
      assert.ok(Math.abs(q.mean_exec_time_ms - q.total_exec_time_ms / q.calls) < 1e-6, `mean != total/calls for ${q.query_id}`);
      assert.match(q.query_id, /^q_[0-9a-f]{12}$|^q_\d+$/);
    });
  });

  check("workload/pg: ordered by total_ms desc, ties by mean_ms desc", () => {
    const qs = wlDefault.body.data.top_queries;
    for (let i = 1; i < qs.length; i++) {
      const a = qs[i - 1], b = qs[i];
      assert.ok(a.total_exec_time_ms > b.total_exec_time_ms || (a.total_exec_time_ms === b.total_exec_time_ms && a.mean_exec_time_ms >= b.mean_exec_time_ms),
        `row ${i - 1} (${a.total_exec_time_ms}/${a.mean_exec_time_ms}) before row ${i} (${b.total_exec_time_ms}/${b.mean_exec_time_ms})`);
    }
  });

  check("workload/pg: top_n omitted -> default 10 (<= 10 rows), top_n=1 -> 1 row, top_n=5 -> <=5 rows, top_n=1000 -> all without truncation", () => {
    assert.ok(wlDefault.body.returned_rows <= 10);
    assert.equal(wl1.body.returned_rows, 1);
    assert.ok(wl5.body.returned_rows <= 5 && wl5.body.returned_rows >= 1);
    assert.equal(wl1000.body.truncated, false);
    assert.ok(wl1000.body.returned_rows >= wl5.body.returned_rows);
  });

  // The JSON schema declares top_n as integer; 0/negative/non-integer are currently coerced to 10 silently.
  check("workload/pg: top_n = 0 / -3 / \"5\" are rejected with INVALID_ARGUMENT (or accepted with an explicit warning), never silently replaced by 10", () => {
    for (const [label, r] of [["0", wl0], ["-3", wlNeg], ['"5"', wlStr]]) {
      const denied = r.isError && r.body.code === "INVALID_ARGUMENT";
      const warned = !r.isError && r.body.warnings.some((w) => /top_n/i.test(w));
      assert.ok(denied || warned, `top_n=${label} silently coerced: rows=${r.body.returned_rows} warnings=${JSON.stringify(r.body.warnings)}`);
    }
  });

  // Restricted tables must never surface in diagnostics (search_objects / describe_object already hide them).
  check("workload/pg: restricted table internal_secrets never appears in synthesized workload / hot_tables", () => {
    const text = JSON.stringify(wl1000.body);
    assert.ok(!/internal_secrets/.test(text), "restricted table leaked into analyze_workload output");
  });

  // The simulation seeds __pg_stat_statements (q_1001, q_1002) and has_pg_stat_statements=true,
  // yet the engine queries `pg_stat_statements` (unmapped) and silently falls back to a synthetic profile.
  // KNOWN-BUG: F08-08
  check("workload/pg: with has_pg_stat_statements=true the source is pg_stat_statements and the seeded statements (q_1001/q_1002) are ranked", () => {
    const d = wlDefault.body.data;
    assert.equal(d.source, "pg_stat_statements", `source=${d.source}; notes=${JSON.stringify(d.notes)}`);
    const ids = d.top_queries.map((q) => q.query_id);
    assert.ok(ids.includes("q_1001") && ids.includes("q_1002"));
    assert.equal(d.top_queries[0].query_id, "q_1001"); // 4250ms total > 1200ms total
  }, "KNOWN-BUG: F08-08");

  check("workload/pg: output never contradicts the connection capability (supports_workload_analysis=true but notes claim pg_stat_statements inactive)", () => {
    const pgCaps = connList.body.data.find((c) => c.id === "prod-postgres").capabilities;
    assert.equal(pgCaps.supports_workload_analysis, true);
    const claimsInactive = (wlDefault.body.data.notes || []).some((n) => /not active/i.test(n));
    assert.ok(!claimsInactive || wlDefault.body.warnings.length > 0,
      `notes say pg_stat_statements inactive while capability says supported, and warnings=[]`);
  });

  // ======================= 3b. analyze_workload on sqlite / mysql (no history yet) =======================
  const sqWl0 = await s.call("analyze_workload", { connection: "local-sqlite" });
  const myWl0 = await s.call("analyze_workload", { connection: "analytics-mysql" });

  check("workload/sqlite+mysql: structured success envelope before any history (fallback source, not a crash)", () => {
    assertSuccessEnvelope(sqWl0, "analyze_workload", "local-sqlite");
    assertSuccessEnvelope(myWl0, "analyze_workload", "analytics-mysql");
    assert.equal(sqWl0.body.returned_rows, sqWl0.body.data.top_queries.length);
    assert.equal(myWl0.body.returned_rows, myWl0.body.data.top_queries.length);
  });

  check("caps: sqlite unavailable_reasons.workload_analysis announces the query-history fallback", () => {
    const sqCaps = connList.body.data.find((c) => c.id === "local-sqlite").capabilities;
    assert.equal(sqCaps.supports_health_diagnostics, true);
    assert.equal(sqCaps.supports_workload_analysis, false);
    assert.match(sqCaps.unavailable_reasons.workload_analysis, /query history fallback/i);
  });

  check("workload/sqlite+mysql: fallback note is engine-appropriate (does not talk about pg_stat_statements on SQLite/MySQL)", () => {
    for (const r of [sqWl0, myWl0]) {
      const notes = JSON.stringify(r.body.data.notes);
      assert.ok(!/pg_stat_statements/.test(notes), `${r.body.connection}: ${notes}`);
    }
  });

  // ======================= 3c. runtime telemetry via execute_query =======================
  const SECRET = "TOPSECRET_TOKEN_123";
  const qPending = "SELECT count(*) FROM orders WHERE status = 'pending'";
  const qAlice = "SELECT id, email FROM users WHERE email = 'alice@example.com' AND password_hash = 'hash_alice_secret'";
  const qSecret = `SELECT id, email FROM users WHERE email = 'bob@example.com' AND password_hash = '${SECRET}'`;
  const execs = [];
  for (const [conn, sql] of [
    ["prod-postgres", qPending], ["prod-postgres", qPending], ["prod-postgres", qPending],
    ["prod-postgres", qAlice], ["prod-postgres", qSecret],
    ["local-sqlite", qPending],
  ]) execs.push({ conn, sql, res: await s.call("execute_query", { connection: conn, sql }) });

  check("telemetry: all seed execute_query calls succeeded", () => {
    for (const e of execs) assert.equal(e.res.isError, false, `${e.conn}: ${JSON.stringify(e.res.body).slice(0, 200)}`);
  });

  const wlPg = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 10 });
  const wlPgTop1 = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 1 });
  const wlSq = await s.call("analyze_workload", { connection: "local-sqlite", top_n: 10 });

  check("telemetry/pg: after execute_query the source is recorded_workload_history with aggregated call counts (3 calls for the repeated query)", () => {
    assertSuccessEnvelope(wlPg, "analyze_workload", "prod-postgres");
    assert.equal(wlPg.body.data.source, "recorded_workload_history");
    const pending = wlPg.body.data.top_queries.find((q) => /FROM orders WHERE status/.test(q.normalized_query));
    assert.ok(pending, "repeated query missing from workload");
    assert.equal(pending.calls, 3);
    assert.ok(pending.total_exec_time_ms >= 0 && Math.abs(pending.mean_exec_time_ms - pending.total_exec_time_ms / 3) < 1e-6);
    assert.equal(pending.rows, 3);
    assert.ok(pending.tables_referenced.includes("orders"));
    assert.ok(wlPg.body.data.hot_tables.includes("orders") && wlPg.body.data.hot_tables.includes("users"));
    assert.deepEqual(wlPg.body.data.notes, []);
  });

  check("telemetry/pg: top_n=1 returns 1 row while total_queries_analyzed reports the full history size", () => {
    assert.equal(wlPgTop1.body.returned_rows, 1);
    assert.equal(wlPgTop1.body.data.total_queries_analyzed, wlPg.body.data.total_queries_analyzed);
    assert.ok(wlPgTop1.body.data.total_queries_analyzed >= 3);
  });

  check("telemetry: history is kept per connection (sqlite sees only its own 1 execution)", () => {
    assert.equal(wlSq.body.data.source, "recorded_workload_history");
    assert.equal(wlSq.body.data.total_queries_analyzed, 1);
    assert.equal(wlSq.body.data.top_queries[0].calls, 1);
    assert.ok(!JSON.stringify(wlSq.body).includes("alice@example.com"));
  });

  // Literal values (including secrets) must be normalized/redacted in query fingerprints.
  check("telemetry/pg: query fingerprints are normalized - literal secrets from SQL are NOT echoed in analyze_workload output", () => {
    const text = JSON.stringify(wlPg.body);
    assert.ok(!text.includes(SECRET), `secret literal echoed in analyze_workload response`);
    assert.ok(!text.includes("hash_alice_secret"), `password_hash literal echoed`);
    assert.ok(!text.includes("'pending'"), `string literal not parameterized`);
  });

  // ======================= 4. denials: unknown connection / missing argument =======================
  const dUnknownH = await s.call("database_health", { connection: "does-not-exist" });
  const dUnknownW = await s.call("analyze_workload", { connection: "does-not-exist" });
  const dMissingH = await s.call("database_health", {});
  const dMissingW = await s.call("analyze_workload", {});
  const dBlankH = await s.call("database_health", { connection: "   " });

  check("denial: unknown connection -> CONNECTION_NOT_FOUND with next_action=list_connections (both tools)", () => {
    assertDenied(dUnknownH, "CONNECTION_NOT_FOUND");
    assertDenied(dUnknownW, "CONNECTION_NOT_FOUND");
    assert.equal(dUnknownH.body.next_action, "list_connections");
    assert.equal(dUnknownH.body.connection, "does-not-exist");
    assert.match(dUnknownH.body.request_id, /^req_/);
  });

  check("denial: missing/blank connection argument -> INVALID_ARGUMENT naming the parameter (both tools)", () => {
    assertDenied(dMissingH, "INVALID_ARGUMENT", { nextAction: false });
    assertDenied(dMissingW, "INVALID_ARGUMENT", { nextAction: false });
    assertDenied(dBlankH, "INVALID_ARGUMENT", { nextAction: false });
    assert.match(dMissingH.body.message, /'connection'/);
    assert.equal(dMissingH.body.retryable, false);
  });

  // ======================= 6. latency =======================
  check("latency: every database_health / analyze_workload call completed in < 2000 ms", () => {
    const slow = latencies.filter((l) => /database_health|analyze_workload/.test(l.name) && l.ms >= 2000);
    assert.deepEqual(slow, []);
  });

  await s.close();

  // ======================= 7. audit records =======================
  const audit = readAuditRecords(iso.dir);
  check("audit: isolated audit.jsonl exists and holds the execute_query records (chain hashed)", () => {
    assert.ok(audit.length >= execs.length, `only ${audit.length} records`);
    const ex = audit.filter((r) => r.tool_name === "execute_query");
    assert.equal(ex.length, execs.length);
    assert.ok(ex.every((r) => r.decision === "allowed" && typeof r.chain_hash === "string"));
  });

  // Neither Diagnose tool calls log_audit (crates/db-mcp-mcp/src/lib.rs:614-634), so the audit trail
  // has no trace of the 20+ health/workload calls above.
  check("audit: each database_health / analyze_workload call (allowed and denied) produces an audit record", () => {
    const health = audit.filter((r) => r.tool_name === "database_health");
    const workload = audit.filter((r) => r.tool_name === "analyze_workload");
    const expectedHealth = latencies.filter((l) => l.name === "database_health").length;
    const expectedWorkload = latencies.filter((l) => l.name === "analyze_workload").length;
    assert.equal(health.length, expectedHealth, `database_health audit records: ${health.length} of ${expectedHealth}`);
    assert.equal(workload.length, expectedWorkload, `analyze_workload audit records: ${workload.length} of ${expectedWorkload}`);
  });

  // ======================= 3d. persistence across restart =======================
  s = await openSession(iso.configPath);
  const wlAfterRestart = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 10 });
  await s.close();

  // Capability text promises a "query history fallback" and the audit store holds every execution,
  // but the tracker is purely in-memory, so a restart silently drops the history and synthesizes a profile.
  // KNOWN-BUG: F08-12
  check("telemetry/pg: workload history survives a server restart (sourced from the durable audit/query history)", () => {
    const d = wlAfterRestart.body.data;
    assert.notEqual(d.source, "catalog_synthesized_workload", `after restart source=${d.source}`);
    assert.ok(d.top_queries.some((q) => /FROM orders WHERE status/.test(q.normalized_query)));
  }, "KNOWN-BUG: F08-12");

  // ======================= 5. role gating =======================
  const viewer = await openSession(iso.configPath, { role: "viewer", principal: "bob" });
  const roleDeniedH = await viewer.call("database_health", { connection: "prod-postgres" });
  const roleDeniedW = await viewer.call("analyze_workload", { connection: "prod-postgres" });
  const roleAllowed = await viewer.call("database_health", { connection: "local-sqlite" });
  await viewer.close();

  check("role gating: role 'viewer' is denied on prod-postgres (allowed_roles excludes it) with UNAUTHORIZED_ROLE + next_action, both tools", () => {
    assertDenied(roleDeniedH, "UNAUTHORIZED_ROLE");
    assertDenied(roleDeniedW, "UNAUTHORIZED_ROLE");
    assert.match(roleDeniedH.body.message, /viewer/);
    assert.equal(roleDeniedH.body.connection, "prod-postgres");
  });

  check("role gating: same viewer is allowed on local-sqlite (allowed_roles = [\"*\"])", () => {
    assertSuccessEnvelope(roleAllowed, "database_health", "local-sqlite");
  });

  // ======================= 3e. has_pg_stat_statements = false =======================
  const noPgss = makeIsolatedConfig({
    transform: (t) => t.replace("has_pg_stat_statements = true", "has_pg_stat_statements = false"),
  });
  s = await openSession(noPgss.configPath);
  const noPgssCaps = (await s.call("list_connections", {})).body.data.find((c) => c.id === "prod-postgres").capabilities;
  const noPgssWl = await s.call("analyze_workload", { connection: "prod-postgres" });
  await s.call("execute_query", { connection: "prod-postgres", sql: qPending });
  await s.call("execute_query", { connection: "prod-postgres", sql: qPending });
  const noPgssWl2 = await s.call("analyze_workload", { connection: "prod-postgres" });
  await s.close();

  check("pgss=false: capability flips to supports_workload_analysis=false with an unavailable_reasons entry", () => {
    assert.equal(noPgssCaps.supports_workload_analysis, false);
    assert.match(noPgssCaps.unavailable_reasons.workload_analysis, /pg_stat_statements/);
  });

  check("pgss=false: analyze_workload still answers (fallback) and switches to recorded_workload_history after execute_query (calls=2)", () => {
    assertSuccessEnvelope(noPgssWl, "analyze_workload", "prod-postgres");
    assert.equal(noPgssWl.body.data.source, "catalog_synthesized_workload");
    assert.ok(noPgssWl.body.data.notes.length >= 1, "fallback must be explained in notes");
    assert.equal(noPgssWl2.body.data.source, "recorded_workload_history");
    assert.equal(noPgssWl2.body.data.top_queries[0].calls, 2);
  });

  // ======================= 4. profile gating =======================
  const limited = makeIsolatedConfig({
    transform: (t) => t.replace(/^active_profiles\s*=.*$/m, 'active_profiles = ["Explore", "Query"]'),
  });
  s = await openSession(limited.configPath);
  const limitedTools = await s.listTools();
  const gatedH = await s.call("database_health", { connection: "prod-postgres" });
  const gatedW = await s.call("analyze_workload", { connection: "prod-postgres" });
  await s.close();

  check("profile gating: active_profiles=[Explore,Query] -> tools/list has no Diagnose tools", () => {
    for (const t of ["database_health", "analyze_workload", "recommend_indexes"]) assert.ok(!limitedTools.includes(t), `${t} still listed`);
    assert.ok(limitedTools.includes("execute_query") && limitedTools.includes("list_connections"));
  });

  check("profile gating: calling database_health / analyze_workload -> TOOL_NOT_ENABLED denial with next_action, not executed", () => {
    assertDenied(gatedH, "TOOL_NOT_ENABLED");
    assertDenied(gatedW, "TOOL_NOT_ENABLED");
    assert.match(gatedH.body.message, /database_health/);
    assert.equal(gatedH.body.data, undefined);
  });

  check("profile gating: gated calls leave no execution trace in the limited config's audit log", () => {
    const rec = readAuditRecords(limited.dir).filter((r) => /database_health|analyze_workload/.test(r.tool_name || ""));
    assert.ok(rec.every((r) => r.decision !== "allowed"));
  });

  // ======================= summary =======================
  const lat = {};
  for (const l of latencies) {
    if (!/database_health|analyze_workload/.test(l.name)) continue;
    const k = `${l.name}@${l.connection}`;
    lat[k] = lat[k] || [];
    lat[k].push(l.ms);
  }
  console.log("# latency (ms):", Object.entries(lat).map(([k, v]) => `${k}=${Math.min(...v)}..${Math.max(...v)}`).join("  "));
  const total = results.pass + results.failUnexpected + results.failKnown + results.fixed;
  console.log(`# F08 summary: ${results.pass} passed, ${results.failUnexpected} failed, ${results.failKnown} known-bug failures, ${results.fixed} fixed, ${total} total`);
  process.exitCode = results.failUnexpected === 0 ? 0 : 1;
}

main()
  .catch((err) => {
    console.error("FATAL", err);
    process.exitCode = 1;
  })
  .finally(() => {
    killAll();
    setTimeout(() => process.exit(process.exitCode || 0), 300);
  });
