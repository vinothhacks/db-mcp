#!/usr/bin/env node
"use strict";
/**
 * F15 - Multi-engine adapter layer and live-vs-simulated fallback honesty.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *
 *   node npm/test/features/15-adapters-fallback.test.js
 *
 * Every check encodes the CORRECT behaviour. Checks that currently fail because of a
 * known defect are tagged with `// KNOWN-BUG: <id>`; they are reported as KNOWN-BUG and
 * do not fail the run, but they are never weakened. Any other failure exits non-zero.
 *
 * The script only ever serves from isolated copies of config/db-mcp.example.toml
 * (scripts/make-isolated-config.js), starts short-lived local TCP listeners on ephemeral
 * ports, and kills every child process it spawned before exiting. Long OS connect
 * timeouts (black-hole addresses, unresolvable hosts) are intentionally NOT exercised here;
 * they were measured manually and reported separately.
 */

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const BIN_WRAPPER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const IS_WINDOWS = process.platform === "win32";

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------
const tally = { pass: 0, fail: 0, known: 0, fixed: 0 };
const failures = [];
const children = new Set();
const tempDirs = new Set();

const short = (s) => String(s).replace(/\s+/g, " ").slice(0, 220);
const info = (msg) => console.log(`INFO      ${msg}`);

async function check(name, fn, opts = {}) {
  try {
    await fn();
    if (opts.knownBug) {
      tally.fixed += 1;
      console.log(`FIXED     ${name} [${opts.knownBug} no longer reproduces - remove the KNOWN-BUG tag]`);
    } else {
      tally.pass += 1;
      console.log(`PASS      ${name}`);
    }
  } catch (err) {
    if (opts.knownBug) {
      tally.known += 1;
      console.log(`KNOWN-BUG ${name} [${opts.knownBug}] ${short(err.message)}`);
    } else {
      tally.fail += 1;
      failures.push(name);
      console.log(`FAIL      ${name}: ${short(err.message)}`);
    }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeConfig(variant, extra) {
  const transforms = {
    default: (t) => t,
    // Every connection writable + Development so dialect/DDL probes are not blocked by policy.
    dev: (t) =>
      t
        .replace(/^default_mode = "ReadOnly"/m, 'default_mode = "Development"')
        .replace(/^mode = "(GovernedProduction|ReadOnly)"/gm, 'mode = "Development"')
        .replace(/^read_only = true/gm, "read_only = false"),
    sqlite_ro: (t) => t.replace(/(id = "local-sqlite"[\s\S]*?)read_only = false/, "$1read_only = true"),
    pg_closed: (t) => t.replace("postgres://localhost:5432/app_prod", "postgres://u:p@127.0.0.1:1/app_prod"),
    pg_listener: (t) => t.replace("postgres://localhost:5432/app_prod", `postgres://u:p@127.0.0.1:${extra}/app_prod`),
    mysql_delimiter: (t) =>
      t.replace(
        /(id = "analytics-mysql"[\s\S]*?init_sql = """)/,
        "$1\nDELIMITER //\nCREATE PROCEDURE sp_x() BEGIN SELECT 1; END //\nDELIMITER ;\n"
      ),
  };
  const r = makeIsolatedConfig({ transform: transforms[variant] });
  tempDirs.add(r.dir);
  return r;
}

async function startServer(configPath, timeoutMs = 30000) {
  const c = createClient({ config: configPath, principal: "local-agent", role: "agent", timeoutMs });
  children.add(c.child);
  c.exited = new Promise((resolve) => c.child.once("exit", (code, sig) => resolve({ code, sig })));
  const init = await Promise.race([
    c.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f15", version: "0" } }),
    c.exited.then((e) => ({ error: { message: `server exited before initialize: ${JSON.stringify(e)} stderr=${c.stderr.join("")}` } })),
  ]);
  if (init.error) throw new Error(`initialize failed: ${short(JSON.stringify(init.error))}`);
  c.notify("notifications/initialized", {});
  c.call = async (name, args) => {
    const r = await c.rpc("tools/call", { name, arguments: args || {} });
    if (r.error) throw new Error(`JSON-RPC error for ${name}: ${JSON.stringify(r.error)}`);
    return r.result.structuredContent;
  };
  // Clean shutdown: close stdin and wait for exit; hard-kill after 5 s.
  c.stop = async () => {
    try { c.child.stdin.end(); } catch { /* ignore */ }
    const res = await Promise.race([c.exited, sleep(5000).then(() => "TIMEOUT")]);
    if (res === "TIMEOUT") { try { c.child.kill(); } catch { /* ignore */ } }
    children.delete(c.child);
    return res;
  };
  return c;
}

process.on("exit", () => {
  for (const ch of children) { try { ch.kill(); } catch { /* ignore */ } }
  for (const d of tempDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
});

const discloses = (payload) => /simulat|embedded|offline|fallback|not\s+(?:a\s+)?live|unreachable|in-?memory/i.test(JSON.stringify(payload));
const isDenied = (p) => p && p.status === "denied";

function approveViaCli(changeId, configPath) {
  const r = spawnSync(
    process.execPath,
    [BIN_WRAPPER, "approve", "--change-id", changeId, "--approver", "dba-admin", "--role", "admin", "--config", configPath],
    { cwd: REPO_ROOT, encoding: "utf8" }
  );
  return r.status;
}

function processStats(pid) {
  if (!IS_WINDOWS) return null;
  const r = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-Command", `$p=Get-Process -Id ${pid}; "$($p.HandleCount) $($p.WorkingSet64)"`],
    { encoding: "utf8" }
  );
  if (r.status !== 0) return null;
  const [h, ws] = r.stdout.trim().split(" ").map(Number);
  return { handles: h, workingSet: ws };
}

// Recursive CTE that runs for seconds unless interrupted (bound keeps runaway threads short).
const LONG_SQL = (n) => `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < ${n}) SELECT COUNT(*) FROM c`;

// ---------------------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------------------
async function sectionTruthInAdvertising(s) {
  console.log("\n[1] Truth in advertising: do the Postgres/MySQL connections say they are simulated?");
  const list = await s.call("list_connections");
  const byId = Object.fromEntries(list.data.map((c) => [c.id, c]));

  await check("list_connections returns the three example connections with capability blocks", () => {
    assert.deepEqual(Object.keys(byId).sort(), ["analytics-mysql", "local-sqlite", "prod-postgres"]);
    for (const c of list.data) assert.equal(typeof c.capabilities.supports_explain, "boolean");
  });

  for (const id of ["prod-postgres", "analytics-mysql"]) {
    const sel = await s.call("execute_query", { connection: id, sql: "SELECT 1" });
    await check(`${id}: execute_query SELECT 1 succeeds through the fallback engine`, () => {
      assert.equal(sel.status, "ok");
      assert.deepEqual(sel.rows, [[1]]);
    });
    await check(`${id}: list_connections entry discloses the backend is simulated/embedded`, () => {
      assert.ok(discloses(byId[id]), `no disclosure field in ${JSON.stringify(byId[id]).slice(0, 200)}`);
    });
    await check(`${id}: execute_query warnings disclose that rows did not come from a live server`, () => {
      assert.ok(Array.isArray(sel.warnings));
      assert.ok(sel.warnings.some((w) => discloses(w)), `warnings=${JSON.stringify(sel.warnings)}`);
    });
    const objs = await s.call("search_objects", { connection: id, limit: 5 });
    const plan = await s.call("explain_query", { connection: id, sql: "SELECT * FROM orders WHERE user_id = 1" });
    await check(`${id}: search_objects and explain_query disclose the simulated backend`, () => {
      assert.equal(objs.status, "ok");
      assert.equal(plan.status, "ok");
      assert.ok(discloses(objs) || discloses(objs.warnings), "search_objects has no disclosure");
      assert.ok(discloses(plan.data.warnings) || discloses(plan.warnings), "explain_query has no disclosure");
    });
  }

  const health = {};
  for (const id of ["prod-postgres", "analytics-mysql", "local-sqlite"]) health[id] = await s.call("database_health", { connection: id });
  await check("database_health on prod-postgres discloses that telemetry is synthetic (not pg_stat_*)", () => {
    assert.equal(health["prod-postgres"].status, "ok");
    assert.ok(discloses(health["prod-postgres"]), `report=${JSON.stringify(health["prod-postgres"].data).slice(0, 160)}`);
  });
  await check("database_health on analytics-mysql is refused (capabilities.supports_health_diagnostics=false)", () => {
    assert.equal(byId["analytics-mysql"].capabilities.supports_health_diagnostics, false);
    assert.ok(isDenied(health["analytics-mysql"]), `got status=${health["analytics-mysql"].status} active_connections=${health["analytics-mysql"].data && health["analytics-mysql"].data.active_connections}`);
  });
  await check("database_health on local-sqlite does not report PostgreSQL-only metrics (dead tuples, cache hit ratio)", () => {
    const d = health["local-sqlite"].data;
    assert.equal(d.engine, "sqlite");
    assert.ok(d.dead_tuples_total === undefined || d.dead_tuples_total === null, `dead_tuples_total=${d.dead_tuples_total}`);
    assert.ok(!d.findings.some((f) => f.check_id === "buffer_cache_hit_ratio"), "buffer_cache_hit_ratio finding present for SQLite");
  });
  info(`database_health numbers: pg active=${health["prod-postgres"].data.active_connections} hit=${health["prod-postgres"].data.cache_hit_ratio} dead=${health["prod-postgres"].data.dead_tuples_total}; mysql active=${health["analytics-mysql"].data && health["analytics-mysql"].data.active_connections}; sqlite dead=${health["local-sqlite"].data.dead_tuples_total}`);

  // Disclosure on every remaining tool (v0.2.1 stamps a simulated-engine warning in the envelope).
  const lineage = await s.call("get_procedure_call_graph", { connection: "prod-postgres" });
  const onto = await s.call("ontology_status", { connection: "prod-postgres" });
  const disc = await s.call("discover_ontology", { connection: "prod-postgres" });
  const lineageSqlite = await s.call("get_procedure_call_graph", { connection: "local-sqlite" });
  await check("get_procedure_call_graph / ontology_status / discover_ontology on simulated pg carry the simulation warning; sqlite does not", () => {
    for (const r of [lineage, onto, disc]) assert.ok((r.warnings || []).some((w) => /embedded simulated postgres engine/.test(w)), JSON.stringify(r.warnings));
    assert.ok(!(lineageSqlite.warnings || []).some(discloses), JSON.stringify(lineageSqlite.warnings));
  });
  const myRoutines = await s.call("search_objects", { connection: "analytics-mysql", object_types: ["function", "procedure"], detail_level: "names", limit: 50 });
  // KNOWN-BUG: F02-06 simulated MySQL seeds 4 demo routines (bootstrap_mysql_system_tables) that no init_sql defined
  await check("analytics-mysql defines no routines in init_sql, so the catalog lists none (no phantom demo routines)", () => {
    assert.deepEqual(myRoutines.data.objects.map((o) => o.name), []);
  }, { knownBug: "F02-06" });
  const ver = await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT version()" });
  // KNOWN-BUG: F15-05 (dialect) a real PostgreSQL answers; the simulation leaks a SQLite error
  await check("prod-postgres: SELECT version() returns a PostgreSQL version string", () => {
    assert.equal(ver.status, "ok", `got ${ver.code}: ${ver.message}`);
    assert.match(String(ver.rows[0][0]), /PostgreSQL/);
  }, { knownBug: "F15-05" });
  await check("prod-postgres: unsupported SQL fails closed (denied) instead of returning fabricated rows", () => {
    assert.ok(isDenied(ver));
    assert.equal(ver.code, "ADAPTER_ERROR");
  });
}

async function sectionLivePath() {
  console.log("\n[2] Live path reality check (what does 'live' mean?)");
  // 2a. TCP listener that accepts and records bytes.
  const conns = [];
  const srv = net.createServer((sock) => {
    const e = { bytes: 0, hex: "", opened: Date.now(), closed: null };
    conns.push(e);
    sock.on("data", (d) => { e.bytes += d.length; e.hex += d.toString("hex"); });
    sock.on("close", () => { e.closed = Date.now(); });
    sock.on("error", () => {});
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const cfgL = makeConfig("pg_listener", port);
  const sL = await startServer(cfgL.configPath);
  const r1 = await sL.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1" });
  await sL.call("search_objects", { connection: "prod-postgres", limit: 3 });
  const r2 = await sL.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1" });
  await sleep(100);
  info(`listener on :${port} saw ${conns.length} TCP connection(s); bytes received per connection: ${JSON.stringify(conns.map((c) => c.bytes))}; lifetimes ms: ${JSON.stringify(conns.map((c) => (c.closed || Date.now()) - c.opened))}`);
  await check("a reachable DSN is probed with a TCP connect on every call (probe result is never cached)", () => {
    assert.ok(conns.length >= 2, `only ${conns.length} connection(s) observed`);
  });
  // KNOWN-BUG: F15-03 the probe is connect-and-drop; the v3 StartupMessage (probe_postgres_wire_handshake) is never sent
  await check("the connectivity probe speaks the PostgreSQL wire protocol (StartupMessage 0x00030000 observed)", () => {
    assert.ok(conns.some((c) => c.bytes > 0), "zero bytes were ever sent on any probe connection");
    assert.ok(conns.some((c) => c.hex.includes("00030000")), "no StartupMessage protocol marker");
  }, { knownBug: "F15-03" });
  await check("with a reachable server, results are either from that server or carry an explicit simulation warning", () => {
    assert.equal(r1.status, "ok");
    assert.ok(r1.warnings.some(discloses) || r2.warnings.some(discloses), `warnings=${JSON.stringify(r1.warnings)}`);
  });
  await sL.stop();
  srv.close();

  // 2b. Closed port: fallback must be fast and bounded (no OS connect hang), every call still answered.
  const cfgC = makeConfig("pg_closed");
  const sC = await startServer(cfgC.configPath);
  const timings = [];
  for (const [tool, args] of [
    ["execute_query", { connection: "prod-postgres", sql: "SELECT 1" }],
    ["search_objects", { connection: "prod-postgres", limit: 3 }],
    ["explain_query", { connection: "prod-postgres", sql: "SELECT * FROM users WHERE id = 1" }],
    ["execute_query", { connection: "prod-postgres", sql: "SELECT 1" }],
  ]) {
    const t = Date.now();
    const res = await sC.call(tool, args);
    timings.push({ tool, ms: Date.now() - t, status: res.status });
  }
  info(`closed-port per-call latency: ${timings.map((t) => `${t.tool}=${t.ms}ms`).join(" ")}`);
  await check("closed port: every call still succeeds via the fallback within a bounded time (< 2500 ms each)", () => {
    for (const t of timings) { assert.equal(t.status, "ok", `${t.tool} status=${t.status}`); assert.ok(t.ms < 2500, `${t.tool} took ${t.ms} ms`); }
  });
  await sC.stop();
}

async function sectionDialects(s) {
  console.log("\n[3] Dialect rewriting fidelity on the embedded engines (Development-mode copies)");
  const pg = (sql, params) => s.call("execute_query", { connection: "prod-postgres", sql, params });
  const my = (sql, params) => s.call("execute_query", { connection: "analytics-mysql", sql, params });

  // --- PostgreSQL-isms ---
  const ddl = await pg("CREATE TABLE t_serial (id SERIAL PRIMARY KEY, name TEXT)");
  const ret = await pg("INSERT INTO t_serial (name) VALUES ('a') RETURNING id");
  // KNOWN-BUG: F15-04 SERIAL is accepted but never auto-assigns ids (NULL primary keys)
  await check("pg: SERIAL PRIMARY KEY auto-assigns an id (INSERT ... RETURNING id -> 1)", () => {
    assert.equal(ddl.status, "ok", ddl.message);
    assert.equal(ret.status, "ok", ret.message);
    assert.equal(ret.rows[0][0], 1, `RETURNING id gave ${JSON.stringify(ret.rows)}`);
  }, { knownBug: "F15-04" });
  await check("pg: RETURNING clause is honoured (a row comes back)", () => {
    assert.equal(ret.status, "ok");
    assert.equal(ret.rows.length, 1);
  });
  const p1 = await pg("SELECT id FROM users WHERE id = $1", [1]);
  await check("pg: single $1 positional parameter binds", () => { assert.equal(p1.status, "ok"); assert.deepEqual(p1.rows, [[1]]); });
  const p2 = await pg("SELECT $2 AS second, $1 AS first", ["A", "B"]);
  // KNOWN-BUG: F15-05 $n placeholders are bound by order of appearance, not by number
  await check("pg: $2/$1 placeholders bind by number ($2 AS second -> 'B', $1 AS first -> 'A')", () => {
    assert.equal(p2.status, "ok", p2.message);
    assert.deepEqual(p2.rows, [["B", "A"]], `got ${JSON.stringify(p2.rows)}`);
  }, { knownBug: "F15-05" });
  const lit = await pg("SELECT 'public.users' AS s");
  const upd = await pg("UPDATE users SET role = 'public.x' WHERE id = 2 RETURNING role");
  const rb = await pg("SELECT role FROM users WHERE id = 2");
  // KNOWN-BUG: F15-06 rewrite_non_routine_pg_fragment strips "public." inside string literals (data corruption on write)
  await check("pg: string literals containing 'public.' are not rewritten (SELECT 'public.users' -> 'public.users'; UPDATE persists 'public.x')", () => {
    assert.equal(lit.status, "ok");
    assert.deepEqual(lit.rows, [["public.users"]], `SELECT gave ${JSON.stringify(lit.rows)}`);
    assert.deepEqual(rb.rows, [["public.x"]], `UPDATE persisted ${JSON.stringify(rb.rows)}`);
  }, { knownBug: "F15-06" });
  const cast = await pg("SELECT 1::text AS t");
  const bools = await pg("SELECT TRUE AS t, FALSE AS f");
  // KNOWN-BUG: F15-07 ::casts are deleted and booleans surface as bigint 1/0
  await check("pg: type fidelity (1::text -> text '1'; TRUE/FALSE -> booleans)", () => {
    assert.equal(cast.status, "ok");
    assert.equal(cast.columns[0].data_type, "text", `1::text typed as ${cast.columns[0].data_type}`);
    assert.equal(bools.status, "ok");
    assert.deepEqual(bools.rows, [[true, false]], `TRUE/FALSE gave ${JSON.stringify(bools.rows)}`);
  }, { knownBug: "F15-07" });
  const quoted = await pg('SELECT "email" FROM "public"."users" WHERE id = 1');
  // KNOWN-BUG: F15-08 only unquoted public. is stripped; "public"."users" fails with no such table
  await check('pg: quoted schema qualification "public"."users" resolves', () => {
    assert.equal(quoted.status, "ok", `${quoted.code}: ${quoted.message}`);
  }, { knownBug: "F15-08" });
  const fdef = await pg("CREATE OR REPLACE FUNCTION f1(x int) RETURNS int LANGUAGE plpgsql AS $$ BEGIN RETURN x+1; END; $$");
  const pdef = await pg("CREATE PROCEDURE p1() LANGUAGE plpgsql AS $$ BEGIN UPDATE users SET role='x' WHERE id=0; END; $$");
  const routines = await s.call("search_objects", { connection: "prod-postgres", object_types: ["function", "procedure"], limit: 50 });
  await check("pg: $$-quoted CREATE FUNCTION/PROCEDURE are accepted and appear in the catalog", () => {
    assert.equal(fdef.status, "ok", fdef.message);
    assert.equal(pdef.status, "ok", pdef.message);
    const names = routines.data.objects.map((o) => `${o.object_type}:${o.name}`);
    assert.ok(names.includes("function:f1") && names.includes("procedure:p1"), names.join(","));
  });
  const fcall = await pg("SELECT f1(1) AS v");
  const pcall = await pg("CALL p1()");
  // KNOWN-BUG: F15-09 routines are catalog metadata only; they cannot be invoked
  await check("pg: a created function/procedure can be invoked (SELECT f1(1) = 2; CALL p1())", () => {
    assert.equal(fcall.status, "ok", `${fcall.code}: ${fcall.message}`);
    assert.deepEqual(fcall.rows, [[2]]);
    assert.equal(pcall.status, "ok", `${pcall.code}: ${pcall.message}`);
  }, { knownBug: "F15-09" });
  const bigddl = await pg("CREATE TABLE t_big (id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT NOW(), flag BOOLEAN DEFAULT TRUE)");
  // KNOWN-BUG: F15-10 DEFAULT NOW() is a syntax error on the embedded engine
  await check("pg: BIGSERIAL/TIMESTAMPTZ DEFAULT NOW()/BOOLEAN DEFAULT TRUE DDL is accepted", () => {
    assert.equal(bigddl.status, "ok", `${bigddl.code}: ${bigddl.message}`);
  }, { knownBug: "F15-10" });

  // Statements a real PostgreSQL executes: here they must at least fail closed (never ok with wrong rows).
  const pgCleanErrorCases = [
    "SELECT NOW()", "SELECT email FROM users WHERE email ILIKE '%ALICE%'", "SELECT id FROM users LIMIT ALL",
    "SELECT * FROM generate_series(1,3)", "SELECT ARRAY[1,2] AS arr", "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'",
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'", "SELECT current_database(), current_user",
    "SELECT EXTRACT(YEAR FROM created_at::timestamptz) AS y FROM users WHERE id = 1", "SELECT * FROM pg_stat_activity",
    "SELECT nextval('t_serial_id_seq')", "SELECT E'a\\nb' AS e",
  ];
  const pgClass = [];
  for (const sql of pgCleanErrorCases) { const r = await pg(sql); pgClass.push(`${sql.split(" ").slice(0, 3).join(" ")}=${r.status === "ok" ? "OK" : r.code}`); }
  info(`pg classification: ${pgClass.join("; ")}`);
  await check("pg: unsupported Postgres-isms fail closed with ADAPTER_ERROR (no fabricated result sets)", async () => {
    for (const sql of pgCleanErrorCases) {
      const r = await pg(sql);
      if (r.status === "ok") {
        // Allowed only if the answer is actually right; NOW() etc. would need a real engine.
        assert.fail(`${sql} returned ok with ${JSON.stringify(r.rows).slice(0, 80)} (unverified fabricated result)`);
      }
      assert.equal(r.code, "ADAPTER_ERROR", `${sql}: ${r.code}`);
    }
  });
  const jsonb = await pg(`SELECT '{"a":1}'::jsonb ->> 'a' AS a`);
  await check("pg: JSONB ->> extraction returns the scalar (SQLite json operator compatibility)", () => {
    assert.equal(jsonb.status, "ok", jsonb.message);
    assert.equal(String(jsonb.rows[0][0]), "1");
  });

  // --- MySQL-isms ---
  const myddl = await my("CREATE TABLE `t_mysql` (`id` INT AUTO_INCREMENT PRIMARY KEY, `name` VARCHAR(50)) ENGINE=InnoDB");
  // KNOWN-BUG: F15-11 AUTO_INCREMENT / ENGINE= table options are not rewritten
  await check("mysql: backticked CREATE TABLE with AUTO_INCREMENT and ENGINE=InnoDB is accepted", () => {
    assert.equal(myddl.status, "ok", `${myddl.code}: ${myddl.message}`);
  }, { knownBug: "F15-11" });
  const plain = await my("CREATE TABLE t2 (id INT PRIMARY KEY, name VARCHAR(50))");
  await check("mysql: DDL on the embedded engine carries the non-transactional DDL warning", () => {
    assert.equal(plain.status, "ok", plain.message);
    assert.ok(plain.warnings.some((w) => /transactional DDL/i.test(w)), JSON.stringify(plain.warnings));
  });
  const lim = await my("SELECT id FROM users LIMIT 1,2");
  const ifn = await my("SELECT IFNULL(NULL,'x') AS v");
  const qp = await my("SELECT id FROM users WHERE id = ?", [1]);
  const bt = await my("SELECT `email` FROM `analytics`.`users` WHERE `id` = 1");
  const cc = await my("SELECT CONCAT('a','b') AS c");
  await check("mysql: LIMIT offset,count / IFNULL / ? params / backtick-qualified names / CONCAT behave like MySQL", () => {
    assert.deepEqual(lim.rows, [[2]], `LIMIT 1,2 -> ${JSON.stringify(lim.rows)}`);
    assert.deepEqual(ifn.rows, [["x"]]);
    assert.deepEqual(qp.rows, [[1]]);
    assert.deepEqual(bt.rows, [["alice@example.com"]]);
    assert.deepEqual(cc.rows, [["ab"]]);
  });
  const ci = await my("SELECT id FROM users WHERE email = 'ALICE@EXAMPLE.COM'");
  // KNOWN-BUG: F15-12 MySQL's default case-insensitive collation is not emulated (silently returns 0 rows)
  await check("mysql: default collation is case-insensitive (email = 'ALICE@EXAMPLE.COM' matches 1 row)", () => {
    assert.equal(ci.status, "ok");
    assert.deepEqual(ci.rows, [[1]], `got ${JSON.stringify(ci.rows)}`);
  }, { knownBug: "F15-12" });
  const mylit = await my("SELECT 'analytics.users' AS s");
  // KNOWN-BUG: F15-06 same literal rewriting defect in rewrite_non_routine_mysql_fragment
  await check("mysql: string literal containing '<default_schema>.' is not rewritten", () => {
    assert.deepEqual(mylit.rows, [["analytics.users"]], `got ${JSON.stringify(mylit.rows)}`);
  }, { knownBug: "F15-06" });
  const myCleanErrorCases = [
    "SHOW TABLES", "DESCRIBE users", "SELECT table_name FROM information_schema.tables WHERE table_schema = 'analytics'",
    "SELECT id FROM users WHERE id = 1 FOR UPDATE", "SELECT NOW() AS n", "SELECT DATE_FORMAT(NOW(), '%Y') AS y",
    "SELECT DATABASE() AS d", "SELECT id DIV 2 AS h FROM users WHERE id = 1", "SELECT id FROM users WHERE email REGEXP 'alice'",
    "SELECT 'x' AS s # comment", "INSERT INTO t2 VALUES (1,'a') ON DUPLICATE KEY UPDATE name='b'", "SELECT 1 FROM DUAL",
    "SELECT VERSION()",
  ];
  const myClass = [];
  for (const sql of myCleanErrorCases) { const r = await my(sql); myClass.push(`${sql.split(" ").slice(0, 2).join(" ")}=${r.status === "ok" ? "OK" : r.code}`); }
  info(`mysql classification: ${myClass.join("; ")}`);
  await check("mysql: unsupported MySQL-isms fail closed with ADAPTER_ERROR (no fabricated result sets)", async () => {
    for (const sql of myCleanErrorCases) {
      const r = await my(sql);
      assert.notEqual(r.status, "ok", `${sql} returned ok with ${JSON.stringify(r.rows || null).slice(0, 80)}`);
      assert.equal(r.code, "ADAPTER_ERROR", `${sql}: ${r.code}`);
    }
  });

  // --- atomicity of a failing multi-row INSERT on both embedded engines ---
  for (const [conn, fn] of [["prod-postgres", pg], ["analytics-mysql", my]]) {
    const ins = await fn("INSERT INTO inventory (sku, available_qty) VALUES ('NEW-1', 1), ('SKU-PRO-1', 2)");
    const cnt = await fn("SELECT COUNT(*) AS n FROM inventory WHERE sku = 'NEW-1'");
    await check(`${conn}: multi-row INSERT failing on the 2nd row leaves no partial write`, () => {
      assert.ok(isDenied(ins), `insert status=${ins.status}`);
      assert.match(ins.message, /UNIQUE constraint/);
      assert.deepEqual(cnt.rows, [[0]]);
    });
  }
  const badPlanPg = await s.call("explain_query", { connection: "prod-postgres", sql: "SELECT * FROM no_such_table WHERE id = 1" });
  const badPlanMy = await s.call("explain_query", { connection: "analytics-mysql", sql: "SELECT * FROM no_such_table WHERE id = 1" });
  // KNOWN-BUG: F15-20 explain fabricates a Seq Scan plan (cost 650, 500 rows) for tables that do not exist
  await check("pg/mysql: explain_query on a non-existent table errors instead of fabricating a plan", () => {
    assert.ok(isDenied(badPlanPg), `pg explain returned ${badPlanPg.status} seq_scans=${JSON.stringify(badPlanPg.data && badPlanPg.data.seq_scans)}`);
    assert.ok(isDenied(badPlanMy), `mysql explain returned ${badPlanMy.status}`);
  }, { knownBug: "F15-20" });
}

async function sectionDelimiterStartup() {
  const cfgD = makeConfig("mysql_delimiter");
  // KNOWN-BUG: F15-13 a MySQL `DELIMITER` block in init_sql aborts server startup with a raw SQLite syntax error
  await check("mysql: init_sql containing a DELIMITER block does not prevent the server from starting", async () => {
    let s;
    try { s = await startServer(cfgD.configPath, 8000); } catch (e) { assert.fail(short(e.message)); }
    const r = await s.call("execute_query", { connection: "analytics-mysql", sql: "SELECT 1" });
    await s.stop();
    assert.equal(r.status, "ok");
  }, { knownBug: "F15-13" });
}

async function sectionSqlite(s, cfgDir) {
  console.log("\n[4] SQLite adapter: real behaviours");
  const q = (sql, extra) => s.call("execute_query", { connection: "local-sqlite", sql, ...(extra || {}) });

  const pk = await s.call("explain_query", { connection: "local-sqlite", sql: "SELECT * FROM users WHERE id = 1", format: "text" });
  const scan = await s.call("explain_query", { connection: "local-sqlite", sql: "SELECT * FROM users WHERE email = 'x'" });
  await check("EXPLAIN QUERY PLAN output is real (SEARCH ... USING INTEGER PRIMARY KEY vs SCAN users + warning)", () => {
    assert.match(pk.data.raw_plan, /SEARCH users USING INTEGER PRIMARY KEY/);
    assert.ok(pk.data.index_scans.length >= 1);
    assert.deepEqual(scan.data.seq_scans, ["users"]);
    assert.ok(scan.data.warnings.some((w) => /Sequential scan/.test(w)));
  });
  const an = await s.call("explain_query", { connection: "local-sqlite", sql: "SELECT * FROM users WHERE id = 1", analyze: true });
  await check("capabilities.supports_analyze_explain=false for SQLite is reflected: analyze=true yields a static-plan warning", () => {
    assert.equal(an.status, "ok", an.message);
    assert.ok(an.data.warnings.some((w) => /static EXPLAIN QUERY PLAN/.test(w)), JSON.stringify(an.data.warnings));
  });

  const t0 = Date.now();
  const to = await q(LONG_SQL(400000000), { timeout_ms: 600 });
  const toMs = Date.now() - t0;
  const t1 = Date.now();
  const alive = await q("SELECT 1 AS alive");
  const aliveMs = Date.now() - t1;
  info(`sqlite timeout: EXECUTION_TIMEOUT after ${toMs} ms, next query answered in ${aliveMs} ms`);
  await check("timeout on a long WITH RECURSIVE interrupts the statement (InterruptHandle) and the connection stays usable", () => {
    assert.equal(to.code, "EXECUTION_TIMEOUT", `${to.status} ${to.code}`);
    assert.ok(toMs < 4000, `timeout took ${toMs} ms`);
    assert.equal(alive.status, "ok");
    assert.ok(aliveMs < 1500, `follow-up query took ${aliveMs} ms (interrupt did not stop the runaway)`);
  });

  // MCP cancellation: notifications/cancelled with the JSON-RPC id of an in-flight request.
  // KNOWN-BUG: F15-14 stdio loop is sequential (main.rs run_stdio_loop) and request_to_execution is keyed by the
  // internal req_ id, so the notification is only read after the request finished and never matches anyway.
  await check("notifications/cancelled {requestId:<jsonrpc id>} interrupts an in-flight long query (< 2500 ms)", async () => {
    const id = 777001;
    const start = Date.now();
    s.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "execute_query", arguments: { connection: "local-sqlite", sql: LONG_SQL(400000000), timeout_ms: 4000 } } }) + "\n");
    await sleep(250);
    s.notify("notifications/cancelled", { requestId: id, reason: "test" });
    let resp;
    while (!resp && Date.now() - start < 9000) { resp = s.notifications.find((m) => m.id === id); if (!resp) await sleep(25); }
    const elapsed = Date.now() - start;
    assert.ok(resp, "no response to the long request within 9 s");
    const sc = resp.result && resp.result.structuredContent;
    info(`cancel: long request answered after ${elapsed} ms with code=${sc && sc.code}`);
    assert.ok(elapsed < 2500, `request ran ${elapsed} ms after cancellation (code=${sc && sc.code})`);
    assert.equal(sc && sc.code, "EXECUTION_CANCELLED");
  }, { knownBug: "F15-14" });

  const fk = await q("INSERT INTO orders (id,user_id,status,total_cents,created_at) VALUES (999, 12345, 'x', 1, 'now')");
  const fkOn = await q("PRAGMA foreign_keys");
  await check("foreign keys are enforced (PRAGMA foreign_keys=1; orphan INSERT rejected)", () => {
    assert.deepEqual(fkOn.rows, [[1]]);
    assert.ok(isDenied(fk));
    assert.match(fk.message, /FOREIGN KEY constraint failed/);
  });
  const dup = await q("INSERT INTO inventory (sku, available_qty) VALUES ('NEW-1', 1), ('SKU-PRO-1', 2)");
  const dupCnt = await q("SELECT COUNT(*) AS n FROM inventory WHERE sku = 'NEW-1'");
  await check("multi-row INSERT with a duplicate key in the 2nd row is atomic (no partial write)", () => {
    assert.ok(isDenied(dup));
    assert.match(dup.message, /UNIQUE constraint failed/);
    assert.deepEqual(dupCnt.rows, [[0]]);
  });
  const jm = await q("PRAGMA journal_mode");
  const ti = await q("PRAGMA table_info(users)");
  const sv = await q("SELECT sqlite_version() AS v");
  await check("read-only PRAGMA queries are allowed and answer truthfully (journal_mode=delete, table_info, sqlite_version)", () => {
    assert.deepEqual(jm.rows, [["delete"]]);
    assert.equal(ti.rows.length, 5);
    assert.match(String(sv.rows[0][0]), /^3\./);
  });
  const att = await q("ATTACH DATABASE ':memory:' AS m2");
  const ext = await q("SELECT load_extension('x')");
  await check("ATTACH and load_extension are blocked by policy", () => {
    assert.equal(att.code, "PRIVILEGED_FUNCTION_FORBIDDEN");
    assert.equal(ext.code, "PRIVILEGED_FUNCTION_FORBIDDEN");
  });

  await q("CREATE TABLE blobs (id INTEGER PRIMARY KEY, b BLOB)");
  const bins = await q("INSERT INTO blobs (id, b) VALUES (1, randomblob(100000)), (2, X'DEADBEEF'), (3, zeroblob(3000000))");
  const b2 = await q("SELECT b FROM blobs WHERE id = 2");
  const b3 = await q("SELECT b FROM blobs WHERE id = 3");
  const b1 = await q("SELECT b FROM blobs WHERE id = 1");
  await check("BLOBs: 4-byte blob is hex-encoded, 100 KB blob returned, 3 MB blob truncated by max_bytes with a warning (no error)", () => {
    assert.equal(bins.status, "ok", bins.message);
    assert.deepEqual(b2.rows, [["0xdeadbeef"]]);
    assert.equal(b1.status, "ok");
    assert.equal(String(b1.rows[0][0]).length, 2 + 200000);
    assert.equal(b3.status, "ok");
    assert.equal(b3.truncated, true);
    assert.ok(b3.warnings.some((w) => /max_bytes/.test(w)), JSON.stringify(b3.warnings));
  });

  const objs = await s.call("search_objects", { connection: "local-sqlite", limit: 200, detail_level: "names" });
  const names = objs.data.objects.map((o) => `${o.object_type}:${o.name}`);
  const hidden = await s.call("describe_object", { connection: "local-sqlite", object_name: "__db_mcp_routines" });
  const proc = await s.call("describe_object", { connection: "local-sqlite", object_name: "checkout_order" });
  await check("init_sql CREATE OR REPLACE PROCEDURE/FUNCTION are stored in a shadow catalog that search_objects hides (__db_mcp_routines)", () => {
    assert.ok(names.includes("procedure:checkout_order") && names.includes("function:calculate_order_discount"), names.join(","));
    assert.ok(!names.some((n) => n.includes("__db_mcp_routines")), "shadow table leaked into search_objects");
    assert.ok(isDenied(hidden));
    assert.match(proc.data.definition, /CREATE OR REPLACE PROCEDURE checkout_order/);
  });
  const shadow = await q("SELECT routine_name FROM __db_mcp_routines");
  // KNOWN-BUG: F15-17 the shadow table is readable through execute_query and sqlite_autoindex_* objects are listed
  await check("internal objects are not user-visible (SELECT FROM __db_mcp_routines refused; no sqlite_autoindex_* in search_objects)", () => {
    assert.ok(isDenied(shadow), `__db_mcp_routines readable: ${JSON.stringify(shadow.rows)}`);
    assert.ok(!names.some((n) => n.includes("sqlite_autoindex")), names.filter((n) => n.includes("sqlite_autoindex")).join(","));
  }, { knownBug: "F15-17" });
  const call = await q("CALL checkout_order(102)");
  await check("CALL procedure on SQLite is a clean ADAPTER_ERROR (procedures are catalog-only; no crash)", () => {
    assert.ok(isDenied(call));
    assert.equal(call.code, "ADAPTER_ERROR");
  });
  assert.ok(fs.existsSync(path.join(cfgDir, "sample.db")), "fixture db missing");
}

async function sectionSqliteReadOnly() {
  const cfg = makeConfig("sqlite_ro");
  const before = fs.existsSync(path.join(cfg.dir, "sample.db"));
  const s = await startServer(cfg.configPath);
  const list = await s.call("list_connections");
  const entry = list.data.find((c) => c.id === "local-sqlite");
  const ins = await s.call("execute_query", { connection: "local-sqlite", sql: "INSERT INTO inventory (sku, available_qty) VALUES ('RO-1', 1)" });
  const cte = await s.call("execute_query", { connection: "local-sqlite", sql: "WITH w AS (SELECT 1) INSERT INTO inventory (sku, available_qty) SELECT 'RO-2', 1 FROM w" });
  const wal = await s.call("execute_query", { connection: "local-sqlite", sql: "PRAGMA journal_mode = WAL" });
  const qo = await s.call("execute_query", { connection: "local-sqlite", sql: "PRAGMA query_only" });
  const sel = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT COUNT(*) FROM users" });
  await check("read_only=true + Development mode: read_only wins (INSERT, CTE-insert and PRAGMA journal_mode=WAL denied; query_only=1; SELECT ok)", () => {
    assert.equal(entry.read_only, true);
    assert.equal(entry.mode, "development");
    assert.equal(ins.code, "READONLY_VIOLATION");
    assert.equal(cte.code, "READONLY_VIOLATION");
    assert.equal(wal.code, "READONLY_VIOLATION");
    assert.deepEqual(qo.rows, [[1]]);
    assert.deepEqual(sel.rows, [[2]]);
  });
  await s.stop();
  // KNOWN-BUG: F15-16 with init_sql set the file is opened READ_WRITE|CREATE and init_sql (DROP/CREATE/INSERT) mutates it
  await check("a read_only SQLite connection never writes the database file (opened with SQLITE_OPEN_READ_ONLY)", () => {
    assert.equal(before, false);
    assert.equal(fs.existsSync(path.join(cfg.dir, "sample.db")), false, "read-only connection created/rewrote sample.db at startup via init_sql");
  }, { knownBug: "F15-16" });
}

async function sectionCapabilitiesAndChanges(s, cfgPath) {
  console.log("\n[5] Capability flags vs behaviour; change application");
  const list = await s.call("list_connections");
  const caps = Object.fromEntries(list.data.map((c) => [c.id, c.capabilities]));
  await check("unavailable_reasons are populated for every false capability that has a reason (sqlite, mysql) and empty for pg with extensions configured", () => {
    assert.ok(caps["local-sqlite"].unavailable_reasons.hypothetical_indexes && caps["local-sqlite"].unavailable_reasons.workload_analysis);
    assert.ok(caps["analytics-mysql"].unavailable_reasons.transactional_ddl && caps["analytics-mysql"].unavailable_reasons.hypothetical_indexes);
    assert.deepEqual(caps["prod-postgres"].unavailable_reasons, {});
    assert.equal(caps["prod-postgres"].supports_workload_analysis, true);
  });
  const wl = await s.call("analyze_workload", { connection: "prod-postgres", top_n: 3 });
  await check("analyze_workload on simulated pg labels its source (recorded_workload_history), not pg_stat_statements", () => {
    assert.equal(wl.status, "ok", wl.message);
    assert.equal(wl.data.source, "recorded_workload_history");
  });
  const ea = await s.call("explain_query", { connection: "prod-postgres", sql: "SELECT * FROM users WHERE id = 1", analyze: true });
  await check("allow_explain_analyze=false on prod-postgres is enforced (ANALYZE_EXPLAIN_FORBIDDEN)", () => {
    assert.equal(ea.code, "ANALYZE_EXPLAIN_FORBIDDEN");
  });
  const cap = await s.call("capture_schema", { connection: "analytics-mysql" });
  const diff = await s.call("diff_schema", { base_connection: "prod-postgres", target_connection: "analytics-mysql" });
  await check("supports_schema_diff: capture_schema and cross-connection diff_schema work", () => {
    assert.equal(cap.status, "ok");
    assert.match(cap.data.schema_version, /^snapshot_/);
    assert.equal(diff.status, "ok");
    assert.ok(Array.isArray(diff.data.items));
  });

  // Transactional DDL via the governed change flow (SQLite supports_transactional_ddl=true).
  const bad = await s.call("propose_change", { connection: "local-sqlite", sql: "CREATE INDEX idx_bad ON orders (no_such_col)" });
  const unapproved = await s.call("apply_change", { change_id: bad.data.change_id });
  const approved = approveViaCli(bad.data.change_id, cfgPath);
  const applied = await s.call("apply_change", { change_id: bad.data.change_id });
  const after = await s.call("get_change", { change_id: bad.data.change_id });
  const idx = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT name FROM sqlite_master WHERE name = 'idx_bad'" });
  await check("apply_change of a failing DDL: approval required, adapter error surfaced, state=failed, nothing created", () => {
    assert.equal(bad.status, "ok", bad.message);
    assert.equal(unapproved.code, "APPROVAL_REQUIRED");
    assert.equal(approved, 0, "CLI approve failed");
    assert.ok(isDenied(applied));
    assert.equal(applied.code, "ADAPTER_ERROR");
    assert.equal(after.data.state, "failed");
    assert.deepEqual(idx.rows, []);
  });
  const multi = await s.call("propose_change", { connection: "local-sqlite", sql: "CREATE TABLE tx_a (id INT); CREATE TABLE tx_a (id INT)" });
  let multiApply = null;
  if (multi.status === "ok") { approveViaCli(multi.data.change_id, cfgPath); multiApply = await s.call("apply_change", { change_id: multi.data.change_id }); }
  const txa = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT COUNT(*) FROM tx_a" });
  // KNOWN-BUG: F15-19 propose_change ignores allow_multi_statement=false; apply_change runs adapter.execute which silently
  // executes only the first statement and reports state=applied (partial, non-atomic change)
  await check("multi-statement DDL change is rejected (allow_multi_statement=false) or applied atomically with its failure reported", () => {
    assert.ok(multi.status !== "ok" || (multiApply && multiApply.status !== "ok"), `propose=${multi.status} apply=${multiApply && multiApply.status} state=${multiApply && multiApply.data && multiApply.data.state} tx_a exists=${txa.status === "ok"}`);
  }, { knownBug: "F15-19" });
}

async function sectionRunawayOnEmbeddedEngines(s) {
  console.log("\n[6] supports_cancellation on the embedded Postgres/MySQL engines");
  const t0 = Date.now();
  const to = await s.call("execute_query", { connection: "prod-postgres", sql: LONG_SQL(25000000), timeout_ms: 300 });
  const toMs = Date.now() - t0;
  const t1 = Date.now();
  const next = await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1 AS q", timeout_ms: 2000 });
  const nextMs = Date.now() - t1;
  info(`pg embedded: timeout returned after ${toMs} ms (code=${to.code}); next SELECT 1 took ${nextMs} ms status=${next.status} code=${next.code || ""}`);
  // KNOWN-BUG: F15-18 no InterruptHandle on the embedded engines: the timed-out statement keeps running under the
  // engine mutex and every later call on the connection blocks/times out; cancel() only logs pg_cancel_backend SQL
  await check("prod-postgres: a timed-out query is actually stopped (capabilities.supports_cancellation=true) so the next call answers quickly", () => {
    assert.equal(to.code, "EXECUTION_TIMEOUT");
    assert.equal(next.status, "ok", `next call ${next.code}`);
    assert.ok(nextMs < 1500, `next call took ${nextMs} ms`);
  }, { knownBug: "F15-18" });
}

async function sectionResourceHygiene(s, cfgDir) {
  console.log("\n[7] Resource hygiene");
  const pid = s.child.pid;
  const warm = async (n) => {
    for (let i = 0; i < n; i++) {
      await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE id = ?", params: [1 + (i % 2)] });
      await s.call("search_objects", { connection: "local-sqlite", limit: 3, detail_level: "names" });
      if (i % 10 === 0) await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1" });
    }
  };
  await warm(10);
  const before = processStats(pid);
  const t0 = Date.now();
  await warm(100);
  const after = processStats(pid);
  info(`200+ calls in ${Date.now() - t0} ms; handles ${before && before.handles} -> ${after && after.handles}; working set ${before && before.workingSet} -> ${after && after.workingSet}`);
  await check("200 sequential calls: handle count stable (delta <= 10) and working set growth < 16 MiB", () => {
    if (!before || !after) { info("process stats unavailable on this platform; skipping numeric assertions"); return; }
    assert.ok(after.handles - before.handles <= 10, `handles grew ${before.handles} -> ${after.handles}`);
    assert.ok(after.workingSet - before.workingSet < 16 * 1024 * 1024, `working set grew ${after.workingSet - before.workingSet} bytes`);
  });
  const tE = Date.now();
  const exit = await s.stop();
  await sleep(200);
  const files = fs.readdirSync(cfgDir).filter((f) => f.startsWith("sample.db"));
  await check("stdin EOF: server exits with code 0 promptly, no -wal/-shm left behind, sample.db not locked", () => {
    assert.deepEqual(exit, { code: 0, sig: null }, `exit=${JSON.stringify(exit)} after ${Date.now() - tE} ms`);
    assert.deepEqual(files, ["sample.db"], `files=${files.join(",")}`);
    const p = path.join(cfgDir, "sample.db");
    fs.renameSync(p, `${p}.moved`);
    fs.renameSync(`${p}.moved`, p);
  });
}

async function sectionConcurrency() {
  console.log("\n[8] Two server processes sharing one SQLite file");
  const cfg = makeConfig("default");
  const A = await startServer(cfg.configPath);
  await A.call("execute_query", { connection: "local-sqlite", sql: "INSERT INTO inventory (sku, available_qty) VALUES ('A-1', 1)" });
  const B = await startServer(cfg.configPath);
  const seen = await A.call("execute_query", { connection: "local-sqlite", sql: "SELECT COUNT(*) FROM inventory WHERE sku = 'A-1'" });
  info(`second server start re-ran init_sql (DROP/CREATE): A's earlier insert visible afterwards = ${JSON.stringify(seen.rows)} (example init_sql is destructive by design)`);
  const q = (c, sql, extra) => c.call("execute_query", { connection: "local-sqlite", sql, ...(extra || {}) });
  const [ra, rb] = await Promise.all([q(A, "SELECT COUNT(*) FROM users"), q(B, "SELECT COUNT(*) FROM users")]);
  const tA = Date.now();
  const pA = q(A, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 8000000) SELECT COUNT(*) FROM c, (SELECT 1 FROM users LIMIT 1)`, { timeout_ms: 20000 });
  await sleep(150);
  const tB = Date.now();
  const w = await q(B, "INSERT INTO inventory (sku, available_qty) VALUES ('B-1', 1)");
  const wMs = Date.now() - tB;
  const a = await pA;
  const aMs = Date.now() - tA;
  const writes = await Promise.all([0, 1, 2, 3].map((i) => q(i % 2 ? A : B, `INSERT INTO inventory (sku, available_qty) VALUES ('W-${i}', 1)`)));
  const cnt = await q(A, "SELECT COUNT(*) FROM inventory WHERE sku LIKE 'W-%'");
  info(`cross-process: write while other process reads took ${wMs} ms (reader ran ${aMs} ms, journal_mode=delete so writers wait for readers via busy_timeout)`);
  await check("concurrent reads/writes from two processes succeed (busy_timeout) with no 'database is locked' errors; all writes visible", () => {
    assert.equal(ra.status, "ok"); assert.equal(rb.status, "ok");
    assert.equal(w.status, "ok", `${w.code}: ${w.message}`);
    assert.equal(a.status, "ok", `${a.code}: ${a.message}`);
    for (const x of writes) assert.equal(x.status, "ok", `${x.code}: ${x.message}`);
    assert.deepEqual(cnt.rows, [[4]]);
  });
  await A.stop();
  await B.stop();
}

// ---------------------------------------------------------------------------------------
async function main() {
  const started = Date.now();
  console.log("F15 adapters / live-vs-simulated fallback verification");

  const def = makeConfig("default");
  const sDef = await startServer(def.configPath);
  await sectionTruthInAdvertising(sDef);
  await sectionLivePath();

  const dev = makeConfig("dev");
  const sDev = await startServer(dev.configPath);
  await sectionDialects(sDev);
  await sectionDelimiterStartup();

  await sectionSqlite(sDef, def.dir);
  await sectionSqliteReadOnly();
  await sectionCapabilitiesAndChanges(sDef, def.configPath);

  await sectionRunawayOnEmbeddedEngines(sDev);
  const devExit = await sDev.stop();
  info(`dev server exit after runaway query: ${JSON.stringify(devExit)}`);

  await sectionResourceHygiene(sDef, def.dir);
  await sectionConcurrency();

  console.log(`\nSUMMARY pass=${tally.pass} fail=${tally.fail} known-bug=${tally.known} fixed=${tally.fixed} runtime=${((Date.now() - started) / 1000).toFixed(1)}s`);
  if (failures.length) { console.log("FAILED: " + failures.join(" | ")); process.exitCode = 1; }
}

main().catch((err) => {
  console.error("FATAL", err);
  process.exitCode = 1;
});
