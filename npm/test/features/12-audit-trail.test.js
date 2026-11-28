#!/usr/bin/env node
"use strict";
/**
 * F12 - Audit trail verification (JSONL + SQLite stores, hash chain, redaction, coverage).
 *
 * Self-contained: spawns the prebuilt db-mcp-server through the npm launcher against private
 * isolated configs (never config/db-mcp.example.toml itself). Uses node:assert only.
 *
 *   node npm/test/features/12-audit-trail.test.js
 *
 * One line per check. Exit 0 only when every check passes. Checks that encode correct behaviour
 * but currently fail are tagged `// KNOWN-BUG: F12-xx` (assertions are NOT weakened).
 *
 * Needs: node >= 18 (fetch), python3 on PATH (reads the SQLite audit store).
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const LAUNCHER = path.join(ROOT, "npm", "bin", "db-mcp.js");
const { makeIsolatedConfig } = require(path.join(ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(ROOT, "scripts", "mcp-call.js"));
const { spawnDbMcpServer } = require(LAUNCHER);

const BASE = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f12-"));
const children = new Set();
const results = [];
const SECRET_PARAM = "SUPER_SECRET_VALUE_123";

// ---------------------------------------------------------------- helpers
function record(name, ok, detail, knownBug) {
  results.push({ name, ok, detail, knownBug });
  const tag = ok ? "PASS" : knownBug ? `FAIL (KNOWN-BUG ${knownBug})` : "FAIL";
  console.log(`${tag.padEnd(26)} ${name}${!ok && detail ? " :: " + detail : ""}`);
}
async function check(name, fn, knownBug) {
  try {
    await fn();
    record(name, true, "", knownBug);
  } catch (err) {
    record(name, false, String(err && err.message ? err.message : err).split("\n")[0].slice(0, 400), knownBug);
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const toPosix = (p) => p.split(path.sep).join("/");
const dropPaths = (t) => t.split(/\r?\n/).filter((l) => !/^(jsonl_path|sqlite_path)\s*=/.test(l)).join("\n");
const noMem = (t) => t.replace(/^in_memory\s*=\s*true/m, "in_memory = false");
const governed = (t) => t.replace(/^default_mode\s*=\s*"[A-Za-z]+"/m, 'default_mode = "GovernedProduction"');
// restrict analytics-mysql to role admin so execute_query by role agent hits UNAUTHORIZED_ROLE
const restrictMysqlRoles = (t) => {
  const i = t.indexOf('id = "analytics-mysql"');
  return t.slice(0, i) + t.slice(i).replace('allowed_roles = ["*"]', 'allowed_roles = ["admin"]');
};

function isoConfig(name, transform) {
  const dir = path.join(BASE, name);
  fs.mkdirSync(dir, { recursive: true });
  const { configPath } = makeIsolatedConfig({ dir, transform });
  return { configPath, dir, jsonl: path.join(dir, "audit.jsonl"), sqlite: path.join(dir, "audit.db") };
}
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}
function countLines(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim()).length : 0;
}
function sqliteRows(dbPath, sql) {
  const py = "import sqlite3,json,sys\ncon=sqlite3.connect(sys.argv[1])\nprint(json.dumps(con.execute(sys.argv[2]).fetchall()))";
  const r = spawnSync("python", ["-I", "-c", py, dbPath, sql], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`python sqlite3 failed: ${r.stderr.slice(0, 200)}`);
  return JSON.parse(r.stdout);
}
async function startStdio(configPath, principal, role) {
  const c = createClient({ config: configPath, principal, role, timeoutMs: 120000 });
  children.add(c.child);
  const exited = new Promise((res) => c.child.on("exit", (code) => res({ exited: code })));
  const init = await Promise.race([
    c.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f12", version: "0" } }),
    exited,
  ]);
  if (init.exited !== undefined) {
    const err = new Error(`server exited code=${init.exited}: ${c.stderr.join("").trim().slice(0, 300)}`);
    err.exitCode = init.exited;
    err.stderr = c.stderr.join("");
    throw err;
  }
  c.notify("notifications/initialized", {});
  const call = async (name, args = {}) => {
    const r = await c.rpc("tools/call", { name, arguments: args });
    if (r.error) return { status: "rpc_error", code: r.error.code, message: r.error.message };
    return r.result.structuredContent;
  };
  return { client: c, call, close: () => c.close() };
}
const freePort = () => new Promise((res, rej) => {
  const s = net.createServer();
  s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close((e) => (e ? rej(e) : res(port))); });
  s.on("error", rej);
});

// Chain hash formula (crates/db-mcp-audit/src/lib.rs compute_event_chain_hash):
// sha256("v1|prev=..|id=..|req=..|ts=<rfc3339 +00:00>|principal=..|role=..|conn=..|mode=..|tool=..|sql_hash=..|sql=..|class=..|decision=<Debug>|denial=..|change=..|rows=..|trunc=..|ms=..|schema=..|err=..")
const DECISION_DEBUG = { allowed: "Allowed", denied: "Denied", requires_approval: "RequiresApproval", approved_execution: "ApprovedExecution", cancelled: "Cancelled", failed: "Failed" };
function chainHash(prev, e) {
  const s = (v) => (v === undefined || v === null ? "" : String(v));
  const ts = e.timestamp.replace(/Z$/, "+00:00");
  const payload = `v1|prev=${prev}|id=${e.event_id}|req=${e.request_id}|ts=${ts}|principal=${e.principal}|role=${e.role}|conn=${e.connection}|mode=${e.operating_mode}|tool=${e.tool_name}|sql_hash=${s(e.sql_hash)}|sql=${s(e.normalized_sql)}|class=${s(e.statement_class)}|decision=${DECISION_DEBUG[e.decision]}|denial=${s(e.denial_code)}|change=${s(e.change_id)}|rows=${s(e.returned_rows)}|trunc=${s(e.truncated)}|ms=${s(e.execution_time_ms)}|schema=${s(e.schema_version)}|err=${s(e.error_message)}`;
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}
function verifyChain(recs) {
  let prev = "GENESIS";
  for (let i = 0; i < recs.length; i++) {
    const r = recs[i];
    if (r.prev_hash !== prev) return { valid: false, at: i, reason: "prev_hash link" };
    if (chainHash(r.prev_hash, r) !== r.chain_hash) return { valid: false, at: i, reason: "chain_hash recompute" };
    prev = r.chain_hash;
  }
  return { valid: true };
}

// ---------------------------------------------------------------- 1 + 2 + 7: coverage, record content, privacy
async function coverageSuite() {
  const cfg = isoConfig("main", restrictMysqlRoles);
  const agent = await startStdio(cfg.configPath, "f12-agent", "agent");
  const guest = await startStdio(cfg.configPath, "f12-guest", "guest");
  const matrix = [];
  // call + measure JSONL delta immediately after the response (also proves synchronous persistence)
  const audited = async (session, name, args) => {
    const before = countLines(cfg.jsonl);
    const resp = await session.call(name, args);
    const after = readJsonl(cfg.jsonl);
    const events = after.slice(before);
    matrix.push({ name, status: resp.status, code: resp.code || "", events: events.length, decision: events.map((e) => `${e.decision}${e.denial_code ? "/" + e.denial_code : ""}`).join(",") });
    return { resp, events };
  };
  const expectOne = (label, out, decision) => {
    assert.equal(out.events.length, 1, `${label}: expected exactly 1 audit event, got ${out.events.length} (response status=${out.resp.status} code=${out.resp.code || ""})`);
    if (decision) assert.equal(out.events[0].decision, decision, `${label}: decision`);
    return out.events[0];
  };
  try {
    // ---- success path for the 16 core tools (ontology tools are covered by 16-ontology.test.js)
    await check("coverage: list_connections emits an audit event", async () => expectOne("list_connections", await audited(agent, "list_connections", {}), "allowed"), "F12-01");
    await check("coverage: search_objects emits an audit event", async () => expectOne("search_objects", await audited(agent, "search_objects", { connection: "local-sqlite", limit: 3 }), "allowed"), "F12-01");
    await check("coverage: describe_object emits an audit event", async () => expectOne("describe_object", await audited(agent, "describe_object", { connection: "local-sqlite", object_name: "orders" }), "allowed"), "F12-01");
    await check("coverage: trace_table_dependencies emits an audit event", async () => expectOne("trace", await audited(agent, "trace_table_dependencies", { connection: "local-sqlite", table_name: "orders" }), "allowed"));
    await check("coverage: get_procedure_call_graph emits an audit event", async () => expectOne("graph", await audited(agent, "get_procedure_call_graph", { connection: "local-sqlite" }), "allowed"));

    const execOut = await audited(agent, "execute_query", {
      connection: "local-sqlite",
      sql: "SELECT id, email FROM users WHERE id = ?1 AND email = 'alice@example.com' -- trailing comment\n",
      params: [SECRET_PARAM],
    });
    await check("coverage: execute_query emits an audit event", async () => expectOne("execute_query", execOut, "allowed"));
    await check("coverage: explain_query emits an audit event", async () => expectOne("explain", await audited(agent, "explain_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE id = 1" }), "allowed"));
    const namedOut = await audited(agent, "run_named_tool", { tool_name: "get_user_by_id", arguments: { user_id: 1 } });
    await check("coverage: run_named_tool emits an audit event (tool_name run_named_tool:<name>)", async () => {
      const e = expectOne("named", namedOut, "allowed");
      assert.equal(e.tool_name, "run_named_tool:get_user_by_id");
    });
    await check("coverage: database_health emits an audit event", async () => expectOne("health", await audited(agent, "database_health", { connection: "local-sqlite" }), "allowed"), "F12-01");
    await check("coverage: analyze_workload emits an audit event", async () => expectOne("workload", await audited(agent, "analyze_workload", { connection: "local-sqlite" }), "allowed"), "F12-01");
    await check("coverage: recommend_indexes emits an audit event", async () => expectOne("recommend", await audited(agent, "recommend_indexes", { connection: "local-sqlite", queries: ["SELECT * FROM orders WHERE user_id = 1"] }), "allowed"), "F12-01");
    await check("coverage: capture_schema emits an audit event", async () => expectOne("capture", await audited(agent, "capture_schema", { connection: "local-sqlite" }), "allowed"), "F12-01");
    await check("coverage: diff_schema emits an audit event", async () => expectOne("diff", await audited(agent, "diff_schema", { base_connection: "local-sqlite", target_connection: "local-sqlite" }), "allowed"), "F12-01");
    const propOut = await audited(agent, "propose_change", { connection: "local-sqlite", sql: "CREATE INDEX idx_f12_audit ON orders (status)" });
    const changeId = propOut.resp.data && propOut.resp.data.change_id;
    await check("coverage: propose_change emits requires_approval event with change_id + sql", async () => {
      const e = expectOne("propose", propOut, "requires_approval");
      assert.equal(e.change_id, changeId);
      assert.match(e.normalized_sql || "", /CREATE INDEX/);
    });
    await check("coverage: get_change emits an audit event", async () => expectOne("get_change", await audited(agent, "get_change", { change_id: changeId }), "allowed"), "F12-01");

    // ---- denial paths
    await check("denial: apply_change before approval (APPROVAL_REQUIRED) is audited", async () => {
      const out = await audited(agent, "apply_change", { change_id: changeId });
      assert.equal(out.resp.code, "APPROVAL_REQUIRED");
      expectOne("apply-unapproved", out, "requires_approval");
    });
    await check("denial: self-approval via CLI (SELF_APPROVAL_FORBIDDEN) is audited", async () => {
      const before = countLines(cfg.jsonl);
      const r = spawnSync(process.execPath, [LAUNCHER, "approve", "--change-id", changeId, "--approver", "f12-agent", "--config", cfg.configPath], { cwd: ROOT, encoding: "utf8" });
      assert.notEqual(r.status, 0, "self-approval must fail");
      assert.match(r.stderr + r.stdout, /Self-approval|SELF_APPROVAL_FORBIDDEN/);
      assert.equal(countLines(cfg.jsonl) - before, 1, "no audit event for the forbidden self-approval");
    }, "F12-03");
    await check("denial: out-of-band admin approval via CLI is audited", async () => {
      const before = countLines(cfg.jsonl);
      const r = spawnSync(process.execPath, [LAUNCHER, "approve", "--change-id", changeId, "--approver", "f12-dba", "--role", "admin", "--config", cfg.configPath], { cwd: ROOT, encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).state, "approved");
      assert.equal(countLines(cfg.jsonl) - before, 1, "no audit event for the approval");
    }, "F12-03");
    const applyOut = await audited(agent, "apply_change", { change_id: changeId });
    await check("coverage: apply_change emits approved_execution event with metrics", async () => {
      const e = expectOne("apply", applyOut, "approved_execution");
      assert.equal(e.change_id, changeId);
      assert.equal(typeof e.returned_rows, "number");
      assert.equal(typeof e.execution_time_ms, "number");
      assert.match(e.schema_version || "", /^snapshot_/);
    });
    await check("denial: replay apply_change (APPROVAL_ALREADY_CONSUMED) is audited", async () => {
      const out = await audited(agent, "apply_change", { change_id: changeId });
      assert.equal(out.resp.code, "APPROVAL_ALREADY_CONSUMED");
      expectOne("replay", out, "denied");
    }, "F12-02");
    await check("denial: unknown connection (CONNECTION_NOT_FOUND) is audited", async () => {
      const out = await audited(agent, "execute_query", { connection: "ghost", sql: "SELECT 1" });
      assert.equal(out.resp.code, "CONNECTION_NOT_FOUND");
      expectOne("ghost", out, "denied");
    }, "F12-02");
    let multiEvent;
    await check("denial: multi-statement (MULTI_STATEMENT_FORBIDDEN) is audited with denial_code", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT 1; DROP TABLE users" });
      assert.equal(out.resp.code, "MULTI_STATEMENT_FORBIDDEN");
      multiEvent = expectOne("multi", out, "denied");
      assert.equal(multiEvent.denial_code, "MULTI_STATEMENT_FORBIDDEN");
      assert.equal(multiEvent.request_id, out.resp.request_id);
    });
    await check("denial: read-only mutation (MUTATION_NOT_ALLOWED_IN_READ_ONLY) is audited", async () => {
      // analytics-mysql (ReadOnly) is role-restricted in this config, so the GovernedProduction
      // connection is used: a direct DELETE is refused before execution either way.
      const out = await audited(agent, "execute_query", { connection: "prod-postgres", sql: "DELETE FROM orders WHERE id = 1" });
      assert.ok(["APPROVAL_REQUIRED", "MUTATION_NOT_ALLOWED_IN_READ_ONLY"].includes(out.resp.code), out.resp.code);
      const e = expectOne("mutation", out);
      assert.ok(["denied", "requires_approval"].includes(e.decision));
      assert.equal(e.denial_code, out.resp.code);
    });
    await check("denial: privileged function (PRIVILEGED_FUNCTION_FORBIDDEN) is audited", async () => {
      const out = await audited(agent, "execute_query", { connection: "prod-postgres", sql: "SELECT pg_read_file('/etc/passwd')" });
      assert.equal(out.resp.code, "PRIVILEGED_FUNCTION_FORBIDDEN");
      expectOne("priv", out, "denied");
    });
    await check("denial: role denial on execute_query (UNAUTHORIZED_ROLE) is audited", async () => {
      const out = await audited(agent, "execute_query", { connection: "analytics-mysql", sql: "SELECT 1" });
      assert.equal(out.resp.code, "UNAUTHORIZED_ROLE");
      const e = expectOne("role", out, "denied");
      assert.equal(e.denial_code, "UNAUTHORIZED_ROLE");
    });
    await check("denial: role denial on run_named_tool (UNAUTHORIZED) is audited", async () => {
      const out = await audited(guest, "run_named_tool", { tool_name: "get_user_by_id", arguments: { user_id: 1 } });
      assert.equal(out.resp.code, "UNAUTHORIZED");
      expectOne("named-role", out, "denied");
    }, "F12-02");
    await check("denial: restricted table via describe_object (RESTRICTED_TABLE) is audited", async () => {
      const out = await audited(agent, "describe_object", { connection: "local-sqlite", object_name: "internal_secrets" });
      assert.equal(out.resp.code, "RESTRICTED_TABLE");
      expectOne("restricted-describe", out, "denied");
    }, "F12-02");
    await check("denial: restricted table via execute_query (RESTRICTED_TABLE_FORBIDDEN) is audited", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT * FROM internal_secrets" });
      assert.equal(out.resp.code, "RESTRICTED_TABLE_FORBIDDEN");
      expectOne("restricted-exec", out, "denied");
    });
    await check("denial: adapter/SQL error is audited as failed with redacted error_message", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELEC nonsense FROM" });
      assert.equal(out.resp.status, "denied");
      const e = expectOne("syntax", out, "failed");
      assert.equal(typeof e.error_message, "string");
      assert.equal(e.denial_code, out.resp.code);
    });
    await check("denial: unknown tool name (TOOL_NOT_ENABLED) is audited and carries a request_id", async () => {
      const out = await audited(agent, "no_such_tool", {});
      assert.equal(out.resp.code, "TOOL_NOT_ENABLED");
      assert.equal(typeof out.resp.request_id, "string", "denied response has no request_id");
      expectOne("unknown-tool", out, "denied");
    }, "F12-02");

    // ---- record content on the execute_query success event
    const ev = execOut.events[0];
    await check("record: required fields present and typed", async () => {
      assert.ok(ev, "no execute_query event");
      assert.match(ev.event_id, /^evt_[0-9a-f]{32}$/);
      assert.match(ev.request_id, /^req_[0-9a-f]{12}$/);
      assert.match(ev.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/, "timestamp not RFC3339 UTC");
      assert.equal(ev.principal, "f12-agent");
      assert.equal(ev.role, "agent");
      assert.equal(ev.transport, "stdio");
      assert.equal(ev.connection, "local-sqlite");
      assert.equal(ev.operating_mode, "development");
      assert.equal(ev.tool_name, "execute_query");
      assert.equal(ev.statement_class, "read");
      assert.equal(ev.decision, "allowed");
      assert.equal(typeof ev.returned_rows, "number");
      assert.equal(typeof ev.truncated, "boolean");
      assert.equal(typeof ev.execution_time_ms, "number");
      assert.match(ev.schema_version || "", /^snapshot_/);
      assert.equal(ev.denial_code, undefined);
      assert.equal(ev.error_message, undefined);
    });
    await check("record: request_id in event matches request_id in the tool response", async () => {
      assert.equal(ev.request_id, execOut.resp.request_id);
    });
    await check("record: sql_hash is sha256 hex of normalized_sql", async () => {
      assert.match(ev.sql_hash, /^[0-9a-f]{64}$/);
      assert.equal(ev.sql_hash, crypto.createHash("sha256").update(ev.normalized_sql).digest("hex"));
    });
    await check("record: normalized_sql strips comments and collapses whitespace", async () => {
      assert.ok(!/--|trailing comment/.test(ev.normalized_sql), ev.normalized_sql);
      assert.ok(!/\n|\s{2,}/.test(ev.normalized_sql), ev.normalized_sql);
    });
    await check("record: truncated=true recorded when max_rows cuts the result", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT id FROM users", max_rows: 1 });
      const e = expectOne("trunc", out, "allowed");
      assert.equal(e.truncated, true);
      assert.equal(e.returned_rows, 1);
    });
    await check("privacy: string literal PII (email) is not persisted in normalized_sql", async () => {
      assert.ok(!ev.normalized_sql.includes("alice@example.com"), ev.normalized_sql);
    }, "F12-04");
    await check("privacy: numeric literals are normalized to placeholders", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE id = 1" });
      const e = expectOne("num", out, "allowed");
      assert.ok(!/=\s*1\b/.test(e.normalized_sql), e.normalized_sql);
    }, "F12-04");
    await check("privacy: sensitive column VALUE in a literal is not persisted", async () => {
      await audited(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT id FROM users WHERE password_hash = 'hash_alice_secret'" });
      const text = fs.readFileSync(cfg.jsonl, "utf8");
      assert.ok(!text.includes("hash_alice_secret"), "hash_alice_secret found in audit.jsonl");
      const rows = sqliteRows(cfg.sqlite, "SELECT count(*) FROM audit_events WHERE payload_json LIKE '%hash_alice_secret%' OR normalized_sql LIKE '%hash_alice_secret%'");
      assert.equal(rows[0][0], 0, "hash_alice_secret found in audit.db");
    }, "F12-04");
    await check("privacy: bound parameter values never reach JSONL or SQLite", async () => {
      assert.ok(!fs.readFileSync(cfg.jsonl, "utf8").includes(SECRET_PARAM));
      const rows = sqliteRows(cfg.sqlite, `SELECT count(*) FROM audit_events WHERE payload_json LIKE '%${SECRET_PARAM}%'`);
      assert.equal(rows[0][0], 0);
    });
    await check("privacy: key=value credential patterns inside SQL literals are redacted", async () => {
      const out = await audited(agent, "execute_query", { connection: "local-sqlite", sql: "INSERT INTO users (id,email,role,password_hash,created_at) VALUES (9,'x@y.z','customer','password=hunter2','2025')" });
      const e = expectOne("insert", out, "allowed");
      assert.ok(!e.normalized_sql.includes("hunter2"), e.normalized_sql);
      // Literals are masked entirely (stronger than key=value redaction).
      assert.ok(e.normalized_sql.includes("[REDACTED]") || /\?/.test(e.normalized_sql), e.normalized_sql);
    });
    await check("privacy: no DSN passwords in audit files", async () => {
      const text = fs.readFileSync(cfg.jsonl, "utf8");
      assert.ok(!/[a-z]+:\/\/[^@\s"]*:[^@\s"]+@/i.test(text), "dsn credential pattern found");
    });

    // ---- hash chain (JSONL) + store equivalence
    const recs = readJsonl(cfg.jsonl);
    await check("chain: first record prev_hash == GENESIS", async () => assert.equal(recs[0].prev_hash, "GENESIS"));
    await check("chain: every prev_hash equals previous chain_hash", async () => {
      for (let i = 1; i < recs.length; i++) assert.equal(recs[i].prev_hash, recs[i - 1].chain_hash, `break at ${i}`);
    });
    await check("chain: chain_hash recomputable from record fields (documented formula)", async () => {
      const v = verifyChain(recs);
      assert.ok(v.valid, `chain invalid at ${v.at}: ${v.reason}`);
    });
    await check("stores: SQLite and JSONL hold identical events (count, event_id, request_id, chain_hash)", async () => {
      const rows = sqliteRows(cfg.sqlite, "SELECT event_id, request_id, chain_hash, prev_hash FROM audit_events ORDER BY seq");
      assert.equal(rows.length, recs.length, `sqlite ${rows.length} vs jsonl ${recs.length}`);
      rows.forEach((r, i) => {
        assert.equal(r[0], recs[i].event_id, `event_id ${i}`);
        assert.equal(r[1], recs[i].request_id, `request_id ${i}`);
        assert.equal(r[2], recs[i].chain_hash, `chain_hash ${i}`);
      });
    });
    await check("stores: SQLite schema has audit_events table with hash columns and 4 lookup indexes", async () => {
      const cols = sqliteRows(cfg.sqlite, "SELECT name FROM pragma_table_info('audit_events')").map((r) => r[0]);
      for (const c of ["seq", "event_id", "request_id", "timestamp", "principal", "role", "transport", "connection", "operating_mode", "tool_name", "sql_hash", "normalized_sql", "statement_class", "decision", "denial_code", "change_id", "returned_rows", "truncated", "execution_time_ms", "schema_version", "error_message", "prev_hash", "chain_hash", "payload_json"]) assert.ok(cols.includes(c), `missing column ${c}`);
      const idx = sqliteRows(cfg.sqlite, "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_events'").map((r) => r[0]);
      for (const i of ["idx_audit_events_request_id", "idx_audit_events_connection", "idx_audit_events_timestamp", "idx_audit_events_principal"]) assert.ok(idx.includes(i), `missing index ${i}`);
    });
    await check("stores: in_memory=true + file paths -> memory + JSONL + SQLite all populated", async () => {
      assert.ok(recs.length > 0 && fs.statSync(cfg.sqlite).size > 0);
    });
  } finally {
    agent.close();
    guest.close();
  }
  console.log("  tool/path -> audit events matrix:");
  for (const m of matrix) console.log(`    ${m.name.padEnd(26)} ${m.status.padEnd(7)} ${m.code.padEnd(34)} events=${m.events} ${m.decision}`);
  return cfg;
}

// ---------------------------------------------------------------- 3: restart continuity, tamper, malformed line
async function chainSuite(cfg) {
  const before = readJsonl(cfg.jsonl);
  await check("chain: new process continues from last persisted chain_hash (no GENESIS restart)", async () => {
    const s = await startStdio(cfg.configPath, "f12-restart", "agent");
    try { await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 2" }); } finally { s.close(); }
    const after = readJsonl(cfg.jsonl);
    assert.equal(after.length, before.length + 1);
    assert.equal(after[before.length].prev_hash, before[before.length - 1].chain_hash);
    const rows = sqliteRows(cfg.sqlite, "SELECT prev_hash, chain_hash FROM audit_events ORDER BY seq DESC LIMIT 2");
    assert.equal(rows[0][0], rows[1][1], "sqlite chain did not continue");
  });
  await check("chain: offline recomputation detects a tampered middle record", async () => {
    const lines = fs.readFileSync(cfg.jsonl, "utf8").split("\n").filter((l) => l.trim());
    const mid = JSON.parse(lines[Math.floor(lines.length / 2)]);
    mid.decision = mid.decision === "allowed" ? "denied" : "allowed";
    const tampered = lines.map((l, i) => (i === Math.floor(lines.length / 2) ? JSON.stringify(mid) : l)).map((l) => JSON.parse(l));
    const v = verifyChain(tampered);
    assert.equal(v.valid, false);
    assert.equal(v.at, Math.floor(lines.length / 2));
  });
  await check("chain: server refuses or flags a tampered JSONL chain on startup/append (verification exposed)", async () => {
    const lines = fs.readFileSync(cfg.jsonl, "utf8").split("\n").filter((l) => l.trim());
    const i = Math.floor(lines.length / 2);
    const mid = JSON.parse(lines[i]);
    mid.principal = "mallory";
    lines[i] = JSON.stringify(mid);
    fs.writeFileSync(cfg.jsonl, lines.join("\n") + "\n");
    const s = await startStdio(cfg.configPath, "f12-tamper", "agent");
    let resp;
    try { resp = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 3" }); } finally { s.close(); }
    const stderr = s.client.stderr.join("");
    assert.ok(resp.status !== "ok" || /chain|tamper|integrity/i.test(stderr), "tampered chain accepted silently; no verify_chain exposure (CLI/tool/startup)");
  });
  await check("chain: a malformed JSONL line must not turn an already-executed write into a STORAGE_ERROR denial", async () => {
    const lines = fs.readFileSync(cfg.jsonl, "utf8").split("\n").filter((l) => l.trim());
    lines[1] = lines[1].slice(0, 40);
    fs.writeFileSync(cfg.jsonl, lines.join("\n") + "\n");
    const s = await startStdio(cfg.configPath, "f12-malformed", "agent");
    let ins, sel;
    try {
      ins = await s.call("execute_query", { connection: "local-sqlite", sql: "INSERT INTO inventory (sku, available_qty) VALUES ('SKU-F12-MALFORMED', 1)" });
      sel = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) FROM inventory WHERE sku = 'SKU-F12-MALFORMED'" });
    } finally { s.close(); }
    // when the follow-up SELECT is itself reported as STORAGE_ERROR, read the fixture DB directly
    const inserted = sel.rows
      ? Number(sel.rows[0][0])
      : sqliteRows(path.join(cfg.dir, "sample.db"), "SELECT count(*) FROM inventory WHERE sku = 'SKU-F12-MALFORMED'")[0][0];
    // correct: either the write is audited and acknowledged, or it is refused BEFORE execution (fail-closed)
    const consistent = (ins.status === "ok") || (ins.status === "denied" && inserted === 0);
    assert.ok(consistent, `response=${ins.status}/${ins.code} but row inserted=${inserted} (executed then reported as ${ins.code})`);
  }, "F12-06");
}

// ---------------------------------------------------------------- 4: store configuration edge cases
async function storesSuite() {
  await check("stores: in_memory=false with no paths in GovernedProduction refuses to start (no persistent audit sink)", async () => {
    const c = isoConfig("nomem_gov", (t) => governed(noMem(dropPaths(t))));
    let s;
    try { s = await startStdio(c.configPath, "p", "agent"); } catch (e) { return; }
    try {
      const r = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" });
      assert.fail(`server started and served (${r.status}); files=${fs.readdirSync(c.dir).join(",")}`);
    } finally { s.close(); }
  });
  await check("stores: in_memory=false with no paths (Development) falls back to in-memory and still serves", async () => {
    const c = isoConfig("nomem_dev", (t) => noMem(dropPaths(t)));
    const s = await startStdio(c.configPath, "p", "agent");
    try {
      const r = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" });
      assert.equal(r.status, "ok");
      assert.ok(!fs.existsSync(c.jsonl) && !fs.existsSync(c.sqlite));
    } finally { s.close(); }
  });
  await check("stores: in_memory=false + file paths -> JSONL and SQLite written, /metrics source is JSONL", async () => {
    const c = isoConfig("nomem_files", noMem);
    const s = await startStdio(c.configPath, "p", "agent");
    try {
      await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" });
      assert.equal(countLines(c.jsonl), 1);
      assert.equal(sqliteRows(c.sqlite, "SELECT count(*) FROM audit_events")[0][0], 1);
    } finally { s.close(); }
  });
  const fileParent = path.join(BASE, "audit-parent-is-file");
  fs.writeFileSync(fileParent, "");
  await check("stores: jsonl_path under a regular file fails at startup with a clear error", async () => {
    const target = JSON.stringify(toPosix(path.join(fileParent, "audit.jsonl")));
    const c = isoConfig("invalid-jsonl-parent", (t) => t.replace(/^jsonl_path = "[^"]+"/m, `jsonl_path = ${target}`));
    await assert.rejects(startStdio(c.configPath, "p", "agent"), (e) => { assert.equal(e.exitCode, 1); assert.match(e.stderr, /audit log directory|Storage error/); return true; });
  });
  await check("stores: sqlite_path under a regular file fails at startup with a clear error", async () => {
    const target = JSON.stringify(toPosix(path.join(fileParent, "audit.db")));
    const c = isoConfig("invalid-sqlite-parent", (t) => t.replace(/^sqlite_path = "[^"]+"/m, `sqlite_path = ${target}`));
    await assert.rejects(startStdio(c.configPath, "p", "agent"), (e) => { assert.equal(e.exitCode, 1); assert.match(e.stderr, /SQLite audit|Storage error/); return true; });
  });
  await check("stores: jsonl_path pointing at an existing DIRECTORY is rejected at startup (not at first write)", async () => {
    const dirTarget = path.join(BASE, "dir_as_jsonl_target");
    fs.mkdirSync(dirTarget, { recursive: true });
    const c = isoConfig("dirpath", (t) => t.replace(/^jsonl_path = "[^"]+"/m, `jsonl_path = "${toPosix(dirTarget)}"`));
    let s;
    try { s = await startStdio(c.configPath, "p", "agent"); } catch (e) { return; }
    try {
      const r = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" });
      assert.fail(`server started; first execute_query -> ${r.status}/${r.code}`);
    } finally { s.close(); }
  }, "F12-08");
  await check("stores: two servers appending to the same audit files keep BOTH chains intact", async () => {
    const c = isoConfig("concurrent");
    const a = await startStdio(c.configPath, "A", "agent");
    const b = await startStdio(c.configPath, "B", "agent");
    const N = 40; // race-dependent: 3 SQLite prev_hash breaks were observed at 40+40 interleaved calls
    try {
      const run = async (s, tag) => { for (let i = 0; i < N; i++) { const r = await s.call("execute_query", { connection: "local-sqlite", sql: `SELECT ${i} AS ${tag}` }); assert.equal(r.status, "ok", `${tag}#${i}: ${r.code} ${r.message || ""}`); } };
      await Promise.all([run(a, "a"), run(b, "b")]);
    } finally { a.close(); b.close(); }
    const recs = readJsonl(c.jsonl);
    assert.equal(recs.length, 2 * N, "jsonl line count");
    const vj = verifyChain(recs);
    const rows = sqliteRows(c.sqlite, "SELECT prev_hash, chain_hash FROM audit_events ORDER BY seq");
    assert.equal(rows.length, 2 * N, "sqlite row count");
    let sqliteBreaks = 0;
    for (let i = 1; i < rows.length; i++) if (rows[i][0] !== rows[i - 1][1]) sqliteBreaks++;
    assert.ok(vj.valid, `JSONL chain broken at ${vj.at}`);
    assert.equal(sqliteBreaks, 0, `SQLite chain has ${sqliteBreaks} prev_hash breaks (no cross-process lock around read-last/insert)`);
  });
  await check("stores: a 1 MB SQL literal is bounded/truncated in the persisted event", async () => {
    const c = isoConfig("bigsql");
    const s = await startStdio(c.configPath, "p", "agent");
    try {
      const r = await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT '" + "b".repeat(1024 * 1024) + "' AS x" });
      assert.equal(r.status, "ok");
    } finally { s.close(); }
    const line = fs.readFileSync(c.jsonl, "utf8").split("\n").filter((l) => l.trim()).pop();
    assert.ok(line.length < 64 * 1024, `persisted audit line is ${line.length} bytes`);
  }, "F12-10");
}

// ---------------------------------------------------------------- 5: HTTP transport + /metrics
async function httpSuite() {
  const c = isoConfig("http");
  const port = await freePort();
  const env = { DB_MCP_AUTH_TOKEN: "f12-token", DB_MCP_ADMIN_TOKEN: "f12-admin" };
  const child = spawnDbMcpServer(["serve", "--transport", "http", "--bind", `127.0.0.1:${port}`, "--config", c.configPath], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  children.add(child);
  const base = `http://127.0.0.1:${port}`;
  const errs = [];
  child.stderr.on("data", (d) => errs.push(String(d)));
  const metrics = async () => (await (await fetch(`${base}/metrics`)).json()).audit_events_total;
  const call = async (name, args, headers = {}) => {
    const r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${env.DB_MCP_AUTH_TOKEN}`, ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
    return (await r.json()).result.structuredContent;
  };
  try {
    let ready = false;
    for (let i = 0; i < 80 && !ready; i++) { try { ready = (await fetch(`${base}/health`)).ok; } catch { await sleep(200); } }
    assert.ok(ready, `http server not ready: ${errs.join("")}`);
    await check("http: event carries transport=http and principal/role from x-mcp-* headers", async () => {
      const r = await call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" }, { "x-mcp-principal": "http-alice", "x-mcp-role": "developer" });
      assert.equal(r.status, "ok");
      const e = readJsonl(c.jsonl).pop();
      assert.equal(e.transport, "http");
      assert.equal(e.principal, "http-alice");
      assert.equal(e.role, "developer");
      assert.equal(e.request_id, r.request_id);
    });
    await check("http: /metrics audit_events_total increments for an allowed call", async () => {
      const m0 = await metrics();
      await call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" });
      assert.equal(await metrics(), m0 + 1);
    });
    await check("http: /metrics audit_events_total increments for a policy denial", async () => {
      const m0 = await metrics();
      const r = await call("execute_query", { connection: "local-sqlite", sql: "SELECT 1; SELECT 2" });
      assert.equal(r.code, "MULTI_STATEMENT_FORBIDDEN");
      assert.equal(await metrics(), m0 + 1);
    });
    await check("http: /metrics audit_events_total increments for metadata tools (list_connections)", async () => {
      const m0 = await metrics();
      await call("list_connections", {});
      assert.equal(await metrics(), m0 + 1);
    }, "F12-01");
    await check("http: /metrics audit_events_total increments for CONNECTION_NOT_FOUND denial", async () => {
      const m0 = await metrics();
      const r = await call("execute_query", { connection: "ghost", sql: "SELECT 1" });
      assert.equal(r.code, "CONNECTION_NOT_FOUND");
      assert.equal(await metrics(), m0 + 1);
    }, "F12-02");
    await check("http: /metrics total equals JSONL line count (same event source)", async () => {
      assert.equal(await metrics(), countLines(c.jsonl));
    });
  } finally {
    child.kill();
  }
}

// ---------------------------------------------------------------- 6: ordering / latency
async function latencySuite() {
  const full = isoConfig("perf_full");
  const mem = isoConfig("perf_mem", dropPaths);
  const sf = await startStdio(full.configPath, "p", "agent");
  const sm = await startStdio(mem.configPath, "p", "agent");
  const bench = async (s, n) => { const t = process.hrtime.bigint(); for (let i = 0; i < n; i++) await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" }); return Number(process.hrtime.bigint() - t) / 1e6 / n; };
  try {
    await check("latency: audit write is synchronous (event on disk before the response is returned)", async () => {
      for (let i = 0; i < 5; i++) {
        const before = countLines(full.jsonl);
        const r = await sf.call("execute_query", { connection: "local-sqlite", sql: `SELECT ${i}` });
        assert.equal(r.status, "ok");
        assert.equal(countLines(full.jsonl), before + 1, `event ${i} not on disk immediately after response`);
      }
    });
    await check("latency: JSONL+SQLite overhead per call stays under 100 ms (reported)", async () => {
      await bench(sm, 10); await bench(sf, 10);
      const m = await bench(sm, 60);
      const f = await bench(sf, 60);
      console.log(`  per-call: memory-only ${m.toFixed(1)} ms, memory+JSONL+SQLite ${f.toFixed(1)} ms, overhead ${(f - m).toFixed(1)} ms`);
      assert.ok(f - m < 100, `overhead ${(f - m).toFixed(1)} ms`);
    });
  } finally { sf.close(); sm.close(); }
}

// ---------------------------------------------------------------- main
(async () => {
  let failed = false;
  try {
    const cfg = await coverageSuite();
    await chainSuite(cfg);
    await storesSuite();
    await httpSuite();
    await latencySuite();
  } catch (err) {
    failed = true;
    console.error("FATAL", err);
  } finally {
    for (const ch of children) { try { ch.kill(); } catch { /* already gone */ } }
    await sleep(400);
    try { fs.rmSync(BASE, { recursive: true, force: true }); } catch { /* files may still be held briefly on Windows */ }
  }
  const pass = results.filter((r) => r.ok).length;
  const fail = results.filter((r) => !r.ok);
  const known = fail.filter((r) => r.knownBug).length;
  console.log(`\nF12 audit trail: ${pass} passed, ${fail.length} failed (${known} known bugs, ${fail.length - known} unexpected) of ${results.length} checks`);
  process.exit(failed || fail.length > 0 ? 1 : 0);
})();
