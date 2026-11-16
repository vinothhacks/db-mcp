#!/usr/bin/env node
"use strict";
/**
 * F10 - Governed change workflow verification
 *   propose_change / get_change / apply_change, out-of-band approval via CLI (`db-mcp approve`)
 *   and HTTP (`POST /admin/approve`), approval-hash binding, separation of duties, replay
 *   prevention, TTL expiry, schema-drift and tamper detection, persistence, audit, envelopes.
 *
 * Run from the repo root:   node npm/test/features/10-change-governance.test.js
 *
 * Every check encodes the CORRECT behaviour. Checks that currently fail because of a known
 * defect are tagged `// KNOWN-BUG: F10-xx` (and printed as such) but are NOT weakened.
 * Exit code: 0 when every check passes; 1 otherwise. Set F10_ALLOW_KNOWN_BUGS=1 to exit 0 when
 * the only failures are tagged known bugs (useful as a regression gate until they are fixed).
 *
 * Uses only node:assert. Creates its own isolated config/changes.db/audit under a private temp
 * directory and cleans up all child processes.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const WRAPPER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));
const { spawnDbMcpServer } = require(WRAPPER);

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------
const results = [];
let currentSection = "";
function section(name) {
  currentSection = name;
  console.log(`\n== ${name}`);
}
async function check(name, fn, opts = {}) {
  const label = `${currentSection} :: ${name}`;
  try {
    await fn();
    results.push({ label, ok: true, known: opts.known });
    console.log(`  PASS  ${name}${opts.known ? `  (previously KNOWN-BUG ${opts.known} - now fixed)` : ""}`);
  } catch (err) {
    results.push({ label, ok: false, known: opts.known, err });
    const tag = opts.known ? `  [KNOWN-BUG ${opts.known}]` : "";
    console.log(`  FAIL  ${name}${tag}\n        ${String(err.message || err).split("\n")[0].slice(0, 300)}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const children = new Set();

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
    srv.on("error", reject);
  });
}

// Private temp dir (NOT a shared scratchpad) so parallel test runs never share a change store.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f10-"));
const { configPath: CFG, dir: ISO } = makeIsolatedConfig({ dir: TMP });
const CHANGES_DB = path.join(ISO, "changes.db");
const AUDIT_JSONL = path.join(ISO, "audit.jsonl");

function stdioClient(principal, role, config = CFG, timeoutMs = 30000) {
  const c = createClient({ config, principal, role, timeoutMs });
  children.add(c.child);
  c.child.on("exit", () => children.delete(c.child));
  return c;
}
async function initClient(c) {
  const r = await c.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f10-test", version: "0" } });
  assert.ok(r.result, `initialize failed: ${JSON.stringify(r)}`);
  c.notify("notifications/initialized", {});
  return c;
}
async function callTool(c, name, args) {
  const r = await c.rpc("tools/call", { name, arguments: args });
  assert.ok(r.result, `tools/call ${name} returned JSON-RPC error: ${JSON.stringify(r.error)}`);
  return r.result.structuredContent;
}
function cliApprove(changeId, approver, role, extra = [], config = CFG) {
  const args = [WRAPPER, "approve", "--change-id", changeId, "--approver", approver, "--role", role, ...extra];
  if (config) args.push("--config", config);
  const r = spawnSync(process.execPath, args, { cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, DB_MCP_QUIET: "1" }, timeout: 60000 });
  return { status: r.status, stdout: (r.stdout || "").trim(), stderr: (r.stderr || "").trim() };
}
function pyTamper(changeId, pythonMutation) {
  const script = [
    "import sqlite3, json, sys",
    "db, cid = sys.argv[1], sys.argv[2]",
    "con = sqlite3.connect(db)",
    "row = con.execute('SELECT proposal_json, state FROM change_proposals WHERE change_id=?', (cid,)).fetchone()",
    "p = json.loads(row[0])",
    pythonMutation,
    "con.execute('UPDATE change_proposals SET proposal_json=?, state=? WHERE change_id=?', (json.dumps(p), p['state'], cid))",
    "con.commit()",
    "print('ok')",
  ].join("\n");
  const r = spawnSync("python", ["-I", "-c", script, CHANGES_DB, changeId], { encoding: "utf8", timeout: 30000 });
  assert.equal(r.status, 0, `python tamper failed: ${r.stderr}`);
}
function assertSuccessEnvelope(p, label) {
  assert.equal(p.status, "ok", `${label}: expected status ok, got ${JSON.stringify(p).slice(0, 400)}`);
  assert.equal(typeof p.request_id, "string", `${label}: request_id`);
  assert.equal(typeof p.connection, "string", `${label}: connection`);
  assert.ok(Array.isArray(p.columns), `${label}: columns`);
  assert.ok(Array.isArray(p.rows), `${label}: rows`);
  assert.equal(typeof p.returned_rows, "number", `${label}: returned_rows`);
  assert.equal(typeof p.truncated, "boolean", `${label}: truncated`);
  assert.ok(Array.isArray(p.warnings), `${label}: warnings`);
  assert.equal(typeof p.schema_version, "string", `${label}: schema_version`);
  assert.equal(p._meta?.provenance?.untrusted_content, true, `${label}: _meta.provenance.untrusted_content`);
}
function assertDenied(p, code, label) {
  assert.equal(p.status, "denied", `${label}: expected denied, got ${JSON.stringify(p).slice(0, 400)}`);
  if (code) assert.equal(p.code, code, `${label}: expected code ${code}, got ${p.code} (${p.message})`);
  assert.equal(typeof p.message, "string", `${label}: message`);
  assert.equal(typeof p.retryable, "boolean", `${label}: retryable`);
  assert.equal(typeof p.request_id, "string", `${label}: request_id`);
}
/** Recompute the documented binding: SHA-256("v1|sql=..|params=..|conn=..|principal=..|policy=..|schema=..|exp=<rfc3339>|constraints=..") */
function expectedApprovalHash(d) {
  const exp = d.expires_at.replace(/Z$/, "+00:00");
  const payload = `v1|sql=${d.normalized_sql}|params=${JSON.stringify(d.params)}|conn=${d.connection}|principal=${d.proposing_principal}|policy=${d.policy_revision}|schema=${d.schema_fingerprint}|exp=${exp}|constraints=${JSON.stringify(d.constraints)}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}
function readAudit() {
  if (!fs.existsSync(AUDIT_JSONL)) return [];
  return fs.readFileSync(AUDIT_JSONL, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

// ---------------------------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------------------------
async function sectionToolSurface(agent) {
  section("1 tool surface");
  const tl = await agent.rpc("tools/list", {});
  const names = tl.result.tools.map((t) => t.name);
  await check("propose_change/get_change/apply_change are listed", () => {
    for (const n of ["propose_change", "get_change", "apply_change"]) assert.ok(names.includes(n), n);
  });
  await check("no in-band approve/reject tool exists in tools/list", () => {
    assert.deepEqual(names.filter((n) => /approv|reject/i.test(n)), []);
  });
  const inBand = await callTool(agent, "approve_change", { change_id: "chg_x", approver: "x" });
  await check("calling approve_change as a tool is refused (TOOL_NOT_ENABLED)", () => {
    assert.equal(inBand.status, "denied");
    assert.equal(inBand.code, "TOOL_NOT_ENABLED");
  });
  await check("TOOL_NOT_ENABLED denial carries the standard envelope (request_id)", () => {
    // KNOWN-BUG: F10-10 built via McpDeniedResponse::new -> no request_id, unlike every other denial.
    assertDenied(inBand, "TOOL_NOT_ENABLED", "approve_change");
  }, { known: "F10-10" });
  await check("propose_change schema exposes params/constraints/ttl_seconds", () => {
    const s = tl.result.tools.find((t) => t.name === "propose_change").inputSchema;
    assert.deepEqual(s.required, ["connection", "sql"]);
    for (const k of ["params", "constraints", "ttl_seconds"]) assert.ok(s.properties[k], k);
  });
}

async function sectionLifecycleProd(agent) {
  section("2 lifecycle on prod-postgres (GovernedProduction)");
  const sql = "UPDATE orders SET status = $1 WHERE id = $2";
  const prop = await callTool(agent, "propose_change", { connection: "prod-postgres", sql, params: ["shipped", 102], constraints: { max_rows_affected: 1 } });
  const d = prop.data || {};
  const id = d.change_id;
  await check("propose_change returns ok envelope", () => assertSuccessEnvelope(prop, "propose"));
  await check("proposal fields (state/sql/params/class/reversibility/principal/policy/fingerprint/expiry)", () => {
    assert.match(id, /^chg_[0-9a-f]{32}$/);
    assert.equal(d.state, "proposed");
    assert.equal(d.connection, "prod-postgres");
    assert.equal(d.sql, sql);
    assert.equal(d.normalized_sql, sql);
    assert.deepEqual(d.params, ["shipped", 102]);
    assert.equal(d.statement_class, "write");
    assert.equal(d.reversal_safety, "compensating_migration_required");
    assert.equal(typeof d.transactional, "boolean");
    assert.equal(d.proposing_principal, "agent-alice");
    assert.equal(d.policy_revision, "policy_v1");
    assert.match(d.schema_fingerprint, /^snapshot_[0-9a-f]{12}$/);
    assert.deepEqual(d.constraints, { max_rows_affected: 1 });
    assert.match(d.created_at, ISO_RE);
    assert.match(d.expires_at, ISO_RE);
    assert.equal(prop.schema_version, d.schema_fingerprint);
    assert.equal(prop.columns.length, 7);
    assert.equal(prop.returned_rows, 1);
    assert.equal(prop.rows[0][0], id);
  });
  await check("approval_hash is the documented SHA-256 binding", () => {
    assert.match(d.approval_hash, /^[0-9a-f]{64}$/);
    assert.equal(d.approval_hash, expectedApprovalHash(d));
  });
  await check("get_change mirrors the proposal", async () => {
    const g = await callTool(agent, "get_change", { change_id: id });
    assertSuccessEnvelope(g, "get_change");
    assert.equal(g.data.state, "proposed");
    assert.equal(g.data.approval_hash, d.approval_hash);
    assert.equal(g.data.approval, undefined);
  });
  await check("apply before approval -> APPROVAL_REQUIRED", async () => {
    assertDenied(await callTool(agent, "apply_change", { change_id: id }), "APPROVAL_REQUIRED", "apply");
  });
  await check("apply-before-approval next_action explains out-of-band approval (not 'propose_change')", async () => {
    // KNOWN-BUG: F10-09 next_action is "propose_change" although the change is already proposed.
    const r = await callTool(agent, "apply_change", { change_id: id });
    assert.match(String(r.next_action), /approve/i, `next_action=${r.next_action}`);
  }, { known: "F10-09" });
  await check("CLI self-approval by proposer -> non-zero exit, SELF_APPROVAL_FORBIDDEN on stderr", () => {
    const r = cliApprove(id, "agent-alice", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /Self-approval is forbidden/i);
    assert.equal(r.stdout, "");
  });
  await check("CLI self-approval is case-insensitive on principal", () => {
    const r = cliApprove(id, "AGENT-ALICE", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /Self-approval is forbidden/i);
  });
  await check("CLI approve with role agent -> denied", () => {
    const r = cliApprove(id, "bob", "agent");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not an out-of-band administrator|Self-approval/i);
  });
  await check("CLI approve with role developer -> denied (only admin/dba may approve)", () => {
    const r = cliApprove(id, "bob", "developer");
    assert.notEqual(r.status, 0);
  });
  await check("CLI approve unknown id -> non-zero exit, 'not found'", () => {
    const r = cliApprove("chg_does_not_exist", "dba-bob", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not found/i);
  });
  await check("CLI approve by admin (different principal) -> exit 0, JSON state=approved with comment", () => {
    const r = cliApprove(id, "dba-bob", "admin", ["--comment", "LGTM"]);
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    assert.equal(j.status, "ok");
    assert.equal(j.state, "approved");
    assert.equal(j.change_id, id);
    assert.equal(j.approval.approved_by, "dba-bob");
    assert.equal(j.approval.comment, "LGTM");
    assert.equal(j.approval.approval_hash, d.approval_hash);
  });
  await check("CLI approve a second time (another admin) is rejected", () => {
    // KNOWN-BUG: F10-02 a second approval silently overwrites the first ApprovalRecord.
    const r = cliApprove(id, "dba-carol", "admin");
    assert.notEqual(r.status, 0, `second approval succeeded: ${r.stdout}`);
  }, { known: "F10-02" });
  await check("get_change after approval shows state=approved + approval record", async () => {
    const g = await callTool(agent, "get_change", { change_id: id });
    assert.equal(g.data.state, "approved");
    assert.match(g.data.approval.approved_at, ISO_RE);
    assert.equal(g.data.approval.approval_hash, d.approval_hash);
  });
  await check("first approver is preserved (not overwritten by a later approve)", async () => {
    // KNOWN-BUG: F10-02
    const g = await callTool(agent, "get_change", { change_id: id });
    assert.equal(g.data.approval.approved_by, "dba-bob");
    assert.equal(g.data.approval.comment, "LGTM");
  }, { known: "F10-02" });

  // Replay: two apply calls fired without awaiting (stdio serialises them, HTTP section covers true parallelism)
  const [a1, a2] = await Promise.all([callTool(agent, "apply_change", { change_id: id }), callTool(agent, "apply_change", { change_id: id })]);
  await check("apply_change -> ok envelope, state=applied, applied_at set", () => {
    assertSuccessEnvelope(a1, "apply");
    assert.equal(a1.data.state, "applied");
    assert.match(a1.data.applied_at, ISO_RE);
    assert.equal(a1.data.change_id, id);
    assert.equal(a1.rows[0][1], "applied");
  });
  await check("apply_change response carries the execution result (rows_affected)", () => {
    // KNOWN-BUG: F10-07 ApplyChangeOutcome.query_result is dropped; only the proposal is returned.
    const ra = a1.data.rows_affected ?? a1.rows_affected ?? a1.data.execution?.rows_affected ?? a1.data.query_result?.rows_affected;
    assert.equal(ra, 1, `no rows_affected in apply response; keys=${Object.keys(a1.data).join(",")}`);
  }, { known: "F10-07" });
  await check("second concurrent apply -> APPROVAL_ALREADY_CONSUMED (exactly one applied)", () => {
    assertDenied(a2, "APPROVAL_ALREADY_CONSUMED", "apply#2");
  });
  await check("apply again (replay) -> APPROVAL_ALREADY_CONSUMED", async () => {
    assertDenied(await callTool(agent, "apply_change", { change_id: id }), "APPROVAL_ALREADY_CONSUMED", "replay");
  });
  await check("effect visible via execute_query", async () => {
    const q = await callTool(agent, "execute_query", { connection: "prod-postgres", sql: "SELECT status FROM orders WHERE id = 102" });
    assert.deepEqual(q.rows, [["shipped"]]);
  });
  await check("get_change after apply -> applied with applied_at and approval", async () => {
    const g = await callTool(agent, "get_change", { change_id: id });
    assert.equal(g.data.state, "applied");
    assert.match(g.data.applied_at, ISO_RE);
    assert.ok(g.data.approval);
  });
  await check("get_change after apply records who applied (applied_by)", async () => {
    // KNOWN-BUG: F10-07 ChangeProposal has no applied_by; only the audit log knows the applier.
    const g = await callTool(agent, "get_change", { change_id: id });
    assert.equal(g.data.applied_by, "agent-alice");
  }, { known: "F10-07" });
  await check("CLI approve of an applied change -> rejected (already consumed)", () => {
    const r = cliApprove(id, "dba-dan", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /already consumed|already been executed/i);
  });
  await check("get_change unknown id -> denied not-found", async () => {
    const r = await callTool(agent, "get_change", { change_id: "chg_does_not_exist" });
    assertDenied(r, null, "get unknown");
    assert.match(r.message, /not found/i);
  });
  await check("?1 placeholders on prod-postgres are rejected (engine expects $n) with a denial, not a crash", async () => {
    const r = await callTool(agent, "propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = ?1 WHERE id = ?2", params: ["x", 102] });
    assertDenied(r, null, "?1 on postgres");
  });
  return id;
}

async function sectionLifecycleSqlite(agent) {
  section("3 DDL/DML matrix on local-sqlite");
  const cases = [
    { sql: "CREATE INDEX idx_f10_orders_status ON orders (status)", cls: "ddl", rev: "transactional_rollback", comp: "DROP INDEX IF EXISTS idx_f10_orders_status;" },
    { sql: "ALTER TABLE inventory ADD COLUMN note TEXT", cls: "ddl", rev: "transactional_rollback" },
    { sql: "DELETE FROM audit_logs WHERE id = ?1", params: [1], cls: "write", rev: "backup_recovery_required" },
    { sql: "DROP TABLE audit_logs", cls: "ddl", rev: "backup_recovery_required" },
  ];
  for (const c of cases) {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: c.sql, params: c.params || [] });
    await check(`${c.sql} -> proposed as ${c.cls}/${c.rev}`, () => {
      assertSuccessEnvelope(p, c.sql);
      assert.equal(p.data.statement_class, c.cls);
      assert.equal(p.data.reversal_safety, c.rev);
      if (c.comp) assert.equal(p.data.compensating_sql, c.comp);
      assert.equal(p.data.approval_hash, expectedApprovalHash(p.data));
    });
    if (!p.data) continue;
    await check(`${c.sql} -> CLI approve + apply -> applied`, async () => {
      const r = cliApprove(p.data.change_id, "dba-bob", "admin");
      assert.equal(r.status, 0, r.stderr);
      const a = await callTool(agent, "apply_change", { change_id: p.data.change_id });
      assertSuccessEnvelope(a, "apply " + c.sql);
      assert.equal(a.data.state, "applied");
    });
  }
  await check("effects visible: index exists, column added, table dropped", async () => {
    const orders = await callTool(agent, "describe_object", { connection: "local-sqlite", object_name: "orders" });
    assert.ok(JSON.stringify(orders.data.indexes || []).includes("idx_f10_orders_status"), "index missing");
    const inv = await callTool(agent, "describe_object", { connection: "local-sqlite", object_name: "inventory" });
    assert.ok(JSON.stringify(inv.data.columns).includes("note"), "column note missing");
    const gone = await callTool(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT count(*) FROM audit_logs" });
    assert.equal(gone.status, "denied", "audit_logs should be gone");
  });
}

async function sectionGovernanceRules(agent) {
  section("4 governance rules at propose time");
  await check("unknown connection -> CONNECTION_NOT_FOUND + next_action list_connections", async () => {
    const r = await callTool(agent, "propose_change", { connection: "nope", sql: "DELETE FROM orders WHERE id = 1" });
    assertDenied(r, "CONNECTION_NOT_FOUND", "unknown conn");
    assert.equal(r.next_action, "list_connections");
  });
  await check("privileged function -> PRIVILEGED_FUNCTION_FORBIDDEN", async () => {
    const r = await callTool(agent, "propose_change", { connection: "prod-postgres", sql: "SELECT pg_read_file('/etc/passwd')" });
    assertDenied(r, "PRIVILEGED_FUNCTION_FORBIDDEN", "priv fn");
    assert.equal(r.next_action, "remove_privileged_function");
  });
  await check("unparseable SQL -> denied (UNKNOWN_SQL_CONSTRUCT)", async () => {
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE FROM WHERE" }), "UNKNOWN_SQL_CONSTRUCT", "bad sql");
  });
  await check("missing sql -> INVALID_ARGUMENT", async () => {
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "  " }), "INVALID_ARGUMENT", "empty sql");
  });
  await check("role not in allowed_roles (guest on prod-postgres) -> UNAUTHORIZED_ROLE for propose and get", async () => {
    const guest = await initClient(stdioClient("guest-1", "guest"));
    try {
      assertDenied(await callTool(guest, "propose_change", { connection: "prod-postgres", sql: "DELETE FROM orders WHERE id = 1" }), "UNAUTHORIZED_ROLE", "guest propose");
    } finally {
      guest.close();
    }
  });
  await check("SELECT cannot be proposed (nothing to govern)", async () => {
    // KNOWN-BUG: F10-04a read statements are accepted, approved and executed through apply_change.
    const r = await callTool(agent, "propose_change", { connection: "prod-postgres", sql: "SELECT id, password_hash FROM users" });
    assert.equal(r.status, "denied", `SELECT accepted as ${r.data && r.data.change_id}`);
  }, { known: "F10-04a" });
  await check("multi-statement batch rejected when allow_multi_statement=false", async () => {
    // KNOWN-BUG: F10-04b accepted; SQLite executes only the first statement and reports 'applied'.
    const r = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status='x' WHERE id=101; UPDATE orders SET status='y' WHERE id=102" });
    assert.equal(r.status, "denied", `multi-statement accepted as ${r.data && r.data.change_id}`);
  }, { known: "F10-04b" });
  await check("mutation on ReadOnly connection (analytics-mysql) rejected at propose time", async () => {
    // KNOWN-BUG: F10-04c accepted at propose/approve; only fails at apply with READONLY_VIOLATION (proposal -> failed).
    const r = await callTool(agent, "propose_change", { connection: "analytics-mysql", sql: "DELETE FROM orders WHERE id = 101" });
    assert.equal(r.status, "denied", `read-only mutation accepted as ${r.data && r.data.change_id}`);
  }, { known: "F10-04c" });
  await check("restricted table (internal_secrets) cannot be targeted by a proposal", async () => {
    // KNOWN-BUG: F10-04d restricted_tables policy is not applied; DELETE FROM internal_secrets gets applied.
    const r = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "DELETE FROM internal_secrets" });
    assert.equal(r.status, "denied", `restricted-table mutation accepted as ${r.data && r.data.change_id}`);
  }, { known: "F10-04d" });
  await check("admin/privilege statement (VACUUM) cannot be proposed", async () => {
    // KNOWN-BUG: F10-04e privilege_or_admin class accepted (policy forbids it for execute_query).
    const r = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "VACUUM" });
    assert.equal(r.status, "denied");
  }, { known: "F10-04e" });

  // execute_query + change_id path
  await check("execute_query with a bogus change_id on GovernedProduction is denied", async () => {
    // KNOWN-BUG: F10-01 (critical) any change_id string flips is_approved_change=true and bypasses approval.
    const r = await callTool(agent, "execute_query", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'hacked' WHERE id = 101", change_id: "chg_bogus" });
    assert.equal(r.status, "denied", `executed with bogus change_id: ${JSON.stringify(r).slice(0, 200)}`);
    const q = await callTool(agent, "execute_query", { connection: "prod-postgres", sql: "SELECT status FROM orders WHERE id = 101" });
    assert.notDeepEqual(q.rows, [["hacked"]]);
  }, { known: "F10-01" });
  await check("execute_query with an approved change_id but different SQL -> APPROVAL_HASH_MISMATCH", async () => {
    // KNOWN-BUG: F10-01 SQL/params/connection are not verified against the proposal.
    const p = await callTool(agent, "propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'viaexec' WHERE id = 101" });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    const r = await callTool(agent, "execute_query", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'other' WHERE id = 101", change_id: p.data.change_id });
    assertDenied(r, r.code === "USE_APPLY_CHANGE" ? "USE_APPLY_CHANGE" : "APPROVAL_HASH_MISMATCH", "exec w/ different sql");
  });
  await check("execute_query with an approved change_id and matching SQL consumes the approval", async () => {
    // KNOWN-BUG: F10-01 the proposal stays 'approved' and can be applied again afterwards (double execution).
    const p = await callTool(agent, "propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'viaexec2' WHERE id = 101" });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    const r = await callTool(agent, "execute_query", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'viaexec2' WHERE id = 101", change_id: p.data.change_id });
    if (r.status === "ok") {
      const g = await callTool(agent, "get_change", { change_id: p.data.change_id });
      assert.equal(g.data.state, "applied", `state after execute_query(change_id) is ${g.data.state}`);
      assertDenied(await callTool(agent, "apply_change", { change_id: p.data.change_id }), "APPROVAL_ALREADY_CONSUMED", "apply after exec");
    } else {
      // Also acceptable: execute_query refuses change_id entirely and points to apply_change.
      assertDenied(r, null, "exec w/ change_id");
    }
  }, { known: "F10-01" });
}

async function sectionTamperDrift(agent) {
  section("5 tamper, drift and constraint binding");
  // (d) constraints are hash-bound
  await check("constraints are part of the approval hash", async () => {
    const a = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'c' WHERE id = 101", constraints: { max_rows: 1 } });
    const b = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'c' WHERE id = 101", constraints: { max_rows: 2 } });
    assert.deepEqual(a.data.constraints, { max_rows: 1 });
    assert.notEqual(a.data.approval_hash, b.data.approval_hash);
    assert.equal(a.data.approval_hash, expectedApprovalHash(a.data));
    assert.equal(cliApprove(a.data.change_id, "dba-bob", "admin").status, 0);
    pyTamper(a.data.change_id, "p['constraints'] = {'max_rows': 999}");
    assertDenied(await callTool(agent, "apply_change", { change_id: a.data.change_id }), "APPROVAL_HASH_MISMATCH", "tampered constraints");
  });
  // (b) tamper sql / params after approval
  await check("tampered params in changes.db after approval -> APPROVAL_HASH_MISMATCH", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = $1 WHERE id = 101", params: ["t1"] });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    pyTamper(p.data.change_id, "p['params'] = ['PWNED']");
    const r = await callTool(agent, "apply_change", { change_id: p.data.change_id });
    assertDenied(r, "APPROVAL_HASH_MISMATCH", "tampered params");
    assert.equal(r.next_action, "capture_schema");
  });
  await check("tampered SQL text in changes.db after approval -> APPROVAL_HASH_MISMATCH, not executed", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'ok' WHERE id = 101" });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    pyTamper(p.data.change_id, "p['sql'] = 'DELETE FROM orders'; p['normalized_sql'] = 'DELETE FROM orders'");
    assertDenied(await callTool(agent, "apply_change", { change_id: p.data.change_id }), "APPROVAL_HASH_MISMATCH", "tampered sql");
    const q = await callTool(agent, "execute_query", { connection: "local-sqlite", sql: "SELECT count(*) FROM orders" });
    assert.equal(q.rows[0][0], 2, "orders must not have been deleted");
  });
  await check("tampered SQL before approval -> CLI approve refuses (integrity check)", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'ok' WHERE id = 101" });
    pyTamper(p.data.change_id, "p['sql'] = 'DELETE FROM orders'; p['normalized_sql'] = 'DELETE FROM orders'");
    const r = cliApprove(p.data.change_id, "dba-bob", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /hash mismatch|integrity/i);
  });
  await check("forged approval written directly to changes.db is not accepted by apply_change", async () => {
    // KNOWN-BUG: F10-03 approval_hash is an unkeyed SHA-256 over proposal fields; writing state='approved'
    // plus a fabricated ApprovalRecord (approved_by any name, hash copied) passes every check and executes.
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'forged' WHERE id = 101" });
    pyTamper(p.data.change_id, "p['state']='approved'; p['approval']={'approved_by':'ghost','approved_at':'2026-01-01T00:00:00Z','approval_hash':p['approval_hash']}");
    const r = await callTool(agent, "apply_change", { change_id: p.data.change_id });
    assert.equal(r.status, "denied", `forged approval executed: state=${r.data && r.data.state}`);
  }, { known: "F10-03" });
  // (a) schema drift
  await check("out-of-band schema change after approval -> SCHEMA_DRIFT_DETECTED, approval not consumed", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'drift' WHERE id = 101" });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    const alter = await callTool(agent, "execute_query", { connection: "local-sqlite", sql: "ALTER TABLE orders ADD COLUMN tmp INT" });
    assert.equal(alter.status, "ok", "OOB alter in Development mode must succeed");
    const r = await callTool(agent, "apply_change", { change_id: p.data.change_id });
    assertDenied(r, "SCHEMA_DRIFT_DETECTED", "drift");
    assert.equal(r.next_action, "capture_schema");
    assert.match(r.message, /approved against 'snapshot_[0-9a-f]+', but current schema is 'snapshot_[0-9a-f]+'/);
    const g = await callTool(agent, "get_change", { change_id: p.data.change_id });
    assert.equal(g.data.state, "approved");
  });
  await check("failed execution (missing table) -> state=failed with execution_error", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE f10_missing SET x = 1" });
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    assertDenied(await callTool(agent, "apply_change", { change_id: p.data.change_id }), "ADAPTER_ERROR", "missing table");
    const g = await callTool(agent, "get_change", { change_id: p.data.change_id });
    assert.equal(g.data.state, "failed");
    assert.match(g.data.execution_error, /no such table/);
  });
}

async function sectionTtl(agent) {
  section("6 TTL / expiry");
  await check("default_ttl_seconds (3600) applied when ttl omitted; expires_at is ISO-8601", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd' WHERE id = 101" });
    assert.match(p.data.expires_at, ISO_RE);
    assert.equal((new Date(p.data.expires_at) - new Date(p.data.created_at)) / 1000, 3600);
  });
  await check("ttl_seconds=1: approved change expires -> apply APPROVAL_EXPIRED, get_change -> expired", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'ttl' WHERE id = 101", ttl_seconds: 1 });
    assert.equal((new Date(p.data.expires_at) - new Date(p.data.created_at)) / 1000, 1);
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    await sleep(2200);
    const r = await callTool(agent, "apply_change", { change_id: p.data.change_id });
    assertDenied(r, "APPROVAL_EXPIRED", "expired apply");
    assert.equal(r.next_action, "propose_change");
    const g = await callTool(agent, "get_change", { change_id: p.data.change_id });
    assert.equal(g.data.state, "expired");
  });
  await check("ttl_seconds=1: CLI approve after expiry -> rejected (expired)", async () => {
    const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'ttl' WHERE id = 101", ttl_seconds: 1 });
    await sleep(2200);
    const r = cliApprove(p.data.change_id, "dba-bob", "admin");
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /expired/i);
  });
  await check("config default_ttl_seconds is honoured (isolated config with 2s)", async () => {
    const { configPath: cfg2 } = makeIsolatedConfig({ dir: ISO, fileName: "db-mcp-ttl2.toml", transform: (t) => t.replace(/default_ttl_seconds\s*=\s*\d+/, "default_ttl_seconds = 2") });
    const c = await initClient(stdioClient("agent-alice", "agent", cfg2));
    try {
      const p = await callTool(c, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd2' WHERE id = 101" });
      assert.equal((new Date(p.data.expires_at) - new Date(p.data.created_at)) / 1000, 2);
    } finally {
      c.close();
    }
  });
  await check("ttl_seconds=0 is rejected as INVALID_ARGUMENT", async () => {
    // KNOWN-BUG: F10-05 no validation; proposal is created already expired.
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd' WHERE id = 101", ttl_seconds: 0 }), "INVALID_ARGUMENT", "ttl 0");
  }, { known: "F10-05" });
  await check("negative ttl_seconds is rejected as INVALID_ARGUMENT", async () => {
    // KNOWN-BUG: F10-05 expires_at lands in the past.
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd' WHERE id = 101", ttl_seconds: -5 }), "INVALID_ARGUMENT", "ttl -5");
  }, { known: "F10-05" });
  await check("non-integer ttl_seconds (1.5) is rejected, not silently replaced by the default", async () => {
    // KNOWN-BUG: F10-05 as_i64() fails -> default TTL used silently.
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd' WHERE id = 101", ttl_seconds: 1.5 }), "INVALID_ARGUMENT", "ttl 1.5");
  }, { known: "F10-05" });
  await check("absurd ttl_seconds (1e12) is rejected (max TTL)", async () => {
    // KNOWN-BUG: F10-05 accepted; expires in year 33715.
    assertDenied(await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'd' WHERE id = 101", ttl_seconds: 1e12 }), "INVALID_ARGUMENT", "ttl 1e12");
  }, { known: "F10-05" });
  await check("ttl_seconds=9223372036854775 returns a denial and does NOT crash the server", async () => {
    // KNOWN-BUG: F10-05 (DoS) chrono TimeDelta::seconds panics -> whole stdio server process exits.
    const probe = await initClient(stdioClient("agent-alice", "agent", CFG, 8000));
    try {
      let resp;
      try {
        resp = await callTool(probe, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'x' WHERE id = 101", ttl_seconds: 9223372036854775 });
      } catch (e) {
        resp = { transportError: e.message.slice(0, 160) };
      }
      await sleep(300);
      assert.equal(probe.child.exitCode, null, `server process exited (code ${probe.child.exitCode}); stderr=${probe.stderr.join("").slice(0, 200)}`);
      assertDenied(resp, "INVALID_ARGUMENT", "huge ttl");
    } finally {
      probe.close();
    }
  }, { known: "F10-05" });
}

async function sectionPersistence() {
  section("8 persistence across restart, policy revision, CLI without --config");
  let changeId;
  await check("proposal + approval survive a server restart (same changes.db)", async () => {
    const c1 = await initClient(stdioClient("agent-alice", "agent"));
    const p = await callTool(c1, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'persist' WHERE id = 101" });
    changeId = p.data.change_id;
    c1.close();
    await sleep(400);
    assert.equal(cliApprove(changeId, "dba-bob", "admin").status, 0);
    const c2 = await initClient(stdioClient("agent-alice", "agent"));
    try {
      const g = await callTool(c2, "get_change", { change_id: changeId });
      assert.equal(g.data.state, "approved");
      assert.equal(g.data.approval.approved_by, "dba-bob");
    } finally {
      c2.close();
    }
  });
  await check("policy_revision changed between approval and apply -> APPROVAL_HASH_MISMATCH", async () => {
    const { configPath: cfgV2 } = makeIsolatedConfig({ dir: ISO, fileName: "db-mcp-v2.toml", transform: (t) => t.replace('policy_revision = "policy_v1"', 'policy_revision = "policy_v2"') });
    const c = await initClient(stdioClient("agent-alice", "agent", cfgV2));
    try {
      assertDenied(await callTool(c, "apply_change", { change_id: changeId }), "APPROVAL_HASH_MISMATCH", "policy rev");
    } finally {
      c.close();
    }
  });
  await check("CLI approve without --config targets the in-memory demo store -> fails loudly (not silently ok)", () => {
    const r = cliApprove(changeId, "dba-x", "admin", [], null);
    assert.notEqual(r.status, 0, `approve without --config succeeded against the wrong store: ${r.stdout}`);
    assert.match(r.stderr, /not found/i);
  });
}

async function sectionHttp() {
  section("9 HTTP transport: /admin/approve + /mcp");
  const port = await getFreePort();
  const bind = `127.0.0.1:${port}`;
  const child = spawnDbMcpServer(["serve", "--transport", "http", "--bind", bind, "--config", CFG], {
    cwd: REPO_ROOT,
    env: { ...process.env, DB_MCP_AUTH_TOKEN: "f10-agent-token", DB_MCP_ADMIN_TOKEN: "f10-admin-token", DB_MCP_QUIET: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  child.on("exit", () => children.delete(child));
  const base = `http://${bind}`;
  let rpcId = 1;
  const mcp = async (name, args, principal = "http-agent", role = "agent") => {
    const r = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer f10-agent-token", "x-mcp-principal": principal, "x-mcp-role": role },
      body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method: "tools/call", params: { name, arguments: args } }),
    });
    const j = await r.json();
    return { http: r.status, payload: j.result ? j.result.structuredContent : j, isError: j.result ? j.result.isError : undefined };
  };
  const approve = async (body, token = "f10-admin-token") => {
    const headers = { "content-type": "application/json" };
    if (token) headers.authorization = `Bearer ${token}`;
    const r = await fetch(`${base}/admin/approve`, { method: "POST", headers, body: JSON.stringify(body) });
    return { http: r.status, body: await r.json().catch(() => null) };
  };
  try {
    let healthy = false;
    for (let i = 0; i < 80 && !healthy; i++) {
      try {
        healthy = (await fetch(`${base}/health`)).status === 200;
      } catch {
        await sleep(150);
      }
    }
    assert.ok(healthy, "HTTP server did not become healthy");

    const prop = await mcp("propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'http' WHERE id = 102" }, "proposer-pat", "agent");
    const cid = prop.payload.data && prop.payload.data.change_id;
    await check("propose over /mcp binds x-mcp-principal as proposing_principal", () => {
      assert.equal(prop.http, 200);
      assertSuccessEnvelope(prop.payload, "http propose");
      assert.equal(prop.payload.data.proposing_principal, "proposer-pat");
    });
    await check("POST /admin/approve with wrong token -> 401", async () => {
      const r = await approve({ change_id: cid, approver: "dba-x", role: "admin" }, "wrong");
      assert.equal(r.http, 401);
      assert.equal(r.body.code, "UNAUTHORIZED");
    });
    await check("POST /admin/approve without token -> 401", async () => {
      assert.equal((await approve({ change_id: cid, approver: "dba-x", role: "admin" }, null)).http, 401);
    });
    await check("POST /admin/approve with the agent bearer token -> 401 (admin token required)", async () => {
      assert.equal((await approve({ change_id: cid, approver: "dba-x", role: "admin" }, "f10-agent-token")).http, 401);
    });
    await check("self-approval via HTTP -> 400 SELF_APPROVAL_FORBIDDEN", async () => {
      const r = await approve({ change_id: cid, approver: "proposer-pat", role: "admin" });
      assert.equal(r.http, 400);
      assert.equal(r.body.status, "denied");
      assert.equal(r.body.code, "SELF_APPROVAL_FORBIDDEN");
    });
    await check("HTTP approve with role=agent -> 400 SELF_APPROVAL_FORBIDDEN", async () => {
      const r = await approve({ change_id: cid, approver: "dba-x", role: "agent" });
      assert.equal(r.http, 400);
      assert.equal(r.body.code, "SELF_APPROVAL_FORBIDDEN");
    });
    await check("HTTP approve unknown change -> 400 not found", async () => {
      const r = await approve({ change_id: "chg_nope", approver: "dba-x", role: "admin" });
      assert.equal(r.http, 400);
      assert.match(r.body.message, /not found/);
    });
    await check("HTTP approve by dba (correct token) -> 200 + proposal JSON state=approved", async () => {
      const r = await approve({ change_id: cid, approver: "dba-x", role: "dba", comment: "via http" });
      assert.equal(r.http, 200);
      assert.equal(r.body.status, "ok");
      assert.equal(r.body.proposal.state, "approved");
      assert.equal(r.body.proposal.change_id, cid);
      assert.equal(r.body.proposal.approval.approved_by, "dba-x");
      assert.equal(r.body.proposal.approval.comment, "via http");
    });
    await check("4 truly concurrent apply_change over HTTP -> exactly one applied, rest APPROVAL_ALREADY_CONSUMED with isError", async () => {
      const rs = await Promise.all([1, 2, 3, 4].map((i) => mcp("apply_change", { change_id: cid }, `applier-${i}`, "agent")));
      const ok = rs.filter((r) => r.payload.status === "ok");
      const denied = rs.filter((r) => r.payload.status === "denied");
      assert.equal(ok.length, 1, JSON.stringify(rs.map((r) => r.payload.code || r.payload.status)));
      assert.equal(denied.length, 3);
      for (const d of denied) {
        assert.equal(d.payload.code, "APPROVAL_ALREADY_CONSUMED");
        assert.equal(d.isError, true);
      }
      assertSuccessEnvelope(ok[0].payload, "http apply");
      assert.equal(ok[0].payload.data.state, "applied");
      const q = await mcp("execute_query", { connection: "prod-postgres", sql: "SELECT status FROM orders WHERE id = 102" });
      assert.deepEqual(q.payload.rows, [["http"]]);
    });
    await check("concurrent approvals by three admins -> only one succeeds", async () => {
      // KNOWN-BUG: F10-02 every approve succeeds and overwrites the previous record.
      const p2 = await mcp("propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'race' WHERE id = 101" }, "proposer-pat", "agent");
      const rs = await Promise.all(["a1", "a2", "a3"].map((n) => approve({ change_id: p2.payload.data.change_id, approver: n, role: "admin" })));
      assert.equal(rs.filter((r) => r.http === 200).length, 1, rs.map((r) => r.http).join(","));
    }, { known: "F10-02" });
    await check("tools/list over HTTP has no approve tool", async () => {
      const r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer f10-agent-token" }, body: JSON.stringify({ jsonrpc: "2.0", id: 9999, method: "tools/list" }) });
      const names = (await r.json()).result.tools.map((t) => t.name);
      assert.deepEqual(names.filter((n) => /approv/i.test(n)), []);
    });
  } finally {
    child.kill();
    await sleep(300);
  }
}

async function sectionAudit(agent, prodChangeId) {
  section("10 audit trail (isolated audit.jsonl)");
  // A proposal containing a credential literal, to check redaction
  const secretProp = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE users SET password_hash = 'super_secret_password_123' WHERE id = 1" });
  await sleep(300);
  const events = readAudit();
  const byChange = (id) => events.filter((e) => e.change_id === id);
  await check("propose_change audited with principal, change_id, decision=requires_approval, sql hash", () => {
    const ev = byChange(prodChangeId).find((e) => e.tool_name === "propose_change");
    assert.ok(ev, "no propose audit event");
    assert.equal(ev.principal, "agent-alice");
    assert.equal(ev.decision, "requires_approval");
    assert.equal(ev.connection, "prod-postgres");
    assert.equal(typeof ev.sql_hash, "string");
    assert.equal(ev.schema_version && ev.schema_version.startsWith("snapshot_"), true);
  });
  await check("apply_change audited with decision=approved_execution and change_id", () => {
    const ev = byChange(prodChangeId).find((e) => e.tool_name === "apply_change");
    assert.ok(ev, "no apply audit event");
    assert.equal(ev.decision, "approved_execution");
    assert.equal(ev.principal, "agent-alice");
  });
  await check("approvals (CLI and HTTP) are recorded in the audit trail", () => {
    // KNOWN-BUG: F10-06a approve_change never emits an AuditEvent (CLI builds a ChangeManager without audit sinks;
    // DbMcpRuntime::approve_change / handle_admin_approve do not record).
    const ev = events.find((e) => e.change_id === prodChangeId && /approve/i.test(e.tool_name));
    assert.ok(ev, `no approval audit event for ${prodChangeId}; tools seen: ${[...new Set(events.map((e) => e.tool_name))].join(",")}`);
  });
  await check("denied apply attempts (replay/drift/hash mismatch/expired) are audited with denial_code", () => {
    // KNOWN-BUG: F10-06b dispatch for apply_change only logs the success path; Err paths are not audited.
    const codes = new Set(events.filter((e) => e.tool_name === "apply_change").map((e) => e.denial_code).filter(Boolean));
    for (const c of ["APPROVAL_ALREADY_CONSUMED", "SCHEMA_DRIFT_DETECTED", "APPROVAL_HASH_MISMATCH", "APPROVAL_EXPIRED"]) {
      assert.ok(codes.has(c), `missing audited denial ${c}; have ${[...codes].join(",") || "none"}`);
    }
  });
  await check("self-approval attempts are audited", () => {
    // KNOWN-BUG: F10-06a
    assert.ok(events.some((e) => e.denial_code === "SELF_APPROVAL_FORBIDDEN"), "no SELF_APPROVAL_FORBIDDEN audit event");
  }, { known: "F10-06a" });
  await check("no credential literals in audit records", () => {
    // KNOWN-BUG: F10-08 redact_sensitive_text misses `password_hash = '...'`; the literal lands in audit.jsonl.
    const raw = fs.readFileSync(AUDIT_JSONL, "utf8");
    assert.ok(secretProp.data, "secret proposal was not created");
    assert.ok(!raw.includes("super_secret_password_123"), "credential literal present in audit.jsonl");
  }, { known: "F10-08" });
  await check("audit records do not carry bearer tokens or DSN secrets", () => {
    const raw = fs.readFileSync(AUDIT_JSONL, "utf8");
    assert.ok(!raw.includes("f10-admin-token") && !raw.includes("f10-agent-token"));
  });
}

async function sectionEnvelopes(agent) {
  section("7 envelopes");
  const p = await callTool(agent, "propose_change", { connection: "local-sqlite", sql: "UPDATE orders SET status = 'env' WHERE id = 102" });
  await check("propose/get/apply all return the standard success envelope", async () => {
    assertSuccessEnvelope(p, "propose");
    const g = await callTool(agent, "get_change", { change_id: p.data.change_id });
    assertSuccessEnvelope(g, "get");
    assert.equal(cliApprove(p.data.change_id, "dba-bob", "admin").status, 0);
    const a = await callTool(agent, "apply_change", { change_id: p.data.change_id });
    assertSuccessEnvelope(a, "apply");
    for (const x of [p, g, a]) {
      assert.equal(x.connection, "local-sqlite");
      assert.equal(x.returned_rows, 1);
      assert.equal(x.truncated, false);
      assert.deepEqual(x.columns.map((c) => c.name), ["change_id", "state", "approval_hash", "proposing_principal", "schema_fingerprint", "reversibility", "expires_at"]);
      assert.equal(x._meta.provenance.source_kind, "change_proposal");
    }
  });
  await check("denied envelope shape (request_id/status/code/message/retryable) and isError flag", async () => {
    const r = await agent.rpc("tools/call", { name: "apply_change", arguments: { change_id: p.data.change_id } });
    assert.equal(r.result.isError, true);
    assertDenied(r.result.structuredContent, "APPROVAL_ALREADY_CONSUMED", "denied envelope");
    assert.equal(r.result.content[0].type, "text");
  });
}

// ---------------------------------------------------------------------------------------------
async function main() {
  console.log(`F10 change governance - isolated config: ${CFG}`);
  const agent = await initClient(stdioClient("agent-alice", "agent"));
  let prodChangeId;
  try {
    await sectionToolSurface(agent);
    prodChangeId = await sectionLifecycleProd(agent);
    await sectionLifecycleSqlite(agent);
    await sectionGovernanceRules(agent);
    await sectionTamperDrift(agent);
    await sectionTtl(agent);
    await sectionEnvelopes(agent);
  } finally {
    agent.close();
    await sleep(400);
  }
  await sectionPersistence();
  await sectionHttp();
  const agent2 = await initClient(stdioClient("agent-alice", "agent"));
  try {
    await sectionAudit(agent2, prodChangeId);
  } finally {
    agent2.close();
    await sleep(400);
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);
  const knownFailed = failed.filter((r) => r.known);
  const unexpected = failed.filter((r) => !r.known);
  console.log(`\n==== F10 SUMMARY: ${passed} passed, ${failed.length} failed (${knownFailed.length} known bugs, ${unexpected.length} unexpected) of ${results.length} checks`);
  if (knownFailed.length) console.log("  known-bug failures: " + [...new Set(knownFailed.map((r) => r.known))].sort().join(", "));
  for (const r of unexpected) console.log(`  UNEXPECTED: ${r.label}: ${String(r.err && r.err.message).split("\n")[0]}`);
  const allowKnown = process.env.F10_ALLOW_KNOWN_BUGS === "1";
  return failed.length === 0 || (allowKnown && unexpected.length === 0) ? 0 : 1;
}

function cleanup() {
  for (const c of children) {
    try {
      c.kill();
    } catch {
      // already gone
    }
  }
  setTimeout(() => {
    try {
      fs.rmSync(TMP, { recursive: true, force: true });
    } catch {
      // leave temp dir behind if a handle is still open
    }
  }, 300).unref();
}

main()
  .then((code) => {
    cleanup();
    setTimeout(() => process.exit(code), 600);
  })
  .catch((err) => {
    console.error("F10 harness failure:", err);
    cleanup();
    setTimeout(() => process.exit(1), 600);
  });
