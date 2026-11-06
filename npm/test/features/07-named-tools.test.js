#!/usr/bin/env node
"use strict";
/**
 * F07 - `run_named_tool` and declarative named-tool configuration.
 *
 * Self-contained feature verification (node:assert only). Run from the repo root:
 *   node npm/test/features/07-named-tools.test.js
 *
 * Every check runs against private isolated configs (never config/db-mcp.example.toml directly)
 * through the prebuilt binary via the npm launcher. Exit 0 when all checks pass, 1 otherwise.
 * Assertions encode the CORRECT behaviour; checks that currently fail are tagged `// KNOWN-BUG: <id>`.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const LAUNCHER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const { createClient } = require(path.join(REPO_ROOT, "scripts", "mcp-call.js"));

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------
const results = [];
const children = new Set();
async function check(id, name, fn) {
  try {
    const detail = await fn();
    results.push({ id, name, ok: true });
    console.log(`PASS  ${id} ${name}${typeof detail === "string" && detail ? "  :: " + detail : ""}`);
  } catch (err) {
    results.push({ id, name, ok: false, err: err.message });
    console.log(`FAIL  ${id} ${name}  :: ${String(err.message).split("\n")[0].slice(0, 400)}`);
  }
}
function killAll() {
  for (const c of children) { try { c.kill(); } catch {} }
}
process.on("exit", killAll);
process.on("SIGINT", () => { killAll(); process.exit(130); });

async function openSession(config, role, principal = "nt-tester") {
  const client = createClient({ config, principal, role, timeoutMs: 30000 });
  children.add(client.child);
  const init = await client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f07", version: "0.1.0" } });
  if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)} ${client.stderr.join("")}`);
  client.notify("notifications/initialized", {});
  const call = async (tool, args) => {
    const resp = await client.rpc("tools/call", { name: tool, arguments: args });
    if (resp.error) throw new Error(`JSON-RPC error for ${tool}: ${JSON.stringify(resp.error)}`);
    return resp.result.structuredContent !== undefined ? resp.result.structuredContent : resp.result;
  };
  const named = (tool_name, args) => {
    const a = { tool_name };
    if (args !== undefined) a.arguments = args;
    return call("run_named_tool", a);
  };
  const close = () => { children.delete(client.child); client.close(); };
  return { client, call, named, close, rpc: client.rpc };
}

function ok(p, label) {
  assert.equal(p.status, "ok", `${label}: expected status=ok, got ${JSON.stringify(p).slice(0, 300)}`);
  for (const k of ["request_id", "connection", "columns", "rows", "returned_rows", "truncated", "warnings", "schema_version"]) {
    assert.ok(k in p, `${label}: envelope missing '${k}'`);
  }
  assert.equal(p._meta?.provenance?.untrusted_content, true, `${label}: _meta.provenance.untrusted_content must be true`);
  assert.equal(p.returned_rows, p.rows.length, `${label}: returned_rows must equal rows.length`);
  return p;
}
function denied(p, code, label) {
  assert.equal(p.status, "denied", `${label}: expected denied, got ${JSON.stringify(p).slice(0, 300)}`);
  assert.equal(p.code, code, `${label}: expected code ${code}, got ${p.code} (${p.message})`);
  return p;
}
function verifyConfig(file) {
  const r = spawnSync(process.execPath, [LAUNCHER, "verify-config", "--config", file], { cwd: REPO_ROOT, encoding: "utf8" });
  let summary = null;
  try { summary = JSON.parse(r.stdout.trim()); } catch {}
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, summary };
}
function isoConfig(extraToml, opts = {}) {
  return makeIsolatedConfig({ ...opts, transform: (t) => t + extraToml });
}

// ---------------------------------------------------------------------------------------------
// Named tools under test (appended to the isolated copy of the example config)
// ---------------------------------------------------------------------------------------------
const EXTRA_TOOLS = `

[[named_tools]]
name = "t_max1"
description = "Two-row result capped by max_rows=1"
connection = "local-sqlite"
statement = "SELECT id FROM orders ORDER BY id"
read_only = true
max_rows = 1
allowed_roles = ["*"]

[[named_tools]]
name = "t_inject"
description = "SELECT * by email (zero interpolation + redaction)"
connection = "local-sqlite"
statement = "SELECT * FROM users WHERE email = ?1"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "email"
param_type = "string"
description = "email"
required = true

[[named_tools]]
name = "t_all_defaults"
description = "Every parameter has a default"
connection = "local-sqlite"
statement = "SELECT id FROM orders WHERE total_cents >= ?1 ORDER BY id"
read_only = true
[[named_tools.parameters]]
name = "min_total"
param_type = "integer"
description = "min total"
required = false
default_value = 0

[[named_tools]]
name = "t_types"
description = "One parameter of every supported type"
connection = "local-sqlite"
statement = "SELECT ?1 AS i, ?2 AS s, ?3 AS f, ?4 AS b, ?5 AS j"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "i"
param_type = "integer"
description = "integer"
[[named_tools.parameters]]
name = "s"
param_type = "string"
description = "string"
[[named_tools.parameters]]
name = "f"
param_type = "float"
description = "float"
[[named_tools.parameters]]
name = "b"
param_type = "boolean"
description = "boolean"
[[named_tools.parameters]]
name = "j"
param_type = "json"
description = "json"

[[named_tools]]
name = "t_write_dev"
description = "INSERT on Development sqlite"
connection = "local-sqlite"
statement = "INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (?1, ?2, ?3)"
read_only = false
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "order_id"
param_type = "integer"
description = "order"
[[named_tools.parameters]]
name = "event_type"
param_type = "string"
description = "event"
[[named_tools.parameters]]
name = "created_at"
param_type = "string"
description = "ts"

[[named_tools]]
name = "t_write_mysql"
description = "INSERT on ReadOnly mysql"
connection = "analytics-mysql"
statement = "INSERT INTO audit_logs (order_id, event_type, created_at) VALUES (?, ?, ?)"
read_only = false
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "order_id"
param_type = "integer"
description = "order"
[[named_tools.parameters]]
name = "event_type"
param_type = "string"
description = "event"
[[named_tools.parameters]]
name = "created_at"
param_type = "string"
description = "ts"

[[named_tools]]
name = "t_secrets"
description = "Reads a restricted table"
connection = "local-sqlite"
statement = "SELECT secret_key FROM internal_secrets"
read_only = true
allowed_roles = ["*"]

[[named_tools]]
name = "t_hash"
description = "Selects a sensitive column"
connection = "local-sqlite"
statement = "SELECT id, password_hash FROM users WHERE id = ?1"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "user_id"
param_type = "integer"
description = "user"

[[named_tools]]
name = "t_pg_read"
description = "Read on GovernedProduction postgres"
connection = "prod-postgres"
statement = "SELECT id, status FROM orders WHERE id = $1"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "order_id"
param_type = "integer"
description = "order"

[[named_tools]]
name = "t_pg_write"
description = "Write on GovernedProduction postgres"
connection = "prod-postgres"
statement = "UPDATE orders SET status = $1 WHERE id = $2"
read_only = false
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "status"
param_type = "string"
description = "status"
[[named_tools.parameters]]
name = "order_id"
param_type = "integer"
description = "order"

[[named_tools]]
name = "t_slow"
description = "Recursive CTE with timeout_ms=1"
connection = "local-sqlite"
statement = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 200000000) SELECT count(*) FROM c"
read_only = true
timeout_ms = 1
allowed_roles = ["*"]

[[named_tools]]
name = "t_two_placeholders"
description = "?2 referenced but only one parameter declared"
connection = "local-sqlite"
statement = "SELECT id FROM orders WHERE id = ?1 AND user_id = ?2"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "id"
param_type = "integer"
description = "id"

[[named_tools]]
name = "t_unused_param"
description = "Declared parameter not referenced by the statement"
connection = "local-sqlite"
statement = "SELECT id FROM orders WHERE id = ?1"
read_only = true
allowed_roles = ["*"]
[[named_tools.parameters]]
name = "id"
param_type = "integer"
description = "id"
[[named_tools.parameters]]
name = "extra"
param_type = "string"
description = "unused"

[[named_tools]]
name = "t_noroles"
description = "allowed_roles omitted"
connection = "local-sqlite"
statement = "SELECT 1 AS one"
read_only = true
`;

const NAMED_TOOL_COUNT = 2 + 14; // 2 example tools + 14 appended above

// ---------------------------------------------------------------------------------------------
// Minimal config object for the JSON / YAML variants (mirrors the TOML shape)
// ---------------------------------------------------------------------------------------------
function minimalConfigObject(dir) {
  const posix = (p) => p.replace(/\\/g, "/");
  return {
    server_name: "db-mcp-fmt",
    server_version: "0.1.0",
    default_mode: "ReadOnly",
    active_profiles: ["Explore", "Query"],
    audit: { in_memory: true, jsonl_path: posix(path.join(dir, "audit.jsonl")) },
    changes: { storage_path: posix(path.join(dir, "changes.db")), policy_revision: "policy_v1", default_ttl_seconds: 3600 },
    connections: [{
      id: "local-sqlite", engine: "Sqlite", dsn: "sqlite://" + posix(path.join(dir, "sample.db")), mode: "Development", read_only: false,
      description: "fmt fixture", default_schema: "main", timeout_ms: 10000, max_rows: 500, max_bytes: 1048576,
      allow_multi_statement: false, allow_explain_analyze: true, restricted_tables: ["internal_secrets"], sensitive_tables: [],
      sensitive_columns: ["password_hash"], deny_sensitive_column_access: false, unrestricted_sql_provenance: false,
      allowed_roles: ["*"], allowed_principals: ["*"],
      init_sql: "DROP TABLE IF EXISTS users;\nCREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT NOT NULL);\nINSERT INTO users VALUES (1, 'alice@example.com', 'h1'), (2, 'bob@example.com', 'h2');\n",
    }],
    named_tools: [{
      name: "get_user_by_id", description: "user by id", connection: "local-sqlite",
      statement: "SELECT id, email FROM users WHERE id = ?1", read_only: true, max_rows: 1, timeout_ms: 5000,
      allowed_roles: ["agent", "developer", "dba", "admin"],
      parameters: [{ name: "user_id", param_type: "integer", description: "user id", required: true }],
    }, {
      name: "list_users", description: "users from id", connection: "local-sqlite",
      statement: "SELECT id, email FROM users WHERE id >= ?1 ORDER BY id", read_only: true,
      parameters: [{ name: "min_id", param_type: "integer", description: "min id", required: false, default_value: 0 }],
    }],
  };
}
// Tiny block-style YAML emitter (scalars double-quoted with JSON escapes, valid YAML 1.2).
function toYaml(obj) {
  const lines = [];
  const scalar = (v) => (typeof v === "string" ? JSON.stringify(v) : String(v));
  const emit = (v, indent, prefix) => {
    const pad = " ".repeat(indent);
    if (Array.isArray(v)) {
      if (v.length === 0) { lines.push(`${pad}${prefix} []`); return; }
      lines.push(`${pad}${prefix}`);
      for (const item of v) {
        if (item && typeof item === "object" && !Array.isArray(item)) {
          Object.keys(item).forEach((k, i) => emit(item[k], indent + 2, `${i === 0 ? "- " : "  "}${k}:`));
        } else {
          lines.push(`${pad}  - ${scalar(item)}`);
        }
      }
    } else if (v && typeof v === "object") {
      lines.push(`${pad}${prefix}`);
      for (const k of Object.keys(v)) emit(v[k], indent + 2, `${k}:`);
    } else {
      lines.push(`${pad}${prefix} ${scalar(v)}`);
    }
  };
  for (const k of Object.keys(obj)) emit(obj[k], 0, `${k}:`);
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------
async function main() {
  console.log("F07 run_named_tool / declarative named tools");
  const { configPath: CFG, dir: DIR } = isoConfig(EXTRA_TOOLS);
  const auditPath = path.join(DIR, "audit.jsonl");

  // ---------------- 0. config loads --------------------------------------------------------
  await check("07.00", "verify-config accepts the isolated config with appended named tools", () => {
    const r = verifyConfig(CFG);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.summary.status, "ok");
    assert.equal(r.summary.named_tools, NAMED_TOOL_COUNT, `named_tools count ${r.summary.named_tools}`);
    return `named_tools=${r.summary.named_tools}`;
  });

  const S = await openSession(CFG, "agent");
  try {
    // ---------------- 1. happy path ---------------------------------------------------------
    await check("07.01", "get_user_by_id happy path returns alice", async () => {
      const p = ok(await S.named("get_user_by_id", { user_id: 1 }), "get_user_by_id");
      assert.equal(p.connection, "local-sqlite");
      assert.deepEqual(p.columns.map((c) => c.name), ["id", "email", "role", "created_at"]);
      assert.equal(p.returned_rows, 1);
      assert.equal(p.rows[0][1], "alice@example.com");
      assert.equal(p.truncated, false);
    });
    await check("07.02", "list_orders_by_status(status=completed) applies default min_total_cents=0", async () => {
      const p = ok(await S.named("list_orders_by_status", { status: "completed" }), "list_orders_by_status");
      assert.equal(p.returned_rows, 1);
      assert.equal(p.rows[0][0], 101);
    });
    await check("07.03", "list_orders_by_status explicit min_total_cents=2000 filters out pending(1900)", async () => {
      const p = ok(await S.named("list_orders_by_status", { status: "pending", min_total_cents: 2000 }), "min_total_cents");
      assert.equal(p.returned_rows, 0);
    });
    await check("07.04", "explicit null for optional parameter falls back to the default", async () => {
      const p = ok(await S.named("list_orders_by_status", { status: "pending", min_total_cents: null }), "null optional");
      assert.equal(p.returned_rows, 1);
      assert.equal(p.rows[0][0], 102);
    });
    await check("07.05", "`arguments` omitted entirely for an all-defaults tool", async () => {
      const p = ok(await S.named("t_all_defaults"), "t_all_defaults");
      assert.equal(p.returned_rows, 2);
    });
    await check("07.06", "tool max_rows=1 truncates a 2-row result (truncated=true + warning)", async () => {
      const p = ok(await S.named("t_max1", {}), "t_max1");
      assert.equal(p.returned_rows, 1);
      assert.equal(p.truncated, true);
      assert.ok(p.warnings.some((w) => /max_rows/i.test(w)), `warnings: ${JSON.stringify(p.warnings)}`);
    });

    // ---------------- 2. type validation ---------------------------------------------------
    const expectInvalid = async (label, tool, args, re) => {
      const p = denied(await S.named(tool, args), "INVALID_ARGUMENT", label);
      assert.match(p.message, re, `${label}: message ${p.message}`);
      return p.message;
    };
    await check("07.07", "integer param given string \"1\" is rejected (strict, no coercion)", () =>
      expectInvalid("str->int", "get_user_by_id", { user_id: "1" }, /expected type Integer, got string/));
    await check("07.08", "integer param given float 1.5 is rejected", () =>
      expectInvalid("float->int", "get_user_by_id", { user_id: 1.5 }, /expected type Integer, got float/));
    await check("07.09", "integer param given boolean is rejected", () =>
      expectInvalid("bool->int", "get_user_by_id", { user_id: true }, /expected type Integer, got boolean/));
    await check("07.10", "null for a required param -> Missing required parameter", () =>
      expectInvalid("null required", "get_user_by_id", { user_id: null }, /Missing required parameter 'user_id'/));
    await check("07.11", "missing required param -> INVALID_ARGUMENT naming the param and type", () =>
      expectInvalid("missing", "get_user_by_id", {}, /Missing required parameter 'user_id' \(type Integer\)/));
    await check("07.12", "extra unknown argument {user_id:1, evil:1} is rejected", () =>
      expectInvalid("unknown arg", "get_user_by_id", { user_id: 1, evil: 1 }, /Unknown argument 'evil'/));
    await check("07.13", "integer beyond i64 range (1e20) is rejected", () =>
      expectInvalid("i64 overflow", "get_user_by_id", { user_id: 99999999999999999999 }, /expected type Integer/));
    await check("07.14", "negative integer is a valid integer (0 rows, no error)", async () => {
      const p = ok(await S.named("get_user_by_id", { user_id: -1 }), "negative");
      assert.equal(p.returned_rows, 0);
    });
    await check("07.15", "string param given integer is rejected", () =>
      expectInvalid("int->str", "list_orders_by_status", { status: 123 }, /expected type String, got integer/));
    await check("07.16", "unknown tool_name -> INVALID_ARGUMENT 'not registered'", () =>
      expectInvalid("unknown tool", "does_not_exist", {}, /not registered/));
    await check("07.17", "missing tool_name -> INVALID_ARGUMENT", async () => {
      denied(await S.call("run_named_tool", { arguments: {} }), "INVALID_ARGUMENT", "no tool_name");
    });
    await check("07.18", "all five param types accept valid values and bind (json object -> serialized text)", async () => {
      const p = ok(await S.named("t_types", { i: 7, s: "x", f: 1.5, b: true, j: { a: [1, 2] } }), "t_types");
      assert.deepEqual(p.rows[0].slice(0, 3), [7, "x", 1.5]);
      assert.ok(p.rows[0][3] === 1 || p.rows[0][3] === true, `boolean bound as ${p.rows[0][3]}`);
      assert.equal(JSON.stringify(JSON.parse(p.rows[0][4])), JSON.stringify({ a: [1, 2] }));
    });
    await check("07.19", "float param accepts an integer literal; json param accepts an array", async () => {
      const p = ok(await S.named("t_types", { i: 1, s: "x", f: 2, b: false, j: [1] }), "t_types int-as-float");
      assert.equal(p.rows[0][2], 2);
      assert.equal(JSON.parse(p.rows[0][4])[0], 1);
    });
    await check("07.20", "float param rejects string \"1.5\"", () =>
      expectInvalid("str->float", "t_types", { i: 1, s: "x", f: "1.5", b: true, j: 1 }, /'f'.*expected type Float, got string/));
    await check("07.21", "boolean param rejects string \"true\" and integer 1", async () => {
      await expectInvalid("str->bool", "t_types", { i: 1, s: "x", f: 1.5, b: "true", j: 1 }, /'b'.*expected type Boolean, got string/);
      await expectInvalid("int->bool", "t_types", { i: 1, s: "x", f: 1.5, b: 1, j: 1 }, /'b'.*expected type Boolean, got integer/);
    });
    await check("07.22", "json param: null counts as missing for a required param", () =>
      expectInvalid("null json", "t_types", { i: 1, s: "x", f: 1.5, b: true, j: null }, /Missing required parameter 'j'/));
    await check("07.23", "non-object `arguments` (array) is rejected as INVALID_ARGUMENT", async () => {
      // KNOWN-BUG: NT-05 - crates/db-mcp-mcp/src/lib.rs run_named_tool arm does `.as_object()...unwrap_or_default()`,
      // silently treating a non-object `arguments` as {} (NamedToolInvocation::from_json_args would reject it).
      const p = await S.named("t_all_defaults", [1]);
      denied(p, "INVALID_ARGUMENT", "array arguments");
      assert.match(p.message, /object/i);
    });

    // ---------------- 3. zero interpolation ------------------------------------------------
    await check("07.24", "SQLi string `' OR 1=1 --` bound literally -> 0 rows (not all rows)", async () => {
      const p = ok(await S.named("t_inject", { email: "' OR 1=1 --" }), "sqli");
      assert.equal(p.returned_rows, 0);
    });
    await check("07.25", "SQLi strings with `; DROP TABLE users` bound literally; users table still intact", async () => {
      ok(await S.named("t_inject", { email: "1; DROP TABLE users" }), "drop1");
      ok(await S.named("t_inject", { email: "x'); DROP TABLE users; --" }), "drop2");
      const q = ok(await S.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) FROM users" }), "count users");
      assert.equal(q.rows[0][0], 2);
      const legit = ok(await S.named("t_inject", { email: "alice@example.com" }), "legit");
      assert.equal(legit.returned_rows, 1);
    });

    // ---------------- 5. policy interplay --------------------------------------------------
    await check("07.26", "read_only=false INSERT tool on local-sqlite (Development) executes and persists", async () => {
      ok(await S.named("t_write_dev", { order_id: 101, event_type: "NT_TEST", created_at: "2026-01-01T00:00:00Z" }), "insert");
      const q = ok(await S.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) FROM audit_logs WHERE event_type = 'NT_TEST'" }), "count");
      assert.equal(q.rows[0][0], 1);
    });
    await check("07.27", "same INSERT tool on analytics-mysql (ReadOnly) -> MUTATION_NOT_ALLOWED_IN_READ_ONLY", async () => {
      const p = denied(await S.named("t_write_mysql", { order_id: 101, event_type: "NT_TEST", created_at: "x" }), "MUTATION_NOT_ALLOWED_IN_READ_ONLY", "mysql write");
      assert.equal(p.next_action, "propose_change");
    });
    await check("07.28", "tool selecting password_hash -> column flagged redacted and cell masked", async () => {
      const p = ok(await S.named("t_hash", { user_id: 1 }), "t_hash");
      const col = p.columns.find((c) => c.name === "password_hash");
      assert.equal(col.redacted, true);
      assert.equal(p.rows[0][1], "[REDACTED]");
      assert.ok(p.warnings.some((w) => /redact/i.test(w)));
    });
    await check("07.29", "SELECT * via named tool still redacts password_hash", async () => {
      const p = ok(await S.named("t_inject", { email: "alice@example.com" }), "star");
      const idx = p.columns.findIndex((c) => c.name === "password_hash");
      assert.ok(idx >= 0);
      assert.equal(p.columns[idx].redacted, true);
      assert.equal(p.rows[0][idx], "[REDACTED]");
    });
    await check("07.30", "curated tool on restricted table internal_secrets is ALLOWED (named tools bypass the restricted-table guard by design)", async () => {
      // DESIGN-NOTE: db-mcp-policy/src/lib.rs:573 skips the restricted-table check when is_named_tool=true and every
      // restricted-table denial points to next_action="run_named_tool". There is no config-time warning for this.
      const p = ok(await S.named("t_secrets", {}), "t_secrets");
      assert.deepEqual(p.columns.map((c) => c.name), ["secret_key"]);
    });

    // ---------------- 7. GovernedProduction ------------------------------------------------
    await check("07.31", "read tool on prod-postgres (GovernedProduction, simulated) works", async () => {
      const p = ok(await S.named("t_pg_read", { order_id: 101 }), "pg read");
      assert.equal(p.connection, "prod-postgres");
      assert.deepEqual(p.rows[0], [101, "completed"]);
    });
    await check("07.32", "write tool on prod-postgres -> APPROVAL_REQUIRED, next_action=propose_change", async () => {
      const p = denied(await S.named("t_pg_write", { status: "x", order_id: 101 }), "APPROVAL_REQUIRED", "pg write");
      assert.equal(p.next_action, "propose_change");
      const q = ok(await S.named("t_pg_read", { order_id: 101 }), "pg read after");
      assert.equal(q.rows[0][1], "completed", "row must be unchanged");
    });

    // ---------------- 8. timeout -----------------------------------------------------------
    await check("07.33", "timeout_ms=1 recursive CTE -> EXECUTION_TIMEOUT (retryable) and server healthy afterwards", async () => {
      const t0 = Date.now();
      const p = denied(await S.named("t_slow", {}), "EXECUTION_TIMEOUT", "t_slow");
      assert.ok(Date.now() - t0 < 10000, "timeout must fire promptly");
      assert.equal(p.retryable, true);
      const q = ok(await S.named("get_user_by_id", { user_id: 2 }), "after timeout");
      assert.equal(q.rows[0][1], "bob@example.com");
    });

    // ---------------- 6b. statement/param mismatch at call time ----------------------------
    await check("07.34", "statement referencing ?2 with one declared param fails at call time with ADAPTER_ERROR (config accepted it)", async () => {
      const p = denied(await S.named("t_two_placeholders", { id: 101 }), "ADAPTER_ERROR", "?2");
      assert.match(p.message, /parameters/i);
    });
    await check("07.35", "declared-but-unused param fails at call time with ADAPTER_ERROR (config accepted it)", async () => {
      denied(await S.named("t_unused_param", { id: 101, extra: "x" }), "ADAPTER_ERROR", "unused");
    });

    // ---------------- 6c. discovery --------------------------------------------------------
    await check("07.36", "tools/list exposes exactly 16 MCP tools; named tools are not separate MCP tools", async () => {
      const resp = await S.rpc("tools/list", {});
      const names = resp.result.tools.map((t) => t.name);
      assert.equal(names.length, 16, names.join(","));
      assert.ok(names.includes("run_named_tool"));
      for (const n of ["get_user_by_id", "list_orders_by_status", "t_max1"]) assert.ok(!names.includes(n), `${n} leaked into tools/list`);
      const def = resp.result.tools.find((t) => t.name === "run_named_tool");
      assert.deepEqual(def.inputSchema.required, ["tool_name"]);
      assert.equal(def.inputSchema.properties.arguments.type, "object");
    });
    await check("07.37", "no discovery surface for named tools (documented gap): unknown-tool error does not list registered tools", async () => {
      const p = denied(await S.named("zzz_nope", {}), "INVALID_ARGUMENT", "discovery");
      assert.ok(!/get_user_by_id/.test(p.message), "error unexpectedly lists tools (update this check if discovery is added)");
      const init = await S.rpc("resources/list", {});
      assert.deepEqual(init.result.resources, []);
      return "GAP: NamedToolRegistry::list_for_caller exists but is not wired to any MCP surface";
    });
  } finally {
    S.close();
  }

  // ---------------- 4. role gating ---------------------------------------------------------
  const I = await openSession(CFG, "intern");
  try {
    await check("07.38", "role intern excluded by allowed_roles -> UNAUTHORIZED with clear message", async () => {
      const p = denied(await I.named("get_user_by_id", { user_id: 1 }), "UNAUTHORIZED", "intern");
      assert.match(p.message, /role 'intern' is not in allowed_roles/);
      assert.match(p.message, /get_user_by_id/);
    });
    await check("07.39", "allowed_roles=[\"*\"] admits intern", async () => {
      ok(await I.named("t_max1", {}), "star roles");
    });
    await check("07.40", "allowed_roles omitted (empty) admits anyone", async () => {
      ok(await I.named("t_noroles", {}), "no roles");
    });
    await check("07.41", "connection allowed_roles wins over tool allowed_roles=[\"*\"] (prod-postgres excludes intern -> UNAUTHORIZED_ROLE)", async () => {
      const p = denied(await I.named("t_pg_read", { order_id: 101 }), "UNAUTHORIZED_ROLE", "conn gate");
      assert.match(p.message, /prod-postgres/);
    });
    await check("07.42", "role denial is reported before argument validation (bad args + bad role -> UNAUTHORIZED)", async () => {
      denied(await I.named("get_user_by_id", { user_id: "x" }), "UNAUTHORIZED", "order");
    });
  } finally {
    I.close();
  }
  const A = await openSession(CFG, "admin", "release-admin");
  try {
    await check("07.43", "role admin is admitted by the example tools", async () => {
      ok(await A.named("get_user_by_id", { user_id: 1 }), "admin");
    });
    await check("07.44", "denied envelopes carry a next_action hint for INVALID_ARGUMENT / UNAUTHORIZED", async () => {
      // KNOWN-BUG: NT-04 - DbMcpError::next_action() returns None for InvalidArgument/Unauthorized, so run_named_tool
      // denials have next_action=null while every policy denial carries one (scripts/feature-smoke.js deniedWith() requires it).
      const p = denied(await A.named("get_user_by_id", { user_id: "1" }), "INVALID_ARGUMENT", "next_action");
      assert.equal(typeof p.next_action, "string", `next_action=${JSON.stringify(p.next_action)}`);
    });
  } finally {
    A.close();
  }

  // ---------------- 9. audit ---------------------------------------------------------------
  await new Promise((r) => setTimeout(r, 500));
  const auditEvents = fs.existsSync(auditPath)
    ? fs.readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    : [];
  await check("07.45", "audit.jsonl records executed named-tool calls with tool_name=run_named_tool:<name>, role, decision", async () => {
    assert.ok(auditEvents.length > 0, "no audit events written");
    const byTool = (n) => auditEvents.filter((e) => e.tool_name === `run_named_tool:${n}`);
    assert.ok(byTool("get_user_by_id").some((e) => e.decision === "allowed" && e.role === "agent"));
    assert.ok(byTool("get_user_by_id").some((e) => e.decision === "allowed" && e.role === "admin"));
    assert.ok(byTool("t_write_mysql").some((e) => e.decision === "denied" && e.denial_code === "MUTATION_NOT_ALLOWED_IN_READ_ONLY"));
    assert.ok(byTool("t_pg_write").some((e) => e.decision === "requires_approval"));
    assert.ok(byTool("t_slow").some((e) => e.denial_code === "EXECUTION_TIMEOUT"));
    assert.ok(byTool("t_max1").some((e) => e.truncated === true && e.returned_rows === 1));
    return `${auditEvents.length} events`;
  });
  await check("07.46", "audit never contains raw bound parameter values (SQLi payload / emails) and SQL is normalized", async () => {
    const blob = JSON.stringify(auditEvents);
    assert.ok(!blob.includes("OR 1=1"), "SQLi payload leaked into audit");
    assert.ok(!blob.includes("alice@example.com"), "bound email leaked into audit");
    const ev = auditEvents.find((e) => e.tool_name === "run_named_tool:get_user_by_id");
    assert.match(ev.normalized_sql, /WHERE id = \?/);
    assert.equal(typeof ev.sql_hash, "string");
    return "GAP: AuditEvent has no params field at all (sanitize_audit_parameters is unused), so 'redacted params' are simply absent";
  });
  await check("07.47", "pre-execution denials (type/role/unknown-tool) of run_named_tool are audited", async () => {
    // KNOWN-BUG: NT-03 - crates/db-mcp-mcp/src/lib.rs:577-596 returns `?` errors from named_tools.get()/get_authorized_adapter()/
    // validate_and_bind() before execute_governed() is reached, so these denials never produce an AuditEvent.
    const internDenied = auditEvents.filter((e) => e.role === "intern" && e.decision !== "allowed");
    assert.ok(internDenied.length >= 2, `expected audited intern denials, found ${internDenied.length}`);
    const invalid = auditEvents.filter((e) => e.denial_code === "INVALID_ARGUMENT" || e.denial_code === "UNAUTHORIZED");
    assert.ok(invalid.length >= 10, `expected audited INVALID_ARGUMENT/UNAUTHORIZED denials, found ${invalid.length}`);
  });

  // ---------------- 6. config robustness (verify-config) -----------------------------------
  const vcDir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f07-vc-"));
  const vcCase = (key, toml) => isoConfig(toml, { dir: path.join(vcDir, key) }).configPath;
  const tool = (body) => `\n[[named_tools]]\n${body}\n`;
  const expectReject = (label, file, re) => {
    const r = verifyConfig(file);
    assert.notEqual(r.status, 0, `${label}: verify-config accepted an invalid config: ${r.stdout}`);
    if (re) assert.match(r.stderr, re, `${label}: stderr ${r.stderr}`);
    return r.stderr.trim().split("\n")[0].slice(0, 160);
  };
  await check("07.48", "verify-config rejects a named tool referencing an unknown connection", () =>
    expectReject("unknown conn", vcCase("unknown_conn", tool(`name="x"\ndescription="a"\nconnection="nope"\nstatement="SELECT 1"`)), /unknown connection 'nope'/));
  await check("07.49", "verify-config rejects an invalid param_type", () =>
    expectReject("bad type", vcCase("bad_type", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT ?1"\n[[named_tools.parameters]]\nname="p"\nparam_type="decimal"\ndescription="d"`)), /unknown variant `decimal`/));
  await check("07.50", "verify-config rejects a tool with no statement / blank statement / empty name", () => {
    expectReject("missing statement", vcCase("missing_stmt", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"`)), /missing field `statement`/);
    expectReject("blank statement", vcCase("blank_stmt", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="  "`)), /non-empty SQL statement/);
    expectReject("empty name", vcCase("empty_name", tool(`name=""\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT 1"`)), /name must not be empty/);
  });
  await check("07.51", "verify-config rejects read_only=true tool whose statement is an UPDATE (rejected at load, not call time)", () =>
    expectReject("ro update", vcCase("ro_update", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="UPDATE orders SET status = ?1 WHERE id = ?2"\nread_only=true\n[[named_tools.parameters]]\nname="s"\nparam_type="string"\ndescription="d"\n[[named_tools.parameters]]\nname="i"\nparam_type="integer"\ndescription="d"`)), /read_only=true but statement is classified as 'write'/));
  await check("07.52", "read_only defaults to true: a DELETE tool without read_only is rejected", () =>
    expectReject("ro default", vcCase("ro_default", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="DELETE FROM orders WHERE id = ?1"\n[[named_tools.parameters]]\nname="i"\nparam_type="integer"\ndescription="d"`)), /read_only=true/));
  await check("07.53", "verify-config rejects multi-statement and privileged-function statements", () => {
    expectReject("multi", vcCase("multi", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT 1; SELECT 2"`)), /single SQL statement/);
    expectReject("priv", vcCase("priv", tool(`name="x"\ndescription="a"\nconnection="prod-postgres"\nstatement="SELECT pg_read_file($1)"\n[[named_tools.parameters]]\nname="p"\nparam_type="string"\ndescription="d"`)), /privileged function/);
  });
  await check("07.54", "verify-config rejects a default_value whose type does not match param_type", () =>
    expectReject("bad default", vcCase("bad_default", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT ?1"\n[[named_tools.parameters]]\nname="p"\nparam_type="integer"\ndescription="d"\nrequired=false\ndefault_value="zero"`)), /expected type Integer, got string/));
  await check("07.55", "verify-config rejects duplicate named-tool names", () => {
    // KNOWN-BUG: NT-01 - NamedToolRegistry::register (crates/db-mcp-tools/src/lib.rs:236) does BTreeMap::insert, so a
    // duplicate silently replaces the earlier definition (last one wins, confirmed at call time) instead of failing.
    const dup = tool(`name="dup"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT 1 AS a"`) + tool(`name="dup"\ndescription="b"\nconnection="local-sqlite"\nstatement="SELECT 2 AS b"`);
    return expectReject("dup", vcCase("dup", dup), /duplicate/i);
  });
  await check("07.56", "verify-config rejects a statement referencing ?2 with only one declared parameter", () => {
    // KNOWN-BUG: NT-02 - no placeholder/parameter arity check at registration (crates/db-mcp-tools/src/lib.rs:178-238);
    // the mismatch only surfaces at call time as ADAPTER_ERROR (see 07.34/07.35).
    return expectReject("?2", vcCase("ph_mismatch", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT ?1, ?2"\n[[named_tools.parameters]]\nname="p"\nparam_type="integer"\ndescription="d"`)), /parameter/i);
  });
  await check("07.57", "verify-config rejects a declared parameter that the statement never references", () => {
    // KNOWN-BUG: NT-02 (same root cause as 07.56)
    return expectReject("unused", vcCase("unused_param", tool(`name="x"\ndescription="a"\nconnection="local-sqlite"\nstatement="SELECT ?1"\n[[named_tools.parameters]]\nname="p"\nparam_type="integer"\ndescription="d"\n[[named_tools.parameters]]\nname="q"\nparam_type="integer"\ndescription="d"`)), /parameter/i);
  });

  // ---------------- 6d. YAML / JSON variants -----------------------------------------------
  const fmtDir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f07-fmt-"));
  const cfgObj = minimalConfigObject(fmtDir);
  const jsonPath = path.join(fmtDir, "cfg.json");
  const yamlPath = path.join(fmtDir, "cfg.yaml");
  const ymlPath = path.join(fmtDir, "cfg.yml");
  fs.writeFileSync(jsonPath, JSON.stringify(cfgObj, null, 2));
  fs.writeFileSync(yamlPath, toYaml(cfgObj));
  fs.writeFileSync(ymlPath, toYaml(cfgObj));
  await check("07.58", "verify-config validates the same config as .json, .yaml and .yml (named_tools=2)", () => {
    for (const p of [jsonPath, yamlPath, ymlPath]) {
      const r = verifyConfig(p);
      assert.equal(r.status, 0, `${path.basename(p)}: ${r.stderr}`);
      assert.equal(r.summary.named_tools, 2, path.basename(p));
      assert.equal(r.summary.connections, 1, path.basename(p));
    }
  });
  await check("07.59", "JSON and YAML configs serve run_named_tool identically (typed params, defaults, role gate)", async () => {
    const outcomes = [];
    for (const p of [jsonPath, yamlPath]) {
      const sess = await openSession(p, "agent");
      try {
        const a = ok(await sess.named("get_user_by_id", { user_id: 2 }), `${path.basename(p)} get_user_by_id`);
        const b = ok(await sess.named("list_users"), `${path.basename(p)} list_users`);
        const c = denied(await sess.named("get_user_by_id", { user_id: "2" }), "INVALID_ARGUMENT", `${path.basename(p)} strict`);
        outcomes.push(JSON.stringify([a.rows, b.rows, c.code]));
      } finally { sess.close(); }
      const intern = await openSession(p, "intern");
      try {
        denied(await intern.named("get_user_by_id", { user_id: 2 }), "UNAUTHORIZED", `${path.basename(p)} intern`);
      } finally { intern.close(); }
    }
    assert.equal(outcomes[0], outcomes[1], "JSON and YAML servers diverged");
    assert.equal(outcomes[0], JSON.stringify([[[2, "bob@example.com"]], [[1, "alice@example.com"], [2, "bob@example.com"]], "INVALID_ARGUMENT"]));
  });

  // ---------------- summary ----------------------------------------------------------------
  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  console.log(`\nF07 summary: ${passed} passed, ${failed} failed, ${results.length} total`);
  if (failed) {
    for (const r of results.filter((r) => !r.ok)) console.log(`  FAILED ${r.id} ${r.name}`);
  }
  await new Promise((r) => setTimeout(r, 400));
  killAll();
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error("F07 harness error:", err);
  killAll();
  process.exit(1);
});
