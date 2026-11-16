#!/usr/bin/env node
"use strict";
/**
 * F13 - Configuration loading, secret handling and identity/policy enforcement.
 *
 * Self-contained verification script (node:assert only). Run from the repo root:
 *   node npm/test/features/13-config-secrets-policy.test.js
 *
 * Every check prints one line. Assertions encode the CORRECT behaviour; checks that currently fail
 * because of a known defect are tagged `// KNOWN-BUG: <id>` and reported as XFAIL (they do not fail
 * the run, but an unexpected pass is reported as XPASS so a fix is noticed). Exit code 0 when no
 * untagged check fails. All servers run against private copies of the config templates in a temp dir.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
const { makeIsolatedConfig } = require(path.join(REPO, "scripts", "make-isolated-config.js"));
const { resolveBinaryPath } = require(path.join(REPO, "npm", "bin", "db-mcp.js"));
const BIN = resolveBinaryPath({ autoBuild: false, preferRelease: true });
const PKG = JSON.parse(fs.readFileSync(path.join(REPO, "package.json"), "utf8"));
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f13-"));
const posix = (p) => p.replace(/\\/g, "/");
const children = new Set();

// ---------------------------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------------------------
const stats = { pass: 0, fail: 0, xfail: 0, xpass: 0 };
const failures = [];
async function check(name, fn, knownBug) {
  let err = null;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  if (!err) {
    if (knownBug) {
      stats.xpass++;
      console.log(`XPASS ${name}  (tagged ${knownBug} but passed - bug fixed?)`);
    } else {
      stats.pass++;
      console.log(`PASS  ${name}`);
    }
    return;
  }
  const msg = String(err && err.message ? err.message : err).split("\n")[0].slice(0, 220);
  if (knownBug) {
    stats.xfail++;
    console.log(`XFAIL ${name}  [${knownBug}] ${msg}`);
  } else {
    stats.fail++;
    failures.push(name);
    console.log(`FAIL  ${name}  ${msg}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------------------------
function runBin(args, opts = {}) {
  const env = { ...process.env, ...(opts.env || {}) };
  for (const k of opts.unsetEnv || []) delete env[k];
  const r = spawnSync(BIN, args, { encoding: "utf8", cwd: opts.cwd || REPO, env, input: opts.input === undefined ? "" : opts.input, timeout: opts.timeout || 30000, windowsHide: true });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "", out: (r.stdout || "") + (r.stderr || "") };
}
function verify(file) {
  return runBin(["verify-config", "--config", file]);
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function startStdio({ config, principal = "local-agent", role = "agent", env = {}, unsetEnv = [], cwd = REPO }) {
  const args = ["serve", "--transport", "stdio", "--principal", principal, "--role", role];
  if (config) args.push("--config", config);
  const fullEnv = { ...process.env, ...env };
  for (const k of unsetEnv) delete fullEnv[k];
  const child = spawn(BIN, args, { cwd, env: fullEnv, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  children.add(child);
  const stderr = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  const pending = new Map();
  let nextId = 1;
  const rl = readline.createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    let m;
    try { m = JSON.parse(line); } catch { return; }
    if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  });
  const exited = new Promise((r) => child.on("exit", (code) => { children.delete(child); r(code); }));
  const rpc = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const t = setTimeout(() => { pending.delete(id); reject(new Error(`timeout ${method}; stderr=${stderr.join("").slice(0, 300)}`)); }, 20000);
    pending.set(id, (m) => { clearTimeout(t); resolve(m); });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
  const call = async (name, args = {}) => {
    const r = await rpc("tools/call", { name, arguments: args });
    if (r.error) return { status: "rpc_error", code: r.error.code, message: r.error.message };
    return r.result.structuredContent !== undefined ? r.result.structuredContent : r.result;
  };
  const close = async () => {
    try { child.stdin.end(); } catch { /* ignore */ }
    const t = setTimeout(() => { try { child.kill(); } catch { /* ignore */ } }, 500);
    await exited;
    clearTimeout(t);
  };
  return { child, rpc, call, close, stderr, exited };
}
async function withServer(opts, fn) {
  const s = startStdio(opts);
  try {
    const init = await s.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "f13", version: "0" } });
    assert.ok(init.result, `initialize failed: ${JSON.stringify(init.error)}`);
    s.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }) + "\n");
    return await fn(s);
  } finally {
    await s.close();
  }
}
function postJson(port, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ host: "127.0.0.1", port, path: p, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...headers } }, (res) => {
      let b = "";
      res.on("data", (x) => { b += x; });
      res.on("end", () => { let parsed; try { parsed = JSON.parse(b); } catch { parsed = b; } resolve({ status: res.statusCode, body: parsed }); });
    });
    req.on("error", reject);
    req.end(data);
  });
}
async function startHttp({ config, env = {}, unsetEnv = [], port }) {
  const fullEnv = { ...process.env, ...env };
  for (const k of unsetEnv) delete fullEnv[k];
  const child = spawn(BIN, ["serve", "--transport", "http", "--config", config], { cwd: REPO, env: fullEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  children.add(child);
  const stderr = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  child.on("exit", () => children.delete(child));
  for (let i = 0; i < 80; i++) {
    try {
      await new Promise((res, rej) => http.get({ host: "127.0.0.1", port, path: "/health" }, (r) => { r.resume(); res(); }).on("error", rej));
      return { child, stderr, stop: async () => { child.kill(); await sleep(400); } };
    } catch { await sleep(150); }
  }
  child.kill();
  throw new Error(`http server did not come up: ${stderr.join("")}`);
}
function dirContains(dir, needle) {
  const hits = [];
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (fs.statSync(p).isFile() && fs.readFileSync(p).includes(needle)) hits.push(f);
  }
  return hits;
}
function writeCfg(name, text) {
  const p = path.join(TMP, name);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, text);
  return p;
}
const MIN_CONN = (extra = "") => `[[connections]]
id = "c1"
engine = "Sqlite"
dsn = "sqlite://:memory:"
mode = "Development"
init_sql = "CREATE TABLE t(a INT);"
${extra}`;
const MIN = (extra = "", head = "") => `server_name = "t"
default_mode = "ReadOnly"
${head}${MIN_CONN(extra)}`;
const INSERT_USER = "INSERT INTO users (id,email,role,password_hash,created_at) VALUES (77,'x@y','customer','h','2025')";
const rows = (r) => (r && r.rows) || null;

// =============================================================================================
async function main() {
  console.log(`F13 config/secrets/policy  binary=${BIN}  tmp=${TMP}`);

  // -------------------------------------------------------------------------------------------
  // 7. CLI UX (cheap, first)
  // -------------------------------------------------------------------------------------------
  await check("cli: --version prints the package.json version", () => {
    const r = runBin(["--version"]);
    assert.equal(r.status, 0);
    assert.equal(r.stdout.trim(), `db-mcp-server ${PKG.version}`);
  });
  await check("cli: --help lists serve/approve/verify-config", () => {
    const r = runBin(["--help"]);
    assert.equal(r.status, 0);
    for (const s of ["serve", "approve", "verify-config"]) assert.ok(r.stdout.includes(s), s);
  });
  await check("cli: unknown subcommand exits 2 with usage", () => {
    const r = runBin(["frobnicate"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /unrecognized subcommand 'frobnicate'/);
  });
  await check("cli: unknown flag exits 2", () => {
    const r = runBin(["serve", "--bogus"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /unexpected argument '--bogus'/);
  });
  await check("cli: verify-config without --config is a usage error (exit 2)", () => {
    const r = runBin(["verify-config"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--config <CONFIG>/);
  });
  await check("cli: serve --transport grpc rejected with clear error (exit 1)", () => {
    const r = runBin(["serve", "--transport", "grpc", "--config", writeCfg("grpc.toml", MIN())]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Unsupported transport 'grpc' \(expected 'stdio' or 'http'\)/);
  });
  await check("cli: serve --transport http --bind malformed exits 1 with socket error", () => {
    const r = runBin(["serve", "--transport", "http", "--bind", "not-an-addr", "--config", writeCfg("bind.toml", MIN())]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /invalid socket address/);
  });

  // -------------------------------------------------------------------------------------------
  // 1. verify-config / ServerConfig::from_file
  // -------------------------------------------------------------------------------------------
  await check("verify: shipped example config validates with expected summary fields", () => {
    const r = verify(path.join(REPO, "config", "db-mcp.example.toml"));
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    assert.equal(j.status, "ok");
    assert.equal(j.connections, 3);
    assert.equal(j.named_tools, 2);
    assert.equal(j.default_mode, "read_only");
    assert.deepEqual(j.active_profiles, ["explore", "query", "diagnose", "change", "schema", "ontology"]);
    for (const k of ["config_path", "server_name", "server_version"]) assert.ok(k in j, k);
  });
  await check("verify: shipped starter config (db-mcp init template) validates", () => {
    // The starter references env:DATABASE_URL / env:MYSQL_URL; unset variables are an error (F13-B2), so supply them.
    assert.equal(verify(path.join(REPO, "config", "db-mcp.starter.toml")).status, 1, "starter must demand its env vars");
    const r = runBin(["verify-config", "--config", path.join(REPO, "config", "db-mcp.starter.toml")], { env: { DATABASE_URL: "postgres://127.0.0.1:1/x", MYSQL_URL: "mysql://127.0.0.1:1/x" } });
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    assert.equal(j.connections, 3);
    assert.equal(j.named_tools, 1);
  });
  const okJson = JSON.stringify({ server_name: "t", default_mode: "ReadOnly", connections: [{ id: "c1", engine: "Sqlite", dsn: "sqlite://:memory:", mode: "Development", init_sql: "CREATE TABLE t(a INT);" }], named_tools: [{ name: "t1", description: "a", connection: "c1", statement: "SELECT 1 AS one" }] });
  const okYaml = `server_name: t\ndefault_mode: ReadOnly\nconnections:\n  - id: c1\n    engine: Sqlite\n    dsn: "sqlite://:memory:"\n    mode: Development\n    init_sql: "CREATE TABLE t(a INT);"\nnamed_tools:\n  - name: t1\n    description: a\n    connection: c1\n    statement: "SELECT 1 AS one"\n`;
  await check("verify: .json accepted", () => assert.equal(verify(writeCfg("ok.json", okJson)).status, 0));
  await check("verify: .yaml accepted", () => assert.equal(verify(writeCfg("ok.yaml", okYaml)).status, 0));
  await check("verify: .yml accepted", () => assert.equal(verify(writeCfg("ok.yml", okYaml)).status, 0));
  await check("verify: .TOML (uppercase ext) accepted", () => assert.equal(verify(writeCfg("ok.TOML", MIN())).status, 0));
  await check("verify: .conf and no extension are parsed as TOML", () => {
    assert.equal(verify(writeCfg("ok.conf", MIN())).status, 0);
    assert.equal(verify(writeCfg("ok_noext", MIN())).status, 0);
    const r = verify(writeCfg("yaml.conf", okYaml));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Invalid TOML config/);
  });
  await check("verify: wrong content for extension fails with format-specific message", () => {
    const a = verify(writeCfg("json_in.toml", okJson));
    assert.equal(a.status, 1); assert.match(a.stderr, /Invalid TOML config/);
    const b = verify(writeCfg("toml_in.json", MIN()));
    assert.equal(b.status, 1); assert.match(b.stderr, /Invalid JSON config/);
    const c = verify(writeCfg("yaml_in.toml", okYaml));
    assert.equal(c.status, 1); assert.match(c.stderr, /Invalid TOML config/);
  });
  await check("verify: unknown engine rejected naming the engine", () => {
    const r = verify(writeCfg("engine.toml", MIN().replace('"Sqlite"', '"Oracle"')));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Unsupported database engine 'oracle'/);
  });
  await check("verify: engine/mode aliases accepted (sqlite3, read-only, dev, prod)", () => {
    const t = MIN().replace('"Sqlite"', '"sqlite3"').replace('"ReadOnly"', '"read-only"').replace('"Development"', '"dev"');
    assert.equal(verify(writeCfg("alias.toml", t)).status, 0);
    assert.equal(verify(writeCfg("alias2.toml", MIN().replace('"Development"', '"prod"'))).status, 0);
  });
  await check("verify: missing dsn rejected", () => {
    const r = verify(writeCfg("nodsn.toml", MIN().replace(/dsn = .*\n/, "")));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing field `dsn`/);
  });
  await check("verify: missing id rejected", () => {
    const r = verify(writeCfg("noid.toml", MIN().replace(/id = "c1"\n/, "")));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing field `id`/);
  });
  await check("verify: empty dsn / empty id / empty server_name rejected", () => {
    assert.match(verify(writeCfg("edsn.toml", MIN().replace('"sqlite://:memory:"', '"  "'))).stderr, /has an empty dsn/);
    assert.match(verify(writeCfg("eid.toml", MIN().replace('id = "c1"', 'id = " "'))).stderr, /Connection id must not be empty/);
    assert.match(verify(writeCfg("ename.toml", MIN().replace('server_name = "t"', 'server_name = " "'))).stderr, /server_name must not be empty/);
  });
  await check("verify: duplicate connection ids rejected", () => {
    const r = verify(writeCfg("dupid.toml", MIN() + "\n" + MIN_CONN()));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Duplicate connection id 'c1'/);
  });
  await check("verify: named tool referencing unknown connection rejected", () => {
    const r = verify(writeCfg("ghost.toml", MIN() + `[[named_tools]]\nname = "t1"\ndescription = "a"\nconnection = "nope"\nstatement = "SELECT 1"\n`));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Named tool 't1' references unknown connection 'nope'/);
  });
  await check("verify: named tool referencing unknown connection rejected even when connections list is empty", () => {
    const r = verify(writeCfg("ghost0.toml", `server_name = "t"\n[[named_tools]]\nname = "t1"\ndescription = "a"\nconnection = "ghost"\nstatement = "SELECT 1"\n`));
    assert.equal(r.status, 1, "verify accepted a tool bound to a connection that cannot exist");
  });
  await check("verify: duplicate named tool names rejected", () => {
    const two = `[[named_tools]]\nname = "dup"\ndescription = "a"\nconnection = "c1"\nstatement = "SELECT 1 AS first"\n[[named_tools]]\nname = "dup"\ndescription = "b"\nconnection = "c1"\nstatement = "SELECT 2 AS second"\n`;
    const r = verify(writeCfg("duptool.toml", MIN() + two));
    assert.equal(r.status, 1, "two named tools with the same name were accepted");
  });
  await check("verify: unknown connection field (typo max_row) rejected", () => {
    const r = verify(writeCfg("typo1.toml", MIN("max_row = 5\n")));
    assert.equal(r.status, 1, "typo silently ignored");
  });
  await check("verify: security-relevant typo (read_onli = true) rejected", () => {
    const r = verify(writeCfg("typo2.toml", MIN("read_onli = true\n")));
    assert.equal(r.status, 1, "read_onli silently ignored - connection stays writable");
  });
  await check("verify: unknown top-level field (defualt_mode) rejected", () => {
    const r = verify(writeCfg("typo3.toml", MIN().replace("default_mode", "defualt_mode")));
    assert.equal(r.status, 1, "top-level typo silently ignored");
  });
  await check("verify: bad default_mode rejected naming the value", () => {
    const r = verify(writeCfg("mode.toml", MIN().replace('"ReadOnly"', '"YOLO"')));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Unsupported operating mode 'yolo'/);
  });
  await check("verify: invalid profile name rejected naming the value", () => {
    const r = verify(writeCfg("prof.toml", MIN("", 'active_profiles = ["Explore", "Hack"]\n')));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Unsupported tool profile 'hack'/);
  });
  await check("verify: negative max_rows rejected (usize)", () => {
    const r = verify(writeCfg("neg.toml", MIN("max_rows = -1\n")));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /invalid value: integer `-1`, expected usize/);
  });
  await check("verify: zero limits rejected with named connection", () => {
    const r = verify(writeCfg("zero.toml", MIN("timeout_ms = 0\n")));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Connection 'c1' limits must be greater than zero/);
  });
  await check("verify: negative changes.default_ttl_seconds rejected", () => {
    const r = verify(writeCfg("ttl.toml", MIN("", "[changes]\ndefault_ttl_seconds = -5\n")));
    assert.equal(r.status, 1, "negative TTL accepted");
  });
  await check("verify: malformed http.bind rejected at verify time (not only at serve)", () => {
    const r = verify(writeCfg("badbind.toml", MIN("", '[http]\nbind = "not-an-addr"\n')));
    assert.equal(r.status, 1, "bad bind passes verify-config and only fails at serve");
  });
  await check("verify: empty connections list rejected (server would expose no databases)", () => {
    const r = verify(writeCfg("noconn.toml", 'server_name = "t"\nconnections = []\n'));
    assert.equal(r.status, 1, "config with zero connections accepted");
  });
  await check("verify: file not found -> exit 1 naming the path", () => {
    const r = verify(path.join(TMP, "does-not-exist.toml"));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Failed to read config file '.*does-not-exist\.toml'/);
  });
  await check("verify: unreadable path (directory) -> exit 1 with read error", () => {
    const d = path.join(TMP, "adir.toml");
    fs.mkdirSync(d, { recursive: true });
    const r = verify(d);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Failed to read config file/);
  });
  await check("verify: BOM-prefixed UTF-8 TOML accepted", () => assert.equal(verify(writeCfg("bom.toml", "﻿" + MIN())).status, 0));
  await check("verify: BOM-prefixed JSON/YAML accepted", () => {
    const a = verify(writeCfg("bom.json", "﻿" + okJson));
    const b = verify(writeCfg("bom.yaml", "﻿" + okYaml));
    assert.equal(a.status, 0, `json: ${a.stderr}`);
    assert.equal(b.status, 0, `yaml: ${b.stderr}`);
  });
  await check("verify: CRLF line endings accepted", () => assert.equal(verify(writeCfg("crlf.toml", MIN().replace(/\n/g, "\r\n"))).status, 0));
  await check("verify: 5 MB config parsed", () => {
    const r = verify(writeCfg("big.toml", MIN() + "# " + "x".repeat(5 * 1024 * 1024) + "\n"));
    assert.equal(r.status, 0, r.stderr);
  });
  await check("verify: duplicate/empty active_profiles accepted and echoed", () => {
    const a = JSON.parse(verify(writeCfg("dupprof.toml", MIN("", 'active_profiles = ["Query", "Query"]\n'))).stdout);
    assert.deepEqual(a.active_profiles, ["query", "query"]);
    const b = JSON.parse(verify(writeCfg("noprof.toml", MIN("", "active_profiles = []\n"))).stdout);
    assert.deepEqual(b.active_profiles, []);
  });
  await check("serve: JSON and YAML configs work at runtime, not only in verify", async () => {
    await withServer({ config: path.join(TMP, "ok.json") }, async (s) => {
      const r = await s.call("run_named_tool", { tool_name: "t1" });
      assert.equal(r.status, "ok", JSON.stringify(r));
    });
    await withServer({ config: path.join(TMP, "ok.yaml") }, async (s) => {
      const l = await s.call("list_connections");
      assert.deepEqual(l.data.map((c) => c.id), ["c1"]);
    });
  });

  // -------------------------------------------------------------------------------------------
  // 2. Secrets
  // -------------------------------------------------------------------------------------------
  const SECRET_DSN = "postgres://user:p4ss@127.0.0.1:1/db";
  await check("secrets: env: DSN resolves at startup; p4ss never appears in tool output, stderr(debug) or audit/change files", async () => {
    const { configPath, dir } = makeIsolatedConfig({ dir: path.join(TMP, "sec-env"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', 'dsn = "env:F13_MY_DSN"') });
    const out = await withServer({ config: configPath, env: { F13_MY_DSN: SECRET_DSN, RUST_LOG: "debug" } }, async (s) => {
      const o = {};
      o.list = await s.call("list_connections");
      o.desc = await s.call("describe_object", { connection: "prod-postgres", object_name: "users" });
      o.health = await s.call("database_health", { connection: "prod-postgres" });
      o.query = await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1 AS x" });
      o.explain = await s.call("explain_query", { connection: "prod-postgres", sql: "SELECT * FROM users" });
      o.bad = await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT * FROM no_such_table_zz" });
      o.stderr = s.stderr.join("");
      return o;
    });
    assert.ok(out.list.data.some((c) => c.id === "prod-postgres"), "prod-postgres listed");
    assert.equal(out.query.status, "ok");
    const text = JSON.stringify(out);
    assert.ok(!text.includes("p4ss"), "password leaked in tool output or stderr");
    assert.ok(!text.includes("user:p4ss"), "userinfo leaked");
    await sleep(300);
    assert.deepEqual(dirContains(dir, "p4ss"), [], "password leaked into audit/change files");
    assert.ok(!JSON.stringify(out.list).includes("dsn"), "list_connections must not expose dsn at all");
  });
  await check("secrets: missing env var for env: DSN -> startup/verify error naming the variable (no silent fallback)", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "sec-missing"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', 'dsn = "env:F13_MISSING_DSN_VAR"') });
    const v = verify(configPath);
    const r = runBin(["serve", "--transport", "stdio", "--config", configPath], { unsetEnv: ["F13_MISSING_DSN_VAR"] });
    const combined = v.out + r.out;
    assert.ok(combined.includes("F13_MISSING_DSN_VAR"), "neither verify-config nor serve mentions the missing variable");
    assert.ok(!combined.includes("localhost:3306"), "other DSNs must not be echoed");
  });
  await check("secrets: missing env var -> serve refuses to start, error names the variable only", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "sec-missing2"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', 'dsn = "env:F13_MISSING_DSN_VAR"') });
    const r = runBin(["serve", "--transport", "stdio", "--config", configPath], { unsetEnv: ["F13_MISSING_DSN_VAR"] });
    assert.notEqual(r.status, 0, "serve started with an unresolvable env: DSN");
    assert.match(r.stderr, /F13_MISSING_DSN_VAR/);
    assert.ok(!r.out.includes("localhost:3306"), "other DSNs must not be echoed");
  });
  await check("secrets: file: DSN reference resolves from file (trimmed) as documented in starter config", async () => {
    const secretFile = path.join(TMP, "dsn.secret");
    fs.writeFileSync(secretFile, SECRET_DSN + "\r\n");
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "sec-file"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', `dsn = "file:${posix(secretFile)}"`) });
    const missing = makeIsolatedConfig({ dir: path.join(TMP, "sec-file-missing"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', `dsn = "file:${posix(path.join(TMP, "nope.secret"))}"`) });
    const r = runBin(["serve", "--transport", "stdio", "--config", missing.configPath]);
    assert.notEqual(r.status, 0, "missing secret file must fail startup");
    assert.match(r.stderr, /nope\.secret/);
    const rel = runBin(["serve", "--transport", "stdio", "--config", configPath]);
    assert.equal(rel.status, 0);
  });
  await check("secrets: file: reference never leaks file contents (p4ss) ", async () => {
    const secretFile = path.join(TMP, "dsn2.secret");
    fs.writeFileSync(secretFile, SECRET_DSN + "\n");
    const { configPath, dir } = makeIsolatedConfig({ dir: path.join(TMP, "sec-file2"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', `dsn = "file:${posix(secretFile)}"`) });
    const out = await withServer({ config: configPath }, async (s) => JSON.stringify([await s.call("database_health", { connection: "prod-postgres" }), await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1" })]) + s.stderr.join(""));
    assert.ok(!out.includes("p4ss"));
    assert.deepEqual(dirContains(dir, "p4ss"), []);
  });
  await check("secrets: literal DSN with percent-encoded '@' in password serves and never leaks either form", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "sec-pct"), transform: (t) => t.replace('dsn = "postgres://localhost:5432/app_prod"', 'dsn = "postgres://u:p%40ss@127.0.0.1:1/db"') });
    const out = await withServer({ config: configPath, env: { RUST_LOG: "debug" } }, async (s) => {
      const h = await s.call("database_health", { connection: "prod-postgres" });
      const q = await s.call("execute_query", { connection: "prod-postgres", sql: "SELECT 1 AS x" });
      assert.equal(q.status, "ok");
      return JSON.stringify([h, q]) + s.stderr.join("");
    });
    assert.ok(!out.includes("p%40ss") && !out.includes("p@ss"));
  });
  await check("secrets: env: http tokens -> unset env var must not silently disable bearer auth (refuse to start or warn)", async () => {
    const port = 18400 + Math.floor(Math.random() * 500);
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "http-notok"), transform: (t) => t.replace('bind = "127.0.0.1:8080"', `bind = "127.0.0.1:${port}"`) });
    let srv;
    try {
      srv = await startHttp({ config: configPath, port, unsetEnv: ["DB_MCP_AUTH_TOKEN", "DB_MCP_ADMIN_TOKEN"] });
    } catch (err) {
      // Fail closed: refusing to start on an unresolvable token reference is the correct outcome.
      assert.match(String(err), /could not be resolved/, `server failed to start for an unexpected reason: ${err}`);
      return;
    }
    try {
      const r = await postJson(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_connections", arguments: {} } });
      const a = await postJson(port, "/admin/approve", { change_id: "chg_none", approver: "mallory" });
      const warned = /DB_MCP_AUTH_TOKEN|auth.*disabled|not set/i.test(srv.stderr.join(""));
      assert.ok(r.status === 401 || warned, `unauthenticated /mcp returned ${r.status} with no warning on stderr`);
      assert.ok(a.status === 401 || warned, `unauthenticated /admin/approve reached the handler (${a.status}) with no warning`);
    } finally { await srv.stop(); }
  });
  await check("secrets: sqlite relative DSN path resolves against cwd (not the config file dir); nested dirs are created", async () => {
    const cwd = path.join(TMP, "sq-cwd");
    const cfgDir = path.join(TMP, "sq-cfg");
    fs.mkdirSync(cwd, { recursive: true });
    const cfg = writeCfg("sq-cfg/c.toml", `server_name = "t"\ndefault_mode = "Development"\n[[connections]]\nid = "rel"\nengine = "Sqlite"\ndsn = "sqlite://relsub/deep/x.db"\n`);
    await withServer({ config: cfg, cwd }, async (s) => {
      const q = await s.call("execute_query", { connection: "rel", sql: "SELECT 1 AS one" });
      assert.equal(q.status, "ok");
    });
    assert.ok(fs.existsSync(path.join(cwd, "relsub", "deep", "x.db")), "db created relative to cwd");
    assert.ok(!fs.existsSync(path.join(cfgDir, "relsub")), "not relative to config dir");
  });
  await check("secrets: sqlite://:memory: works and init_sql seeds it", async () => {
    const cfg = writeCfg("mem.toml", MIN().replace('init_sql = "CREATE TABLE t(a INT);"', 'init_sql = "CREATE TABLE t(a INT); INSERT INTO t VALUES (41);"'));
    await withServer({ config: cfg }, async (s) => {
      const q = await s.call("execute_query", { connection: "c1", sql: "SELECT a FROM t" });
      assert.deepEqual(rows(q), [[41]]);
    });
  });

  // -------------------------------------------------------------------------------------------
  // 3. Identity & authorization
  // -------------------------------------------------------------------------------------------
  const authCfg = (name, roles, principals) => {
    const d = path.join(TMP, name);
    fs.mkdirSync(d, { recursive: true });
    const p = writeCfg(`${name}/c.toml`, `server_name = "t"\ndefault_mode = "Development"\n[audit]\njsonl_path = "${posix(path.join(d, "audit.jsonl"))}"\n[[connections]]\nid = "c1"\nengine = "Sqlite"\ndsn = "sqlite://:memory:"\nallowed_roles = ${JSON.stringify(roles)}\nallowed_principals = ${JSON.stringify(principals)}\ninit_sql = "CREATE TABLE t(a INT);"\n[[named_tools]]\nname = "nt"\ndescription = "d"\nconnection = "c1"\nstatement = "SELECT 1 AS one"\n`);
    return { p, d };
  };
  const CONN_TOOLS = [
    ["execute_query", { connection: "c1", sql: "SELECT 1" }],
    ["search_objects", { connection: "c1", query: "t" }],
    ["capture_schema", { connection: "c1" }],
    ["database_health", { connection: "c1" }],
    ["propose_change", { connection: "c1", sql: "INSERT INTO t VALUES (1)" }],
    ["describe_object", { connection: "c1", object_name: "t" }],
    ["explain_query", { connection: "c1", sql: "SELECT 1" }],
    ["run_named_tool", { tool_name: "nt" }],
  ];
  const matrix = async (cfg, principal, role) => withServer({ config: cfg, principal, role }, async (s) => {
    const out = {};
    for (const [n, a] of CONN_TOOLS) {
      const v = await s.call(n, a);
      out[n] = v.status === "ok" ? "ok" : v.code;
    }
    out.list_connections = (await s.call("list_connections")).data.length;
    return out;
  });
  const dbaOnly = authCfg("auth-dba", ["dba"], ["*"]);
  await check("authz: allowed_roles=[dba] -> role agent denied UNAUTHORIZED_ROLE on every connection-taking tool", async () => {
    const m = await matrix(dbaOnly.p, "bob", "agent");
    for (const [n] of CONN_TOOLS) assert.equal(m[n], "UNAUTHORIZED_ROLE", n);
  });
  await check("authz: unauthorized connection is hidden from list_connections (no error, filtered)", async () => {
    const m = await matrix(dbaOnly.p, "bob", "agent");
    assert.equal(m.list_connections, 0);
  });
  await check("authz: role matching is case-insensitive (DBA allowed by [dba])", async () => {
    const m = await matrix(dbaOnly.p, "bob", "DBA");
    for (const [n] of CONN_TOOLS) assert.equal(m[n], "ok", n);
    assert.equal(m.list_connections, 1);
  });
  await check("authz: --principal/--role flags and denial code are reflected in audit JSONL", async () => {
    await sleep(300);
    const aud = fs.readFileSync(path.join(dbaOnly.d, "audit.jsonl"), "utf8");
    const events = aud.trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(events.some((e) => e.principal === "bob" && e.role === "agent" && e.transport === "stdio"), "flags recorded");
    assert.ok(events.some((e) => e.role === "DBA"), "role string recorded verbatim");
    assert.ok(aud.includes("UNAUTHORIZED_ROLE"), "denial code recorded");
  });
  const devOnly = authCfg("auth-dev", ["developer"], ["*"]);
  await check("authz: allowed_roles=[developer] denies agent", async () => {
    assert.equal((await matrix(devOnly.p, "bob", "agent")).execute_query, "UNAUTHORIZED_ROLE");
  });
  await check("authz: explicit allowed_roles allowlist is honoured for self-asserted admin/dba roles", async () => {
    const dba = await matrix(devOnly.p, "bob", "dba");
    const adm = await matrix(devOnly.p, "bob", "admin");
    assert.equal(dba.execute_query, "UNAUTHORIZED_ROLE", "role dba bypasses allowed_roles=[developer]");
    assert.equal(adm.execute_query, "UNAUTHORIZED_ROLE", "role admin bypasses allowed_roles=[developer]");
  }, "KNOWN-BUG: F13-B11"); // CallerIdentity::is_admin() (admin|dba) short-circuits the allowlist in ConnectionPolicyConfig::can_access_connection (policy lib.rs:222)
  const aliceOnly = authCfg("auth-alice", ["*"], ["alice"]);
  await check("authz: allowed_principals=[alice] denies bob even with role admin (no admin bypass for principals)", async () => {
    const m = await matrix(aliceOnly.p, "bob", "admin");
    for (const [n] of CONN_TOOLS) assert.equal(m[n], "UNAUTHORIZED_ROLE", n);
    assert.equal(m.list_connections, 0);
  });
  await check("authz: principal matching is case-insensitive (ALICE allowed)", async () => {
    assert.equal((await matrix(aliceOnly.p, "ALICE", "agent")).execute_query, "ok");
  });
  await check("authz: wildcard '*' and empty lists both allow any caller (documented in policy)", async () => {
    const star = authCfg("auth-star", ["*"], ["*"]);
    const empty = authCfg("auth-empty", [], []);
    assert.equal((await matrix(star.p, "anyone", "whatever")).execute_query, "ok");
    assert.equal((await matrix(empty.p, "anyone", "whatever")).execute_query, "ok");
  });
  await check("authz: omitting allowed_roles/allowed_principals defaults to ['*']", async () => {
    assert.equal((await matrix(writeCfg("auth-default.toml", MIN() + `[[named_tools]]\nname = "nt"\ndescription = "d"\nconnection = "c1"\nstatement = "SELECT 1 AS one"\n`), "zed", "weird")).execute_query, "ok");
  });

  // -------------------------------------------------------------------------------------------
  // 4. Modes & profiles
  // -------------------------------------------------------------------------------------------
  await check("modes: connection without mode inherits default_mode (GovernedProduction -> write needs approval)", async () => {
    const cfg = writeCfg("inherit.toml", MIN().replace('default_mode = "ReadOnly"', 'default_mode = "GovernedProduction"').replace(/^mode = "Development"\r?\n/m, ""));
    assert.ok(!fs.readFileSync(cfg, "utf8").includes('mode = "Development"'));
    await withServer({ config: cfg }, async (s) => {
      const l = await s.call("list_connections");
      assert.equal(l.data[0].mode, "governed_production");
      const w = await s.call("execute_query", { connection: "c1", sql: "INSERT INTO t VALUES (1)" });
      assert.equal(w.code, "APPROVAL_REQUIRED");
    });
  });
  await check("modes: example config with mode removed inherits default_mode via makeIsolatedConfig transform", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "inherit-ex"), mode: "GovernedProduction", transform: (t) => t.replace(/^mode = "Development"\r?\n/m, "") });
    await withServer({ config: configPath }, async (s) => {
      const l = await s.call("list_connections");
      assert.equal(l.data.find((c) => c.id === "local-sqlite").mode, "governed_production");
    });
  });
  await check("modes: per-connection mode overrides default_mode (Development under default ReadOnly allows writes)", async () => {
    await withServer({ config: writeCfg("override.toml", MIN()) }, async (s) => {
      const l = await s.call("list_connections");
      assert.equal(l.data[0].mode, "development");
      assert.equal((await s.call("execute_query", { connection: "c1", sql: "INSERT INTO t VALUES (1)" })).status, "ok");
    });
  });
  await check("modes: read_only = true on a Development connection wins -> READONLY_VIOLATION, reads still ok", async () => {
    await withServer({ config: writeCfg("ro-dev.toml", MIN("read_only = true\n")) }, async (s) => {
      const l = await s.call("list_connections");
      assert.equal(l.data[0].mode, "development");
      assert.equal(l.data[0].read_only, true);
      const w = await s.call("execute_query", { connection: "c1", sql: "INSERT INTO t VALUES (1)" });
      assert.equal(w.code, "READONLY_VIOLATION");
      assert.equal((await s.call("execute_query", { connection: "c1", sql: "SELECT count(*) AS n FROM t" })).status, "ok");
    });
  });
  await check("modes: typo read_onli=true refuses to start instead of leaving the connection writable (F13-B1)", () => {
    const r = runBin(["serve", "--transport", "stdio", "--config", writeCfg("ro-typo.toml", MIN("read_onli = true\n"))]);
    assert.notEqual(r.status, 0, "server started with a misspelled read_only");
    assert.match(r.stderr, /unknown field `read_onli`/);
  });
  await check("profiles: active_profiles=[Explore] -> tools/list only Explore tools; hidden tool call -> TOOL_NOT_ENABLED", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "prof-explore"), transform: (t) => t.replace(/active_profiles = .*/, 'active_profiles = ["Explore"]') });
    await withServer({ config: configPath }, async (s) => {
      const names = (await s.rpc("tools/list", {})).result.tools.map((t) => t.name).sort();
      assert.deepEqual(names, ["describe_object", "get_procedure_call_graph", "list_connections", "search_objects", "trace_table_dependencies"]);
      assert.equal((await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT 1" })).code, "TOOL_NOT_ENABLED");
      assert.equal((await s.call("run_named_tool", { tool_name: "get_user_by_id", arguments: { user_id: 1 } })).code, "TOOL_NOT_ENABLED");
      assert.equal((await s.call("list_connections")).status, "ok");
    });
  });
  await check("profiles: empty active_profiles -> zero tools, server still answers ping", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "prof-empty"), transform: (t) => t.replace(/active_profiles = .*/, "active_profiles = []") });
    await withServer({ config: configPath }, async (s) => {
      assert.equal((await s.rpc("tools/list", {})).result.tools.length, 0);
      assert.ok((await s.rpc("ping", {})).result !== undefined);
    });
  });
  await check("profiles: duplicate/mixed-case entries deduplicate to one tool set", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "prof-dup"), transform: (t) => t.replace(/active_profiles = .*/, 'active_profiles = ["Query", "Query", "query"]') });
    await withServer({ config: configPath }, async (s) => {
      const names = (await s.rpc("tools/list", {})).result.tools.map((t) => t.name).sort();
      assert.deepEqual(names, ["execute_query", "explain_query", "run_named_tool"]);
    });
  });
  await check("profiles: all six profiles expose 24 tools", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "prof-all") });
    await withServer({ config: configPath }, async (s) => assert.equal((await s.rpc("tools/list", {})).result.tools.length, 24));
  });

  // -------------------------------------------------------------------------------------------
  // 5. init_sql
  // -------------------------------------------------------------------------------------------
  await check("init_sql: runs at startup on each connection (fixture tables present on sqlite, postgres, mysql)", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "init-ex") });
    await withServer({ config: configPath }, async (s) => {
      for (const c of ["local-sqlite", "prod-postgres", "analytics-mysql"]) {
        const q = await s.call("execute_query", { connection: c, sql: "SELECT count(*) AS n FROM users" });
        assert.equal(q.status, "ok", `${c}: ${JSON.stringify(q).slice(0, 200)}`);
        assert.equal(rows(q)[0][0], 2, c);
      }
    });
  });
  await check("init_sql: example config DROPs and recreates on every restart -> writes to local-sqlite are lost (documented)", async () => {
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "init-restart") });
    await withServer({ config: configPath }, async (s) => {
      assert.equal((await s.call("execute_query", { connection: "local-sqlite", sql: INSERT_USER })).status, "ok");
      assert.equal(rows(await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) AS n FROM users" }))[0][0], 3);
    });
    await sleep(300);
    await withServer({ config: configPath }, async (s) => {
      assert.equal(rows(await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) AS n FROM users" }))[0][0], 2, "row survived restart");
    });
  });
  await check("init_sql: starter config uses IF NOT EXISTS -> writes persist across restart", async () => {
    const { configPath } = makeIsolatedConfig({ source: path.join(REPO, "config", "db-mcp.starter.toml"), dir: path.join(TMP, "init-starter"), transform: (t) => t.replace('dsn = "env:DATABASE_URL"', 'dsn = "postgres://127.0.0.1:1/x"').replace('dsn = "env:MYSQL_URL"', 'dsn = "mysql://127.0.0.1:1/x"') });
    await withServer({ config: configPath }, async (s) => {
      assert.equal((await s.call("execute_query", { connection: "local-sqlite", sql: "INSERT INTO notes (title) VALUES ('persist')" })).status, "ok");
    });
    await sleep(300);
    await withServer({ config: configPath }, async (s) => {
      assert.equal(rows(await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) AS n FROM notes" }))[0][0], 1);
    });
  });
  await check("init_sql: syntax error refuses startup with exit 1 and a clear error (sqlite and postgres)", () => {
    const a = runBin(["serve", "--transport", "stdio", "--config", writeCfg("init-bad-sqlite.toml", MIN().replace('init_sql = "CREATE TABLE t(a INT);"', 'init_sql = "CREATE TABEL broken ("'))]);
    assert.equal(a.status, 1);
    assert.match(a.stderr, /syntax error/);
    const b = runBin(["serve", "--transport", "stdio", "--config", `${writeCfg("init-bad-pg.toml", `server_name = "t"\n[[connections]]\nid = "pg"\nengine = "Postgres"\ndsn = "postgres://user:p4ss@127.0.0.1:1/x"\ninit_sql = "CREATE TABEL broken ("\n`)}`]);
    assert.equal(b.status, 1);
    assert.match(b.stderr, /syntax error/);
    assert.ok(!b.stderr.includes("p4ss"), "startup error leaked DSN password");
  });
  await check("init_sql: Postgres/MySQL init_sql only ever runs against the embedded in-memory engine (no wire client linked)", () => {
    const cargo = fs.readFileSync(path.join(REPO, "crates", "db-mcp-postgres", "Cargo.toml"), "utf8");
    assert.ok(!/tokio-postgres|sqlx|postgres\s*=/.test(cargo), "a live Postgres client is linked; re-audit init_sql path");
    const src = fs.readFileSync(path.join(REPO, "crates", "db-mcp-postgres", "src", "lib.rs"), "utf8");
    assert.ok(/pub fn new\(config: PostgresConfig\)[\s\S]{0,200}Connection::open_in_memory\(\)/.test(src));
  });

  // -------------------------------------------------------------------------------------------
  // 6. Default demo config (no --config)
  // -------------------------------------------------------------------------------------------
  await check("demo: serve without --config exposes 3 in-memory demo connections, 24 tools, ReadOnly default, writable sqlite", async () => {
    const cwd = path.join(TMP, "demo-cwd");
    fs.mkdirSync(cwd, { recursive: true });
    await withServer({ config: null, cwd }, async (s) => {
      const l = await s.call("list_connections");
      const byId = Object.fromEntries(l.data.map((c) => [c.id, c]));
      assert.deepEqual(Object.keys(byId).sort(), ["analytics-mysql", "local-sqlite", "prod-postgres"]);
      assert.equal(byId["local-sqlite"].mode, "development");
      assert.equal(byId["prod-postgres"].mode, "governed_production");
      assert.equal(byId["analytics-mysql"].mode, "read_only");
      assert.equal((await s.rpc("tools/list", {})).result.tools.length, 24);
      assert.equal(rows(await s.call("execute_query", { connection: "local-sqlite", sql: "SELECT count(*) AS n FROM users" }))[0][0], 2);
      assert.equal((await s.call("execute_query", { connection: "local-sqlite", sql: INSERT_USER })).status, "ok");
      assert.equal((await s.call("execute_query", { connection: "prod-postgres", sql: "UPDATE orders SET status='x'" })).code, "APPROVAL_REQUIRED");
    });
    await sleep(300);
    assert.deepEqual(fs.readdirSync(cwd), [], "demo mode wrote files into cwd");
  });
  await check("demo: approve without --config uses an in-memory store and can never find a proposal (UX trap, exit 1)", () => {
    const r = runBin(["approve", "--change-id", "chg_deadbeef", "--approver", "a"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Change proposal 'chg_deadbeef' not found/);
  });

  // -------------------------------------------------------------------------------------------
  // 3b. HTTP identity & trust model
  // -------------------------------------------------------------------------------------------
  await check("http: with tokens set, /mcp requires bearer; header role cannot approve, /admin/approve needs the separate admin token", async () => {
    const port = 19000 + Math.floor(Math.random() * 500);
    const { configPath, dir } = makeIsolatedConfig({ dir: path.join(TMP, "http-tok"), transform: (t) => t.replace('bind = "127.0.0.1:8080"', `bind = "127.0.0.1:${port}"`) });
    const srv = await startHttp({ config: configPath, port, env: { DB_MCP_AUTH_TOKEN: "tok-user-123456", DB_MCP_ADMIN_TOKEN: "tok-admin-654321" } });
    try {
      const U = { authorization: "Bearer tok-user-123456" };
      const asAdminHdr = { ...U, "x-mcp-principal": "mallory", "x-mcp-role": "admin" };
      const call = (id, name, args, h) => postJson(port, "/mcp", { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }, h).then((r) => ({ status: r.status, sc: r.body && r.body.result && r.body.result.structuredContent, body: r.body }));
      assert.equal((await call(1, "list_connections", {}, {})).status, 401, "no bearer must be 401");
      assert.equal((await call(1, "list_connections", {}, { authorization: "Bearer wrong" })).status, 401);
      const prop = await call(2, "propose_change", { connection: "prod-postgres", sql: "UPDATE orders SET status = 'completed' WHERE id = 102" }, asAdminHdr);
      assert.equal(prop.sc.status, "ok");
      const chg = prop.sc.data.change_id;
      const apply1 = await call(3, "apply_change", { change_id: chg }, asAdminHdr);
      assert.equal(apply1.sc.code, "APPROVAL_REQUIRED", "x-mcp-role: admin must not be able to apply an unapproved change");
      const names = (await postJson(port, "/mcp", { jsonrpc: "2.0", id: 9, method: "tools/list", params: {} }, asAdminHdr)).body.result.tools.map((t) => t.name);
      assert.ok(!names.includes("approve_change"), "no approve tool is exposed over MCP");
      assert.equal((await postJson(port, "/admin/approve", { change_id: chg, approver: "mallory" }, U)).status, 401, "user token must not approve");
      assert.equal((await postJson(port, "/admin/approve", { change_id: chg, approver: "mallory" }, {})).status, 401);
      const ok = await postJson(port, "/admin/approve", { change_id: chg, approver: "release-admin" }, { authorization: "Bearer tok-admin-654321" });
      assert.equal(ok.status, 200);
      assert.equal((await call(4, "apply_change", { change_id: chg }, U)).sc.status, "ok");
      const deny = await call(5, "execute_query", { connection: "prod-postgres", sql: "SELECT 1" }, { ...U, "x-mcp-role": "nobody" });
      assert.equal(deny.sc.code, "UNAUTHORIZED_ROLE", "header role is honoured for denials");
      assert.equal((await call(6, "execute_query", { connection: "prod-postgres", sql: "SELECT 1" }, { ...U, "x-mcp-role": "dba", "x-mcp-principal": "anyone" })).sc.status, "ok", "any bearer holder can self-assert dba (trust model)");
      await sleep(300);
      const aud = fs.readFileSync(path.join(dir, "audit.jsonl"), "utf8");
      assert.ok(aud.includes('"principal":"mallory"') && aud.includes('"transport":"http"'), "header identity audited");
      assert.ok(!aud.includes("tok-user") && !aud.includes("tok-admin"), "tokens leaked into audit");
      assert.ok(!srv.stderr.join("").includes("tok-user"));
    } finally { await srv.stop(); }
  });
  await check("http: empty-string token env var fails closed (401 even for 'Bearer ' - header value trimming saves it)", async () => {
    const port = 19600 + Math.floor(Math.random() * 300);
    const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "http-empty"), transform: (t) => t.replace('bind = "127.0.0.1:8080"', `bind = "127.0.0.1:${port}"`) });
    const srv = await startHttp({ config: configPath, port, env: { DB_MCP_AUTH_TOKEN: "", DB_MCP_ADMIN_TOKEN: "" } });
    try {
      const r = await postJson(port, "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_connections", arguments: {} } }, { authorization: "Bearer " });
      const a = await postJson(port, "/admin/approve", { change_id: "chg_none", approver: "x" }, { authorization: "Bearer " });
      assert.equal(r.status, 401, `"Authorization: Bearer " (empty) accepted on /mcp with empty token env`);
      assert.equal(a.status, 401, `empty bearer accepted on /admin/approve`);
    } finally { await srv.stop(); }
  }); // resolve_optional_token yields Some("") for an env var set to ""; no bearer can equal "" because HTTP strips the trailing space, so the server locks out (fail closed)

  // -------------------------------------------------------------------------------------------
  console.log(`\nF13 summary: pass=${stats.pass} fail=${stats.fail} xfail(known-bug)=${stats.xfail} xpass=${stats.xpass}`);
  if (failures.length) console.log("Unexpected failures:\n  - " + failures.join("\n  - "));
  return stats.fail === 0 ? 0 : 1;
}

function cleanup() {
  for (const c of children) { try { c.kill(); } catch { /* ignore */ } }
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* ignore */ }
}
process.on("SIGINT", () => { cleanup(); process.exit(130); });
main()
  .then(async (code) => { await sleep(400); cleanup(); process.exit(code); })
  .catch(async (err) => { console.error("F13 harness error:", err); await sleep(400); cleanup(); process.exit(1); });
