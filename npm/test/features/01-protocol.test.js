#!/usr/bin/env node
"use strict";
const EXPECTED_TOOL_COUNT = Number(process.env.DB_MCP_EXPECTED_TOOLS || 16);
/**
 * F01 - MCP protocol conformance and transports (stdio + Streamable HTTP).
 *
 *   node npm/test/features/01-protocol.test.js
 *
 * Self-contained (node:assert only). Spawns the prebuilt db-mcp-server through the npm launcher with a
 * private isolated config (never config/db-mcp.example.toml directly) and ephemeral HTTP ports.
 * Prints one line per check; exit code 0 only when every check passes.
 *
 * Checks tagged `// KNOWN-BUG: F01-Bn` assert the CORRECT behaviour and are expected to fail until fixed:
 *   F01-B1  HTTP auth fail-open: `auth_token = "env:DB_MCP_AUTH_TOKEN"` with the env var unset silently
 *           disables auth on POST /mcp and POST /admin/approve            (crates/db-mcp-server/src/main.rs:96-106,348-349)
 *   F01-B2  A stdin line with invalid UTF-8 terminates the stdio server    (crates/db-mcp-server/src/main.rs:230)
 *   F01-B3  HTTP notifications answered with 200 + JSON body, spec requires 202 Accepted / no body
 *                                                                          (main.rs:172-193, crates/db-mcp-mcp/src/lib.rs:783)
 *   F01-B4  Valid JSON that is not a request object (missing method, batch array, scalar) -> -32700 instead of -32600
 *                                                                          (crates/db-mcp-mcp/src/lib.rs:823-827)
 *   F01-B5  id-less JSON-RPC notifications whose method is not prefixed `notifications/` receive a reply with id:null
 *                                                                          (main.rs:236-241)
 *   F01-B6  401 responses carry no `WWW-Authenticate: Bearer` header       (main.rs:177-186, 200-205)
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const readline = require("node:readline");
const { spawn } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
const launcher = require(path.join(REPO_ROOT, "npm", "bin", "db-mcp.js"));

const EXPECTED_TOOLS = [
  "list_connections", "search_objects", "describe_object", "trace_table_dependencies", "get_procedure_call_graph",
  "execute_query", "explain_query", "run_named_tool", "database_health", "analyze_workload", "recommend_indexes",
  "propose_change", "get_change", "apply_change", "capture_schema", "diff_schema",
];
const SLOW_SQL = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 4000000) SELECT COUNT(*) FROM c";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------------------------
const children = new Set();
const results = { pass: 0, fail: 0, failedNames: [] };
function killAll() {
  for (const c of children) { try { c.kill(); } catch { /* already gone */ } }
  children.clear();
}
process.on("exit", killAll);
process.on("SIGINT", () => { killAll(); process.exit(130); });

async function check(name, fn) {
  try {
    await fn();
    results.pass++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    results.fail++;
    results.failedNames.push(name);
    const msg = String(err && err.message ? err.message : err).split("\n")[0].slice(0, 300);
    console.log(`FAIL  ${name} -- ${msg}`);
  }
}
const info = (msg) => console.log(`INFO  ${msg}`);

const BINARY = launcher.resolveBinaryPath({ autoBuild: false });

/** Spawn the server directly (not via process.env merge) so DB_MCP_*_TOKEN never leak in from the parent. */
function spawnServer(args, { env = {}, stdio = ["pipe", "pipe", "pipe"] } = {}) {
  const cleanEnv = { ...process.env };
  delete cleanEnv.DB_MCP_AUTH_TOKEN;
  delete cleanEnv.DB_MCP_ADMIN_TOKEN;
  const child = spawn(BINARY, args, { cwd: REPO_ROOT, env: { ...cleanEnv, ...env }, stdio, windowsHide: true });
  children.add(child);
  child.on("exit", () => children.delete(child));
  return child;
}

function stdioClient(configPath, extraArgs = []) {
  const child = spawnServer(["serve", "--transport", "stdio", "--config", configPath, ...extraArgs]);
  const lines = [];
  const stderr = [];
  const raw = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  child.stdout.on("data", (d) => raw.push(Buffer.from(d)));
  readline.createInterface({ input: child.stdout }).on("line", (l) => lines.push(l));
  const exited = new Promise((res) => child.on("exit", (code, signal) => res({ code, signal })));
  let cursor = 0;
  const waitLines = (n, ms = 20000) => new Promise((res, rej) => {
    const t0 = Date.now();
    const iv = setInterval(() => {
      if (lines.length >= n) { clearInterval(iv); res(); }
      else if (child.exitCode !== null) { clearInterval(iv); rej(new Error(`server exited (code=${child.exitCode}) before line ${n}; stderr=${stderr.join("").trim()}`)); }
      else if (Date.now() - t0 > ms) { clearInterval(iv); rej(new Error(`timeout waiting for line ${n} (have ${lines.length}); stderr=${stderr.join("").trim()}`)); }
    }, 5);
  });
  const next = async (ms) => { await waitLines(cursor + 1, ms); return lines[cursor++]; };
  const write = (s) => child.stdin.write(s);
  const send = (obj) => write((typeof obj === "string" ? obj : JSON.stringify(obj)) + "\n");
  const ask = async (obj, ms) => { send(obj); return JSON.parse(await next(ms)); };
  const drainFor = async (ms) => { await sleep(ms); const extra = lines.slice(cursor); cursor = lines.length; return extra; };
  const exitWithin = (ms) => Promise.race([exited, sleep(ms).then(() => "TIMEOUT")]);
  let syncSeq = 0;
  /** Re-align the reader after a failed check: send a sentinel ping and discard everything up to its reply. */
  const resync = async () => {
    if (child.exitCode !== null || child.stdin.destroyed || child.stdin.writableEnded) return;
    const tag = `sync-${++syncSeq}`;
    try {
      send({ jsonrpc: "2.0", id: tag, method: "ping" });
      for (let i = 0; i < 200; i++) { const l = await next(10000); if (JSON.parse(l).id === tag) return; }
    } catch { /* leave it to the next check to report */ }
  };
  return { child, lines, stderr, raw, next, write, send, ask, waitLines, drainFor, exitWithin, resync, cursor: () => cursor, setCursor: (c) => { cursor = c; } };
}

const freePort = () => new Promise((res, rej) => {
  const s = net.createServer();
  s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close((e) => (e ? rej(e) : res(p))); });
});

async function httpServer({ env = {}, transform, extraArgs = [] } = {}) {
  const { configPath, dir } = makeIsolatedConfig({ transform });
  const port = await freePort();
  const bind = `127.0.0.1:${port}`;
  const child = spawnServer(["serve", "--transport", "http", "--bind", bind, "--config", configPath, ...extraArgs], { env, stdio: ["ignore", "pipe", "pipe"] });
  const stderr = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  const exited = new Promise((res) => child.on("exit", (code, signal) => res({ code, signal })));
  const base = `http://${bind}`;
  const t0 = Date.now();
  let up = false;
  for (let i = 0; i < 200 && !up; i++) {
    if (child.exitCode !== null) break;
    try { const r = await fetch(`${base}/health`); if (r.status === 200) up = true; } catch { /* not yet */ }
    if (!up) await sleep(50);
  }
  return { child, base, bind, port, dir, configPath, stderr, startupMs: Date.now() - t0, up, exitWithin: (ms) => Promise.race([exited, sleep(ms).then(() => "TIMEOUT")]) };
}
const post = (base, body, headers = {}, pathname = "/mcp") => fetch(base + pathname, {
  method: "POST",
  headers: { "content-type": "application/json", ...headers },
  body: typeof body === "string" ? body : JSON.stringify(body),
});
const callParams = (sql, connection = "local-sqlite") => ({ name: "execute_query", arguments: { connection, sql } });
const RESTRICT_PRINCIPALS = (t) => t
  .replace(/allowed_principals = \["\*"\]/, 'allowed_principals = ["alice"]')
  .replace(/allowed_roles = \["\*"\]/, 'allowed_roles = ["agent", "dba"]');

// ---------------------------------------------------------------------------------------------------------------
// 1-4. stdio framing, methods, tools, edge cases, concurrency, lifecycle
// ---------------------------------------------------------------------------------------------------------------
async function stdioSuite(configPath) {
  // Baseline: bare process start+exit without serving (verify-config) to attribute startup latency.
  {
    const t0 = Date.now();
    const vc = spawnServer(["verify-config", "--config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
    const vcExit = await new Promise((res) => vc.on("exit", (code) => res(code)));
    info(`verify-config exit=${vcExit} in ${Date.now() - t0} ms (process start + config parse baseline)`);
  }

  const t0 = Date.now();
  const s = stdioClient(configPath);
  // Every check on the shared stdio client re-aligns the reader afterwards so a failing (known-bug) check
  // cannot leak its stray output into the next check.
  const checkOnShared = check;
  check = (name, fn) => checkOnShared(name, async () => { try { await fn(); } finally { await s.resync(); } });
  let firstPingMs = -1;
  await check("stdio: first ping answered after spawn (startup latency)", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 1, method: "ping" }, 20000);
    firstPingMs = Date.now() - t0;
    assert.deepEqual(r, { jsonrpc: "2.0", id: 1, result: {} });
  });
  info(`stdio startup -> first ping response: ${firstPingMs} ms`);

  for (const v of ["2024-11-05", "2025-03-26", "2025-06-18"]) {
    await check(`stdio: initialize protocolVersion=${v} -> valid InitializeResult (version negotiated, tools capability, serverInfo)`, async () => {
      const r = await s.ask({ jsonrpc: "2.0", id: `init-${v}`, method: "initialize", params: { protocolVersion: v, capabilities: {}, clientInfo: { name: "f01", version: "1" } } });
      assert.equal(r.id, `init-${v}`);
      assert.ok(r.result, `no result: ${JSON.stringify(r)}`);
      // Spec: respond with the requested version if supported, else with a version the server supports.
      assert.ok([v, "2024-11-05"].includes(r.result.protocolVersion), `unexpected protocolVersion ${r.result.protocolVersion}`);
      assert.equal(typeof r.result.capabilities, "object");
      assert.equal(typeof r.result.capabilities.tools, "object", "capabilities.tools missing");
      assert.equal(typeof r.result.serverInfo.name, "string");
      assert.equal(typeof r.result.serverInfo.version, "string");
      if (r.result.protocolVersion !== v) info(`initialize ${v}: server answered protocolVersion=${r.result.protocolVersion} (no negotiation of newer versions; fixed value at crates/db-mcp-mcp/src/lib.rs:773)`);
    });
  }

  await check("stdio: notifications/initialized produces no response", async () => {
    s.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    s.send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    const r = await s.ask({ jsonrpc: "2.0", id: 2, method: "ping" });
    assert.equal(r.id, 2, `expected ping reply, got ${JSON.stringify(r)}`);
    assert.deepEqual(await s.drainFor(150), []);
  });

  await check("stdio: ping without params -> {} and string / zero ids echoed verbatim", async () => {
    assert.deepEqual(await s.ask({ jsonrpc: "2.0", id: "abc-1", method: "ping" }), { jsonrpc: "2.0", id: "abc-1", result: {} });
    assert.deepEqual(await s.ask({ jsonrpc: "2.0", id: 0, method: "ping", params: {} }), { jsonrpc: "2.0", id: 0, result: {} });
  });

  await check("stdio: tools/list -> 16 tools with name/description/inputSchema (object schemas, required <= properties)", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 3, method: "tools/list" });
    const tools = r.result.tools;
    assert.ok(Array.isArray(tools));
    assert.equal(tools.length, EXPECTED_TOOL_COUNT);
    assert.deepEqual(tools.map((t) => t.name).sort(), [...EXPECTED_TOOLS].sort());
    assert.equal(new Set(tools.map((t) => t.name)).size, 16, "duplicate tool names");
    for (const t of tools) {
      assert.ok(t.name && typeof t.name === "string", "tool name");
      assert.ok(t.description && typeof t.description === "string", `${t.name}: description`);
      const sch = t.inputSchema;
      assert.ok(sch && typeof sch === "object" && !Array.isArray(sch), `${t.name}: inputSchema not an object`);
      assert.equal(sch.type, "object", `${t.name}: inputSchema.type`);
      assert.ok(sch.properties && typeof sch.properties === "object", `${t.name}: properties`);
      const props = Object.keys(sch.properties);
      for (const req of sch.required || []) assert.ok(props.includes(req), `${t.name}: required '${req}' not in properties`);
      for (const [p, def] of Object.entries(sch.properties)) assert.ok(def && typeof def === "object", `${t.name}.${p}: property schema not object`);
    }
  });

  await check("stdio: tools/list tolerates missing params and an unknown cursor", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 4, method: "tools/list", params: { cursor: "does-not-exist" } });
    assert.ok(Array.isArray(r.result.tools));
  });

  await check("stdio: unknown method -> error -32601 with id echoed", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 5, method: "foo/bar" });
    assert.equal(r.id, 5);
    assert.equal(r.error.code, -32601);
    assert.equal(r.result, undefined);
  });

  await check("stdio: malformed JSON line -> error -32700 with id null", async () => {
    const r = await s.ask("{this is not json");
    assert.equal(r.id, null);
    assert.equal(r.error.code, -32700);
  });

  await check("stdio: valid JSON but not a Request object (missing method) -> -32600 Invalid Request", async () => { // KNOWN-BUG: F01-B4
    const r = await s.ask({ jsonrpc: "2.0", id: 6 });
    assert.equal(r.error && r.error.code, -32600, `got ${JSON.stringify(r)}`);
  });

  await check("stdio: batch array -> per-item responses or single -32600 error (never 'parse error')", async () => { // KNOWN-BUG: F01-B4
    s.send([{ jsonrpc: "2.0", id: 10, method: "ping" }, { jsonrpc: "2.0", id: 11, method: "ping" }]);
    const first = JSON.parse(await s.next());
    if (Array.isArray(first)) {
      assert.deepEqual(first.map((x) => x.id).sort(), [10, 11]);
    } else {
      assert.equal(first.error && first.error.code, -32600, `got ${JSON.stringify(first)}`);
    }
    await s.drainFor(150);
  });

  await check("stdio: id-less JSON-RPC notification for a non-'notifications/' method gets no reply", async () => { // KNOWN-BUG: F01-B5
    s.send({ jsonrpc: "2.0", method: "ping" });
    const r = await s.ask({ jsonrpc: "2.0", id: 7, method: "ping" });
    assert.equal(r.id, 7, `expected reply to id 7 first, got ${JSON.stringify(r)}`);
    await s.drainFor(100);
  });

  await check("stdio: notifications/cancelled is accepted silently and server keeps serving", async () => {
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "nope", reason: "test" } });
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled" });
    const r = await s.ask({ jsonrpc: "2.0", id: 8, method: "ping" });
    assert.equal(r.id, 8);
    assert.deepEqual(await s.drainFor(100), []);
  });

  await check("stdio: tools/call without params -> JSON-RPC -32602 (invalid params)", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 9, method: "tools/call" });
    assert.equal(r.error && r.error.code, -32602, JSON.stringify(r));
  });

  await check("stdio: tools/call with missing required args -> structured isError result (no crash)", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 12, method: "tools/call", params: { name: "execute_query", arguments: { connection: "local-sqlite" } } });
    assert.ok(r.result, JSON.stringify(r));
    assert.equal(r.result.isError, true);
    assert.equal(r.result.structuredContent.status, "denied");
    assert.equal(r.result.structuredContent.code, "INVALID_ARGUMENT");
    assert.equal(r.result.content[0].type, "text");
    const r2 = await s.ask({ jsonrpc: "2.0", id: 13, method: "tools/call", params: { name: "execute_query" } });
    assert.equal(r2.result.isError, true);
    assert.equal((await s.ask({ jsonrpc: "2.0", id: 14, method: "ping" })).id, 14);
  });

  await check("stdio: tools/call with wrongly typed args -> isError result, not a crash", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 15, method: "tools/call", params: { name: "execute_query", arguments: { connection: 5, sql: ["x"] } } });
    assert.equal(r.result.isError, true);
    const r2 = await s.ask({ jsonrpc: "2.0", id: 16, method: "tools/call", params: { name: "execute_query", arguments: "SELECT 1" } });
    assert.equal(r2.result.isError, true);
  });

  await check("stdio: tools/call unknown tool -> isError result", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 17, method: "tools/call", params: { name: "no_such_tool", arguments: {} } });
    assert.equal(r.result.isError, true);
    assert.equal(r.result.structuredContent.status, "denied");
  });

  await check("stdio: tools/call success -> content[] text mirrors structuredContent, isError=false", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 18, method: "tools/call", params: callParams("SELECT 1 AS one") });
    assert.equal(r.result.isError, false);
    assert.equal(r.result.content.length, 1);
    assert.equal(r.result.content[0].type, "text");
    assert.deepEqual(JSON.parse(r.result.content[0].text), r.result.structuredContent);
    assert.equal(r.result.structuredContent.status, "ok");
    assert.deepEqual(r.result.structuredContent.rows, [[1]]);
  });

  await check("stdio: tools/call policy denial -> isError=true with structured denial", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: 19, method: "tools/call", params: callParams("SELECT * FROM internal_secrets") });
    assert.equal(r.result.isError, true);
    assert.equal(r.result.structuredContent.status, "denied");
    assert.equal(r.result.structuredContent.code, "RESTRICTED_TABLE_FORBIDDEN");
    assert.equal(JSON.parse(r.result.content[0].text).code, "RESTRICTED_TABLE_FORBIDDEN");
  });

  await check("stdio: empty lines, whitespace-only lines and CRLF line endings are tolerated", async () => {
    s.write("\n\n   \n\r\n\t\r\n");
    s.write(JSON.stringify({ jsonrpc: "2.0", id: 20, method: "ping" }) + "\r\n");
    assert.equal(JSON.parse(await s.next()).id, 20);
    s.write("   " + JSON.stringify({ jsonrpc: "2.0", id: 21, method: "ping" }) + "   \r\n");
    assert.equal(JSON.parse(await s.next()).id, 21);
    assert.deepEqual(await s.drainFor(100), []);
  });

  await check("stdio: two requests in one write and one request split across writes are both framed correctly", async () => {
    s.write(JSON.stringify({ jsonrpc: "2.0", id: 22, method: "ping" }) + "\n" + JSON.stringify({ jsonrpc: "2.0", id: 23, method: "ping" }) + "\n");
    assert.equal(JSON.parse(await s.next()).id, 22);
    assert.equal(JSON.parse(await s.next()).id, 23);
    const msg = JSON.stringify({ jsonrpc: "2.0", id: 24, method: "ping" });
    s.write(msg.slice(0, 12));
    await sleep(60);
    s.write(msg.slice(12) + "\n");
    assert.equal(JSON.parse(await s.next()).id, 24);
  });

  await check("stdio: 1 MB SQL string in one request line is processed (single-line reply, server alive)", async () => {
    const sql = "SELECT '" + "x".repeat(1024 * 1024) + "' AS big";
    const t = Date.now();
    const r = await s.ask({ jsonrpc: "2.0", id: 25, method: "tools/call", params: callParams(sql) }, 60000);
    info(`1 MB request line round trip: ${Date.now() - t} ms, status=${r.result.structuredContent.status}, truncated=${r.result.structuredContent.truncated}`);
    assert.equal(r.id, 25);
    assert.ok(r.result);
    assert.ok(["ok", "denied"].includes(r.result.structuredContent.status));
  });

  await check("stdio: 1 MB garbage line -> -32700 and server keeps serving", async () => {
    s.write("x".repeat(1024 * 1024) + "\n");
    const r = JSON.parse(await s.next(30000));
    assert.equal(r.error.code, -32700);
    assert.equal((await s.ask({ jsonrpc: "2.0", id: 26, method: "ping" })).id, 26);
  });

  await check("stdio: unicode in id and SQL round-trips", async () => {
    const r = await s.ask({ jsonrpc: "2.0", id: "ü-漢字-🎉", method: "tools/call", params: callParams("SELECT 'héllo 漢字 🎉' AS u") });
    assert.equal(r.id, "ü-漢字-🎉");
    assert.deepEqual(r.result.structuredContent.rows, [["héllo 漢字 🎉"]]);
  });

  await check("stdio: 20 tools/call fired without awaiting -> 20 well-formed replies, each id exactly once", async () => {
    const base = s.cursor();
    const t = Date.now();
    for (let i = 0; i < 20; i++) s.send({ jsonrpc: "2.0", id: 1000 + i, method: "tools/call", params: callParams(`SELECT ${i} AS n`) });
    await s.waitLines(base + 20, 60000);
    s.setCursor(base + 20);
    const got = s.lines.slice(base, base + 20).map((l) => JSON.parse(l));
    info(`20 concurrent stdio tools/call answered in ${Date.now() - t} ms`);
    const ids = got.map((m) => m.id).sort((a, b) => a - b);
    assert.deepEqual(ids, Array.from({ length: 20 }, (_, i) => 1000 + i));
    for (const m of got) assert.equal(m.result.structuredContent.rows[0][0], m.id - 1000, "reply payload matches its id");
    assert.deepEqual(await s.drainFor(200), [], "no extra lines");
  });

  await check("stdio: 20 interleaved ping/tools/list requests -> every id answered once, every stdout line is complete JSON", async () => {
    const base = s.cursor();
    for (let i = 0; i < 10; i++) { s.send({ jsonrpc: "2.0", id: `p${i}`, method: "ping" }); s.send({ jsonrpc: "2.0", id: `l${i}`, method: "tools/list" }); }
    await s.waitLines(base + 20, 60000);
    s.setCursor(base + 20);
    const ids = s.lines.slice(base, base + 20).map((l) => JSON.parse(l).id).sort();
    assert.deepEqual(ids, [...Array.from({ length: 10 }, (_, i) => `l${i}`), ...Array.from({ length: 10 }, (_, i) => `p${i}`)].sort());
    const all = Buffer.concat(s.raw).toString("utf8");
    assert.ok(all.endsWith("\n"), "stdout ends with newline");
    for (const l of all.split("\n")) if (l.trim()) JSON.parse(l);
  });

  {
    // Document (not assert) the serial stdio loop: a ping queued behind a slow query waits; cancellation cannot pre-empt.
    const t = Date.now();
    s.send({ jsonrpc: "2.0", id: 2000, method: "tools/call", params: callParams(SLOW_SQL) });
    s.send({ jsonrpc: "2.0", id: 2001, method: "ping" });
    const a = JSON.parse(await s.next(60000)); const ta = Date.now() - t;
    const b = JSON.parse(await s.next(60000)); const tb = Date.now() - t;
    info(`stdio serial loop: slow query (id ${a.id}) answered at ${ta} ms, queued ping (id ${b.id}) only at ${tb} ms (head-of-line blocking, main.rs:230-251)`);
    const t2 = Date.now();
    s.send({ jsonrpc: "2.0", id: 2002, method: "tools/call", params: callParams(SLOW_SQL) });
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2002, reason: "test" } });
    const c = JSON.parse(await s.next(60000));
    info(`stdio notifications/cancelled for in-flight id 2002: result status=${c.result.structuredContent.status} after ${Date.now() - t2} ms (cancellation cannot reach an in-flight call over stdio)`);
  }

  await check("stdio: stdin EOF -> clean exit code 0", async () => {
    s.child.stdin.end();
    const ex = await s.exitWithin(10000);
    assert.deepEqual(ex, { code: 0, signal: null });
  });

  await check("stdio: stdin EOF while a request is in flight -> reply flushed, then exit 0", async () => {
    const c = stdioClient(configPath);
    await c.ask({ jsonrpc: "2.0", id: 1, method: "ping" });
    c.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: callParams(SLOW_SQL) });
    c.child.stdin.end();
    const ex = await c.exitWithin(30000);
    assert.deepEqual(ex, { code: 0, signal: null });
    assert.equal(c.lines.length, 2);
    assert.equal(JSON.parse(c.lines[1]).id, 2);
  });

  await check("stdio: immediate EOF with no request -> exit 0, nothing on stdout", async () => {
    const c = stdioClient(configPath);
    c.child.stdin.end();
    const ex = await c.exitWithin(15000);
    assert.deepEqual(ex, { code: 0, signal: null });
    assert.equal(c.lines.length, 0);
  });

  await check("stdio: SIGTERM/kill terminates the server promptly", async () => {
    const c = stdioClient(configPath);
    await c.ask({ jsonrpc: "2.0", id: 1, method: "ping" });
    c.child.kill("SIGTERM");
    const ex = await c.exitWithin(5000);
    assert.notEqual(ex, "TIMEOUT");
  });

  await check("stdio: a line with invalid UTF-8 -> -32700 (or ignored) and the server stays alive", async () => { // KNOWN-BUG: F01-B2
    const c = stdioClient(configPath);
    await c.ask({ jsonrpc: "2.0", id: 1, method: "ping" });
    c.write(Buffer.concat([Buffer.from('{"jsonrpc":"2.0","id":2,"method":"ping","params":{"x":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}}\n')]));
    c.send({ jsonrpc: "2.0", id: 3, method: "ping" });
    let last;
    for (;;) { const l = JSON.parse(await c.next(5000)); last = l; if (l.id === 3) break; assert.ok(l.id === null || l.id === 2, JSON.stringify(l)); }
    assert.equal(last.id, 3);
    assert.equal(c.child.exitCode, null, `server exited: ${c.stderr.join("")}`);
    c.child.kill();
  });

  await check("stdio: --config pointing at a missing file -> exit 1 with error on stderr", async () => {
    const c = stdioClient(path.join(path.dirname(configPath), "does-not-exist.toml"));
    const ex = await c.exitWithin(10000);
    assert.equal(ex.code, 1);
    assert.match(c.stderr.join(""), /config/i);
  });

  await check("stdio: --transport other than stdio/http -> exit 1 with error", async () => {
    const c = spawnServer(["serve", "--transport", "websocket", "--config", configPath]);
    const err = []; c.stderr.on("data", (d) => err.push(String(d)));
    const code = await Promise.race([new Promise((r) => c.on("exit", (x) => r(x))), sleep(10000).then(() => "TIMEOUT")]);
    assert.equal(code, 1);
    assert.match(err.join(""), /Unsupported transport/);
  });

  await check("stdio: --principal/--role flags are the caller identity seen by policy", async () => {
    const { configPath: restricted } = makeIsolatedConfig({ transform: RESTRICT_PRINCIPALS });
    const bob = stdioClient(restricted, ["--principal", "bob", "--role", "agent"]);
    const rb = await bob.ask({ jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT 1") });
    assert.equal(rb.result.isError, true);
    assert.equal(rb.result.structuredContent.code, "UNAUTHORIZED_ROLE");
    assert.match(rb.result.structuredContent.message, /'bob'/);
    bob.child.kill();
    const alice = stdioClient(restricted, ["--principal", "alice", "--role", "agent"]);
    const ra = await alice.ask({ jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT 1") });
    assert.equal(ra.result.isError, false);
    alice.child.kill();
  });
  check = checkOnShared;
}

// ---------------------------------------------------------------------------------------------------------------
// 5. Streamable HTTP transport
// ---------------------------------------------------------------------------------------------------------------
async function httpSuite() {
  // ---- Server A: example config verbatim, DB_MCP_AUTH_TOKEN / DB_MCP_ADMIN_TOKEN NOT set in the environment ----
  // F01-B1 (fixed): an unresolvable env: token reference must stop startup instead of disabling auth.
  const A = await httpServer();
  await check("http: auth_token='env:DB_MCP_AUTH_TOKEN' with env var unset fails closed (server refuses to start)", async () => {
    assert.ok(!A.up, "server started although its configured auth token could not be resolved");
    assert.match(A.stderr.join(""), /DB_MCP_AUTH_TOKEN|could not be resolved/i);
  });

  // The rest of the HTTP checks run against a server with tokens configured.
  const B = await httpServer({ env: { DB_MCP_AUTH_TOKEN: "agent-tok", DB_MCP_ADMIN_TOKEN: "admin-tok" } });
  info(`http startup -> /health 200: ${B.startupMs} ms`);
  await check("http: server starts and /health returns 200 JSON {status:'ok', tools, connections, server_name, server_version}", async () => {
    assert.ok(B.up, `server not up: ${B.stderr.join("")}`);
    const r = await fetch(`${B.base}/health`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type") || "", /application\/json/);
    const b = await r.json();
    assert.equal(b.status, "ok");
    assert.equal(b.tools, EXPECTED_TOOL_COUNT);
    assert.equal(typeof b.connections, "number");
    assert.equal(typeof b.server_name, "string");
    assert.equal(typeof b.server_version, "string");
  });

  await check("http: /metrics returns 200 JSON with numeric counters", async () => {
    const r = await fetch(`${B.base}/metrics`);
    assert.equal(r.status, 200);
    const b = await r.json();
    assert.equal(b.status, "ok");
    assert.equal(typeof b.audit_events_total, "number");
    assert.equal(b.registered_tools, EXPECTED_TOOL_COUNT);
    assert.equal(typeof b.configured_connections, "number");
  });

  await check("http: /admin/approve without credentials is rejected (401)", async () => {
    const r = await post(B.base, { change_id: "chg_does_not_exist", approver: "mallory" }, {}, "/admin/approve");
    assert.ok([401, 403].includes(r.status), `expected 401/403, got ${r.status}: ${(await r.text()).slice(0, 200)}`);
  });

  await check("http: GET /mcp -> 405 (no SSE stream offered), DELETE /mcp -> 405, PUT /mcp -> 405", async () => {
    assert.equal((await fetch(`${B.base}/mcp`)).status, 405);
    assert.equal((await fetch(`${B.base}/mcp`, { headers: { accept: "text/event-stream" } })).status, 405);
    assert.equal((await fetch(`${B.base}/mcp`, { method: "DELETE" })).status, 405);
    assert.equal((await fetch(`${B.base}/mcp`, { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" })).status, 405);
  });

  await check("http: unknown paths -> 404", async () => {
    assert.equal((await fetch(`${B.base}/nope`)).status, 404);
    assert.equal((await fetch(`${B.base}/`)).status, 404);
    assert.equal((await post(B.base, {}, {}, "/mcp/extra")).status, 404);
  });
  const AUTH = { authorization: "Bearer agent-tok" };
  await check("http: server with env tokens starts; /health and /metrics stay unauthenticated", async () => {
    assert.ok(B.up, B.stderr.join(""));
    assert.equal((await fetch(`${B.base}/health`)).status, 200);
    assert.equal((await fetch(`${B.base}/metrics`)).status, 200);
  });

  await check("http: POST /mcp without bearer -> 401 with JSON-RPC error body (id echoed)", async () => {
    const r = await post(B.base, { jsonrpc: "2.0", id: "u1", method: "tools/list" });
    assert.equal(r.status, 401);
    const b = await r.json();
    assert.equal(b.jsonrpc, "2.0");
    assert.equal(b.id, "u1");
    assert.equal(typeof b.error.code, "number");
    assert.match(b.error.message, /unauthori[sz]ed/i);
  });

  await check("http: POST /mcp with wrong bearer / admin token / Basic / token-prefix -> 401", async () => {
    for (const authorization of ["Bearer wrong", "Bearer admin-tok", "Basic YWdlbnQtdG9r", "Bearer agent-tok-extra", "Token agent-tok"]) {
      const r = await post(B.base, { jsonrpc: "2.0", id: 1, method: "ping" }, { authorization });
      assert.equal(r.status, 401, `authorization '${authorization}' got ${r.status}`);
    }
  });

  await check("http: 401 carries WWW-Authenticate: Bearer (RFC 6750 / MCP auth)", async () => { // KNOWN-BUG: F01-B6
    const r = await post(B.base, { jsonrpc: "2.0", id: 1, method: "ping" });
    assert.equal(r.status, 401);
    assert.match(r.headers.get("www-authenticate") || "", /Bearer/i, "WWW-Authenticate header missing");
  });

  await check("http: POST /mcp with correct bearer -> 200, tools/list has 16 tools, content-type application/json", async () => {
    const r = await post(B.base, { jsonrpc: "2.0", id: 1, method: "tools/list" }, AUTH);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type") || "", /application\/json/);
    const b = await r.json();
    assert.equal(b.id, 1);
    assert.equal(b.result.tools.length, EXPECTED_TOOL_COUNT);
  });

  await check("http: bearer scheme is case-insensitive per RFC 7235 (Bearer / bearer)", async () => {
    assert.equal((await post(B.base, { jsonrpc: "2.0", id: 1, method: "ping" }, { authorization: "bearer agent-tok" })).status, 200);
    assert.equal((await post(B.base, { jsonrpc: "2.0", id: 1, method: "ping" }, { authorization: "Bearer agent-tok" })).status, 200);
  });

  await check("http: initialize / ping / unknown method / string id over HTTP behave like stdio", async () => {
    const i = await (await post(B.base, { jsonrpc: "2.0", id: "i", method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "f01", version: "1" } } }, { ...AUTH, "mcp-protocol-version": "2025-06-18" })).json();
    assert.ok(["2025-06-18", "2024-11-05"].includes(i.result.protocolVersion));
    assert.equal(typeof i.result.capabilities.tools, "object");
    const p = await (await post(B.base, { jsonrpc: "2.0", id: "s-1", method: "ping" }, AUTH)).json();
    assert.deepEqual(p, { jsonrpc: "2.0", id: "s-1", result: {} });
    const u = await post(B.base, { jsonrpc: "2.0", id: 9, method: "nope" }, AUTH);
    assert.equal(u.status, 200);
    assert.equal((await u.json()).error.code, -32601);
  });

  await check("http: invalid JSON body -> 400; non-request JSON -> 4xx; missing content-type -> 415; server alive", async () => {
    assert.equal((await post(B.base, "{not json", AUTH)).status, 400);
    assert.equal((await post(B.base, "", AUTH)).status, 400);
    const nr = await post(B.base, { foo: 1 }, AUTH);
    assert.ok([400, 422].includes(nr.status), `non-request JSON got ${nr.status}`);
    assert.equal((await fetch(`${B.base}/mcp`, { method: "POST", headers: AUTH, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) })).status, 415);
    assert.equal((await post(B.base, { jsonrpc: "2.0", id: 1, method: "ping" }, { ...AUTH, "content-type": "application/json; charset=utf-8" })).status, 200);
  });
  {
    const r = await post(B.base, "{not json");
    info(`http: unauthenticated invalid-JSON body -> ${r.status} (body is parsed by the Json extractor before the bearer check, main.rs:175-177)`);
    const bat = await post(B.base, [{ jsonrpc: "2.0", id: 1, method: "ping" }], AUTH);
    info(`http: JSON-RPC batch array -> ${bat.status} (batching unsupported; fine for 2024-11-05 / 2025-06-18, would violate 2025-03-26 MUST)`);
  }

  await check("http: POST of a notification (notifications/initialized) -> 202 Accepted with empty body", async () => { // KNOWN-BUG: F01-B3
    const r = await post(B.base, { jsonrpc: "2.0", method: "notifications/initialized" }, AUTH);
    const text = await r.text();
    assert.equal(r.status, 202, `got ${r.status} body=${text.slice(0, 120)}`);
    assert.equal(text, "");
  });

  await check("http: tools/call result shape over HTTP (content[] + structuredContent + isError)", async () => {
    const ok = await (await post(B.base, { jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT 2 AS two") }, AUTH)).json();
    assert.equal(ok.result.isError, false);
    assert.deepEqual(JSON.parse(ok.result.content[0].text), ok.result.structuredContent);
    assert.deepEqual(ok.result.structuredContent.rows, [[2]]);
    const den = await (await post(B.base, { jsonrpc: "2.0", id: 2, method: "tools/call", params: callParams("SELECT * FROM internal_secrets") }, AUTH)).json();
    assert.equal(den.result.isError, true);
    assert.equal(den.result.structuredContent.code, "RESTRICTED_TABLE_FORBIDDEN");
    const miss = await (await post(B.base, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "execute_query", arguments: {} } }, AUTH)).json();
    assert.equal(miss.result.isError, true);
    assert.equal(miss.result.structuredContent.code, "INVALID_ARGUMENT");
  });

  await check("http: /metrics audit_events_total increases after tools/call", async () => {
    const before = (await (await fetch(`${B.base}/metrics`)).json()).audit_events_total;
    await post(B.base, { jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT 3") }, AUTH);
    const after = (await (await fetch(`${B.base}/metrics`)).json()).audit_events_total;
    assert.ok(after > before, `${before} -> ${after}`);
  });

  await check("http: 1 MB request body accepted; oversized body rejected without killing the server", async () => {
    const r = await post(B.base, { jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT '" + "x".repeat(1024 * 1024) + "' AS big") }, AUTH);
    assert.equal(r.status, 200);
    let bigStatus;
    try { const rr = await post(B.base, { jsonrpc: "2.0", id: 2, method: "tools/call", params: callParams("SELECT '" + "y".repeat(3 * 1024 * 1024) + "' AS big") }, AUTH); bigStatus = rr.status; }
    catch (e) { bigStatus = `fetch error ${e.cause ? e.cause.code : e.message}`; }
    info(`http: 3 MB body -> ${bigStatus} (axum default 2 MB body limit; connection is reset before the client can read a 413)`);
    assert.equal(B.child.exitCode, null);
    assert.equal((await post(B.base, { jsonrpc: "2.0", id: 3, method: "ping" }, AUTH)).status, 200);
  });

  await check("http: invalid UTF-8 in body -> 400 and server alive", async () => {
    const r = await fetch(`${B.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", ...AUTH }, body: Buffer.concat([Buffer.from('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"'), Buffer.from([0xff]), Buffer.from('"}}')]) });
    assert.equal(r.status, 400);
    assert.equal(B.child.exitCode, null);
  });

  await check("http: 20 parallel POST /mcp -> every id answered with its own payload", async () => {
    const t = Date.now();
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => post(B.base, { jsonrpc: "2.0", id: 500 + i, method: "tools/call", params: callParams(`SELECT ${i} AS n`) }, AUTH).then((x) => x.json())));
    info(`20 parallel HTTP tools/call answered in ${Date.now() - t} ms`);
    rs.forEach((x, i) => { assert.equal(x.id, 500 + i); assert.equal(x.result.structuredContent.rows[0][0], i); });
  });

  await check("http: requests are served concurrently (ping is not blocked behind a slow query)", async () => {
    const t = Date.now();
    const slow = post(B.base, { jsonrpc: "2.0", id: "slow", method: "tools/call", params: callParams(SLOW_SQL) }, AUTH).then(() => Date.now() - t);
    await sleep(30);
    const pingMs = await post(B.base, { jsonrpc: "2.0", id: "fast", method: "ping" }, AUTH).then(() => Date.now() - t);
    const slowMs = await slow;
    info(`http concurrency: ping answered at ${pingMs} ms, slow query at ${slowMs} ms`);
    assert.ok(pingMs < slowMs, `ping (${pingMs} ms) waited for slow query (${slowMs} ms)`);
  });

  await check("http: /admin/approve requires the admin token (401 without / with agent token), 400 structured denial for unknown change", async () => {
    const payload = { change_id: "chg_does_not_exist", approver: "release-admin", comment: "f01" };
    assert.equal((await post(B.base, payload, {}, "/admin/approve")).status, 401);
    assert.equal((await post(B.base, payload, AUTH, "/admin/approve")).status, 401);
    const r = await post(B.base, payload, { authorization: "Bearer admin-tok" }, "/admin/approve");
    assert.equal(r.status, 400);
    const b = await r.json();
    assert.equal(b.status, "denied");
    assert.ok([400, 422].includes((await post(B.base, { nope: 1 }, { authorization: "Bearer admin-tok" }, "/admin/approve")).status));
  });

  // ---- Server C: principal restriction proves x-mcp-principal / x-mcp-role reach policy + audit ----
  const C = await httpServer({ transform: RESTRICT_PRINCIPALS, extraArgs: ["--principal", "default-http", "--role", "agent"] });
  await check("http: x-mcp-principal / x-mcp-role headers are the identity evaluated by policy; --principal is the fallback", async () => {
    assert.ok(C.up, C.stderr.join(""));
    const q = { jsonrpc: "2.0", id: 1, method: "tools/call", params: callParams("SELECT 1") };
    const def = await (await post(C.base, q)).json();
    assert.equal(def.result.structuredContent.code, "UNAUTHORIZED_ROLE");
    assert.match(def.result.structuredContent.message, /'default-http'/);
    const alice = await (await post(C.base, q, { "x-mcp-principal": "alice", "x-mcp-role": "agent" })).json();
    assert.equal(alice.result.isError, false);
    const bob = await (await post(C.base, q, { "x-mcp-principal": "bob", "x-mcp-role": "agent" })).json();
    assert.equal(bob.result.isError, true);
    assert.match(bob.result.structuredContent.message, /'bob'/);
    const viewer = await (await post(C.base, q, { "x-mcp-principal": "alice", "x-mcp-role": "viewer" })).json();
    assert.equal(viewer.result.isError, true);
    assert.match(viewer.result.structuredContent.message, /'viewer'/);
  });

  await check("http: principal/role/transport from headers are recorded in the audit log", async () => {
    await sleep(300);
    const jl = path.join(C.dir, "audit.jsonl");
    assert.ok(fs.existsSync(jl), `no audit.jsonl in ${C.dir}`);
    const events = fs.readFileSync(jl, "utf8").trim().split(/\r?\n/).map((l) => JSON.parse(l));
    const principals = new Set(events.map((e) => e.principal));
    assert.ok(principals.has("alice") && principals.has("bob") && principals.has("default-http"), [...principals].join(","));
    assert.ok(events.every((e) => e.transport === "http"));
    assert.ok(events.some((e) => e.principal === "alice" && e.role === "viewer"));
  });

  await check("http: binding an occupied port -> exit 1 with an error message", async () => {
    const { configPath } = makeIsolatedConfig();
    const dup = spawnServer(["serve", "--transport", "http", "--bind", C.bind, "--config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
    const err = []; dup.stderr.on("data", (d) => err.push(String(d)));
    const code = await Promise.race([new Promise((r) => dup.on("exit", (x) => r(x))), sleep(10000).then(() => "TIMEOUT")]);
    assert.equal(code, 1);
    assert.ok(err.join("").length > 0, "no error printed");
  });

  await check("http: SIGTERM/kill terminates the HTTP server promptly", async () => {
    C.child.kill("SIGTERM");
    assert.notEqual(await C.exitWithin(5000), "TIMEOUT");
  });

  A.child.kill();
  B.child.kill();
}

// ---------------------------------------------------------------------------------------------------------------
(async () => {
  const { configPath, dir } = makeIsolatedConfig();
  info(`isolated config: ${configPath}`);
  info(`binary: ${BINARY}`);
  try {
    await stdioSuite(configPath);
    await httpSuite();
  } finally {
    killAll();
  }
  const known = results.failedNames.length;
  console.log(`\n${results.pass} passed, ${results.fail} failed${known ? ` (failing checks: ${results.failedNames.map((n) => `"${n}"`).join("; ")})` : ""}`);
  console.log(`isolated dir left for inspection: ${dir}`);
  process.exit(results.fail === 0 ? 0 : 1);
})().catch((err) => {
  console.error("FATAL", err);
  killAll();
  process.exit(1);
});
