#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const BIN_WRAPPER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const EXAMPLE_CONFIG = "config/db-mcp.example.toml";

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

function assertSuccessEnvelope(payload, label) {
  assert.equal(payload.status, "ok", `${label}: expected status='ok', got ${JSON.stringify(payload)}`);
  assert.equal(typeof payload.request_id, "string", `${label}: missing request_id`);
  assert.equal(typeof payload.connection, "string", `${label}: missing connection`);
  assert.ok(Array.isArray(payload.columns), `${label}: columns must be array`);
  assert.ok(Array.isArray(payload.rows), `${label}: rows must be array`);
  assert.equal(typeof payload.returned_rows, "number", `${label}: returned_rows must be number`);
  assert.equal(typeof payload.truncated, "boolean", `${label}: truncated must be boolean`);
  assert.ok(Array.isArray(payload.warnings), `${label}: warnings must be array`);
  assert.equal(typeof payload.schema_version, "string", `${label}: schema_version must be string`);
  assert.equal(
    payload._meta?.provenance?.untrusted_content,
    true,
    `${label}: _meta.provenance.untrusted_content must be true`
  );
}

async function testVerifyConfigCli() {
  console.log("[E2E 1/3] Testing CLI verify-config...");
  const res = spawnSync(
    process.execPath,
    [BIN_WRAPPER, "verify-config", "--config", EXAMPLE_CONFIG],
    { cwd: REPO_ROOT, encoding: "utf8" }
  );
  assert.equal(res.status, 0, `verify-config exited with ${res.status}: ${res.stderr}`);
  const parsed = JSON.parse(res.stdout.trim());
  assert.equal(parsed.status, "ok");
  assert.equal(parsed.server_name, "db-mcp");
  assert.equal(parsed.connections, 3);
  console.log("  -> PASS: verify-config returned status='ok'");
}

async function testStdioMcpAndCliApproval() {
  console.log("[E2E 2/3] Testing Local Stdio MCP Server + Out-of-Band CLI Approval...");
  const child = spawn(
    process.execPath,
    [BIN_WRAPPER, "serve", "--transport", "stdio", "--config", EXAMPLE_CONFIG],
    { cwd: REPO_ROOT, stdio: ["pipe", "pipe", "pipe"] }
  );

  const rl = readline.createInterface({ input: child.stdout });
  const pending = new Map();
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    const msg = JSON.parse(trimmed);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const resolve = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  });

  let nextId = 1;
  const rpc = (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Timeout waiting for JSON-RPC id=${id} (${method})`));
      }, 15000);
      pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });

  const callTool = async (name, args = {}) => {
    const resp = await rpc("tools/call", { name, arguments: args });
    assert.ok(resp.result, `tools/call ${name} missing result: ${JSON.stringify(resp)}`);
    return resp.result.structuredContent;
  };

  try {
    const initResp = await rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "e2e-stdio-client", version: "1.0.0" },
    });
    assert.equal(initResp.result.serverInfo.name, "db-mcp");

    const pingResp = await rpc("ping", {});
    assert.deepEqual(pingResp.result, {});

    const toolsResp = await rpc("tools/list", {});
    assert.equal(toolsResp.result.tools.length, 16, "Expected 16 MCP tools");

    assertSuccessEnvelope(await callTool("list_connections"), "list_connections");
    assertSuccessEnvelope(
      await callTool("search_objects", { connection: "local-sqlite", detail_level: "summary" }),
      "search_objects"
    );
    assertSuccessEnvelope(
      await callTool("describe_object", { connection: "local-sqlite", object_name: "users" }),
      "describe_object"
    );

    const traceDepRes = await callTool("trace_table_dependencies", {
      connection: "local-sqlite",
      table_name: "users",
      target_table: "order_items",
      max_depth: 3,
    });
    assertSuccessEnvelope(traceDepRes, "trace_table_dependencies");
    assert.equal(traceDepRes.data.join_path.hops.length, 2, "Expected 2-hop join path users -> orders -> order_items");
    assert.ok(
      traceDepRes.data.join_path.synthesized_join_sql.includes("JOIN main.orders ON"),
      "Expected synthesized JOIN SQL"
    );
    assert.ok(
      traceDepRes.data.mermaid_diagram.includes("flowchart LR"),
      "Expected Mermaid diagram in trace_table_dependencies"
    );

    const callGraphRes = await callTool("get_procedure_call_graph", {
      connection: "prod-postgres",
      procedure_name: "checkout_order",
      direction: "callees",
      max_depth: 5,
    });
    assertSuccessEnvelope(callGraphRes, "get_procedure_call_graph");
    assert.ok(callGraphRes.data.nodes.length >= 3, "Expected >= 3 procedure nodes in call graph");
    assert.ok(callGraphRes.data.call_chains.length >= 1, "Expected call chains in call graph");
    assert.ok(
      callGraphRes.data.mermaid_diagram.includes("flowchart TD"),
      "Expected Mermaid diagram in get_procedure_call_graph"
    );

    const execRes = await callTool("execute_query", {
      connection: "local-sqlite",
      sql: "SELECT id, email, password_hash FROM users WHERE id = 1",
    });
    assertSuccessEnvelope(execRes, "execute_query");
    assert.equal(execRes.rows[0][2], "[REDACTED]", "password_hash must be redacted");

    assertSuccessEnvelope(
      await callTool("explain_query", {
        connection: "local-sqlite",
        sql: "SELECT id, email FROM users WHERE id = 1",
      }),
      "explain_query"
    );
    assertSuccessEnvelope(
      await callTool("run_named_tool", {
        tool_name: "get_user_by_id",
        arguments: { user_id: 1 },
      }),
      "run_named_tool"
    );
    assertSuccessEnvelope(
      await callTool("database_health", { connection: "prod-postgres" }),
      "database_health"
    );
    assertSuccessEnvelope(
      await callTool("analyze_workload", { connection: "prod-postgres", top_n: 5 }),
      "analyze_workload"
    );
    assertSuccessEnvelope(
      await callTool("recommend_indexes", {
        connection: "prod-postgres",
        queries: ["SELECT * FROM orders WHERE user_id = 1 AND status = 'completed'"],
      }),
      "recommend_indexes"
    );

    const snapBefore = await callTool("capture_schema", { connection: "local-sqlite" });
    assertSuccessEnvelope(snapBefore, "capture_schema");

    const propRes = await callTool("propose_change", {
      connection: "local-sqlite",
      sql: "CREATE INDEX idx_orders_e2e_stdio ON orders (user_id)",
    });
    assertSuccessEnvelope(propRes, "propose_change");
    const changeId = propRes.data.change_id;
    assert.ok(changeId.startsWith("chg_"));

    const getRes = await callTool("get_change", { change_id: changeId });
    assertSuccessEnvelope(getRes, "get_change");
    assert.equal(getRes.data.state, "proposed");

    // Out-of-band CLI approval against the shared change store
    const approveCli = spawnSync(
      process.execPath,
      [
        BIN_WRAPPER,
        "approve",
        "--change-id",
        changeId,
        "--approver",
        "dba-admin",
        "--role",
        "admin",
        "--config",
        EXAMPLE_CONFIG,
      ],
      { cwd: REPO_ROOT, encoding: "utf8" }
    );
    assert.equal(approveCli.status, 0, `CLI approve failed: ${approveCli.stderr}`);
    const approveJson = JSON.parse(approveCli.stdout.trim());
    assert.equal(approveJson.status, "ok");
    assert.equal(approveJson.state, "approved");

    const applyRes = await callTool("apply_change", { change_id: changeId });
    assertSuccessEnvelope(applyRes, "apply_change");
    assert.equal(applyRes.data.state, "applied");

    const diffRes = await callTool("diff_schema", {
      base_snapshot: snapBefore.data,
      target_connection: "local-sqlite",
    });
    assertSuccessEnvelope(diffRes, "diff_schema");
    assert.equal(diffRes.data.is_identical, false);
    console.log("  -> PASS: Stdio MCP exercised all 16 tools + out-of-band CLI approval");
  } finally {
    rl.close();
    child.kill();
  }
}

async function testStreamableHttpE2E() {
  console.log("[E2E 3/3] Testing Self-Hosted Streamable HTTP Server + Bearer Auth + Admin Approval...");
  const port = await getFreePort();
  const bindAddr = `127.0.0.1:${port}`;
  const tempConfigRel = "research/traces/e2e-http.temp.toml";
  const tempConfigAbs = path.join(REPO_ROOT, tempConfigRel);
  const baseToml = fs.readFileSync(path.join(REPO_ROOT, EXAMPLE_CONFIG), "utf8");
  const httpToml = baseToml
    .replace('bind = "127.0.0.1:8080"', `bind = "${bindAddr}"`)
    .replace('auth_token = "env:DB_MCP_AUTH_TOKEN"', 'auth_token = "e2e-agent-secret"')
    .replace('admin_token = "env:DB_MCP_ADMIN_TOKEN"', 'admin_token = "e2e-admin-secret"');
  fs.mkdirSync(path.dirname(tempConfigAbs), { recursive: true });
  fs.writeFileSync(tempConfigAbs, httpToml, "utf8");

  const child = spawn(
    process.execPath,
    [BIN_WRAPPER, "serve", "--transport", "http", "--bind", bindAddr, "--config", tempConfigRel],
    { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] }
  );

  try {
    const baseUrl = `http://${bindAddr}`;
    let healthy = false;
    for (let i = 0; i < 40; i++) {
      try {
        const res = await fetch(`${baseUrl}/health`);
        if (res.status === 200) {
          const body = await res.json();
          assert.equal(body.status, "ok");
          assert.equal(body.tools, 16);
          healthy = true;
          break;
        }
      } catch {
        // Wait for server startup
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    assert.ok(healthy, "HTTP server failed to become healthy");

    // 1. Unauthenticated POST /mcp -> 401
    const unauthRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    assert.equal(unauthRes.status, 401, "Unauthenticated POST /mcp must return 401");

    const authHeaders = {
      "content-type": "application/json",
      authorization: "Bearer e2e-agent-secret",
      "x-mcp-principal": "http-agent",
      "x-mcp-role": "agent",
    };

    // 2. Authenticated tools/list
    const listRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    assert.equal(listRes.status, 200);
    const listBody = await listRes.json();
    assert.equal(listBody.result.tools.length, 16);

    // 2b. Authenticated trace_table_dependencies & get_procedure_call_graph over HTTP
    const httpTraceRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 21,
        method: "tools/call",
        params: {
          name: "trace_table_dependencies",
          arguments: {
            connection: "prod-postgres",
            table_name: "users",
            target_table: "order_items",
            max_depth: 3,
          },
        },
      }),
    });
    assert.equal(httpTraceRes.status, 200);
    const httpTracePayload = (await httpTraceRes.json()).result.structuredContent;
    assertSuccessEnvelope(httpTracePayload, "HTTP trace_table_dependencies");
    assert.equal(httpTracePayload.data.join_path.hops.length, 2);

    const httpGraphRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 22,
        method: "tools/call",
        params: {
          name: "get_procedure_call_graph",
          arguments: {
            connection: "analytics-mysql",
            procedure_name: "checkout_order",
            direction: "callees",
            max_depth: 5,
          },
        },
      }),
    });
    assert.equal(httpGraphRes.status, 200);
    const httpGraphPayload = (await httpGraphRes.json()).result.structuredContent;
    assertSuccessEnvelope(httpGraphPayload, "HTTP get_procedure_call_graph");
    assert.ok(httpGraphPayload.data.nodes.length >= 3);

    // 3. Authenticated tools/call execute_query & propose_change
    const execRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "execute_query",
          arguments: { connection: "local-sqlite", sql: "SELECT id, email FROM users ORDER BY id ASC" },
        },
      }),
    });
    assert.equal(execRes.status, 200);
    const execPayload = (await execRes.json()).result.structuredContent;
    assertSuccessEnvelope(execPayload, "HTTP execute_query");

    const propRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "propose_change",
          arguments: {
            connection: "prod-postgres",
            sql: "UPDATE orders SET status = 'completed' WHERE id = 102",
          },
        },
      }),
    });
    assert.equal(propRes.status, 200);
    const propPayload = (await propRes.json()).result.structuredContent;
    assertSuccessEnvelope(propPayload, "HTTP propose_change");
    const changeId = propPayload.data.change_id;

    // 4. POST /admin/approve with admin token
    const approveRes = await fetch(`${baseUrl}/admin/approve`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer e2e-admin-secret",
      },
      body: JSON.stringify({
        change_id: changeId,
        approver: "http-dba-admin",
        role: "admin",
        comment: "Approved over HTTP admin endpoint",
      }),
    });
    assert.equal(approveRes.status, 200);
    const approveBody = await approveRes.json();
    assert.equal(approveBody.status, "ok");
    assert.equal(approveBody.proposal.state, "approved");

    // 5. apply_change over HTTP
    const applyRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "apply_change", arguments: { change_id: changeId } },
      }),
    });
    assert.equal(applyRes.status, 200);
    const applyPayload = (await applyRes.json()).result.structuredContent;
    assertSuccessEnvelope(applyPayload, "HTTP apply_change");
    assert.equal(applyPayload.data.state, "applied");
    console.log("  -> PASS: Streamable HTTP E2E verified /health, 401 auth, /mcp, /admin/approve, and apply_change");
  } finally {
    child.kill();
    try {
      fs.unlinkSync(tempConfigAbs);
    } catch {
      // Ignore cleanup error
    }
  }
}

async function main() {
  await testVerifyConfigCli();
  await testStdioMcpAndCliApproval();
  await testStreamableHttpE2E();
  console.log("\nALL DB-MCP E2E TESTS PASSED (3/3 suites).");
}

main().catch((err) => {
  console.error("E2E Test Failure:", err);
  process.exit(1);
});
