#!/usr/bin/env node
"use strict";
/**
 * Minimal stdio MCP client for DB-MCP.
 *
 *   node scripts/mcp-call.js [--config <path>] [--principal <id>] [--role <role>] <tool_name> ['<json args>']
 *   node scripts/mcp-call.js --raw <method> ['<json params>']
 *   node scripts/mcp-call.js --batch <file.json>     # [{ "tool": "...", "arguments": {...} }, ...] or [{ "method": "...", "params": {...} }]
 *
 * Prints the JSON-RPC result (structuredContent for tools/call when present) to stdout.
 * Exit code 0 on JSON-RPC success, 2 on JSON-RPC error, 1 on transport failure.
 */
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { spawnDbMcpServer } = require(path.join(__dirname, "..", "npm", "bin", "db-mcp.js"));

function parseArgs(argv) {
  const opts = { config: "config/db-mcp.example.toml", principal: "local-agent", role: "agent", raw: false, batch: null, full: false, timeoutMs: 20000 };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config") opts.config = argv[++i];
    else if (a === "--principal") opts.principal = argv[++i];
    else if (a === "--role") opts.role = argv[++i];
    else if (a === "--raw") opts.raw = true;
    else if (a === "--full") opts.full = true;
    else if (a === "--batch") opts.batch = argv[++i];
    else if (a === "--timeout") opts.timeoutMs = Number(argv[++i]);
    else rest.push(a);
  }
  return { opts, rest };
}

function createClient(opts) {
  const args = ["serve", "--transport", "stdio", "--principal", opts.principal, "--role", opts.role];
  if (opts.config) args.push("--config", opts.config);
  const child = spawnDbMcpServer(args, { cwd: process.cwd(), stdio: ["pipe", "pipe", "pipe"] });
  const stderr = [];
  child.stderr.on("data", (d) => stderr.push(String(d)));
  const pending = new Map();
  const notifications = [];
  const rl = readline.createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    const t = line.trim();
    if (!t) return;
    let msg;
    try { msg = JSON.parse(t); } catch { return; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    } else {
      notifications.push(msg);
    }
  });
  let nextId = 1;
  const rpc = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`timeout waiting for ${method} (id=${id}); stderr=${stderr.join("")}`)); }, opts.timeoutMs);
    pending.set(id, (m) => { clearTimeout(timer); resolve(m); });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
  const notify = (method, params) => { child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n"); };
  const close = () => { try { child.stdin.end(); } catch {} setTimeout(() => { try { child.kill(); } catch {} }, 200); };
  return { child, rpc, notify, close, notifications, stderr };
}

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  const client = createClient(opts);
  let exitCode = 0;
  try {
    const init = await client.rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "db-mcp-call", version: "0.1.0" } });
    if (init.error) throw new Error(`initialize failed: ${JSON.stringify(init.error)}`);
    client.notify("notifications/initialized", {});

    const calls = [];
    if (opts.batch) {
      calls.push(...JSON.parse(fs.readFileSync(opts.batch, "utf8")));
    } else if (opts.raw) {
      calls.push({ method: rest[0], params: rest[1] ? JSON.parse(rest[1]) : {} });
    } else {
      if (!rest[0]) throw new Error("usage: mcp-call.js [--config p] <tool_name> ['{json}'] | --raw <method> ['{json}'] | --batch file.json");
      calls.push({ tool: rest[0], arguments: rest[1] ? JSON.parse(rest[1]) : {} });
    }

    const results = [];
    for (const c of calls) {
      const resp = c.tool
        ? await client.rpc("tools/call", { name: c.tool, arguments: c.arguments || {} })
        : await client.rpc(c.method, c.params || {});
      if (resp.error) { exitCode = 2; results.push({ call: c, error: resp.error }); continue; }
      const r = resp.result;
      results.push(opts.full || !c.tool ? { call: c, result: r } : { call: c, result: r.structuredContent !== undefined ? r.structuredContent : r });
    }
    const out = results.length === 1 ? (results[0].error || results[0].result) : results;
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  } catch (err) {
    process.stderr.write(`[mcp-call] ${err.message}\n`);
    exitCode = 1;
  } finally {
    client.close();
  }
  process.exit(exitCode);
}

if (require.main === module) main();
module.exports = { createClient };
