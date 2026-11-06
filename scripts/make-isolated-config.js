#!/usr/bin/env node
"use strict";
/**
 * Create an isolated copy of a DB-MCP config so several servers/tests can run concurrently
 * without sharing SQLite fixture, audit or change-store files.
 *
 *   node scripts/make-isolated-config.js [--source config/db-mcp.example.toml] [--dir <tempdir>] [--mode <ReadOnly|Development|GovernedProduction>]
 *
 * Prints the absolute path of the generated TOML. All relative storage paths in the source config
 * (research/traces/*, research/fixtures/*) are rewritten to live under the isolated directory.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function makeIsolatedConfig(options = {}) {
  const source = path.resolve(options.source || path.join(__dirname, "..", "config", "db-mcp.example.toml"));
  const dir = options.dir ? path.resolve(options.dir) : fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-iso-"));
  fs.mkdirSync(dir, { recursive: true });
  const toPosix = (p) => p.replace(/\\/g, "/");
  let text = fs.readFileSync(source, "utf8");
  text = text
    .replace(/sqlite:\/\/research\/fixtures\/([A-Za-z0-9_.-]+)/g, (_, f) => `sqlite://${toPosix(path.join(dir, f))}`)
    .replace(/"research\/traces\/([A-Za-z0-9_.-]+)"/g, (_, f) => `"${toPosix(path.join(dir, f))}"`)
    .replace(/"\.db-mcp\/([A-Za-z0-9_.-]+)"/g, (_, f) => `"${toPosix(path.join(dir, f))}"`)
    .replace(/sqlite:\/\/\.db-mcp\/([A-Za-z0-9_.-]+)/g, (_, f) => `sqlite://${toPosix(path.join(dir, f))}`);
  if (options.mode) {
    text = text.replace(/^default_mode\s*=\s*"[A-Za-z]+"/m, `default_mode = "${options.mode}"`);
  }
  if (typeof options.transform === "function") {
    text = options.transform(text);
  }
  const out = path.join(dir, options.fileName || "db-mcp.toml");
  fs.writeFileSync(out, text);
  return { configPath: out, dir };
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--source") opt.source = argv[++i];
    else if (argv[i] === "--dir") opt.dir = argv[++i];
    else if (argv[i] === "--mode") opt.mode = argv[++i];
  }
  process.stdout.write(makeIsolatedConfig(opt).configPath + "\n");
}

module.exports = { makeIsolatedConfig };
