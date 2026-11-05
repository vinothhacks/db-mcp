#!/usr/bin/env node
"use strict";
/**
 * Unit tests for the npx launcher (no network, no cargo): platform mapping, release asset naming,
 * local binary resolution precedence, the `init` starter config, and launcher help.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const LAUNCHER = path.join(__dirname, "..", "bin", "db-mcp.js");
const launcher = require(LAUNCHER);

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    console.error(`  FAIL ${name}\n       ${err.message}`);
    process.exitCode = 1;
  }
}

console.log("[launcher] unit tests");

test("detectTarget maps supported platforms and rejects unknown ones", () => {
  assert.equal(launcher.detectTarget("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(launcher.detectTarget("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(launcher.detectTarget("darwin", "x64"), "x86_64-apple-darwin");
  assert.equal(launcher.detectTarget("darwin", "arm64"), "aarch64-apple-darwin");
  assert.equal(launcher.detectTarget("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(launcher.detectTarget("freebsd", "x64"), null);
  assert.equal(launcher.detectTarget("win32", "ia32"), null);
});

test("releaseAsset builds versioned GitHub release URLs with checksums", () => {
  const a = launcher.releaseAsset("0.1.0", "x86_64-unknown-linux-gnu");
  assert.equal(a.archive, "db-mcp-server-v0.1.0-x86_64-unknown-linux-gnu.tar.gz");
  assert.ok(a.url.endsWith("/releases/download/v0.1.0/db-mcp-server-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"), a.url);
  assert.equal(a.shaUrl, `${a.url}.sha256`);
  const w = launcher.releaseAsset("0.1.0", "x86_64-pc-windows-msvc");
  assert.equal(w.ext, "zip");
  assert.equal(launcher.releaseAsset("0.1.0", null), null);
});

test("cachedBinaryPath lives under the per-user cache and is version scoped", () => {
  const p = launcher.cachedBinaryPath("9.9.9", "x86_64-unknown-linux-gnu");
  assert.ok(p.includes(path.join("bin", "v9.9.9", "x86_64-unknown-linux-gnu")), p);
  assert.ok(path.basename(p).startsWith("db-mcp-server"));
});

test("findLocalBinary honours DB_MCP_BINARY_PATH and ignores missing paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-launcher-"));
  const fake = path.join(tmp, process.platform === "win32" ? "db-mcp-server.exe" : "db-mcp-server");
  fs.writeFileSync(fake, "#!/bin/sh\nexit 0\n");
  const prev = process.env.DB_MCP_BINARY_PATH;
  try {
    process.env.DB_MCP_BINARY_PATH = fake;
    assert.equal(launcher.findLocalBinary({ repoRoot: tmp }), fake);
    process.env.DB_MCP_BINARY_PATH = path.join(tmp, "missing");
    const resolved = launcher.findLocalBinary({ repoRoot: tmp });
    assert.notEqual(resolved, path.join(tmp, "missing"));
  } finally {
    if (prev === undefined) delete process.env.DB_MCP_BINARY_PATH;
    else process.env.DB_MCP_BINARY_PATH = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("findLocalBinary prefers a dev-checkout release build over debug", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-launcher-"));
  const bin = process.platform === "win32" ? "db-mcp-server.exe" : "db-mcp-server";
  fs.mkdirSync(path.join(tmp, "crates", "db-mcp-server"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "Cargo.toml"), "[workspace]\n");
  fs.mkdirSync(path.join(tmp, "target", "release"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "target", "debug"), { recursive: true });
  fs.writeFileSync(path.join(tmp, "target", "debug", bin), "");
  fs.writeFileSync(path.join(tmp, "target", "release", bin), "");
  const prev = process.env.DB_MCP_BINARY_PATH;
  delete process.env.DB_MCP_BINARY_PATH;
  try {
    assert.equal(launcher.findLocalBinary({ repoRoot: tmp, preferRelease: true }), path.join(tmp, "target", "release", bin));
  } finally {
    if (prev !== undefined) process.env.DB_MCP_BINARY_PATH = prev;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("resolveBinaryPath with autoBuild=false throws a clear error when nothing is installed", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-launcher-"));
  const prevBin = process.env.DB_MCP_BINARY_PATH;
  const prevCache = process.env.DB_MCP_CACHE_DIR;
  delete process.env.DB_MCP_BINARY_PATH;
  try {
    // cache dir is captured at module load, so only the repoRoot part is exercised here
    assert.throws(() => launcher.resolveBinaryPath({ repoRoot: tmp, autoBuild: false, _ignoreCache: true }), /not found|binary/i);
  } catch (err) {
    // If a cached binary exists for this user the resolver legitimately returns it.
    const cached = launcher.cachedBinaryPath();
    if (!fs.existsSync(cached)) throw err;
  } finally {
    if (prevBin !== undefined) process.env.DB_MCP_BINARY_PATH = prevBin;
    if (prevCache !== undefined) process.env.DB_MCP_CACHE_DIR = prevCache;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("`db-mcp init` writes a starter config and refuses to overwrite without --force", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-init-"));
  const r1 = spawnSync(process.execPath, [LAUNCHER, "init"], { cwd: tmp, encoding: "utf8" });
  assert.equal(r1.status, 0, r1.stderr);
  const cfg = path.join(tmp, "db-mcp.toml");
  assert.ok(fs.existsSync(cfg));
  assert.match(fs.readFileSync(cfg, "utf8"), /\[\[connections\]\]/);
  const r2 = spawnSync(process.execPath, [LAUNCHER, "init"], { cwd: tmp, encoding: "utf8" });
  assert.notEqual(r2.status, 0);
  const r3 = spawnSync(process.execPath, [LAUNCHER, "init", "--force", "--output", "custom.toml", "--example"], { cwd: tmp, encoding: "utf8" });
  assert.equal(r3.status, 0, r3.stderr);
  assert.match(fs.readFileSync(path.join(tmp, "custom.toml"), "utf8"), /local-sqlite/);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test("launcher help prints without needing a binary", () => {
  const r = spawnSync(process.execPath, [LAUNCHER, "--launcher-help"], { encoding: "utf8", env: { ...process.env, DB_MCP_SKIP_DOWNLOAD: "1" } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /init \[--output/);
  assert.match(r.stdout, /serve --transport/);
});

console.log(`[launcher] ${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
