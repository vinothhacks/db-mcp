#!/usr/bin/env node
"use strict";

/**
 * DB-MCP npx launcher.
 *
 * Resolves the native `db-mcp-server` binary and forwards every CLI flag, env var and stdio stream to it.
 *
 * Resolution order:
 *   1. $DB_MCP_BINARY_PATH
 *   2. a dev checkout build: <repo>/target/release|debug/db-mcp-server[.exe]
 *   3. <package>/dist/bin/db-mcp-server[.exe]
 *   4. the per-user cache: ~/.db-mcp/bin/v<version>/<target>/db-mcp-server[.exe]
 *   5. download the prebuilt release asset for this platform (SHA-256 verified) into the cache
 *   6. build from source with cargo (dev checkout) or `cargo install --git` into the cache
 *
 * Launcher-only subcommands (everything else is forwarded to the binary):
 *   db-mcp init [--output db-mcp.toml] [--force]   write a starter configuration
 *   db-mcp install                                 pre-fetch / build the binary and print its path
 *   db-mcp where                                   print the resolved binary path
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

const PKG_ROOT = path.resolve(__dirname, "..", "..");
const PKG = readJson(path.join(PKG_ROOT, "package.json")) || { name: "db-mcp", version: "0.0.0" };
const VERSION = process.env.DB_MCP_VERSION || PKG.version;
const REPO_SLUG = process.env.DB_MCP_REPO || "vinothhacks/db-mcp";
const RELEASE_BASE_URL = process.env.DB_MCP_RELEASE_BASE_URL || `https://github.com/${REPO_SLUG}/releases/download`;
const IS_WINDOWS = process.platform === "win32";
const BIN_BASENAME = "db-mcp-server";
const BIN_NAME = IS_WINDOWS ? `${BIN_BASENAME}.exe` : BIN_BASENAME;
const CACHE_ROOT = process.env.DB_MCP_CACHE_DIR || path.join(os.homedir(), ".db-mcp");
const STARTER_CONFIG = path.join(PKG_ROOT, "config", "db-mcp.starter.toml");
const EXAMPLE_CONFIG = path.join(PKG_ROOT, "config", "db-mcp.example.toml");

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function log(msg) {
  if (process.env.DB_MCP_QUIET === "1") return;
  process.stderr.write(`[db-mcp] ${msg}\n`);
}

function toWslPath(winPath) {
  return String(winPath)
    .replace(/^([A-Za-z]):[\\/]/, (_, drive) => `/mnt/${drive.toLowerCase()}/`)
    .replace(/\\/g, "/");
}

/** Rust target triple for the current platform, or null when no prebuilt asset exists. */
function detectTarget(platform = process.platform, arch = process.arch) {
  const table = {
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
    "darwin-x64": "x86_64-apple-darwin",
    "darwin-arm64": "aarch64-apple-darwin",
    "win32-x64": "x86_64-pc-windows-msvc",
  };
  return table[`${platform}-${arch}`] || null;
}

function releaseAsset(version = VERSION, target = detectTarget()) {
  if (!target) return null;
  const ext = target.includes("windows") ? "zip" : "tar.gz";
  const name = `${BIN_BASENAME}-v${version}-${target}`;
  return {
    name,
    archive: `${name}.${ext}`,
    url: `${RELEASE_BASE_URL}/v${version}/${name}.${ext}`,
    shaUrl: `${RELEASE_BASE_URL}/v${version}/${name}.${ext}.sha256`,
    ext,
    target,
  };
}

function cachedBinaryPath(version = VERSION, target = detectTarget() || `${process.platform}-${process.arch}`) {
  return path.join(CACHE_ROOT, "bin", `v${version}`, target, BIN_NAME);
}

function isDevCheckout(root) {
  return fs.existsSync(path.join(root, "Cargo.toml")) && fs.existsSync(path.join(root, "crates", "db-mcp-server"));
}

function isExecutableFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Synchronously locate an already-present binary. Returns null when nothing is installed yet.
 */
function findLocalBinary(options = {}) {
  const repoRoot = options.repoRoot ? path.resolve(options.repoRoot) : PKG_ROOT;

  if (process.env.DB_MCP_BINARY_PATH) {
    const p = path.resolve(process.env.DB_MCP_BINARY_PATH);
    if (isExecutableFile(p)) return p;
    log(`DB_MCP_BINARY_PATH is set but ${p} does not exist; ignoring`);
  }

  const candidates = [];
  if (isDevCheckout(repoRoot)) {
    const release = path.join(repoRoot, "target", "release", BIN_NAME);
    const debug = path.join(repoRoot, "target", "debug", BIN_NAME);
    candidates.push(release, debug);
    if (IS_WINDOWS) {
      // A Linux build left behind by WSL can still be used through wsl.exe (dev convenience only).
      candidates.push(path.join(repoRoot, "target", "release", BIN_BASENAME), path.join(repoRoot, "target", "debug", BIN_BASENAME));
    }
    if (options.preferRelease && isExecutableFile(release)) return release;
  }
  candidates.push(path.join(repoRoot, "dist", "bin", BIN_NAME));
  candidates.push(cachedBinaryPath());

  const existing = candidates.filter(isExecutableFile);
  if (existing.length === 0) return null;
  if (existing.length === 1) return existing[0];

  // Prefer native executables, then the most recently built one so fresh builds are never shadowed.
  const native = existing.filter((p) => !IS_WINDOWS || p.toLowerCase().endsWith(".exe"));
  const pool = native.length ? native : existing;
  pool.sort((a, b) => {
    try {
      return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs;
    } catch {
      return 0;
    }
  });
  return pool[0];
}

async function fetchBuffer(url, { expectText = false } = {}) {
  if (typeof fetch !== "function") {
    throw new Error("global fetch is unavailable; Node.js >= 18 is required to download prebuilt binaries");
  }
  const res = await fetch(url, { redirect: "follow", headers: { "user-agent": `db-mcp-launcher/${VERSION}` } });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${url}`);
  }
  if (expectText) return await res.text();
  return Buffer.from(await res.arrayBuffer());
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function extractArchive(archivePath, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  // bsdtar (shipped with Windows 10+, macOS and most Linux distros) handles both .tar.gz and .zip.
  let res = spawnSync("tar", ["-xf", archivePath, "-C", destDir], { stdio: "pipe", encoding: "utf8" });
  if (res.status === 0) return;
  if (IS_WINDOWS && archivePath.endsWith(".zip")) {
    res = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${destDir}' -Force`],
      { stdio: "pipe", encoding: "utf8" }
    );
    if (res.status === 0) return;
  }
  throw new Error(`failed to extract ${archivePath}: ${(res.stderr || res.error?.message || "").trim()}`);
}

function findFileRecursive(dir, fileName, depth = 0) {
  if (depth > 4) return null;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findFileRecursive(full, fileName, depth + 1);
      if (found) return found;
    } else if (entry.name === fileName) {
      return full;
    }
  }
  return null;
}

/**
 * Download the prebuilt release asset for this platform into the cache and return the binary path.
 */
async function downloadPrebuilt({ version = VERSION } = {}) {
  const asset = releaseAsset(version);
  if (!asset) {
    throw new Error(`no prebuilt binary is published for ${process.platform}-${process.arch}`);
  }
  const dest = cachedBinaryPath(version, asset.target);
  const destDir = path.dirname(dest);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-dl-"));
  try {
    log(`downloading ${asset.url}`);
    const archive = await fetchBuffer(asset.url);
    let expected = null;
    try {
      expected = (await fetchBuffer(asset.shaUrl, { expectText: true })).trim().split(/\s+/)[0].toLowerCase();
    } catch (err) {
      log(`checksum file unavailable (${err.message}); continuing without verification`);
    }
    if (expected) {
      const actual = sha256(archive);
      if (actual !== expected) {
        throw new Error(`SHA-256 mismatch for ${asset.archive}: expected ${expected}, got ${actual}`);
      }
      log("sha256 verified");
    }
    const archivePath = path.join(tmpDir, asset.archive);
    fs.writeFileSync(archivePath, archive);
    const extractDir = path.join(tmpDir, "extract");
    extractArchive(archivePath, extractDir);
    const binary = findFileRecursive(extractDir, BIN_NAME);
    if (!binary) {
      throw new Error(`archive ${asset.archive} did not contain ${BIN_NAME}`);
    }
    fs.mkdirSync(destDir, { recursive: true });
    fs.copyFileSync(binary, dest);
    if (!IS_WINDOWS) fs.chmodSync(dest, 0o755);
    const exampleCfg = findFileRecursive(extractDir, "db-mcp.example.toml");
    if (exampleCfg) fs.copyFileSync(exampleCfg, path.join(destDir, "db-mcp.example.toml"));
    log(`installed ${dest}`);
    return dest;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function haveCargo() {
  const res = spawnSync("cargo", ["--version"], { stdio: "pipe" });
  return !res.error && res.status === 0;
}

/**
 * Build from source: `cargo build` inside a dev checkout, otherwise `cargo install --git` into the cache.
 */
function buildWithCargo({ repoRoot = PKG_ROOT, version = VERSION } = {}) {
  if (!haveCargo()) {
    throw new Error("cargo is not installed (https://rustup.rs) and no prebuilt binary could be downloaded");
  }
  if (isDevCheckout(repoRoot)) {
    log("building db-mcp-server from source with cargo (this can take several minutes)...");
    const res = spawnSync("cargo", ["build", "--release", "-p", "db-mcp-server"], { cwd: repoRoot, env: process.env, stdio: "inherit" });
    if (res.status !== 0) {
      throw new Error(`cargo build failed: ${res.error ? res.error.message : `exit code ${res.status}`}`);
    }
    const built = path.join(repoRoot, "target", "release", BIN_NAME);
    if (!isExecutableFile(built)) throw new Error(`cargo build succeeded but ${built} is missing`);
    return built;
  }
  const dest = cachedBinaryPath(version);
  const root = path.dirname(dest);
  fs.mkdirSync(root, { recursive: true });
  log(`installing db-mcp-server v${version} from https://github.com/${REPO_SLUG} with cargo (this can take several minutes)...`);
  const res = spawnSync(
    "cargo",
    ["install", "--git", `https://github.com/${REPO_SLUG}`, "--tag", `v${version}`, "--locked", "--root", root, "db-mcp-server"],
    { env: process.env, stdio: "inherit" }
  );
  if (res.status !== 0) {
    throw new Error(`cargo install failed: ${res.error ? res.error.message : `exit code ${res.status}`}`);
  }
  const installed = path.join(root, "bin", BIN_NAME);
  if (!isExecutableFile(installed)) throw new Error(`cargo install succeeded but ${installed} is missing`);
  fs.copyFileSync(installed, dest);
  if (!IS_WINDOWS) fs.chmodSync(dest, 0o755);
  return dest;
}

/**
 * Make sure a binary exists, downloading or building it when needed. Async.
 */
async function ensureBinary(options = {}) {
  const local = findLocalBinary(options);
  if (local) return local;

  const errors = [];
  if (process.env.DB_MCP_SKIP_DOWNLOAD !== "1") {
    try {
      return await downloadPrebuilt(options);
    } catch (err) {
      errors.push(`download: ${err.message}`);
      log(`prebuilt download failed: ${err.message}`);
    }
  } else {
    errors.push("download: skipped (DB_MCP_SKIP_DOWNLOAD=1)");
  }
  try {
    return buildWithCargo(options);
  } catch (err) {
    errors.push(`cargo: ${err.message}`);
  }
  throw new Error(
    `could not obtain db-mcp-server v${VERSION} for ${process.platform}-${process.arch}:\n  - ${errors.join("\n  - ")}\n` +
      `Set DB_MCP_BINARY_PATH to an existing binary, install Rust (https://rustup.rs), or download a release from https://github.com/${REPO_SLUG}/releases`
  );
}

/**
 * Synchronous resolution kept for programmatic callers (tests, scripts). If nothing is installed yet it
 * delegates the download/build to a child `node db-mcp.js install` so callers do not need to await.
 */
function resolveBinaryPath(options = {}) {
  const local = findLocalBinary(options);
  if (local) return local;
  if (options.autoBuild === false) {
    throw new Error(`db-mcp-server binary not found (looked in target/, dist/bin and ${cachedBinaryPath()})`);
  }
  const res = spawnSync(process.execPath, [__filename, "install", "--quiet-path"], {
    env: process.env,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
  });
  if (res.status !== 0) {
    throw new Error(`failed to install db-mcp-server (exit ${res.status})`);
  }
  const resolved = String(res.stdout || "").trim().split(/\r?\n/).pop();
  if (!resolved || !isExecutableFile(resolved)) {
    throw new Error("installer finished but did not report a usable binary path");
  }
  return resolved;
}

/**
 * Spawn `db-mcp-server` with forwarded CLI arguments, environment variables, and stdio streams.
 */
function spawnDbMcpServer(argsOrOptions = [], maybeOptions = {}) {
  let args;
  let options;
  if (Array.isArray(argsOrOptions)) {
    args = argsOrOptions;
    options = maybeOptions || {};
  } else if (argsOrOptions && typeof argsOrOptions === "object") {
    args = Array.isArray(argsOrOptions.args) ? argsOrOptions.args : [];
    options = argsOrOptions;
  } else {
    args = [];
    options = {};
  }

  const binaryPath = options.binaryPath || resolveBinaryPath(options);
  const cwd = options.cwd || process.cwd();
  const env = { ...process.env, ...(options.env || {}) };
  const stdio = options.stdio || ["pipe", "pipe", "pipe"];

  if (IS_WINDOWS && !binaryPath.toLowerCase().endsWith(".exe")) {
    const wslBin = toWslPath(binaryPath);
    const wslArgs = args.map((arg) => (/^[A-Za-z]:[\\/]/.test(arg) ? toWslPath(arg) : arg));
    return spawn("wsl.exe", ["--exec", wslBin, ...wslArgs], { cwd, env, stdio, windowsHide: true });
  }
  return spawn(binaryPath, args, { cwd, env, stdio, windowsHide: true });
}

function writeStarterConfig(argv) {
  let output = "db-mcp.toml";
  let force = false;
  let template = "starter";
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--output" || argv[i] === "-o") output = argv[++i];
    else if (argv[i] === "--force" || argv[i] === "-f") force = true;
    else if (argv[i] === "--example") template = "example";
    else if (argv[i] === "--help" || argv[i] === "-h") {
      process.stdout.write("usage: db-mcp init [--output db-mcp.toml] [--force] [--example]\n");
      return 0;
    }
  }
  const src = template === "example" ? EXAMPLE_CONFIG : STARTER_CONFIG;
  const dest = path.resolve(output);
  if (fs.existsSync(dest) && !force) {
    process.stderr.write(`[db-mcp] ${dest} already exists (use --force to overwrite)\n`);
    return 1;
  }
  fs.copyFileSync(src, dest);
  process.stdout.write(
    `Wrote ${dest}\n` +
      `Next steps:\n` +
      `  1. Edit the [[connections]] entries (DSNs may use env:VAR or file:/path references).\n` +
      `  2. Validate:  npx ${PKG.name} verify-config --config ${output}\n` +
      `  3. Serve:     npx ${PKG.name} serve --transport stdio --config ${output}\n`
  );
  return 0;
}

function printLauncherHelp() {
  process.stdout.write(
    `${PKG.name} v${VERSION} - launcher for db-mcp-server\n\n` +
      `Launcher commands:\n` +
      `  init [--output db-mcp.toml] [--force] [--example]   write a starter configuration file\n` +
      `  install                                            download/build the native binary and print its path\n` +
      `  where                                              print the resolved binary path\n\n` +
      `Server commands (forwarded to db-mcp-server):\n` +
      `  serve --transport stdio|http [--bind host:port] --config <file> [--principal id] [--role role]\n` +
      `  approve --change-id <chg_id> --approver <principal> [--role admin] [--comment text] --config <file>\n` +
      `  verify-config --config <file>\n\n` +
      `Environment: DB_MCP_BINARY_PATH, DB_MCP_SKIP_DOWNLOAD=1, DB_MCP_RELEASE_BASE_URL, DB_MCP_CACHE_DIR\n\n`
  );
}

async function runCli() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (cmd === "init") {
    process.exit(writeStarterConfig(argv.slice(1)));
  }
  if (cmd === "install" || cmd === "where") {
    try {
      const bin = cmd === "where" ? findLocalBinary() : await ensureBinary();
      if (!bin) {
        process.stderr.write("[db-mcp] no binary installed yet; run `db-mcp install`\n");
        process.exit(1);
      }
      process.stdout.write(`${bin}\n`);
      process.exit(0);
    } catch (err) {
      process.stderr.write(`[db-mcp] ${err.message}\n`);
      process.exit(1);
    }
  }
  if (cmd === "--launcher-help" || cmd === "-h" || cmd === "--help" || cmd === "help" || cmd === undefined) {
    printLauncherHelp();
    if (cmd === "--launcher-help" || cmd === undefined) process.exit(0);
  }

  let binaryPath;
  try {
    binaryPath = await ensureBinary();
  } catch (err) {
    process.stderr.write(`[db-mcp] ${err.message}\n`);
    process.exit(1);
  }

  const child = spawnDbMcpServer(argv, { binaryPath, cwd: process.cwd(), env: process.env, stdio: "inherit" });

  const forwardSignal = (signal) => {
    if (child && !child.killed) {
      try {
        child.kill(signal);
      } catch {
        // child already exited
      }
    }
  };
  process.on("SIGINT", () => forwardSignal("SIGINT"));
  process.on("SIGTERM", () => forwardSignal("SIGTERM"));

  child.on("error", (err) => {
    process.stderr.write(`[db-mcp] Failed to launch ${binaryPath}: ${err.message}\n`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(typeof code === "number" ? code : 0);
  });
}

if (require.main === module) {
  runCli().catch((err) => {
    process.stderr.write(`[db-mcp] ${err.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  VERSION,
  REPO_SLUG,
  detectTarget,
  releaseAsset,
  cachedBinaryPath,
  findLocalBinary,
  resolveBinaryPath,
  ensureBinary,
  downloadPrebuilt,
  buildWithCargo,
  spawnDbMcpServer,
};
