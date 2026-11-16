#!/usr/bin/env node
"use strict";
/**
 * F14 - Installation and packaging experience.
 *
 * Self-contained verification of the npx launcher (`npm/bin/db-mcp.js`), the npm publish contents,
 * the prebuilt-download path (against a LOCAL mock GitHub-release server), the Dockerfile / compose
 * files, the GitHub workflows and the README / docs accuracy.
 *
 * Run from the repo root:  node npm/test/features/14-install-packaging.test.js
 * Exit 0 when every check passes. Needs: node >= 18, npm, tar (GNU or bsdtar), PowerShell on Windows,
 * and ideally a built `target/release/db-mcp-server(.exe)` (download/behaviour checks are skipped without it).
 *
 * Rules honoured: never runs cargo/docker, never touches ~/.db-mcp (DB_MCP_CACHE_DIR -> temp), all state
 * under os.tmpdir(), children are cleaned up.
 *
 * Checks that encode the CORRECT behaviour but currently fail are tagged `// KNOWN-BUG: <id>`.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const LAUNCHER = path.join(REPO_ROOT, "npm", "bin", "db-mcp.js");
const IS_WIN = process.platform === "win32";
const BIN_NAME = IS_WIN ? "db-mcp-server.exe" : "db-mcp-server";
const PKG = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
const BUILT_BINARY = path.join(REPO_ROOT, "target", "release", BIN_NAME);
const HAVE_BINARY = fs.existsSync(BUILT_BINARY);

// All state lives under one temp root; the launcher cache is redirected there before it is required.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "db-mcp-f14-"));
const CACHE_DIR = path.join(TMP, "cache");
process.env.DB_MCP_CACHE_DIR = CACHE_DIR;
delete process.env.DB_MCP_BINARY_PATH;
delete process.env.DB_MCP_VERSION;
delete process.env.DB_MCP_REPO;
delete process.env.DB_MCP_RELEASE_BASE_URL;
const launcher = require(LAUNCHER);

const children = new Set();
let passed = 0;
let failed = 0;
let skipped = 0;
const failures = [];

// The starter config references env:DATABASE_URL / env:MYSQL_URL; unset variables are a config error.
const STARTER_ENV = { DATABASE_URL: "postgres://127.0.0.1:1/x", MYSQL_URL: "mysql://127.0.0.1:1/x" };

function ok(name) {
  passed++;
  console.log(`  ok    ${name}`);
}
function fail(name, err) {
  failed++;
  failures.push(name);
  const msg = String((err && err.message) || err).split("\n").slice(0, 6).join("\n        ");
  console.log(`  FAIL  ${name}\n        ${msg}`);
}
function skip(name, why) {
  skipped++;
  console.log(`  skip  ${name} (${why})`);
}
async function check(name, fn) {
  try {
    const r = await fn();
    if (r === "skip") return;
    ok(name);
  } catch (err) {
    fail(name, err);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const read = (p) => fs.readFileSync(p, "utf8");
const exists = (p) => fs.existsSync(p);
const q = (s) => (/[\s"]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s);
// GNU tar (Git Bash) treats "C:\..." as a remote host; always use the OS bsdtar on Windows.
const TAR = IS_WIN ? path.join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe") : "tar";

/** Minimal environment with no cargo on PATH (only the OS directories needed for tar/powershell/exe launch). */
function strippedEnv(extra = {}) {
  const env = {
    DB_MCP_CACHE_DIR: CACHE_DIR,
    HOME: os.homedir(),
    TMP: os.tmpdir(),
    TEMP: os.tmpdir(),
    TMPDIR: os.tmpdir(),
    ...extra,
  };
  if (IS_WIN) {
    const root = process.env.SystemRoot || "C:\\Windows";
    env.PATH = [path.join(root, "System32"), root, path.join(root, "System32", "WindowsPowerShell", "v1.0")].join(";");
    env.SystemRoot = root;
    env.SYSTEMROOT = root;
    env.USERPROFILE = os.homedir();
    env.HOMEDRIVE = process.env.HOMEDRIVE || "C:";
    env.HOMEPATH = process.env.HOMEPATH || "\\";
    env.COMSPEC = process.env.COMSPEC || path.join(root, "System32", "cmd.exe");
    env.PATHEXT = ".COM;.EXE;.BAT;.CMD";
  } else {
    env.PATH = "/usr/bin:/bin";
  }
  return env;
}

function run(args, opts = {}) {
  const res = spawnSync(process.execPath, args, { encoding: "utf8", timeout: opts.timeout || 60000, ...opts });
  return { status: res.status, stdout: res.stdout || "", stderr: res.stderr || "", error: res.error };
}
function runLauncher(launcherPath, args, opts = {}) {
  return run([launcherPath, ...args], opts);
}
function sh(cmd, args, opts = {}) {
  const res = spawnSync([cmd, ...args.map(q)].join(" "), { shell: true, encoding: "utf8", timeout: 180000, ...opts });
  return { status: res.status, stdout: res.stdout || "", stderr: res.stderr || "" };
}
function getFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close((e) => (e ? reject(e) : resolve(port)));
    });
    s.on("error", reject);
  });
}
function parseYamlMatrixTargets(yaml) {
  const out = [];
  for (const m of yaml.matchAll(/-\s*\{\s*os:\s*([^,]+),\s*target:\s*([^,]+),\s*archive:\s*([^}\s]+)\s*\}/g)) {
    out.push({ os: m[1].trim(), target: m[2].trim(), archive: m[3].trim() });
  }
  return out;
}
function semverGte(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true;
    if ((pa[i] || 0) < (pb[i] || 0)) return false;
  }
  return true;
}
/** Highest `rust-version` declared by any crate pinned in Cargo.lock (from the local cargo registry when present). */
function maxRustVersionFromLock() {
  const lock = read(path.join(REPO_ROOT, "Cargo.lock"));
  const pkgs = [...lock.matchAll(/\[\[package\]\]\s*\nname = "([^"]+)"\nversion = "([^"]+)"/g)].map((m) => ({ name: m[1], version: m[2] }));
  // Floor derived from crates.io metadata (checked 2026-11) for crates present in this lock file.
  const known = { "uuid@1.29.0": "1.89", "icu_normalizer@2.4.0": "1.88", "icu_properties@2.4.0": "1.88", "tokio@1.54.1": "1.85", "hashbrown@0.17.1": "1.85", "indexmap@2.14.2": "1.85" };
  let max = "1.0";
  let who = "none";
  for (const p of pkgs) {
    const k = `${p.name}@${p.version}`;
    if (known[k] && !semverGte(max, known[k])) {
      max = known[k];
      who = k;
    }
  }
  const regRoot = path.join(os.homedir(), ".cargo", "registry", "src");
  if (exists(regRoot)) {
    for (const idx of fs.readdirSync(regRoot)) {
      for (const p of pkgs) {
        const manifest = path.join(regRoot, idx, `${p.name}-${p.version}`, "Cargo.toml");
        if (!exists(manifest)) continue;
        const m = read(manifest).match(/^rust-version\s*=\s*"([^"]+)"/m);
        if (m && !semverGte(max, m[1])) {
          max = m[1];
          who = `${p.name}@${p.version}`;
        }
      }
    }
  }
  return { max, who, count: pkgs.length };
}

// ---------------------------------------------------------------------------------------------
// Mock GitHub release server
// ---------------------------------------------------------------------------------------------
function startMockRelease(rootDir) {
  // The mock must live in a CHILD process: the checks call the launcher with spawnSync, which blocks this
  // process's event loop, so an in-process http server could never answer (every download timed out).
  const hitsFile = path.join(TMP, "mock-hits.log");
  fs.writeFileSync(hitsFile, "");
  const code = `
    const http=require("http"),fs=require("fs"),path=require("path");
    const [root,log]=process.argv.slice(1);
    http.createServer((req,res)=>{
      const rel=decodeURIComponent(req.url.split("?")[0]).replace(/^\\/+/,"");
      fs.appendFileSync(log,rel+"\\n");
      const file=path.join(root,rel);
      if(!rel.includes("..")&&fs.existsSync(file)&&fs.statSync(file).isFile()){
        const buf=fs.readFileSync(file);
        res.writeHead(200,{"content-type":"application/octet-stream","content-length":buf.length});res.end(buf);
      }else{res.writeHead(404,{"content-type":"text/plain"});res.end("Not Found");}
    }).listen(0,"127.0.0.1",function(){console.log(this.address().port)});`;
  const child = spawn(process.execPath, ["-e", code, rootDir, hitsFile], { stdio: ["ignore", "pipe", "inherit"] });
  children.add(child);
  const readHits = () => {
    const m = new Map();
    for (const l of fs.readFileSync(hitsFile, "utf8").split("\n").filter(Boolean)) m.set(l, (m.get(l) || 0) + 1);
    return m;
  };
  const hits = {
    get: (k) => readHits().get(k),
    keys: () => readHits().keys(),
    get size() { return readHits().size; },
  };
  return new Promise((resolve) => {
    child.stdout.once("data", (d) => {
      const port = String(d).trim();
      resolve({
        server: { close: (cb) => { child.kill(); cb(); } },
        hits,
        baseUrl: `http://127.0.0.1:${port}`,
        reset: () => fs.writeFileSync(hitsFile, ""),
      });
    });
  });
}

/**
 * Build a release asset exactly like .github/workflows/release.yml:
 *   dist/<NAME>/{db-mcp-server[.exe],README.md,LICENSE-*,db-mcp.example.toml}
 *   unix:    tar -C dist -czf NAME.tar.gz NAME            (directory inside the archive)
 *   windows: Compress-Archive -Path dist/NAME/* -> NAME.zip (contents at the zip root)
 *   NAME.<ext>.sha256 : "<hex>  <NAME>.<ext>" (Out-File -Encoding ascii => CRLF on Windows)
 */
function buildReleaseAsset({ version, target, ext, outDir, binarySrc, layout }) {
  const name = `db-mcp-server-v${version}-${target}`;
  const stage = path.join(outDir, "stage", name);
  fs.mkdirSync(stage, { recursive: true });
  fs.copyFileSync(binarySrc, path.join(stage, BIN_NAME));
  for (const f of ["README.md", "LICENSE-MIT", "LICENSE-APACHE"]) fs.copyFileSync(path.join(REPO_ROOT, f), path.join(stage, f));
  fs.copyFileSync(path.join(REPO_ROOT, "config", "db-mcp.example.toml"), path.join(stage, "db-mcp.example.toml"));
  const versionDir = path.join(outDir, `v${version}`);
  fs.mkdirSync(versionDir, { recursive: true });
  const archive = path.join(versionDir, `${name}.${ext}`);
  let res;
  if (ext === "zip" && layout === "workflow-flat") {
    res = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", `Compress-Archive -Path '${stage}/*' -DestinationPath '${archive}' -Force`],
      { encoding: "utf8" }
    );
  } else if (ext === "zip") {
    res = spawnSync(TAR, ["-a", "-cf", archive, "-C", path.dirname(stage), name], { encoding: "utf8" });
  } else {
    res = spawnSync(TAR, ["-C", path.dirname(stage), "-czf", archive, name], { encoding: "utf8" });
  }
  if (res.status !== 0) throw new Error(`asset build failed: ${res.stderr || res.error}`);
  const hex = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
  const eol = ext === "zip" ? "\r\n" : "\n";
  fs.writeFileSync(`${archive}.sha256`, `${hex}  ${name}.${ext}${eol}`, "ascii");
  return { name, archive, sha: `${archive}.sha256`, hex, relArchive: `v${version}/${name}.${ext}` };
}
function listArchive(archive) {
  const res = spawnSync(TAR, ["-tf", archive], { encoding: "utf8" });
  return (res.stdout || "").split(/\r?\n/).filter(Boolean);
}

async function killTree(child) {
  if (!child || child.exitCode !== null || child.signalCode) return;
  try {
    if (IS_WIN) spawnSync("taskkill", ["/T", "/F", "/PID", String(child.pid)], { stdio: "ignore" });
    else child.kill("SIGKILL");
  } catch {
    /* already gone */
  }
}
function childPids(pid) {
  if (IS_WIN) {
    const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `Get-CimInstance Win32_Process -Filter "ParentProcessId=${pid}" | Select-Object -ExpandProperty ProcessId`], { encoding: "utf8" });
    return (r.stdout || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  }
  const r = spawnSync("pgrep", ["-P", String(pid)], { encoding: "utf8" });
  return (r.stdout || "").split(/\n/).map((s) => s.trim()).filter(Boolean);
}
function pidAlive(pid) {
  if (IS_WIN) {
    const r = spawnSync("tasklist", ["/FI", `PID eq ${pid}`, "/NH"], { encoding: "utf8" });
    return new RegExp(`\\s${pid}\\s`).test(r.stdout || "");
  }
  try {
    process.kill(Number(pid), 0);
    return true;
  } catch {
    return false;
  }
}

// =============================================================================================
async function main() {
  console.log(`[F14] installation & packaging  (node ${process.version}, ${process.platform}-${process.arch}, binary ${HAVE_BINARY ? "present" : "ABSENT"})`);
  console.log(`[F14] temp root: ${TMP}`);

  const releaseYml = read(path.join(REPO_ROOT, ".github", "workflows", "release.yml"));
  const ciYml = read(path.join(REPO_ROOT, ".github", "workflows", "ci.yml"));
  const dockerfile = read(path.join(REPO_ROOT, "Dockerfile"));
  const compose = read(path.join(REPO_ROOT, "docker-compose.yml"));
  const readme = read(path.join(REPO_ROOT, "README.md"));
  const clientSetup = read(path.join(REPO_ROOT, "docs", "CLIENT-SETUP.md"));
  const launcherSrc = read(LAUNCHER);
  const cargoToml = read(path.join(REPO_ROOT, "Cargo.toml"));
  const exampleCfg = read(path.join(REPO_ROOT, "config", "db-mcp.example.toml"));
  const starterCfg = read(path.join(REPO_ROOT, "config", "db-mcp.starter.toml"));

  // ------------------------------------------------------------------ 5. package.json / npm pack
  console.log("\n[5] package.json and publish contents");
  await check("package.json: scoped public name, bin, engines>=18, repository/homepage/bugs point at vinothhacks/db-mcp", () => {
    assert.equal(PKG.name, "@vinoth_n_3000/db-mcp");
    assert.equal(PKG.bin["db-mcp"], "./npm/bin/db-mcp.js");
    assert.match(PKG.engines.node, />=\s*18/);
    assert.equal(PKG.publishConfig.access, "public");
    assert.match(PKG.repository.url, /github\.com\/vinothhacks\/db-mcp/);
    assert.match(PKG.homepage, /vinothhacks\/db-mcp/);
    assert.match(PKG.bugs.url, /vinothhacks\/db-mcp\/issues/);
    assert.ok(/MIT OR Apache-2\.0/.test(PKG.license));
  });
  await check("package.json: `files` covers every path the launcher reads from the package root", () => {
    const refs = [...launcherSrc.matchAll(/path\.join\(PKG_ROOT,\s*([^)]+)\)/g)].map((m) => m[1].split(",").map((s) => s.trim().replace(/^["']|["']$/g, "")).join("/"));
    assert.ok(refs.length >= 3, `expected package-root references in launcher, got ${JSON.stringify(refs)}`);
    for (const r of refs) {
      if (r === "package.json") continue; // always packed
      assert.ok(PKG.files.includes(r), `${r} is read by the launcher but missing from package.json files`);
    }
    for (const f of PKG.files) assert.ok(exists(path.join(REPO_ROOT, f)), `${f} listed in files but missing on disk`);
  });
  await check("package.json: version is consistent with Cargo workspace version, starter server_version and launcher VERSION", () => {
    const ws = cargoToml.match(/\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"/)[1];
    assert.equal(PKG.version, ws, "npm version must equal Cargo workspace version (release tag v<version> is shared)");
    assert.equal(launcher.VERSION, PKG.version);
    assert.equal(starterCfg.match(/^server_version\s*=\s*"([^"]+)"/m)[1], PKG.version);
    assert.equal(exampleCfg.match(/^server_version\s*=\s*"([^"]+)"/m)[1], PKG.version);
  });
  await check("package.json: scripts referenced by README/docs/CI exist (init, install:binary, verify:features, test, build)", () => {
    for (const s of ["init", "install:binary", "verify:features", "test", "build", "verify-config"]) assert.ok(PKG.scripts[s], `missing script ${s}`);
    assert.match(PKG.scripts["verify:features"], /scripts\/feature-smoke\.js/);
    assert.ok(exists(path.join(REPO_ROOT, "scripts", "feature-smoke.js")));
    assert.ok(exists(path.join(REPO_ROOT, "npm", "test", "e2e.test.js")));
    assert.ok(exists(path.join(REPO_ROOT, "npm", "test", "launcher.test.js")));
  });

  const packDir = path.join(TMP, "pack");
  fs.mkdirSync(packDir, { recursive: true });
  let tarball = null;
  await check("npm pack --dry-run --json lists only the 7 intended files (< 100 kB packed)", () => {
    const r = sh("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: REPO_ROOT });
    assert.equal(r.status, 0, r.stderr);
    const info = JSON.parse(r.stdout.trim().replace(/^[^[{]*/, ""))[0];
    const files = info.files.map((f) => f.path).sort();
    assert.deepEqual(files, [...PKG.files, "package.json"].sort());
    assert.ok(info.size < 100 * 1024, `packed size ${info.size}`);
    assert.ok(!files.some((f) => /^(target|research|crates|tests|reference)\//.test(f)), "source/evidence leaked into tarball");
  });
  await check("npm pack produces a tarball and `tar -tzf` shows package/npm/bin/db-mcp.js + config/db-mcp.starter.toml", () => {
    const r = sh("npm", ["pack", "--pack-destination", packDir, "--ignore-scripts"], { cwd: REPO_ROOT });
    assert.equal(r.status, 0, r.stderr);
    const tgz = fs.readdirSync(packDir).find((f) => f.endsWith(".tgz"));
    assert.ok(tgz, "no tarball produced");
    tarball = path.join(packDir, tgz);
    const list = spawnSync(TAR, ["-tzf", tarball], { encoding: "utf8" }).stdout.split(/\r?\n/).filter(Boolean);
    for (const f of ["package/npm/bin/db-mcp.js", "package/config/db-mcp.starter.toml", "package/config/db-mcp.example.toml", "package/package.json"]) {
      assert.ok(list.includes(f), `${f} missing from tarball: ${list.join(", ")}`);
    }
  });

  // ------------------------------------------------------------------ 1. fresh-user simulation
  console.log("\n[1] fresh-user simulation (extracted tarball, empty cwd, no Cargo workspace)");
  const extractDir = path.join(TMP, "extract");
  const userDir = path.join(TMP, "user-project");
  fs.mkdirSync(extractDir, { recursive: true });
  fs.mkdirSync(userDir, { recursive: true });
  const PACKED_LAUNCHER = path.join(extractDir, "package", "npm", "bin", "db-mcp.js");
  await check("tarball extracts and the packed launcher does not look like a dev checkout", () => {
    assert.ok(tarball, "tarball missing");
    const r = spawnSync(TAR, ["-xzf", tarball, "-C", extractDir], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(exists(PACKED_LAUNCHER));
    assert.ok(!exists(path.join(extractDir, "package", "Cargo.toml")));
  });
  await check("`db-mcp init` in an empty directory writes db-mcp.toml from the packed starter template (exit 0, next steps printed)", () => {
    const r = runLauncher(PACKED_LAUNCHER, ["init"], { cwd: userDir, env: strippedEnv() });
    assert.equal(r.status, 0, r.stderr);
    const cfg = path.join(userDir, "db-mcp.toml");
    assert.ok(exists(cfg));
    assert.equal(read(cfg), starterCfg);
    assert.match(r.stdout, /verify-config --config db-mcp\.toml/);
    assert.match(r.stdout, new RegExp(`npx ${PKG.name.replace(/[/@]/g, "\\$&")} serve`));
  });
  await check("`db-mcp init` refuses to overwrite without --force (exit 1) and honours --force --output --example", () => {
    const r1 = runLauncher(PACKED_LAUNCHER, ["init"], { cwd: userDir, env: strippedEnv() });
    assert.equal(r1.status, 1);
    assert.match(r1.stderr, /already exists/);
    const r2 = runLauncher(PACKED_LAUNCHER, ["init", "--force", "--output", "ex.toml", "--example"], { cwd: userDir, env: strippedEnv() });
    assert.equal(r2.status, 0, r2.stderr);
    assert.equal(read(path.join(userDir, "ex.toml")), exampleCfg);
  });
  await check("`db-mcp where` with nothing installed -> exit 1 + hint to run `db-mcp install`", () => {
    const r = runLauncher(PACKED_LAUNCHER, ["where"], { cwd: userDir, env: strippedEnv() });
    assert.equal(r.status, 1);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /no binary installed yet; run `db-mcp install`/);
  });
  await check("verify-config through the packed launcher with DB_MCP_BINARY_PATH -> exit 0, JSON status ok, 1 active connection", () => {
    if (!HAVE_BINARY) return skip("verify-config via DB_MCP_BINARY_PATH", "no built binary") || "skip";
    const r = runLauncher(PACKED_LAUNCHER, ["verify-config", "--config", "db-mcp.toml"], { cwd: userDir, env: strippedEnv({ DB_MCP_BINARY_PATH: BUILT_BINARY, ...STARTER_ENV }) });
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    assert.equal(j.status, "ok");
    assert.equal(j.connections, 1); // starter: local SQLite active, PostgreSQL/MySQL templates commented out
    assert.equal(j.named_tools, 1);
  });
  await check("no binary + DB_MCP_SKIP_DOWNLOAD=1 + no cargo on PATH -> exit 1 with actionable message (DB_MCP_BINARY_PATH, rustup, releases URL)", () => {
    const r = runLauncher(PACKED_LAUNCHER, ["verify-config", "--config", "db-mcp.toml"], { cwd: userDir, env: strippedEnv({ DB_MCP_SKIP_DOWNLOAD: "1" }) });
    assert.equal(r.status, 1, r.stderr);
    assert.equal(r.stdout, "", "stdout must stay empty on resolution failure");
    assert.match(r.stderr, new RegExp(`could not obtain db-mcp-server v${PKG.version.replace(/\./g, "\\.")}`));
    assert.match(r.stderr, /download: skipped \(DB_MCP_SKIP_DOWNLOAD=1\)/);
    assert.match(r.stderr, /cargo is not installed \(https:\/\/rustup\.rs\)/);
    assert.match(r.stderr, /DB_MCP_BINARY_PATH/);
    assert.match(r.stderr, /https:\/\/github\.com\/vinothhacks\/db-mcp\/releases/);
    assert.ok(!exists(CACHE_DIR) || fs.readdirSync(CACHE_DIR).length === 0, "nothing may be cached on failure");
  });
  await check("`--launcher-help` prints launcher help and exits 0 without needing a binary", () => {
    const r = runLauncher(PACKED_LAUNCHER, ["--launcher-help"], { cwd: userDir, env: strippedEnv({ DB_MCP_SKIP_DOWNLOAD: "1" }) });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Launcher commands:/);
    assert.match(r.stdout, /DB_MCP_CACHE_DIR/);
  });
  await check("`--help` / `-h` with no binary available still exits 0 with the launcher help (must not try to download or build)", () => {
    const r = runLauncher(PACKED_LAUNCHER, ["--help"], { cwd: userDir, env: strippedEnv({ DB_MCP_SKIP_DOWNLOAD: "1" }) });
    assert.match(r.stdout, /Launcher commands:/);
    assert.equal(r.status, 0, `--help exited ${r.status}: ${r.stderr.trim().split("\n")[0]}`);
  });

  // ------------------------------------------------------------------ 5b. global install shim
  console.log("\n[5b] global install from the tarball");
  const prefix = path.join(TMP, "gprefix");
  await check("npm install -g <tarball> --prefix <tmp> creates a db-mcp shim that resolves the binary", () => {
    if (!tarball) throw new Error("tarball missing");
    const r = sh("npm", ["install", "-g", tarball, "--prefix", prefix, "--ignore-scripts", "--no-fund", "--no-audit"], { cwd: TMP });
    assert.equal(r.status, 0, r.stderr);
    const shim = IS_WIN ? path.join(prefix, "db-mcp.cmd") : path.join(prefix, "bin", "db-mcp");
    assert.ok(exists(shim), `shim ${shim} missing`);
    if (!HAVE_BINARY) return;
    const w = sh(shim, ["where"], { cwd: userDir, env: { ...process.env, DB_MCP_BINARY_PATH: BUILT_BINARY, DB_MCP_CACHE_DIR: CACHE_DIR } });
    assert.equal(w.status, 0, w.stderr);
    assert.equal(path.resolve(w.stdout.trim()), path.resolve(BUILT_BINARY));
  });

  // ------------------------------------------------------------------ 2. release naming + download path
  console.log("\n[2] release asset naming vs release.yml, and the download path against a mock release server");
  const matrix = parseYamlMatrixTargets(releaseYml);
  await check("release.yml matrix has the five targets the launcher maps and NAME=${BIN}-${TAG}-${target}", () => {
    assert.equal(matrix.length, 5, JSON.stringify(matrix));
    assert.match(releaseYml, /NAME="\$\{BIN\}-\$\{TAG\}-\$\{\{ matrix\.target \}\}"/);
    assert.match(releaseYml, /\$Name = "\$env:BIN-\$Tag-\$\{\{ matrix\.target \}\}"/);
    assert.match(releaseYml, /BIN: db-mcp-server/);
    const mapped = new Set([
      launcher.detectTarget("linux", "x64"), launcher.detectTarget("linux", "arm64"),
      launcher.detectTarget("darwin", "x64"), launcher.detectTarget("darwin", "arm64"), launcher.detectTarget("win32", "x64"),
    ]);
    assert.deepEqual(new Set(matrix.map((m) => m.target)), mapped);
  });
  await check("releaseAsset() composes identical archive names, URLs and .sha256 names for all five targets (tag v<version>)", () => {
    const tag = `v${PKG.version}`;
    for (const m of matrix) {
      const a = launcher.releaseAsset(PKG.version, m.target);
      const expectedName = `db-mcp-server-${tag}-${m.target}`;
      assert.equal(a.name, expectedName);
      assert.equal(a.archive, `${expectedName}.${m.archive}`);
      assert.equal(a.ext, m.archive, `${m.target}: workflow packages ${m.archive}, launcher expects ${a.ext}`);
      assert.equal(a.url, `https://github.com/vinothhacks/db-mcp/releases/download/${tag}/${expectedName}.${m.archive}`);
      assert.equal(a.shaUrl, `${a.url}.sha256`);
    }
    assert.match(releaseYml, /"\$\{NAME\}\.tar\.gz\.sha256"/);
    assert.match(releaseYml, /"dist\/\$Name\.zip\.sha256"/);
  });
  await check("release.yml: artifacts uploaded/published cover *.tar.gz, *.zip and *.sha256 and the tag is reused for the release", () => {
    assert.match(releaseYml, /dist\/\*\.tar\.gz/);
    assert.match(releaseYml, /dist\/\*\.zip/);
    assert.match(releaseYml, /dist\/\*\.sha256/);
    assert.match(releaseYml, /softprops\/action-gh-release@v2/);
    assert.match(releaseYml, /permissions:\s*\n\s*contents: write/);
    assert.match(releaseYml, /merge-multiple: true/);
    assert.match(releaseYml, /files: artifacts\/\*/);
  });
  await check("extractArchive prerequisites: `tar` is on PATH; on Windows System32\\tar.exe is bsdtar (zip capable)", () => {
    const r = spawnSync("tar", ["--version"], { encoding: "utf8" });
    assert.equal(r.status, 0, "tar missing");
    if (IS_WIN) {
      const bsd = spawnSync(TAR, ["--version"], { encoding: "utf8" });
      assert.match(bsd.stdout, /bsdtar/);
    }
  });
  await check("cachedBinaryPath honours DB_MCP_CACHE_DIR and is <cache>/bin/v<ver>/<target>/db-mcp-server[.exe]", () => {
    const p = launcher.cachedBinaryPath(PKG.version, "x86_64-pc-windows-msvc");
    assert.equal(p, path.join(CACHE_DIR, "bin", `v${PKG.version}`, "x86_64-pc-windows-msvc", BIN_NAME));
  });

  const target = launcher.detectTarget();
  const ext = target && target.includes("windows") ? "zip" : "tar.gz";
  if (!HAVE_BINARY || !target) {
    skip("download path (install/where/verify through cache, no-op reinstall, sha mismatch, missing sha, 404)", HAVE_BINARY ? "unsupported platform" : "no built binary");
  } else {
    const assetsRoot = path.join(TMP, "release-assets");
    const mock = await startMockRelease(assetsRoot);
    try {
      // v0.1.0: exactly what release.yml produces on this OS (zip via Compress-Archive is FLAT; tar.gz is nested)
      const a1 = buildReleaseAsset({ version: PKG.version, target, ext, outDir: assetsRoot, binarySrc: BUILT_BINARY, layout: IS_WIN ? "workflow-flat" : "nested" });
      await check(`mock asset built like release.yml: ${a1.name}.${ext} + .sha256 ("<hex>  <name>", ${ext === "zip" ? "CRLF" : "LF"})`, () => {
        assert.ok(exists(a1.archive) && exists(a1.sha));
        assert.match(read(a1.sha), /^[0-9a-f]{64}  db-mcp-server-v[^\s]+\.(zip|tar\.gz)\r?\n$/);
        const entries = listArchive(a1.archive);
        assert.ok(entries.some((e) => e.endsWith(BIN_NAME)), entries.join(","));
        if (IS_WIN) assert.ok(entries.includes(BIN_NAME), "Compress-Archive -Path dir/* produces a FLAT zip (see observation O-zip-layout)");
        else assert.ok(entries.includes(`${a1.name}/${BIN_NAME}`), "tar.gz carries the top-level directory");
      });

      const installEnv = (extra = {}) => strippedEnv({ DB_MCP_RELEASE_BASE_URL: mock.baseUrl, ...extra });
      const expectedCached = path.join(CACHE_DIR, "bin", `v${PKG.version}`, target, BIN_NAME);

      await check("`db-mcp install` downloads from DB_MCP_RELEASE_BASE_URL, verifies sha256, caches at <cache>/bin/v<ver>/<target>/ and prints the path", () => {
        mock.reset();
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv(), timeout: 120000 });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.stdout.trim(), expectedCached);
        assert.ok(exists(expectedCached), "binary not cached");
        assert.equal(fs.statSync(expectedCached).size, fs.statSync(BUILT_BINARY).size);
        assert.ok(exists(path.join(path.dirname(expectedCached), "db-mcp.example.toml")), "example config not copied next to binary");
        assert.match(r.stderr, /sha256 verified/);
        assert.match(r.stderr, /installed /);
        assert.equal(mock.hits.get(a1.relArchive), 1);
        assert.equal(mock.hits.get(`${a1.relArchive}.sha256`), 1);
      });
      await check("`db-mcp where` now resolves the cached binary", () => {
        const r = runLauncher(PACKED_LAUNCHER, ["where"], { cwd: userDir, env: installEnv() });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.stdout.trim(), expectedCached);
      });
      await check("verify-config runs through the cached binary (no DB_MCP_BINARY_PATH), stdout is pure JSON", () => {
        const r = runLauncher(PACKED_LAUNCHER, ["verify-config", "--config", "db-mcp.toml"], { cwd: userDir, env: installEnv(STARTER_ENV) });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(JSON.parse(r.stdout).status, "ok");
      });
      await check("second `db-mcp install` is a no-op: zero requests to the release server", () => {
        mock.reset();
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv() });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.stdout.trim(), expectedCached);
        assert.equal(mock.hits.size, 0, `unexpected requests: ${[...mock.hits.keys()].join(", ")}`);
      });
      await check("DB_MCP_QUIET=1 silences launcher stderr logs during install; binary output untouched", () => {
        const cache2 = path.join(TMP, "cache-quiet");
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache2, DB_MCP_QUIET: "1" }), timeout: 120000 });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.stderr, "");
        assert.ok(exists(path.join(cache2, "bin", `v${PKG.version}`, target, BIN_NAME)));
      });

      // nested layout (what tar.gz / a hand-made zip look like) via DB_MCP_VERSION=0.1.1
      const a2 = buildReleaseAsset({ version: "0.1.1", target, ext, outDir: assetsRoot, binarySrc: BUILT_BINARY, layout: "nested" });
      await check("findFileRecursive handles the nested <NAME>/db-mcp-server layout too (DB_MCP_VERSION=0.1.1 asset)", () => {
        const entries = listArchive(a2.archive);
        assert.ok(entries.includes(`${a2.name}/${BIN_NAME}`), entries.join(","));
        const cache3 = path.join(TMP, "cache-nested");
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache3, DB_MCP_VERSION: "0.1.1" }), timeout: 120000 });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.stdout.trim(), path.join(cache3, "bin", "v0.1.1", target, BIN_NAME));
      });

      // corrupt checksum
      await check("corrupt .sha256 -> install exits 1 with 'SHA-256 mismatch' and nothing is cached", () => {
        const a3 = buildReleaseAsset({ version: "0.1.2", target, ext, outDir: assetsRoot, binarySrc: BUILT_BINARY, layout: "nested" });
        fs.writeFileSync(a3.sha, `${"0".repeat(64)}  ${a3.name}.${ext}\n`);
        const cache4 = path.join(TMP, "cache-badsha");
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache4, DB_MCP_VERSION: "0.1.2" }), timeout: 120000 });
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stderr, /SHA-256 mismatch/);
        assert.ok(!exists(path.join(cache4, "bin", "v0.1.2", target, BIN_NAME)), "corrupt download must not be cached");
        assert.match(r.stderr, /DB_MCP_BINARY_PATH/, "final error must stay actionable");
      });

      // missing checksum
      await check("missing .sha256 -> install refuses by default (fail closed) instead of silently installing an unverified binary", () => {
        const a4 = buildReleaseAsset({ version: "0.1.3", target, ext, outDir: assetsRoot, binarySrc: BUILT_BINARY, layout: "nested" });
        fs.rmSync(a4.sha);
        const cache5 = path.join(TMP, "cache-nosha");
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache5, DB_MCP_VERSION: "0.1.3" }), timeout: 120000 });
        assert.match(r.stderr, /checksum file unavailable/, "a warning must at least be printed");
        assert.equal(r.status, 1, `install succeeded without checksum verification (exit ${r.status})`);
        assert.ok(!exists(path.join(cache5, "bin", "v0.1.3", target, BIN_NAME)), "unverified binary must not be cached");
      });

      await check("missing .sha256 + DB_MCP_ALLOW_UNVERIFIED=1 -> install proceeds with a loud warning", () => {
        const a5 = buildReleaseAsset({ version: "0.1.4", target, ext, outDir: assetsRoot, binarySrc: BUILT_BINARY, layout: "nested" });
        fs.rmSync(a5.sha);
        const cache7 = path.join(TMP, "cache-nosha-optout");
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache7, DB_MCP_VERSION: "0.1.4", DB_MCP_ALLOW_UNVERIFIED: "1" }), timeout: 120000 });
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stderr, /WITHOUT verification/);
        assert.ok(exists(path.join(cache7, "bin", "v0.1.4", target, BIN_NAME)));
      });

      // 404
      await check("404 asset -> download error recorded, cargo fallback reports 'cargo is not installed', exit 1, nothing cached", () => {
        const cache6 = path.join(TMP, "cache-404");
        mock.reset();
        const r = runLauncher(PACKED_LAUNCHER, ["install"], { cwd: userDir, env: installEnv({ DB_MCP_CACHE_DIR: cache6, DB_MCP_VERSION: "9.9.9" }), timeout: 120000 });
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stderr, /download: HTTP 404 for http:\/\/127\.0\.0\.1:\d+\/v9\.9\.9\/db-mcp-server-v9\.9\.9-/);
        assert.match(r.stderr, /cargo: cargo is not installed/);
        assert.match(r.stderr, /DB_MCP_BINARY_PATH/);
        assert.ok(!exists(cache6));
        assert.equal(mock.hits.get(`v9.9.9/db-mcp-server-v9.9.9-${target}.${ext}`), 1);
      });
    } finally {
      await new Promise((r) => mock.server.close(() => r()));
    }
  }

  // ------------------------------------------------------------------ 3. resolution precedence
  console.log("\n[3] binary resolution precedence");
  const fakeRepo = path.join(TMP, "fake-repo");
  const mk = (p, mtimeOffsetSec = 0) => {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, "fake");
    const t = new Date(Date.now() + mtimeOffsetSec * 1000);
    fs.utimesSync(p, t, t);
    return p;
  };
  const setupRepo = () => {
    fs.rmSync(path.join(CACHE_DIR, "bin"), { recursive: true, force: true }); // earlier install checks leave a (newer) cached binary that would win the mtime tie-break
    fs.rmSync(fakeRepo, { recursive: true, force: true });
    fs.mkdirSync(path.join(fakeRepo, "crates", "db-mcp-server"), { recursive: true });
    fs.writeFileSync(path.join(fakeRepo, "Cargo.toml"), "[workspace]\n");
  };
  await check("DB_MCP_BINARY_PATH wins over a dev-checkout release build", () => {
    setupRepo();
    const rel = mk(path.join(fakeRepo, "target", "release", BIN_NAME));
    const override = mk(path.join(TMP, "override", BIN_NAME));
    process.env.DB_MCP_BINARY_PATH = override;
    try {
      assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), override);
    } finally {
      delete process.env.DB_MCP_BINARY_PATH;
    }
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), rel);
  });
  await check("preferRelease returns target/release even when target/debug is newer; otherwise newest native build wins", () => {
    setupRepo();
    const rel = mk(path.join(fakeRepo, "target", "release", BIN_NAME), -600);
    const dbg = mk(path.join(fakeRepo, "target", "debug", BIN_NAME), 0);
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo, preferRelease: true }), rel);
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), dbg);
  });
  await check("a stale Linux ELF target/release/db-mcp-server is never preferred over the native .exe on Windows (even when newer)", () => {
    if (!IS_WIN) return skip("ELF vs exe precedence", "windows only") || "skip";
    setupRepo();
    const exe = mk(path.join(fakeRepo, "target", "release", "db-mcp-server.exe"), -3600);
    mk(path.join(fakeRepo, "target", "release", "db-mcp-server"), 0);
    mk(path.join(fakeRepo, "target", "debug", "db-mcp-server"), 0);
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), exe);
    if (exists(path.join(REPO_ROOT, "target", "release", "db-mcp-server")) && HAVE_BINARY) {
      assert.equal(launcher.findLocalBinary({ repoRoot: REPO_ROOT }).toLowerCase().endsWith(".exe"), true, "real repo: stale ELF shadowed the exe");
    }
  });
  await check("WSL fallback is only used when NO native exe exists (dev checkout with ELF only -> ELF path, spawn goes via wsl.exe)", () => {
    if (!IS_WIN) return skip("WSL fallback", "windows only") || "skip";
    setupRepo();
    const elf = mk(path.join(fakeRepo, "target", "release", "db-mcp-server"));
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), elf);
    assert.match(launcherSrc, /spawn\("wsl\.exe", \["--exec", wslBin/);
  });
  await check("dist/bin is consulted before the cache, and the cache is used when nothing else exists", () => {
    setupRepo();
    fs.rmSync(path.join(fakeRepo, "Cargo.toml"));
    const cached = mk(launcher.cachedBinaryPath());
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), cached);
    const dist = mk(path.join(fakeRepo, "dist", "bin", BIN_NAME), -3600);
    const found = launcher.findLocalBinary({ repoRoot: fakeRepo });
    assert.ok([dist, cached].includes(found));
    fs.rmSync(cached);
    assert.equal(launcher.findLocalBinary({ repoRoot: fakeRepo }), dist);
  });
  await check("resolveBinaryPath({autoBuild:false}) throws a clear error when nothing is installed (never spawns cargo)", () => {
    setupRepo();
    fs.rmSync(path.join(fakeRepo, "Cargo.toml"));
    assert.throws(() => launcher.resolveBinaryPath({ repoRoot: fakeRepo, autoBuild: false }), /binary not found/);
  });

  // ------------------------------------------------------------------ 4. launcher behaviour with the real binary
  console.log("\n[4] launcher behaviour (dev checkout launcher + built binary)");
  if (!HAVE_BINARY) {
    skip("help/version/unknown-command forwarding, exit codes, stdio transparency, signal forwarding", "no built binary");
  } else {
    const devEnv = { ...process.env, DB_MCP_CACHE_DIR: CACHE_DIR };
    await check("`--help` prints the launcher help followed by the binary's clap help on stdout, exit 0", () => {
      const r = runLauncher(LAUNCHER, ["--help"], { cwd: REPO_ROOT, env: devEnv });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /Launcher commands:[\s\S]*Usage: db-mcp-server/);
      assert.ok(r.stdout.indexOf("Launcher commands:") < r.stdout.indexOf("Usage: db-mcp-server"));
    });
    await check("`--version` is forwarded: prints `db-mcp-server <package version>`", () => {
      const r = runLauncher(LAUNCHER, ["--version"], { cwd: REPO_ROOT, env: devEnv });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout.trim(), `db-mcp-server ${PKG.version}`);
    });
    await check("unknown subcommand is forwarded: binary's clap error on stderr and exit code 2 propagated", () => {
      const r = runLauncher(LAUNCHER, ["frobnicate"], { cwd: REPO_ROOT, env: devEnv });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /unrecognized subcommand 'frobnicate'/);
      assert.equal(r.stdout, "");
    });
    await check("verify-config failure (missing file) propagates exit 1 and the binary's error", () => {
      const r = runLauncher(LAUNCHER, ["verify-config", "--config", "does-not-exist.toml"], { cwd: REPO_ROOT, env: devEnv });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /Failed to read config file/);
    });
    await check("stdio transparency: launcher diagnostics go to stderr only; DB_MCP_QUIET=1 suppresses them; stdout stays parseable JSON", () => {
      const missing = path.join(TMP, "nope", BIN_NAME);
      const r1 = runLauncher(LAUNCHER, ["verify-config", "--config", "config/db-mcp.example.toml"], { cwd: REPO_ROOT, env: { ...devEnv, DB_MCP_BINARY_PATH: missing } });
      assert.equal(r1.status, 0, r1.stderr);
      assert.equal(JSON.parse(r1.stdout).status, "ok");
      assert.match(r1.stderr, /\[db-mcp\] DB_MCP_BINARY_PATH is set but .* does not exist; ignoring/);
      const r2 = runLauncher(LAUNCHER, ["verify-config", "--config", "config/db-mcp.example.toml"], { cwd: REPO_ROOT, env: { ...devEnv, DB_MCP_BINARY_PATH: missing, DB_MCP_QUIET: "1" } });
      assert.equal(r2.status, 0, r2.stderr);
      assert.equal(JSON.parse(r2.stdout).status, "ok");
      assert.ok(!/\[db-mcp\]/.test(r2.stderr), `launcher log leaked with DB_MCP_QUIET=1: ${r2.stderr}`);
    });
    await check("SIGTERM to the launcher (serve --transport http) stops the db-mcp-server child within 2 s; no orphan process", async () => {
      const { makeIsolatedConfig } = require(path.join(REPO_ROOT, "scripts", "make-isolated-config.js"));
      const { configPath } = makeIsolatedConfig({ dir: path.join(TMP, "iso-http") });
      const port = await getFreePort();
      const child = spawn(process.execPath, [LAUNCHER, "serve", "--transport", "http", "--bind", `127.0.0.1:${port}`, "--config", configPath], { cwd: REPO_ROOT, env: { ...devEnv, DB_MCP_AUTH_TOKEN: "f14-agent-token", DB_MCP_ADMIN_TOKEN: "f14-admin-token" }, stdio: ["pipe", "pipe", "pipe"] });
      children.add(child);
      let stderr = "";
      child.stderr.on("data", (d) => (stderr += d));
      let up = false;
      for (let i = 0; i < 75 && !up; i++) {
        await sleep(200);
        try {
          up = (await fetch(`http://127.0.0.1:${port}/health`)).ok;
        } catch {
          /* not yet */
        }
      }
      assert.ok(up, `server never became healthy: ${stderr}`);
      const kids = childPids(child.pid);
      assert.ok(kids.length >= 1, "could not find the db-mcp-server child process");
      child.kill("SIGTERM");
      const t0 = Date.now();
      let gone = false;
      while (Date.now() - t0 < 2000) {
        await sleep(100);
        gone = kids.every((k) => !pidAlive(k));
        if (gone) break;
      }
      let still = false;
      try {
        still = (await fetch(`http://127.0.0.1:${port}/health`)).ok;
      } catch {
        /* expected */
      }
      for (const k of kids) if (pidAlive(k)) spawnSync(IS_WIN ? "taskkill" : "kill", IS_WIN ? ["/F", "/PID", k] : ["-9", k], { stdio: "ignore" });
      children.delete(child);
      assert.ok(gone, `db-mcp-server child (pid ${kids.join(",")}) still alive 2 s after SIGTERM to the launcher`);
      assert.equal(still, false, "HTTP server still answering after the launcher was terminated");
    });
  }

  // ------------------------------------------------------------------ 6. Dockerfile / compose static review
  console.log("\n[6] Dockerfile and docker-compose static review");
  const msrv = maxRustVersionFromLock();
  await check(`Dockerfile builder image toolchain >= highest rust-version in Cargo.lock (${msrv.max} needed by ${msrv.who})`, () => {
    const m = dockerfile.match(/^FROM rust:(\d+\.\d+(?:\.\d+)?)/m);
    assert.ok(m, "no rust base image");
    assert.ok(semverGte(m[1], msrv.max), `rust:${m[1]} < required ${msrv.max} (${msrv.who})`);
  });
  await check("Cargo.toml workspace rust-version is not lower than what the lock file actually requires", () => {
    const rv = cargoToml.match(/^rust-version\s*=\s*"([^"]+)"/m)[1];
    assert.ok(semverGte(rv, msrv.max), `rust-version ${rv} < ${msrv.max} (${msrv.who})`);
  });
  await check("Dockerfile copies Cargo.lock and builds with --locked (reproducible image)", () => {
    assert.match(dockerfile, /COPY Cargo\.toml Cargo\.lock|COPY Cargo\.lock/, "Cargo.lock is not copied into the builder stage");
    assert.match(dockerfile, /cargo build --release --locked/, "builder does not use --locked");
  });
  await check(".dockerignore exists and excludes target/, node_modules/, .git/, research/traces/", () => {
    const di = read(path.join(REPO_ROOT, ".dockerignore"));
    for (const e of ["target/", "node_modules/", ".git/", "research/traces/"]) assert.ok(di.split(/\r?\n/).includes(e), `${e} missing`);
  });
  await check("Dockerfile runtime: non-root USER, HEALTHCHECK on /health, EXPOSE 8080, config at /etc/db-mcp/db-mcp.toml matches CMD and compose", () => {
    assert.match(dockerfile, /^USER dbmcp/m);
    assert.match(dockerfile, /HEALTHCHECK[\s\S]*http:\/\/127\.0\.0\.1:8080\/health/);
    assert.match(dockerfile, /^EXPOSE 8080/m);
    assert.match(dockerfile, /CMD \["db-mcp-server", "serve", "--transport", "http", "--bind", "0\.0\.0\.0:8080", "--config", "\/etc\/db-mcp\/db-mcp\.toml"\]/);
    assert.match(compose, /\.\/config\/db-mcp\.example\.toml:\/etc\/db-mcp\/db-mcp\.toml:ro/);
    assert.match(compose, /"8080:8080"/);
  });
  await check("Dockerfile does not bake the research/ evidence bundle (~21 MB of traces/REA evidence) into the image", () => {
    assert.ok(!/^COPY research \.\/research/m.test(dockerfile), "builder copies the whole research/ tree");
    assert.ok(!/COPY --from=builder \/workspace\/research /.test(dockerfile), "runtime copies the whole research/ tree");
  });
  await check("docker-compose: no postgres/mysql side-cars that the (simulated) adapters can never reach", () => {
    // F14-07 fixed: the PostgreSQL/MySQL adapters have no wire client (embedded simulation), so side-car databases
    // and depends_on on them were misleading; compose now runs only db-mcp.
    assert.ok(!/depends_on:/.test(compose), "compose still declares depends_on");
    assert.ok(!/^\s{2}(postgres|mysql):/m.test(compose), "compose still declares a postgres/mysql service");
  });
  await check("docker-compose: default bearer tokens are explicit dev placeholders and RUST_LOG is overridable", () => {
    assert.match(compose, /DB_MCP_AUTH_TOKEN: \$\{DB_MCP_AUTH_TOKEN:-dev-agent-token\}/);
    assert.match(compose, /DB_MCP_ADMIN_TOKEN: \$\{DB_MCP_ADMIN_TOKEN:-dev-admin-token\}/);
    assert.match(compose, /RUST_LOG: \$\{RUST_LOG:-info\}/);
  });
  await check("example config init_sql never runs DDL against a live Postgres/MySQL (seeds only the embedded engine)", () => {
    const pg = read(path.join(REPO_ROOT, "crates", "db-mcp-postgres", "src", "lib.rs"));
    assert.match(pg, /Connection::open_in_memory\(\)[\s\S]{0,600}init_sql/);
    assert.ok(!/tokio[-_]postgres|sqlx|postgres::Client/.test(read(path.join(REPO_ROOT, "crates", "db-mcp-postgres", "Cargo.toml"))), "a real PG client is linked; re-check init_sql execution path");
  });

  // ------------------------------------------------------------------ 7. workflows
  console.log("\n[7] GitHub workflows");
  await check("ci.yml: every referenced script/file exists and the OS matrix uses valid runner labels", () => {
    for (const f of [...ciYml.matchAll(/node (scripts\/[\w.-]+\.js)/g)].map((m) => m[1])) assert.ok(exists(path.join(REPO_ROOT, f)), `${f} missing`);
    assert.match(ciYml, /run: npm test/);
    assert.match(ciYml, /npm pack --dry-run/);
    const oses = ciYml.match(/os: \[([^\]]+)\]/)[1].split(",").map((s) => s.trim());
    assert.deepEqual(oses, ["ubuntu-latest", "windows-latest", "macos-latest"]);
    assert.match(ciYml, /node-version: 20/);
  });
  await check("release.yml: --locked with a committed Cargo.lock; arm runner label ubuntu-22.04-arm; no retired macOS runner label", () => {
    assert.match(releaseYml, /cargo build --release --locked -p db-mcp-server --target \$\{\{ matrix\.target \}\}/);
    assert.ok(exists(path.join(REPO_ROOT, "Cargo.lock")));
    assert.ok(matrix.some((m) => m.os === "ubuntu-22.04-arm" && m.target === "aarch64-unknown-linux-gnu"));
    const intelMac = matrix.find((m) => m.target === "x86_64-apple-darwin");
    assert.notEqual(intelMac.os, "macos-13", "macos-13 runner image is retired; use macos-15-intel");
  });
  await check("release.yml Windows packaging: sha256 line format `<hex>  <name>.zip` (ascii) is what the launcher parses; zip is built from dist/$Name/*", () => {
    assert.match(releaseYml, /"\$Hash  \$Name\.zip" \| Out-File -Encoding ascii/);
    assert.match(releaseYml, /\.Hash\.ToLower\(\)/);
    assert.match(releaseYml, /Compress-Archive -Path "dist\/\$Name\/\*" -DestinationPath "dist\/\$Name\.zip"/);
    assert.match(launcherSrc, /\.trim\(\)\.split\(\/\\s\+\/\)\[0\]\.toLowerCase\(\)/);
  });
  await check("release.yml unix packaging keeps the top-level directory (tar -C dist ... NAME) and the launcher searches recursively", () => {
    assert.match(releaseYml, /tar -C dist -czf "dist\/\$\{NAME\}\.tar\.gz" "\$\{NAME\}"/);
    assert.match(launcherSrc, /findFileRecursive\(extractDir, BIN_NAME\)/);
  });

  // ------------------------------------------------------------------ 8. README / docs accuracy
  console.log("\n[8] README and docs/CLIENT-SETUP.md accuracy");
  await check("README: every `npm run <script>` and launcher subcommand shown exists", () => {
    for (const m of [...readme.matchAll(/npm run ([\w:.-]+)/g)]) assert.ok(PKG.scripts[m[1]], `npm run ${m[1]} does not exist`);
    for (const m of [...readme.matchAll(/npx @vinoth_n_3000\/db-mcp (\w[\w-]*)/g)]) assert.ok(["init", "install", "where", "selftest", "serve", "approve", "verify-config", "check-connection", "verify-audit"].includes(m[1]), `unknown subcommand ${m[1]}`);
  });
  await check("README: `cargo install --git ... db-mcp-server` names the real bin crate and repository", () => {
    const binCrate = read(path.join(REPO_ROOT, "crates", "db-mcp-server", "Cargo.toml"));
    assert.match(binCrate, /name = "db-mcp-server"/);
    assert.match(readme, /cargo install --git https:\/\/github\.com\/vinothhacks\/db-mcp --locked db-mcp-server/);
    assert.match(launcherSrc, /"install", "--git", `https:\/\/github\.com\/\$\{REPO_SLUG\}`, "--tag", `v\$\{version\}`, "--locked", "--root", root, "db-mcp-server"/);
  });
  await check("README + CLIENT-SETUP: every ```json snippet is valid JSON and the claude mcp add line uses `--` before npx", () => {
    for (const [label, doc] of [["README", readme], ["CLIENT-SETUP", clientSetup]]) {
      const snippets = [...doc.matchAll(/```json\s*\n([\s\S]*?)```/g)].map((m) => m[1]);
      assert.ok(snippets.length >= 1, `${label}: no json snippets`);
      for (const s of snippets) JSON.parse(s);
      assert.match(doc, /claude mcp add db-mcp -- npx -y @vinoth_n_3000\/db-mcp serve --transport stdio --config/);
    }
  });
  await check("README: files it points at exist (docs/CLIENT-SETUP.md, research/findings/capability-matrix.md, research/contracts/tool-contracts.json, scripts/mcp-call.js)", () => {
    for (const f of ["docs/CLIENT-SETUP.md", "research/findings/capability-matrix.md", "research/contracts/tool-contracts.json", "research/licenses/license-inventory.md", "scripts/mcp-call.js", "LICENSE-MIT", "LICENSE-APACHE"]) {
      assert.ok(readme.includes(f), `README no longer mentions ${f}`);
      assert.ok(exists(path.join(REPO_ROOT, f)), `${f} referenced by README is missing`);
    }
  });
  await check("CLIENT-SETUP env var table documents every DB_MCP_* knob the launcher reads", () => {
    const knobs = [...new Set([...launcherSrc.matchAll(/process\.env\.(DB_MCP_[A-Z_]+)/g)].map((m) => m[1]))].sort();
    assert.ok(knobs.length >= 7, knobs.join(","));
    const missing = knobs.filter((k) => !new RegExp(`\\|\\s*\`${k}`).test(clientSetup));
    assert.deepEqual(missing, [], `undocumented launcher env vars: ${missing.join(", ")}`);
  });
  await check("README quick start: cache location and fallback description match the launcher (~/.db-mcp/bin, cargo install fallback, DB_MCP_BINARY_PATH)", () => {
    assert.match(readme, /~\/\.db-mcp\/bin\//);
    assert.match(readme, /verifies its SHA-256/);
    assert.match(readme, /DB_MCP_BINARY_PATH/);
    assert.match(launcherSrc, /path\.join\(os\.homedir\(\), "\.db-mcp"\)/);
  });

  // ------------------------------------------------------------------ summary
  console.log(`\n[F14] ${passed} passed, ${failed} failed, ${skipped} skipped`);
  if (failures.length) console.log(`[F14] failing checks:\n  - ${failures.join("\n  - ")}`);
  process.exitCode = failed ? 1 : 0;
}

async function cleanup() {
  for (const c of children) await killTree(c);
  try {
    fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch (err) {
    console.log(`[F14] temp cleanup incomplete: ${err.message}`);
  }
}

main()
  .catch((err) => {
    console.error(`[F14] fatal: ${err.stack || err.message}`);
    process.exitCode = 1;
  })
  .finally(cleanup);
