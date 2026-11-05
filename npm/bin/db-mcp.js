#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const IS_WINDOWS = process.platform === "win32";
const BIN_NAME = IS_WINDOWS ? "db-mcp-server.exe" : "db-mcp-server";

function toWslPath(winPath) {
  return String(winPath)
    .replace(/^([A-Za-z]):[\\/]/, (_, drive) => `/mnt/${drive.toLowerCase()}/`)
    .replace(/\\/g, "/");
}

/**
 * Locate the compiled `db-mcp-server` binary in `target/release` or `target/debug`
 * (or build it on demand via `cargo build -p db-mcp-server` if missing).
 *
 * @param {object} [options]
 * @param {string} [options.repoRoot]
 * @param {boolean} [options.autoBuild=true]
 * @param {boolean} [options.preferRelease=false]
 * @returns {string} Absolute path to the resolved executable.
 */
function resolveBinaryPath(options = {}) {
  const repoRoot = options.repoRoot ? path.resolve(options.repoRoot) : REPO_ROOT;
  const autoBuild = options.autoBuild !== false;

  if (process.env.DB_MCP_BINARY_PATH && fs.existsSync(process.env.DB_MCP_BINARY_PATH)) {
    return path.resolve(process.env.DB_MCP_BINARY_PATH);
  }

  const releaseCandidate = path.join(repoRoot, "target", "release", BIN_NAME);
  const debugCandidate = path.join(repoRoot, "target", "debug", BIN_NAME);
  const distCandidate = path.join(repoRoot, "dist", "bin", BIN_NAME);
  const wslReleaseCandidate = path.join(repoRoot, "target", "release", "db-mcp-server");
  const wslDebugCandidate = path.join(repoRoot, "target", "debug", "db-mcp-server");

  const existingCandidates = [
    releaseCandidate,
    debugCandidate,
    distCandidate,
    ...(IS_WINDOWS ? [wslReleaseCandidate, wslDebugCandidate] : []),
  ].filter((candidate) => fs.existsSync(candidate));

  if (existingCandidates.length === 1) {
    return existingCandidates[0];
  }

  if (existingCandidates.length > 1) {
    if (options.preferRelease && fs.existsSync(releaseCandidate)) {
      return releaseCandidate;
    }
    // Select the most recently modified binary so fresh debug/release builds are never shadowed.
    existingCandidates.sort((a, b) => {
      try {
        return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs;
      } catch {
        return 0;
      }
    });
    return existingCandidates[0];
  }

  if (!autoBuild) {
    throw new Error(
      `db-mcp-server binary not found at ${releaseCandidate} or ${debugCandidate}`
    );
  }

  const buildResult = spawnSync("cargo", ["build", "-p", "db-mcp-server"], {
    cwd: repoRoot,
    env: process.env,
    stdio: "inherit",
  });

  if (buildResult.status !== 0) {
    const errMsg = buildResult.error ? buildResult.error.message : `exit code ${buildResult.status}`;
    throw new Error(`Failed to build db-mcp-server via cargo: ${errMsg}`);
  }

  if (fs.existsSync(debugCandidate)) {
    return debugCandidate;
  }
  if (fs.existsSync(releaseCandidate)) {
    return releaseCandidate;
  }

  throw new Error(
    `Cargo build succeeded, but binary was not found at ${debugCandidate} or ${releaseCandidate}`
  );
}

/**
 * Spawn `db-mcp-server` with forwarded CLI arguments, environment variables, and stdio streams.
 *
 * @param {string[]|object} [argsOrOptions]
 * @param {object} [maybeOptions]
 * @returns {import("node:child_process").ChildProcess}
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
    return spawn("wsl.exe", ["--exec", wslBin, ...wslArgs], {
      cwd,
      env,
      stdio,
      windowsHide: true,
    });
  }

  return spawn(binaryPath, args, {
    cwd,
    env,
    stdio,
    windowsHide: true,
  });
}

function runCli() {
  let binaryPath;
  try {
    binaryPath = resolveBinaryPath();
  } catch (err) {
    process.stderr.write(`[db-mcp] ${err.message}\n`);
    process.exit(1);
  }

  const child = spawnDbMcpServer(process.argv.slice(2), {
    binaryPath,
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
  });

  const forwardSignal = (signal) => {
    if (child && !child.killed) {
      try {
        child.kill(signal);
      } catch {
        // Ignore if child already exited
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
  runCli();
}

module.exports = {
  resolveBinaryPath,
  spawnDbMcpServer,
};
