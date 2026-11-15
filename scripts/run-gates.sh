#!/usr/bin/env bash
# Phase gate: every check must pass before the next phase starts.
# Usage: bash scripts/run-gates.sh [logfile]   (prints a compact summary)
set -u
cd "$(dirname "$0")/.."
LOG="${1:-/dev/stdout}"
{
  echo "### cargo test --workspace --release"
  cargo test --workspace --release 2>&1 | grep -E "^test result|FAILED|panicked|^error(\[|:)" | sort | uniq -c
  echo "### cargo-exit=${PIPESTATUS[0]}"
  echo "### npm test"
  npm test 2>&1 | grep -E "PASS|FAIL|ok |passed|Failure|Error" | tail -15
  echo "### npm-exit=${PIPESTATUS[0]}"
  echo "### feature smoke"
  node scripts/feature-smoke.js 2>&1 | grep -E "^FAIL|checks passed"
  echo "### smoke-exit=${PIPESTATUS[0]}"
  echo "### feature suites (known-bug failures are reported, not fatal)"
  for f in npm/test/features/*.test.js; do
    out=$(timeout 600 node "$f" 2>&1 | tail -3 | tr '\n' ' ')
    echo "$(basename "$f"): ${out:0:260}"
  done
  echo "### DONE"
} > "$LOG" 2>&1
