#!/usr/bin/env bash
# Phase gate: every check must pass before the next phase starts.
# Usage: bash scripts/run-gates.sh [logfile]
set -u
LOG="${1:-/dev/stdout}"
exec > "$LOG" 2>&1
cd "$(dirname "$0")/.." || exit 1
failed=0

run_gate() {
  printf '\n### %s\n' "$*"
  "$@"
  local status=$?
  printf '### exit=%s\n' "$status"
  if (( status != 0 )); then
    failed=1
  fi
}

run_gate cargo build --locked --release -p db-mcp-server
# Never verify a stale executable left by an earlier build.
if (( failed )); then exit "$failed"; fi
run_gate target/release/db-mcp-server selftest
run_gate target/release/db-mcp-server verify-config --config config/db-mcp.example.toml
run_gate cargo test --locked --workspace --release
run_gate npm test
run_gate npm run verify:features
for file in npm/test/features/{01..16}-*.test.js; do
  run_gate node "$file"
done
run_gate npm pack --dry-run
exit "$failed"
