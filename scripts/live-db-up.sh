#!/usr/bin/env bash
# Start a disposable database container, seed the DB-MCP fixture, create read-only logins and
# print the DSNs to export. Usage: scripts/live-db-up.sh <mysql|mssql> [--down]
#   mssql: container dbmcp-mssql (mcr.microsoft.com/mssql/server:2022-latest) on 127.0.0.1:${DB_MCP_MSSQL_PORT:-11433}
# The DSNs are printed as `export NAME=...` lines (eval "$(scripts/live-db-up.sh mssql)").
# Progress goes to stderr. Passwords are random per run and contain @ ) $ to exercise
# percent-encoding; they are printed only inside the DSN lines.
set -euo pipefail
ENGINE="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log() { echo "[live-db-up] $*" >&2; }

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-16}"; }
pct() { # percent-encode the characters our generated passwords can contain
  local s="$1"; s="${s//%/%25}"; s="${s//@/%40}"; s="${s//)/%29}"; s="${s//\$/%24}"; printf '%s' "$s"; }

mssql_up() {
  local name=dbmcp-mssql port="${DB_MCP_MSSQL_PORT:-11433}"
  local sa_pw="Sa1!$(rand 20)"
  local ro_pw="Ro@1)x\$$(rand 14)" full_pw="Fu@2)y\$$(rand 14)"
  if [ "${DB_MCP_MSSQL_REUSE:-0}" = 1 ] && docker ps --format '{{.Names}}' | grep -qx "$name"; then
    # Reuse a running container (the first start of the 2022 image can take minutes): re-seed only.
    sa_pw="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name" | sed -n 's/^MSSQL_SA_PASSWORD=//p')"
    log "reusing running $name"
  else
    docker rm -f "$name" >/dev/null 2>&1 || true
    log "starting $name on 127.0.0.1:$port"
    MSYS_NO_PATHCONV=1 docker run -d --name "$name" -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=$sa_pw" \
      -p "127.0.0.1:$port:1433" mcr.microsoft.com/mssql/server:2022-latest >/dev/null
  fi
  local sqlcmd=/opt/mssql-tools18/bin/sqlcmd
  for i in $(seq 1 300); do
    if MSYS_NO_PATHCONV=1 docker exec "$name" "$sqlcmd" -C -S localhost -U sa -P "$sa_pw" -Q "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    [ "$i" = 300 ] && { log "SQL Server did not become ready"; docker logs --tail 30 "$name" >&2; exit 1; }
    sleep 2
  done
  log "seeding fixture"
  local src="$HERE/research/fixtures/sqlserver-live"
  if command -v cygpath >/dev/null 2>&1; then src="$(cygpath -w "$src")"; fi
  MSYS_NO_PATHCONV=1 docker cp "$src/." "$name:/tmp/fixture" >/dev/null
  MSYS_NO_PATHCONV=1 docker exec "$name" "$sqlcmd" -C -b -S localhost -U sa -P "$sa_pw" -i /tmp/fixture/01-schema.sql >&2
  MSYS_NO_PATHCONV=1 docker exec "$name" "$sqlcmd" -C -b -S localhost -U sa -P "$sa_pw" \
    -v "RO_PASSWORD=$ro_pw" "FULL_PASSWORD=$full_pw" -i /tmp/fixture/02-logins.sql >&2
  log "ready: db_datareader login dbmcp_ro (default database dbmcp_fixture), extra-grants login dbmcp_ro_full"
  # Read-only login, login default database, named-instance style DSN on an explicit port.
  echo "export DB_MCP_MSSQL_TEST_DSN='sqlserver://dbmcp_ro:$(pct "$ro_pw")@127.0.0.1:$port?instance=V2DEMO&encrypt=optional&trustServerCertificate=true'"
  echo "export DB_MCP_MSSQL_FULL_TEST_DSN='sqlserver://dbmcp_ro_full:$(pct "$full_pw")@127.0.0.1:$port?database=dbmcp_fixture'"
  echo "export DB_MCP_MSSQL_ADMIN_DSN='sqlserver://sa:$(pct "$sa_pw")@127.0.0.1:$port?database=dbmcp_fixture'"
}

case "$ENGINE" in
  mssql|sqlserver)
    if [ "${2:-}" = "--down" ]; then docker rm -f dbmcp-mssql >/dev/null 2>&1 || true; exit 0; fi
    mssql_up ;;
  mysql)
    log "mysql fixture is provided by the MySQL track (research/fixtures/mysql-live)"; exit 2 ;;
  *)
    echo "usage: $0 <mysql|mssql> [--down]" >&2; exit 2 ;;
esac
