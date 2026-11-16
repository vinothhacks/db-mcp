#!/usr/bin/env bash
# Start a disposable database container, seed the live fixture, create read-only logins and
# print the test DSNs as `export NAME='...'` lines.
#
#   eval "$(bash scripts/live-db-up.sh mysql)"     # exports DB_MCP_MYSQL_TEST_DSN (+ _DIAG, _RW)
#   eval "$(bash scripts/live-db-up.sh mssql)"     # exports DB_MCP_MSSQL_TEST_DSN (+ _FULL_TEST_DSN, _ADMIN_DSN)
#   bash scripts/live-db-up.sh <mysql|mssql> --down  # remove the container
#
# mysql: container dbmcp-mysql (mysql:8.0) on 127.0.0.1:${DB_MCP_MYSQL_PORT:-13306}
# mssql: container dbmcp-mssql (mcr.microsoft.com/mssql/server:2022-latest) on 127.0.0.1:${DB_MCP_MSSQL_PORT:-11433}
#
# Only containers on 127.0.0.1 are touched. Passwords are random per run; the read-only password
# contains '@ ) $' so DSN percent-decoding is exercised. Progress goes to stderr, exports to stdout.
set -euo pipefail
cd "$(dirname "$0")/.."
HERE="$(pwd)"

ENGINE="${1:-}"
ACTION="${2:-up}"

log() { echo "[live-db-up] $*" >&2; }
rand_hex() { od -An -N12 -tx1 /dev/urandom | tr -d ' \n'; }

up_mysql() {
  local name="${DB_MCP_MYSQL_CONTAINER:-dbmcp-mysql}"
  local port="${DB_MCP_MYSQL_PORT:-13306}"
  if [ "$ACTION" = "--down" ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
    log "removed $name"
    return 0
  fi
  local root_pw ro_pw diag_pw rw_pw
  root_pw="root$(rand_hex)"
  ro_pw="ro$(rand_hex)@)\$"
  diag_pw="diag$(rand_hex)"
  rw_pw="rw$(rand_hex)"
  docker rm -f "$name" >/dev/null 2>&1 || true
  log "starting $name (mysql:8.0) on 127.0.0.1:$port"
  docker run -d --name "$name" -e MYSQL_ROOT_PASSWORD="$root_pw" -p "127.0.0.1:$port:3306" mysql:8.0 >/dev/null
  # The entrypoint first runs a temporary server without networking; wait for the real one (TCP).
  local i
  for i in $(seq 1 120); do
    if docker exec -e MYSQL_PWD="$root_pw" "$name" mysql -uroot -h127.0.0.1 -P3306 -e "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 2
    if [ "$i" = 120 ]; then log "mysql did not become ready"; docker logs "$name" 2>&1 | tail -20 >&2; exit 1; fi
  done
  log "seeding research/fixtures/mysql-live"
  docker exec -i -e MYSQL_PWD="$root_pw" "$name" mysql -uroot -h127.0.0.1 --default-character-set=utf8mb4 < research/fixtures/mysql-live/01-schema.sql >/dev/null
  sed -e "s|__RO_PASSWORD__|${ro_pw}|" -e "s|__DIAG_PASSWORD__|${diag_pw}|" -e "s|__RW_PASSWORD__|${rw_pw}|" \
    research/fixtures/mysql-live/02-users.sql.tmpl \
    | docker exec -i -e MYSQL_PWD="$root_pw" "$name" mysql -uroot -h127.0.0.1 --default-character-set=utf8mb4 >/dev/null
  local ro_enc
  ro_enc=$(printf '%s' "$ro_pw" | sed -e 's/@/%40/g' -e 's/)/%29/g' -e 's/\$/%24/g')
  log "ready: read-only login dbmcp_ro (SELECT, SHOW VIEW on appdb)"
  echo "export DB_MCP_MYSQL_TEST_DSN='mysql://dbmcp_ro:${ro_enc}@127.0.0.1:${port}/appdb'"
  echo "export DB_MCP_MYSQL_TEST_DSN_DIAG='mysql://dbmcp_diag:${diag_pw}@127.0.0.1:${port}/appdb'"
  echo "export DB_MCP_MYSQL_TEST_DSN_RW='mysql://dbmcp_rw:${rw_pw}@127.0.0.1:${port}/appdb'"
}

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
  mysql) up_mysql ;;
  mssql|sqlserver)
    if [ "$ACTION" = "--down" ]; then docker rm -f dbmcp-mssql >/dev/null 2>&1 || true; log "removed dbmcp-mssql"; exit 0; fi
    mssql_up ;;
  *) echo "usage: bash scripts/live-db-up.sh <mysql|mssql> [--down]" >&2; exit 2 ;;
esac
