#!/usr/bin/env bash
# Start a disposable database container, seed the live fixture and print the test DSNs.
#
#   eval "$(bash scripts/live-db-up.sh mysql)"     # exports DB_MCP_MYSQL_TEST_DSN (+ _DIAG, _RW)
#   bash scripts/live-db-up.sh mysql --down        # remove the container
#
# Only containers on 127.0.0.1 are touched. Passwords are random per run; the read-only password
# contains '@ ) $' so DSN percent-decoding is exercised. Progress goes to stderr, exports to stdout.
set -euo pipefail
cd "$(dirname "$0")/.."

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
  docker exec -i -e MYSQL_PWD="$root_pw" "$name" mysql -uroot -h127.0.0.1 < research/fixtures/mysql-live/01-schema.sql >/dev/null
  sed -e "s|__RO_PASSWORD__|${ro_pw}|" -e "s|__DIAG_PASSWORD__|${diag_pw}|" -e "s|__RW_PASSWORD__|${rw_pw}|" \
    research/fixtures/mysql-live/02-users.sql.tmpl \
    | docker exec -i -e MYSQL_PWD="$root_pw" "$name" mysql -uroot -h127.0.0.1 >/dev/null
  local ro_enc
  ro_enc=$(printf '%s' "$ro_pw" | sed -e 's/@/%40/g' -e 's/)/%29/g' -e 's/\$/%24/g')
  log "ready: read-only login dbmcp_ro (SELECT, SHOW VIEW on appdb)"
  echo "export DB_MCP_MYSQL_TEST_DSN='mysql://dbmcp_ro:${ro_enc}@127.0.0.1:${port}/appdb'"
  echo "export DB_MCP_MYSQL_TEST_DSN_DIAG='mysql://dbmcp_diag:${diag_pw}@127.0.0.1:${port}/appdb'"
  echo "export DB_MCP_MYSQL_TEST_DSN_RW='mysql://dbmcp_rw:${rw_pw}@127.0.0.1:${port}/appdb'"
}

case "$ENGINE" in
  mysql) up_mysql ;;
  *) echo "usage: bash scripts/live-db-up.sh mysql [--down]" >&2; exit 2 ;;
esac
