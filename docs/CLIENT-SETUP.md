# Connecting coding agents to DB-MCP

Install the native binary using the [release archive instructions](../README.md#quick-start). Copy the bundled example config to `db-mcp.toml` and point each client at the absolute paths to the binary and config. On Windows, include the `.exe` suffix and escape backslashes in JSON.

## stdio (local agents)

### Claude Code

```bash
claude mcp add db-mcp -- /abs/path/db-mcp-server serve --transport stdio --config /abs/path/db-mcp.toml
claude mcp list
```

Project-scoped alternative (`.mcp.json` in the repo root):

```json
{
  "mcpServers": {
    "db-mcp": {
      "command": "/abs/path/db-mcp-server",
      "args": ["serve", "--transport", "stdio", "--config", "/abs/path/db-mcp.toml"]
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "db-mcp": {
      "command": "/abs/path/db-mcp-server",
      "args": ["serve", "--transport", "stdio", "--config", "/abs/path/db-mcp.toml"],
      "env": { "DATABASE_URL": "<database-dsn>" }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

Same JSON shape as Cursor under the `mcpServers` key.

### VS Code (`.vscode/mcp.json`)

```json
{
  "servers": {
    "db-mcp": {
      "type": "stdio",
      "command": "/abs/path/db-mcp-server",
      "args": ["serve", "--transport", "stdio", "--config", "${workspaceFolder}/db-mcp.toml"]
    }
  }
}
```

### Windsurf / Cline / Continue

Use the generic stdio shape: command `/abs/path/db-mcp-server`, args `["serve", "--transport", "stdio", "--config", "<path>"]`.

## Streamable HTTP (shared or self-hosted)

```bash
export DB_MCP_AUTH_TOKEN="<agent-token>"
export DB_MCP_ADMIN_TOKEN="<admin-token>"
/abs/path/db-mcp-server serve --transport http --bind 127.0.0.1:8080 --config /abs/path/db-mcp.toml
```

Endpoints:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/mcp` | `Authorization: Bearer <DB_MCP_AUTH_TOKEN>` | MCP JSON-RPC (`initialize`, `tools/list`, `tools/call`, `ping`) |
| GET | `/health` | none | liveness, server name, connection and tool counts |
| GET | `/metrics` | none | audit event count, registered tools |
| POST | `/admin/approve` | `Authorization: Bearer <DB_MCP_ADMIN_TOKEN>` | approve a `chg_*` proposal out of band |

Only share the HTTP bearer token with trusted clients. Token holders can set `X-MCP-Principal` and `X-MCP-Role`. For a shared deployment, keep the agent token at a trusted proxy that authenticates clients and sets those headers. Non-loopback binds require a configured agent token.

Example:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $DB_MCP_AUTH_TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_connections","arguments":{}}}'
```

Clients that support remote MCP servers can connect directly, for example
`claude mcp add --transport http db-mcp http://host:8080/mcp --header "Authorization: Bearer <token>"`.

## Approving governed changes

```bash
# CLI (same machine / same changes.db)
/abs/path/db-mcp-server approve --change-id chg_abc123 --approver release-admin --config /abs/path/db-mcp.toml

# HTTP
curl -s http://127.0.0.1:8080/admin/approve \
  -H "Authorization: Bearer $DB_MCP_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"change_id":"chg_abc123","approver":"release-admin","comment":"reviewed"}'
```

The proposing principal can never approve its own change (`SELF_APPROVAL_FORBIDDEN`), an approval is consumed exactly
once (`APPROVAL_ALREADY_CONSUMED`), and the SQL, parameters, connection, policy revision and schema fingerprint are all
bound into the approval hash (`APPROVAL_HASH_MISMATCH`, `SCHEMA_DRIFT_DETECTED`).

Only a `proposed` change can be approved, and only once: a second or concurrent approval, or approving a rejected or
expired change, is refused (`CHANGE_NOT_PENDING`, `APPROVAL_EXPIRED`). `propose_change` applies the connection policy of
`execute_query` (restricted tables, multi-statement batches, ReadOnly connections, privileged and administrative
statements) and refuses plain reads (`NOT_A_CHANGE`); `apply_change` checks the policy again before executing.

### Approval key

Approval records are signed with HMAC-SHA256 (`approval_mac`) over the change id, approval hash, approver, approval
time and comment. Configure the same key for the server and for `db-mcp approve`:

```toml
[changes]
approval_key = "env:DB_MCP_APPROVAL_KEY"   # or "file:/run/secrets/db-mcp-approval-key"; at least 16 bytes
```

When `changes.approval_key` is unset, the `DB_MCP_APPROVAL_KEY` environment variable is used if present. A configured
reference that cannot be resolved stops startup. `apply_change` refuses an approval whose MAC is missing or invalid
(`APPROVAL_HASH_MISMATCH`), so an approval written directly into `changes.db` is never executed. Rotating the key
invalidates approvals that have not been applied yet; approve them again.

Without a key, approvals in a persistent change store are not keyed: the server prints a startup warning, approve and
apply results carry the warning `approval records are not keyed`, and **GovernedProduction connections refuse
`apply_change`** (`APPROVAL_KEY_REQUIRED`). Development connections keep working. An in-memory change store (no
`storage_path`) signs approvals with a random per-process key.

## Connect to MySQL (live MySQL 8, read-only login)

MySQL connections talk to the real server (`backend = "live"`, the default for `engine = "MySql"`).
The embedded simulation is used only when a connection says `backend = "simulated"` (the bundled
example config does this so the offline demo and test suites never need a server). A live
connection never falls back to the simulation: an unreachable server or a refused login returns
`CONNECTION_UNAVAILABLE` with a `next_action`.

```toml
[[connections]]
id = "mysql-reporting"
engine = "MySql"
dsn = "env:MYSQL_REPORTING_DSN"   # mysql://user:pass@host:3306/database ; never put the password in the file
mode = "ReadOnly"
read_only = true
timeout_ms = 15000                # also sent to the server as max_execution_time
max_rows = 1000
restricted_tables = []
sensitive_columns = ["password_hash", "api_key", "secret_token"]
```

```bash
export MYSQL_REPORTING_DSN='mysql://report_ro:p%40ss%29w%24rd@10.0.0.12:3306/sales'
db-mcp check-connection --config db-mcp.toml --connection mysql-reporting
```

- **DSN**: `mysql://user:password@host[:port][/database][?connect_timeout=<ms>]` (port 3306 and a
  3 s connect timeout by default). Percent-encode special characters in the user or password
  (`@` -> `%40`, `)` -> `%29`, `$` -> `%24`, `:` -> `%3A`, `/` -> `%2F`, `%` -> `%25`). Without a
  database, unqualified table names do not resolve. `mariadb://` is accepted.
- **Transport**: plain TCP only in this build (no TLS). `ssl-mode=DISABLED` is accepted; any other
  `ssl-mode` is a configuration error. `caching_sha2_password` (the MySQL 8 default) works over
  plain TCP through the server's RSA public-key exchange; `mysql_native_password` accounts work too.
- **Read-only defence in depth**: policy (`ReadOnly` mode) and the adapter's SQL guard refuse writes
  first; every pooled session then runs `SET SESSION transaction_read_only = 1` (the server answers
  error 1792 to any write), statements run as prepared statements (one statement each), and the
  login's own grants are the last line. Timeouts set `max_execution_time` on the server and cancel
  with `KILL QUERY` (a login may always kill its own queries).

### Minimum and optional grants

```sql
-- minimum (explore, query, explain, lineage through views, schema diff, ontology, health, index advice)
CREATE USER 'report_ro'@'%' IDENTIFIED BY '...';
GRANT SELECT, SHOW VIEW ON sales.* TO 'report_ro'@'%';

-- optional, read-only diagnostics
GRANT SELECT ON performance_schema.* TO 'report_ro'@'%';  -- analyze_workload from statement digests
GRANT SHOW_ROUTINE ON *.* TO 'report_ro'@'%';             -- procedures/functions + call graph (8.0.20+)
GRANT PROCESS ON *.* TO 'report_ro'@'%';                  -- health sees every session, not just its own
```

| Feature | Needs |
|---|---|
| search/describe tables, views, columns, indexes, foreign keys | `SELECT` on the schema |
| view definitions (lineage through views) | `SHOW VIEW` |
| procedures/functions, `get_procedure_call_graph`, lineage through routines | `SHOW_ROUTINE` (or global `SELECT`) |
| triggers | `TRIGGER` on the table. It also allows creating triggers, so it is **not** recommended for a read-only login; triggers are then not listed and the catalog says so |
| `explain_query` (`EXPLAIN FORMAT=JSON` / `TREE`) | `SELECT` on the tables |
| `explain_query` with `analyze: true` | MySQL 8.0.18+, `allow_explain_analyze = true` (the statement is executed in the read-only session) |
| `database_health` | nothing extra (server counters, own sessions, catalog checks); `PROCESS` for all sessions |
| `analyze_workload` | `SELECT` on `performance_schema` (digests); without it, the server's own session history with a note naming the grant |
| `recommend_indexes` | nothing extra; candidates are checked with a real `EXPLAIN` and emitted as `ALTER TABLE ... ADD INDEX` (advisory only, never executed) |

A missing optional grant is never an error: the response carries a warning or an `info` finding
naming the `GRANT` to request. `check-connection` prints the version, `SELECT 1`, the account's
`SHOW GRANTS`, the catalog object count, `can_write` (with a warning when the account holds any
write privilege) and the optional grants that are missing. It never prints the DSN or password.

### Test against a container

```bash
eval "$(bash scripts/live-db-up.sh mysql)"   # mysql:8.0 on 127.0.0.1:13306, fixture + read-only logins
node npm/test/features/17-mysql-live.test.js
cargo test --release -p db-mcp-mysql         # live tests run when DB_MCP_MYSQL_TEST_DSN is set
bash scripts/live-db-up.sh mysql --down
```

## Connect to SQL Server

DB-MCP talks to Microsoft SQL Server directly over TDS with platform TLS. Linux builds require OpenSSL 3
and system CA certificates at runtime (`libssl3` and `ca-certificates` on Ubuntu 22.04 and Debian 12). The
server version is detected at connect; Query Store diagnostics need SQL Server 2016 or newer.
There is no simulated SQL Server backend: an unreachable server or a failed login is reported as
`CONNECTION_UNAVAILABLE` with `next_action` pointing to `db-mcp check-connection`.

```toml
[[connections]]
id = "erp-sql"
engine = "sqlserver"                 # alias: mssql
dsn = "env:ERP_SQL_DSN"              # never put the password in the file
mode = "read_only"
read_only = true
default_schema = "dbo"
restricted_tables = ["internal_secrets"]
sensitive_columns = ["password_hash"]
```

```bash
# Named instance on an explicit port, SQL login, password percent-encoded (@ -> %40, ) -> %29, $ -> %24)
export ERP_SQL_DSN='sqlserver://ro_user:P%40ss%29w%24rd@10.0.0.5:33333?instance=V2DEMO'
db-mcp check-connection --config db-mcp.toml --connection erp-sql
```

DSN shape: `sqlserver://user:password@host[:port][/database][?parameters]`.

| Parameter | Default | Meaning |
|---|---|---|
| `instance` | none | Named instance. With an explicit port the client connects to that port directly and the name is informational; without a port it is resolved through the SQL Server Browser (UDP 1434). `host%5CINSTANCE` is accepted too. |
| `database` (or `/database` path) | the login's default database | Database whose catalog is explored and queried. |
| `encrypt` | `true` | Encrypt the whole session. `optional` allows login-only TLS and `disable` disables TLS. TDS 8.0 strict mode is pending. |
| `trustServerCertificate` | `false` | Validate the certificate against the OS trust store. The disposable self-signed CI fixture explicitly uses `true`. |
| `connectTimeout` | `15` | Seconds for TCP connect plus login. |
| `applicationName` | `db-mcp` | Shown in `sys.dm_exec_sessions.program_name`. |

`check-connection` prints `{connection, engine, backend, server_version, can_connect, select_1,
object_count, permissions[], can_write, warnings[]}`. It only reads; it warns when the login can
write and lists the optional grants that are missing. It never prints the password, and it exits
non-zero when a live connection cannot be verified.

### Minimum and optional grants

| Feature | Needs |
|---|---|
| search/describe tables and views, execute_query, named tools, lineage over foreign keys, schema capture/diff, ontology | `db_datareader` (minimum) |
| Procedures, functions, triggers and view definitions (call graphs, routine lineage) | `GRANT VIEW DEFINITION TO [user]` |
| `explain_query` (estimated plans via SHOWPLAN_XML), optimizer missing-index hints | `GRANT SHOWPLAN TO [user]` |
| `analyze_workload` from Query Store, table sizes | `GRANT VIEW DATABASE STATE TO [user]` |
| Buffer/PLE counters, connections, blocking, plan-cache workload, missing-index DMVs | `GRANT VIEW SERVER STATE TO [login]` (in `master`) |

Without an optional grant the tool still answers: `database_health` keeps the catalog checks
(missing primary keys, heaps, duplicate/disabled indexes, unindexed foreign keys, untrusted
constraints, database options) and adds an Info finding that names the grant; `explain_query`
returns `UNSUPPORTED_CAPABILITY` with the `GRANT SHOWPLAN` statement; `analyze_workload` reports
`source: unavailable` (or the statements recorded through DB-MCP) instead of inventing statistics;
`list_connections` shows the missing grants under `capabilities.unavailable_reasons` after the
first connect.

### Read-only guarantees

Read-only holds even if one layer fails: the policy engine (ReadOnly mode), the adapter's own read
guard (re-classifies the T-SQL and refuses writes, `EXEC`, `sp_*`/`xp_*`, `OPENROWSET`/`OPENQUERY`,
`BULK INSERT`, `DBCC`, `WAITFOR`, `USE`, `SELECT ... INTO` and semicolon-less batches such as
`SELECT 1 DELETE FROM t`), every statement runs inside `BEGIN TRANSACTION ... ROLLBACK`, and the
login's own permissions. Timeouts and cancellation close the TDS connection (a read-only login
cannot `KILL`); the server rolls the open transaction back. `explain_query` never collects actual
execution plans (`analyze=true` is refused) because they would run the statement. Index advice is
advisory T-SQL (`CREATE NONCLUSTERED INDEX ... ON dbo.t (...)`); DB-MCP never runs it.

To try it locally with a disposable container: `eval "$(bash scripts/live-db-up.sh mssql)"`
(seeds `research/fixtures/sqlserver-live`, creates a `db_datareader` login and an extra-grants
login), then `node npm/test/features/18-sqlserver-live.test.js`.

## Environment variables

| Variable | Effect |
|---|---|
| `DB_MCP_BINARY_PATH` | Use this `db-mcp-server` executable instead of resolving/downloading one |
| `DB_MCP_SKIP_DOWNLOAD=1` | Never download prebuilt binaries (build locally or fail) |
| `DB_MCP_RELEASE_BASE_URL` | Override the release download base (mirrors / air-gapped) |
| `DB_MCP_AUTH_TOKEN`, `DB_MCP_ADMIN_TOKEN` | Bearer tokens referenced from the example config |
| `DB_MCP_CACHE_DIR` | Directory for the per-user binary cache (default `~/.db-mcp`) |
| `DB_MCP_QUIET=1` | Suppress launcher progress messages on stderr |
| `DB_MCP_REPO` | GitHub `owner/repo` used for release downloads and `cargo install --git` (default `vinothhacks/db-mcp`) |
| `DB_MCP_VERSION` | Release version the launcher fetches (default: the package version) |
| `DB_MCP_ALLOW_UNVERIFIED=1` | Install a downloaded binary even when its `.sha256` file cannot be fetched. Default is fail closed; a checksum that is present but does not match is always an error |
| `DB_MCP_APPROVAL_KEY` | HMAC key signing change approvals when `changes.approval_key` is unset (required for `apply_change` on GovernedProduction) |
| `DB_MCP_MYSQL_TEST_DSN` (`_DIAG`, `_RW`) | Live MySQL test DSNs for suite 17 and the gated Rust tests (printed by `scripts/live-db-up.sh mysql`) |
| `RUST_LOG` | Tracing filter for the server (`info`, `debug`, ...) |
