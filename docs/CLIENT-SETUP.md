# Connecting coding agents to DB-MCP

All recipes assume a config file at `/abs/path/db-mcp.toml` (create one with `npx @vinoth_n_3000/db-mcp init`).
Replace `npx -y @vinoth_n_3000/db-mcp` with the path to `db-mcp-server` if you installed the binary directly.

## stdio (local agents)

### Claude Code

```bash
claude mcp add db-mcp -- npx -y @vinoth_n_3000/db-mcp serve --transport stdio --config /abs/path/db-mcp.toml
claude mcp list
```

Project-scoped alternative (`.mcp.json` in the repo root):

```json
{
  "mcpServers": {
    "db-mcp": {
      "command": "npx",
      "args": ["-y", "@vinoth_n_3000/db-mcp", "serve", "--transport", "stdio", "--config", "/abs/path/db-mcp.toml"]
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "db-mcp": {
      "command": "npx",
      "args": ["-y", "@vinoth_n_3000/db-mcp", "serve", "--transport", "stdio", "--config", "/abs/path/db-mcp.toml"],
      "env": { "DATABASE_URL": "postgres://user:pass@localhost:5432/app" }
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
      "command": "npx",
      "args": ["-y", "@vinoth_n_3000/db-mcp", "serve", "--transport", "stdio", "--config", "${workspaceFolder}/db-mcp.toml"]
    }
  }
}
```

### Windsurf / Cline / Continue

Use the generic stdio shape: command `npx`, args `["-y", "@vinoth_n_3000/db-mcp", "serve", "--transport", "stdio", "--config", "<path>"]`.

## Streamable HTTP (shared or self-hosted)

```bash
export DB_MCP_AUTH_TOKEN=agent-secret
export DB_MCP_ADMIN_TOKEN=admin-secret
npx @vinoth_n_3000/db-mcp serve --transport http --bind 0.0.0.0:8080 --config /abs/path/db-mcp.toml
```

Endpoints:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/mcp` | `Authorization: Bearer <DB_MCP_AUTH_TOKEN>` | MCP JSON-RPC (`initialize`, `tools/list`, `tools/call`, `ping`) |
| GET | `/health` | none | liveness, server name, connection and tool counts |
| GET | `/metrics` | none | audit event count, registered tools |
| POST | `/admin/approve` | `Authorization: Bearer <DB_MCP_ADMIN_TOKEN>` | approve a `chg_*` proposal out of band |

Caller identity over HTTP comes from `X-MCP-Principal` and `X-MCP-Role` headers (defaults: `local-agent` / `agent`).

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
npx @vinoth_n_3000/db-mcp approve --change-id chg_abc123 --approver release-admin --config /abs/path/db-mcp.toml

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

## Connect to SQL Server

DB-MCP talks to Microsoft SQL Server directly over TDS (pure-Rust TLS, no ODBC driver needed). The
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
| `encrypt` | `optional` | `optional`: TLS for the login packet when the server offers it (ODBC `Encrypt=Optional`); `true`: encrypt the whole session and fail without TLS; `disable`: no TLS at all. `strict` (TDS 8.0) is not supported yet. |
| `trustServerCertificate` | `true` | Accept the server certificate without validation (typical for private networks with self-signed certificates). Set `false` to validate against the OS trust store. |
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
| `RUST_LOG` | Tracing filter for the server (`info`, `debug`, ...) |
