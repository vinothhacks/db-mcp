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

## Environment variables

| Variable | Effect |
|---|---|
| `DB_MCP_BINARY_PATH` | Use this `db-mcp-server` executable instead of resolving/downloading one |
| `DB_MCP_SKIP_DOWNLOAD=1` | Never download prebuilt binaries (build locally or fail) |
| `DB_MCP_RELEASE_BASE_URL` | Override the release download base (mirrors / air-gapped) |
| `DB_MCP_AUTH_TOKEN`, `DB_MCP_ADMIN_TOKEN` | Bearer tokens referenced from the example config |
| `DB_MCP_APPROVAL_KEY` | HMAC key signing change approvals when `changes.approval_key` is unset (required for `apply_change` on GovernedProduction) |
| `RUST_LOG` | Tracing filter for the server (`info`, `debug`, ...) |
