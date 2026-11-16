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
| `RUST_LOG` | Tracing filter for the server (`info`, `debug`, ...) |
