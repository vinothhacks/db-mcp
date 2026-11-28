# DB MCP first use on Windows x64

This guide exercises the native SQLite backend in the published `v0.3.0` Windows x64 ZIP. Use PowerShell in an empty directory. The database stays in memory and the server uses local stdio.

```powershell
$archive = 'db-mcp-server-v0.3.0-x86_64-pc-windows-msvc.zip'
$base = 'https://github.com/vinothhacks/db-mcp/releases/download/v0.3.0'
curl.exe --fail --location --silent --show-error --output $archive "$base/$archive"
if ($LASTEXITCODE -ne 0) { throw 'DB MCP archive download failed' }
curl.exe --fail --location --silent --show-error --output "$archive.sha256" "$base/$archive.sha256"
if ($LASTEXITCODE -ne 0) { throw 'DB MCP checksum download failed' }
$expected = ((Get-Content "$archive.sha256" -Raw).Trim() -split '\s+')[0]
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'DB MCP archive checksum mismatch'
}
Expand-Archive -LiteralPath $archive -DestinationPath '.\db-mcp-v0.3.0'
Set-Location '.\db-mcp-v0.3.0'
.\db-mcp-server.exe verify-config --config .\db-mcp.example.toml
if ($LASTEXITCODE -ne 0) { throw 'Bundled config validation failed' }
```

Create a read-only SQLite connection and send an MCP initialize and query request.

```powershell
@'
default_mode = "ReadOnly"
active_profiles = ["Query"]

[[connections]]
id = "academy-sqlite"
engine = "Sqlite"
dsn = "sqlite://:memory:"
mode = "ReadOnly"
read_only = true
'@ | Set-Content -Encoding ascii '.\first-use.toml'
.\db-mcp-server.exe verify-config --config .\first-use.toml
if ($LASTEXITCODE -ne 0) { throw 'Fixture config validation failed' }

@(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"academy","version":"1"}}}'
  '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_query","arguments":{"connection":"academy-sqlite","sql":"SELECT 1 AS ready"}}}'
) | .\db-mcp-server.exe serve --transport stdio --config .\first-use.toml
```

Config validation returns `status: ok`. The initialize response identifies `db-mcp` and the query returns `structuredContent.status: ok` with `rows: [[1]]`.

The `v0.3.0` binary predates the native `selftest` command. The Academy release gate still requires a published build with a passing `selftest` and config validation. Linux and macOS first use and exact-release MySQL and SQL Server checks are pending. PostgreSQL support is an embedded simulation.

Get approval before connecting to shared or production data, modifying rows or schema, or granting broader privileges. Keep credentials in environment references and use a dedicated read-only login for shared databases.
