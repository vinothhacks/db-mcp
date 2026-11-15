# Ontology release: REA post-build verification (v0.2.0)

Date: 2026-11-15. Tool: REA MCP (`inspect_pe_imports`, `inspect_rust_binary`,
`inspect_sqlite_database`, `export_evidence_bundle`). Targets were copies of local build outputs;
nothing was executed by REA.

## 1. Release binary `db-mcp-server.exe` (Windows x86_64)

| Fact | Evidence |
|---|---|
| SHA-256 of inspected build | `52f996ae6913ccebfaf714d042b17a279143f383a6d2a0d9104a1cffe703edbf` (16,152,064 bytes) |
| Import coverage | complete: 16 DLLs, 204 imports, no delay-loads |
| Network imports | `ws2_32.dll` only (`socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `getaddrinfo`) |
| No HTTP-client / TLS stack | no `winhttp.dll`, `wininet.dll`, `secur32.dll`/schannel, `crypt32.dll`, `ncrypt.dll` imports |
| Cargo dependency metadata | not embedded (no `cargo-auditable` section); dependency check done on `Cargo.lock` instead |

`Cargo.lock` contains none of `reqwest`, `ureq`, `isahc`, `surf`, `hyper-tls`, `rustls`,
`native-tls`, `openai`/`async-openai`, `anthropic`, `tokio-postgres`, `sqlx`, `mysql_async`.

Interpretation: socket use is explained by the Streamable HTTP server (`bind`/`listen`/`accept`)
and the TCP reachability probe of configured PostgreSQL/MySQL DSNs (`connect`, `getaddrinfo`).
There is no HTTP client, TLS client or model SDK in the binary, so the ontology's discovery and
planning have no path to send schema or data to an external model service. The probe only targets
hosts named in the operator's configuration.

Limits: import tables do not prove which code paths run; a statically linked network client would
not appear as a DLL import, which is why the lockfile scan above is part of the check.

## 2. Ontology metadata store (`ontology.db` produced by `scripts/ontology-demo.js`)

| Fact | Evidence |
|---|---|
| SHA-256 | `8e47db1cf74fff1970b4ba06f355ea15bc627b277862f9ad37f62cf04ff361ac` (126,976 bytes) |
| Tables | `ontology_definitions`, `ontology_certifications`, `ontology_revisions`, `ontology_question_evidence`; no views or triggers |
| Indexes | status and name indexes on definitions; `(def_id, version)` index on certifications; unique `(tenant_id, connection, seq)` on revisions |
| Question evidence content | `question_hash`, `revision_id`, `def_refs` (id, version, content hash), `sql_hash`, `decision`, `principal`, timestamp |
| Not stored | question text, SQL literals or parameters, result rows |

The store is a dedicated file separate from the business database and holds metadata only.

## Reproduce

```bash
cargo build --release -p db-mcp-server
node scripts/ontology-demo.js --keep      # prints the kept ontology.db path
# then, from an MCP client with REA: inspect_pe_imports / inspect_sqlite_database on those paths
```
