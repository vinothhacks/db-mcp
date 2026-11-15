# DB-MCP

Self-hosted **database MCP server written in Rust** for coding agents (Claude Code, Cursor, Windsurf, Claude Desktop, VS Code, any MCP client).

It combines, in one binary:

| Capability | What the agent gets |
|---|---|
| Schema exploration | `list_connections`, `search_objects`, `describe_object` with pagination and detail levels |
| Lineage and call graphs | `trace_table_dependencies` (FK graph, dependent views/triggers/procedures, shortest join path, Mermaid) and `get_procedure_call_graph` (callers/callees, cycles, table read/write touchpoints, Mermaid) |
| Bounded SQL | `execute_query`, `explain_query` with timeouts, row and byte limits, parameter binding, multi-statement and mutating-CTE guards, sensitive-column redaction |
| Declarative tools | `run_named_tool` for curated parameterized SQL defined in config (zero string interpolation) |
| PostgreSQL intelligence | `database_health`, `analyze_workload`, `recommend_indexes` (heuristic candidates + HypoPG validation when available) |
| Governed changes | `propose_change`, `get_change`, `apply_change` with SHA-256 approval binding, separation of duties, replay prevention and schema-drift checks |
| Schema snapshots | `capture_schema`, `diff_schema` with deterministic `snapshot_<hash>` versions |
| Governed ontology (v0.2) | `ontology_status`, `discover_ontology`, `search_terms`, `describe_term`, `trace_semantic_relationships`, `propose_semantic_definition`, `plan_semantic_query`, `ask_semantic_question`: certified business terms, metrics and relationships, and natural-language questions compiled into validated SQL only from human-certified definitions |
| Audit | Structured JSONL + SQLite audit trail for every tool call, denial and admin action, with literal-free SQL fingerprints and secret redaction |

Engines: **SQLite** (native). **PostgreSQL** and **MySQL/MariaDB** connections currently run on a deterministic embedded simulation (no wire-protocol client yet). Every response from those connections carries a warning saying so, so an agent never mistakes simulated output for production data. See `research/findings/capability-matrix.md`.

Transports: **stdio** (local agents) and **Streamable HTTP** JSON-RPC (`POST /mcp`, Bearer auth, `/health`, `/metrics`, `/admin/approve`, `/admin/ontology/review`, `/admin/ontology/publish`).

---

## Quick start

### Option A: npx (no Rust toolchain needed)

```bash
npx @vinoth_n_3000/db-mcp init                                   # writes ./db-mcp.toml starter config
npx @vinoth_n_3000/db-mcp verify-config --config ./db-mcp.toml
npx @vinoth_n_3000/db-mcp serve --transport stdio --config ./db-mcp.toml
```

On first run the launcher downloads the prebuilt `db-mcp-server` binary for your platform from the
[GitHub release](https://github.com/vinothhacks/db-mcp/releases) matching the package version, verifies its SHA-256,
and caches it under `~/.db-mcp/bin/`. If no prebuilt binary exists for your platform it falls back to
`cargo install` from this repository (requires Rust), or to a binary you point at with `DB_MCP_BINARY_PATH`.

### Option B: cargo

```bash
cargo install --git https://github.com/vinothhacks/db-mcp --locked db-mcp-server
db-mcp-server serve --transport stdio --config ./db-mcp.toml
```

### Option C: Docker (self-hosted HTTP)

```bash
docker compose up --build            # db-mcp on :8080 plus disposable Postgres and MySQL
curl -s http://127.0.0.1:8080/health
```

### Option D: from source

```bash
git clone https://github.com/vinothhacks/db-mcp && cd db-mcp
npm run build                        # cargo build --release -p db-mcp-server
npm test                             # stdio + HTTP + CLI approval end-to-end
npm run verify:features              # exercises all 24 tools and prints a feature matrix
```

---

## Connect your coding agent

The server speaks MCP over stdio. Point your client at the launcher (or the binary) and a config file.

**Claude Code**

```bash
claude mcp add db-mcp -- npx -y @vinoth_n_3000/db-mcp serve --transport stdio --config /abs/path/db-mcp.toml
```

**Cursor / Windsurf / Claude Desktop / VS Code** (`mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json`)

```json
{
  "mcpServers": {
    "db-mcp": {
      "command": "npx",
      "args": ["-y", "@vinoth_n_3000/db-mcp", "serve", "--transport", "stdio", "--config", "/abs/path/db-mcp.toml"],
      "env": { "DATABASE_URL": "postgres://user:pass@host:5432/app" }
    }
  }
}
```

More client recipes, HTTP mode and the admin approval flow: [docs/CLIENT-SETUP.md](docs/CLIENT-SETUP.md).

---

## Configuration

`config/db-mcp.example.toml` is a complete, validated example. The important parts:

```toml
server_name = "db-mcp"
default_mode = "ReadOnly"                 # Development | ReadOnly | GovernedProduction
active_profiles = ["Explore", "Query", "Diagnose", "Change", "Schema"]

[http]
bind = "127.0.0.1:8080"
auth_token = "env:DB_MCP_AUTH_TOKEN"      # Bearer token for POST /mcp (optional)
admin_token = "env:DB_MCP_ADMIN_TOKEN"    # Bearer token for POST /admin/approve

[audit]
jsonl_path = "research/traces/audit.jsonl"
sqlite_path = "research/traces/audit.db"

[changes]
storage_path = "research/traces/changes.db"
policy_revision = "policy_v1"
default_ttl_seconds = 3600

[[connections]]
id = "prod-postgres"
engine = "Postgres"                       # Postgres | MySql | Sqlite
dsn = "env:DATABASE_URL"                  # literal DSN, env:VAR, or file:/path
mode = "GovernedProduction"
read_only = false
timeout_ms = 10000
max_rows = 500
max_bytes = 1048576
restricted_tables = ["internal_secrets"]
sensitive_columns = ["password_hash", "api_key", "secret_token"]
allowed_roles = ["agent", "developer", "dba", "admin"]

[[named_tools]]
name = "get_user_by_id"
connection = "prod-postgres"
statement = "SELECT id, email, role FROM users WHERE id = ?1"
read_only = true
[[named_tools.parameters]]
name = "user_id"
param_type = "integer"
required = true
```

Validate any config with `db-mcp verify-config --config <file>`. Secrets are never echoed: DSNs resolve through
`env:` / `file:` references and are redacted in logs, errors and audit records.

### Operating modes

| Mode | Reads | Writes / DDL | Notes |
|---|---|---|---|
| `Development` | yes | direct | local fixtures, still bounded by limits |
| `ReadOnly` | yes | denied (`MUTATION_NOT_ALLOWED_IN_READ_ONLY`) | mutating CTEs and privileged functions blocked |
| `GovernedProduction` | yes | only via approved `chg_*` proposals | self-approval, replay, hash tampering and schema drift are rejected |

### Governed change flow

```text
agent: propose_change  ->  chg_123 (PENDING, approval_hash)
admin: db-mcp approve --change-id chg_123 --approver release-admin      # CLI, or POST /admin/approve
agent: apply_change    ->  executes once, re-verifies hash + schema fingerprint, audited
```

---

## Governed ontology (semantic layer)

The ontology turns schema objects into **certified** business definitions and answers questions only
from them. It never lets a model write free-form SQL.

```text
agent:    discover_ontology            -> unverified candidates (entities, attributes, FK relationships, metrics)
agent:    propose_semantic_definition  -> typed drafts ("order value" = SUM(orders.total_cents), filters, joins)
reviewer: db-mcp ontology review ...   -> certify one exact version (reviewer != proposer, admin/dba role)
reviewer: db-mcp ontology publish ...  -> immutable revision pinned to the schema fingerprint
agent:    plan_semantic_query          -> answerable | not_answerable | ambiguous | stale, with SQL + provenance
agent:    ask_semantic_question        -> runs the validated plan through the governed executor
```

- Definitions are versioned and immutable; only their lifecycle status changes (`discovered -> proposed -> certified -> published -> stale/deprecated`, or `rejected`).
- Certifications bind the definition content hash, schema fingerprint, reviewer and expiry (optionally HMAC-signed with `ontology.review_key`).
- Plans refuse instead of guessing: no certified metric, ambiguous metric names, unknown dimensions, sensitive columns and one-to-many joins that would double count all return `not_answerable` or `ambiguous`.
- Schema drift (dropped or retyped columns) marks dependent definitions `stale`; they stop generating SQL until re-certified, and pinned `plan_hash` values stop matching.
- Restricted tables never enter the ontology; sensitive columns can be described but never used as filters, metrics or grouping keys.
- Store: a dedicated SQLite metadata database (`[ontology] storage_path`), never the business database.

Admin channel (never exposed to agents):

```bash
db-mcp ontology list    --connection local-sqlite --status discovered --config db-mcp.toml
db-mcp ontology review  --connection local-sqlite --def-id metric:order_value --version 1 --action approve --reviewer alice --config db-mcp.toml
db-mcp ontology publish --connection local-sqlite --reviewer alice --config db-mcp.toml
db-mcp ontology eval    --connection local-sqlite --cases research/ontology/golden-local-sqlite.json --config db-mcp.toml
# or over HTTP with the admin token: POST /admin/ontology/review, POST /admin/ontology/publish
```

Design, security model and contracts: [docs/ontology/architecture.md](docs/ontology/architecture.md),
[docs/ontology/security.md](docs/ontology/security.md), [docs/ontology/contract.md](docs/ontology/contract.md).

---

## Tool reference

- Explore: `list_connections`, `search_objects`, `describe_object`, `trace_table_dependencies`, `get_procedure_call_graph`
- Query: `execute_query`, `explain_query`, `run_named_tool`
- Diagnose: `database_health`, `analyze_workload`, `recommend_indexes`
- Change: `propose_change`, `get_change`, `apply_change`
- Schema: `capture_schema`, `diff_schema`
- Ontology: `ontology_status`, `discover_ontology`, `search_terms`, `describe_term`, `trace_semantic_relationships`, `propose_semantic_definition`, `plan_semantic_query`, `ask_semantic_question`

Every success response carries the same envelope: `request_id`, `connection`, `status`, `columns`, `rows`,
`returned_rows`, `truncated`, `warnings`, `schema_version`, plus `_meta.provenance.untrusted_content = true` so
agents treat database content as data, not instructions. Denials are structured: `status: "denied"`, `code`,
`message`, `next_action`. Full contracts: `research/contracts/tool-contracts.json`.

Call any tool from a shell for debugging:

```bash
node scripts/mcp-call.js --config config/db-mcp.example.toml trace_table_dependencies '{"connection":"local-sqlite","table_name":"users","target_table":"order_items"}'
node scripts/mcp-call.js --raw tools/list
```

---

## Repository layout

```text
crates/            16 Rust crates (core, secrets, sql, catalog, policy, audit, executor, tools,
                   sqlite, postgres, mysql, pg-insights, changes, ontology, mcp, server)
npm/bin/db-mcp.js  npx launcher: resolves, downloads or builds the native binary
npm/test/          Node end-to-end suite (stdio, HTTP, CLI approval)
scripts/           mcp-call.js (ad-hoc client), feature-smoke.js (all-feature verification)
config/            example configuration
docs/              client setup, feature verification report
research/          contracts, capability matrix, provenance, license inventory
tests/             contract, integration and adversarial-security suite indexes (run by cargo)
```

## Development

```bash
cargo test --workspace            # unit + contract + adversarial security + runtime integration
npm test                          # Node E2E over the npx launcher
npm run verify:features           # feature matrix (used by CI)
```

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
Reference projects studied during design (DBHub, Postgres MCP Pro, Google MCP Toolbox, Bytebase) are documented in
`research/licenses/license-inventory.md`; DB-MCP is a clean-room Rust implementation.
