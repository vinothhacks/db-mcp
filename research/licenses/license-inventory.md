# License Inventory and Clean-Room Boundary Audit

## 1. Executive Summary

This inventory records the license obligations, third-party dependencies, and clean-room boundaries for the four reference projects studied during Phase 0 of **DB-MCP**. All Rust crates in `crates/db-mcp-*` are written from scratch as an independent clean-room implementation against the behavioral contracts in `research/contracts/tool-contracts.json`.

---

## 2. Reference Project License Matrix

| Reference Project | Pinned Version / Commit | License | Commercial / Self-Hosted Reuse Policy | DB-MCP Implementation Approach |
|---|---|---|---|---|
| **DBHub** (`@bytebase/dbhub`) | `1.5.0` (`d49b0cf347bb2e1bd1df345837e5c482dff1d13f`) | **MIT License** (`Copyright (c) 2025 Bytebase`) | Permissive; allows study, adaptation, and commercial/self-hosted use with copyright notice retention in reference artifacts. | Clean-room Rust re-architecture of progressive schema discovery (`search_objects`, `describe_object`), `max_rows` N+1 truncation probing, read-only transaction wrapping, and escape-hatch function blocking. |
| **Postgres MCP Pro** (`crystaldba/postgres-mcp`) | `0.3.0` (`a3f91d8c4b2e70619f54e821c0d39a7b6e124501`) | **Apache License 2.0** | Permissive; allows study and independent re-implementation in Rust. | Independent Rust implementation in `db-mcp-pg-insights` (`database_health`, `analyze_workload`, `recommend_indexes` with heuristic AST extraction + optional HypoPG evaluation). |
| **Google MCP Toolbox** (`googleapis/genai-toolbox`) | `0.5.0` (`7c82e149b05a4d198f32e0619a4b7c2d81e53904`) | **Apache License 2.0** | Permissive; allows study and independent re-implementation in Rust. | Independent Rust implementation in `db-mcp-tools` (`run_named_tool`, typed parameter schemas, `allowed_values` validation, and strictly bound SQL execution). |
| **Bytebase** (`bytebase/bytebase`) | `3.4.0` (`e914b2c7803f5a126d984c017b3e52a90f816420`) | **Dual License**: Apache-2.0 (`LICENSE`) + Bytebase Enterprise (`LICENSE.enterprise`) | **Restricted Enterprise Boundary**: Enterprise features (dynamic data masking, multi-stage enterprise approval workflows, RBAC enterprise policies) are governed by `LICENSE.enterprise`. | **Strict Clean-Room Boundary**: Zero code copied or translated from Bytebase. DB-MCP implements its own independent SHA-256 cryptographic approval binding (`db-mcp-changes`), policy engine (`db-mcp-policy`), and column/secret redaction from first-principles requirements. |

---

## 3. Third-Party Dependency Inventory of `@bytebase/dbhub@1.5.0` (Reference Artifact)

Extracted from `reference/dbhub/package.json` (SHA-256 root artifact digest `54faee3eb8fe59cdad5ad1b1e74faf20ff8387bb6ea8f6530f3cd7e1cd1fdb96` verified by REA MCP):

### Runtime Dependencies (Reference Only — Not Shipped in DB-MCP Rust Binary)
- `@modelcontextprotocol/node` (`^2.0.0`) — MIT
- `@modelcontextprotocol/server` (`^2.0.0`) — MIT
- `@iarna/toml` (`^2.2.5`) — ISC
- `dotenv` (`^16.4.7`) — BSD-2-Clause
- `express` (`^4.18.2`) — MIT
- `ssh-config` (`^5.0.3`) — MIT
- `ssh2` (`^1.16.0`) — MIT
- `zod` (`^4.2.0`) — MIT

### Optional Database Driver Dependencies (Reference Only)
- `pg` (`^8.13.3`) — MIT
- `mysql2` (`^3.13.0`) — MIT
- `mariadb` (`^3.4.0`) — LGPL-2.1-or-later (Note: DBHub optional JS dependency only; DB-MCP uses MIT/Apache-2.0 Rust crates)
- `mssql` (`^11.0.1`) — MIT
- `oracledb` (`^7.0.1`) — Apache-2.0

---

## 4. Planned Rust Workspace Dependency License Gate

All crates selected for the DB-MCP Rust workspace must satisfy `MIT OR Apache-2.0` (or BSD/ISC equivalent) licensing:
- `tokio` — MIT
- `serde`, `serde_json`, `toml` — MIT / Apache-2.0
- `sqlparser` — Apache-2.0
- `rusqlite` — MIT
- `tokio-postgres` / `sqlx` — MIT / Apache-2.0
- `sha2`, `hex`, `uuid`, `chrono` — MIT / Apache-2.0
- `axum` / `hyper` — MIT
- `clap` — MIT / Apache-2.0
- `tracing`, `tracing-subscriber` — MIT

---

## 5. Governance & Masking Compliance Rules

1. **No Bytebase Enterprise Porting**: Bytebase's dynamic data masking and enterprise approval engine are proprietary under `LICENSE.enterprise`. DB-MCP implements:
   - Least-privilege database roles and read-only session enforcement (`BEGIN READ ONLY`, `PRAGMA query_only = ON`, `SET SESSION TRANSACTION READ ONLY`).
   - Declarative parameterized tools (`run_named_tool`) for curated access to sensitive tables.
   - Policy-based sensitive column guards and secret redaction in `db-mcp-policy` and `db-mcp-secrets`.
   - Independent SHA-256 proposal/approval state machine in `db-mcp-changes` with out-of-band CLI approval (`db-mcp approve`).
2. **REA Isolation**: REA (`user-rea`) is used strictly during Phase 0 investigation and post-build verification; it is never linked into or invoked by the production DB-MCP server.
