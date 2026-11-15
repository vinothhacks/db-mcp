# DB-MCP governed ontology: tool contract

Machine-readable version: `research/contracts/ontology-tools.json`.
All tools return the standard DB-MCP envelope (`request_id`, `connection`, `status`, `columns`,
`rows`, `returned_rows`, `truncated`, `warnings`, `schema_version`, `_meta.provenance`) with
results in `data`. Denials use `status: "denied"`, `code`, `message`, `next_action`.

## Definition bodies (typed, no SQL)

```json
{"type": "entity", "table": "orders"}
{"type": "attribute", "table": "users", "column": "role"}
{"type": "relationship", "from_table": "orders", "to_table": "users",
 "column_pairs": [["user_id", "id"]], "cardinality": "many_to_one", "source": "manual"}
{"type": "metric", "base_table": "orders", "aggregation": "sum", "column": "total_cents",
 "default_filters": ["filter:completed_order"], "unit": "cents", "grain": "order"}
{"type": "filter", "table": "orders", "column": "status", "operator": "eq", "value": "completed"}
```

Aggregations: `sum`, `count` (column optional), `count_distinct`, `avg`, `min`, `max`.
Filter operators: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in` (array value), `is_null`, `is_not_null`.
Table names are canonicalized to the catalog's qualified name on proposal.

## Tools

| Tool | Required | Optional | Notes |
|---|---|---|---|
| `ontology_status` | `connection` | | readiness `ready` / `degraded` / `not_ready` with reasons; runs the drift check |
| `discover_ontology` | `connection` | `infer_joins` | writes `discovered` candidates; idempotent |
| `search_terms` | `connection`, `query` | `kinds`, `statuses`, `limit` | `usable_for_sql` is true only for published definitions |
| `describe_term` | `connection`, one of `def_id` / `name` | | versions, certifications, `in_published_revision` |
| `trace_semantic_relationships` | `connection` | `entity`, `max_depth`, `certified_only` | edges + Mermaid (solid = published) |
| `propose_semantic_definition` | `connection`, `definition` | `def_id`, `expected_version` | creates `proposed` version |
| `plan_semantic_query` | `connection`, `question` | `max_rows` | `data.status`: `answerable`, `not_answerable`, `ambiguous`, `stale` |
| `ask_semantic_question` | `connection`, `question` | `plan_hash`, `max_rows` | executes only answerable plans; `data.answered` |

### Plan (`plan_semantic_query.data`)

```json
{
  "status": "answerable",
  "sql": "SELECT t1.role AS user_role, SUM(t0.total_cents) AS order_value FROM main.orders t0 JOIN main.users t1 ON t1.id = t0.user_id GROUP BY t1.role ORDER BY order_value DESC LIMIT 200",
  "params": [],
  "plan_hash": "<sha256>",
  "metric": {"def_id": "metric:order_value", "version": 1, "name": "order value", "content_hash": "..."},
  "dimensions": [{"def_id": "attribute:main.users.role", "version": 1, "...": "..."}],
  "filters": [],
  "relationships": [{"def_id": "relationship:main.orders(user_id)->main.users", "...": "..."}],
  "tables": ["main.orders", "main.users"],
  "missing": [],
  "candidates": [{"def_id": "...", "name": "...", "score": 9.1, "status": "published"}],
  "assumptions": ["selected metric 'order value' (score ...) over 'order count' (score ...)"],
  "limitations": ["'order value' is expressed in cents"],
  "result_kind": "rule_based_calculation",
  "revision_id": "rev_...",
  "schema_fingerprint": "snapshot_..."
}
```

Refusals keep `sql` empty and explain themselves in `missing`, for example
`multiplicative join: main.orders -> main.order_items is one-to-many ...` or
`'revenue' matches several certified metrics: ...`.

## Admin channel

```text
db-mcp ontology list|show|review|publish|eval ... --config <file>
POST /admin/ontology/review   {connection, def_id, version, action, reviewer, role?, reason?}
POST /admin/ontology/publish  {connection, reviewer, role?}
```

Both HTTP endpoints require `Authorization: Bearer <http.admin_token>`.

## Denial codes

`ONTOLOGY_VERSION_CONFLICT`, `ONTOLOGY_UNKNOWN_OBJECT`, `ONTOLOGY_SENSITIVE_COLUMN`,
`ONTOLOGY_INVALID_DEFINITION`, `ONTOLOGY_INVALID_TRANSITION`, `ONTOLOGY_CERTIFICATION_INVALID`,
`ONTOLOGY_NOTHING_TO_PUBLISH`, `ONTOLOGY_PLAN_MISMATCH`, `SELF_APPROVAL_FORBIDDEN`,
`SCHEMA_DRIFT_DETECTED`, `ADMIN_TOKEN_NOT_CONFIGURED`, plus the standard connection and policy
codes (`CONNECTION_NOT_FOUND`, `UNAUTHORIZED_ROLE`, `RESTRICTED_TABLE`, ...).

## Recommended agent workflow

```text
list_connections -> ontology_status
  ready:     search_terms / describe_term -> plan_semantic_query -> ask_semantic_question(plan_hash)
  not_ready: search_objects / trace_table_dependencies -> discover_ontology
             -> propose_semantic_definition -> ask a human to review and publish
  degraded:  diff_schema -> propose revised definitions (expected_version) -> human re-certifies
```
