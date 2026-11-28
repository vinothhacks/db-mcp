//! Stored procedure and function body analyzer for extracting routine call graphs
//! (`CALL`, `PERFORM`, `EXEC`, `EXECUTE`, and SQL function invocations) and
//! table read/write touchpoints (`tables_read`, `tables_written`).

use std::collections::{BTreeMap, BTreeSet};

use db_mcp_core::{DatabaseEngine, SqlStatementClass};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlparser::tokenizer::Tokenizer;

use crate::{dialect_for_engine, is_literal_token, parse_and_analyze_sql, split_sql_statements};

/// Standard SQL built-in functions and procedural keywords that should never be
/// classified as user-defined stored procedure or function calls.
pub const SQL_BUILTIN_FUNCTIONS: &[&str] = &[
    "coalesce",
    "now",
    "count",
    "sum",
    "lower",
    "upper",
    "cast",
    "max",
    "min",
    "avg",
    "concat",
    "substring",
    "substr",
    "date_trunc",
    "nullif",
    "greatest",
    "least",
    "abs",
    "round",
    "floor",
    "ceil",
    "ceiling",
    "mod",
    "power",
    "sqrt",
    "exp",
    "ln",
    "log",
    "length",
    "char_length",
    "character_length",
    "octet_length",
    "bit_length",
    "trim",
    "btrim",
    "ltrim",
    "rtrim",
    "replace",
    "translate",
    "overlay",
    "position",
    "strpos",
    "split_part",
    "left",
    "right",
    "repeat",
    "reverse",
    "initcap",
    "lpad",
    "rpad",
    "format",
    "chr",
    "ascii",
    "md5",
    "sha256",
    "encode",
    "decode",
    "current_timestamp",
    "current_date",
    "current_time",
    "localtime",
    "localtimestamp",
    "clock_timestamp",
    "statement_timestamp",
    "transaction_timestamp",
    "timeofday",
    "age",
    "extract",
    "date_part",
    "date_add",
    "date_sub",
    "datediff",
    "timestampdiff",
    "to_char",
    "to_date",
    "to_timestamp",
    "to_number",
    "make_date",
    "make_timestamp",
    "make_interval",
    "strftime",
    "datetime",
    "date",
    "time",
    "julianday",
    "unixepoch",
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
    "array_agg",
    "string_agg",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "json_build_object",
    "jsonb_build_object",
    "json_build_array",
    "jsonb_build_array",
    "json_extract",
    "json_extract_path",
    "json_extract_path_text",
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_set",
    "json_set",
    "json_object",
    "json_array",
    "json_each",
    "jsonb_each",
    "to_json",
    "to_jsonb",
    "array_length",
    "unnest",
    "generate_series",
    "random",
    "gen_random_uuid",
    "uuid_generate_v4",
    "lastval",
    "currval",
    "nextval",
    "setval",
    "pg_typeof",
    "typeof",
    "ifnull",
    "nvl",
    "iif",
    "if",
    "found",
    "raise",
    "exists",
    "in",
    "values",
    "not",
    "and",
    "or",
];

const NON_TABLE_IDENTIFIERS: &[&str] = &[
    "select",
    "from",
    "where",
    "insert",
    "into",
    "values",
    "update",
    "set",
    "delete",
    "merge",
    "using",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "outer",
    "cross",
    "natural",
    "lateral",
    "on",
    "as",
    "and",
    "or",
    "not",
    "in",
    "exists",
    "null",
    "true",
    "false",
    "case",
    "when",
    "then",
    "else",
    "end",
    "loop",
    "while",
    "for",
    "begin",
    "declare",
    "return",
    "returns",
    "dual",
    "only",
    "unnest",
    "generate_series",
    "json_each",
    "jsonb_each",
];

/// Reference to a routine called inside a stored procedure or function body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoutineCallRef {
    pub callee: String,
    /// One of `"CALL"`, `"PERFORM"`, `"EXEC"`, or `"FUNCTION_EXPR"`.
    pub call_kind: String,
}

/// Complete static analysis of a stored procedure or function definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineBodyAnalysis {
    pub routine_name: String,
    pub calls: Vec<RoutineCallRef>,
    pub tables_read: Vec<String>,
    pub tables_written: Vec<String>,
}

/// Strip SQL comments (`-- ...` and `/* ... */`) while preserving whitespace layout.
fn strip_sql_comments(sql: &str) -> String {
    let block_re = Regex::new(r"(?s)/\*.*?\*/").expect("valid block comment regex");
    let without_blocks = block_re.replace_all(sql, " ");
    let line_re = Regex::new(r"(?m)--[^\r\n]*").expect("valid line comment regex");
    line_re.replace_all(&without_blocks, " ").into_owned()
}

/// Extract the executable body of a `CREATE [OR REPLACE] PROCEDURE/FUNCTION` statement,
/// or return the cleaned SQL if it is already a raw routine body.
pub fn extract_routine_body(definition_sql: &str) -> String {
    let cleaned = strip_sql_comments(definition_sql);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. Check for PostgreSQL dollar-quoted body: AS $$ ... $$ or AS $tag$ ... $tag$
    let dollar_re = Regex::new(r"\$([A-Za-z0-9_]*)\$").expect("valid dollar tag regex");
    if let Some(first_match) = dollar_re.find(trimmed) {
        let tag = first_match.as_str();
        let after_open = &trimmed[first_match.end()..];
        if let Some(last_rel_idx) = after_open.rfind(tag) {
            return after_open[..last_rel_idx].trim().to_string();
        }
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("CREATE ") || upper.starts_with("CREATE\t") || upper.starts_with("CREATE\n")
    {
        // 2. Check for single-quoted body: AS '...'
        let as_quote_re =
            Regex::new(r"(?is)\bAS\s+'((?:[^']|'')*)'").expect("valid AS single-quote regex");
        if let Some(caps) = as_quote_re.captures(trimmed) {
            if let Some(body_match) = caps.get(1) {
                return body_match.as_str().replace("''", "'").trim().to_string();
            }
        }

        // 3. Check for BEGIN ... END block after the routine signature
        let begin_re = Regex::new(r"(?is)\bBEGIN(?:\s+ATOMIC)?\b").expect("valid BEGIN regex");
        if let Some(begin_match) = begin_re.find(trimmed) {
            let after_begin = &trimmed[begin_match.end()..];
            let end_re =
                Regex::new(r"(?is)\bEND\s*(?:[A-Za-z0-9_]+)?\s*;?\s*$").expect("valid END regex");
            let body_slice = if let Some(end_match) = end_re.find(after_begin) {
                &after_begin[..end_match.start()]
            } else {
                after_begin
            };
            return body_slice.trim().to_string();
        }

        // 4. Single-statement routine without BEGIN ... END:
        // Strip the CREATE [OR REPLACE] ... (PROCEDURE|FUNCTION) <name>(<params>) ... header.
        let header_re = Regex::new(
            r"(?is)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:PROCEDURE|FUNCTION|TRIGGER)\s+[^(]+\([^)]*\)\s*(?:RETURNS\s+[^;]+?\s+)?(?:LANGUAGE\s+\w+\s+)?(?:DETERMINISTIC\s+|IMMUTABLE\s+|STABLE\s+|VOLATILE\s+)?(?:AS\s+|RETURN\s+)?",
        )
        .expect("valid header regex");
        if let Some(m) = header_re.find(trimmed) {
            if m.end() < trimmed.len() {
                return trimmed[m.end()..].trim().to_string();
            }
        }
    }

    trimmed.to_string()
}

fn clean_identifier(raw: &str) -> String {
    raw.split('.')
        .map(|part| {
            part.trim()
                .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn base_name(ident: &str) -> &str {
    ident.rsplit('.').next().unwrap_or(ident)
}

fn is_sql_builtin_or_keyword(name: &str) -> bool {
    let base = base_name(&clean_identifier(name)).to_ascii_lowercase();
    SQL_BUILTIN_FUNCTIONS.contains(&base.as_str())
        || NON_TABLE_IDENTIFIERS.contains(&base.as_str())
}

fn is_non_table_word(name: &str) -> bool {
    let cleaned = clean_identifier(name);
    if cleaned.is_empty() {
        return true;
    }
    let base = base_name(&cleaned).to_ascii_lowercase();
    NON_TABLE_IDENTIFIERS.contains(&base.as_str())
}

/// Resolve an identifier against a list of known catalog names (`known_routines` or `known_tables`).
/// Matches exact case-insensitive name first, then falls back to unqualified base-name matching.
fn resolve_known_identifier(raw: &str, known_list: &[String]) -> Option<String> {
    let cleaned = clean_identifier(raw);
    if cleaned.is_empty() {
        return None;
    }

    // Pass 1: exact (case-insensitive) match
    for known in known_list {
        let known_clean = clean_identifier(known);
        if known_clean.eq_ignore_ascii_case(&cleaned) {
            return Some(known.clone());
        }
    }

    // Pass 2: base-name match when at least one side is unqualified or shares base name
    let raw_base = base_name(&cleaned);
    let raw_has_schema = cleaned.contains('.');
    for known in known_list {
        let known_clean = clean_identifier(known);
        let known_base = base_name(&known_clean);
        let known_has_schema = known_clean.contains('.');
        if known_base.eq_ignore_ascii_case(raw_base) && (!raw_has_schema || !known_has_schema) {
            return Some(known.clone());
        }
    }

    None
}

fn resolve_table_candidate(
    raw: &str,
    known_tables: &[String],
    known_routines: &[String],
    cte_names: &BTreeSet<String>,
    alias_map: &BTreeMap<String, String>,
) -> Option<String> {
    let cleaned = clean_identifier(raw);
    if cleaned.is_empty() || is_non_table_word(&cleaned) {
        return None;
    }

    let lower = cleaned.to_ascii_lowercase();
    let base_lower = base_name(&cleaned).to_ascii_lowercase();

    // Ignore CTE names
    if cte_names.contains(&lower) || cte_names.contains(&base_lower) {
        return None;
    }

    // Resolve table alias if applicable
    let resolved_raw = alias_map
        .get(&lower)
        .cloned()
        .unwrap_or_else(|| cleaned.clone());

    // If it matches a known table, return canonical known table name
    if let Some(known_tbl) = resolve_known_identifier(&resolved_raw, known_tables) {
        return Some(known_tbl);
    }

    // If it matches a known routine (and did not match a known table), it's a table function, not a table
    if resolve_known_identifier(&resolved_raw, known_routines).is_some() {
        return None;
    }

    Some(resolved_raw)
}

fn extract_cte_and_alias_maps(body_sql: &str) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let mut cte_names = BTreeSet::new();
    let mut alias_map = BTreeMap::new();

    let cte_re = Regex::new(
        r"(?is)\b(?:WITH(?:\s+RECURSIVE)?|,)\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:AS\s*\()",
    )
    .expect("valid CTE regex");
    for caps in cte_re.captures_iter(body_sql) {
        if let Some(m) = caps.get(1) {
            cte_names.insert(clean_identifier(m.as_str()).to_ascii_lowercase());
        }
    }

    let alias_re = Regex::new(
        r#"(?is)\b(?:FROM|JOIN|UPDATE)\s+(?:ONLY\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*)\b"#,
    )
    .expect("valid alias regex");
    for caps in alias_re.captures_iter(body_sql) {
        if let (Some(tbl_m), Some(alias_m)) = (caps.get(1), caps.get(2)) {
            let tbl = clean_identifier(tbl_m.as_str());
            let alias = clean_identifier(alias_m.as_str()).to_ascii_lowercase();
            if !is_non_table_word(&tbl) && !is_non_table_word(&alias) {
                alias_map.insert(alias, tbl);
            }
        }
    }

    (cte_names, alias_map)
}

fn extract_write_targets_from_fragment(fragment: &str) -> Vec<String> {
    let mut targets = Vec::new();

    let insert_re = Regex::new(
        r#"(?is)\b(?:INSERT(?:\s+OR\s+\w+)?|REPLACE|MERGE)\s+INTO\s+([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)"#,
    )
    .expect("valid INSERT/MERGE regex");
    for caps in insert_re.captures_iter(fragment) {
        if let Some(m) = caps.get(1) {
            targets.push(clean_identifier(m.as_str()));
        }
    }

    let update_re = Regex::new(
        r#"(?is)\bUPDATE\s+(?:ONLY\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s+(?:(?:AS\s+)?[A-Za-z_][A-Za-z0-9_]*\s+)?SET\b"#,
    )
    .expect("valid UPDATE regex");
    for caps in update_re.captures_iter(fragment) {
        if let Some(m) = caps.get(1) {
            targets.push(clean_identifier(m.as_str()));
        }
    }

    let delete_re = Regex::new(
        r#"(?is)\bDELETE\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?FROM\s+(?:ONLY\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)"#,
    )
    .expect("valid DELETE regex");
    for caps in delete_re.captures_iter(fragment) {
        if let Some(m) = caps.get(1) {
            targets.push(clean_identifier(m.as_str()));
        }
    }

    targets
}

fn extract_read_targets_from_fragment(fragment: &str) -> Vec<String> {
    let mut reads = Vec::new();

    // Match JOIN <table> (excluding JOIN LATERAL (subquery) or JOIN func(...))
    let join_re = Regex::new(
        r#"(?is)\bJOIN\s+(?:LATERAL\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)(\s*\()?"#,
    )
    .expect("valid JOIN regex");
    for caps in join_re.captures_iter(fragment) {
        if caps.get(2).is_none() {
            if let Some(m) = caps.get(1) {
                reads.push(clean_identifier(m.as_str()));
            }
        }
    }

    // Match USING <table> in MERGE/DELETE statements (not USING (col) join constraint)
    let using_re = Regex::new(
        r#"(?is)\bUSING\s+([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)(\s*\()?"#,
    )
    .expect("valid USING regex");
    for caps in using_re.captures_iter(fragment) {
        if caps.get(2).is_none() {
            if let Some(m) = caps.get(1) {
                reads.push(clean_identifier(m.as_str()));
            }
        }
    }

    // Match FROM <table> while checking preceding context so we ignore:
    // - DELETE [alias] FROM <table>
    // - IS [NOT] DISTINCT FROM <expr>
    // - EXTRACT(... FROM <expr>), TRIM(... FROM <expr>), SUBSTRING(... FROM <expr>), OVERLAY(... FROM <expr>)
    // - FROM <func>(...)
    let from_re = Regex::new(
        r#"(?is)\bFROM\s+(?:ONLY\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)(\s*\()?"#,
    )
    .expect("valid FROM regex");
    let special_from_fn_re = Regex::new(
        r"(?is)\b(?:EXTRACT|TRIM|BTRIM|LTRIM|RTRIM|SUBSTRING|OVERLAY)\s*\([^)]*$",
    )
    .expect("valid special FROM fn regex");
    let delete_prefix_re =
        Regex::new(r"(?is)\bDELETE(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*$").expect("valid DELETE prefix regex");
    let distinct_prefix_re =
        Regex::new(r"(?is)\bDISTINCT\s*$").expect("valid DISTINCT prefix regex");

    for caps in from_re.captures_iter(fragment) {
        if caps.get(2).is_some() {
            // Followed by `(`, so this is a table-valued function call `FROM fn(...)`, not a table.
            continue;
        }
        let full_match = caps.get(0).unwrap();
        let prefix = &fragment[..full_match.start()];
        if delete_prefix_re.is_match(prefix)
            || distinct_prefix_re.is_match(prefix)
            || special_from_fn_re.is_match(prefix)
        {
            continue;
        }
        if let Some(m) = caps.get(1) {
            reads.push(clean_identifier(m.as_str()));
        }
    }

    reads
}

/// Strip leading PL/pgSQL or MySQL procedural prefixes from a semicolon-delimited statement
/// so that `parse_and_analyze_sql` can inspect the underlying SQL query or DML statement.
fn normalize_procedural_statement_for_ast(stmt: &str) -> String {
    let mut s = stmt.trim();

    let prefix_re = Regex::new(
        r"(?is)^(?:BEGIN(?:\s+ATOMIC)?|DECLARE\b[^;]*|EXCEPTION(?:\s+WHEN\s+[^\n]+?\s+THEN)?|WHEN\s+[^\n]+?\s+THEN|THEN|ELSE|LOOP|RETURN\s+QUERY|RETURN)\s+",
    )
    .expect("valid procedural prefix regex");

    while let Some(m) = prefix_re.find(s) {
        s = s[m.end()..].trim();
    }

    // Convert PL/pgSQL `v_var := (SELECT ...)` or `SET v_var = (SELECT ...)` into inner query if applicable
    let assign_re =
        Regex::new(r"(?is)^(?:SET\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*:?=\s*\((.+)\)\s*$")
            .expect("valid assignment subquery regex");
    if let Some(caps) = assign_re.captures(s) {
        if let Some(inner) = caps.get(1) {
            return inner.as_str().trim().to_string();
        }
    }

    // Convert `FOR rec IN SELECT ... LOOP` into `SELECT ...`
    let for_in_re = Regex::new(
        r"(?is)^FOR\s+[A-Za-z_][A-Za-z0-9_]*\s+IN\s+(SELECT\b.+?)(?:\bLOOP\b\s*(.*))?$",
    )
    .expect("valid FOR IN SELECT regex");
    if let Some(caps) = for_in_re.captures(s) {
        if let Some(sel) = caps.get(1) {
            return sel.as_str().trim().to_string();
        }
    }

    // Convert `PERFORM ...` into `SELECT ...` for AST table extraction
    let perform_re = Regex::new(r"(?is)^PERFORM\s+(.+)$").expect("valid PERFORM regex");
    if let Some(caps) = perform_re.captures(s) {
        if let Some(rest) = caps.get(1) {
            return format!("SELECT {}", rest.as_str().trim());
        }
    }

    s.to_string()
}

/// Analyze a stored procedure or function definition to extract:
/// - Routine calls (`CALL`, `PERFORM`, `EXEC`, `FUNCTION_EXPR`)
/// - Tables read (`SELECT ... FROM`, `JOIN`, read subqueries)
/// - Tables written (`INSERT INTO`, `UPDATE`, `DELETE FROM`, `MERGE INTO`)
pub fn analyze_routine_definition(
    engine: DatabaseEngine,
    routine_name: &str,
    definition_sql: &str,
    known_routines: &[String],
    known_tables: &[String],
) -> RoutineBodyAnalysis {
    let body = extract_routine_body(definition_sql);
    let dialect = dialect_for_engine(engine);
    let masked = Tokenizer::new(dialect.as_ref(), &body)
        .tokenize()
        .map(|tokens| {
            tokens
                .into_iter()
                .map(|token| {
                    if is_literal_token(&token) {
                        "''".to_owned()
                    } else {
                        token.to_string()
                    }
                })
                .collect::<String>()
        });
    let call_body = masked.as_deref().unwrap_or(&body);
    let mut call_map: BTreeMap<String, RoutineCallRef> = BTreeMap::new();
    let mut call_order: Vec<String> = Vec::new();

    let mut record_call = |raw_callee: &str, call_kind: &str, require_known: bool| {
        let cleaned = clean_identifier(raw_callee);
        if cleaned.is_empty() || is_sql_builtin_or_keyword(&cleaned) {
            return;
        }
        let resolved = if let Some(known) = resolve_known_identifier(&cleaned, known_routines) {
            known
        } else if require_known {
            if known_routines.is_empty() && cleaned.contains('.') {
                cleaned
            } else {
                return;
            }
        } else {
            cleaned
        };

        // Do not mistake a known table for a function call
        if resolve_known_identifier(&resolved, known_tables).is_some()
            && resolve_known_identifier(&resolved, known_routines).is_none()
        {
            return;
        }

        let key = resolved.to_ascii_lowercase();
        if let Some(existing) = call_map.get_mut(&key) {
            // Prefer explicit procedural call kinds (CALL, PERFORM, EXEC) over FUNCTION_EXPR
            if existing.call_kind == "FUNCTION_EXPR" && call_kind != "FUNCTION_EXPR" {
                existing.call_kind = call_kind.to_string();
            }
        } else {
            call_order.push(key.clone());
            call_map.insert(
                key,
                RoutineCallRef {
                    callee: resolved,
                    call_kind: call_kind.to_string(),
                },
            );
        }
    };

    // 1. Detect explicit `CALL <routine>(...)`
    let call_re = Regex::new(
        r#"(?is)\bCALL\s+([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*(?:\(|;|$|\s)"#,
    )
    .expect("valid CALL regex");
    for caps in call_re.captures_iter(call_body) {
        if let Some(m) = caps.get(1) {
            record_call(m.as_str(), "CALL", false);
        }
    }

    // 2. Detect PL/pgSQL `PERFORM <routine>(...)`
    let perform_call_re = Regex::new(
        r#"(?is)\bPERFORM\s+([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*\("#,
    )
    .expect("valid PERFORM regex");
    for caps in perform_call_re.captures_iter(call_body) {
        if let Some(m) = caps.get(1) {
            record_call(m.as_str(), "PERFORM", false);
        }
    }

    // 3. Detect `EXEC` / `EXECUTE [FUNCTION|PROCEDURE] <routine>`
    let exec_re = Regex::new(
        r#"(?is)\bEXEC(?:UTE)?\s+(?:(?:FUNCTION|PROCEDURE)\s+)?([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*(?:\(|;|$|\s)"#,
    )
    .expect("valid EXEC regex");
    for caps in exec_re.captures_iter(call_body) {
        if let Some(m) = caps.get(1) {
            let candidate = clean_identifier(m.as_str());
            let cand_upper = candidate.to_ascii_uppercase();
            if !matches!(
                cand_upper.as_str(),
                "IMMEDIATE" | "USING" | "INTO" | "SQL" | "STATEMENT"
            ) {
                record_call(&candidate, "EXEC", false);
            }
        }
    }

    // 4. Detect `<routine>(...)` expressions matching `known_routines`
    let fn_expr_re = Regex::new(
        r#"(?is)([A-Za-z_"\[`][A-Za-z0-9_."\]`]*)\s*\("#,
    )
    .expect("valid FUNCTION_EXPR regex");
    let skip_fn_prefix_re = Regex::new(
        r"(?is)\b(?:CALL|PERFORM|EXEC|EXECUTE|INTO|TABLE|UPDATE|REFERENCES)\s+$",
    )
    .expect("valid skip fn prefix regex");

    for caps in fn_expr_re.captures_iter(call_body) {
        let full_match = caps.get(0).unwrap();
        let prefix = &call_body[..full_match.start()];
        if skip_fn_prefix_re.is_match(prefix) {
            continue;
        }
        if let Some(m) = caps.get(1) {
            record_call(m.as_str(), "FUNCTION_EXPR", true);
        }
    }

    // 5. Extract `tables_read` and `tables_written` using both `parse_and_analyze_sql`
    // on individual statements and regex/token scanning across the procedural body.
    let (cte_names, alias_map) = extract_cte_and_alias_maps(&body);
    let mut tables_read_set = BTreeSet::new();
    let mut tables_written_set = BTreeSet::new();

    for raw_stmt in split_sql_statements(engine, &body) {
        let normalized_stmt = normalize_procedural_statement_for_ast(&raw_stmt);
        if normalized_stmt.is_empty() {
            continue;
        }

        let stmt_write_raw = extract_write_targets_from_fragment(&normalized_stmt);
        let mut stmt_write_resolved = BTreeSet::new();
        for w in &stmt_write_raw {
            if let Some(resolved) =
                resolve_table_candidate(w, known_tables, known_routines, &cte_names, &alias_map)
            {
                stmt_write_resolved.insert(resolved.clone());
                tables_written_set.insert(resolved);
            }
        }

        if let Ok(analysis) = parse_and_analyze_sql(engine, &normalized_stmt) {
            for st in &analysis.statements {
                // Note: In PL/pgSQL, `SELECT col INTO v_var FROM tbl` has `statement_kind == "SELECT"`
                // even though `sqlparser` flags `SELECT INTO` as `SqlStatementClass::Write`.
                let is_select_stmt = st.statement_kind == "SELECT"
                    || st.statement_class == SqlStatementClass::Read;

                for tbl in &st.referenced_tables {
                    if let Some(resolved) = resolve_table_candidate(
                        tbl,
                        known_tables,
                        known_routines,
                        &cte_names,
                        &alias_map,
                    ) {
                        if is_select_stmt || !stmt_write_resolved.contains(&resolved) {
                            tables_read_set.insert(resolved);
                        }
                    }
                }
            }
        }
    }

    // Fallback regex/token scanning across the entire body for procedural blocks
    for w in extract_write_targets_from_fragment(&body) {
        if let Some(resolved) =
            resolve_table_candidate(&w, known_tables, known_routines, &cte_names, &alias_map)
        {
            tables_written_set.insert(resolved);
        }
    }

    for r in extract_read_targets_from_fragment(&body) {
        if let Some(resolved) =
            resolve_table_candidate(&r, known_tables, known_routines, &cte_names, &alias_map)
        {
            tables_read_set.insert(resolved);
        }
    }

    let calls = call_order
        .into_iter()
        .filter_map(|k| call_map.remove(&k))
        .collect();

    RoutineBodyAnalysis {
        routine_name: routine_name.to_string(),
        calls,
        tables_read: tables_read_set.into_iter().collect(),
        tables_written: tables_written_set.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_plpgsql_procedure_with_call_perform_and_dml() {
        let sql = r#"
        CREATE OR REPLACE PROCEDURE public.checkout_order(p_order_id INTEGER, p_user_id INTEGER)
        LANGUAGE plpgsql
        AS $$
        DECLARE
            v_tier TEXT;
        BEGIN
            -- Reserve stock and compute user loyalty tier
            CALL reserve_inventory(p_order_id);
            v_tier := calculate_user_tier(p_user_id);

            UPDATE orders
            SET status = 'completed',
                applied_tier = COALESCE(v_tier, 'standard'),
                updated_at = NOW()
            WHERE id = p_order_id;

            INSERT INTO audit_logs (user_id, action, created_at)
            SELECT u.id, CONCAT('CHECKOUT:', UPPER(v_tier)), NOW()
            FROM users u
            WHERE u.id = p_user_id;

            PERFORM record_order_audit(p_order_id, 'COMPLETED');
        END;
        $$;
        "#;

        let known_routines = vec![
            "public.checkout_order".to_string(),
            "public.reserve_inventory".to_string(),
            "public.calculate_user_tier".to_string(),
            "public.record_order_audit".to_string(),
        ];
        let known_tables = vec![
            "public.users".to_string(),
            "public.orders".to_string(),
            "public.order_items".to_string(),
            "public.audit_logs".to_string(),
        ];

        let analysis = analyze_routine_definition(
            DatabaseEngine::Postgres,
            "public.checkout_order",
            sql,
            &known_routines,
            &known_tables,
        );

        assert_eq!(analysis.routine_name, "public.checkout_order");
        assert_eq!(
            analysis.calls,
            vec![
                RoutineCallRef {
                    callee: "public.reserve_inventory".to_string(),
                    call_kind: "CALL".to_string(),
                },
                RoutineCallRef {
                    callee: "public.record_order_audit".to_string(),
                    call_kind: "PERFORM".to_string(),
                },
                RoutineCallRef {
                    callee: "public.calculate_user_tier".to_string(),
                    call_kind: "FUNCTION_EXPR".to_string(),
                },
            ]
        );
        // Should not treat self header or COALESCE/NOW/CONCAT/UPPER as routine calls
        assert!(!analysis
            .calls
            .iter()
            .any(|c| c.callee == "public.checkout_order"));

        assert_eq!(analysis.tables_read, vec!["public.users".to_string()]);
        assert_eq!(
            analysis.tables_written,
            vec!["public.audit_logs".to_string(), "public.orders".to_string()]
        );
    }

    #[test]
    fn test_analyze_mysql_procedure_with_joins_delete_and_exec() {
        let sql = r#"
        CREATE PROCEDURE archive_old_orders(IN cutoff_days INT)
        BEGIN
            INSERT INTO archived_orders (id, user_id, total)
            SELECT o.id, o.user_id, SUM(oi.price * oi.quantity)
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            WHERE o.status = 'cancelled'
            GROUP BY o.id, o.user_id;

            DELETE FROM order_items WHERE order_id IN (SELECT id FROM archived_orders);
            DELETE FROM orders WHERE id IN (SELECT id FROM archived_orders);

            EXEC notify_archive_complete(cutoff_days);
        END
        "#;

        let known_routines = vec![
            "archive_old_orders".to_string(),
            "notify_archive_complete".to_string(),
        ];
        let known_tables = vec![
            "orders".to_string(),
            "order_items".to_string(),
            "archived_orders".to_string(),
        ];

        let analysis = analyze_routine_definition(
            DatabaseEngine::MySql,
            "archive_old_orders",
            sql,
            &known_routines,
            &known_tables,
        );

        assert_eq!(
            analysis.calls,
            vec![RoutineCallRef {
                callee: "notify_archive_complete".to_string(),
                call_kind: "EXEC".to_string(),
            }]
        );
        assert_eq!(
            analysis.tables_read,
            vec![
                "archived_orders".to_string(),
                "order_items".to_string(),
                "orders".to_string()
            ]
        );
        assert_eq!(
            analysis.tables_written,
            vec![
                "archived_orders".to_string(),
                "order_items".to_string(),
                "orders".to_string()
            ]
        );
    }

    #[test]
    fn test_detects_recursive_routine_call_in_body() {
        let sql = r#"
        CREATE OR REPLACE FUNCTION public.compute_category_depth(p_cat_id INT)
        RETURNS INT AS $$
        DECLARE
            v_parent_id INT;
        BEGIN
            SELECT parent_id INTO v_parent_id FROM categories WHERE id = p_cat_id;
            IF v_parent_id IS NULL THEN
                RETURN 0;
            END IF;
            RETURN 1 + compute_category_depth(v_parent_id);
        END;
        $$ LANGUAGE plpgsql;
        "#;

        let known_routines = vec!["public.compute_category_depth".to_string()];
        let known_tables = vec!["public.categories".to_string()];

        let analysis = analyze_routine_definition(
            DatabaseEngine::Postgres,
            "public.compute_category_depth",
            sql,
            &known_routines,
            &known_tables,
        );

        assert_eq!(
            analysis.calls,
            vec![RoutineCallRef {
                callee: "public.compute_category_depth".to_string(),
                call_kind: "FUNCTION_EXPR".to_string(),
            }]
        );
        assert_eq!(analysis.tables_read, vec!["public.categories".to_string()]);
        assert!(analysis.tables_written.is_empty());
    }
}
