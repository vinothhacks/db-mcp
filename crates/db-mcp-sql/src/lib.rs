//! Dialect-aware SQL parser and classifier (`Postgres`, `MySql`, `Sqlite`) built on `sqlparser`.
//!
//! Responsibilities:
//! - Parse all statements in a query batch and detect multi-statement queries.
//! - Recursively inspect CTE bodies (`WITH ... INSERT/UPDATE/DELETE`) for hidden data modifications.
//! - Detect privileged or side-effecting functions (`pg_sleep`, `pg_read_file`, `pg_write_file`,
//!   `dblink`, `lo_import`, `lo_export`, `load_file`, `sys_exec`, `attach`, etc.).
//! - Classify statements into `Read`, `Write`, `Ddl`, `Transaction`, `PrivilegeOrAdmin`, or `Unknown`.
//! - Extract referenced tables, columns, and filter/join/order predicates for index analysis.
//! - Deterministically normalize SQL and compute SHA-256 hashes.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use db_mcp_core::{DatabaseEngine, DbMcpError, DbMcpResult, OperatingMode, SqlStatementClass};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlparser::ast::{
    BinaryOperator, Cte, Expr, Ident, JoinConstraint, JoinOperator, ObjectName, OrderByExpr, Query,
    Select, SelectItem, SetExpr, Statement, TableFactor, TableWithJoins, Visit, Visitor,
};
use sqlparser::dialect::{Dialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

pub mod disclosure;
pub mod routine;
pub use disclosure::*;
pub use routine::*;

/// Privileged or side-effecting SQL functions that must be flagged and restricted.
pub const PRIVILEGED_FUNCTIONS: &[&str] = &[
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_write_file",
    "pg_stat_file",
    "pg_ls_dir",
    "pg_ls_logdir",
    "pg_ls_waldir",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_promote",
    "pg_advisory_lock",
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "dblink_connect_u",
    "dblink_send_query",
    "lo_import",
    "lo_export",
    "lo_unlink",
    "load_file",
    "sys_exec",
    "sys_eval",
    "sleep",
    "benchmark",
    "load_extension",
    "fts3_tokenizer",
    "attach",
];

/// Returns true if a function name (qualified or unqualified) is a privileged or side-effecting function.
pub fn is_privileged_function(raw_name: &str) -> bool {
    let base = raw_name
        .rsplit('.')
        .next()
        .unwrap_or(raw_name)
        .trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']')
        .to_ascii_lowercase();
    PRIVILEGED_FUNCTIONS.contains(&base.as_str())
}

/// Reference to a table column discovered in a SQL statement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ColumnReference {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
}

/// Kind of predicate or access pattern in which a column participates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOperator {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    In,
    Between,
    Like,
    IsNull,
    JoinEq,
    OrderBy,
    GroupBy,
    Other,
}

/// Column usage inside a `WHERE`, `JOIN`, `GROUP BY`, or `ORDER BY` clause for index recommendation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PredicateColumn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    pub operator: PredicateOperator,
}

/// Per-statement analysis output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementAnalysis {
    pub index: usize,
    pub raw_sql: String,
    pub normalized_sql: String,
    pub statement_class: SqlStatementClass,
    pub statement_kind: String,
    pub has_cte: bool,
    pub has_cte_write: bool,
    pub privileged_functions: Vec<String>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<ColumnReference>,
    pub predicates: Vec<PredicateColumn>,
    pub is_transactional_ddl_safe: bool,
    /// How column values reach the statement's output (result-disclosure provenance).
    #[serde(default)]
    pub disclosure: DisclosureAnalysis,
}

/// Full analysis result for a SQL string (single or multi-statement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlAnalysis {
    pub engine: DatabaseEngine,
    pub raw_sql: String,
    pub normalized_sql: String,
    pub sql_hash: String,
    pub statement_count: usize,
    pub is_multi_statement: bool,
    pub overall_class: SqlStatementClass,
    pub has_writes: bool,
    pub has_ddl: bool,
    pub has_cte_write: bool,
    pub has_privileged_functions: bool,
    pub privileged_functions: Vec<String>,
    pub referenced_tables: Vec<String>,
    pub referenced_columns: Vec<ColumnReference>,
    pub predicates: Vec<PredicateColumn>,
    pub statements: Vec<StatementAnalysis>,
    #[serde(default)]
    pub parse_warnings: Vec<String>,
    /// Result-disclosure provenance merged across all statements.
    #[serde(default)]
    pub disclosure: DisclosureAnalysis,
}

/// Deterministically normalize SQL by collapsing whitespace, stripping comments, and trimming trailing semicolons.
pub fn normalize_sql(sql: &str) -> String {
    normalize_sql_tokens(sql, false)
}

/// Literal-free SQL fingerprint for audit records and workload statistics.
///
/// Like [`normalize_sql`] but every string, number and byte literal is replaced with `?`, so PII
/// and secrets embedded in SQL text are never persisted. Do NOT use it for approval hashes:
/// two statements differing only in literals share a fingerprint.
pub fn fingerprint_sql(sql: &str) -> String {
    normalize_sql_tokens(sql, true)
}

fn is_literal_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Number(_, _)
            | Token::SingleQuotedString(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedString(_)
            | Token::UnicodeStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_)
    )
}

fn normalize_sql_tokens(sql: &str, mask_literals: bool) -> String {
    let dialect = PostgreSqlDialect {};
    if let Ok(tokens) = Tokenizer::new(&dialect, sql).tokenize() {
        let mut out = String::new();
        let mut prev_was_word_or_num = false;
        for token in tokens {
            let token = if mask_literals && is_literal_token(&token) {
                Token::Placeholder("?".to_string())
            } else {
                token
            };
            match token {
                Token::Whitespace(_) => continue,
                Token::SemiColon => {
                    out.push(';');
                    prev_was_word_or_num = false;
                }
                other => {
                    let s = other.to_string();
                    let is_punct = matches!(
                        other,
                        Token::Comma
                            | Token::LParen
                            | Token::RParen
                            | Token::Period
                            | Token::Colon
                            | Token::DoubleColon
                    );
                    if prev_was_word_or_num && !is_punct && !out.ends_with('(') && !out.ends_with('.') && !out.ends_with("::") {
                        out.push(' ');
                    } else if !out.is_empty()
                        && !is_punct
                        && !out.ends_with(' ')
                        && !out.ends_with('(')
                        && !out.ends_with('.')
                        && !out.ends_with("::")
                    {
                        out.push(' ');
                    }
                    out.push_str(&s);
                    prev_was_word_or_num = !is_punct;
                }
            }
        }
        let trimmed = out.trim().trim_end_matches(';').trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    if mask_literals {
        // Tokenizer failed: never fall back to raw text that may contain literals.
        return format!("<unparsed sql, {} bytes>", sql.len());
    }

    // Fallback whitespace collapse if tokenizer fails on dialect-specific literal
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .trim()
        .to_string()
}

/// Compute a deterministic SHA-256 hex digest of normalized SQL.
pub fn hash_sql(sql: &str) -> String {
    let norm = normalize_sql(sql);
    let mut hasher = Sha256::new();
    hasher.update(norm.as_bytes());
    hex::encode(hasher.finalize())
}

fn dialect_for_engine(engine: DatabaseEngine) -> Box<dyn Dialect> {
    match engine {
        DatabaseEngine::Postgres => Box::new(PostgreSqlDialect {}),
        DatabaseEngine::MySql => Box::new(MySqlDialect {}),
        DatabaseEngine::Sqlite => Box::new(SQLiteDialect {}),
    }
}

/// Split a raw SQL batch into individual top-level statement strings using the dialect tokenizer.
pub fn split_sql_statements(engine: DatabaseEngine, sql: &str) -> Vec<String> {
    let dialect = dialect_for_engine(engine);
    if let Ok(tokens) = Tokenizer::new(dialect.as_ref(), sql).tokenize() {
        let mut statements = Vec::new();
        let mut current = Vec::new();
        for token in tokens {
            if matches!(token, Token::SemiColon) {
                let s = current.join("").trim().to_string();
                if !s.is_empty() {
                    statements.push(s);
                }
                current.clear();
            } else {
                current.push(token.to_string());
            }
        }
        let tail = current.join("").trim().to_string();
        if !tail.is_empty() {
            statements.push(tail);
        }
        return statements;
    }

    sql.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Parse and analyze a SQL request under a specific operating mode.
/// In `ReadOnly` or `GovernedProduction` mode, unparseable/unknown SQL fails closed.
pub fn analyze_sql_for_mode(
    engine: DatabaseEngine,
    sql: &str,
    mode: OperatingMode,
) -> DbMcpResult<SqlAnalysis> {
    let analysis = parse_and_analyze_sql(engine, sql)?;
    if mode.fails_closed_on_unknown_sql() && analysis.overall_class == SqlStatementClass::Unknown {
        return Err(DbMcpError::PolicyDenied {
            code: "UNKNOWN_SQL_CONSTRUCT".to_string(),
            message: format!(
                "SQL statement could not be safely classified for engine '{}' in '{}' mode (fail-closed policy)",
                engine, mode
            ),
            next_action: None,
        });
    }
    Ok(analysis)
}

/// Parse and analyze all statements in a SQL request for the specified database engine.
pub fn parse_and_analyze_sql(engine: DatabaseEngine, sql: &str) -> DbMcpResult<SqlAnalysis> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(DbMcpError::InvalidArgument(
            "SQL query must not be empty".to_string(),
        ));
    }

    let dialect = dialect_for_engine(engine);
    let raw_statements = split_sql_statements(engine, trimmed);
    if raw_statements.is_empty() {
        return Err(DbMcpError::InvalidArgument(
            "SQL query contains no executable statements".to_string(),
        ));
    }

    let mut statement_analyses = Vec::new();
    let mut parse_warnings = Vec::new();

    match Parser::parse_sql(dialect.as_ref(), trimmed) {
        Ok(ast_statements) if !ast_statements.is_empty() => {
            for (idx, stmt) in ast_statements.iter().enumerate() {
                let raw_piece = raw_statements
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| stmt.to_string());
                let analysis = analyze_ast_statement(engine, idx, &raw_piece, stmt);
                statement_analyses.push(analysis);
            }
        }
        Ok(_) => {
            return Err(DbMcpError::InvalidArgument(
                "SQL query contains no statements".to_string(),
            ));
        }
        Err(parse_err) => {
            // Inspect each split statement individually; handle PostgreSQL data-modifying CTEs
            // or SQLite/vendor commands if sqlparser rejects a specific clause.
            parse_warnings.push(format!("Primary AST parser note: {parse_err}"));
            for (idx, raw_stmt) in raw_statements.iter().enumerate() {
                match Parser::parse_sql(dialect.as_ref(), raw_stmt) {
                    Ok(mut stmts) if !stmts.is_empty() => {
                        let stmt = stmts.remove(0);
                        statement_analyses.push(analyze_ast_statement(
                            engine, idx, raw_stmt, &stmt,
                        ));
                    }
                    _ => {
                        let fallback =
                            analyze_fallback_statement(engine, idx, raw_stmt, &parse_err.to_string());
                        statement_analyses.push(fallback);
                    }
                }
            }
        }
    }

    let statement_count = statement_analyses.len().max(raw_statements.len());
    let is_multi_statement = statement_count > 1;

    let mut privileged_functions = BTreeSet::new();
    let mut referenced_tables = BTreeSet::new();
    let mut referenced_columns = BTreeSet::new();
    let mut predicates = BTreeSet::new();
    let mut has_writes = false;
    let mut has_ddl = false;
    let mut has_cte_write = false;
    let mut disclosure = DisclosureAnalysis::default();

    for st in &statement_analyses {
        disclosure.merge(&st.disclosure);
        if st.statement_class == SqlStatementClass::Write {
            has_writes = true;
        }
        if st.statement_class == SqlStatementClass::Ddl {
            has_ddl = true;
        }
        if st.has_cte_write {
            has_cte_write = true;
            has_writes = true;
        }
        for f in &st.privileged_functions {
            privileged_functions.insert(f.clone());
        }
        for t in &st.referenced_tables {
            referenced_tables.insert(t.clone());
        }
        for c in &st.referenced_columns {
            referenced_columns.insert(c.clone());
        }
        for p in &st.predicates {
            predicates.insert(p.clone());
        }
    }

    let overall_class = combine_statement_classes(
        statement_analyses.iter().map(|s| s.statement_class),
        has_cte_write,
        !privileged_functions.is_empty(),
    );

    let normalized_sql = normalize_sql(trimmed);
    let sql_hash = hash_sql(trimmed);

    Ok(SqlAnalysis {
        engine,
        raw_sql: trimmed.to_string(),
        normalized_sql,
        sql_hash,
        statement_count,
        is_multi_statement,
        overall_class,
        has_writes,
        has_ddl,
        has_cte_write,
        has_privileged_functions: !privileged_functions.is_empty(),
        privileged_functions: privileged_functions.into_iter().collect(),
        referenced_tables: referenced_tables.into_iter().collect(),
        referenced_columns: referenced_columns.into_iter().collect(),
        predicates: predicates.into_iter().collect(),
        statements: statement_analyses,
        parse_warnings,
        disclosure,
    })
}

fn combine_statement_classes(
    classes: impl Iterator<Item = SqlStatementClass>,
    has_cte_write: bool,
    has_privileged_functions: bool,
) -> SqlStatementClass {
    let collected: Vec<SqlStatementClass> = classes.collect();
    if collected.contains(&SqlStatementClass::Unknown) {
        return SqlStatementClass::Unknown;
    }
    if collected.contains(&SqlStatementClass::PrivilegeOrAdmin) || has_privileged_functions {
        return SqlStatementClass::PrivilegeOrAdmin;
    }
    if collected.contains(&SqlStatementClass::Ddl) {
        return SqlStatementClass::Ddl;
    }
    if collected.contains(&SqlStatementClass::Write) || has_cte_write {
        return SqlStatementClass::Write;
    }
    if collected.contains(&SqlStatementClass::Transaction) {
        return SqlStatementClass::Transaction;
    }
    SqlStatementClass::Read
}

fn clean_ident(ident: &Ident) -> String {
    ident.value.trim().to_string()
}

fn clean_object_name(name: &ObjectName) -> String {
    name.0
        .iter()
        .map(clean_ident)
        .collect::<Vec<_>>()
        .join(".")
}

struct AstInspector {
    cte_names: BTreeSet<String>,
    alias_to_table: BTreeMap<String, String>,
    referenced_tables: BTreeSet<String>,
    referenced_columns: BTreeSet<ColumnReference>,
    predicates: BTreeSet<PredicateColumn>,
    privileged_functions: BTreeSet<String>,
    has_cte: bool,
    has_cte_write: bool,
    nested_classes: Vec<SqlStatementClass>,
    in_cte_depth: usize,
}

impl AstInspector {
    fn new() -> Self {
        Self {
            cte_names: BTreeSet::new(),
            alias_to_table: BTreeMap::new(),
            referenced_tables: BTreeSet::new(),
            referenced_columns: BTreeSet::new(),
            predicates: BTreeSet::new(),
            privileged_functions: BTreeSet::new(),
            has_cte: false,
            has_cte_write: false,
            nested_classes: Vec::new(),
            in_cte_depth: 0,
        }
    }

    fn resolve_table_name(&self, raw: &str) -> String {
        self.alias_to_table
            .get(raw)
            .cloned()
            .unwrap_or_else(|| raw.to_string())
    }

    fn record_table_factor(&mut self, factor: &TableFactor) {
        if let TableFactor::Table { name, alias, .. } = factor {
            let table_name = clean_object_name(name);
            let base = table_name.rsplit('.').next().unwrap_or(&table_name);
            if !self.cte_names.contains(base) && !self.cte_names.contains(&table_name) {
                self.referenced_tables.insert(table_name.clone());
            }
            if let Some(a) = alias {
                self.alias_to_table
                    .insert(clean_ident(&a.name), table_name);
            }
        }
    }

    fn inspect_query(&mut self, query: &Query) {
        if let Some(with) = &query.with {
            self.has_cte = true;
            for cte in &with.cte_tables {
                self.inspect_cte(cte);
            }
        }
        self.inspect_set_expr(&query.body);
        if let Some(order_by) = &query.order_by {
            for expr in &order_by.exprs {
                self.inspect_order_by_expr(expr);
            }
        }
    }

    fn inspect_cte(&mut self, cte: &Cte) {
        let cte_name = clean_ident(&cte.alias.name);
        self.cte_names.insert(cte_name);
        self.in_cte_depth += 1;
        self.inspect_query(&cte.query);
        self.in_cte_depth -= 1;
    }

    fn inspect_set_expr(&mut self, set_expr: &SetExpr) {
        match set_expr {
            SetExpr::Select(select) => self.inspect_select(select),
            SetExpr::Query(q) => self.inspect_query(q),
            SetExpr::SetOperation { left, right, .. } => {
                self.inspect_set_expr(left);
                self.inspect_set_expr(right);
            }
            SetExpr::Insert(stmt) | SetExpr::Update(stmt) => {
                if self.in_cte_depth > 0 {
                    self.has_cte_write = true;
                }
                self.nested_classes.push(SqlStatementClass::Write);
                let _ = stmt.visit(self);
            }
            _ => {
                // Check if serialized form of any other SetExpr inside a CTE starts with DELETE/INSERT/UPDATE/MERGE
                let text = set_expr.to_string().trim_start().to_ascii_uppercase();
                if text.starts_with("DELETE ")
                    || text.starts_with("INSERT ")
                    || text.starts_with("UPDATE ")
                    || text.starts_with("MERGE ")
                {
                    if self.in_cte_depth > 0 {
                        self.has_cte_write = true;
                    }
                    self.nested_classes.push(SqlStatementClass::Write);
                }
            }
        }
    }

    fn inspect_select(&mut self, select: &Select) {
        // Record FROM and JOIN tables first so aliases can be resolved
        for twj in &select.from {
            self.inspect_table_with_joins(twj);
        }
        // Check SELECT INTO (creates a table in PostgreSQL)
        if select.into.is_some() {
            self.nested_classes.push(SqlStatementClass::Write);
        }
        for item in &select.projection {
            if let SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } = item {
                self.inspect_expr(expr, None);
            }
        }
        if let Some(selection) = &select.selection {
            self.inspect_where_expr(selection);
        }
        if let sqlparser::ast::GroupByExpr::Expressions(exprs, _) = &select.group_by {
            for expr in exprs {
                if let Some((table, column)) = self.extract_column_ref(expr) {
                    self.predicates.insert(PredicateColumn {
                        table,
                        column,
                        operator: PredicateOperator::GroupBy,
                    });
                }
            }
        }
    }

    fn inspect_table_with_joins(&mut self, twj: &TableWithJoins) {
        self.record_table_factor(&twj.relation);
        for join in &twj.joins {
            self.record_table_factor(&join.relation);
            let constraint = match &join.join_operator {
                JoinOperator::Inner(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::FullOuter(c)
                | JoinOperator::LeftSemi(c)
                | JoinOperator::RightSemi(c)
                | JoinOperator::LeftAnti(c)
                | JoinOperator::RightAnti(c) => Some(c),
                _ => None,
            };
            if let Some(JoinConstraint::On(expr)) = constraint {
                self.inspect_join_expr(expr);
            } else if let Some(JoinConstraint::Using(idents)) = constraint {
                for ident in idents {
                    self.predicates.insert(PredicateColumn {
                        table: None,
                        column: clean_ident(ident),
                        operator: PredicateOperator::JoinEq,
                    });
                }
            }
        }
    }

    fn inspect_order_by_expr(&mut self, order_by: &OrderByExpr) {
        if let Some((table, column)) = self.extract_column_ref(&order_by.expr) {
            self.predicates.insert(PredicateColumn {
                table,
                column,
                operator: PredicateOperator::OrderBy,
            });
        }
    }

    fn extract_column_ref(&self, expr: &Expr) -> Option<(Option<String>, String)> {
        match expr {
            Expr::Identifier(ident) => {
                let default_table = if self.referenced_tables.len() == 1 {
                    self.referenced_tables.iter().next().cloned()
                } else {
                    None
                };
                Some((default_table, clean_ident(ident)))
            }
            Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
                let col = clean_ident(parts.last().unwrap());
                let raw_tbl = clean_ident(&parts[parts.len() - 2]);
                let resolved_tbl = self.resolve_table_name(&raw_tbl);
                Some((Some(resolved_tbl), col))
            }
            Expr::Nested(inner) => self.extract_column_ref(inner),
            Expr::Cast { expr, .. } => self.extract_column_ref(expr),
            _ => None,
        }
    }

    fn inspect_join_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::And | BinaryOperator::Or => {
                    self.inspect_join_expr(left);
                    self.inspect_join_expr(right);
                }
                BinaryOperator::Eq => {
                    if let Some((table, column)) = self.extract_column_ref(left) {
                        self.predicates.insert(PredicateColumn {
                            table,
                            column,
                            operator: PredicateOperator::JoinEq,
                        });
                    }
                    if let Some((table, column)) = self.extract_column_ref(right) {
                        self.predicates.insert(PredicateColumn {
                            table,
                            column,
                            operator: PredicateOperator::JoinEq,
                        });
                    }
                }
                _ => {
                    self.inspect_where_expr(expr);
                }
            },
            Expr::Nested(inner) => self.inspect_join_expr(inner),
            _ => {}
        }
    }

    fn inspect_where_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op, right } => match op {
                BinaryOperator::And | BinaryOperator::Or => {
                    self.inspect_where_expr(left);
                    self.inspect_where_expr(right);
                }
                _ => {
                    let pred_op = match op {
                        BinaryOperator::Eq => PredicateOperator::Eq,
                        BinaryOperator::NotEq => PredicateOperator::NotEq,
                        BinaryOperator::Lt => PredicateOperator::Lt,
                        BinaryOperator::LtEq => PredicateOperator::LtEq,
                        BinaryOperator::Gt => PredicateOperator::Gt,
                        BinaryOperator::GtEq => PredicateOperator::GtEq,
                        _ => PredicateOperator::Other,
                    };
                    if let Some((table, column)) = self.extract_column_ref(left) {
                        self.predicates.insert(PredicateColumn {
                            table,
                            column,
                            operator: pred_op,
                        });
                    }
                    if let Some((table, column)) = self.extract_column_ref(right) {
                        self.predicates.insert(PredicateColumn {
                            table,
                            column,
                            operator: pred_op,
                        });
                    }
                }
            },
            Expr::InList { expr: inner, .. } | Expr::InSubquery { expr: inner, .. } => {
                if let Some((table, column)) = self.extract_column_ref(inner) {
                    self.predicates.insert(PredicateColumn {
                        table,
                        column,
                        operator: PredicateOperator::In,
                    });
                }
            }
            Expr::Between { expr: inner, .. } => {
                if let Some((table, column)) = self.extract_column_ref(inner) {
                    self.predicates.insert(PredicateColumn {
                        table,
                        column,
                        operator: PredicateOperator::Between,
                    });
                }
            }
            Expr::Like { expr: inner, .. } | Expr::ILike { expr: inner, .. } => {
                if let Some((table, column)) = self.extract_column_ref(inner) {
                    self.predicates.insert(PredicateColumn {
                        table,
                        column,
                        operator: PredicateOperator::Like,
                    });
                }
            }
            Expr::IsNull(inner) | Expr::IsNotNull(inner) => {
                if let Some((table, column)) = self.extract_column_ref(inner) {
                    self.predicates.insert(PredicateColumn {
                        table,
                        column,
                        operator: PredicateOperator::IsNull,
                    });
                }
            }
            Expr::Nested(inner) => self.inspect_where_expr(inner),
            _ => {}
        }
    }

    fn inspect_expr(&mut self, expr: &Expr, _op_hint: Option<PredicateOperator>) {
        if let Some((table, column)) = self.extract_column_ref(expr) {
            self.referenced_columns
                .insert(ColumnReference { table, column });
        }
    }
}

impl Visitor for AstInspector {
    type Break = ();

    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<Self::Break> {
        let (class, _) = classify_top_level_statement(statement);
        if self.in_cte_depth > 0 && matches!(class, SqlStatementClass::Write | SqlStatementClass::Ddl) {
            self.has_cte_write = true;
        }
        self.nested_classes.push(class);

        match statement {
            Statement::Query(q) => self.inspect_query(q),
            Statement::Insert(ins) => {
                let tbl = clean_object_name(&ins.table_name);
                self.referenced_tables.insert(tbl);
                if let Some(src) = &ins.source {
                    self.inspect_query(src);
                }
            }
            Statement::Update {
                table, selection, ..
            } => {
                self.inspect_table_with_joins(table);
                if let Some(sel) = selection {
                    self.inspect_where_expr(sel);
                }
            }
            Statement::Delete(del) => {
                for tbl in &del.tables {
                    self.referenced_tables.insert(clean_object_name(tbl));
                }
                let from_tables = match &del.from {
                    sqlparser::ast::FromTable::WithFromKeyword(v)
                    | sqlparser::ast::FromTable::WithoutKeyword(v) => v,
                };
                for twj in from_tables {
                    self.inspect_table_with_joins(twj);
                }
                if let Some(sel) = &del.selection {
                    self.inspect_where_expr(sel);
                }
            }
            Statement::CreateTable(ct) => {
                self.referenced_tables.insert(clean_object_name(&ct.name));
            }
            Statement::AlterTable { name, .. } => {
                self.referenced_tables.insert(clean_object_name(name));
            }
            Statement::CreateIndex(ci) => {
                self.referenced_tables
                    .insert(clean_object_name(&ci.table_name));
            }
            Statement::Drop { names, .. } => {
                for n in names {
                    self.referenced_tables.insert(clean_object_name(n));
                }
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, table_factor: &TableFactor) -> ControlFlow<Self::Break> {
        self.record_table_factor(table_factor);
        if let TableFactor::Derived { subquery, .. } = table_factor {
            self.inspect_query(subquery);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Some((table, column)) = self.extract_column_ref(expr) {
            self.referenced_columns
                .insert(ColumnReference { table, column });
        }
        if let Expr::Function(function) = expr {
            let fn_name = clean_object_name(&function.name);
            if is_privileged_function(&fn_name) {
                self.privileged_functions
                    .insert(fn_name.to_ascii_lowercase());
            }
        }
        if let Expr::Subquery(subq) | Expr::Exists { subquery: subq, .. } = expr {
            self.inspect_query(subq);
        }
        if let Expr::InSubquery { subquery, .. } = expr {
            self.inspect_query(subquery);
        }
        ControlFlow::Continue(())
    }
}

fn classify_top_level_statement(stmt: &Statement) -> (SqlStatementClass, &'static str) {
    match stmt {
        Statement::Query(_) => (SqlStatementClass::Read, "SELECT"),
        Statement::Explain { statement, analyze, .. } => {
            let (inner_class, _) = classify_top_level_statement(statement);
            if inner_class != SqlStatementClass::Read {
                (inner_class, "EXPLAIN_MUTATING")
            } else if *analyze {
                (SqlStatementClass::Read, "EXPLAIN_ANALYZE")
            } else {
                (SqlStatementClass::Read, "EXPLAIN")
            }
        }
        Statement::ShowTables { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowFunctions { .. } => (SqlStatementClass::Read, "SHOW"),
        Statement::Insert(_) => (SqlStatementClass::Write, "INSERT"),
        Statement::Update { .. } => (SqlStatementClass::Write, "UPDATE"),
        Statement::Delete(_) => (SqlStatementClass::Write, "DELETE"),
        Statement::Merge { .. } => (SqlStatementClass::Write, "MERGE"),
        Statement::Copy { .. } => (SqlStatementClass::PrivilegeOrAdmin, "COPY"),
        Statement::CreateTable(_) => (SqlStatementClass::Ddl, "CREATE_TABLE"),
        Statement::CreateView { .. } => (SqlStatementClass::Ddl, "CREATE_VIEW"),
        Statement::CreateIndex(_) => (SqlStatementClass::Ddl, "CREATE_INDEX"),
        Statement::CreateSchema { .. } => (SqlStatementClass::Ddl, "CREATE_SCHEMA"),
        Statement::CreateSequence { .. } => (SqlStatementClass::Ddl, "CREATE_SEQUENCE"),
        Statement::CreateFunction { .. } => (SqlStatementClass::Ddl, "CREATE_FUNCTION"),
        Statement::CreateProcedure { .. } => (SqlStatementClass::Ddl, "CREATE_PROCEDURE"),
        Statement::CreateTrigger { .. } => (SqlStatementClass::Ddl, "CREATE_TRIGGER"),
        Statement::CreateType { .. } => (SqlStatementClass::Ddl, "CREATE_TYPE"),
        Statement::AlterTable { .. } => (SqlStatementClass::Ddl, "ALTER_TABLE"),
        Statement::AlterIndex { .. } => (SqlStatementClass::Ddl, "ALTER_INDEX"),
        Statement::AlterView { .. } => (SqlStatementClass::Ddl, "ALTER_VIEW"),
        Statement::Drop { .. } => (SqlStatementClass::Ddl, "DROP"),
        Statement::Truncate { .. } => (SqlStatementClass::Ddl, "TRUNCATE"),
        Statement::StartTransaction { .. } => (SqlStatementClass::Transaction, "BEGIN"),
        Statement::Commit { .. } => (SqlStatementClass::Transaction, "COMMIT"),
        Statement::Rollback { .. } => (SqlStatementClass::Transaction, "ROLLBACK"),
        Statement::Savepoint { .. } => (SqlStatementClass::Transaction, "SAVEPOINT"),
        Statement::ReleaseSavepoint { .. } => {
            (SqlStatementClass::Transaction, "RELEASE_SAVEPOINT")
        }
        Statement::SetTransaction { .. } => (SqlStatementClass::Transaction, "SET_TRANSACTION"),
        Statement::Grant { .. } => (SqlStatementClass::PrivilegeOrAdmin, "GRANT"),
        Statement::Revoke { .. } => (SqlStatementClass::PrivilegeOrAdmin, "REVOKE"),
        Statement::CreateRole { .. } | Statement::AlterRole { .. } => {
            (SqlStatementClass::PrivilegeOrAdmin, "ROLE_ADMIN")
        }
        Statement::Kill { .. } => (SqlStatementClass::PrivilegeOrAdmin, "KILL"),
        Statement::Analyze { .. } => (SqlStatementClass::PrivilegeOrAdmin, "ANALYZE"),
        Statement::Call(_) => (SqlStatementClass::Write, "CALL"),
        Statement::Execute { .. } => (SqlStatementClass::Write, "EXECUTE"),
        Statement::SetVariable { .. } => (SqlStatementClass::Transaction, "SET"),
        Statement::Pragma { value, .. } => {
            if value.is_some() {
                (SqlStatementClass::PrivilegeOrAdmin, "PRAGMA_WRITE")
            } else {
                (SqlStatementClass::Read, "PRAGMA_READ")
            }
        }
        _ => (SqlStatementClass::Unknown, "UNKNOWN"),
    }
}

fn analyze_ast_statement(
    engine: DatabaseEngine,
    index: usize,
    raw_sql: &str,
    stmt: &Statement,
) -> StatementAnalysis {
    let (base_class, kind) = classify_top_level_statement(stmt);
    let mut inspector = AstInspector::new();
    let _ = stmt.visit(&mut inspector);

    // Additional token-level check for CTE writes or privileged functions that might appear in raw tokens
    let (token_cte_write, token_priv_fns) = inspect_tokens_for_hazards(engine, raw_sql);
    if token_cte_write {
        inspector.has_cte = true;
        inspector.has_cte_write = true;
    }
    for pf in token_priv_fns {
        inspector.privileged_functions.insert(pf);
    }

    let mut classes = vec![base_class];
    classes.extend(inspector.nested_classes.iter().copied());
    let final_class = combine_statement_classes(
        classes.into_iter(),
        inspector.has_cte_write,
        !inspector.privileged_functions.is_empty(),
    );

    let is_transactional_ddl_safe = match engine {
        DatabaseEngine::Postgres | DatabaseEngine::Sqlite => {
            matches!(
                final_class,
                SqlStatementClass::Read | SqlStatementClass::Write | SqlStatementClass::Ddl
            ) && !raw_sql.to_ascii_uppercase().contains("CONCURRENTLY")
        }
        DatabaseEngine::MySql => final_class != SqlStatementClass::Ddl,
    };

    let mut disclosure = analyze_statement_disclosure(engine, stmt);
    if kind == "UNKNOWN" {
        // Unclassified statements may embed queries the AST walk does not understand.
        disclosure.opaque_sql.push(raw_sql.to_string());
    }

    StatementAnalysis {
        index,
        raw_sql: raw_sql.to_string(),
        normalized_sql: normalize_sql(raw_sql),
        statement_class: final_class,
        statement_kind: kind.to_string(),
        has_cte: inspector.has_cte,
        has_cte_write: inspector.has_cte_write,
        privileged_functions: inspector.privileged_functions.into_iter().collect(),
        referenced_tables: inspector.referenced_tables.into_iter().collect(),
        referenced_columns: inspector.referenced_columns.into_iter().collect(),
        predicates: inspector.predicates.into_iter().collect(),
        is_transactional_ddl_safe,
        disclosure,
    }
}

/// Inspect token stream for CTE writes (`WITH ... AS (DELETE/INSERT/UPDATE ...)`) and privileged functions.
fn inspect_tokens_for_hazards(engine: DatabaseEngine, raw_sql: &str) -> (bool, Vec<String>) {
    let dialect = dialect_for_engine(engine);
    let Ok(tokens) = Tokenizer::new(dialect.as_ref(), raw_sql).tokenize() else {
        return (false, Vec::new());
    };

    let words: Vec<String> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.value.to_ascii_lowercase()),
            Token::LParen => Some("(".to_string()),
            Token::RParen => Some(")".to_string()),
            _ => None,
        })
        .collect();

    let mut has_cte_write = false;
    let mut priv_fns = Vec::new();

    if words.first().map(String::as_str) == Some("with") {
        let mut paren_depth = 0usize;
        for w in &words {
            match w.as_str() {
                "(" => paren_depth += 1,
                ")" => paren_depth = paren_depth.saturating_sub(1),
                "insert" | "update" | "delete" | "merge" | "drop" | "alter" | "truncate"
                    if paren_depth > 0 =>
                {
                    has_cte_write = true;
                }
                _ => {}
            }
        }
    }

    for i in 0..words.len() {
        let w = &words[i];
        let next_is_paren = words.get(i + 1).map(String::as_str) == Some("(");
        if next_is_paren && is_privileged_function(w) {
            priv_fns.push(w.clone());
        }
        if (w == "attach" || w == "detach") && i == 0 {
            priv_fns.push(w.clone());
        }
    }

    (has_cte_write, priv_fns)
}

fn analyze_fallback_statement(
    engine: DatabaseEngine,
    index: usize,
    raw_sql: &str,
    _parse_err: &str,
) -> StatementAnalysis {
    let (has_cte_write, priv_fns) = inspect_tokens_for_hazards(engine, raw_sql);
    let upper = raw_sql.trim_start().to_ascii_uppercase();
    let first_word = upper.split_whitespace().next().unwrap_or("");

    let (class, kind) = if !priv_fns.is_empty()
        || matches!(first_word, "ATTACH" | "DETACH" | "VACUUM" | "COPY" | "GRANT" | "REVOKE")
    {
        (SqlStatementClass::PrivilegeOrAdmin, first_word)
    } else if has_cte_write {
        (SqlStatementClass::Write, "CTE_WRITE")
    } else {
        (SqlStatementClass::Unknown, "UNKNOWN")
    };

    StatementAnalysis {
        index,
        raw_sql: raw_sql.to_string(),
        normalized_sql: normalize_sql(raw_sql),
        statement_class: class,
        statement_kind: kind.to_string(),
        has_cte: upper.starts_with("WITH "),
        has_cte_write,
        privileged_functions: priv_fns,
        referenced_tables: Vec::new(),
        referenced_columns: Vec::new(),
        predicates: Vec::new(),
        is_transactional_ddl_safe: false,
        disclosure: DisclosureAnalysis::opaque(raw_sql),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_simple_select_and_extract_predicates() {
        let sql = "SELECT u.id, u.email, o.total FROM public.users u JOIN public.orders o ON u.id = o.user_id WHERE u.status = 'active' AND o.created_at > '2026-01-01' ORDER BY o.created_at DESC";
        let analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, sql).unwrap();

        assert_eq!(analysis.statement_count, 1);
        assert!(!analysis.is_multi_statement);
        assert_eq!(analysis.overall_class, SqlStatementClass::Read);
        assert!(!analysis.has_writes);
        assert!(!analysis.has_ddl);
        assert!(!analysis.has_cte_write);
        assert!(analysis.referenced_tables.contains(&"public.users".to_string()));
        assert!(analysis.referenced_tables.contains(&"public.orders".to_string()));

        assert!(analysis.predicates.iter().any(|p| {
            p.table.as_deref() == Some("public.users")
                && p.column == "status"
                && p.operator == PredicateOperator::Eq
        }));
        assert!(analysis.predicates.iter().any(|p| {
            p.table.as_deref() == Some("public.orders")
                && p.column == "user_id"
                && p.operator == PredicateOperator::JoinEq
        }));
        assert!(analysis.predicates.iter().any(|p| {
            p.table.as_deref() == Some("public.orders")
                && p.column == "created_at"
                && p.operator == PredicateOperator::OrderBy
        }));
    }

    #[test]
    fn test_detect_multi_statement_injection() {
        let sql = "SELECT id FROM users WHERE id = 1; DROP TABLE users;";
        let analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, sql).unwrap();
        assert_eq!(analysis.statement_count, 2);
        assert!(analysis.is_multi_statement);
        assert!(analysis.has_ddl);
        assert_eq!(analysis.overall_class, SqlStatementClass::Ddl);
    }

    #[test]
    fn test_detect_hidden_writes_in_cte() {
        let sql = "WITH deleted_rows AS (DELETE FROM users WHERE active = false RETURNING id) SELECT * FROM deleted_rows";
        let analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, sql).unwrap();
        assert!(analysis.has_cte_write);
        assert!(analysis.has_writes);
        assert_eq!(analysis.overall_class, SqlStatementClass::Write);
    }

    #[test]
    fn test_detect_privileged_functions() {
        let pg_sql = "SELECT pg_read_file('/etc/passwd'), pg_sleep(5)";
        let pg_analysis = parse_and_analyze_sql(DatabaseEngine::Postgres, pg_sql).unwrap();
        assert!(pg_analysis.has_privileged_functions);
        assert!(pg_analysis
            .privileged_functions
            .contains(&"pg_read_file".to_string()));
        assert!(pg_analysis
            .privileged_functions
            .contains(&"pg_sleep".to_string()));
        assert_eq!(
            pg_analysis.overall_class,
            SqlStatementClass::PrivilegeOrAdmin
        );

        let mysql_sql = "SELECT LOAD_FILE('/var/lib/mysql-files/secret.txt')";
        let mysql_analysis = parse_and_analyze_sql(DatabaseEngine::MySql, mysql_sql).unwrap();
        assert!(mysql_analysis.has_privileged_functions);
        assert!(mysql_analysis
            .privileged_functions
            .contains(&"load_file".to_string()));
        assert_eq!(
            mysql_analysis.overall_class,
            SqlStatementClass::PrivilegeOrAdmin
        );
    }

    #[test]
    fn test_unknown_construct_fails_closed_in_governed_mode() {
        let bad_sql = "FOOBAR_VENDOR_COMMAND table_x WITH MAGIC";
        let dev_res =
            analyze_sql_for_mode(DatabaseEngine::Postgres, bad_sql, OperatingMode::Development);
        assert!(dev_res.is_ok());
        assert_eq!(dev_res.unwrap().overall_class, SqlStatementClass::Unknown);

        let gov_res = analyze_sql_for_mode(
            DatabaseEngine::Postgres,
            bad_sql,
            OperatingMode::GovernedProduction,
        );
        assert!(gov_res.is_err());
        assert_eq!(gov_res.unwrap_err().code(), "UNKNOWN_SQL_CONSTRUCT");
    }

    #[test]
    fn test_normalize_and_hash_sql() {
        let s1 = "SELECT   id,  email \n FROM users -- inline comment\n WHERE id = 1 ; ";
        let s2 = "SELECT id, email FROM users WHERE id = 1";
        assert_eq!(normalize_sql(s1), normalize_sql(s2));
        assert_eq!(hash_sql(s1), hash_sql(s2));
    }

    fn exposed(engine: DatabaseEngine, sql: &str) -> Vec<(String, Option<String>)> {
        parse_and_analyze_sql(engine, sql)
            .unwrap()
            .disclosure
            .exposures
            .into_iter()
            .map(|e| (e.column, e.output_name))
            .collect()
    }

    fn untracked(engine: DatabaseEngine, sql: &str) -> Vec<String> {
        parse_and_analyze_sql(engine, sql)
            .unwrap()
            .disclosure
            .untracked_provenance
    }

    #[test]
    fn test_disclosure_bare_projection_and_predicates_are_not_exposures() {
        for engine in [DatabaseEngine::Sqlite, DatabaseEngine::Postgres, DatabaseEngine::MySql] {
            for sql in [
                "SELECT password_hash FROM users",
                "SELECT users.password_hash FROM users",
                "SELECT u.password_hash, o.id FROM users u JOIN orders o ON o.user_id = u.id",
                "SELECT * FROM users ORDER BY id",
                "WITH c AS (SELECT password_hash FROM users) SELECT * FROM c",
                "SELECT id FROM users WHERE password_hash = 'x' ORDER BY password_hash",
                "SELECT id FROM users WHERE id IN (SELECT id FROM users WHERE password_hash IS NULL)",
                "SELECT id FROM users UNION ALL SELECT id FROM orders",
                "INSERT INTO users (id, password_hash) VALUES (1, 'h')",
                "UPDATE users SET password_hash = 'x' WHERE password_hash = 'y'",
            ] {
                let analysis = parse_and_analyze_sql(engine, sql).unwrap();
                let sensitive: Vec<_> = analysis
                    .disclosure
                    .exposures
                    .iter()
                    .filter(|e| {
                        e.column == "password_hash"
                            && e.output_name.as_deref() != Some("password_hash")
                    })
                    .collect();
                assert!(sensitive.is_empty(), "{engine} {sql}: {sensitive:?}");
                assert!(analysis.disclosure.untracked_provenance.is_empty(), "{engine} {sql}");
            }
        }
    }

    #[test]
    fn test_disclosure_renamed_and_derived_projections_are_exposures() {
        let ph = |out: Option<&str>| ("password_hash".to_string(), out.map(str::to_string));
        for engine in [DatabaseEngine::Sqlite, DatabaseEngine::Postgres, DatabaseEngine::MySql] {
            let cases: [(&str, Option<&str>); 11] = [
                ("SELECT password_hash AS ph FROM users", Some("ph")),
                ("SELECT upper(password_hash) FROM users", None),
                ("SELECT email || ':' || password_hash AS creds FROM users", Some("creds")),
                ("SELECT ph FROM (SELECT password_hash AS ph FROM users) t", Some("ph")),
                ("SELECT 1 UNION SELECT password_hash FROM users", None),
                ("SELECT (SELECT password_hash FROM users LIMIT 1) AS v", Some("v")),
                ("WITH c(x) AS (SELECT password_hash FROM users) SELECT x FROM c", Some("x")),
                ("INSERT INTO notes SELECT password_hash FROM users", None),
                ("INSERT INTO notes (body) SELECT password_hash FROM users", Some("body")),
                ("UPDATE users SET email = password_hash", Some("email")),
                ("CREATE VIEW v AS SELECT password_hash AS x FROM users", Some("x")),
            ];
            for (sql, out) in cases {
                assert!(exposed(engine, sql).contains(&ph(out)), "{engine} {sql}: {:?}", exposed(engine, sql));
            }
            // The leftmost branch names the column: a sensitive name stays masked.
            assert!(exposed(engine, "SELECT password_hash FROM users UNION SELECT password_hash FROM users")
                .iter()
                .all(|(_, out)| out.as_deref() == Some("password_hash")));
        }
        assert!(exposed(DatabaseEngine::Sqlite, "ALTER TABLE users RENAME COLUMN password_hash TO ph")
            .contains(&ph(Some("ph"))));
    }

    #[test]
    fn test_disclosure_untracked_provenance() {
        for engine in [DatabaseEngine::Sqlite, DatabaseEngine::Postgres, DatabaseEngine::MySql] {
            for sql in [
                "SELECT id, email, role, created_at, 1 FROM orders UNION SELECT * FROM users",
                "INSERT INTO copy SELECT * FROM users",
                "SELECT x FROM (SELECT * FROM users) AS t(a, b, x)",
            ] {
                assert!(!untracked(engine, sql).is_empty(), "{engine} {sql}");
            }
            assert!(untracked(engine, "SELECT * FROM users").is_empty());
            assert!(untracked(engine, "SELECT * INTO new_table FROM users").is_empty(), "{engine}");
            assert!(untracked(engine, "SELECT count(*) FROM users").is_empty());
        }
        let pg = DatabaseEngine::Postgres;
        for sql in [
            "SELECT u FROM users u",
            "SELECT row_to_json(u) AS j FROM users u",
            "SELECT row_to_json(u.*) AS j FROM users u",
            "SELECT x FROM users AS u(a, x)",
        ] {
            assert!(!untracked(pg, sql).is_empty(), "{sql}");
        }
        assert!(untracked(pg, "SELECT n FROM generate_series(1, 3) AS g(n)").is_empty());
    }

    #[test]
    fn test_disclosure_opaque_sql_is_reported() {
        let analysis = parse_and_analyze_sql(
            DatabaseEngine::Postgres,
            "CREATE FUNCTION leak() RETURNS text AS $$ SELECT password_hash FROM users LIMIT 1 $$ LANGUAGE sql",
        )
        .unwrap();
        assert!(analysis
            .disclosure
            .opaque_sql
            .iter()
            .any(|t| t.contains("password_hash")));
        let unparsed =
            parse_and_analyze_sql(DatabaseEngine::Sqlite, "FOOBAR_VENDOR password_hash WITH MAGIC").unwrap();
        assert_eq!(unparsed.disclosure.opaque_sql.len(), 1);
    }
}
