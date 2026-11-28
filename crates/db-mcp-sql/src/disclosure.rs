//! Result-disclosure provenance analysis.
//!
//! Result redaction masks sensitive columns by *output column name*. A query can move a sensitive
//! column's value under a different name (alias, expression, set-operation position, column alias
//! list, `INSERT ... SELECT`, `UPDATE ... SET`, `ALTER TABLE ... RENAME COLUMN`) so that the value
//! reaches the result, or a readable column, under a name redaction does not recognise.
//!
//! This module counts every column reference in a statement and subtracts the references whose
//! output provenance is known:
//! - a bare, unaliased projection item (`SELECT password_hash`, `SELECT u.password_hash`) in a
//!   SELECT whose output columns keep their own names, so redaction still sees the column name;
//! - filter / join / grouping / ordering positions, which never place the value in the output.
//!
//! Everything else is reported as a [`ColumnExposure`] (with the name it surfaces under, when the
//! query chose one) so policy can deny exposures of configured sensitive columns. Wildcards whose
//! columns land in positions named elsewhere, PostgreSQL whole-row references and column alias
//! lists on base relations are reported as untracked provenance. The analysis fails closed: any
//! position it does not understand stays counted as an exposure.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use db_mcp_core::DatabaseEngine;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    AlterTableOperation, AssignmentTarget, Distinct, Expr, FunctionArg, FunctionArgExpr,
    FunctionArguments, GroupByExpr, Ident, JoinConstraint, JoinOperator, Query, Select, SelectItem,
    SetExpr, Statement, TableFactor, TableWithJoins, Visit, Visitor,
};

/// A column reference whose value reaches query output (or stored data) under a name other than
/// its own column name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ColumnExposure {
    /// Table the column resolves to (`None` when it cannot be resolved to a single table).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    /// Name the value surfaces under (alias, positional target column, renamed column).
    /// `None` when the name is derived from an expression or is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_name: Option<String>,
}

/// Output-provenance facts used by result-disclosure policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureAnalysis {
    /// Column references that are not a bare, unaliased projection item or a filter position.
    #[serde(default)]
    pub exposures: Vec<ColumnExposure>,
    /// Reasons the statement's output columns cannot be traced back to source columns.
    #[serde(default)]
    pub untracked_provenance: Vec<String>,
    /// Raw text of statements whose bodies could not be analysed (unparsed SQL, routine/trigger
    /// bodies, unclassified statements); policy scans it for sensitive column names.
    #[serde(default)]
    pub opaque_sql: Vec<String>,
}

impl DisclosureAnalysis {
    /// Analysis for a statement the AST parser could not handle: only its raw text is known.
    pub fn opaque(raw_sql: &str) -> Self {
        Self {
            opaque_sql: vec![raw_sql.to_string()],
            ..Self::default()
        }
    }

    /// Merge another statement's analysis into this one.
    pub fn merge(&mut self, other: &DisclosureAnalysis) {
        let mut exposures: BTreeSet<ColumnExposure> = self.exposures.drain(..).collect();
        exposures.extend(other.exposures.iter().cloned());
        self.exposures = exposures.into_iter().collect();
        for reason in &other.untracked_provenance {
            if !self.untracked_provenance.contains(reason) {
                self.untracked_provenance.push(reason.clone());
            }
        }
        self.opaque_sql.extend(other.opaque_sql.iter().cloned());
    }
}

/// Analyse how the column references of one parsed statement reach its output.
pub fn analyze_statement_disclosure(
    engine: DatabaseEngine,
    stmt: &Statement,
) -> DisclosureAnalysis {
    let mut scope = RelationScope::default();
    let _ = stmt.visit(&mut scope);
    let whole_row_names = if engine == DatabaseEngine::Postgres {
        scope.relation_names.clone()
    } else {
        BTreeSet::new()
    };

    let all = RefCounter::count(stmt, &whole_row_names);
    let mut walker = DisclosureWalker {
        whole_row_names: &whole_row_names,
        safe: BTreeMap::new(),
        renamed: Vec::new(),
        explicit: Vec::new(),
        untracked: Vec::new(),
    };
    walker.walk_statement(stmt);

    let mut remaining = all;
    for (key, n) in &walker.safe {
        subtract(&mut remaining, key, *n);
    }
    for (key, _) in &walker.renamed {
        subtract(&mut remaining, key, 1);
    }

    let mut exposures = BTreeSet::new();
    let mut untracked = walker.untracked.clone();
    for (key, output_name) in &walker.renamed {
        if let RefKey::Column { qualifier, column } = key {
            for exp in scope.resolve(qualifier.as_deref(), column, output_name.clone()) {
                exposures.insert(exp);
            }
        }
    }
    for (key, n) in &remaining {
        if *n == 0 {
            continue;
        }
        match key {
            RefKey::Column { qualifier, column } => {
                for exp in scope.resolve(qualifier.as_deref(), column, None) {
                    exposures.insert(exp);
                }
            }
            RefKey::WholeRow(name) => untracked.push(format!(
                "whole-row reference '{name}' returns every column of the row under one output name"
            )),
            RefKey::Wildcard => untracked.push(
                "wildcard projection whose columns land in positions named elsewhere (set operation, INSERT ... SELECT, column alias list, scalar subquery or SELECT INTO)"
                    .to_string(),
            ),
        }
    }
    exposures.extend(walker.explicit);
    untracked.sort();
    untracked.dedup();

    let mut opaque_sql = Vec::new();
    if matches!(
        stmt,
        Statement::CreateFunction { .. }
            | Statement::CreateProcedure { .. }
            | Statement::CreateTrigger { .. }
            | Statement::Prepare { .. }
    ) {
        opaque_sql.push(stmt.to_string());
    }

    DisclosureAnalysis {
        exposures: exposures.into_iter().collect(),
        untracked_provenance: untracked,
        opaque_sql,
    }
}

fn subtract(map: &mut BTreeMap<RefKey, usize>, key: &RefKey, n: usize) {
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(n);
    }
}

fn clean(ident: &Ident) -> String {
    ident.value.trim().to_ascii_lowercase()
}

/// Identity of one counted reference occurrence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RefKey {
    Column {
        qualifier: Option<String>,
        column: String,
    },
    /// PostgreSQL whole-row value (`SELECT u FROM users u`, `row_to_json(u.*)`).
    WholeRow(String),
    /// Projection wildcard (`*`, `t.*`, `TABLE t`).
    Wildcard,
}

fn key_for_expr(expr: &Expr, whole_row_names: &BTreeSet<String>) -> Option<RefKey> {
    match expr {
        Expr::Identifier(ident) => {
            let name = clean(ident);
            if whole_row_names.contains(&name) {
                Some(RefKey::WholeRow(name))
            } else {
                Some(RefKey::Column {
                    qualifier: None,
                    column: name,
                })
            }
        }
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => Some(RefKey::Column {
            qualifier: Some(clean(&parts[parts.len() - 2])),
            column: clean(&parts[parts.len() - 1]),
        }),
        Expr::CompoundIdentifier(parts) if parts.len() == 1 => {
            key_for_expr(&Expr::Identifier(parts[0].clone()), whole_row_names)
        }
        Expr::QualifiedWildcard(name) => {
            Some(RefKey::WholeRow(name.to_string().to_ascii_lowercase()))
        }
        _ => None,
    }
}

/// Counts every column reference, whole-row reference and projection wildcard in a node.
struct RefCounter<'a> {
    whole_row_names: &'a BTreeSet<String>,
    counts: BTreeMap<RefKey, usize>,
}

impl<'a> RefCounter<'a> {
    fn count<V: Visit>(node: &V, whole_row_names: &'a BTreeSet<String>) -> BTreeMap<RefKey, usize> {
        let mut counter = RefCounter {
            whole_row_names,
            counts: BTreeMap::new(),
        };
        let _ = node.visit(&mut counter);
        counter.counts
    }

    fn add(&mut self, key: RefKey) {
        *self.counts.entry(key).or_insert(0) += 1;
    }

    fn count_body_wildcards(&mut self, body: &SetExpr) {
        match body {
            SetExpr::Select(select) => {
                for item in &select.projection {
                    if matches!(
                        item,
                        SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
                    ) {
                        self.add(RefKey::Wildcard);
                    }
                }
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.count_body_wildcards(left);
                self.count_body_wildcards(right);
            }
            SetExpr::Table(_) => self.add(RefKey::Wildcard),
            // Nested queries and statements are visited (and counted) on their own.
            SetExpr::Query(_) | SetExpr::Values(_) | SetExpr::Insert(_) | SetExpr::Update(_) => {}
        }
    }
}

impl Visitor for RefCounter<'_> {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        self.count_body_wildcards(&query.body);
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Some(key) = key_for_expr(expr, self.whole_row_names) {
            self.add(key);
        }
        if let Expr::Function(function) = expr {
            if let FunctionArguments::List(list) = &function.args {
                for arg in &list.args {
                    let arg_expr = match arg {
                        FunctionArg::Named { arg, .. } | FunctionArg::Unnamed(arg) => arg,
                    };
                    if let FunctionArgExpr::QualifiedWildcard(name) = arg_expr {
                        self.add(RefKey::WholeRow(name.to_string().to_ascii_lowercase()));
                    }
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Relation names, aliases and base tables visible anywhere in a statement.
#[derive(Default)]
struct RelationScope {
    /// Lower-cased table names, aliases and CTE names (PostgreSQL whole-row detection).
    relation_names: BTreeSet<String>,
    /// Alias or table name -> base tables it may denote.
    alias_tables: BTreeMap<String, BTreeSet<String>>,
    /// Base tables referenced by the statement (CTE names excluded).
    base_tables: BTreeSet<String>,
    cte_names: BTreeSet<String>,
}

impl RelationScope {
    fn resolve(
        &self,
        qualifier: Option<&str>,
        column: &str,
        output_name: Option<String>,
    ) -> Vec<ColumnExposure> {
        let tables: Vec<Option<String>> = match qualifier {
            Some(q) => {
                let mut candidates: BTreeSet<String> =
                    self.alias_tables.get(q).cloned().unwrap_or_default();
                candidates.insert(q.to_string());
                candidates.into_iter().map(Some).collect()
            }
            None if self.base_tables.len() == 1 => vec![self.base_tables.iter().next().cloned()],
            None => vec![None],
        };
        tables
            .into_iter()
            .map(|table| ColumnExposure {
                table,
                column: column.to_string(),
                output_name: output_name.clone(),
            })
            .collect()
    }

    fn record_alias(&mut self, alias: Option<&sqlparser::ast::TableAlias>, table: Option<&str>) {
        if let Some(alias) = alias {
            let name = clean(&alias.name);
            self.relation_names.insert(name.clone());
            if let Some(t) = table {
                self.alias_tables
                    .entry(name)
                    .or_default()
                    .insert(t.to_string());
            }
        }
    }
}

impl Visitor for RelationScope {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                let name = clean(&cte.alias.name);
                self.relation_names.insert(name.clone());
                self.cte_names.insert(name);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        match factor {
            TableFactor::Table { name, alias, .. } => {
                let full = name.to_string().to_ascii_lowercase();
                let base = name.0.last().map(clean).unwrap_or_else(|| full.clone());
                self.relation_names.insert(base.clone());
                self.alias_tables
                    .entry(base.clone())
                    .or_default()
                    .insert(full.clone());
                if !self.cte_names.contains(&base) {
                    self.base_tables.insert(full.clone());
                }
                self.record_alias(alias.as_ref(), Some(&full));
            }
            TableFactor::Derived { alias, .. }
            | TableFactor::TableFunction { alias, .. }
            | TableFactor::Function { alias, .. }
            | TableFactor::UNNEST { alias, .. }
            | TableFactor::JsonTable { alias, .. }
            | TableFactor::NestedJoin { alias, .. } => self.record_alias(alias.as_ref(), None),
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// How a SELECT's output columns are named.
#[derive(Debug, Clone)]
enum ProjectionContext {
    /// Output columns keep the names this SELECT gives them (top-level query, CTE or derived
    /// table without a column list, subqueries).
    Named,
    /// Output column `i` is named by the surrounding construct (column alias list, INSERT target
    /// columns, leftmost set-operation branch). `None` when those names are unknown.
    Positional(Option<Vec<Option<String>>>),
}

impl ProjectionContext {
    fn positional_name(&self, index: usize) -> Option<String> {
        match self {
            Self::Named | Self::Positional(None) => None,
            Self::Positional(Some(names)) => names.get(index).cloned().flatten(),
        }
    }
}

fn ident_names(idents: &[Ident]) -> Option<Vec<Option<String>>> {
    Some(idents.iter().map(|i| Some(clean(i))).collect())
}

/// Output column names of the leftmost branch of a set operation, up to the first wildcard.
fn leftmost_output_names(body: &SetExpr) -> Option<Vec<Option<String>>> {
    match body {
        SetExpr::Select(select) => {
            let mut names = Vec::new();
            for item in &select.projection {
                match item {
                    SelectItem::UnnamedExpr(Expr::Identifier(ident)) => {
                        names.push(Some(clean(ident)))
                    }
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                        names.push(parts.last().map(clean))
                    }
                    SelectItem::UnnamedExpr(_) => names.push(None),
                    SelectItem::ExprWithAlias { alias, .. } => names.push(Some(clean(alias))),
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => break,
                }
            }
            Some(names)
        }
        SetExpr::SetOperation { left, .. } => leftmost_output_names(left),
        SetExpr::Query(q) => leftmost_output_names(&q.body),
        _ => None,
    }
}

struct DisclosureWalker<'a> {
    whole_row_names: &'a BTreeSet<String>,
    /// References in positions that never reach output, or bare passthrough projection items.
    safe: BTreeMap<RefKey, usize>,
    /// References that reach output under a name chosen by the query.
    renamed: Vec<(RefKey, Option<String>)>,
    /// Exposures with no expression occurrence (column renames in DDL).
    explicit: Vec<ColumnExposure>,
    untracked: Vec<String>,
}

impl DisclosureWalker<'_> {
    fn mark_safe<V: Visit>(&mut self, node: &V) {
        for (key, n) in RefCounter::count(node, self.whole_row_names) {
            *self.safe.entry(key).or_insert(0) += n;
        }
    }

    fn mark_renamed(&mut self, expr: &Expr, output_name: Option<String>) {
        for (key, n) in RefCounter::count(expr, self.whole_row_names) {
            // Whole-row values and wildcards inside an expression stay unaccounted: they carry
            // every column of a row regardless of the name the expression is given.
            if matches!(key, RefKey::Column { .. }) {
                for _ in 0..n {
                    self.renamed.push((key.clone(), output_name.clone()));
                }
            }
        }
    }

    fn walk_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Query(q) => self.walk_query(q, &ProjectionContext::Named),
            Statement::Insert(ins) => {
                if let Some(source) = &ins.source {
                    let names = if ins.columns.is_empty() {
                        None
                    } else {
                        ident_names(&ins.columns)
                    };
                    self.walk_query(source, &ProjectionContext::Positional(names));
                }
                if let Some(returning) = &ins.returning {
                    self.walk_projection(returning, &ProjectionContext::Named, false);
                }
            }
            Statement::Update {
                table,
                assignments,
                from,
                selection,
                returning,
                ..
            } => {
                self.walk_table_with_joins(table);
                if let Some(from) = from {
                    self.walk_table_with_joins(from);
                }
                if let Some(selection) = selection {
                    self.mark_safe(selection);
                }
                for assignment in assignments {
                    let target = match &assignment.target {
                        AssignmentTarget::ColumnName(name) => name.0.last().map(clean),
                        AssignmentTarget::Tuple(_) => None,
                    };
                    self.mark_renamed(&assignment.value, target);
                }
                if let Some(returning) = returning {
                    self.walk_projection(returning, &ProjectionContext::Named, false);
                }
            }
            Statement::Delete(del) => {
                let from_tables = match &del.from {
                    sqlparser::ast::FromTable::WithFromKeyword(v)
                    | sqlparser::ast::FromTable::WithoutKeyword(v) => v,
                };
                for twj in from_tables {
                    self.walk_table_with_joins(twj);
                }
                if let Some(using) = &del.using {
                    for twj in using {
                        self.walk_table_with_joins(twj);
                    }
                }
                if let Some(selection) = &del.selection {
                    self.mark_safe(selection);
                }
                for order in &del.order_by {
                    self.mark_safe(order);
                }
                if let Some(limit) = &del.limit {
                    self.mark_safe(limit);
                }
                if let Some(returning) = &del.returning {
                    self.walk_projection(returning, &ProjectionContext::Named, false);
                }
            }
            Statement::CreateTable(ct) => {
                // Column defaults, CHECK constraints and generated columns only see the new
                // table's own columns.
                for column in &ct.columns {
                    self.mark_safe(column);
                }
                for constraint in &ct.constraints {
                    self.mark_safe(constraint);
                }
                if let Some(query) = &ct.query {
                    let ctx = if ct.columns.is_empty() {
                        ProjectionContext::Named
                    } else {
                        ProjectionContext::Positional(Some(
                            ct.columns.iter().map(|c| Some(clean(&c.name))).collect(),
                        ))
                    };
                    self.walk_query(query, &ctx);
                }
            }
            Statement::CreateView { columns, query, .. } => {
                let ctx = if columns.is_empty() {
                    ProjectionContext::Named
                } else {
                    ProjectionContext::Positional(Some(
                        columns.iter().map(|c| Some(clean(&c.name))).collect(),
                    ))
                };
                self.walk_query(query, &ctx);
            }
            Statement::CreateIndex(index) => self.mark_safe(index),
            Statement::AlterTable {
                name, operations, ..
            } => {
                let table = name.to_string().to_ascii_lowercase();
                for op in operations {
                    let renamed = match op {
                        AlterTableOperation::RenameColumn {
                            old_column_name,
                            new_column_name,
                        } => Some((old_column_name, new_column_name)),
                        AlterTableOperation::ChangeColumn {
                            old_name, new_name, ..
                        } => Some((old_name, new_name)),
                        _ => None,
                    };
                    if let Some((old, new)) = renamed {
                        self.explicit.push(ColumnExposure {
                            table: Some(table.clone()),
                            column: clean(old),
                            output_name: Some(clean(new)),
                        });
                    }
                }
            }
            Statement::Explain { statement, .. } => self.walk_statement(statement),
            // Any other statement: every reference stays counted as an exposure (fail closed).
            _ => {}
        }
    }

    fn walk_query(&mut self, query: &Query, ctx: &ProjectionContext) {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                let cte_ctx = if cte.alias.columns.is_empty() {
                    ProjectionContext::Named
                } else {
                    ProjectionContext::Positional(ident_names(&cte.alias.columns))
                };
                self.walk_query(&cte.query, &cte_ctx);
            }
        }
        self.walk_set_expr(&query.body, ctx);
        if let Some(order_by) = &query.order_by {
            for expr in &order_by.exprs {
                self.mark_safe(expr);
            }
        }
        if let Some(limit) = &query.limit {
            self.mark_safe(limit);
        }
        if let Some(offset) = &query.offset {
            self.mark_safe(offset);
        }
        if let Some(fetch) = &query.fetch {
            self.mark_safe(fetch);
        }
        for expr in &query.limit_by {
            self.mark_safe(expr);
        }
    }

    fn walk_set_expr(&mut self, body: &SetExpr, ctx: &ProjectionContext) {
        match body {
            SetExpr::Select(select) => self.walk_select(select, ctx),
            SetExpr::Query(q) => self.walk_query(q, ctx),
            SetExpr::SetOperation { left, right, .. } => {
                self.walk_set_expr(left, ctx);
                // Output columns are named by the leftmost branch; later branches only supply
                // values for those positions.
                let names = match ctx {
                    ProjectionContext::Positional(names) => names.clone(),
                    ProjectionContext::Named => leftmost_output_names(left),
                };
                self.walk_set_expr(right, &ProjectionContext::Positional(names));
            }
            SetExpr::Values(values) => {
                for row in &values.rows {
                    for (i, expr) in row.iter().enumerate() {
                        self.mark_renamed(expr, ctx.positional_name(i));
                    }
                }
            }
            SetExpr::Insert(stmt) | SetExpr::Update(stmt) => self.walk_statement(stmt),
            SetExpr::Table(_) => {
                if matches!(ctx, ProjectionContext::Named) {
                    *self.safe.entry(RefKey::Wildcard).or_insert(0) += 1;
                }
            }
        }
    }

    fn walk_select(&mut self, select: &Select, ctx: &ProjectionContext) {
        for twj in &select.from {
            self.walk_table_with_joins(twj);
        }
        // `SELECT ... INTO new_table` creates a table with the projection's own column names;
        // `SELECT ... INTO @var` stores values in targets the projection does not name.
        let ctx = match &select.into {
            Some(into) if into.name.to_string().starts_with('@') => {
                ProjectionContext::Positional(None)
            }
            _ => ctx.clone(),
        };
        self.walk_projection(&select.projection, &ctx, true);
        if let Some(selection) = &select.selection {
            self.mark_safe(selection);
        }
        if let Some(prewhere) = &select.prewhere {
            self.mark_safe(prewhere);
        }
        if let Some(having) = &select.having {
            self.mark_safe(having);
        }
        if let Some(qualify) = &select.qualify {
            self.mark_safe(qualify);
        }
        if let GroupByExpr::Expressions(exprs, _) = &select.group_by {
            for expr in exprs {
                self.mark_safe(expr);
            }
        }
        if let Some(Distinct::On(exprs)) = &select.distinct {
            for expr in exprs {
                self.mark_safe(expr);
            }
        }
        for window in &select.named_window {
            self.mark_safe(window);
        }
    }

    fn walk_projection(
        &mut self,
        items: &[SelectItem],
        ctx: &ProjectionContext,
        counted_wildcards: bool,
    ) {
        for (i, item) in items.iter().enumerate() {
            match ctx {
                ProjectionContext::Named => match item {
                    SelectItem::UnnamedExpr(expr) => {
                        // A bare column keeps its own name in the output, where redaction sees it.
                        if let Some(key @ RefKey::Column { .. }) =
                            key_for_expr(expr, self.whole_row_names)
                        {
                            *self.safe.entry(key).or_insert(0) += 1;
                        }
                        // Any other expression is named after its own text: left unaccounted.
                    }
                    SelectItem::ExprWithAlias { expr, alias } => {
                        self.mark_renamed(expr, Some(clean(alias)))
                    }
                    SelectItem::Wildcard(opts) | SelectItem::QualifiedWildcard(_, opts) => {
                        let renames = opts.opt_rename.is_some() || opts.opt_replace.is_some();
                        if counted_wildcards && !renames {
                            *self.safe.entry(RefKey::Wildcard).or_insert(0) += 1;
                        } else if renames {
                            self.untracked.push(
                                "wildcard projection with RENAME/REPLACE options".to_string(),
                            );
                        }
                    }
                },
                ProjectionContext::Positional(_) => match item {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                        self.mark_renamed(expr, ctx.positional_name(i));
                    }
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => {
                        if !counted_wildcards {
                            self.untracked.push(
                                "wildcard projection whose columns land in positions named elsewhere"
                                    .to_string(),
                            );
                        }
                        // Counted wildcards stay unaccounted and are reported as untracked.
                    }
                },
            }
        }
    }

    fn walk_table_with_joins(&mut self, twj: &TableWithJoins) {
        self.walk_table_factor(&twj.relation);
        for join in &twj.joins {
            self.walk_table_factor(&join.relation);
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
                self.mark_safe(expr);
            }
        }
    }

    fn walk_table_factor(&mut self, factor: &TableFactor) {
        match factor {
            TableFactor::Table {
                name, alias, args, ..
            } => {
                // `users AS u(a, b, ...)` renames a relation's columns positionally without naming
                // them. Table-valued function outputs are tracked through their arguments instead.
                if args.is_none() && alias.as_ref().is_some_and(|a| !a.columns.is_empty()) {
                    self.untracked.push(format!(
                        "column alias list on relation '{name}' renames its columns positionally"
                    ));
                }
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => {
                let ctx = match alias {
                    Some(a) if !a.columns.is_empty() => {
                        ProjectionContext::Positional(ident_names(&a.columns))
                    }
                    _ => ProjectionContext::Named,
                };
                self.walk_query(subquery, &ctx);
            }
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => {
                if alias.as_ref().is_some_and(|a| !a.columns.is_empty()) {
                    self.untracked
                        .push("column alias list on a parenthesized join renames its columns positionally".to_string());
                }
                self.walk_table_with_joins(table_with_joins);
            }
            // Table functions, UNNEST, JSON_TABLE, ...: argument references stay unaccounted.
            _ => {}
        }
    }
}
