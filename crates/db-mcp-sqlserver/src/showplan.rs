//! Parser for SQL Server estimated plans (`SET SHOWPLAN_XML ON`).

use db_mcp_core::{DbMcpError, DbMcpResult};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{json, Value};

/// Structured summary of a showplan document.
#[derive(Debug, Clone, Default)]
pub struct ParsedShowplan {
    pub estimated_cost: Option<f64>,
    pub estimated_rows: Option<f64>,
    /// Tables read by scans (`Table Scan`, `Clustered Index Scan`, `Index Scan`).
    pub scans: Vec<String>,
    /// Index seeks as `schema.table using index`.
    pub seeks: Vec<String>,
    pub missing_indexes: Vec<MissingIndexHint>,
    pub warnings: Vec<String>,
    pub structured: Value,
    pub text_tree: String,
}

/// A `<MissingIndexGroup>` hint from the optimizer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MissingIndexHint {
    pub impact: f64,
    pub schema: String,
    pub table: String,
    pub equality: Vec<String>,
    pub inequality: Vec<String>,
    pub include: Vec<String>,
}

impl MissingIndexHint {
    pub fn qualified_table(&self) -> String {
        if self.schema.is_empty() {
            self.table.clone()
        } else {
            format!("{}.{}", self.schema, self.table)
        }
    }

    /// Advisory T-SQL for the hint.
    pub fn suggested_ddl(&self) -> String {
        let keys: Vec<String> = self
            .equality
            .iter()
            .chain(self.inequality.iter())
            .cloned()
            .collect();
        let name = format!(
            "ix_{}_{}",
            self.table,
            keys.iter()
                .map(|k| k.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_"))
                .collect::<Vec<_>>()
                .join("_")
        );
        let include = if self.include.is_empty() {
            String::new()
        } else {
            format!(" INCLUDE ({})", self.include.join(", "))
        };
        format!(
            "CREATE NONCLUSTERED INDEX {name} ON {} ({}){include};",
            self.qualified_table(),
            keys.join(", ")
        )
    }
}

#[derive(Debug, Clone, Default)]
struct Node {
    physical_op: String,
    logical_op: String,
    estimate_rows: Option<f64>,
    estimated_cost: Option<f64>,
    object: Option<String>,
    index: Option<String>,
    children: Vec<Node>,
}

impl Node {
    fn to_json(&self) -> Value {
        json!({
            "physical_op": self.physical_op,
            "logical_op": self.logical_op,
            "estimate_rows": self.estimate_rows,
            "estimated_subtree_cost": self.estimated_cost,
            "object": self.object,
            "index": self.index,
            "children": self.children.iter().map(Node::to_json).collect::<Vec<_>>(),
        })
    }

    fn render(&self, depth: usize, out: &mut String) {
        out.push_str(&"  ".repeat(depth));
        out.push_str(&self.physical_op);
        if let Some(o) = &self.object {
            out.push_str(&format!(" on {o}"));
            if let Some(i) = &self.index {
                out.push_str(&format!(" ({i})"));
            }
        }
        out.push_str(&format!(
            "  (rows={}, cost={})\n",
            self.estimate_rows
                .map(|r| format!("{r:.1}"))
                .unwrap_or_else(|| "?".into()),
            self.estimated_cost
                .map(|c| format!("{c:.6}"))
                .unwrap_or_else(|| "?".into())
        ));
        for c in &self.children {
            c.render(depth + 1, out);
        }
    }
}

fn unbracket(s: &str) -> String {
    s.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn attr(e: &BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == name.as_bytes())
        .and_then(|a| {
            a.decoded_and_normalized_value(XmlVersion::Implicit1_0, e.decoder())
                .ok()
                .map(|value| value.into_owned())
        })
}

fn attr_f64(e: &BytesStart, name: &str) -> Option<f64> {
    attr(e, name).and_then(|v| v.parse::<f64>().ok())
}

/// Parse a SHOWPLAN_XML document. The plan of the last statement that carries a cost is used
/// for the top-level estimates.
pub fn parse_showplan_xml(xml: &str) -> DbMcpResult<ParsedShowplan> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut out = ParsedShowplan::default();
    let mut stack: Vec<Node> = Vec::new();
    let mut roots: Vec<Node> = Vec::new();
    let mut in_warnings = 0usize;
    let mut current_hint: Option<MissingIndexHint> = None;
    let mut current_usage: Option<String> = None;
    let mut statement_roots_start = 0usize;

    loop {
        let ev = reader.read_event().map_err(|e| {
            DbMcpError::AdapterError(format!("could not parse SQL Server showplan XML: {e}"))
        })?;
        let (e, is_empty) = match &ev {
            Event::Start(e) => (Some(e.clone()), false),
            Event::Empty(e) => (Some(e.clone()), true),
            Event::End(end) => {
                match end.local_name().as_ref() {
                    b"RelOp" => {
                        if let Some(node) = stack.pop() {
                            match stack.last_mut() {
                                Some(parent) => parent.children.push(node),
                                None => roots.push(node),
                            }
                        }
                    }
                    b"Warnings" => in_warnings = in_warnings.saturating_sub(1),
                    b"MissingIndexGroup" => {
                        if let Some(h) = current_hint.take() {
                            out.missing_indexes.push(h);
                        }
                    }
                    b"ColumnGroup" => current_usage = None,
                    _ => {}
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let Some(e) = e else { continue };
        let name = e.local_name();
        match name.as_ref() {
            b"StmtSimple" => {
                if let Some(cost) = attr_f64(&e, "StatementSubTreeCost") {
                    out.estimated_cost = Some(cost);
                    out.estimated_rows = attr_f64(&e, "StatementEstRows");
                    statement_roots_start = roots.len();
                }
            }
            b"RelOp" => {
                let node = Node {
                    physical_op: attr(&e, "PhysicalOp").unwrap_or_default(),
                    logical_op: attr(&e, "LogicalOp").unwrap_or_default(),
                    estimate_rows: attr_f64(&e, "EstimateRows"),
                    estimated_cost: attr_f64(&e, "EstimatedTotalSubtreeCost"),
                    ..Node::default()
                };
                if is_empty {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => roots.push(node),
                    }
                } else {
                    stack.push(node);
                }
            }
            b"Object" => {
                if let Some(top) = stack.last_mut() {
                    if top.object.is_none() {
                        if let Some(table) = attr(&e, "Table") {
                            let schema = attr(&e, "Schema")
                                .map(|s| unbracket(&s))
                                .unwrap_or_default();
                            let table = unbracket(&table);
                            top.object = Some(if schema.is_empty() {
                                table
                            } else {
                                format!("{schema}.{table}")
                            });
                            top.index = attr(&e, "Index").map(|i| unbracket(&i));
                        }
                    }
                }
            }
            b"Warnings" => {
                if !is_empty {
                    in_warnings += 1;
                }
                for a in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(a.key.local_name().as_ref()).to_string();
                    if a.decoded_and_normalized_value(XmlVersion::Implicit1_0, e.decoder())
                        .map(|value| value == "true" || value == "1")
                        .unwrap_or(false)
                    {
                        out.warnings.push(format!("plan warning: {key}"));
                    }
                }
            }
            b"MissingIndexGroup" => {
                current_hint = Some(MissingIndexHint {
                    impact: attr_f64(&e, "Impact").unwrap_or(0.0),
                    ..Default::default()
                });
            }
            b"MissingIndex" => {
                if let Some(h) = current_hint.as_mut() {
                    h.schema = attr(&e, "Schema")
                        .map(|s| unbracket(&s))
                        .unwrap_or_default();
                    h.table = attr(&e, "Table").map(|s| unbracket(&s)).unwrap_or_default();
                }
            }
            b"ColumnGroup" => current_usage = attr(&e, "Usage"),
            b"Column" => {
                if let (Some(h), Some(usage)) = (current_hint.as_mut(), current_usage.as_deref()) {
                    if let Some(col) = attr(&e, "Name").map(|n| unbracket(&n)) {
                        match usage {
                            "EQUALITY" => h.equality.push(col),
                            "INEQUALITY" => h.inequality.push(col),
                            _ => h.include.push(col),
                        }
                    }
                }
            }
            other if in_warnings > 0 => {
                out.warnings
                    .push(format!("plan warning: {}", String::from_utf8_lossy(other)));
            }
            _ => {}
        }
    }

    let plan_roots: Vec<Node> = roots.split_off(statement_roots_start.min(roots.len()));
    let plan_roots = if plan_roots.is_empty() {
        roots
    } else {
        plan_roots
    };
    fn walk(n: &Node, scans: &mut Vec<String>, seeks: &mut Vec<String>) {
        if let Some(obj) = &n.object {
            let op = n.physical_op.as_str();
            if op.ends_with("Scan") {
                if !scans.contains(obj) {
                    scans.push(obj.clone());
                }
            } else if op.ends_with("Seek") {
                let s = match &n.index {
                    Some(i) => format!("{obj} using {i}"),
                    None => obj.clone(),
                };
                if !seeks.contains(&s) {
                    seeks.push(s);
                }
            }
        }
        for c in &n.children {
            walk(c, scans, seeks);
        }
    }
    let mut text = String::new();
    for r in &plan_roots {
        walk(r, &mut out.scans, &mut out.seeks);
        r.render(0, &mut text);
    }
    for h in &out.missing_indexes {
        out.warnings.push(format!(
            "optimizer missing-index hint (impact {:.1}%): {}",
            h.impact,
            h.suggested_ddl()
        ));
    }
    out.text_tree = text;
    out.structured = json!({
        "engine": "sqlserver",
        "plan_kind": "estimated",
        "statement_subtree_cost": out.estimated_cost,
        "statement_est_rows": out.estimated_rows,
        "operators": plan_roots.iter().map(Node::to_json).collect::<Vec<_>>(),
        "missing_indexes": out.missing_indexes.iter().map(|h| json!({
            "impact": h.impact,
            "table": h.qualified_table(),
            "equality_columns": h.equality,
            "inequality_columns": h.inequality,
            "include_columns": h.include,
            "suggested_ddl": h.suggested_ddl(),
        })).collect::<Vec<_>>(),
    });
    if plan_roots.is_empty() {
        return Err(DbMcpError::AdapterError(
            "SQL Server showplan contained no operators".to_string(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN: &str = r#"<?xml version="1.0" encoding="utf-16"?>
<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.564" Build="16.0.1000.6">
 <BatchSequence><Batch><Statements>
  <StmtSimple StatementText="DECLARE @P1 bigint;" StatementId="1" StatementType="DECLARE"/>
  <StmtSimple StatementText="SELECT ..." StatementId="2" StatementSubTreeCost="0.0065704" StatementEstRows="1" StatementType="SELECT">
   <QueryPlan>
    <MissingIndexes>
     <MissingIndexGroup Impact="87.5">
      <MissingIndex Database="[dbmcp_fixture]" Schema="[dbo]" Table="[orders]">
       <ColumnGroup Usage="EQUALITY"><Column Name="[status]" ColumnId="3"/></ColumnGroup>
       <ColumnGroup Usage="INCLUDE"><Column Name="[total_cents]" ColumnId="4"/></ColumnGroup>
      </MissingIndex>
     </MissingIndexGroup>
    </MissingIndexes>
    <RelOp NodeId="0" PhysicalOp="Nested Loops" LogicalOp="Inner Join" EstimateRows="1" EstimatedTotalSubtreeCost="0.0065704">
     <Warnings NoJoinPredicate="false"/>
     <NestedLoops Optimized="false">
      <RelOp NodeId="1" PhysicalOp="Clustered Index Scan" LogicalOp="Clustered Index Scan" EstimateRows="4" EstimatedTotalSubtreeCost="0.0032864">
       <IndexScan Ordered="false"><Object Database="[dbmcp_fixture]" Schema="[dbo]" Table="[orders]" Index="[pk_orders]" IndexKind="Clustered"/></IndexScan>
      </RelOp>
      <RelOp NodeId="2" PhysicalOp="Clustered Index Seek" LogicalOp="Clustered Index Seek" EstimateRows="1" EstimatedTotalSubtreeCost="0.0032831">
       <IndexScan Ordered="true"><Object Database="[dbmcp_fixture]" Schema="[dbo]" Table="[users]" Index="[pk_users]"/></IndexScan>
      </RelOp>
     </NestedLoops>
    </RelOp>
   </QueryPlan>
  </StmtSimple>
 </Statements></Batch></BatchSequence>
</ShowPlanXML>"#;

    #[test]
    fn parses_costs_operators_scans_seeks_and_missing_indexes() {
        let p = parse_showplan_xml(PLAN).unwrap();
        assert_eq!(p.estimated_cost, Some(0.0065704));
        assert_eq!(p.estimated_rows, Some(1.0));
        assert_eq!(p.scans, vec!["dbo.orders"]);
        assert_eq!(p.seeks, vec!["dbo.users using pk_users"]);
        assert_eq!(p.missing_indexes.len(), 1);
        let h = &p.missing_indexes[0];
        assert_eq!(h.qualified_table(), "dbo.orders");
        assert_eq!(h.equality, vec!["status"]);
        assert_eq!(h.include, vec!["total_cents"]);
        assert_eq!(h.suggested_ddl(), "CREATE NONCLUSTERED INDEX ix_orders_status ON dbo.orders (status) INCLUDE (total_cents);");
        assert_eq!(p.structured["operators"][0]["physical_op"], "Nested Loops");
        assert_eq!(
            p.structured["operators"][0]["children"][1]["object"],
            "dbo.users"
        );
        assert!(p.text_tree.starts_with("Nested Loops"), "{}", p.text_tree);
        assert!(p
            .text_tree
            .contains("\n  Clustered Index Scan on dbo.orders (pk_orders)"));
        assert!(p.warnings.iter().any(|w| w.contains("missing-index")));
        assert!(!p.warnings.iter().any(|w| w.contains("NoJoinPredicate")));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_showplan_xml("<ShowPlanXML><BatchSequence/></ShowPlanXML>").is_err());
        assert!(parse_showplan_xml("<a><b></a>").is_err());
    }
}
