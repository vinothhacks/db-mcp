//! TDS value mapping (SQL Server column data -> JSON) and parameter conversion (JSON -> TDS).

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use serde_json::Value;
use tiberius::{ColumnData, ColumnType, FromSql, ToSql};

/// SQL Server type name for a result column.
pub fn column_type_name(ty: ColumnType) -> &'static str {
    match ty {
        ColumnType::Null => "null",
        ColumnType::Bit | ColumnType::Bitn => "bit",
        ColumnType::Int1 => "tinyint",
        ColumnType::Int2 => "smallint",
        ColumnType::Int4 | ColumnType::Intn => "int",
        ColumnType::Int8 => "bigint",
        ColumnType::Datetime4 => "smalldatetime",
        ColumnType::Float4 => "real",
        ColumnType::Float8 | ColumnType::Floatn => "float",
        ColumnType::Money => "money",
        ColumnType::Money4 => "smallmoney",
        ColumnType::Datetime | ColumnType::Datetimen => "datetime",
        ColumnType::Guid => "uniqueidentifier",
        ColumnType::Decimaln => "decimal",
        ColumnType::Numericn => "numeric",
        ColumnType::Daten => "date",
        ColumnType::Timen => "time",
        ColumnType::Datetime2 => "datetime2",
        ColumnType::DatetimeOffsetn => "datetimeoffset",
        ColumnType::BigVarBin => "varbinary",
        ColumnType::BigVarChar => "varchar",
        ColumnType::BigBinary => "binary",
        ColumnType::BigChar => "char",
        ColumnType::NVarchar => "nvarchar",
        ColumnType::NChar => "nchar",
        ColumnType::Xml => "xml",
        ColumnType::Udt => "udt",
        ColumnType::Text => "text",
        ColumnType::Image => "image",
        ColumnType::NText => "ntext",
        ColumnType::SSVariant => "sql_variant",
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

fn float(v: f64) -> Value {
    serde_json::Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// Map one cell to JSON: integers and floats as numbers, decimals as exact strings, dates as
/// ISO 8601 strings, binary as `0x...` hex, uniqueidentifier as upper-case text, NULL as null.
pub fn column_data_to_json(data: &ColumnData<'static>) -> Value {
    match data {
        ColumnData::U8(v) => v.map(Value::from).unwrap_or(Value::Null),
        ColumnData::I16(v) => v.map(Value::from).unwrap_or(Value::Null),
        ColumnData::I32(v) => v.map(Value::from).unwrap_or(Value::Null),
        ColumnData::I64(v) => v.map(Value::from).unwrap_or(Value::Null),
        ColumnData::F32(v) => v.map(|f| float(f as f64)).unwrap_or(Value::Null),
        ColumnData::F64(v) => v.map(float).unwrap_or(Value::Null),
        ColumnData::Bit(v) => v.map(Value::Bool).unwrap_or(Value::Null),
        ColumnData::String(v) => v
            .as_ref()
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Guid(v) => v
            .map(|g| Value::String(g.to_string().to_uppercase()))
            .unwrap_or(Value::Null),
        ColumnData::Binary(v) => v
            .as_ref()
            .map(|b| Value::String(hex_upper(b)))
            .unwrap_or(Value::Null),
        ColumnData::Numeric(v) => v
            .map(|n| Value::String(n.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::Xml(v) => v
            .as_ref()
            .map(|x| Value::String(x.to_string()))
            .unwrap_or(Value::Null),
        ColumnData::DateTime(_) | ColumnData::SmallDateTime(_) | ColumnData::DateTime2(_) => {
            match NaiveDateTime::from_sql(data) {
                Ok(Some(dt)) => Value::String(dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string()),
                _ => Value::Null,
            }
        }
        ColumnData::Date(_) => match NaiveDate::from_sql(data) {
            Ok(Some(d)) => Value::String(d.format("%Y-%m-%d").to_string()),
            _ => Value::Null,
        },
        ColumnData::Time(_) => match NaiveTime::from_sql(data) {
            Ok(Some(t)) => Value::String(t.format("%H:%M:%S%.f").to_string()),
            _ => Value::Null,
        },
        ColumnData::DateTimeOffset(_) => match DateTime::<FixedOffset>::from_sql(data) {
            Ok(Some(dt)) => Value::String(dt.to_rfc3339()),
            _ => Value::Null,
        },
    }
}

/// Approximate JSON size of a value (for `max_bytes` budgets).
pub fn json_size(v: &Value) -> usize {
    match v {
        Value::Null => 4,
        Value::Bool(_) => 5,
        Value::Number(n) => n.to_string().len(),
        Value::String(s) => s.len() + 2,
        other => other.to_string().len(),
    }
}

/// An owned TDS parameter converted from a JSON tool argument.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlParam {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
}

impl SqlParam {
    pub fn from_json(v: &Value) -> Self {
        match v {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Self::Int(i),
                None => Self::Float(n.as_f64().unwrap_or(0.0)),
            },
            Value::String(s) => Self::Text(s.clone()),
            other => Self::Text(other.to_string()),
        }
    }

    pub fn as_tosql(&self) -> &dyn ToSql {
        // A NULL parameter is sent as a typed NULL nvarchar.
        const NULL_TEXT: Option<&str> = None;
        match self {
            Self::Null => &NULL_TEXT,
            Self::Bool(b) => b,
            Self::Int(i) => i,
            Self::Float(f) => f,
            Self::Text(s) => s,
        }
    }

    /// T-SQL type used when the parameter must be declared (estimated plans).
    pub fn declared_type(&self) -> &'static str {
        match self {
            Self::Null | Self::Text(_) => "nvarchar(4000)",
            Self::Bool(_) => "bit",
            Self::Int(_) => "bigint",
            Self::Float(_) => "float",
        }
    }
}

/// Rewrite `?`, `?N` and `$N` placeholders (used by other engines and named tools) to the
/// `@PN` form SQL Server expects. Text inside string literals, quoted identifiers and comments
/// is left alone, and SQL that already uses `@P` placeholders (or has no parameters) is
/// returned unchanged.
pub fn rewrite_placeholders(sql: &str, param_count: usize) -> String {
    if param_count == 0 || sql.to_ascii_lowercase().contains("@p1") {
        return sql.to_string();
    }
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len() + 8);
    let mut i = 0;
    let mut next_positional = 1usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' | '"' | '[' => {
                let close = match c {
                    '[' => ']',
                    other => other,
                };
                out.push(c);
                i += 1;
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == close {
                        if i + 1 < chars.len() && chars[i + 1] == close {
                            out.push(chars[i + 1]);
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            '-' if chars.get(i + 1) == Some(&'-') => {
                while i < chars.len() && chars[i] != '\n' {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        out.push('/');
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            '?' | '$' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                let digits: String = chars[i + 1..j].iter().collect();
                let prev_is_ident = i > 0
                    && (chars[i - 1].is_alphanumeric()
                        || chars[i - 1] == '_'
                        || chars[i - 1] == '@');
                if prev_is_ident
                    || (c == '$' && digits.is_empty())
                    || (c == '$' && chars.get(j) == Some(&'.'))
                {
                    out.push(c);
                    i += 1;
                    continue;
                }
                let n = if digits.is_empty() {
                    let n = next_positional;
                    next_positional += 1;
                    n
                } else {
                    digits.parse::<usize>().unwrap_or(0)
                };
                out.push_str(&format!("@P{n}"));
                i = j;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn maps_scalar_values() {
        assert_eq!(
            column_data_to_json(&ColumnData::I32(Some(7))),
            Value::from(7)
        );
        assert_eq!(column_data_to_json(&ColumnData::I64(None)), Value::Null);
        assert_eq!(
            column_data_to_json(&ColumnData::Bit(Some(true))),
            Value::Bool(true)
        );
        assert_eq!(
            column_data_to_json(&ColumnData::F64(Some(1.5))),
            Value::from(1.5)
        );
        assert_eq!(
            column_data_to_json(&ColumnData::F64(Some(f64::NAN))),
            Value::Null
        );
        assert_eq!(
            column_data_to_json(&ColumnData::String(Some(Cow::Borrowed("héllo")))),
            Value::from("héllo")
        );
        assert_eq!(
            column_data_to_json(&ColumnData::Binary(Some(Cow::Borrowed(&[
                0xde, 0xad, 0x01
            ])))),
            Value::from("0xDEAD01")
        );
        let g = uuid::Uuid::parse_str("6f9619ff-8b86-d011-b42d-00c04fc964ff").unwrap();
        assert_eq!(
            column_data_to_json(&ColumnData::Guid(Some(g))),
            Value::from("6F9619FF-8B86-D011-B42D-00C04FC964FF")
        );
        let n = tiberius::numeric::Numeric::new_with_scale(12345, 2);
        assert_eq!(
            column_data_to_json(&ColumnData::Numeric(Some(n))),
            Value::from("123.45")
        );
    }

    #[test]
    fn maps_dates_to_iso_strings() {
        use tiberius::IntoSql as _;
        let dt = NaiveDate::from_ymd_opt(2025, 1, 3)
            .unwrap()
            .and_hms_milli_opt(10, 0, 1, 250)
            .unwrap();
        let data = dt.into_sql();
        assert_eq!(
            column_data_to_json(&data),
            Value::from("2025-01-03T10:00:01.250")
        );
        let d = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap().into_sql();
        assert_eq!(column_data_to_json(&d), Value::from("2024-02-29"));
        let off = DateTime::parse_from_rfc3339("2025-05-06T07:08:09+02:00")
            .unwrap()
            .into_sql();
        assert_eq!(
            column_data_to_json(&off),
            Value::from("2025-05-06T07:08:09+02:00")
        );
    }

    #[test]
    fn json_params_convert() {
        assert_eq!(SqlParam::from_json(&Value::from(5)), SqlParam::Int(5));
        assert_eq!(SqlParam::from_json(&Value::from(2.5)), SqlParam::Float(2.5));
        assert_eq!(
            SqlParam::from_json(&Value::from("x")),
            SqlParam::Text("x".into())
        );
        assert_eq!(SqlParam::from_json(&Value::Null), SqlParam::Null);
        assert_eq!(
            SqlParam::from_json(&serde_json::json!([1])),
            SqlParam::Text("[1]".into())
        );
    }

    #[test]
    fn placeholders_are_rewritten_outside_literals() {
        assert_eq!(
            rewrite_placeholders("SELECT * FROM t WHERE a = ? AND b = ? AND c = '?'", 2),
            "SELECT * FROM t WHERE a = @P1 AND b = @P2 AND c = '?'"
        );
        assert_eq!(rewrite_placeholders("SELECT ?2, ?1", 2), "SELECT @P2, @P1");
        assert_eq!(
            rewrite_placeholders("SELECT $1 -- $2\n, [a$1]", 1),
            "SELECT @P1 -- $2\n, [a$1]"
        );
        assert_eq!(
            rewrite_placeholders("SELECT x FROM t WHERE id = @P1", 1),
            "SELECT x FROM t WHERE id = @P1"
        );
        assert_eq!(rewrite_placeholders("SELECT ? ", 0), "SELECT ? ");
        assert_eq!(
            rewrite_placeholders("SELECT $5.00, ?", 1),
            "SELECT $5.00, @P1"
        );
    }
}
