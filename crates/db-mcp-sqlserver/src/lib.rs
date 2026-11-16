//! Microsoft SQL Server adapter (live TDS via tiberius).

pub mod dsn;
pub mod values;

pub use dsn::{SqlServerDsn, SqlServerEncryption};
