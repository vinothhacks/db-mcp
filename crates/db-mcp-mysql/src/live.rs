//! Live MySQL 8 backend: DSN parsing and fail-closed connectivity.
//!
//! A live connection never falls back to the embedded simulation: an unreachable server is
//! reported as `CONNECTION_UNAVAILABLE` with a `next_action`, and the DSN password never appears
//! in any message.

use std::time::Duration;

use db_mcp_core::{DbMcpError, DbMcpResult};
use db_mcp_secrets::SecretString;
use percent_encoding::percent_decode_str;
use tokio::net::TcpStream;
use url::Url;

/// Default TCP connect timeout for live MySQL connections (DSN `connect_timeout` overrides it).
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3_000;

/// Error code returned when a live server cannot be reached or refuses the login.
pub const CODE_CONNECTION_UNAVAILABLE: &str = "CONNECTION_UNAVAILABLE";

/// Parsed `mysql://user:pass@host[:port][/database][?connect_timeout=ms]` DSN.
#[derive(Clone)]
pub struct MySqlDsn {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: SecretString,
    pub database: Option<String>,
    pub connect_timeout_ms: u64,
}

impl std::fmt::Debug for MySqlDsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlDsn")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"***")
            .field("database", &self.database)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .finish()
    }
}

impl MySqlDsn {
    /// `host:port` for messages (never includes credentials).
    pub fn address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn decode(component: &str, what: &str, connection_id: &str) -> DbMcpResult<String> {
    percent_decode_str(component)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| {
            DbMcpError::ConfigurationError(format!(
                "Connection '{connection_id}': the MySQL DSN {what} is not valid percent-encoded UTF-8"
            ))
        })
}

/// Parse a live MySQL DSN. User and password are percent-decoded (`%40` -> `@`, `%29` -> `)`,
/// `%24` -> `$`). Errors name the problem, never the password.
pub fn parse_mysql_dsn(connection_id: &str, dsn: &str) -> DbMcpResult<MySqlDsn> {
    let invalid = |why: &str| {
        DbMcpError::ConfigurationError(format!(
            "Connection '{connection_id}': invalid MySQL DSN ({why}); expected mysql://user:password@host[:port][/database]"
        ))
    };
    let url = Url::parse(dsn.trim()).map_err(|_| invalid("not a URL"))?;
    if !matches!(url.scheme(), "mysql" | "mariadb") {
        return Err(invalid("scheme must be mysql:// or mariadb://"));
    }
    let host = url
        .host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| invalid("missing host"))?;
    let port = url.port().unwrap_or(3306);
    let user = decode(url.username(), "user", connection_id)?;
    if user.is_empty() {
        return Err(invalid("missing user"));
    }
    let password = match url.password() {
        Some(p) => decode(p, "password", connection_id)?,
        None => String::new(),
    };
    let database = {
        let raw = url.path().trim_start_matches('/');
        if raw.is_empty() {
            None
        } else {
            Some(decode(raw, "database", connection_id)?)
        }
    };
    let mut connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "connect_timeout" | "connect_timeout_ms" => {
                connect_timeout_ms = value
                    .parse::<u64>()
                    .ok()
                    .filter(|v| *v > 0)
                    .ok_or_else(|| invalid("connect_timeout must be a positive number of milliseconds"))?;
            }
            "ssl-mode" | "ssl_mode" | "sslmode" => {
                if !value.eq_ignore_ascii_case("disabled") {
                    return Err(invalid(
                        "TLS is not supported by this build (plain TCP only); remove ssl-mode or set ssl-mode=disabled",
                    ));
                }
            }
            other => {
                return Err(invalid(&format!("unsupported DSN parameter '{other}'")));
            }
        }
    }
    Ok(MySqlDsn {
        host,
        port,
        user,
        password: SecretString::new(password),
        database,
        connect_timeout_ms,
    })
}

/// Build the fail-closed `CONNECTION_UNAVAILABLE` error for a live connection.
pub fn connection_unavailable(connection_id: &str, dsn: &MySqlDsn, reason: &str) -> DbMcpError {
    DbMcpError::PolicyDenied {
        code: CODE_CONNECTION_UNAVAILABLE.to_string(),
        message: format!(
            "Live MySQL connection '{connection_id}' ({}) is unavailable: {reason}. No simulated data is returned for a live backend.",
            dsn.address()
        ),
        next_action: Some(format!(
            "Check the server address, port, network and credentials, then run `db-mcp check-connection --config <file> --connection {connection_id}`"
        )),
    }
}

/// Live backend handle (phase 0: fail-closed reachability only).
#[derive(Debug)]
pub struct LiveMySql {
    pub connection_id: String,
    pub dsn: MySqlDsn,
}

impl LiveMySql {
    pub fn new(connection_id: &str, dsn: &str) -> DbMcpResult<Self> {
        Ok(Self {
            connection_id: connection_id.to_string(),
            dsn: parse_mysql_dsn(connection_id, dsn)?,
        })
    }

    /// TCP reachability within the connect timeout.
    pub async fn probe(&self) -> DbMcpResult<()> {
        let addr = (self.dsn.host.as_str(), self.dsn.port);
        match tokio::time::timeout(
            Duration::from_millis(self.dsn.connect_timeout_ms),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(connection_unavailable(
                &self.connection_id,
                &self.dsn,
                &db_mcp_secrets::redact_sensitive_text(&e.to_string()),
            )),
            Err(_) => Err(connection_unavailable(
                &self.connection_id,
                &self.dsn,
                &format!("TCP connect timed out after {} ms", self.dsn.connect_timeout_ms),
            )),
        }
    }

    /// `check-connection` report (phase 0: reachability only).
    pub async fn check(&self) -> serde_json::Value {
        let probe = self.probe().await;
        let mut warnings = Vec::new();
        if let Err(e) = &probe {
            warnings.push(e.to_string());
        } else {
            warnings.push("server reachable; live statement execution is not available in this build".to_string());
        }
        serde_json::json!({
            "connection": self.connection_id,
            "engine": "mysql",
            "backend": "live",
            "server_version": null,
            "can_connect": probe.is_ok(),
            "select_1": false,
            "object_count": null,
            "permissions": [],
            "can_write": null,
            "warnings": warnings,
        })
    }

    /// Reachable but the wire client is not part of this build yet: fail closed.
    pub async fn not_yet_available(&self) -> DbMcpError {
        if let Err(e) = self.probe().await {
            return e;
        }
        DbMcpError::UnsupportedCapability(format!(
            "Live MySQL connection '{}' is reachable but live statement execution is not available in this build",
            self.connection_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_percent_decoding_and_defaults() {
        let d = parse_mysql_dsn("m", "mysql://ro%40corp:p%40ss%29w%24rd@10.0.0.5/appdb").unwrap();
        assert_eq!(d.user, "ro@corp");
        assert_eq!(d.password.expose_secret(), "p@ss)w$rd");
        assert_eq!(d.host, "10.0.0.5");
        assert_eq!(d.port, 3306);
        assert_eq!(d.database.as_deref(), Some("appdb"));
        assert_eq!(d.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
        assert!(!format!("{d:?}").contains("p@ss"));

        let d = parse_mysql_dsn("m", "mariadb://u:p@db.local:3307?connect_timeout=500").unwrap();
        assert_eq!((d.port, d.database.clone(), d.connect_timeout_ms), (3307, None, 500));
        assert_eq!(d.address(), "db.local:3307");
    }

    #[test]
    fn dsn_errors_never_echo_password() {
        for bad in [
            "postgres://u:topsecret@h/db",
            "mysql://:topsecret@h/db",
            "mysql://u:topsecret@h/db?ssl-mode=REQUIRED",
            "mysql://u:topsecret@h/db?bogus=1",
            "mysql://u:topsecret@h/db?connect_timeout=0",
        ] {
            let e = parse_mysql_dsn("m", bad).unwrap_err().to_string();
            assert!(!e.contains("topsecret"), "{e}");
            assert!(e.contains("'m'"), "{e}");
        }
        parse_mysql_dsn("m", "mysql://u:p@h/db?ssl-mode=DISABLED").unwrap();
    }

    #[tokio::test]
    async fn unreachable_server_fails_closed_with_next_action() {
        let live = LiveMySql::new("m", "mysql://u:topsecret@127.0.0.1:1/db?connect_timeout=500").unwrap();
        let e = live.probe().await.unwrap_err();
        assert_eq!(e.code(), CODE_CONNECTION_UNAVAILABLE);
        assert!(e.next_action().unwrap().contains("check-connection"));
        assert!(!e.to_string().contains("topsecret"));
    }
}
