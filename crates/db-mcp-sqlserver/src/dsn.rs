//! SQL Server DSN parsing.
//!
//! Shape: `sqlserver://user:pass@host[:port][/database][?instance=NAME&database=DB&encrypt=optional|true|false|strict&trustServerCertificate=true|false&connectTimeout=SECONDS&applicationName=NAME]`
//! (`mssql://` is accepted as an alias). User name and password are percent-decoded, so a
//! password such as `P@ss)w$rd` is written `P%40ss%29w%24rd`.
//!
//! Errors never contain the password or the raw DSN.

use std::fmt;

use db_mcp_core::{DbMcpError, DbMcpResult};
use percent_encoding::percent_decode_str;

/// Transport encryption requested by the DSN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlServerEncryption {
    /// Encrypt the login packet when the server supports TLS; the session may be plain
    /// (ODBC `Encrypt=Optional`). Default.
    Optional,
    /// Encrypt the whole session and fail when TLS is unavailable (`encrypt=true`).
    Required,
    /// TDS 8.0 strict mode: TLS before the prelogin (`encrypt=strict`).
    Strict,
    /// Never use TLS, not even for the login packet (`encrypt=disable`).
    Disabled,
}

impl SqlServerEncryption {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
            Self::Strict => "strict",
            Self::Disabled => "disabled",
        }
    }
}

/// Parsed, credential-bearing SQL Server connection settings.
#[derive(Clone, PartialEq, Eq)]
pub struct SqlServerDsn {
    pub host: String,
    /// Explicit TCP port. When set the client connects directly and `instance` is informational.
    pub port: Option<u16>,
    /// Named instance (`?instance=V2DEMO` or `host\V2DEMO`). Without a port it is resolved
    /// through the SQL Server Browser service (UDP 1434).
    pub instance: Option<String>,
    /// Database to use; `None` means the login's default database.
    pub database: Option<String>,
    pub user: String,
    password: String,
    pub encryption: SqlServerEncryption,
    pub trust_server_certificate: bool,
    pub connect_timeout_secs: u64,
    pub application_name: String,
}

impl fmt::Debug for SqlServerDsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlServerDsn")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("instance", &self.instance)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &"***")
            .field("encryption", &self.encryption)
            .field("trust_server_certificate", &self.trust_server_certificate)
            .finish()
    }
}

fn bad(msg: impl Into<String>) -> DbMcpError {
    DbMcpError::ConfigurationError(format!("Invalid SQL Server DSN: {}", msg.into()))
}

fn decode(raw: &str, what: &str) -> DbMcpResult<String> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| bad(format!("{what} is not valid percent-encoded UTF-8")))
}

fn parse_bool(key: &str, value: &str) -> DbMcpResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(bad(format!("parameter '{key}' must be true or false"))),
    }
}

impl SqlServerDsn {
    /// Parse a `sqlserver://` / `mssql://` DSN.
    pub fn parse(dsn: &str) -> DbMcpResult<Self> {
        let raw = dsn.trim();
        let rest = ["sqlserver://", "mssql://"]
            .iter()
            .find_map(|scheme| {
                raw.get(..scheme.len())
                    .filter(|p| p.eq_ignore_ascii_case(scheme))
                    .map(|_| &raw[scheme.len()..])
            })
            .ok_or_else(|| bad("expected a sqlserver:// (or mssql://) URL"))?;

        // The userinfo ends at the last '@' before the query string. A '?' inside an unencoded
        // password is tolerated because the query is only searched after the '@'.
        let first_q = rest.find('?').unwrap_or(rest.len());
        let at = rest[..first_q]
            .rfind('@')
            .or_else(|| rest.rfind('@'))
            .ok_or_else(|| bad("missing 'user:password@' (SQL logins only)"))?;
        let (userinfo, after_at) = (&rest[..at], &rest[at + 1..]);
        let (user_raw, pass_raw) = userinfo
            .split_once(':')
            .ok_or_else(|| bad("missing ':' between user and password"))?;
        let user = decode(user_raw, "user")?;
        let password = decode(pass_raw, "password")?;
        if user.trim().is_empty() {
            return Err(bad("user must not be empty"));
        }

        let (authority_path, query) = match after_at.split_once('?') {
            Some((a, q)) => (a, q),
            None => (after_at, ""),
        };
        let (authority, path) = match authority_path.split_once('/') {
            Some((a, p)) => (a, p),
            None => (authority_path, ""),
        };

        let (host_part, port) = if let Some(stripped) = authority.strip_prefix('[') {
            // IPv6 literal: [::1]:1433
            let end = stripped.find(']').ok_or_else(|| bad("unterminated IPv6 host"))?;
            let host = &stripped[..end];
            let tail = &stripped[end + 1..];
            let port = match tail.strip_prefix(':') {
                Some(p) => Some(p),
                None if tail.is_empty() => None,
                None => return Err(bad("unexpected text after IPv6 host")),
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            Some(p) => Some(
                p.parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| bad("port must be a number between 1 and 65535"))?,
            ),
            None => None,
        };
        let host_part = decode(&host_part, "host")?;
        let (host, mut instance) = match host_part.split_once('\\') {
            Some((h, i)) if !i.is_empty() => (h.to_string(), Some(i.to_string())),
            Some((h, _)) => (h.to_string(), None),
            None => (host_part, None),
        };
        if host.trim().is_empty() {
            return Err(bad("host must not be empty"));
        }

        let mut database = if path.trim().is_empty() {
            None
        } else {
            Some(decode(path.trim_end_matches('/'), "database")?)
        };
        let mut encryption = SqlServerEncryption::Optional;
        let mut trust_server_certificate = true;
        let mut connect_timeout_secs = 15;
        let mut application_name = "db-mcp".to_string();

        for pair in query.split('&').filter(|p| !p.trim().is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode(k, "parameter name")?;
            let value = decode(v, "parameter value")?;
            match key.trim().to_ascii_lowercase().replace(['_', '-'], "").as_str() {
                "instance" | "instancename" => {
                    instance = Some(value.trim().to_string()).filter(|s| !s.is_empty())
                }
                "database" | "initialcatalog" | "db" => {
                    database = Some(value.trim().to_string()).filter(|s| !s.is_empty())
                }
                "encrypt" | "encryption" => {
                    encryption = match value.trim().to_ascii_lowercase().as_str() {
                        "optional" | "false" | "no" | "off" | "login" => SqlServerEncryption::Optional,
                        "true" | "yes" | "on" | "mandatory" | "required" => SqlServerEncryption::Required,
                        "strict" => SqlServerEncryption::Strict,
                        "disable" | "disabled" | "none" | "notsupported" => SqlServerEncryption::Disabled,
                        _ => {
                            return Err(bad(
                                "parameter 'encrypt' must be optional, true, strict or disable",
                            ))
                        }
                    }
                }
                "trustservercertificate" | "trustcert" => {
                    trust_server_certificate = parse_bool("trustServerCertificate", &value)?
                }
                "connecttimeout" | "logintimeout" | "timeout" => {
                    connect_timeout_secs = value
                        .trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|s| (1..=600).contains(s))
                        .ok_or_else(|| bad("parameter 'connectTimeout' must be 1..600 seconds"))?
                }
                "applicationname" | "appname" => {
                    if !value.trim().is_empty() {
                        application_name = value.trim().to_string();
                    }
                }
                other => {
                    return Err(bad(format!(
                        "unknown parameter '{other}' (supported: instance, database, encrypt, trustServerCertificate, connectTimeout, applicationName)"
                    )))
                }
            }
        }

        Ok(Self {
            host,
            port,
            instance,
            database,
            user,
            password,
            encryption,
            trust_server_certificate,
            connect_timeout_secs,
            application_name,
        })
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// Credential-free description, e.g. `ro_user@10.0.0.5:33333 (instance V2DEMO, database <login default>)`.
    pub fn display_target(&self) -> String {
        let port = self
            .port
            .map(|p| format!(":{p}"))
            .unwrap_or_else(|| if self.instance.is_some() { String::new() } else { ":1433".to_string() });
        let mut out = format!("{}@{}{}", self.user, self.host, port);
        let mut extras = Vec::new();
        if let Some(i) = &self.instance {
            extras.push(format!("instance {i}"));
        }
        extras.push(format!(
            "database {}",
            self.database.as_deref().unwrap_or("<login default>")
        ));
        extras.push(format!("encrypt {}", self.encryption.as_str()));
        out.push_str(&format!(" ({})", extras.join(", ")));
        out
    }

    /// Replace every occurrence of the password (raw and percent-encoded) in `text` with `***`.
    pub fn scrub(&self, text: &str) -> String {
        scrub_secret(text, &self.password)
    }
}

/// Remove a secret (raw and percent-encoded) from free text such as driver error messages.
pub fn scrub_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    let mut out = text.replace(secret, "***");
    let encoded: String = percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC).to_string();
    if encoded != secret {
        out = out.replace(&encoded, "***");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_instance_with_port_and_encoded_password() {
        let d = SqlServerDsn::parse("sqlserver://ro_user:P%40ss%29w%24rd@10.0.0.5:33333?instance=V2DEMO").unwrap();
        assert_eq!(d.user, "ro_user");
        assert_eq!(d.password(), "P@ss)w$rd");
        assert_eq!(d.host, "10.0.0.5");
        assert_eq!(d.port, Some(33333));
        assert_eq!(d.instance.as_deref(), Some("V2DEMO"));
        assert_eq!(d.database, None);
        assert_eq!(d.encryption, SqlServerEncryption::Optional);
        assert!(d.trust_server_certificate);
        let shown = d.display_target();
        assert!(!shown.contains("P@ss") && shown.contains("instance V2DEMO") && shown.contains(":33333"), "{shown}");
        assert!(!format!("{d:?}").contains("P@ss"));
    }

    #[test]
    fn parses_database_encrypt_and_trust_options() {
        let d = SqlServerDsn::parse(
            "mssql://u:p@db.local/appdb?encrypt=true&trustServerCertificate=false&connectTimeout=5",
        )
        .unwrap();
        assert_eq!(d.database.as_deref(), Some("appdb"));
        assert_eq!(d.port, None);
        assert_eq!(d.encryption, SqlServerEncryption::Required);
        assert!(!d.trust_server_certificate);
        assert_eq!(d.connect_timeout_secs, 5);
        let d = SqlServerDsn::parse("sqlserver://u:p@h:1433?database=Sales&Encrypt=Strict").unwrap();
        assert_eq!(d.database.as_deref(), Some("Sales"));
        assert_eq!(d.encryption, SqlServerEncryption::Strict);
    }

    #[test]
    fn backslash_instance_ipv6_and_unencoded_at_in_password() {
        let d = SqlServerDsn::parse("sqlserver://u:p@srv%5CINST1").unwrap();
        assert_eq!(d.host, "srv");
        assert_eq!(d.instance.as_deref(), Some("INST1"));
        let d = SqlServerDsn::parse("sqlserver://u:p@[::1]:1444").unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, Some(1444));
        let d = SqlServerDsn::parse("sqlserver://u:a@b@h:1433").unwrap();
        assert_eq!(d.password(), "a@b");
        assert_eq!(d.host, "h");
    }

    #[test]
    fn errors_never_echo_the_password() {
        for dsn in [
            "postgres://u:S3cretPw@h",
            "sqlserver://u:S3cretPw@h:notaport",
            "sqlserver://u:S3cretPw@h?bogus=1",
            "sqlserver://u:S3cretPw@h?encrypt=maybe",
            "sqlserver://:S3cretPw@h",
            "sqlserver://S3cretPw@h",
        ] {
            let e = SqlServerDsn::parse(dsn).unwrap_err().to_string();
            assert!(!e.contains("S3cretPw"), "{dsn} -> {e}");
        }
    }

    #[test]
    fn scrub_removes_raw_and_encoded_secret() {
        let s = scrub_secret("login failed P@ss)w$rd / P%40ss%29w%24rd", "P@ss)w$rd");
        assert_eq!(s, "login failed *** / ***");
    }
}
