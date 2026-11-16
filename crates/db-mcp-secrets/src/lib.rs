//! Credential provider abstraction (`EnvSecretProvider`, `StaticSecretProvider`,
//! `CompositeSecretProvider`), `SecretString` with redacted `Debug`/`Display`/`Serialize`,
//! and DSN/password redaction utilities (`redact_sensitive_text`, `redact_dsn`).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use db_mcp_core::{DbMcpError, DbMcpResult};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Redaction placeholder constant.
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED]";

/// Wrapper around sensitive credential material that never prints or serializes its raw contents.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            inner: value.into(),
        }
    }

    /// Explicitly access the underlying secret string for driver connection setup.
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return a redacted DSN preview safe for logging or diagnostics.
    pub fn redacted_dsn_preview(&self) -> String {
        redact_sensitive_text(&self.inner)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(\"{REDACTED_PLACEHOLDER}\")")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_PLACEHOLDER)
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED_PLACEHOLDER)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

/// Read a `file:<path>` secret reference: the file contents with trailing newlines trimmed.
/// A missing or unreadable file is an error; contents are never included in messages.
pub fn read_secret_file(path: &str) -> DbMcpResult<SecretString> {
    if path.is_empty() {
        return Err(DbMcpError::ConfigurationError(
            "file: secret reference has an empty path".to_string(),
        ));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        DbMcpError::ConfigurationError(format!(
            "Secret file '{path}' could not be read: {}",
            e.kind()
        ))
    })?;
    Ok(SecretString::new(raw.trim_end_matches(['\r', '\n']).to_string()))
}

/// Trait implemented by credential providers.
pub trait SecretProvider: Send + Sync {
    /// Resolve a secret key (e.g. `DB_PASSWORD` or `env:DB_PASSWORD`) into a `SecretString`.
    fn get_secret(&self, key: &str) -> DbMcpResult<SecretString>;

    /// Resolve a connection string or DSN template that may reference `env:VAR` or `${VAR}`.
    fn resolve_dsn(&self, raw_dsn_or_ref: &str) -> DbMcpResult<SecretString> {
        let trimmed = raw_dsn_or_ref.trim();
        if let Some(env_key) = trimmed.strip_prefix("env:") {
            return self.get_secret(env_key.trim());
        }
        if let Some(secret_key) = trimmed.strip_prefix("secret:") {
            return self.get_secret(secret_key.trim());
        }
        if let Some(path) = trimmed.strip_prefix("file:") {
            return read_secret_file(path.trim());
        }

        // Interpolate `${VAR_NAME}` placeholders inside a DSN template.
        let placeholder_re = Regex::new(r"\$\{([A-Za-z0-9_.-]+)\}")
            .map_err(|e| DbMcpError::InternalError(e.to_string()))?;
        let mut resolved = String::with_capacity(trimmed.len());
        let mut last_end = 0usize;
        for caps in placeholder_re.captures_iter(trimmed) {
            let m = caps.get(0).unwrap();
            let key = &caps[1];
            resolved.push_str(&trimmed[last_end..m.start()]);
            let secret = self.get_secret(key)?;
            resolved.push_str(secret.expose_secret());
            last_end = m.end();
        }
        resolved.push_str(&trimmed[last_end..]);
        Ok(SecretString::new(resolved))
    }
}

/// Resolves secrets from process environment variables (with optional prefix).
#[derive(Debug, Clone, Default)]
pub struct EnvSecretProvider {
    prefix: Option<String>,
}

impl EnvSecretProvider {
    pub fn new() -> Self {
        Self { prefix: None }
    }

    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: Some(prefix.into()),
        }
    }

    fn candidate_keys(&self, key: &str) -> Vec<String> {
        let clean = key.strip_prefix("env:").unwrap_or(key).trim();
        let mut keys = Vec::new();
        if let Some(prefix) = &self.prefix {
            if !clean.starts_with(prefix) {
                keys.push(format!("{prefix}{clean}"));
            }
        }
        keys.push(clean.to_string());
        keys
    }
}

impl SecretProvider for EnvSecretProvider {
    fn get_secret(&self, key: &str) -> DbMcpResult<SecretString> {
        for candidate in self.candidate_keys(key) {
            if let Ok(val) = std::env::var(&candidate) {
                return Ok(SecretString::new(val));
            }
        }
        Err(DbMcpError::ConfigurationError(format!(
            "Environment secret '{}' is not set",
            key.strip_prefix("env:").unwrap_or(key)
        )))
    }
}

/// Resolves secrets from an in-memory map (useful for static config and deterministic tests).
#[derive(Debug, Clone, Default)]
pub struct StaticSecretProvider {
    secrets: BTreeMap<String, SecretString>,
}

impl StaticSecretProvider {
    pub fn new() -> Self {
        Self {
            secrets: BTreeMap::new(),
        }
    }

    pub fn from_map(map: BTreeMap<String, String>) -> Self {
        let secrets = map
            .into_iter()
            .map(|(k, v)| (k, SecretString::new(v)))
            .collect();
        Self { secrets }
    }

    pub fn insert(&mut self, key: impl Into<String>, secret: impl Into<SecretString>) {
        self.secrets.insert(key.into(), secret.into());
    }

    pub fn with_secret(mut self, key: impl Into<String>, secret: impl Into<SecretString>) -> Self {
        self.insert(key, secret);
        self
    }
}

impl SecretProvider for StaticSecretProvider {
    fn get_secret(&self, key: &str) -> DbMcpResult<SecretString> {
        let clean = key
            .strip_prefix("secret:")
            .or_else(|| key.strip_prefix("env:"))
            .unwrap_or(key)
            .trim();
        self.secrets.get(clean).cloned().ok_or_else(|| {
            DbMcpError::ConfigurationError(format!("Static secret '{clean}' not found"))
        })
    }
}

/// Chains multiple `SecretProvider`s in priority order.
#[derive(Clone, Default)]
pub struct CompositeSecretProvider {
    providers: Vec<Arc<dyn SecretProvider>>,
}

impl CompositeSecretProvider {
    pub fn new(providers: Vec<Arc<dyn SecretProvider>>) -> Self {
        Self { providers }
    }

    /// Default composite provider checking static overrides first, then environment variables.
    pub fn with_static_and_env(static_provider: StaticSecretProvider) -> Self {
        Self {
            providers: vec![
                Arc::new(static_provider),
                Arc::new(EnvSecretProvider::new()),
            ],
        }
    }

    pub fn push(&mut self, provider: Arc<dyn SecretProvider>) {
        self.providers.push(provider);
    }
}

impl SecretProvider for CompositeSecretProvider {
    fn get_secret(&self, key: &str) -> DbMcpResult<SecretString> {
        for provider in &self.providers {
            if let Ok(secret) = provider.get_secret(key) {
                return Ok(secret);
            }
        }
        Err(DbMcpError::ConfigurationError(format!(
            "Secret '{}' could not be resolved from any configured provider",
            key
        )))
    }
}

/// Redact credentials, DSN userinfo passwords, bearer tokens, and key-value password parameters
/// from arbitrary text so secrets never appear in tool responses, errors, or audit logs.
pub fn redact_sensitive_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    // 1. Redact URL/DSN userinfo passwords: scheme://user:password@host (including SQL-tokenized spacing)
    let url_userinfo_re =
        Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*\s*:\s*/\s*/\s*[^/\s:@]+)\s*:\s*([^@\s/'\x22]+)\s*@").unwrap();
    let step1 = url_userinfo_re
        .replace_all(input, format!("$1:{REDACTED_PLACEHOLDER}@"))
        .into_owned();

    // 2. Redact query string or key=value credentials:
    //    password=..., pwd=..., passwd=..., secret=..., token=..., api_key=..., apikey=..., access_token=...
    let kv_re = Regex::new(
        r#"(?i)\b(password|passwd|pwd|secret|client_secret|access_token|refresh_token|api_key|apikey|auth_token)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s;&"',)]+)"#,
    )
    .unwrap();
    let step2 = kv_re
        .replace_all(&step1, format!("$1$2{REDACTED_PLACEHOLDER}"))
        .into_owned();

    // 3. Redact Authorization: Bearer <token>
    let bearer_re = Regex::new(r"(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{6,}").unwrap();
    bearer_re
        .replace_all(&step2, format!("$1 {REDACTED_PLACEHOLDER}"))
        .into_owned()
}

/// Alias for redacting a connection DSN string.
pub fn redact_dsn(dsn: &str) -> String {
    redact_sensitive_text(dsn)
}

/// Redact both generic sensitive patterns and an explicit list of known secret values.
pub fn redact_known_secrets(input: &str, known_secrets: &[&str]) -> String {
    let mut output = redact_sensitive_text(input);
    for secret in known_secrets {
        let trimmed = secret.trim();
        if !trimmed.is_empty() && trimmed != REDACTED_PLACEHOLDER {
            output = output.replace(trimmed, REDACTED_PLACEHOLDER);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_string_never_leaks_in_debug_display_or_serde() {
        let s = SecretString::new("s3cr3t-p@ssw0rd!");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(format!("{s:?}"), "SecretString(\"[REDACTED]\")");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"[REDACTED]\"");
        assert!(!json.contains("s3cr3t"));
        assert_eq!(s.expose_secret(), "s3cr3t-p@ssw0rd!");
    }

    #[test]
    fn test_redact_sensitive_text_covers_urls_kv_and_bearer() {
        let raw = "Failed to connect to postgres://admin:my_super_secret@db.internal:5432/prod?sslmode=require with password=topsecret and Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let redacted = redact_sensitive_text(raw);
        assert!(!redacted.contains("my_super_secret"));
        assert!(!redacted.contains("topsecret"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(redacted.contains("postgres://admin:[REDACTED]@db.internal:5432/prod"));
        assert!(redacted.contains("password=[REDACTED]"));
        assert!(redacted.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn test_composite_secret_provider_and_dsn_interpolation() {
        let static_provider = StaticSecretProvider::new()
            .with_secret("PG_PASS", "hunter2_pg_secret")
            .with_secret("FULL_DSN", "mysql://root:mysql_secret@127.0.0.1:3306/app");
        let composite = CompositeSecretProvider::with_static_and_env(static_provider);

        let dsn = composite
            .resolve_dsn("postgres://app_user:${PG_PASS}@localhost:5432/app_db")
            .unwrap();
        assert_eq!(
            dsn.expose_secret(),
            "postgres://app_user:hunter2_pg_secret@localhost:5432/app_db"
        );
        assert_eq!(
            dsn.redacted_dsn_preview(),
            "postgres://app_user:[REDACTED]@localhost:5432/app_db"
        );

        let direct = composite.resolve_dsn("secret:FULL_DSN").unwrap();
        assert_eq!(
            direct.redacted_dsn_preview(),
            "mysql://root:[REDACTED]@127.0.0.1:3306/app"
        );
    }

    #[test]
    fn file_secret_ref_reads_and_trims_newline() {
        let path = std::env::temp_dir().join(format!("db_mcp_secret_{}", std::process::id()));
        std::fs::write(&path, "s3cret-value\r\n").unwrap();
        let composite = CompositeSecretProvider::with_static_and_env(StaticSecretProvider::new());
        let got = composite
            .resolve_dsn(&format!("file:{}", path.display()))
            .unwrap();
        assert_eq!(got.expose_secret(), "s3cret-value");
        let _ = std::fs::remove_file(&path);
        let err = composite
            .resolve_dsn(&format!("file:{}", path.display()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not be read"), "{err}");
    }
}
