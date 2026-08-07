//! CLI configuration for jirakeep.
//!
//! Precedence: CLI argument > environment variable > hardcoded default.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::builder::TypedValueParser as _;
use clap::{Parser, ValueEnum};

/// Transport for the MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Streamable HTTP transport (default).
    Http,
    /// Stdio transport.
    Stdio,
}

/// How jirakeep authenticates to Jira.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum AuthModeCli {
    /// Cloud Basic auth: email + API token (default).
    #[default]
    Basic,
    /// Bearer token: Data Center personal access token (email not required).
    Bearer,
}

impl From<AuthModeCli> for jirakeep_core::client::AuthMode {
    fn from(value: AuthModeCli) -> Self {
        match value {
            AuthModeCli::Basic => jirakeep_core::client::AuthMode::Basic,
            AuthModeCli::Bearer => jirakeep_core::client::AuthMode::Bearer,
        }
    }
}

/// MCP server for Atlassian Jira with operator-controlled security guards.
#[derive(Parser)]
#[command(name = "jirakeep", version, about)]
pub struct Cli {
    /// Base URL of the Jira site (e.g. 'https://example.atlassian.net' or a DC host).
    #[arg(long, env = "JIRA_SERVER")]
    pub jira_server: String,

    /// Authentication mode: 'basic' (Cloud email+token, default) or 'bearer' (DC PAT).
    #[arg(long, env = "JIRA_AUTH_MODE", value_enum, default_value = "basic")]
    pub auth_mode: AuthModeCli,

    /// Transport for the MCP server: 'http' (default) or 'stdio'.
    #[arg(long, env = "MCP_TRANSPORT", value_enum, default_value = "http")]
    pub transport: Transport,

    /// Host address for the MCP server to listen on (http transport only).
    #[arg(long, env = "MCP_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port for the MCP server to listen on (http transport only).
    #[arg(long, env = "MCP_PORT", default_value_t = 8000)]
    pub port: u16,

    /// HTTP header for clients to send the Jira API token.
    #[arg(long, env = "MCP_API_KEY_HEADER", default_value = "ApiKey")]
    pub api_key_header: String,

    /// HTTP header for clients to send the Atlassian account email (per-request
    /// Cloud Basic auth when --email is not set on the server).
    #[arg(long, env = "MCP_EMAIL_HEADER", default_value = "X-Atlassian-Email")]
    pub email_header: String,

    /// Jira Cloud API token.
    #[arg(long, env = "JIRA_API_TOKEN", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Path to a file holding the Jira Cloud API token.
    #[arg(
        long,
        env = "JIRA_API_TOKEN_FILE",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    pub api_key_file: Option<PathBuf>,

    /// Atlassian account email for Cloud Basic auth.
    #[arg(long, env = "JIRA_EMAIL")]
    pub email: Option<String>,

    /// Path to a file holding the Atlassian account email.
    #[arg(
        long,
        env = "JIRA_EMAIL_FILE",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    pub email_file: Option<PathBuf>,

    /// Disables all tools which modify Jira state.
    #[arg(long, env = "MCP_READ_ONLY")]
    pub read_only: bool,

    /// Path to the guard policy TOML file.
    #[arg(long, env = "JIRAKEEP_POLICY", value_hint = clap::ValueHint::FilePath)]
    pub policy: Option<PathBuf>,

    /// Path to the audit configuration TOML file.
    #[arg(long, env = "JIRAKEEP_AUDIT_CONFIG", value_hint = clap::ValueHint::FilePath)]
    pub audit_config: Option<PathBuf>,
}

impl std::fmt::Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cli")
            .field("jira_server", &self.jira_server)
            .field("auth_mode", &self.auth_mode)
            .field("transport", &self.transport)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("api_key_header", &self.api_key_header)
            .field("email_header", &self.email_header)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("api_key_file", &self.api_key_file)
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("email_file", &self.email_file)
            .field("read_only", &self.read_only)
            .field("policy", &self.policy)
            .field("audit_config", &self.audit_config)
            .finish()
    }
}

pub fn command() -> clap::Command {
    use clap::CommandFactory as _;
    Cli::command()
}

#[derive(Clone)]
pub enum TokenCustody {
    Server(String),
    PerRequest,
}

impl Cli {
    pub fn resolve_token_custody(&self) -> anyhow::Result<TokenCustody> {
        let startup_key = self.api_key.as_deref().filter(|k| !k.is_empty());
        let key_file = self
            .api_key_file
            .as_deref()
            .filter(|p| !p.as_os_str().is_empty());
        if startup_key.is_some() && key_file.is_some() {
            anyhow::bail!(
                "--api-key (JIRA_API_TOKEN) and --api-key-file (JIRA_API_TOKEN_FILE) \
                 are mutually exclusive; pass exactly one"
            );
        }
        if let Some(path) = key_file {
            let key = read_secret_file(path, "API token")?;
            match self.transport {
                Transport::Stdio => tracing::info!("API token: startup token (stdio)"),
                Transport::Http => tracing::info!(
                    "API token: server-held (from {}); the per-request '{}' header \
                     is not consulted",
                    path.display(),
                    self.api_key_header
                ),
            }
            return Ok(TokenCustody::Server(key));
        }
        match self.transport {
            Transport::Stdio => match startup_key {
                Some(key) => {
                    tracing::info!("API token: startup token (stdio)");
                    Ok(TokenCustody::Server(key.to_owned()))
                }
                None => anyhow::bail!(
                    "--transport stdio requires --api-key / JIRA_API_TOKEN or --api-key-file"
                ),
            },
            Transport::Http => {
                if startup_key.is_some() {
                    tracing::warn!(
                        "--api-key / JIRA_API_TOKEN is ignored with --transport http; \
                         clients send the token per-request via the '{}' header, or pass \
                         --api-key-file for server-held mode",
                        self.api_key_header
                    );
                }
                tracing::info!("API token: per-request (header '{}')", self.api_key_header);
                Ok(TokenCustody::PerRequest)
            }
        }
    }

    pub fn resolve_email(&self, token: &TokenCustody) -> anyhow::Result<Option<String>> {
        let startup = self.email.as_deref().filter(|e| !e.is_empty());
        let file = self
            .email_file
            .as_deref()
            .filter(|p| !p.as_os_str().is_empty());
        if startup.is_some() && file.is_some() {
            anyhow::bail!(
                "--email (JIRA_EMAIL) and --email-file (JIRA_EMAIL_FILE) \
                 are mutually exclusive; pass exactly one"
            );
        }
        let email = if let Some(path) = file {
            Some(read_secret_file(path, "email")?)
        } else {
            startup.map(str::to_owned)
        };

        // Bearer (DC PAT) never needs an email.
        if self.auth_mode == AuthModeCli::Bearer {
            return Ok(email);
        }

        match token {
            TokenCustody::Server(_) if email.is_none() => {
                anyhow::bail!(
                    "Cloud Basic auth requires --email / JIRA_EMAIL or --email-file \
                     when a server-held API token is configured (or use --auth-mode bearer)"
                );
            }
            _ => Ok(email),
        }
    }
}

fn read_secret_file(path: &Path, kind: &str) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {kind} file {}", path.display()))?;
    let value = raw.trim().to_owned();
    if value.is_empty() {
        anyhow::bail!("{kind} file {} is empty", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    "{} file {} is accessible by group or others (mode {:04o}); \
                     prefer chmod 0600",
                    kind,
                    path.display(),
                    meta.mode() & 0o777
                );
            }
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        use clap::Parser as _;
        Cli::try_parse_from(std::iter::once("jirakeep").chain(args.iter().copied()))
            .expect("cli parses")
    }

    #[test]
    fn http_default_is_per_request() {
        let cli = parse(&["--jira-server", "https://example.atlassian.net"]);
        let tok = cli.resolve_token_custody().unwrap();
        assert!(matches!(tok, TokenCustody::PerRequest));
        assert!(cli.resolve_email(&tok).unwrap().is_none());
    }

    #[test]
    fn stdio_requires_token() {
        let cli = parse(&[
            "--jira-server",
            "https://example.atlassian.net",
            "--transport",
            "stdio",
        ]);
        assert!(cli.resolve_token_custody().is_err());
    }

    #[test]
    fn stdio_token_requires_email() {
        let cli = parse(&[
            "--jira-server",
            "https://example.atlassian.net",
            "--transport",
            "stdio",
            "--api-key",
            "tok",
        ]);
        let tok = cli.resolve_token_custody().unwrap();
        assert!(cli.resolve_email(&tok).is_err());
    }

    #[test]
    fn stdio_with_token_and_email() {
        let cli = parse(&[
            "--jira-server",
            "https://example.atlassian.net",
            "--transport",
            "stdio",
            "--api-key",
            "tok",
            "--email",
            "user@example.com",
        ]);
        let tok = cli.resolve_token_custody().unwrap();
        assert!(matches!(tok, TokenCustody::Server(_)));
        assert_eq!(
            cli.resolve_email(&tok).unwrap().as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn bearer_stdio_token_without_email() {
        let cli = parse(&[
            "--jira-server",
            "https://jira.example.com",
            "--transport",
            "stdio",
            "--auth-mode",
            "bearer",
            "--api-key",
            "pat-token",
        ]);
        let tok = cli.resolve_token_custody().unwrap();
        assert!(matches!(tok, TokenCustody::Server(_)));
        assert!(cli.resolve_email(&tok).unwrap().is_none());
    }

    #[test]
    fn debug_redacts_secrets() {
        let cli = parse(&[
            "--jira-server",
            "https://example.atlassian.net",
            "--api-key",
            "super-secret",
            "--email",
            "user@example.com",
        ]);
        let s = format!("{cli:?}");
        assert!(!s.contains("super-secret"));
        assert!(!s.contains("user@example.com"));
        assert!(s.contains("<redacted>"));
    }
}
