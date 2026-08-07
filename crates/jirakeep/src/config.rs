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
    /// Streamable HTTP transport (default). Clients send the Jira API token
    /// per-request via the API key header, unless `--api-key-file` selects
    /// server-held token mode (then the header is not consulted at all).
    Http,
    /// Stdio transport. Token and email come from flags/env/files at startup.
    Stdio,
}

/// MCP server for Atlassian Jira Cloud with operator-controlled security guards.
// Keep this doc comment to ONE paragraph so clap does not resurrect it as
// long_about (see bugwarden: multi-paragraph docs once leaked into --help).
#[derive(Parser)]
#[command(name = "jirakeep", version, about)]
pub struct Cli {
    /// Base URL of the Jira Cloud site (e.g. 'https://example.atlassian.net').
    /// Environment variable JIRA_SERVER is used if the argument is not provided.
    #[arg(long, env = "JIRA_SERVER")]
    pub jira_server: String,

    /// Transport for the MCP server: 'http' (default) or 'stdio'. Environment
    /// variable MCP_TRANSPORT can also be used.
    #[arg(long, env = "MCP_TRANSPORT", value_enum, default_value = "http")]
    pub transport: Transport,

    /// Host address for the MCP server to listen on (http transport only).
    /// Defaults to 127.0.0.1 or the MCP_HOST environment variable.
    #[arg(long, env = "MCP_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port for the MCP server to listen on (http transport only). Defaults
    /// to 8000 or the MCP_PORT environment variable.
    #[arg(long, env = "MCP_PORT", default_value_t = 8000)]
    pub port: u16,

    /// HTTP header for clients to send the Jira API token. Defaults to
    /// 'ApiKey' or the MCP_API_KEY_HEADER environment variable. Not consulted
    /// in server-held token mode (--api-key-file over http).
    #[arg(long, env = "MCP_API_KEY_HEADER", default_value = "ApiKey")]
    pub api_key_header: String,

    /// Jira Cloud API token. Required for --transport stdio unless
    /// --api-key-file provides it. Environment variable JIRA_API_TOKEN can
    /// also be used. Ignored for --transport http unless --api-key-file is
    /// set (clients send the token per-request; use --api-key-file for a
    /// server-held token).
    #[arg(long, env = "JIRA_API_TOKEN", hide_env_values = true)]
    pub api_key: Option<String>,

    /// Path to a file holding the Jira Cloud API token. Mutually exclusive
    /// with --api-key. Over http this selects server-held token mode.
    #[arg(
        long,
        env = "JIRA_API_TOKEN_FILE",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    pub api_key_file: Option<PathBuf>,

    /// Atlassian account email for Cloud Basic auth. Environment variable
    /// JIRA_EMAIL can also be used. Required whenever a token is used
    /// (stdio, or http server-held mode).
    #[arg(long, env = "JIRA_EMAIL")]
    pub email: Option<String>,

    /// Path to a file holding the Atlassian account email. Mutually exclusive
    /// with --email.
    #[arg(
        long,
        env = "JIRA_EMAIL_FILE",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from)
    )]
    pub email_file: Option<PathBuf>,

    /// Disables all tools which modify Jira state. Environment variable
    /// MCP_READ_ONLY=true can also be used. Can only tighten the guard
    /// policy, never loosen it.
    #[arg(long, env = "MCP_READ_ONLY")]
    pub read_only: bool,

    /// Path to the guard policy TOML file. Environment variable
    /// JIRAKEEP_POLICY can also be used. Without it an allow-all default
    /// policy is used (restricted comments still off).
    #[arg(long, env = "JIRAKEEP_POLICY", value_hint = clap::ValueHint::FilePath)]
    pub policy: Option<PathBuf>,
}

/// Manual impl so tokens and emails never reach a log through `{:?}` (I12).
impl std::fmt::Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cli")
            .field("jira_server", &self.jira_server)
            .field("transport", &self.transport)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("api_key_header", &self.api_key_header)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("api_key_file", &self.api_key_file)
            .field("email", &self.email.as_ref().map(|_| "<redacted>"))
            .field("email_file", &self.email_file)
            .field("read_only", &self.read_only)
            .field("policy", &self.policy)
            .finish()
    }
}

/// The clap command for the `jirakeep` binary — the single definition the
/// server parses and `jirakeep-gen` renders into the man page and shell
/// completions.
pub fn command() -> clap::Command {
    use clap::CommandFactory as _;
    Cli::command()
}

/// Who holds the Jira API token, resolved exactly once at startup.
///
/// No Debug impl: the `Server` variant carries the token itself (I12).
#[derive(Clone)]
pub enum TokenCustody {
    /// Server owns one token resolved at startup.
    Server(String),
    /// http per-request mode: each request must carry the token header.
    PerRequest,
}

impl Cli {
    /// Resolve who holds the Jira API token.
    ///
    /// # Errors
    ///
    /// Mutually exclusive flag combinations, unreadable files, empty token
    /// files, or stdio without a token source.
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

    /// Resolve the Atlassian account email for Cloud Basic auth.
    ///
    /// Required whenever the server holds a token (stdio, or http
    /// server-held). In pure per-request http mode the skeleton still
    /// accepts a startup email (typical fleet setup: one service account
    /// email + per-request tokens is unusual; usually both are server-held
    /// or both follow the same custody). For per-request without email the
    /// skeleton tools do not call Jira yet, so email may be absent until
    /// the client layer needs it.
    ///
    /// # Errors
    ///
    /// Mutually exclusive flag combinations, unreadable files, or stdio /
    /// server-held mode without an email.
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

        match token {
            TokenCustody::Server(_) if email.is_none() => {
                anyhow::bail!(
                    "Cloud Basic auth requires --email / JIRA_EMAIL or --email-file \
                     when a server-held API token is configured"
                );
            }
            _ => Ok(email),
        }
    }
}

/// Read a secret file: trim whitespace/newlines; empty is an error. Errors
/// name the path, never the contents (I12).
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
