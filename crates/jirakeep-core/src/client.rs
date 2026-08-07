//! Async Jira Cloud REST client (shell).
//!
//! Built once at startup; authentication is applied per request. The API
//! token must never appear in logs, error messages, or tool results
//! (invariant I12). Sanitize every [`reqwest::Error`] with
//! [`reqwest::Error::without_url`] before wrapping.
//!
//! The `User-Agent` is supplied by the caller and never derived here: a
//! value built from this crate's `CARGO_PKG_*` would name `jirakeep-core`
//! in the access log of every binary that embeds it.

use std::time::Duration;

use anyhow::{bail, Result};

/// Async client for the Jira Cloud REST API.
///
/// Cloud Basic auth is `email` + API token; both are passed per request so
/// the client itself never stores secrets.
#[derive(Debug, Clone)]
pub struct JiraClient {
    /// Site base URL with any trailing `/` trimmed
    /// (e.g. `https://example.atlassian.net`).
    base_url: String,
    http: reqwest::Client,
}

impl JiraClient {
    /// Create a client for the Jira Cloud site at `base_url`.
    ///
    /// `user_agent` must name the *program* making the request.
    ///
    /// # Errors
    ///
    /// Returns an error when `user_agent` is blank, is not a valid HTTP
    /// header value, or when the underlying HTTP client cannot be built.
    pub fn new(base_url: &str, user_agent: &str) -> Result<Self> {
        if user_agent.trim().is_empty() {
            bail!("jira client: user_agent must name the calling program, and was blank");
        }
        let base_url = base_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            bail!("jira client: base_url must not be empty");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(user_agent)
            .build()
            .map_err(sanitize)?;
        Ok(Self { base_url, http })
    }

    /// The site base URL (no trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// REST API v3 root: `{base}/rest/api/3`.
    pub fn api_v3_url(&self) -> String {
        format!("{}/rest/api/3", self.base_url)
    }

    /// Underlying HTTP client (for future authenticated methods).
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }
}

/// Strip URL (and thus any credential-bearing query) from a reqwest error (I12).
pub fn sanitize(err: reqwest::Error) -> anyhow::Error {
    anyhow::Error::new(err.without_url())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_trailing_slash() {
        let c = JiraClient::new("https://example.atlassian.net/", "jirakeep/0.0.0 (+test)")
            .expect("builds");
        assert_eq!(c.base_url(), "https://example.atlassian.net");
        assert_eq!(c.api_v3_url(), "https://example.atlassian.net/rest/api/3");
    }

    #[test]
    fn blank_user_agent_is_rejected() {
        assert!(JiraClient::new("https://example.atlassian.net", "  ").is_err());
    }
}
