//! Async Jira REST client (Cloud and Data Center).
//!
//! Authentication is applied per request so the client never stores secrets.
//! Modes:
//! - **Basic** — Cloud email + API token
//! - **Bearer** — Data Center personal access token (or Cloud OAuth bearer)
//!
//! Errors are sanitized so credentials cannot leak (I12). The `User-Agent`
//! is supplied by the caller (the binary), never derived from this crate's
//! package name.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

/// Fields fetched for guard classification of an issue.
pub const CLASSIFY_FIELDS: &str =
    "summary,project,status,priority,issuetype,labels,components,security,created,reporter,assignee,issuelinks,parent,subtasks";

/// How credentials are attached to each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// `Authorization: Basic base64(email:token)` — Jira Cloud API tokens.
    #[default]
    Basic,
    /// `Authorization: Bearer <token>` — Jira Data Center PATs (and similar).
    Bearer,
}

/// Credentials for one Jira request.
///
/// For [`AuthMode::Basic`], `email` must be non-empty. For
/// [`AuthMode::Bearer`], `email` is ignored (may be empty).
#[derive(Clone)]
pub struct Credentials {
    pub email: String,
    pub token: String,
}

// No Debug: never print token/email.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("email", &"<redacted>")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Async client for the Jira REST API v3.
#[derive(Debug, Clone)]
pub struct JiraClient {
    base_url: String,
    api_url: String,
    http: reqwest::Client,
    auth_mode: AuthMode,
}

impl JiraClient {
    /// Create a client for the Jira site at `base_url` (Cloud Basic auth).
    pub fn new(base_url: &str, user_agent: &str) -> Result<Self> {
        Self::with_auth_mode(base_url, user_agent, AuthMode::Basic)
    }

    /// Create a client with an explicit auth mode (Cloud Basic or DC Bearer).
    pub fn with_auth_mode(base_url: &str, user_agent: &str, auth_mode: AuthMode) -> Result<Self> {
        if user_agent.trim().is_empty() {
            bail!("jira client: user_agent must name the calling program, and was blank");
        }
        let base_url = base_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            bail!("jira client: base_url must not be empty");
        }
        let api_url = format!("{base_url}/rest/api/3");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(user_agent)
            .build()
            .map_err(sanitize)?;
        Ok(Self {
            base_url,
            api_url,
            http,
            auth_mode,
        })
    }

    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn api_v3_url(&self) -> &str {
        &self.api_url
    }

    /// GET `/rest/api/3/myself` — returns the account object (`accountId`, …).
    pub async fn myself(&self, creds: &Credentials) -> Result<Value> {
        self.get_json(creds, "/myself", &[]).await
    }

    /// Account id of the credential holder, or an error if unreadable.
    pub async fn account_id(&self, creds: &Credentials) -> Result<String> {
        let v = self.myself(creds).await?;
        v.get("accountId")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("jira /myself response carries no usable accountId"))
    }

    /// GET `/rest/api/3/serverInfo`.
    pub async fn server_info(&self, creds: &Credentials) -> Result<Value> {
        let mut info = self.get_json(creds, "/serverInfo", &[]).await?;
        if let Some(obj) = info.as_object_mut() {
            obj.insert("url".into(), json!(self.base_url));
        }
        Ok(info)
    }

    /// GET `/rest/api/3/issue/{keyOrId}` with optional fields projection.
    pub async fn get_issue(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        fields: Option<&str>,
    ) -> Result<Value> {
        let path = format!("/issue/{}", urlencoding_path(key_or_id));
        let mut query = Vec::new();
        if let Some(f) = fields {
            query.push(("fields", f.to_string()));
        }
        self.get_json(creds, &path, &query).await
    }

    /// GET issue changelog.
    pub async fn issue_changelog(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<Value> {
        let path = format!("/issue/{}/changelog", urlencoding_path(key_or_id));
        self.get_json(
            creds,
            &path,
            &[
                ("startAt", start_at.to_string()),
                ("maxResults", max_results.to_string()),
            ],
        )
        .await
    }

    /// GET issue comments.
    pub async fn issue_comments(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        start_at: u32,
        max_results: u32,
    ) -> Result<Value> {
        let path = format!("/issue/{}/comment", urlencoding_path(key_or_id));
        self.get_json(
            creds,
            &path,
            &[
                ("startAt", start_at.to_string()),
                ("maxResults", max_results.to_string()),
                ("orderBy", "created".into()),
            ],
        )
        .await
    }

    /// POST a comment. Body is Atlassian Document Format or plain text
    /// converted to a simple ADF doc.
    pub async fn add_comment(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        body_text: &str,
        visibility: Option<Value>,
    ) -> Result<Value> {
        let path = format!("/issue/{}/comment", urlencoding_path(key_or_id));
        let mut payload = json!({
            "body": plain_to_adf(body_text),
        });
        if let Some(vis) = visibility {
            payload["visibility"] = vis;
        }
        self.send_json(reqwest::Method::POST, creds, &path, &payload)
            .await
    }

    /// JQL search via POST `/rest/api/3/search/jql` (token pagination).
    ///
    /// Falls back to legacy `/rest/api/3/search` with `startAt` if the jql
    /// endpoint is unavailable (404).
    pub async fn search(
        &self,
        creds: &Credentials,
        jql: &str,
        fields: &[&str],
        max_results: u32,
        next_page_token: Option<&str>,
        start_at: Option<u32>,
    ) -> Result<Value> {
        let field_list: Vec<String> = fields.iter().map(|s| (*s).to_string()).collect();
        // Prefer modern token-paginated endpoint.
        let mut payload = json!({
            "jql": jql,
            "maxResults": max_results,
            "fields": field_list,
        });
        if let Some(tok) = next_page_token {
            payload["nextPageToken"] = json!(tok);
        }
        match self
            .send_json(reqwest::Method::POST, creds, "/search/jql", &payload)
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("404") || msg.contains("HTTP 404") {
                    // Legacy offset pagination.
                    let mut legacy = json!({
                        "jql": jql,
                        "maxResults": max_results,
                        "fields": fields,
                        "startAt": start_at.unwrap_or(0),
                    });
                    if let Some(obj) = legacy.as_object_mut() {
                        obj.insert("fields".into(), json!(fields.to_vec()));
                    }
                    self.send_json(reqwest::Method::POST, creds, "/search", &legacy)
                        .await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// List attachment metadata from an issue (fields.attachment).
    pub async fn list_attachments(
        &self,
        creds: &Credentials,
        key_or_id: &str,
    ) -> Result<Vec<Value>> {
        let issue = self.get_issue(creds, key_or_id, Some("attachment")).await?;
        Ok(issue
            .get("fields")
            .and_then(|f| f.get("attachment"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Download attachment content by content URL (absolute or relative).
    pub async fn download_attachment_bytes(
        &self,
        creds: &Credentials,
        content_url: &str,
    ) -> Result<Vec<u8>> {
        let url = if content_url.starts_with("http://") || content_url.starts_with("https://") {
            content_url.to_string()
        } else {
            format!(
                "{}{}",
                self.base_url,
                if content_url.starts_with('/') {
                    content_url.to_string()
                } else {
                    format!("/{content_url}")
                }
            )
        };
        let rb = self.apply_auth(self.http.get(&url), creds);
        let resp = rb.send().await.map_err(sanitize)?;
        let status = resp.status();
        if !status.is_success() {
            bail!("jira attachment download error (HTTP {})", status.as_u16());
        }
        resp.bytes().await.map(|b| b.to_vec()).map_err(sanitize)
    }

    /// GET transitions available for an issue.
    pub async fn get_transitions(&self, creds: &Credentials, key_or_id: &str) -> Result<Value> {
        let path = format!("/issue/{}/transitions", urlencoding_path(key_or_id));
        self.get_json(creds, &path, &[]).await
    }

    /// POST a transition.
    pub async fn transition_issue(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        transition_id: &str,
        fields: Option<Value>,
        comment: Option<&str>,
    ) -> Result<()> {
        let path = format!("/issue/{}/transitions", urlencoding_path(key_or_id));
        let mut payload = json!({
            "transition": {"id": transition_id},
        });
        if let Some(f) = fields {
            payload["fields"] = f;
        }
        if let Some(c) = comment {
            payload["update"] = json!({
                "comment": [{"add": {"body": plain_to_adf(c)}}]
            });
        }
        self.send_json_empty_ok(reqwest::Method::POST, creds, &path, &payload)
            .await
    }

    /// PUT issue fields.
    pub async fn update_issue(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        fields: Value,
    ) -> Result<()> {
        let path = format!("/issue/{}", urlencoding_path(key_or_id));
        let payload = json!({ "fields": fields });
        self.send_json_empty_ok(reqwest::Method::PUT, creds, &path, &payload)
            .await
    }

    /// POST create issue. Returns the created issue envelope (`id`, `key`).
    pub async fn create_issue(&self, creds: &Credentials, fields: Value) -> Result<Value> {
        let payload = json!({ "fields": fields });
        self.send_json(reqwest::Method::POST, creds, "/issue", &payload)
            .await
    }

    /// Link two issues.
    pub async fn create_issue_link(
        &self,
        creds: &Credentials,
        link_type: &str,
        inward_key: &str,
        outward_key: &str,
    ) -> Result<()> {
        let payload = json!({
            "type": {"name": link_type},
            "inwardIssue": {"key": inward_key},
            "outwardIssue": {"key": outward_key},
        });
        self.send_json_empty_ok(reqwest::Method::POST, creds, "/issueLink", &payload)
            .await
    }

    /// Add watcher by account id.
    pub async fn add_watcher(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        account_id: &str,
    ) -> Result<()> {
        let path = format!("/issue/{}/watchers", urlencoding_path(key_or_id));
        // Body is a JSON string of the account id.
        let rb = self.apply_auth(
            self.http
                .post(format!("{}{}", self.api_url, path))
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(format!("\"{account_id}\"")),
            creds,
        );
        let (status, body) = self.send(rb, "POST", &path).await?;
        if status.as_u16() == 204 || status.is_success() {
            return Ok(());
        }
        parse_response(status, &body).map(|_| ())
    }

    /// POST attachment (multipart).
    pub async fn add_attachment(
        &self,
        creds: &Credentials,
        key_or_id: &str,
        filename: &str,
        data: Vec<u8>,
    ) -> Result<Value> {
        let path = format!("/issue/{}/attachments", urlencoding_path(key_or_id));
        let part = reqwest::multipart::Part::bytes(data)
            .file_name(filename.to_owned())
            .mime_str("application/octet-stream")
            .map_err(|e| anyhow!("attachment part: {e}"))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let rb = self.apply_auth(
            self.http
                .post(format!("{}{}", self.api_url, path))
                .header(reqwest::header::ACCEPT, "application/json")
                .header("X-Atlassian-Token", "no-check")
                .multipart(form),
            creds,
        );
        let (status, body) = self.send(rb, "POST", &path).await?;
        parse_response(status, &body)
    }

    fn apply_auth(
        &self,
        rb: reqwest::RequestBuilder,
        creds: &Credentials,
    ) -> reqwest::RequestBuilder {
        match self.auth_mode {
            AuthMode::Basic => rb.basic_auth(&creds.email, Some(&creds.token)),
            AuthMode::Bearer => rb.header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", creds.token),
            ),
        }
    }

    async fn send(
        &self,
        rb: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> Result<(reqwest::StatusCode, String)> {
        tracing::debug!(method, path, "jira request");
        let resp = rb.send().await.map_err(sanitize)?;
        let status = resp.status();
        let body = resp.text().await.map_err(sanitize)?;
        Ok((status, body))
    }

    async fn get_json(
        &self,
        creds: &Credentials,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value> {
        let mut rb = self
            .http
            .get(format!("{}{}", self.api_url, path))
            .header(reqwest::header::ACCEPT, "application/json");
        if !query.is_empty() {
            rb = rb.query(query);
        }
        let rb = self.apply_auth(rb, creds);
        let (status, body) = self.send(rb, "GET", path).await?;
        parse_response(status, &body)
    }

    async fn send_json(
        &self,
        method: reqwest::Method,
        creds: &Credentials,
        path: &str,
        payload: &Value,
    ) -> Result<Value> {
        let method_name = method.as_str().to_string();
        let rb = self
            .http
            .request(method, format!("{}{}", self.api_url, path))
            .header(reqwest::header::ACCEPT, "application/json")
            .json(payload);
        let rb = self.apply_auth(rb, creds);
        let (status, body) = self.send(rb, &method_name, path).await?;
        parse_response(status, &body)
    }

    async fn send_json_empty_ok(
        &self,
        method: reqwest::Method,
        creds: &Credentials,
        path: &str,
        payload: &Value,
    ) -> Result<()> {
        let method_name = method.as_str().to_string();
        let rb = self
            .http
            .request(method, format!("{}{}", self.api_url, path))
            .header(reqwest::header::ACCEPT, "application/json")
            .json(payload);
        let rb = self.apply_auth(rb, creds);
        let (status, body) = self.send(rb, &method_name, path).await?;
        if (status.as_u16() == 204 || body.trim().is_empty())
            && (status.is_success() || status.as_u16() == 204)
        {
            return Ok(());
        }
        parse_response(status, &body).map(|_| ())
    }
}

/// Minimal URL-path escape for issue keys (keep `/` out of keys).
fn urlencoding_path(s: &str) -> String {
    // Issue keys are [A-Z][A-Z0-9]+-[0-9]+; still escape anything odd.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Plain text → minimal Atlassian Document Format paragraph.
pub fn plain_to_adf(text: &str) -> Value {
    json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{
                "type": "text",
                "text": text,
            }]
        }]
    })
}

/// Strip URL from a reqwest error (I12).
pub fn sanitize(err: reqwest::Error) -> anyhow::Error {
    anyhow::Error::new(err.without_url())
}

fn check_error(status: reqwest::StatusCode, parsed: Option<&Value>) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    let message = parsed
        .and_then(|v| {
            v.get("errorMessages")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| v.get("message").and_then(Value::as_str).map(str::to_owned))
                .or_else(|| v.get("errors").map(|e| e.to_string()))
        })
        .unwrap_or_else(|| "unknown error".into());
    bail!("jira error (HTTP {}): {}", status.as_u16(), message);
}

fn parse_response(status: reqwest::StatusCode, body: &str) -> Result<Value> {
    if status.as_u16() == 204 {
        return Ok(Value::Null);
    }
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    check_error(status, parsed.as_ref())?;
    parsed.ok_or_else(|| {
        anyhow!(
            "jira error (HTTP {}): response body is not valid JSON",
            status.as_u16()
        )
    })
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

    #[test]
    fn plain_to_adf_wraps_text() {
        let v = plain_to_adf("hello");
        assert_eq!(v["type"], "doc");
        assert_eq!(v["content"][0]["content"][0]["text"], json!("hello"));
    }

    #[test]
    fn credentials_debug_redacts() {
        let c = Credentials {
            email: "a@b.c".into(),
            token: "secret".into(),
        };
        let s = format!("{c:?}");
        assert!(!s.contains("secret"));
        assert!(!s.contains("a@b.c"));
    }
}
