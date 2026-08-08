//! MCP tool surface for jirakeep.
//!
//! Every tool that takes an issue key runs guard assessment before side
//! effects or data return (I8). Denials use [`Guard::denial`] only (I2).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use jirakeep_core::client::{Credentials, JiraClient};
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::{Access, Action, Capability, IssueMeta};
use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::{AuditCell, AuditState, FailMode, Verdict};
use crate::config::{Cli, TokenCustody, Transport};

const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2024_11_05,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
];
const DEFAULT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2025_11_25;
const SERVER_NAME: &str = env!("CARGO_PKG_NAME");
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn server_identity() -> Implementation {
    Implementation::new(SERVER_NAME, SERVER_VERSION)
}

pub const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

pub const WRITE_TOOLS: &[&str] = &[
    "add_comment",
    "transition_issue",
    "assign_issue",
    "update_issue_fields",
    "add_watcher",
    "link_issues",
    "create_issue",
    "add_attachment",
];

pub fn jira_client(cli: &Cli) -> anyhow::Result<JiraClient> {
    use anyhow::Context as _;
    use jirakeep_core::client::AuthMode;
    let mode: AuthMode = cli.auth_mode.into();
    JiraClient::with_auth_mode(&cli.jira_server, USER_AGENT, mode)
        .context("failed to build Jira client")
}

fn ok_json(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn err_text(msg: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(msg.into())])
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Restrict => "restrict",
    }
}

fn audit_cell(ctx: &RequestContext<RoleServer>) -> Option<Arc<AuditCell>> {
    ctx.extensions.get::<Arc<AuditCell>>().cloned()
}

fn note_refused(ctx: &RequestContext<RoleServer>) {
    if let Some(cell) = audit_cell(ctx) {
        cell.note_verdict(Verdict::Refused);
    }
}

// --- params -----------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueKeysParams {
    /// One or more issue keys (e.g. PROJ-123).
    pub keys: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueKeyParams {
    pub key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueCommentsParams {
    pub key: String,
    #[serde(default)]
    pub include_restricted: bool,
    #[serde(default = "default_max")]
    pub max_results: u32,
}

fn default_max() -> u32 {
    50
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueHistoryParams {
    pub key: String,
    #[serde(default = "default_max")]
    pub max_results: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// JQL query string.
    pub jql: String,
    #[serde(default = "default_max")]
    pub max_results: u32,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub start_at: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddCommentParams {
    pub key: String,
    pub body: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransitionParams {
    pub key: String,
    pub transition_id: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AssignParams {
    pub key: String,
    /// Account id to assign; omit or null to unassign.
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateFieldsParams {
    pub key: String,
    /// Fields object (Jira REST shape). Security level changes are rejected.
    pub fields: Value,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WatcherParams {
    pub key: String,
    pub account_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LinkParams {
    pub link_type: String,
    pub inward_key: String,
    pub outward_key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateIssueParams {
    pub project_key: String,
    pub summary: String,
    pub issue_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    #[serde(default)]
    pub components: Option<Vec<String>>,
    #[serde(default)]
    pub priority: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddAttachmentParams {
    pub key: String,
    pub filename: String,
    /// Base64-encoded file content.
    pub content_base64: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadAttachmentParams {
    pub key: String,
    /// Attachment id (numeric string from list_attachments).
    pub attachment_id: String,
}

// --- server -----------------------------------------------------------------

#[derive(Clone)]
pub struct JiraKeep {
    cfg: Arc<Cli>,
    guard: Arc<Guard>,
    jira: Arc<JiraClient>,
    tool_router: ToolRouter<Self>,
    token_custody: TokenCustody,
    email: Option<String>,
    audit: Option<Arc<AuditState>>,
}

impl JiraKeep {
    pub fn new(cfg: Arc<Cli>, guard: Arc<Guard>, jira: Arc<JiraClient>) -> anyhow::Result<Self> {
        let token_custody = cfg.resolve_token_custody()?;
        let email = cfg.resolve_email(&token_custody)?;
        let mut tool_router = Self::tool_router();
        for name in &guard.policy.global.disabled_tools {
            if !tool_router.has_route(name) {
                let known = tool_router
                    .list_all()
                    .iter()
                    .map(|t| t.name.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::bail!(
                    "policy global.disabled_tools names unknown tool \"{name}\" \
                     (known tools: {known})"
                );
            }
        }
        if guard.policy.global.read_only {
            for name in WRITE_TOOLS {
                tracing::info!(tool = name, "read-only mode: removing write tool");
                tool_router.remove_route(name);
            }
        }
        for name in &guard.policy.global.disabled_tools {
            tracing::info!(tool = %name, "policy: removing disabled tool");
            tool_router.remove_route(name);
        }
        Ok(Self {
            cfg,
            guard,
            jira,
            tool_router,
            token_custody,
            email,
            audit: None,
        })
    }

    pub fn with_audit(mut self, audit: Arc<AuditState>) -> Self {
        self.audit = Some(audit);
        self
    }

    fn credentials(&self, ctx: &RequestContext<RoleServer>) -> Result<Credentials, McpError> {
        use crate::config::AuthModeCli;
        let token = match &self.token_custody {
            TokenCustody::Server(t) => t.clone(),
            TokenCustody::PerRequest => {
                let header_name = self.cfg.api_key_header.to_lowercase();
                ctx.extensions
                    .get::<axum::http::request::Parts>()
                    .and_then(|parts| parts.headers.get(header_name.as_str()))
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        McpError::invalid_request(
                            format!("`{}` header is required", self.cfg.api_key_header),
                            None,
                        )
                    })?
            }
        };
        let email = if self.cfg.auth_mode == AuthModeCli::Bearer {
            self.email.clone().unwrap_or_default()
        } else {
            match &self.email {
                Some(e) => e.clone(),
                None => {
                    // Per-request email header for multi-user Cloud Basic.
                    let header = self.cfg.email_header.to_lowercase();
                    ctx.extensions
                        .get::<axum::http::request::Parts>()
                        .and_then(|parts| parts.headers.get(header.as_str()))
                        .and_then(|v| v.to_str().ok())
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            McpError::invalid_request(
                                format!(
                                    "email required: set --email or send `{}` header \
                                     (or --auth-mode bearer for DC PAT)",
                                    self.cfg.email_header
                                ),
                                None,
                            )
                        })?
                }
            }
        };
        Ok(Credentials { email, token })
    }

    async fn deny_unless(
        &self,
        creds: &Credentials,
        key: &str,
        cap: Capability,
        caller: Option<&str>,
        ctx: &RequestContext<RoleServer>,
    ) -> Option<CallToolResult> {
        let assessments = self
            .guard
            .assess(&self.jira, creds, &[key.to_owned()], caller)
            .await;
        let entry = assessments.get(key).or_else(|| {
            assessments
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v)
        });
        let allowed = entry.is_some_and(|(access, _)| access.allows(cap));
        if let Some(cell) = audit_cell(ctx) {
            let verdict = if allowed {
                Verdict::Served
            } else {
                Verdict::Denied
            };
            match entry {
                Some((access, _)) => {
                    let rule = match access {
                        Access::Denied { rule } | Access::Granted { rule, .. } => rule.as_str(),
                    };
                    cell.note_verdict_rule(verdict, rule);
                }
                None => cell.note_verdict(verdict),
            }
        }
        if allowed {
            None
        } else {
            tracing::info!(issue = key, capability = ?cap, "guard denied operation");
            Some(err_text(Guard::denial(key)))
        }
    }
}

#[tool_router]
impl JiraKeep {
    #[tool(
        description = "Coarse facts about this jirakeep MCP server and its guard policy. Does not expose rule names or match criteria.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn mcp_server_info(&self) -> Result<CallToolResult, McpError> {
        let p = &self.guard.policy;
        Ok(ok_json(json!({
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "backend": match self.cfg.auth_mode {
                crate::config::AuthModeCli::Basic => "jira-cloud-basic",
                crate::config::AuthModeCli::Bearer => "jira-bearer",
            },
            "jira_server": self.cfg.jira_server,
            "transport": match self.cfg.transport {
                Transport::Http => "http",
                Transport::Stdio => "stdio",
            },
            "policy": {
                "rule_count": p.rule_count(),
                "default_action": action_name(p.default_action),
                "min_issue_age_days": p.global.min_issue_age_days,
                "read_only": p.global.read_only,
                "allow_restricted_comments": p.global.allow_restricted_comments,
                "disabled_tools": p.global.disabled_tools,
                "public_projects_count": p.global.public_projects.len(),
            },
            "audit": self.audit.is_some(),
        })))
    }

    #[tool(
        description = "Jira Cloud site serverInfo for the configured instance.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn jira_server_info(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        match self.jira.server_info(&creds).await {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => Ok(err_text(format!("failed to fetch server info: {e:#}"))),
        }
    }

    #[tool(
        description = "Return issue details for one or more keys. Denied or missing issues appear under 'restricted' with no existence oracle.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn issue_info(
        &self,
        Parameters(p): Parameters<IssueKeysParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        let keys: Vec<String> = p
            .keys
            .into_iter()
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty())
            .collect();
        if keys.len() > Guard::MAX_ASSESS_KEYS {
            note_refused(&ctx);
            return Ok(err_text(format!(
                "at most {} issue keys per call",
                Guard::MAX_ASSESS_KEYS
            )));
        }
        let assessments = self
            .guard
            .assess(&self.jira, &creds, &keys, caller.as_deref())
            .await;
        let mut issues = Vec::new();
        let mut restricted = Vec::new();
        let mut all_scrubbed: Vec<String> = Vec::new();
        for key in &keys {
            match assessments.get(key) {
                Some((access, body)) if !body.is_null() => {
                    if access.allows(Capability::Read) {
                        // Full body for Read grants (classify fetch is a projection).
                        let full = match self.jira.get_issue(&creds, key, None).await {
                            Ok(v) => v,
                            Err(_) => body.clone(),
                        };
                        // I14: scrub linked keys the client may not see.
                        let mut candidates = Guard::linked_keys(&full);
                        candidates.insert(key.clone());
                        let disclosable = self
                            .guard
                            .disclosable(&self.jira, &creds, &candidates, caller.as_deref())
                            .await;
                        let (scrubbed, removed) = Guard::scrub_links(&full, &disclosable);
                        all_scrubbed.extend(removed);
                        if let Some(cell) = audit_cell(&ctx) {
                            cell.note_verdict_rule(
                                Verdict::Served,
                                match access {
                                    Access::Denied { rule } | Access::Granted { rule, .. } => rule,
                                },
                            );
                        }
                        issues.push(scrubbed);
                    } else if let Some(proj) = Guard::project_issue(access, body) {
                        if let Some(cell) = audit_cell(&ctx) {
                            cell.note_verdict_rule(
                                Verdict::Served,
                                match access {
                                    Access::Denied { rule } | Access::Granted { rule, .. } => rule,
                                },
                            );
                        }
                        issues.push(proj);
                    } else {
                        restricted.push(key.clone());
                    }
                }
                _ => restricted.push(key.clone()),
            }
        }
        if let Some(cell) = audit_cell(&ctx) {
            if !restricted.is_empty() {
                cell.note_suppressed(restricted.clone());
                cell.note_suppressed_count(restricted.len() as u64);
            }
            if !all_scrubbed.is_empty() {
                cell.note_suppressed(all_scrubbed);
            }
        }
        Ok(ok_json(json!({
            "issues": issues,
            "restricted": restricted,
        })))
    }

    #[tool(
        description = "Read comments on an issue. Restricted-visibility comments require policy allow_restricted_comments and include_restricted=true.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn issue_comments(
        &self,
        Parameters(p): Parameters<IssueCommentsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.key,
                Capability::Comments,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        match self
            .jira
            .issue_comments(&creds, &p.key, 0, p.max_results.min(100))
            .await
        {
            Ok(envelope) => {
                let comments = envelope
                    .get("comments")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let filtered = self.guard.filter_comments(comments, p.include_restricted);
                Ok(ok_json(json!({ "key": p.key, "comments": filtered })))
            }
            Err(_) => Ok(err_text(Guard::denial(&p.key))),
        }
    }

    #[tool(
        description = "Read the changelog (history) of an issue.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn issue_history(
        &self,
        Parameters(p): Parameters<IssueHistoryParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::History, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        match self
            .jira
            .issue_changelog(&creds, &p.key, 0, p.max_results.min(100))
            .await
        {
            Ok(v) => {
                // I14: redact issue-key values in changelog that policy hides.
                use std::collections::BTreeSet;
                let mut candidates = BTreeSet::new();
                candidates.insert(p.key.clone());
                if let Some(values) = v
                    .get("values")
                    .or_else(|| v.get("histories"))
                    .and_then(Value::as_array)
                {
                    for hist in values {
                        if let Some(items) = hist.get("items").and_then(Value::as_array) {
                            for item in items {
                                for field in ["fromString", "toString", "from", "to"] {
                                    if let Some(s) = item.get(field).and_then(Value::as_str) {
                                        if s.contains('-') {
                                            candidates.insert(s.to_owned());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                let disclosable = self
                    .guard
                    .disclosable(&self.jira, &creds, &candidates, caller.as_deref())
                    .await;
                Ok(ok_json(Guard::scrub_changelog(&v, &disclosable)))
            }
            Err(_) => Ok(err_text(Guard::denial(&p.key))),
        }
    }

    #[tool(
        description = "Search issues with JQL. Policy-denied issues are silently omitted from results (no drop counts).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn issues_search(
        &self,
        Parameters(p): Parameters<SearchParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        match self
            .guard
            .search_filtered(
                &self.jira,
                &creds,
                &p.jql,
                p.max_results.min(50),
                p.next_page_token.as_deref(),
                p.start_at,
                caller.as_deref(),
            )
            .await
        {
            Ok(window) => {
                if let Some(cell) = audit_cell(&ctx) {
                    cell.note_verdict(Verdict::Filtered);
                    cell.note_suppressed(window.dropped_keys.clone());
                    cell.note_suppressed_count(window.dropped_keys.len() as u64);
                    // I14: linked keys scrubbed from served issues are
                    // audit-side only, never client-visible.
                    if !window.scrubbed_keys.is_empty() {
                        cell.note_suppressed(window.scrubbed_keys.clone());
                    }
                    cell.note_scan(u64::from(window.scanned), window.dropped_keys.len() as u64);
                }
                // I3: do not return scanned/dropped counts to the client.
                Ok(ok_json(json!({
                    "issues": window.issues,
                    "nextPageToken": window.next_page_token,
                })))
            }
            Err(e) => Ok(err_text(format!("search failed: {e:#}"))),
        }
    }

    #[tool(
        description = "List attachment metadata for an issue (no file content).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn list_attachments(
        &self,
        Parameters(p): Parameters<IssueKeyParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.key,
                Capability::Attachments,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        match self.jira.list_attachments(&creds, &p.key).await {
            Ok(atts) => Ok(ok_json(json!({ "key": p.key, "attachments": atts }))),
            Err(_) => Ok(err_text(Guard::denial(&p.key))),
        }
    }

    #[tool(
        description = "Download one attachment as base64. Subject to policy max_attachment_bytes.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn download_attachment(
        &self,
        Parameters(p): Parameters<DownloadAttachmentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.key,
                Capability::Attachments,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        let atts = match self.jira.list_attachments(&creds, &p.key).await {
            Ok(a) => a,
            Err(_) => return Ok(err_text(Guard::denial(&p.key))),
        };
        let meta = atts.iter().find(|a| match a.get("id") {
            Some(Value::String(s)) => s == &p.attachment_id,
            Some(Value::Number(n)) => n.as_u64().is_some_and(|u| u.to_string() == p.attachment_id),
            _ => false,
        });
        let Some(meta) = meta else {
            return Ok(err_text(Guard::denial(&p.key)));
        };
        let size = meta.get("size").and_then(Value::as_u64).unwrap_or(0);
        if !self.guard.attachment_within_cap(size) {
            note_refused(&ctx);
            return Ok(err_text(format!(
                "attachment exceeds max_attachment_bytes ({size} bytes)"
            )));
        }
        let content_url = match meta.get("content").and_then(Value::as_str) {
            Some(u) => u,
            None => return Ok(err_text("attachment has no content URL")),
        };
        match self
            .jira
            .download_attachment_bytes(&creds, content_url)
            .await
        {
            Ok(bytes) => {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                Ok(ok_json(json!({
                    "key": p.key,
                    "attachment_id": p.attachment_id,
                    "filename": meta.get("filename"),
                    "size": bytes.len(),
                    "content_base64": b64,
                })))
            }
            Err(e) => Ok(err_text(format!("download failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Build a browse URL for an issue key locally (does not contact Jira).",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn issue_url(
        &self,
        Parameters(p): Parameters<IssueKeyParams>,
    ) -> Result<CallToolResult, McpError> {
        let base = self.cfg.jira_server.trim_end_matches('/');
        Ok(ok_json(json!({
            "key": p.key,
            "url": format!("{base}/browse/{}", p.key),
        })))
    }

    #[tool(
        description = "Return a prompt text for summarizing an issue's comments (comments still policy-gated).",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn summarize_issue(
        &self,
        Parameters(p): Parameters<IssueKeyParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.key,
                Capability::Comments,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        let comments = match self.jira.issue_comments(&creds, &p.key, 0, 100).await {
            Ok(envelope) => envelope
                .get("comments")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            Err(_) => return Ok(err_text(Guard::denial(&p.key))),
        };
        let comments = self.guard.filter_comments(comments, false);
        let text = serde_json::to_string_pretty(&comments).unwrap_or_else(|_| "[]".into());
        let prompt = format!(
            "You are an expert at summarizing Jira issue comments.\n\
             Rules:\n\
             - Structure the summary clearly\n\
             - Mention authors and dates where relevant\n\
             - Do not invent facts not present in the data\n\n\
             Issue: {}\nComments:\n{text}",
            p.key
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(prompt)]))
    }

    #[tool(
        description = "Add a comment to an issue.",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn add_comment(
        &self,
        Parameters(p): Parameters<AddCommentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Comment, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        match self.jira.add_comment(&creds, &p.key, &p.body, None).await {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => Ok(err_text(format!("add_comment failed: {e:#}"))),
        }
    }

    #[tool(
        description = "List available workflow transitions for an issue.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn list_transitions(
        &self,
        Parameters(p): Parameters<IssueKeyParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Read, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        match self.jira.get_transitions(&creds, &p.key).await {
            Ok(v) => Ok(ok_json(v)),
            Err(_) => Ok(err_text(Guard::denial(&p.key))),
        }
    }

    #[tool(
        description = "Transition an issue to another status by transition id.",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn transition_issue(
        &self,
        Parameters(p): Parameters<TransitionParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Status, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        match self
            .jira
            .transition_issue(&creds, &p.key, &p.transition_id, None, p.comment.as_deref())
            .await
        {
            Ok(()) => Ok(ok_json(json!({"ok": true, "key": p.key}))),
            Err(e) => Ok(err_text(format!("transition failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Assign an issue to an account id (or unassign with null account_id).",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn assign_issue(
        &self,
        Parameters(p): Parameters<AssignParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Assign, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        let fields = match &p.account_id {
            Some(id) => json!({"assignee": {"accountId": id}}),
            None => json!({"assignee": Value::Null}),
        };
        match self.jira.update_issue(&creds, &p.key, fields).await {
            Ok(()) => Ok(ok_json(json!({"ok": true, "key": p.key}))),
            Err(e) => Ok(err_text(format!("assign failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Update issue fields (Jira fields object). Rejects security level and project smuggling.",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn update_issue_fields(
        &self,
        Parameters(p): Parameters<UpdateFieldsParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Fields, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        // I7: block privileged field smuggling.
        if let Some(obj) = p.fields.as_object() {
            for banned in ["security", "project", "reporter"] {
                if obj.contains_key(banned) {
                    note_refused(&ctx);
                    return Ok(err_text(format!(
                        "field \"{banned}\" cannot be set through update_issue_fields"
                    )));
                }
            }
        } else {
            note_refused(&ctx);
            return Ok(err_text("fields must be a JSON object"));
        }
        match self.jira.update_issue(&creds, &p.key, p.fields).await {
            Ok(()) => Ok(ok_json(json!({"ok": true, "key": p.key}))),
            Err(e) => Ok(err_text(format!("update failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Add a watcher (by account id) to an issue.",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn add_watcher(
        &self,
        Parameters(p): Parameters<WatcherParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.key,
                Capability::Watchers,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        match self.jira.add_watcher(&creds, &p.key, &p.account_id).await {
            Ok(()) => Ok(ok_json(json!({"ok": true}))),
            Err(e) => Ok(err_text(format!("add_watcher failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Create an issue link. Requires Links on both issues (at least Summary on the other side).",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn link_issues(
        &self,
        Parameters(p): Parameters<LinkParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.inward_key,
                Capability::Links,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        if let Some(deny) = self
            .deny_unless(
                &creds,
                &p.outward_key,
                Capability::Summary,
                caller.as_deref(),
                &ctx,
            )
            .await
        {
            return Ok(deny);
        }
        match self
            .jira
            .create_issue_link(&creds, &p.link_type, &p.inward_key, &p.outward_key)
            .await
        {
            Ok(()) => Ok(ok_json(json!({"ok": true}))),
            Err(e) => Ok(err_text(format!("link failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Create a new issue. Subject to create-gate policy (project visibility, etc.).",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn create_issue(
        &self,
        Parameters(p): Parameters<CreateIssueParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let mut meta = IssueMeta {
            project: Some(p.project_key.clone()),
            summary: Some(p.summary.clone()),
            issue_type: Some(p.issue_type.clone()),
            labels: p.labels.clone(),
            components: p.components.clone(),
            priority: p.priority.clone(),
            created_by_me: Some(true),
            public_projects: self.guard.policy.global.public_projects.clone(),
            ..Default::default()
        };
        let access = self.guard.may_create(&meta);
        if !access.allows(Capability::Create) {
            if let Some(cell) = audit_cell(&ctx) {
                cell.note_verdict(Verdict::Denied);
            }
            note_refused(&ctx);
            return Ok(err_text(format!(
                "Issue create in project {} is not permitted by policy",
                p.project_key
            )));
        }
        let mut fields = json!({
            "project": {"key": p.project_key},
            "summary": p.summary,
            "issuetype": {"name": p.issue_type},
        });
        if let Some(desc) = p.description {
            fields["description"] = jirakeep_core::client::plain_to_adf(&desc);
        }
        if let Some(labels) = p.labels {
            fields["labels"] = json!(labels);
        }
        if let Some(components) = p.components {
            fields["components"] = json!(components
                .into_iter()
                .map(|n| json!({"name": n}))
                .collect::<Vec<_>>());
        }
        if let Some(pri) = p.priority {
            fields["priority"] = json!({"name": pri});
        }
        let _ = &mut meta;
        match self.jira.create_issue(&creds, fields).await {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => Ok(err_text(format!("create_issue failed: {e:#}"))),
        }
    }

    #[tool(
        description = "Upload an attachment (base64 content). Subject to max_attachment_bytes.",
        annotations(read_only_hint = false, open_world_hint = true)
    )]
    async fn add_attachment(
        &self,
        Parameters(p): Parameters<AddAttachmentParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let creds = self.credentials(&ctx)?;
        let caller = self.guard.resolve_caller(&self.jira, &creds).await;
        if let Some(deny) = self
            .deny_unless(&creds, &p.key, Capability::Attach, caller.as_deref(), &ctx)
            .await
        {
            return Ok(deny);
        }
        use base64::Engine as _;
        let bytes = match base64::engine::general_purpose::STANDARD.decode(p.content_base64.trim())
        {
            Ok(b) => b,
            Err(_) => {
                note_refused(&ctx);
                return Ok(err_text("content_base64 is not valid base64"));
            }
        };
        if !self.guard.attachment_within_cap(bytes.len() as u64) {
            note_refused(&ctx);
            return Ok(err_text("attachment exceeds max_attachment_bytes"));
        }
        match self
            .jira
            .add_attachment(&creds, &p.key, &p.filename, bytes)
            .await
        {
            Ok(v) => Ok(ok_json(v)),
            Err(e) => Ok(err_text(format!("add_attachment failed: {e:#}"))),
        }
    }
}

// Hand-written ServerHandler pieces for audit wrapping; tool dispatch via router.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for JiraKeep {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(DEFAULT_PROTOCOL_VERSION)
            .with_server_info(server_identity())
            .with_instructions(
                "MCP server for Atlassian Jira with operator-controlled \
                 security guards. Policy-denied issues are indistinguishable from \
                 nonexistent ones: 'Issue {key} is not accessible through this server'. \
                 Search silently omits denied issues. Restricted comments need dual opt-in. \
                 Linked issue keys the policy would hide are scrubbed from responses."
                    .to_string(),
            )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        let mut info = self.get_info();
        if SUPPORTED_PROTOCOL_VERSIONS.contains(&request.protocol_version) {
            info.protocol_version = request.protocol_version.clone();
        }
        if let Some(audit) = &self.audit {
            if let Err(e) = audit.record_initialize(
                Some(request.client_info.name.clone()),
                Some(request.client_info.version.clone()),
                Some(info.protocol_version.as_str().to_string()),
            ) {
                tracing::error!(error = %e, "audit initialize record failed");
                if audit.fail_mode == FailMode::ClosedAll {
                    return Err(McpError::internal_error("audit unavailable", None));
                }
            }
        }
        Ok(info)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let started = Instant::now();
        let tool_name = request.name.to_string();

        // Audit fail-closed gating.
        if let Some(audit) = &self.audit {
            if audit.sink.is_failing() {
                let gate = match audit.fail_mode {
                    FailMode::Open => false,
                    FailMode::ClosedAll => true,
                    FailMode::ClosedWritesDenials => WRITE_TOOLS.contains(&tool_name.as_str()),
                };
                if gate {
                    return Ok(CallToolResponse::Complete(err_text("audit unavailable")));
                }
            }
        }

        let cell = Arc::new(AuditCell::default());
        if self.audit.is_some() {
            context.extensions.insert(cell.clone());
        }

        let result = self
            .tool_router
            .call(ToolCallContext::new(self, request, context))
            .await;

        if let Some(audit) = &self.audit {
            let duration_ms = started.elapsed().as_millis() as u64;
            let err = result.as_ref().err().map(|e| e.to_string());
            if let Err(e) = audit.record_tool(&tool_name, &cell, duration_ms, err) {
                tracing::error!(error = %e, "audit record failed");
                match audit.fail_mode {
                    FailMode::Open => {}
                    FailMode::ClosedAll => {
                        return Ok(CallToolResponse::Complete(err_text("audit unavailable")));
                    }
                    FailMode::ClosedWritesDenials if WRITE_TOOLS.contains(&tool_name.as_str()) => {
                        return Ok(CallToolResponse::Complete(err_text("audit unavailable")));
                    }
                    FailMode::ClosedWritesDenials => {}
                }
            }
        }

        result
    }
}

pub fn http_server_config() -> rmcp::transport::streamable_http_server::StreamableHttpServerConfig {
    rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jirakeep_core::policy::Policy;

    fn test_server(read_only: bool) -> JiraKeep {
        use crate::config::AuthModeCli;
        let cli = Arc::new(Cli {
            jira_server: "https://example.atlassian.net".into(),
            auth_mode: AuthModeCli::Basic,
            transport: Transport::Http,
            host: "127.0.0.1".into(),
            port: 8000,
            api_key_header: "ApiKey".into(),
            email_header: "X-Atlassian-Email".into(),
            api_key: None,
            api_key_file: None,
            email: None,
            email_file: None,
            read_only,
            policy: None,
            audit_config: None,
        });
        let mut policy = Policy::default();
        policy.global.read_only |= read_only;
        let guard = Arc::new(Guard::new(policy));
        let jira = Arc::new(jira_client(&cli).unwrap());
        JiraKeep::new(cli, guard, jira).unwrap()
    }

    #[test]
    fn lists_expected_tools() {
        let s = test_server(false);
        let names: Vec<_> = s
            .tool_router
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        for need in [
            "mcp_server_info",
            "issue_info",
            "issues_search",
            "add_comment",
            "create_issue",
        ] {
            assert!(
                names.iter().any(|n| n == need),
                "missing {need} in {names:?}"
            );
        }
    }

    #[test]
    fn read_only_removes_write_tools() {
        let s = test_server(true);
        let names: Vec<_> = s
            .tool_router
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        for w in WRITE_TOOLS {
            assert!(!names.iter().any(|n| n == w), "write tool {w} still listed");
        }
        assert!(names.iter().any(|n| n == "issue_info"));
    }
}
