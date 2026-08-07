//! MCP tool surface for jirakeep (skeleton).
//!
//! Only `mcp_server_info` and `jira_server_info` are registered. Issue
//! read/search/write tools land after the guard and Jira client are real
//! (invariant I8: every id-taking tool must assess before side effects).

use std::borrow::Cow;
use std::sync::Arc;

use jirakeep_core::client::JiraClient;
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::Action;
use rmcp::{
    handler::server::router::tool::ToolRouter, model::*, tool, tool_handler, tool_router,
    ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};

use crate::config::{Cli, TokenCustody, Transport};

/// MCP revisions this build implements, newest last. Pinned rather than
/// inherited from the SDK (same discipline as bugwarden).
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

/// The `User-Agent` every request to Jira carries.
pub const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

/// Build the Jira client this build's requests go through.
///
/// # Errors
///
/// Returns an error when the client cannot be built — see [`JiraClient::new`].
pub fn jira_client(cli: &Cli) -> anyhow::Result<JiraClient> {
    use anyhow::Context as _;
    JiraClient::new(&cli.jira_server, USER_AGENT).context("failed to build Jira client")
}

/// Write tools (empty in the skeleton; filled as write tools land). Used so
/// read-only mode has a stable removal list (I13).
pub const WRITE_TOOLS: &[&str] = &[];

fn ok_json(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Restrict => "restrict",
    }
}

/// The MCP server: guard policy, Jira client shell, pruned tool router.
#[derive(Clone)]
pub struct JiraKeep {
    cfg: Arc<Cli>,
    guard: Arc<Guard>,
    #[allow(dead_code)] // used once issue tools land
    jira: Arc<JiraClient>,
    tool_router: ToolRouter<Self>,
    #[allow(dead_code)]
    token_custody: TokenCustody,
    #[allow(dead_code)]
    email: Option<String>,
}

impl JiraKeep {
    /// Build the server, pruning the tool router per policy (I13).
    ///
    /// # Errors
    ///
    /// Token/email custody resolution failures, or `disabled_tools` naming an
    /// unknown tool.
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
        })
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
            "backend": "jira-cloud",
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
            "status": "skeleton",
        })))
    }

    #[tool(
        description = "Skeleton placeholder for Jira site information. Does not contact Jira in this build.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn jira_server_info(&self) -> Result<CallToolResult, McpError> {
        Ok(ok_json(json!({
            "status": "skeleton",
            "backend": "jira-cloud",
            "jira_server": self.cfg.jira_server,
            "api_v3": self.jira.api_v3_url(),
            "note": "Issue tools and live Jira calls are not implemented in this skeleton build.",
        })))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for JiraKeep {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(DEFAULT_PROTOCOL_VERSION)
            .with_server_info(server_identity())
            .with_instructions(
                "MCP server for Atlassian Jira Cloud. Access is governed by an \
                 operator-controlled policy. This build is a skeleton: only \
                 mcp_server_info and jira_server_info are available. A reply that \
                 an issue 'is not accessible through this server' is final; it \
                 does not indicate whether the issue exists."
                    .to_string(),
            )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }
}

/// Streamable HTTP server config used by `main`.
pub fn http_server_config() -> rmcp::transport::streamable_http_server::StreamableHttpServerConfig {
    rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jirakeep_core::policy::Policy;
    use std::sync::Arc;

    fn test_server(read_only: bool) -> JiraKeep {
        let cli = Arc::new(Cli {
            jira_server: "https://example.atlassian.net".into(),
            transport: Transport::Http,
            host: "127.0.0.1".into(),
            port: 8000,
            api_key_header: "ApiKey".into(),
            api_key: None,
            api_key_file: None,
            email: None,
            email_file: None,
            read_only,
            policy: None,
        });
        let mut policy = Policy::default();
        policy.global.read_only |= read_only;
        let guard = Arc::new(Guard::new(policy));
        let jira = Arc::new(jira_client(&cli).unwrap());
        JiraKeep::new(cli, guard, jira).unwrap()
    }

    #[test]
    fn builds_and_lists_skeleton_tools() {
        let s = test_server(false);
        let names: Vec<_> = s
            .tool_router
            .list_all()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.iter().any(|n| n == "mcp_server_info"));
        assert!(names.iter().any(|n| n == "jira_server_info"));
    }

    #[test]
    fn unknown_disabled_tool_is_startup_error() {
        let cli = Arc::new(Cli {
            jira_server: "https://example.atlassian.net".into(),
            transport: Transport::Http,
            host: "127.0.0.1".into(),
            port: 8000,
            api_key_header: "ApiKey".into(),
            api_key: None,
            api_key_file: None,
            email: None,
            email_file: None,
            read_only: false,
            policy: None,
        });
        let mut policy = Policy::default();
        policy.global.disabled_tools = vec!["not_a_tool".into()];
        let guard = Arc::new(Guard::new(policy));
        let jira = Arc::new(jira_client(&cli).unwrap());
        let err = match JiraKeep::new(cli, guard, jira) {
            Ok(_) => panic!("expected unknown disabled tool to fail startup"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not_a_tool"));
    }
}
