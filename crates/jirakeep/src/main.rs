//! jirakeep — Rust MCP server for Atlassian Jira Cloud with
//! operator-controlled security guards.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use jirakeep::audit::{policy_hash_of, AuditConfig, AuditSink, AuditState, FailMode};
use jirakeep::config::{Cli, Transport};
use jirakeep::server;
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::Policy;
use rmcp::{
    transport::{
        stdio,
        streamable_http_server::{session::local::LocalSessionManager, StreamableHttpService},
    },
    ServiceExt,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let mut policy = match &cli.policy {
        Some(path) => Policy::load(path)
            .with_context(|| format!("failed to load guard policy from {}", path.display()))?,
        None => Policy::default(),
    };
    policy.global.read_only |= cli.read_only;

    let jira = Arc::new(server::jira_client(&cli)?);
    let guard = Arc::new(Guard::new(policy));
    let cfg = Arc::new(cli);
    let mut server = server::JiraKeep::new(cfg.clone(), guard, jira)
        .context("failed to build the MCP server")?;
    // Fail loudly at startup when identity-consulting rules could never
    // be satisfied; runtime denials stay silent (I4).
    server.preflight_identity().await?;

    let audit = match &cfg.audit_config {
        Some(path) => {
            let audit_cfg = AuditConfig::load(path)?;
            let fail_mode =
                FailMode::resolve(audit_cfg.fail_mode, cfg.transport == Transport::Http);
            let suppressed_ids = audit_cfg.suppressed_ids;
            let policy_hash = match &cfg.policy {
                Some(policy_path) => {
                    let bytes = std::fs::read(policy_path).with_context(|| {
                        format!(
                            "failed to read guard policy from {} for the audit digest",
                            policy_path.display()
                        )
                    })?;
                    Some(policy_hash_of(&bytes))
                }
                None => None,
            };
            let sink = AuditSink::open(audit_cfg).context("failed to open the audit sink")?;
            let transport = match cfg.transport {
                Transport::Stdio => "stdio",
                Transport::Http => "http",
            };
            Some(AuditState::new(
                sink,
                fail_mode,
                policy_hash,
                suppressed_ids,
                transport,
            ))
        }
        None => None,
    };
    if audit.is_none() && cfg.transport == Transport::Http {
        tracing::warn!(
            "auditing is OFF: remote tool calls over http will leave no audit \
             record — pass --audit-config / JIRAKEEP_AUDIT_CONFIG to enable it"
        );
    }
    if let Some(audit) = audit {
        server = server.with_audit(audit);
    }

    match cfg.transport {
        Transport::Stdio => {
            tracing::info!("Starting Jira MCP server on stdio");
            let service = server.serve(stdio()).await.inspect_err(|e| {
                tracing::error!("serving error: {:?}", e);
            })?;
            service.waiting().await?;
        }
        Transport::Http => {
            let ct = tokio_util::sync::CancellationToken::new();

            let service = StreamableHttpService::new(
                move || Ok(server.clone()),
                LocalSessionManager::default().into(),
                server::http_server_config().with_cancellation_token(ct.child_token()),
            );
            let router = axum::Router::new().nest_service("/mcp", service);
            let addr = format!("{}:{}", cfg.host, cfg.port);
            tracing::info!("Starting Jira MCP server on {addr}");
            let tcp_listener = tokio::net::TcpListener::bind(&addr)
                .await
                .with_context(|| format!("failed to bind {addr}"))?;
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    ct.cancel();
                })
                .await?;
        }
    }

    Ok(())
}
