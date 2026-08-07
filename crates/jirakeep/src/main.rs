//! jirakeep — Rust MCP server for Atlassian Jira Cloud with
//! operator-controlled security guards.
//!
//! The binary is a thin transport wrapper; the CLI and the MCP tool surface
//! live in the `jirakeep` library crate (`config`, `server`) so integration
//! tests can drive the tools without a process boundary.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
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

    // Tracing always goes to stderr: stdout belongs to the stdio transport.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    // Guard policy comes ONLY from the TOML file given at startup (I1);
    // without one the built-in default policy applies.
    let mut policy = match &cli.policy {
        Some(path) => Policy::load(path)
            .with_context(|| format!("failed to load guard policy from {}", path.display()))?,
        None => Policy::default(),
    };
    // CLI/env can only tighten policy (I9).
    policy.global.read_only |= cli.read_only;

    let jira = Arc::new(server::jira_client(&cli)?);
    let guard = Arc::new(Guard::new(policy));
    let cfg = Arc::new(cli);
    let server = server::JiraKeep::new(cfg.clone(), guard, jira)
        .context("failed to build the MCP server")?;

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
