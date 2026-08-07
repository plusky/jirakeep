//! jirakeep — MCP server for Atlassian Jira Cloud with operator-controlled
//! security guards.
//!
//! This library target exists so the MCP tool surface can be driven end to
//! end by integration tests (`tests/`): the binary (`main.rs`) is a thin
//! transport wrapper around [`server::JiraKeep`], and a binary-only crate
//! would leave the tool gates untestable as a unit. The supported product
//! remains the `jirakeep` binary; this API carries no stability promise.

pub mod config;
pub mod server;
