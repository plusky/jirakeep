//! # jirakeep-core
//!
//! Guard policy engine and async Jira Cloud REST client for the `jirakeep` MCP
//! server. This crate is transport-agnostic and MUST NOT depend on rmcp, axum,
//! clap, or any MCP/transport crate (see `docs/DESIGN.md`); the dependency
//! direction is `jirakeep -> jirakeep-core`, never the reverse.
//!
//! Modules:
//!
//! - [`policy`] — the operator-controlled guard policy: TOML schema and
//!   classification types. Loaded once at startup and immutable at runtime
//!   (invariant I1).
//! - [`guard`] — runtime enforcement on top of the policy: uniform denial
//!   text (I2) and fail-closed defaults (I4). Full projections land later.
//! - [`client`] — async Jira Cloud REST client shell (reqwest + rustls).
//!   Errors must never leak credentials (I12).

pub mod client;
pub mod guard;
pub mod policy;
