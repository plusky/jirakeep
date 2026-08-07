# jirakeep-core

Guard policy engine and async Jira Cloud REST client for the
[`jirakeep`](https://github.com/plusky/jirakeep) MCP server.

This crate is transport-agnostic and **must not** depend on `rmcp`, `axum`,
`clap`, or any MCP/transport crate. Dependency direction is
`jirakeep → jirakeep-core`, never the reverse.

## Status

Early skeleton: policy load/default and a client shell are present; the full
matcher, guard projections, and Jira REST methods land in later work. See
`docs/DESIGN.md` in the repository root.
