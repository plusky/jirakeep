# jirakeep

<img src="https://raw.githubusercontent.com/plusky/jirakeep/main/assets/logo.svg"
     align="right" width="130" alt="jirakeep logo">

**jirakeep** is a Model Context Protocol (MCP) server, written in Rust, with
operator-controlled security guards. It exposes an **Atlassian Jira Cloud**
site to LLM clients while a policy file that the model can neither see nor
change decides, per issue, what the model is allowed to do.

Sibling of [bugwarden](https://github.com/plusky/bugwarden) (Bugzilla): same
operational shape (policy guard, CI/release, fail-closed design), separate
repository so tracker-specific invariants stay honest. See
[bugwarden#69](https://github.com/plusky/bugwarden/issues/69) (Option B).

## Features

* **Guard policy engine** — TOML rules: allow / deny / restrict with a
  13-capability vocabulary; match on project, components, labels, status,
  priority, issue type, security level, summary text, public-project flag,
  age, and `created_by_me`.
* **Fail-closed visibility** — missing security level is **not** treated as
  public; declare public projects under `global.public_projects`.
* **No existence oracle** — denied and missing issues share one denial text.
* **Silent search filtering** — JQL results drop denied issues without counts.
* **Restricted comments** — dual opt-in (policy + per-call flag).
* **Read + write tools** — issues, comments, history, search, attachments,
  transitions, assign, field update, watchers, links, create, attach.
* **Audit stream** — operator-only JSONL (`--audit-config`); never on MCP.
* **Two transports** — streamable HTTP and stdio.
* **Auth** — Cloud Basic (email + API token) or Data Center Bearer PAT
  (`--auth-mode bearer`).
* **I14 link scrubbing** — denied issue keys removed from links/parent/subtasks
  and redacted in changelog strings.

## Tools

| Tool | Kind |
|------|------|
| `mcp_server_info` | meta |
| `jira_server_info` | read |
| `issue_info` | read |
| `issue_comments` | read |
| `issue_history` | read |
| `issues_search` | read (JQL) |
| `list_attachments` / `download_attachment` | read |
| `issue_url` | local |
| `summarize_issue` | read (prompt) |
| `list_transitions` | read |
| `add_comment` | write |
| `transition_issue` | write |
| `assign_issue` | write |
| `update_issue_fields` | write |
| `add_watcher` | write |
| `link_issues` | write |
| `create_issue` | write |
| `add_attachment` | write |

Write tools vanish from the listing in read-only mode or via
`global.disabled_tools` (I13).

## Quick start

```bash
cargo build --release -p jirakeep

# HTTP (default): clients send token in ApiKey header; email via
# X-Atlassian-Email or --email on the server
./target/release/jirakeep \
  --jira-server https://example.atlassian.net \
  --policy examples/policy.toml \
  --audit-config examples/audit.toml

# stdio (server-held Cloud Basic credentials)
./target/release/jirakeep \
  --transport stdio \
  --jira-server https://example.atlassian.net \
  --email you@example.com \
  --api-key "$JIRA_API_TOKEN" \
  --policy examples/policy.toml

# Data Center personal access token (Bearer)
./target/release/jirakeep \
  --transport stdio \
  --auth-mode bearer \
  --jira-server https://jira.example.com \
  --api-key "$JIRA_PAT" \
  --policy examples/policy.toml
```

## Policy

See [`examples/policy.toml`](examples/policy.toml) and
[`docs/DESIGN.md`](docs/DESIGN.md).

Critical Jira rule: **an issue with no security level is not world-readable**.

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p jirakeep --features gen --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
cargo run --locked -p jirakeep --features gen --bin jirakeep-gen
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md). Report guard bypasses privately to
martin@pluskal.org.
