# jirakeep

**jirakeep** is a Model Context Protocol (MCP) server, written in Rust, with
operator-controlled security guards. It exposes an **Atlassian Jira Cloud**
site to LLM clients — while a policy file that the model can neither see nor
change decides, per issue, what the model is allowed to do.

It is a **sibling** of [bugwarden](https://github.com/plusky/bugwarden)
(Bugzilla), not a second backend inside it. Same operational shape (policy
guard, CI/release, fail-closed design); separate repository and crate so
Bugzilla-specific invariants stay honest.

> **Status: early skeleton (0.1.0).** The workspace, CLI, policy load path,
> CI/release pipelines, and two info tools are in place. Issue
> read/search/write tools, full policy matching, and live Jira calls are
> not implemented yet. See [`docs/DESIGN.md`](docs/DESIGN.md).

## Features (planned / partial)

* **Guard policy engine** — operator TOML; allow / deny / restrict with a
  capability vocabulary; fail closed (DESIGN.md).
* **No existence oracle** — denied and missing issues share one denial text.
* **Jira Cloud first** — Basic auth (email + API token); Data Center later.
* **Two transports** — streamable HTTP and stdio.
* **Audit stream** — planned (operator-only JSONL; never on the MCP surface).

## Skeleton tools

| Tool | Description |
|------|-------------|
| `mcp_server_info` | Coarse server + policy facts (no rule names) |
| `jira_server_info` | Static skeleton status (does not call Jira) |

## Quick start (skeleton)

```bash
cargo build --release -p jirakeep

# HTTP (default): listen on 127.0.0.1:8000
./target/release/jirakeep \
  --jira-server https://example.atlassian.net \
  --policy examples/policy.toml

# stdio (requires token + email for Cloud Basic auth)
./target/release/jirakeep \
  --transport stdio \
  --jira-server https://example.atlassian.net \
  --email you@example.com \
  --api-key "$JIRA_API_TOKEN" \
  --policy examples/policy.toml
```

## Installation

### From source

```bash
git clone https://github.com/plusky/jirakeep
cd jirakeep
cargo build --release
# binary at target/release/jirakeep
```

The repository pins its Rust toolchain via `rust-toolchain.toml`. Building
`reqwest`/`aws-lc-sys` needs a C toolchain (compiler + `cmake`).

### crates.io

Not published until the first real feature release. The release workflow is
already wired for Trusted Publishing.

## Policy

See [`examples/policy.toml`](examples/policy.toml) and
[`docs/DESIGN.md`](docs/DESIGN.md). Critical Jira-specific rule: **an issue
with no security level is not world-readable**; declare public projects
explicitly under `global.public_projects`.

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p jirakeep --features gen --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
```

Regenerate man page and shell completions:

```bash
cargo run --locked -p jirakeep --features gen --bin jirakeep-gen
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md). Report guard bypasses privately to
martin@pluskal.org.
