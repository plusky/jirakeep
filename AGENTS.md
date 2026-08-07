# Rust Workspace Guidelines

These instructions apply to this repository — a root Rust workspace with
sources under `crates/`. The binding design contract is `docs/DESIGN.md`;
when this file and DESIGN.md disagree, DESIGN.md wins.

## Workspace Commands

Run commands from the repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p jirakeep --features gen --all-targets -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
```

Use the toolchain pinned in `rust-toolchain.toml` (repo root, currently
`1.97.0`). The workspace MSRV is declared once in `Cargo.toml`
(`rust-version = "1.88"`); do not introduce APIs or dependencies which
require a newer compiler without deliberately updating both the pin and the
MSRV policy. CI and reproducible local checks use the committed
`Cargo.lock`, so use `--locked` for verification.

## Workspace Architecture

- `jirakeep-core` is the portable domain layer: the guard policy engine
  (`policy`, `guard`) and the async Jira Cloud REST client (`client`). It
  MUST NOT depend on `rmcp`, `axum`, `clap`, or any MCP/transport crate.
- `jirakeep` is the binary: clap CLI parsing, the rmcp MCP server, and the
  stdio / streamable-HTTP transports. It must not duplicate guard or client
  logic.
- Keep the dependency direction acyclic: `jirakeep -> jirakeep-core`,
  never the reverse.
- Both crates inherit `[workspace.package]` metadata and
  `[workspace.lints]` (`[lints] workspace = true` in each crate manifest).
- jirakeep is a **sibling** of bugwarden, not a shared-crate consumer.
  Do not add a path dependency on bugwarden without an explicit design
  change recorded in DESIGN.md.

## Security guard rules

The security guards are defined in `docs/DESIGN.md` as invariants
**I1–I15**. They are normative: reviewers verify them, and CI failures are
never a reason to relax them.

- **NEVER weaken a guard to fix a build or test.** In particular, do not
  turn fail-closed behavior into fail-open (I4), do not vary the uniform
  denial text `Issue {key} is not accessible through this server` between
  denied and nonexistent issues (I2), and do not surface filtered/dropped
  result counts to the client (I3). If a guard blocks a test, fix the test
  or the design — not the guard.
- **Never map “no security level” to public.** That fail-open hazard is
  called out in DESIGN.md; absent security level is unknown unless the
  operator declared the project public.
- The guard policy comes only from the operator's TOML file at startup and
  is immutable at runtime (I1). **The policy file must never become
  readable or writable through MCP.**
- CLI/env flags may only tighten policy, never loosen it (I9).
- The Jira API token must never appear in logs, error messages, or tool
  results; sanitize reqwest errors with `.without_url()` (I12).
- In read-only mode, and for `global.disabled_tools`, write tools are
  removed from the tool listing (`ToolRouter::remove_route`), not merely
  made to error (I13).

## DESIGN.md Records Deliberate Decisions

docs/DESIGN.md is the sole design authority. It records decisions that may
look like accidents but are deliberate; convenience, precedent, or other
implementations are never a justification for undoing them.

## Rust Style and APIs

- Follow `rustfmt`; use idiomatic ownership and borrowing rather than
  cloning to resolve a lifetime issue by default.
- Public items need rustdoc that explains purpose, relevant errors, and
  behavioral constraints. Keep crate documentation accurate.
- Return errors with actionable context (`anyhow` with context). Do not use
  `unwrap`, `expect`, or panics in recoverable production paths.
- Keep `unsafe` forbidden. Do not weaken workspace lint configuration
  merely to silence a new warning.
- Prefer small, focused functions and exhaustive `match` expressions for
  externally meaningful enums (`Capability`, `Action`, `Access`).

## Async and Networking

- Do not block Tokio worker threads with synchronous I/O, sleeps, or
  process calls. Bound network operations with the client's configured
  timeout.
- Tracing goes to stderr always — stdout belongs to the stdio transport.

## Tests and Dependencies

- Add focused unit tests alongside changed modules; use wiremock for
  HTTP-level integration tests in `crates/jirakeep-core/tests/` as the
  client grows.
- A dependency change must update `Cargo.lock`, preserve the MSRV, and pass
  `cargo deny check`. Prefer the smallest compatible version change; do not
  run a broad `cargo update` as part of an unrelated change.
- `typos` runs as its own workflow; `typos.toml` is an allowlist of
  deliberate spellings, never a mask for a real typo.

## Commits and Pull Requests

- One logical, self-contained change per pull request.
- Commit subjects follow Conventional Commits:
  `type(scope): imperative lowercase subject`, no trailing period, at most
  ~72 characters. Types in use: `feat`, `fix`, `docs`, `test`, `refactor`,
  `chore`, `ci`; Dependabot owns `build(deps)`. Scope is the crate or area
  (`core`, `server`, `policy`, `release`, …).
- `main` takes rebase merges only; every commit must build and pass the
  workspace verification commands on its own.
- PR titles equal the primary commit subject. Security-relevant changes name
  the DESIGN.md invariants they touch.

## Releases

A release is one push of an annotated tag; nothing is released by hand.

- The tag is the bare version, no `v` prefix (`0.1.0`), and must equal
  `[workspace.package] version`.
- `.github/workflows/release.yml` builds x86_64-unknown-linux-gnu and
  aarch64-apple-darwin, creates a GitHub release, then publishes
  `jirakeep-core` before `jirakeep` via crates.io Trusted Publishing (OIDC;
  no registry credential in the repo).
