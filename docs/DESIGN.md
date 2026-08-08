# jirakeep — design contract

An MCP server exposing **Atlassian Jira Cloud** to LLM clients, hardened with
operator-controlled security guards. This document is the binding contract
between modules. If an implementation must deviate, note the deviation
explicitly.

**Status:** skeleton (Phase 0). Invariants below are normative for the
product; only a subset is implemented in the initial tree.

## Relationship to bugwarden

jirakeep is a **sibling** of [bugwarden](https://github.com/plusky/bugwarden),
not a second backend inside it (Option B from
[bugwarden#69](https://github.com/plusky/bugwarden/issues/69)).

| | bugwarden | jirakeep |
|---|-----------|----------|
| Tracker | Bugzilla | Jira Cloud (v1) |
| Repo | independent | independent |
| Policy crate | `bugwarden-core` | `jirakeep-core` (own copy of the *decision* ideas) |
| Shared runtime dep | none | none |

Share ideas (fail-closed policy engine, CI/release shape, audit model). Do
**not** path-depend on `bugwarden-core` until/unless a tracker-agnostic
policy crate is extracted and published deliberately.

## Architecture

Cargo workspace, two crates:

- `crates/jirakeep-core` — guard policy engine + async Jira Cloud REST client.
  MUST NOT depend on rmcp, axum, clap, or any MCP/transport crate.
- `crates/jirakeep` — the binary: clap CLI, rmcp MCP server, stdio and
  streamable-HTTP transports. Depends on `jirakeep-core`. The crate also
  has a lib target consumed by `main.rs` and integration tests.

Dependency direction: `jirakeep -> jirakeep-core`, never the reverse.

## Backend scope (v1)

- **In scope:** Jira REST API v3.
  - **Cloud:** Basic auth (`email` + API token) — default (`--auth-mode basic`).
  - **Data Center:** Bearer personal access token (`--auth-mode bearer`).
- **Out of scope for v1:** OAuth 2.0 interactive flows, multi-tracker process,
  Confluence.

## Security invariants (normative — reviewers verify these)

Numbering aligns with bugwarden where the spirit matches; wording is Jira-specific.

- **I1** The guard policy comes ONLY from a TOML file given at startup
  (`--policy` / `JIRAKEEP_POLICY`). It is immutable at runtime. No MCP tool may
  expose rule names or match criteria; `mcp_server_info` may expose only coarse
  facts (rule count, `default_action`, age quarantine, `read_only`, disabled
  tool names, public-project count — not the project keys themselves if that
  would leak topology the operator hid).
- **I2** Uniform denial: a policy-denied issue and a nonexistent issue produce
  the same response text:
  `Issue {key} is not accessible through this server`.
  No wording/detail difference may reveal existence. `{key}` is the key the
  client supplied (or a stable placeholder if the request had none).
- **I3** Search filtering is silent: counts of dropped/filtered results are
  never returned to the client (server-side debug logging is fine).
- **I4** Fail closed: classification-fetch failure, issue absent from the
  response, or a CONSULTED rule that cannot be decided because required
  metadata is missing/unreadable ⇒ Denied. Unreadable metadata never yields
  more access than readable metadata would.
- **I5** Restricted-visibility comments/attachments are returned only when
  policy `global.allow_restricted_comments = true` **and** the call opts in.
  Default policy has restricted content off.
- **I6** Capability implication: `read` implies `summary`. Nothing else is
  implied.
- **I7** Generic field-update tools must not smuggle security level, project
  permission, or other privileged fields the capability model does not grant.
- **I8** Every tool that takes an issue key/id performs guard assessment
  BEFORE any side effect or data return. Exception: pure local URL builders
  that contact nothing.
- **I9** CLI/env can only tighten policy: `--read-only` ORs into
  `global.read_only`.
- **I10** No tool may echo incoming request headers back to the client.
- **I11** Linking/duplicating requires appropriate capability on *both*
  issues involved (at least `summary` on the other side for disclosure).
- **I12** The Jira API token (and email when treated as secret material in
  logs) must never appear in logs, error messages, or tool results. Sanitize
  reqwest errors with `.without_url()`.
- **I13** In read-only mode (policy or CLI) write tools are removed from the
  tool listing via `ToolRouter::remove_route`, not merely erroring. Same for
  `global.disabled_tools`.
- **I14** Issue keys the policy would deny must not appear inside something
  the client IS shown: `issuelinks`, `parent`, `subtasks` on served issues,
  and changelog `from`/`to`/`fromString`/`toString` values that look like
  issue keys. Bar is `Capability::Summary`. Candidate keys are assessed in
  batch via `Guard::disclosable`; failed fetches scrub (I4). Free-text
  description/comment bodies are not scanned (deliberate, unfixable
  without destroying content).
- **I15** The audit stream is never reachable through any MCP surface.
  Records include tool calls (verdicts, suppressed keys, search scan
  counts) and `initialize` handshakes. Tokens, emails, and free-text issue
  content are unrepresentable in the event type.

## Visibility semantics (Jira-specific — critical)

Jira has **no** Bugzilla-style multi-group list on the issue.

- An issue carries at most one optional **security level**.
- Visibility is otherwise decided by the **project permission scheme**.
- An issue with **no security level is not world-readable**; it is visible to
  whoever holds Browse Projects on that project.

**Fail-open hazard:** mapping “no security level” to “public / empty groups”
would turn private projects into apparent public issues.

**Security-level parsing is three-valued** (`SecurityLevel` in
`jirakeep-core::policy`):

- `security` absent or `null` ⇒ **absent**: knowledge that no level is set
  (still not “public”); matches `has_security_level = false`.
- an object with a string `name` ⇒ **present** with that level name.
- any other shape (object without a readable `name`, non-object) ⇒
  **unreadable**: unknown — independent of whether other metadata such as
  the project was readable — so a consulted criterion denies (I4).
  Unreadable never collapses into “no level”.

**Rule for jirakeep:**

1. Absent security level is **unknown** for any “publicness” criterion unless
   the operator has declared the project in `global.public_projects` (or a
   future explicit visibility rule).
2. Unknown ⇒ **deny** when a consulted rule needs that fact (I4).
3. Never treat empty/missing security level as proof of public access.

## Identifiers

- Primary client-facing id: **issue key** string (`PROJ-123`).
- Numeric id is retained when the API returns it (stable across project moves).
- Audit and denial text use keys, not bare integers.

## Tool result contract (v1)

**Vendor-shaped Jira Cloud REST JSON** is returned to the client (after guard
projection/redaction). A canonical multi-tracker schema is out of scope for
this sibling.

## Search

JQL + token pagination. Do **not** copy bugwarden's offset-chunk timing
mitigation without re-analysis; the threat model must be redone for token
pages.

## Policy shape (skeleton)

```toml
default_action = "allow"   # or "deny"; not "restrict"

[global]
min_issue_age_days = 0
allow_restricted_comments = false
read_only = false
disabled_tools = []
max_attachment_bytes = 2097152
public_projects = []         # keys declared publicly browsable

[[rule]]
name = "example"
action = "deny"
[rule.match]
# Phase 1: projects, components, labels, statuses, priorities,
# issue_types, security_levels, younger_than_days, created_by_me, …
```

Rules: first match wins; unmatched → `default_action`. Full matcher is Phase 1.

## Skeleton tool surface

| Tool | Role |
|------|------|
| `mcp_server_info` | Coarse server/policy facts (I1) |
| `jira_server_info` | Static skeleton status (no network) |

Issue tools are intentionally absent until I8 can be upheld.

## Testing (minimum bar as features land)

- Policy parse / unknown keys / validation unit tests.
- Guard denial uniformity (I2).
- wiremock for Jira client methods.
- MCP integration tests through the library server (not only pure helpers).
- Adversarial review of guard changes against this document.

## Releases

Annotated version tags without a `v` prefix (`0.1.0`), matching
`[workspace.package] version`. `.github/workflows/release.yml` builds
linux-gnu + aarch64-apple-darwin, creates a GitHub release, then publishes
`jirakeep-core` before `jirakeep` via crates.io Trusted Publishing.
