# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately to
**martin@pluskal.org**. Do not open a public issue for a security report.

This applies in particular to **guard bypasses**: any way to make jirakeep
reveal a policy-denied issue's existence or content, leak filtered-result
counts, expose policy rule names or match criteria, obtain restricted
comments against policy, reach a write tool in read-only mode, treat a
private Jira project as public because an issue has no security level, or
extract the Jira API token from logs, errors, or tool results.

## Scope

jirakeep exposes a Jira Cloud site over MCP behind operator-controlled
security guards. The guards are defined as invariants in `docs/DESIGN.md`.
Security-relevant areas include fail-closed classification, the uniform
denial response, silent search filtering, visibility semantics for projects
without security levels, restricted-comment gating, read-only/disabled-tool
enforcement, and API-token handling. The dependency tree is gated in CI by
`cargo-deny` (RUSTSEC advisories, license and source policy), and the code
is scanned by CodeQL.

## Supported versions

The latest release from `main` is supported.
