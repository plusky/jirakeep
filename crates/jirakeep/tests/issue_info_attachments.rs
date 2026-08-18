//! MCP-level tests: `issue_info` must not disclose capability-gated field
//! families through its unprojected `read` fetch (I6) — attachment metadata
//! without `attachments`, comment bodies without `comments`, restricted
//! comments ever (I5: no opt-in exists on this route), worklog always —
//! while `list_attachments` / `issue_comments` stay uniformly denied (I2).
//! Also pins I14 scrubbing of declared link custom fields on this route.
//! Runs the library server over an in-process stdio-style transport against
//! a wiremock Jira.

use std::sync::Arc;
use std::time::Duration;

use jirakeep::config::{AuthModeCli, Cli, Transport};
use jirakeep::server::{jira_client, JiraKeep};
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::Policy;
use rmcp::ServiceExt as _;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream};
use tokio::time::timeout;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUE_KEY: &str = "HR-3";
const SECRET_FILENAME: &str = "severance-agreement-smith.pdf";
const PUBLIC_COMMENT: &str = "public onboarding note";
const RESTRICTED_COMMENT: &str = "manager-only severance discussion";
const WORKLOG_NOTE: &str = "billing-sensitive worklog note";

/// Policy from the finding: `read` (and friends) without `attachments`.
const POLICY_NO_ATTACHMENTS: &str = r#"
default_action = "deny"
[[rule]]
name = "read-but-no-attachments"
action = "restrict"
capabilities = ["read", "summary", "comments"]
[rule.match]
projects = ["HR"]
"#;

/// The reviewer's scenario: `read` + `summary` only — no `comments`.
const POLICY_READ_NO_COMMENTS: &str = r#"
default_action = "deny"
[[rule]]
name = "read-without-comments"
action = "restrict"
capabilities = ["read", "summary"]
[rule.match]
projects = ["HR"]
"#;

/// Same rule, but with `attachments` granted.
const POLICY_WITH_ATTACHMENTS: &str = r#"
default_action = "deny"
[[rule]]
name = "read-and-attachments"
action = "restrict"
capabilities = ["read", "summary", "comments", "attachments"]
[rule.match]
projects = ["HR"]
"#;

/// Full issue body as Jira returns it without a fields projection: the
/// default navigable field set includes `attachment`.
fn issue_body() -> Value {
    json!({
        "key": ISSUE_KEY,
        "id": "10042",
        "fields": {
            "summary": "Onboarding paperwork",
            "description": "full body",
            "project": {"key": "HR"},
            "status": {"name": "Open"},
            "priority": {"name": "Medium"},
            "issuetype": {"name": "Task"},
            "labels": [],
            "components": [],
            "created": "2020-01-01T00:00:00.000+0000",
            "reporter": {"accountId": "u1"},
            "security": Value::Null,
            "attachment": [{
                "id": "20001",
                "filename": SECRET_FILENAME,
                "size": 1234,
                "created": "2020-01-02T00:00:00.000+0000",
                "author": {"accountId": "u1"},
                "content": "https://example.invalid/attachment/content/20001",
            }],
            "comment": {
                "comments": [
                    {"id": "30001", "body": PUBLIC_COMMENT},
                    {
                        "id": "30002",
                        "body": RESTRICTED_COMMENT,
                        "visibility": {"type": "role", "value": "HR Managers"},
                    },
                ],
                "maxResults": 2,
                "total": 2,
                "startAt": 0,
            },
            "worklog": {
                "worklogs": [{"id": "40001", "comment": WORKLOG_NOTE, "timeSpent": "2h"}],
                "total": 1,
            },
            "watches": {"watchCount": 3, "isWatching": false},
            "votes": {"votes": 1, "hasVoted": false},
        }
    })
}

async fn mock_jira() -> MockServer {
    let jira = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/3/issue/{ISSUE_KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue_body()))
        .mount(&jira)
        .await;
    jira
}

/// Minimal newline-delimited JSON-RPC client over one end of a duplex pipe.
struct McpClient {
    reader: tokio::io::Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
    next_id: u64,
}

impl McpClient {
    async fn send(&mut self, msg: Value) {
        let mut line = msg.to_string();
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .expect("write to server");
    }

    async fn recv_result(&mut self, id: u64) -> Value {
        loop {
            let line = timeout(Duration::from_secs(30), self.reader.next_line())
                .await
                .expect("server response timed out")
                .expect("transport read")
                .expect("server closed the transport");
            let msg: Value = serde_json::from_str(&line).expect("server sent invalid JSON");
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                return msg
                    .get("result")
                    .cloned()
                    .unwrap_or_else(|| panic!("error response: {msg}"));
            }
        }
    }

    async fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }))
        .await;
        self.recv_result(id).await
    }
}

/// Build the library server with `policy_toml`, serve it over an in-process
/// transport, and return an initialized MCP client.
async fn connect(jira_url: &str, policy_toml: &str) -> McpClient {
    let cli = Arc::new(Cli {
        jira_server: jira_url.to_owned(),
        auth_mode: AuthModeCli::Basic,
        api_version: None,
        transport: Transport::Stdio,
        host: "127.0.0.1".into(),
        port: 0,
        api_key_header: "ApiKey".into(),
        email_header: "X-Atlassian-Email".into(),
        api_key: Some("test-token".into()),
        api_key_file: None,
        email: Some("tester@example.com".into()),
        email_file: None,
        read_only: false,
        policy: None,
        audit_config: None,
    });
    let guard = Arc::new(Guard::new(
        Policy::from_toml_str(policy_toml).expect("policy parses"),
    ));
    let jira = Arc::new(jira_client(&cli).expect("jira client"));
    let server = JiraKeep::new(cli, guard, jira).expect("server builds");

    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });

    let (rd, wr) = tokio::io::split(client_io);
    let mut mcp = McpClient {
        reader: BufReader::new(rd).lines(),
        writer: wr,
        next_id: 0,
    };
    mcp.next_id += 1;
    let id = mcp.next_id;
    mcp.send(json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "jirakeep-test", "version": "0.0.0"},
        },
    }))
    .await;
    let _ = mcp.recv_result(id).await;
    mcp.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    mcp
}

fn tool_text(result: &Value) -> &str {
    result["content"][0]["text"]
        .as_str()
        .expect("text content block")
}

#[tokio::test]
async fn issue_info_strips_attachments_like_list_attachments_denial() {
    let jira = mock_jira().await;
    let mut mcp = connect(&jira.uri(), POLICY_NO_ATTACHMENTS).await;

    // issue_info serves the full Read body — minus attachment metadata.
    let result = mcp
        .call_tool("issue_info", json!({"keys": [ISSUE_KEY]}))
        .await;
    assert_ne!(
        result.get("isError"),
        Some(&json!(true)),
        "issue_info errored: {result}"
    );
    let text = tool_text(&result);
    assert!(
        !text.contains(SECRET_FILENAME),
        "attachment filename leaked through issue_info: {text}"
    );
    assert!(
        !text.contains("attachment"),
        "attachment field (or a removal marker) leaked through issue_info: {text}"
    );
    assert!(
        !text.contains(RESTRICTED_COMMENT),
        "restricted-visibility comment leaked through issue_info (I5): {text}"
    );
    assert!(
        !text.contains(WORKLOG_NOTE) && !text.contains("worklog"),
        "worklog content leaked through issue_info: {text}"
    );
    let payload: Value = serde_json::from_str(text).expect("payload is JSON");
    let issue = &payload["issues"][0];
    assert_eq!(issue["key"], json!(ISSUE_KEY));
    // The rest of the full body is still served normally (not summary-projected).
    assert_eq!(issue["fields"]["description"], json!("full body"));
    assert_eq!(issue["fields"]["summary"], json!("Onboarding paperwork"));
    assert!(issue["fields"].get("attachment").is_none());
    // `comments` is granted: the container is served, minus the restricted
    // comment, with total tracking the served list (silent removal, I3).
    let comments = issue["fields"]["comment"]["comments"]
        .as_array()
        .expect("comment container served when comments granted");
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0]["body"], json!(PUBLIC_COMMENT));
    assert_eq!(issue["fields"]["comment"]["total"], json!(1));
    assert!(payload["restricted"]
        .as_array()
        .expect("restricted array")
        .is_empty());

    // ... alongside the existing list_attachments denial (I2 uniform text).
    let denied = mcp
        .call_tool("list_attachments", json!({"key": ISSUE_KEY}))
        .await;
    assert_eq!(denied.get("isError"), Some(&json!(true)), "{denied}");
    assert_eq!(
        tool_text(&denied),
        format!("Issue {ISSUE_KEY} is not accessible through this server")
    );
}

#[tokio::test]
async fn issue_info_strips_comments_without_comments_capability() {
    let jira = mock_jira().await;
    let mut mcp = connect(&jira.uri(), POLICY_READ_NO_COMMENTS).await;

    // issue_comments is denied under this policy (Comments gate, I2) ...
    let denied = mcp
        .call_tool("issue_comments", json!({"key": ISSUE_KEY}))
        .await;
    assert_eq!(denied.get("isError"), Some(&json!(true)), "{denied}");
    assert_eq!(
        tool_text(&denied),
        format!("Issue {ISSUE_KEY} is not accessible through this server")
    );

    // ... so issue_info must not hand out the same comment bodies (I6).
    let result = mcp
        .call_tool("issue_info", json!({"keys": [ISSUE_KEY]}))
        .await;
    assert_ne!(
        result.get("isError"),
        Some(&json!(true)),
        "issue_info errored: {result}"
    );
    let text = tool_text(&result);
    assert!(
        !text.contains(PUBLIC_COMMENT) && !text.contains(RESTRICTED_COMMENT),
        "comment bodies leaked through issue_info without the comments capability: {text}"
    );
    let payload: Value = serde_json::from_str(text).expect("payload is JSON");
    let issue = &payload["issues"][0];
    assert!(issue["fields"].get("comment").is_none());
    assert!(issue["fields"].get("attachment").is_none());
    assert!(issue["fields"].get("worklog").is_none());
    // Count-only families remain part of the Read body (documented in I6).
    assert_eq!(issue["fields"]["watches"]["watchCount"], json!(3));
    assert_eq!(issue["fields"]["votes"]["votes"], json!(1));
    assert_eq!(issue["fields"]["description"], json!("full body"));
}

/// Deny SEC; declare the classic Epic Link custom field for I14 scrubbing.
const POLICY_EPIC_LINK: &str = r#"
default_action = "allow"
[global]
link_custom_fields = ["customfield_10014"]
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC"]
"#;

/// I14: a denied epic key in a declared link custom field must not survive
/// issue_info's unprojected Read body, and nothing reports the scrub (I3).
#[tokio::test]
async fn issue_info_scrubs_declared_epic_link_custom_field() {
    let jira = MockServer::start().await;
    let mut body = issue_body();
    body["fields"]["customfield_10014"] = json!("SEC-100");
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/3/issue/{ISSUE_KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&jira)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/SEC-100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": "SEC-100",
            "id": "7",
            "fields": {
                "summary": "codename embargo",
                "project": {"key": "SEC"},
                "created": "2020-01-01T00:00:00.000+0000",
                "security": Value::Null,
            }
        })))
        .mount(&jira)
        .await;
    let mut mcp = connect(&jira.uri(), POLICY_EPIC_LINK).await;

    let result = mcp
        .call_tool("issue_info", json!({"keys": [ISSUE_KEY]}))
        .await;
    assert_ne!(result.get("isError"), Some(&json!(true)), "{result}");
    let text = tool_text(&result);
    assert!(
        !text.contains("SEC-100"),
        "denied epic key leaked through a declared link custom field: {text}"
    );
    let payload: Value = serde_json::from_str(text).expect("payload is JSON");
    let issue = &payload["issues"][0];
    assert_eq!(issue["fields"]["customfield_10014"], Value::Null);
    // Silent to the client (I3): nothing reports the removal.
    assert!(payload["restricted"]
        .as_array()
        .expect("restricted array")
        .is_empty());
}

#[tokio::test]
async fn issue_info_serves_attachments_when_capability_granted() {
    let jira = mock_jira().await;
    let mut mcp = connect(&jira.uri(), POLICY_WITH_ATTACHMENTS).await;

    let result = mcp
        .call_tool("issue_info", json!({"keys": [ISSUE_KEY]}))
        .await;
    assert_ne!(
        result.get("isError"),
        Some(&json!(true)),
        "issue_info errored: {result}"
    );
    let text = tool_text(&result);
    let payload: Value = serde_json::from_str(text).expect("payload is JSON");
    let atts = payload["issues"][0]["fields"]["attachment"]
        .as_array()
        .expect("attachment array served when capability granted");
    assert_eq!(atts[0]["filename"], json!(SECRET_FILENAME));
    // Even with every read capability granted, this route has no restricted
    // opt-in, so the restricted comment stays out (I5) and worklog stays out.
    assert!(
        !text.contains(RESTRICTED_COMMENT),
        "restricted-visibility comment leaked through issue_info (I5): {text}"
    );
    assert!(payload["issues"][0]["fields"].get("worklog").is_none());
}
