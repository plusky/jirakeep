//! Data Center end-to-end (issue #14): bearer mode against a wiremock Jira
//! that serves ONLY `/rest/api/2`. Pins that bearer defaults to REST v2,
//! that v2 search pages with `startAt`, and that the v2 envelope's
//! `total`/`startAt` never reach the MCP client (I3). Guard semantics are
//! version-independent (I2, I4).

use std::sync::Arc;

use jirakeep::config::{AuthModeCli, Cli, Transport};
use jirakeep::server::{jira_client, JiraKeep};
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::Policy;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, RoleServer, ServiceExt as _};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, body_partial_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "DC-1";

/// Bearer PAT config with no explicit `--api-version`: the v2 default must
/// carry the whole flow.
fn cli(jira_server: &str) -> Arc<Cli> {
    Arc::new(Cli {
        jira_server: jira_server.to_owned(),
        auth_mode: AuthModeCli::Bearer,
        api_version: None,
        transport: Transport::Stdio,
        host: "127.0.0.1".into(),
        port: 8000,
        api_key_header: "ApiKey".into(),
        email_header: "X-Atlassian-Email".into(),
        api_key: Some("DCPATTOKEN".into()),
        api_key_file: None,
        email: None,
        email_file: None,
        read_only: false,
        policy: None,
        audit_config: None,
    })
}

fn issue_body() -> Value {
    json!({
        "key": KEY,
        "id": "10001",
        "fields": {
            "summary": "dc issue",
            "project": {"key": "DC"},
            "status": {"name": "Open"},
            "priority": {"name": "Medium"},
            "issuetype": {"name": "Bug"},
            "labels": [],
            "components": [],
            "created": "2020-01-01T00:00:00.000+0000",
            "reporter": {"accountId": "u1"},
            "security": Value::Null,
        }
    })
}

/// A Jira DC stand-in: only `/rest/api/2` exists; any `/rest/api/3` request
/// fails the test when the [`MockServer`] drops.
async fn mock_dc_jira() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(path_regex(r"^/rest/api/3/.*"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accountId": "dc-user"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/2/issue/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue_body()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/2/issue/{KEY}/comment")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [{"id": "30001", "body": "dc comment"}],
            "startAt": 0,
            "maxResults": 1,
            "total": 1,
        })))
        .mount(&server)
        .await;
    // v2 search: offset paging — the guard's fetch must carry `startAt`.
    Mock::given(method("POST"))
        .and(path("/rest/api/2/search"))
        .and(body_partial_json(json!({"startAt": 3})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [issue_body()],
            "startAt": 3,
            "maxResults": 20,
            "total": 42,
        })))
        .expect(1)
        .mount(&server)
        .await;
    server
}

async fn connect(
    mock: &MockServer,
) -> (
    RunningService<RoleClient, ()>,
    RunningService<RoleServer, JiraKeep>,
) {
    let cfg = cli(&mock.uri());
    let policy = Policy::from_toml_str("default_action = \"allow\"\n").expect("policy");
    let guard = Arc::new(Guard::new(policy));
    let jira = Arc::new(jira_client(&cfg).expect("jira client"));
    let server = JiraKeep::new(cfg, guard, jira).expect("server");
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(server.serve(server_io));
    let client = ().serve(client_io).await.expect("client handshake");
    let server = serving
        .await
        .expect("server task")
        .expect("server handshake");
    (client, server)
}

async fn call(client: &RunningService<RoleClient, ()>, tool: &str, args: Value) -> CallToolResult {
    let args = args.as_object().cloned().expect("arguments object");
    client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(args))
        .await
        .unwrap_or_else(|e| panic!("tools/call {tool}: {e}"))
}

fn result_json(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|t| t.text.as_str())
        .expect("text content");
    serde_json::from_str(text).expect("json body")
}

#[tokio::test]
async fn bearer_mode_works_end_to_end_on_rest_api_2_only() {
    let mock = mock_dc_jira().await;
    let (client, server) = connect(&mock).await;

    let info = call(&client, "issue_info", json!({"keys": [KEY]})).await;
    assert_ne!(info.is_error, Some(true), "{info:?}");
    let body = result_json(&info);
    assert_eq!(body["issues"][0]["key"], json!(KEY));
    assert_eq!(body["restricted"], json!([]));

    let comments = call(&client, "issue_comments", json!({"key": KEY})).await;
    assert_ne!(comments.is_error, Some(true), "{comments:?}");
    let body = result_json(&comments);
    assert_eq!(body["comments"][0]["body"], json!("dc comment"));

    let search = call(
        &client,
        "issues_search",
        json!({"jql": "project = DC", "max_results": 10, "start_at": 3}),
    )
    .await;
    assert_ne!(search.is_error, Some(true), "{search:?}");
    let body = result_json(&search);
    assert_eq!(body["issues"][0]["key"], json!(KEY));
    // v2 has no token pagination: the field exists and is null.
    assert_eq!(body["nextPageToken"], Value::Null);
    // I3: the v2 envelope's total/startAt/maxResults never reach the client.
    let keys: Vec<&str> = body
        .as_object()
        .expect("search result object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["issues", "nextPageToken"]);

    let _ = client.cancel().await;
    let _ = server.cancel().await;
    // MockServer::drop verifies zero /rest/api/3 hits and one v2 search.
}

/// #15: on v2 the created issue's `description` is the plain string, not an
/// ADF doc — the exact body match leaves an ADF payload with no mock.
#[tokio::test]
async fn create_issue_description_is_plain_string_on_v2() {
    let mock = MockServer::start().await;
    Mock::given(path_regex(r"^/rest/api/3/.*"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .and(body_json(json!({
            "fields": {
                "project": {"key": "DC"},
                "summary": "dc summary",
                "issuetype": {"name": "Task"},
                "description": "plain body",
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10002",
            "key": "DC-2",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let (client, server) = connect(&mock).await;
    let created = call(
        &client,
        "create_issue",
        json!({
            "project_key": "DC",
            "summary": "dc summary",
            "issue_type": "Task",
            "description": "plain body",
        }),
    )
    .await;
    assert_ne!(created.is_error, Some(true), "{created:?}");
    assert_eq!(result_json(&created)["key"], json!("DC-2"));

    let _ = client.cancel().await;
    let _ = server.cancel().await;
}

/// Policy that consults caller identity (`created_by_me`).
const IDENTITY_POLICY: &str = r#"
default_action = "deny"
[[rule]]
name = "mine"
action = "allow"
[rule.match]
created_by_me = true
"#;

/// Issue #16 preflight: server-held credentials + identity-consulting
/// policy + unusable `/myself` must fail loudly, naming the endpoint and
/// the consequence — without leaking the token (I12).
#[tokio::test]
async fn identity_preflight_fails_loudly_when_myself_is_unusable() {
    let mock = MockServer::start().await;
    // Cloud-shaped body on the v2 surface: no name/key → no identity.
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accountId": "acc-1"})))
        .mount(&mock)
        .await;
    let cfg = cli(&mock.uri());
    let policy = Policy::from_toml_str(IDENTITY_POLICY).expect("policy");
    let guard = Arc::new(Guard::new(policy));
    let jira = Arc::new(jira_client(&cfg).expect("jira client"));
    let server = JiraKeep::new(cfg, guard, jira).expect("server");
    let err = server
        .preflight_identity()
        .await
        .expect_err("preflight must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("/myself"), "no endpoint named: {msg}");
    assert!(msg.contains("created_by_me"), "no consequence named: {msg}");
    assert!(!msg.contains("DCPATTOKEN"), "token leaked: {msg}");
}

/// A policy without identity criteria never contacts `/myself` at startup.
#[tokio::test]
async fn preflight_is_skipped_without_identity_rules() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock)
        .await;
    let cfg = cli(&mock.uri());
    let policy = Policy::from_toml_str("default_action = \"allow\"\n").expect("policy");
    let guard = Arc::new(Guard::new(policy));
    let jira = Arc::new(jira_client(&cfg).expect("jira client"));
    let server = JiraKeep::new(cfg, guard, jira).expect("server");
    server
        .preflight_identity()
        .await
        .expect("preflight is a no-op");
}

/// The shipped binary bails at startup (stdio mode) when the preflight
/// fails, instead of serving a silent blackout.
#[tokio::test]
async fn startup_errors_loudly_in_stdio_mode_on_identity_preflight_failure() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(&policy_path, IDENTITY_POLICY).expect("write policy");
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_jirakeep"))
        .args([
            "--jira-server",
            &mock.uri(),
            "--transport",
            "stdio",
            "--auth-mode",
            "bearer",
            "--api-key",
            "DCPATTOKEN",
            "--policy",
            policy_path.to_str().expect("utf-8 path"),
        ])
        .env_remove("JIRA_API_VERSION")
        .env_remove("JIRA_API_TOKEN_FILE")
        .env_remove("JIRA_EMAIL")
        .env_remove("JIRA_EMAIL_FILE")
        .env_remove("MCP_READ_ONLY")
        .env_remove("JIRAKEEP_AUDIT_CONFIG")
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .expect("spawn jirakeep");
    assert!(!out.status.success(), "startup must fail loudly");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/myself"), "stderr: {stderr}");
    assert!(!stderr.contains("DCPATTOKEN"), "token leaked: {stderr}");
}

/// Issue #16: v2 writes are name-based — assignment sends
/// `{"assignee":{"name":…}}` and the watchers body is the JSON-encoded
/// username string. v3 accountId shapes are pinned in server_mcp tests.
#[tokio::test]
async fn v2_assign_and_watcher_send_name_based_shapes() {
    let mock = MockServer::start().await;
    Mock::given(path_regex(r"^/rest/api/3/.*"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/2/issue/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue_body()))
        .mount(&mock)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/rest/api/2/issue/{KEY}")))
        .and(body_json(json!({"fields": {"assignee": {"name": "jdoe"}}})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/rest/api/2/issue/{KEY}/watchers")))
        .and(body_json(json!("jdoe")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;

    let (client, server) = connect(&mock).await;
    let assign = call(
        &client,
        "assign_issue",
        json!({"key": KEY, "account_id": "jdoe"}),
    )
    .await;
    assert_ne!(assign.is_error, Some(true), "{assign:?}");
    let watch = call(
        &client,
        "add_watcher",
        json!({"key": KEY, "account_id": "jdoe"}),
    )
    .await;
    assert_ne!(watch.is_error, Some(true), "{watch:?}");

    let _ = client.cancel().await;
    let _ = server.cancel().await;
    // MockServer::drop verifies the v2 wire shapes were hit exactly once.
}
