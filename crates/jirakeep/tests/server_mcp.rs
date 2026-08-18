//! MCP integration tests through the library server (DESIGN.md testing bar).
//!
//! A real rmcp client speaks MCP to [`JiraKeep`] over an in-process duplex
//! transport, with wiremock standing in for Jira Cloud. This pins invariant
//! I7 at the tool boundary: the `update_issue_fields` *handler* must refuse
//! privileged and capability-owned fields. Unit tests on the `refused_field`
//! helper alone would stay green if the handler stopped consulting it.

use std::sync::Arc;

use jirakeep::config::{AuthModeCli, Cli, Transport};
use jirakeep::server::{jira_client, JiraKeep};
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::Policy;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, RoleServer, ServiceExt as _};
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "OPS-1";

fn cli(jira_server: &str) -> Arc<Cli> {
    Arc::new(Cli {
        jira_server: jira_server.to_owned(),
        auth_mode: AuthModeCli::Basic,
        api_version: None,
        transport: Transport::Stdio,
        host: "127.0.0.1".into(),
        port: 8000,
        api_key_header: "ApiKey".into(),
        email_header: "X-Atlassian-Email".into(),
        api_key: Some("MCPTESTTOKEN".into()),
        api_key_file: None,
        email: Some("mcp-test@example.com".into()),
        email_file: None,
        read_only: false,
        policy: None,
        audit_config: None,
    })
}

/// Classification body served to the guard's assessment fetch (I8): an
/// unrestricted issue in an ordinary project, so the default-allow policy
/// grants every capability and any refusal below can only come from the I7
/// field gate inside the handler.
fn classification_body() -> Value {
    json!({
        "key": KEY,
        "id": "1",
        "fields": {
            "summary": "s",
            "project": {"key": "OPS"},
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

/// Start a Jira stand-in that answers the guard classification fetch and
/// counts hits on the edit endpoint (`expected_edits` is verified when the
/// [`MockServer`] drops).
async fn mock_jira(expected_edits: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/api/3/issue/{KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(classification_body()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("/rest/api/3/issue/{KEY}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(expected_edits)
        .mount(&server)
        .await;
    server
}

/// Serve [`JiraKeep`] on one end of an in-process duplex pipe and connect an
/// rmcp client to the other, under a default-allow policy.
async fn connect(
    mock: &MockServer,
) -> (
    RunningService<RoleClient, ()>,
    RunningService<RoleServer, JiraKeep>,
) {
    connect_with_policy(mock, "default_action = \"allow\"\n").await
}

async fn connect_with_policy(
    mock: &MockServer,
    policy_toml: &str,
) -> (
    RunningService<RoleClient, ()>,
    RunningService<RoleServer, JiraKeep>,
) {
    let cfg = cli(&mock.uri());
    let policy = Policy::from_toml_str(policy_toml).expect("policy");
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

async fn shutdown(
    client: RunningService<RoleClient, ()>,
    server: RunningService<RoleServer, JiraKeep>,
) {
    let _ = client.cancel().await;
    let _ = server.cancel().await;
}

async fn call_update_issue_fields(
    client: &RunningService<RoleClient, ()>,
    fields: Value,
) -> CallToolResult {
    let args = json!({"key": KEY, "fields": fields});
    let args = args.as_object().cloned().expect("arguments object");
    client
        .call_tool(CallToolRequestParams::new("update_issue_fields").with_arguments(args))
        .await
        .expect("tools/call update_issue_fields")
}

fn result_text(result: &CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|t| t.text.as_str())
        .expect("text content")
}

/// The I7 pin at the tool boundary: `update_issue_fields` must refuse an
/// `assignee` edit (owned by `Capability::Assign` / `assign_issue`) before
/// any request reaches Jira's edit endpoint. Reverting the handler to the
/// old inline security/project/reporter loop fails this test.
#[tokio::test]
async fn update_issue_fields_refuses_assignee_at_the_tool_boundary() {
    let mock = mock_jira(0).await;
    let (client, server) = connect(&mock).await;

    let result =
        call_update_issue_fields(&client, json!({"assignee": {"accountId": "5b10ac8d"}})).await;

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result_text(&result),
        "field \"assignee\" cannot be set through update_issue_fields"
    );
    shutdown(client, server).await;
    // MockServer::drop verifies the edit endpoint saw zero requests.
}

/// Every capability-owned and privileged field is refused through the
/// server, and a non-object `fields` value is refused too — none of them
/// may produce a Jira edit request.
#[tokio::test]
async fn update_issue_fields_refuses_owned_and_privileged_fields() {
    let mock = mock_jira(0).await;
    let (client, server) = connect(&mock).await;

    for banned in [
        "assignee",
        "resolution",
        "parent",
        "security",
        "project",
        "reporter",
    ] {
        let mut fields = serde_json::Map::new();
        fields.insert(banned.to_owned(), json!({"id": "1"}));
        let result = call_update_issue_fields(&client, Value::Object(fields)).await;
        assert_eq!(result.is_error, Some(true), "field {banned}");
        assert_eq!(
            result_text(&result),
            format!("field \"{banned}\" cannot be set through update_issue_fields"),
            "field {banned}"
        );
    }

    let result = call_update_issue_fields(&client, json!(42)).await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(result_text(&result), "fields must be a JSON object");

    shutdown(client, server).await;
}

/// Ordinary edits still pass through to Jira: proves the guard grants
/// `fields` in this harness, so the refusals above come from the handler's
/// I7 gate and not from a policy denial or handshake failure.
#[tokio::test]
async fn update_issue_fields_permits_ordinary_edit() {
    let mock = mock_jira(1).await;
    let (client, server) = connect(&mock).await;

    let result = call_update_issue_fields(
        &client,
        json!({"summary": "new summary", "labels": ["triage"]}),
    )
    .await;

    assert_ne!(result.is_error, Some(true), "{result:?}");
    let body: Value = serde_json::from_str(result_text(&result)).expect("json body");
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["key"], json!(KEY));
    shutdown(client, server).await;
    // MockServer::drop verifies exactly one edit request went through.
}

/// A search-result issue with the classify fields the guard filters on.
fn search_issue(key: &str, project: &str) -> Value {
    json!({
        "key": key,
        "id": "1",
        "fields": {
            "summary": "s",
            "project": {"key": project},
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

/// `search_filter` executes the saved filter's JQL through the same guarded
/// search path as `issues_search`: policy-denied issues vanish silently and
/// the response carries only `issues` + `nextPageToken` — no counts (I3).
#[tokio::test]
async fn search_filter_runs_filter_jql_through_the_guarded_search() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/filter/10042"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10042",
            "name": "triage",
            "jql": "project in (OPS, SEC)",
            "sharePermissions": [{"type": "group"}],
        })))
        .expect(1)
        .mount(&mock)
        .await;
    // Pins that the filter's stored JQL — not client-supplied text — runs.
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .and(body_partial_json(json!({"jql": "project in (OPS, SEC)"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [search_issue("OPS-7", "OPS"), search_issue("SEC-9", "SEC")],
            "nextPageToken": "tok",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let (client, server) = connect_with_policy(
        &mock,
        r#"
default_action = "allow"
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC"]
"#,
    )
    .await;

    let args = json!({"filter_id": "10042"});
    let result = client
        .call_tool(
            CallToolRequestParams::new("search_filter")
                .with_arguments(args.as_object().cloned().expect("arguments object")),
        )
        .await
        .expect("tools/call search_filter");

    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = result_text(&result);
    assert!(!text.contains("SEC-9"), "denied issue served: {text}");
    let body: Value = serde_json::from_str(text).expect("json body");
    // Identical shape to issues_search: issues + nextPageToken only (I3).
    assert_eq!(body.as_object().expect("object").len(), 2);
    assert_eq!(body["nextPageToken"], json!("tok"));
    let issues = body["issues"].as_array().expect("issues array");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["key"], json!("OPS-7"));
    shutdown(client, server).await;
}

/// `list_filters` serves the projection only: sharing metadata and account
/// ids from the favourite-filter response never reach the client.
#[tokio::test]
async fn list_filters_never_serves_sharing_metadata() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/filter/favourite"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": "10042",
            "name": "triage",
            "description": "weekly",
            "jql": "project = OPS",
            "owner": {"displayName": "Alice", "accountId": "acc-1"},
            "viewUrl": "https://jira.example/issues/?filter=10042",
            "sharePermissions": [{"type": "group", "group": {"name": "staff"}}],
            "sharedUsers": {"items": [{"accountId": "acc-2"}]},
            "subscriptions": {"items": [{"user": {"accountId": "acc-3"}}]},
        }])))
        .mount(&mock)
        .await;
    let (client, server) = connect(&mock).await;

    let result = client
        .call_tool(CallToolRequestParams::new("list_filters"))
        .await
        .expect("tools/call list_filters");

    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = result_text(&result);
    for banned in [
        "sharePermissions",
        "sharedUsers",
        "subscriptions",
        "accountId",
        "acc-1",
        "acc-2",
        "acc-3",
    ] {
        assert!(!text.contains(banned), "{banned} leaked: {text}");
    }
    let body: Value = serde_json::from_str(text).expect("json body");
    assert_eq!(body["filters"][0]["id"], json!("10042"));
    assert_eq!(body["filters"][0]["owner"], json!("Alice"));
    assert_eq!(body["filters"][0]["jql"], json!("project = OPS"));
    shutdown(client, server).await;
}
