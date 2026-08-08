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
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "OPS-1";

fn cli(jira_server: &str) -> Arc<Cli> {
    Arc::new(Cli {
        jira_server: jira_server.to_owned(),
        auth_mode: AuthModeCli::Basic,
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
