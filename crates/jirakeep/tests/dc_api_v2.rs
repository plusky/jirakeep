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
use wiremock::matchers::{body_partial_json, method, path, path_regex};
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
