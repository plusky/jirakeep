//! HTTP-level integration tests for guard + client (wiremock).

use jirakeep_core::client::{Credentials, JiraClient};
use jirakeep_core::guard::Guard;
use jirakeep_core::policy::{Access, Capability, Policy};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "GUARDTESTSECRET999";
const EMAIL: &str = "guard@example.com";
const UA: &str = "jirakeep-guard-test/0.0.0";

fn creds() -> Credentials {
    Credentials {
        email: EMAIL.into(),
        token: TOKEN.into(),
    }
}

fn client(server: &MockServer) -> JiraClient {
    JiraClient::new(&server.uri(), UA).expect("client")
}

fn guard(toml: &str) -> Guard {
    Guard::new(Policy::from_toml_str(toml).expect("policy"))
}

fn issue(key: &str, project: &str, security: Option<&str>) -> serde_json::Value {
    let mut fields = json!({
        "summary": "s",
        "project": {"key": project},
        "status": {"name": "Open"},
        "priority": {"name": "Medium"},
        "issuetype": {"name": "Bug"},
        "labels": [],
        "components": [],
        "created": "2020-01-01T00:00:00.000+0000",
        "reporter": {"accountId": "u1"},
        "security": serde_json::Value::Null,
    });
    if let Some(name) = security {
        fields["security"] = json!({"name": name});
    }
    json!({"key": key, "id": "1", "fields": fields})
}

#[tokio::test]
async fn assess_denies_security_project() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/SEC-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("SEC-1", "SEC", None)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/OPEN-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("OPEN-1", "OPEN", None)))
        .mount(&server)
        .await;

    let g = guard(
        r#"
default_action = "allow"
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC*"]
"#,
    );
    let out = g
        .assess(
            &client(&server),
            &creds(),
            &["SEC-1".into(), "OPEN-1".into()],
            None,
        )
        .await;
    assert!(matches!(out["SEC-1"].0, Access::Denied { .. }));
    assert!(out["OPEN-1"].0.allows(Capability::Read));
}

#[tokio::test]
async fn assess_fail_closed_on_missing_issue() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/rest/api/3/issue/.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "errorMessages": ["Issue does not exist"],
        })))
        .mount(&server)
        .await;

    let g = guard("default_action = \"allow\"\n");
    let out = g
        .assess(&client(&server), &creds(), &["NOPE-1".into()], None)
        .await;
    assert!(matches!(
        out["NOPE-1"].0,
        Access::Denied { ref rule } if rule == "unavailable"
    ));
}

#[tokio::test]
async fn assess_security_level_deny() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/X-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue(
            "X-1",
            "X",
            Some("Red Embargo"),
        )))
        .mount(&server)
        .await;

    let g = guard(
        r#"
default_action = "allow"
[[rule]]
name = "embargo"
action = "deny"
[rule.match]
security_levels = ["*Embargo*"]
"#,
    );
    let out = g
        .assess(&client(&server), &creds(), &["X-1".into()], None)
        .await;
    assert!(!out["X-1"].0.allows(Capability::Summary));
}

#[tokio::test]
async fn search_filtered_drops_denied_silently() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [
                issue("SEC-1", "SEC", None),
                issue("OPEN-1", "OPEN", None),
            ],
        })))
        .mount(&server)
        .await;

    let g = guard(
        r#"
default_action = "allow"
[[rule]]
name = "hide"
action = "deny"
[rule.match]
projects = ["SEC"]
"#,
    );
    let window = g
        .search_filtered(
            &client(&server),
            &creds(),
            "order by created",
            10,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(window.issues.len(), 1);
    assert_eq!(window.issues[0]["key"], json!("OPEN-1"));
    assert_eq!(window.dropped_keys, vec!["SEC-1".to_string()]);
    // Client path would only see issues + nextPageToken — never dropped.
}

#[tokio::test]
async fn denial_text_has_no_token() {
    let msg = Guard::denial("SEC-1");
    assert!(!msg.contains(TOKEN));
    assert_eq!(msg, "Issue SEC-1 is not accessible through this server");
}
