//! HTTP-level integration tests for the Jira client (wiremock).

use jirakeep_core::client::{AuthMode, Credentials, JiraClient};
use serde_json::json;
use wiremock::matchers::{any, header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "SUPERSECRETTOKEN123";
const EMAIL: &str = "agent@example.com";
const UA: &str = "jirakeep-test/0.0.0 (+test)";

fn creds() -> Credentials {
    Credentials {
        email: EMAIL.into(),
        token: TOKEN.into(),
    }
}

fn basic_client(server: &MockServer) -> JiraClient {
    JiraClient::with_auth_mode(&server.uri(), UA, AuthMode::Basic).expect("client")
}

fn bearer_client(server: &MockServer) -> JiraClient {
    JiraClient::with_auth_mode(&server.uri(), UA, AuthMode::Bearer).expect("client")
}

#[tokio::test]
async fn myself_and_account_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accountId": "acc-1",
            "displayName": "Agent",
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let me = c.myself(&creds()).await.expect("myself");
    assert_eq!(me["accountId"], json!("acc-1"));
    assert_eq!(c.account_id(&creds()).await.unwrap(), "acc-1");
}

#[tokio::test]
async fn get_issue() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": "PROJ-1",
            "id": "10001",
            "fields": {"summary": "hello", "project": {"key": "PROJ"}},
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let issue = c
        .get_issue(&creds(), "PROJ-1", Some("summary,project"))
        .await
        .unwrap();
    assert_eq!(issue["key"], json!("PROJ-1"));
    assert_eq!(issue["fields"]["summary"], json!("hello"));
}

#[tokio::test]
async fn search_jql() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{"key": "PROJ-1", "fields": {"summary": "a"}}],
            "nextPageToken": "tok2",
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let out = c
        .search(&creds(), "project = PROJ", &["summary"], 10, None, None)
        .await
        .unwrap();
    assert_eq!(out["issues"].as_array().unwrap().len(), 1);
    assert_eq!(out["nextPageToken"], json!("tok2"));
}

#[tokio::test]
async fn search_falls_back_to_legacy_on_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "errorMessages": ["not found"],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{"key": "LEG-1"}],
            "startAt": 0,
            "maxResults": 50,
            "total": 1,
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let out = c
        .search(
            &creds(),
            "order by created",
            &["summary"],
            50,
            None,
            Some(0),
        )
        .await
        .unwrap();
    assert_eq!(out["issues"][0]["key"], json!("LEG-1"));
}

#[tokio::test]
async fn add_comment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue/PROJ-1/comment"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "100",
            "body": {"type": "doc"},
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let out = c.add_comment(&creds(), "PROJ-1", "hi", None).await.unwrap();
    assert_eq!(out["id"], json!("100"));
}

#[tokio::test]
async fn download_attachment_relative_and_same_origin_urls() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/secure/attachment/10001/notes.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    // A relative content URL resolves against the (here: http) base URL.
    let bytes = c
        .download_attachment_bytes(&creds(), "/secure/attachment/10001/notes.txt")
        .await
        .expect("relative download");
    assert_eq!(bytes, b"hello");
    // An absolute content URL on the same origin is honored too.
    let absolute = format!("{}/secure/attachment/10001/notes.txt", server.uri());
    let bytes = c
        .download_attachment_bytes(&creds(), &absolute)
        .await
        .expect("same-origin absolute download");
    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn download_attachment_never_contacts_a_foreign_host() {
    let jira = MockServer::start().await;
    let foreign = MockServer::start().await;
    // Any request reaching the foreign host — credentialed or not — fails
    // the test on drop via the expect(0) verification.
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"stolen".to_vec()))
        .expect(0)
        .mount(&foreign)
        .await;

    let c = basic_client(&jira);
    let off_origin = format!("{}/collect", foreign.uri());
    let err = c
        .download_attachment_bytes(&creds(), &off_origin)
        .await
        .expect_err("off-origin content URL must be refused");
    let msg = format!("{err:#}");
    assert!(!msg.contains(TOKEN), "token leaked into error: {msg}");
    assert!(
        !msg.contains(&foreign.uri()),
        "refusal echoed the foreign URL: {msg}"
    );
    let received = foreign.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "a request (and its Authorization header) reached the foreign host"
    );
}

#[tokio::test]
async fn bearer_auth_sends_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accountId": "dc-user",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = bearer_client(&server);
    let me = c
        .myself(&Credentials {
            email: String::new(),
            token: TOKEN.into(),
        })
        .await
        .unwrap();
    assert_eq!(me["accountId"], json!("dc-user"));
}

#[tokio::test]
async fn error_body_does_not_echo_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/rest/api/3/issue/.*"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "errorMessages": ["Unauthorized"],
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let err = c.get_issue(&creds(), "X-1", None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains(TOKEN), "token leaked into error: {msg}");
    assert!(msg.contains("401") || msg.contains("Unauthorized"));
}

#[tokio::test]
async fn server_info_embeds_base_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/serverInfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "serverTitle": "Jira",
            "version": "9.0.0",
        })))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    let info = c.server_info(&creds()).await.unwrap();
    assert_eq!(info["url"], json!(server.uri()));
    assert_eq!(info["version"], json!("9.0.0"));
}
