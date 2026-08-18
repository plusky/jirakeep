//! HTTP-level integration tests for the Jira client (wiremock).

use jirakeep_core::client::{AuthMode, Credentials, JiraClient};
use serde_json::json;
use wiremock::matchers::{any, body_json, header, method, path, path_regex};
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
async fn download_attachment_within_cap_and_unbounded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/attachments/content/1"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 512]))
        .mount(&server)
        .await;

    let c = basic_client(&server);
    // Exactly at the cap is allowed.
    let bytes = c
        .download_attachment_bytes(&creds(), "/attachments/content/1", Some(512))
        .await
        .unwrap();
    assert_eq!(bytes.len(), 512);
    // No cap (policy max_attachment_bytes = 0) stays unlimited.
    let bytes = c
        .download_attachment_bytes(&creds(), "/attachments/content/1", None)
        .await
        .unwrap();
    assert_eq!(bytes.len(), 512);
}

#[tokio::test]
async fn download_attachment_refuses_body_over_cap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/attachments/content/2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 4096]))
        .mount(&server)
        .await;

    // Even if attachment metadata understated the size, the real byte
    // count is what the cap is enforced against.
    let c = basic_client(&server);
    let err = c
        .download_attachment_bytes(&creds(), "/attachments/content/2", Some(1024))
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    assert!(!msg.contains(TOKEN), "token leaked into error: {msg}");
}

#[tokio::test]
async fn download_attachment_aborts_stream_without_content_length() {
    // wiremock always sets Content-Length, so use a raw socket to serve a
    // chunked response with no declared length: the cap must still hold,
    // enforced against the bytes actually received.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = std::io::Read::read(&mut sock, &mut buf);
        let mut resp: Vec<u8> = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..8 {
            resp.extend_from_slice(b"400\r\n");
            resp.extend_from_slice(&[b'x'; 1024]);
            resp.extend_from_slice(b"\r\n");
        }
        resp.extend_from_slice(b"0\r\n\r\n");
        let _ = std::io::Write::write_all(&mut sock, &resp);
    });

    let c = JiraClient::new(&format!("http://{addr}"), UA).unwrap();
    let err = c
        .download_attachment_bytes(&creds(), "/attachments/content/3", Some(1024))
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("exceeds"), "unexpected error: {msg}");
    served.join().unwrap();
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
        .download_attachment_bytes(&creds(), "/secure/attachment/10001/notes.txt", None)
        .await
        .expect("relative download");
    assert_eq!(bytes, b"hello");
    // An absolute content URL on the same origin is honored too.
    let absolute = format!("{}/secure/attachment/10001/notes.txt", server.uri());
    let bytes = c
        .download_attachment_bytes(&creds(), &absolute, None)
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
        .download_attachment_bytes(&creds(), &off_origin, None)
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
    // Bearer defaults to the DC surface: /rest/api/2.
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
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
async fn search_v2_uses_offset_paging_and_ignores_page_token() {
    let server = MockServer::start().await;
    // Exact-body match: startAt is sent, nextPageToken never enters the
    // payload even when a caller supplies one, and no /search/jql call is
    // made (any other request 404s the test).
    Mock::given(method("POST"))
        .and(path("/rest/api/2/search"))
        .and(body_json(json!({
            "jql": "project = DC",
            "maxResults": 10,
            "fields": ["summary"],
            "startAt": 5,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{"key": "DC-6", "fields": {"summary": "s"}}],
            "startAt": 5,
            "maxResults": 10,
            "total": 42,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = bearer_client(&server);
    let out = c
        .search(
            &creds(),
            "project = DC",
            &["summary"],
            10,
            Some("stale-token"),
            Some(5),
        )
        .await
        .unwrap();
    assert_eq!(out["issues"][0]["key"], json!("DC-6"));
    assert!(out.get("nextPageToken").is_none());
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
