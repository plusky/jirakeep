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
async fn assess_never_aliases_requested_key_to_another_issue() {
    // I8 aliasing case: the later-requested key's reported form ("ABC-9")
    // sorts before the earlier fetched key ("ZED-1"). The requested key
    // must bind to the issue fetched for it — never to whichever issue
    // happens to sort last among the fetched bodies.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/ZED-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("ZED-1", "OPEN", None)))
        .mount(&server)
        .await;
    // Moved issue: requesting OLD-9 reports key ABC-9 in a denied project.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/OLD-9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("ABC-9", "SEC", None)))
        .mount(&server)
        .await;

    let g = guard(
        r#"
default_action = "allow"
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC"]
"#,
    );
    let out = g
        .assess(
            &client(&server),
            &creds(),
            &["ZED-1".into(), "OLD-9".into()],
            None,
        )
        .await;
    // OLD-9 is assessed as the issue fetched for it (ABC-9, project SEC):
    // denied, and never carrying ZED-1's body.
    assert!(matches!(out["OLD-9"].0, Access::Denied { .. }));
    assert_eq!(out["OLD-9"].1["key"], json!("ABC-9"));
    assert!(out["ZED-1"].0.allows(Capability::Read));
    assert_eq!(out["ZED-1"].1["key"], json!("ZED-1"));
}

#[tokio::test]
async fn assess_resolves_case_and_moved_key_redirects() {
    let server = MockServer::start().await;
    // Case-only difference: requested lowercase, reported uppercase.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/abc-9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("ABC-9", "OPEN", None)))
        .mount(&server)
        .await;
    // Moved issue: the reported key shares nothing with the requested one.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/OLD-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("NEW-5", "OPEN", None)))
        .mount(&server)
        .await;

    let g = guard("default_action = \"allow\"\n");
    let out = g
        .assess(
            &client(&server),
            &creds(),
            &["abc-9".into(), "OLD-1".into()],
            None,
        )
        .await;
    assert!(out["abc-9"].0.allows(Capability::Read));
    assert_eq!(out["abc-9"].1["key"], json!("ABC-9"));
    assert!(out["OLD-1"].0.allows(Capability::Read));
    assert_eq!(out["OLD-1"].1["key"], json!("NEW-5"));
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

/// I4: attachment metadata without a readable numeric `size` fails closed
/// under a non-zero `max_attachment_bytes` — the content URL is never
/// fetched. Mirrors the server's `download_attachment` flow: gate on the
/// declared size first, download (cap-bounded) only after.
#[tokio::test]
async fn attachment_unknown_size_refused_before_download() {
    let server = MockServer::start().await;
    let content_path = "/rest/api/3/attachment/content/10001";
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/ATT-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "key": "ATT-1",
            "id": "9",
            "fields": {"attachment": [
                {
                    // No "size" key at all.
                    "id": "10001",
                    "filename": "big.bin",
                    "content": format!("{}{content_path}", server.uri()),
                },
                {
                    // Size present but not a u64 (string).
                    "id": "10002",
                    "filename": "big2.bin",
                    "size": "524288000",
                    "content": format!("{}{content_path}", server.uri()),
                },
            ]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(content_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 8]))
        .expect(0)
        .mount(&server)
        .await;

    let g = guard("default_action = \"allow\"\n[global]\nmax_attachment_bytes = 1024\n");
    let jira = client(&server);
    let atts = jira.list_attachments(&creds(), "ATT-1").await.unwrap();
    assert_eq!(atts.len(), 2);
    for meta in &atts {
        let size = meta.get("size").and_then(serde_json::Value::as_u64);
        if g.attachment_within_cap(size) {
            // Pre-fix behavior: an unreadable size slipped through the cap
            // and the body was fetched, tripping the expect(0) above.
            let url = meta
                .get("content")
                .and_then(serde_json::Value::as_str)
                .unwrap();
            let _ = jira
                .download_attachment_bytes(&creds(), url, g.attachment_cap())
                .await;
        }
        assert!(
            !g.attachment_within_cap(size),
            "unknown attachment size must fail closed (I4)"
        );
    }
    // MockServer::verify (also run on drop) asserts no download happened.
    server.verify().await;
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
async fn search_filtered_scrubs_denied_linked_keys() {
    let server = MockServer::start().await;
    // PUB-7 references denied and unavailable issues through its link fields.
    let mut pub7 = issue("PUB-7", "PUB", None);
    pub7["fields"]["issuelinks"] = json!([
        {"outwardIssue": {"key": "SEC-42"}},
        {"inwardIssue": {"key": "PUB-8"}},
    ]);
    pub7["fields"]["parent"] = json!({"key": "SEC-1"});
    pub7["fields"]["subtasks"] = json!([{"key": "SEC-2"}, {"key": "PUB-9"}]);
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            // PUB-8 is in the served window: its key must stay disclosable
            // without a classification re-fetch (no GET mock for PUB-8).
            "issues": [pub7, issue("PUB-8", "PUB", None)],
        })))
        .mount(&server)
        .await;
    // Assessment fetches for linked keys outside the served window.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/SEC-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("SEC-42", "SEC", None)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/SEC-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("SEC-1", "SEC", None)))
        .mount(&server)
        .await;
    // SEC-2 cannot be fetched at all: fail closed, scrub (I4).
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/SEC-2"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PUB-9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("PUB-9", "PUB", None)))
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
            "project = PUB",
            10,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(window.issues.len(), 2);
    let served = &window.issues[0];
    assert_eq!(served["key"], json!("PUB-7"));
    let links = served["fields"]["issuelinks"].as_array().unwrap();
    assert_eq!(links.len(), 1, "denied SEC-42 link must be scrubbed");
    assert_eq!(links[0]["inwardIssue"]["key"], json!("PUB-8"));
    assert!(
        served["fields"].get("parent").is_none(),
        "denied parent must be scrubbed"
    );
    let subs = served["fields"]["subtasks"].as_array().unwrap();
    assert_eq!(subs.len(), 1, "unfetchable SEC-2 must scrub fail-closed");
    assert_eq!(subs[0]["key"], json!("PUB-9"));
    // Scrubbed keys stay on the audit side (I3); issues_search returns
    // window.issues verbatim, so no served body may name a denied key.
    assert_eq!(
        window.scrubbed_keys,
        vec!["SEC-1".to_string(), "SEC-2".into(), "SEC-42".into()]
    );
    let body = serde_json::to_string(&window.issues).unwrap();
    assert!(!body.contains("SEC-"), "denied key leaked: {body}");
}

#[tokio::test]
async fn search_filtered_scrubs_linked_keys_past_assess_bound() {
    let server = MockServer::start().await;
    let total = Guard::MAX_ASSESS_KEYS + 5;
    let subtasks: Vec<serde_json::Value> = (1..=total)
        .map(|i| json!({"key": format!("LNK-{i}")}))
        .collect();
    let mut parent = issue("PUB-1", "PUB", None);
    parent["fields"]["subtasks"] = json!(subtasks);
    Mock::given(method("POST"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issues": [parent]})))
        .mount(&server)
        .await;
    // Every linked key would classify as allowed if it were assessed.
    Mock::given(method("GET"))
        .and(path_regex(r"^/rest/api/3/issue/LNK-\d+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issue("LNK-0", "LNK", None)))
        .mount(&server)
        .await;

    let g = guard("default_action = \"allow\"\n");
    let window = g
        .search_filtered(
            &client(&server),
            &creds(),
            "project = PUB",
            10,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(window.issues.len(), 1);
    let subs = window.issues[0]["fields"]["subtasks"].as_array().unwrap();
    assert_eq!(
        subs.len(),
        Guard::MAX_ASSESS_KEYS,
        "keys past the assessment bound must scrub, not pass (I4)"
    );
    assert_eq!(window.scrubbed_keys.len(), total - Guard::MAX_ASSESS_KEYS);
    for key in &window.scrubbed_keys {
        assert!(
            !subs.iter().any(|s| s["key"] == json!(key.as_str())),
            "scrubbed key {key} still served"
        );
    }
}

#[tokio::test]
async fn denial_text_has_no_token() {
    let msg = Guard::denial("SEC-1");
    assert!(!msg.contains(TOKEN));
    assert_eq!(msg, "Issue SEC-1 is not accessible through this server");
}
