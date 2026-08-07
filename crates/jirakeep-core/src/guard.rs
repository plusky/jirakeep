//! Runtime guard enforcement on top of [`crate::policy`].
//!
//! - **I2** — uniform denial text via [`Guard::denial`]
//! - **I3** — silent filtering; dropped keys are server-side only
//! - **I4** — fail closed on fetch/classification failure
//! - **I5** — restricted comments need policy + per-call opt-in

use std::collections::{BTreeMap, BTreeSet};
// BTreeSet used for I14 linked/disclosable key sets.

use chrono::Utc;
use serde_json::{json, Map, Value};

use crate::client::{Credentials, JiraClient, CLASSIFY_FIELDS};
use crate::policy::{Access, Capability, IssueMeta, Operation, Policy};

/// Fields kept by the redacted summary-only projection.
pub const SUMMARY_FIELDS: &[&str] = &[
    "key",
    "id",
    "fields.summary",
    "fields.status",
    "fields.priority",
    "fields.issuetype",
    "fields.project",
    "fields.created",
    "fields.updated",
];

/// Policy enforcement wrapper used by every MCP tool that touches an issue.
#[derive(Debug, Clone)]
pub struct Guard {
    pub policy: Policy,
}

/// Result of one search scan (client sees only `issues`).
#[derive(Debug, Clone, Default)]
pub struct SearchWindow {
    pub issues: Vec<Value>,
    pub scanned: u32,
    pub dropped_keys: Vec<String>,
    pub next_page_token: Option<String>,
}

impl Guard {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Uniform denial text (I2).
    pub fn denial(key: &str) -> String {
        format!("Issue {key} is not accessible through this server")
    }

    pub const MAX_ASSESS_KEYS: usize = 25;

    /// Resolve the caller's account id once per tool call when the policy
    /// needs `created_by_me`.
    pub async fn resolve_caller(&self, jira: &JiraClient, creds: &Credentials) -> Option<String> {
        if !self.policy.needs_identity() {
            return None;
        }
        match jira.account_id(creds).await {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::debug!(error = %err, "caller identity resolution failed");
                None
            }
        }
    }

    /// Classify issue keys against the policy (one fetch per distinct key).
    pub async fn assess(
        &self,
        jira: &JiraClient,
        creds: &Credentials,
        keys: &[String],
        caller: Option<&str>,
    ) -> BTreeMap<String, (Access, Value)> {
        let mut out = BTreeMap::new();
        if keys.is_empty() {
            return out;
        }
        let now = Utc::now();
        let mut fetched: BTreeMap<String, Value> = BTreeMap::new();
        let mut requested: BTreeSet<String> = BTreeSet::new();

        for key in keys {
            let key = key.trim();
            if key.is_empty() || !requested.insert(key.to_owned()) {
                continue;
            }
            if requested.len() > Self::MAX_ASSESS_KEYS {
                tracing::warn!(
                    keys = keys.len(),
                    max = Self::MAX_ASSESS_KEYS,
                    "assess called with more keys than the bound; denying the excess"
                );
                break;
            }
            match jira.get_issue(creds, key, Some(CLASSIFY_FIELDS)).await {
                Ok(issue) => {
                    // Trust server-reported key when present.
                    let reported = issue
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or(key)
                        .to_owned();
                    fetched.insert(reported, issue);
                    // Also index under requested key if different (case).
                    if !fetched.contains_key(key) {
                        if let Some(v) = fetched.values().last().cloned() {
                            fetched.insert(key.to_owned(), v);
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!(key, error = %err, "classification fetch failed");
                }
            }
        }

        for key in keys {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            // Lookup case-insensitive among fetched keys.
            let entry = fetched
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.clone());
            let mapped = match entry {
                Some(issue) => {
                    let meta = IssueMeta::from_jira_issue(
                        &issue,
                        caller,
                        &self.policy.global.public_projects,
                    );
                    (self.policy.classify(&meta, now, Operation::Access), issue)
                }
                None => (
                    Access::Denied {
                        rule: "unavailable".into(),
                    },
                    Value::Null,
                ),
            };
            out.insert(key.to_owned(), mapped);
        }
        out
    }

    /// Redacted summary-only projection of an issue JSON object.
    pub fn summary_view(issue: &Value) -> Value {
        let fields = issue.get("fields").cloned().unwrap_or(Value::Null);
        let mut out = Map::new();
        out.insert(
            "key".into(),
            issue.get("key").cloned().unwrap_or(Value::Null),
        );
        out.insert("id".into(), issue.get("id").cloned().unwrap_or(Value::Null));
        out.insert("_redacted".into(), json!(true));
        let mut f = Map::new();
        for name in [
            "summary",
            "status",
            "priority",
            "issuetype",
            "project",
            "created",
            "updated",
            "resolution",
        ] {
            if let Some(v) = fields.get(name) {
                f.insert(name.into(), v.clone());
            }
        }
        out.insert("fields".into(), Value::Object(f));
        Value::Object(out)
    }

    /// Project full or summary body based on access.
    pub fn project_issue(access: &Access, issue: &Value) -> Option<Value> {
        if access.allows(Capability::Read) {
            Some(issue.clone())
        } else if access.allows(Capability::Summary) {
            Some(Self::summary_view(issue))
        } else {
            None
        }
    }

    /// Filter a list of issue objects; returns (visible, dropped_keys).
    /// Dropped keys must never reach the MCP client (I3).
    pub fn filter_issue_list(
        &self,
        issues: &[Value],
        caller: Option<&str>,
    ) -> (Vec<Value>, Vec<String>) {
        let now = Utc::now();
        let mut visible = Vec::new();
        let mut dropped = Vec::new();
        for issue in issues {
            let key = issue
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let meta =
                IssueMeta::from_jira_issue(issue, caller, &self.policy.global.public_projects);
            let access = self.policy.classify(&meta, now, Operation::Access);
            match Self::project_issue(&access, issue) {
                Some(v) => visible.push(v),
                None => {
                    if !key.is_empty() {
                        dropped.push(key);
                    }
                }
            }
        }
        (visible, dropped)
    }

    /// JQL search with silent post-filter (I3).
    #[allow(clippy::too_many_arguments)]
    pub async fn search_filtered(
        &self,
        jira: &JiraClient,
        creds: &Credentials,
        jql: &str,
        max_results: u32,
        next_page_token: Option<&str>,
        start_at: Option<u32>,
        caller: Option<&str>,
    ) -> Result<SearchWindow, anyhow::Error> {
        // Request enough classify fields so filter works without re-fetch.
        let fields: Vec<&str> = CLASSIFY_FIELDS.split(',').collect();
        // Over-fetch a bit to fill the visible window after filtering.
        let fetch = max_results.saturating_mul(2).clamp(1, 100);
        let envelope = jira
            .search(creds, jql, &fields, fetch, next_page_token, start_at)
            .await?;
        let raw = envelope
            .get("issues")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let scanned = raw.len() as u32;
        let (mut visible, dropped) = self.filter_issue_list(&raw, caller);
        visible.truncate(max_results as usize);
        let next = envelope
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(SearchWindow {
            issues: visible,
            scanned,
            dropped_keys: dropped,
            next_page_token: next,
        })
    }

    /// Whether a comment is restricted (has visibility restriction).
    pub fn comment_is_restricted(comment: &Value) -> bool {
        comment
            .get("visibility")
            .map(|v| !v.is_null())
            .unwrap_or(false)
    }

    /// Filter comments for I5: restricted content needs dual opt-in.
    pub fn filter_comments(&self, comments: Vec<Value>, include_restricted: bool) -> Vec<Value> {
        let allow = self.policy.global.allow_restricted_comments && include_restricted;
        comments
            .into_iter()
            .filter(|c| allow || !Self::comment_is_restricted(c))
            .collect()
    }

    /// Attachment privacy: Jira attachments do not always flag privacy the
    /// same way; treat missing as public metadata, but size-cap downloads.
    pub fn attachment_within_cap(&self, size: u64) -> bool {
        let cap = self.policy.global.max_attachment_bytes;
        cap == 0 || size <= cap
    }

    /// Create-gate: classify a prospective issue's fields.
    pub fn may_create(&self, meta: &IssueMeta) -> Access {
        let mut m = meta.clone();
        // Prospective issue is authored by the caller.
        m.created_by_me = Some(true);
        m.public_projects = self.policy.global.public_projects.clone();
        self.policy.classify(&m, Utc::now(), Operation::Create)
    }

    /// Whether access grants `cap` under skeleton default (no issue).
    pub fn allows(&self, cap: Capability) -> bool {
        self.policy.default_access().allows(cap)
    }

    /// Collect issue keys referenced from a served issue body (I14 candidates).
    ///
    /// Sources: `fields.issuelinks` (inward/outward), `fields.parent`,
    /// `fields.subtasks`. Free-text description/comments are not scanned.
    pub fn linked_keys(issue: &Value) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        let fields = issue.get("fields").unwrap_or(issue);
        if let Some(links) = fields.get("issuelinks").and_then(Value::as_array) {
            for link in links {
                for side in ["inwardIssue", "outwardIssue"] {
                    if let Some(k) = link
                        .get(side)
                        .and_then(|i| i.get("key"))
                        .and_then(Value::as_str)
                    {
                        keys.insert(k.to_owned());
                    }
                }
            }
        }
        if let Some(k) = fields
            .get("parent")
            .and_then(|p| p.get("key"))
            .and_then(Value::as_str)
        {
            keys.insert(k.to_owned());
        }
        if let Some(subs) = fields.get("subtasks").and_then(Value::as_array) {
            for sub in subs {
                if let Some(k) = sub.get("key").and_then(Value::as_str) {
                    keys.insert(k.to_owned());
                }
            }
        }
        keys
    }

    /// Keys that may appear in a client-visible response (at least Summary).
    ///
    /// Failed fetches fail closed: those keys are not disclosable (I4).
    pub async fn disclosable(
        &self,
        jira: &JiraClient,
        creds: &Credentials,
        keys: &BTreeSet<String>,
        caller: Option<&str>,
    ) -> BTreeSet<String> {
        if keys.is_empty() {
            return BTreeSet::new();
        }
        let list: Vec<String> = keys.iter().cloned().collect();
        let assessments = self.assess(jira, creds, &list, caller).await;
        let mut ok = BTreeSet::new();
        for key in keys {
            if assessments
                .get(key)
                .or_else(|| {
                    assessments
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(key))
                        .map(|(_, v)| v)
                })
                .is_some_and(|(access, _)| access.allows(Capability::Summary))
            {
                ok.insert(key.clone());
            }
        }
        ok
    }

    /// Remove links/parent/subtasks that name non-disclosable issues (I14).
    ///
    /// `disclosable` must include keys the client is already allowed to see
    /// in this response (typically the requested key itself). Returns the
    /// scrubbed issue and the keys that were removed (server-side only).
    pub fn scrub_links(issue: &Value, disclosable: &BTreeSet<String>) -> (Value, Vec<String>) {
        let mut out = issue.clone();
        let mut scrubbed = Vec::new();
        let Some(fields) = out.get_mut("fields").and_then(Value::as_object_mut) else {
            return (out, scrubbed);
        };

        if let Some(Value::Array(links)) = fields.get_mut("issuelinks") {
            let before = links.len();
            links.retain(|link| {
                for side in ["inwardIssue", "outwardIssue"] {
                    if let Some(k) = link
                        .get(side)
                        .and_then(|i| i.get("key"))
                        .and_then(Value::as_str)
                    {
                        if !disclosable.iter().any(|d| d.eq_ignore_ascii_case(k)) {
                            scrubbed.push(k.to_owned());
                            return false;
                        }
                    }
                }
                true
            });
            let _ = before;
        }

        if let Some(parent) = fields.get("parent").cloned() {
            if let Some(k) = parent.get("key").and_then(Value::as_str) {
                if !disclosable.iter().any(|d| d.eq_ignore_ascii_case(k)) {
                    scrubbed.push(k.to_owned());
                    fields.remove("parent");
                }
            }
        }

        if let Some(Value::Array(subs)) = fields.get_mut("subtasks") {
            subs.retain(|sub| {
                if let Some(k) = sub.get("key").and_then(Value::as_str) {
                    if !disclosable.iter().any(|d| d.eq_ignore_ascii_case(k)) {
                        scrubbed.push(k.to_owned());
                        return false;
                    }
                }
                true
            });
        }

        scrubbed.sort();
        scrubbed.dedup();
        (out, scrubbed)
    }

    /// Scrub changelog histories that name other issues in `to`/`from` fields.
    pub fn scrub_changelog(changelog: &Value, disclosable: &BTreeSet<String>) -> Value {
        let mut out = changelog.clone();
        let values = if out.get("values").map(Value::is_array).unwrap_or(false) {
            out.get_mut("values")
        } else {
            out.get_mut("histories")
        };
        let Some(values) = values.and_then(Value::as_array_mut) else {
            return out;
        };
        for hist in values.iter_mut() {
            let Some(items) = hist.get_mut("items").and_then(Value::as_array_mut) else {
                continue;
            };
            for item in items.iter_mut() {
                for field in ["fromString", "toString", "from", "to"] {
                    if let Some(Value::String(s)) = item.get_mut(field) {
                        // Drop values that look like issue keys and are not disclosable.
                        if looks_like_issue_key(s)
                            && !disclosable.iter().any(|d| d.eq_ignore_ascii_case(s))
                        {
                            *s = "[redacted]".to_owned();
                        }
                    }
                }
            }
        }
        out
    }
}

/// Rough issue-key shape: `ABC-123` (project key + hyphen + digits).
fn looks_like_issue_key(s: &str) -> bool {
    let s = s.trim();
    let mut parts = s.splitn(2, '-');
    let (Some(proj), Some(num)) = (parts.next(), parts.next()) else {
        return false;
    };
    !proj.is_empty()
        && proj.chars().all(|c| c.is_ascii_alphanumeric())
        && !num.is_empty()
        && num.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn denial_is_uniform() {
        assert_eq!(
            Guard::denial("SEC-1"),
            "Issue SEC-1 is not accessible through this server"
        );
    }

    #[test]
    fn summary_view_redacts() {
        let issue = json!({
            "key": "P-1",
            "id": "1",
            "fields": {
                "summary": "s",
                "status": {"name": "Open"},
                "description": "secret",
                "assignee": {"displayName": "Alice"},
            }
        });
        let v = Guard::summary_view(&issue);
        assert_eq!(v["_redacted"], json!(true));
        assert!(v["fields"].get("description").is_none());
        assert!(v["fields"].get("assignee").is_none());
        assert_eq!(v["fields"]["summary"], json!("s"));
    }

    #[test]
    fn filter_comments_restricted() {
        let mut p = Policy::default();
        p.global.allow_restricted_comments = false;
        let g = Guard::new(p);
        let comments = vec![
            json!({"id": "1", "body": "public"}),
            json!({"id": "2", "body": "secret", "visibility": {"type": "role", "value": "Administrators"}}),
        ];
        let out = g.filter_comments(comments, true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], json!("1"));
    }

    #[test]
    fn filter_issue_list_denies() {
        let p = Policy::from_toml_str(
            r#"
default_action = "allow"
[[rule]]
name = "hide"
action = "deny"
[rule.match]
projects = ["SEC"]
"#,
        )
        .unwrap();
        let g = Guard::new(p);
        let issues = vec![
            json!({"key":"SEC-1","fields":{"summary":"a","project":{"key":"SEC"},"status":{"name":"Open"},"created":"2020-01-01T00:00:00.000+0000"}}),
            json!({"key":"OPEN-1","fields":{"summary":"b","project":{"key":"OPEN"},"status":{"name":"Open"},"created":"2020-01-01T00:00:00.000+0000"}}),
        ];
        let (vis, drop) = g.filter_issue_list(&issues, None);
        assert_eq!(vis.len(), 1);
        assert_eq!(vis[0]["key"], json!("OPEN-1"));
        assert_eq!(drop, vec!["SEC-1".to_string()]);
    }

    #[test]
    fn linked_keys_and_scrub_links() {
        let issue = json!({
            "key": "OPEN-1",
            "fields": {
                "issuelinks": [
                    {"outwardIssue": {"key": "OPEN-2"}},
                    {"inwardIssue": {"key": "SEC-9"}},
                ],
                "parent": {"key": "SEC-1"},
                "subtasks": [{"key": "OPEN-3"}, {"key": "SEC-2"}],
            }
        });
        let keys = Guard::linked_keys(&issue);
        assert!(keys.contains("SEC-9"));
        assert!(keys.contains("OPEN-2"));
        let mut allow = BTreeSet::new();
        allow.insert("OPEN-1".into());
        allow.insert("OPEN-2".into());
        allow.insert("OPEN-3".into());
        let (scrubbed, removed) = Guard::scrub_links(&issue, &allow);
        assert!(removed.iter().any(|k| k == "SEC-9"));
        assert!(removed.iter().any(|k| k == "SEC-1"));
        assert!(removed.iter().any(|k| k == "SEC-2"));
        let links = scrubbed["fields"]["issuelinks"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert!(scrubbed["fields"].get("parent").is_none());
        assert_eq!(scrubbed["fields"]["subtasks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn looks_like_issue_key_shape() {
        assert!(super::looks_like_issue_key("PROJ-123"));
        assert!(!super::looks_like_issue_key("not a key"));
        assert!(!super::looks_like_issue_key("PROJ-"));
    }
}
