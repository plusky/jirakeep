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

/// Result of one search scan (client sees only `issues` and
/// `next_page_token`).
///
/// `scanned`, `dropped_keys`, and `scrubbed_keys` are server-side audit
/// data and must never reach the MCP client (I3).
#[derive(Debug, Clone, Default)]
pub struct SearchWindow {
    pub issues: Vec<Value>,
    pub scanned: u32,
    pub dropped_keys: Vec<String>,
    /// Linked issue keys removed from served issues by I14 scrubbing.
    pub scrubbed_keys: Vec<String>,
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
    ///
    /// A key the server reports under a different form (case change or a
    /// moved-issue redirect) is bound to the issue fetched for that key,
    /// never to any other fetched issue (I8); a key that cannot be bound
    /// to a fetched body is denied (I4).
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
                    // Also index under the requested key when the server
                    // reported a different one (case change or moved-issue
                    // redirect), binding it to the issue just fetched —
                    // never to another entry in the map (I8/I4).
                    if reported != key && !fetched.contains_key(key) {
                        fetched.insert(key.to_owned(), issue.clone());
                    }
                    fetched.insert(reported, issue);
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

    /// Remove capability-gated field families from a served issue body (I6).
    ///
    /// The unprojected `fields: None` fetch returns Jira's default navigable
    /// field set, which bundles field families that have their own
    /// capability. [`Capability::Read`] implies none of them:
    ///
    /// - `fields.attachment` (filenames, sizes, content URLs) is removed
    ///   unless `access` grants [`Capability::Attachments`];
    /// - `fields.comment` is removed unless `access` grants
    ///   [`Capability::Comments`]. When granted, restricted-visibility
    ///   comments are still removed: this path carries no per-call
    ///   restricted opt-in, so I5's dual opt-in can never be satisfied here;
    /// - `fields.worklog` is always removed — no v1 capability covers
    ///   worklog content, and ungoverned content is stripped, not served
    ///   (I4);
    /// - count-only `fields.watches` / `fields.votes` are kept (deliberate:
    ///   counts, no identities, no restricted content).
    ///
    /// Denied or ungranted access strips (fail closed, I4), and every
    /// removal is silent to the client (I3 spirit): the embedded comment
    /// `total` tracks the served list so no count betrays a removal.
    pub fn scrub_gated_fields(access: &Access, mut issue: Value) -> Value {
        let Some(fields) = issue.get_mut("fields").and_then(Value::as_object_mut) else {
            return issue;
        };
        if !access.allows(Capability::Attachments) {
            fields.remove("attachment");
        }
        // No v1 capability grants worklog content; fail closed (I4).
        fields.remove("worklog");
        if !access.allows(Capability::Comments) {
            fields.remove("comment");
        } else if let Some(container) = fields.get_mut("comment") {
            let served = container
                .get_mut("comments")
                .and_then(Value::as_array_mut)
                .map(|list| {
                    // I5: no opt-in is possible on this path, so restricted
                    // comments are always removed here.
                    list.retain(|c| !Self::comment_is_restricted(c));
                    list.len()
                });
            match served {
                Some(n) => {
                    // Silent removal (I3): total matches the served list.
                    if let Some(obj) = container.as_object_mut() {
                        if obj.contains_key("total") {
                            obj.insert("total".into(), json!(n));
                        }
                    }
                }
                // Unrecognized container shape: strip rather than serve (I4).
                None => {
                    fields.remove("comment");
                }
            }
        }
        issue
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

    /// JQL search with silent post-filter (I3) and linked-key scrubbing (I14).
    ///
    /// Issue keys referenced from served issues (`issuelinks`, `parent`,
    /// `subtasks`, declared `link_custom_fields`) that are not positively
    /// disclosable — policy-denied,
    /// unfetchable, or past the [`Guard::MAX_ASSESS_KEYS`] assessment bound —
    /// are removed from the served bodies and reported only via
    /// [`SearchWindow::scrubbed_keys`] (fail closed, I4).
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
        // Keys classified above as at least Summary-visible are disclosable
        // in this window without spending assessment budget on a re-fetch.
        let mut disclosable: BTreeSet<String> = visible
            .iter()
            .filter_map(|i| i.get("key").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        visible.truncate(max_results as usize);

        // I14: keys referenced from served issues (issuelinks, parent,
        // subtasks) must themselves be disclosable; assess the unknown ones.
        let link_fields = &self.policy.global.link_custom_fields;
        let mut candidates: BTreeSet<String> = BTreeSet::new();
        for issue in &visible {
            candidates.extend(Self::linked_keys(issue, link_fields));
        }
        candidates.retain(|k| {
            !disclosable.iter().any(|d| d.eq_ignore_ascii_case(k))
                && !dropped.iter().any(|d| d.eq_ignore_ascii_case(k))
        });
        if !candidates.is_empty() {
            // Bounded by MAX_ASSESS_KEYS inside `assess`; candidates past the
            // bound or with failed fetches stay non-disclosable and scrub (I4).
            let extra = self.disclosable(jira, creds, &candidates, caller).await;
            disclosable.extend(extra);
        }
        let mut scrubbed_keys: Vec<String> = Vec::new();
        for issue in &mut visible {
            let (clean, removed) = Self::scrub_links(issue, &disclosable, link_fields);
            *issue = clean;
            scrubbed_keys.extend(removed);
        }
        scrubbed_keys.sort();
        scrubbed_keys.dedup();

        let next = envelope
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(SearchWindow {
            issues: visible,
            scanned,
            dropped_keys: dropped,
            scrubbed_keys,
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
    ///
    /// `size` is the byte count when it could be read from metadata, `None`
    /// when it is missing or unreadable. With a non-zero cap an unknown size
    /// is refused — unreadable metadata never yields more access than
    /// readable metadata would (I4). A cap of `0` means no limit.
    pub fn attachment_within_cap(&self, size: Option<u64>) -> bool {
        match self.attachment_cap() {
            None => true,
            Some(cap) => size.is_some_and(|s| s <= cap),
        }
    }

    /// The configured `max_attachment_bytes` bound, or `None` when the
    /// policy value is `0` (documented as "no limit").
    pub fn attachment_cap(&self) -> Option<u64> {
        match self.policy.global.max_attachment_bytes {
            0 => None,
            cap => Some(cap),
        }
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
    /// `fields.subtasks`, and each operator-declared field in
    /// `link_custom_fields` whose value is an issue-key string (e.g. the
    /// classic/DC Epic Link field). Undeclared custom fields and free-text
    /// description/comments are not scanned.
    pub fn linked_keys(issue: &Value, link_custom_fields: &[String]) -> BTreeSet<String> {
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
        for name in link_custom_fields {
            if let Some(s) = fields.get(name).and_then(Value::as_str) {
                if looks_like_issue_key(s) {
                    keys.insert(s.trim().to_owned());
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
    /// in this response (typically the requested key itself). Each declared
    /// field in `link_custom_fields` is nulled unless its value is a
    /// positively disclosable issue-key string — an unassessable value never
    /// serves (I4). Returns the scrubbed issue and the keys that were
    /// removed (server-side only, I3).
    pub fn scrub_links(
        issue: &Value,
        disclosable: &BTreeSet<String>,
        link_custom_fields: &[String],
    ) -> (Value, Vec<String>) {
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

        for name in link_custom_fields {
            let Some(v) = fields.get_mut(name) else {
                continue;
            };
            if v.is_null() {
                continue;
            }
            let keep = v.as_str().is_some_and(|s| {
                looks_like_issue_key(s)
                    && disclosable.iter().any(|d| d.eq_ignore_ascii_case(s.trim()))
            });
            if !keep {
                if let Some(s) = v.as_str() {
                    if looks_like_issue_key(s) {
                        scrubbed.push(s.trim().to_owned());
                    }
                }
                // Null, not remove: an unset link field is null in Jira.
                *v = Value::Null;
            }
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
    fn attachment_cap_fails_closed_on_unknown_size() {
        let mut p = Policy::default();
        p.global.max_attachment_bytes = 1024;
        let g = Guard::new(p);
        assert_eq!(g.attachment_cap(), Some(1024));
        assert!(g.attachment_within_cap(Some(1024)));
        assert!(!g.attachment_within_cap(Some(1025)));
        // I4: a missing/unreadable size must not pass a non-zero cap.
        assert!(!g.attachment_within_cap(None));
    }

    #[test]
    fn attachment_cap_zero_means_unlimited() {
        let mut p = Policy::default();
        p.global.max_attachment_bytes = 0;
        let g = Guard::new(p);
        assert_eq!(g.attachment_cap(), None);
        assert!(g.attachment_within_cap(Some(u64::MAX)));
        assert!(g.attachment_within_cap(None));
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
        let keys = Guard::linked_keys(&issue, &[]);
        assert!(keys.contains("SEC-9"));
        assert!(keys.contains("OPEN-2"));
        let mut allow = BTreeSet::new();
        allow.insert("OPEN-1".into());
        allow.insert("OPEN-2".into());
        allow.insert("OPEN-3".into());
        let (scrubbed, removed) = Guard::scrub_links(&issue, &allow, &[]);
        assert!(removed.iter().any(|k| k == "SEC-9"));
        assert!(removed.iter().any(|k| k == "SEC-1"));
        assert!(removed.iter().any(|k| k == "SEC-2"));
        let links = scrubbed["fields"]["issuelinks"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert!(scrubbed["fields"].get("parent").is_none());
        assert_eq!(scrubbed["fields"]["subtasks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn declared_link_custom_fields_join_candidates_and_scrub() {
        let declared = vec![
            "customfield_10014".to_owned(),
            "customfield_10500".to_owned(),
        ];
        let issue = json!({
            "key": "PUB-7",
            "fields": {
                "customfield_10014": "SEC-100",
                "customfield_10500": "PUB-8",
                // Undeclared: never scanned, never touched.
                "customfield_20000": "SEC-77",
            }
        });
        let keys = Guard::linked_keys(&issue, &declared);
        assert!(keys.contains("SEC-100"));
        assert!(keys.contains("PUB-8"));
        assert!(!keys.contains("SEC-77"));
        let allow: BTreeSet<String> = BTreeSet::from(["PUB-7".into(), "PUB-8".into()]);
        let (scrubbed, removed) = Guard::scrub_links(&issue, &allow, &declared);
        assert_eq!(scrubbed["fields"]["customfield_10014"], Value::Null);
        assert_eq!(scrubbed["fields"]["customfield_10500"], json!("PUB-8"));
        assert_eq!(scrubbed["fields"]["customfield_20000"], json!("SEC-77"));
        assert_eq!(removed, vec!["SEC-100".to_string()]);
    }

    #[test]
    fn declared_link_custom_field_unreadable_value_nulls() {
        // A declared link field carrying anything but a disclosable
        // issue-key string cannot be assessed: null it (I4).
        let declared = vec!["customfield_10014".to_owned()];
        let allow: BTreeSet<String> = BTreeSet::from(["PUB-7".into()]);
        for odd in [json!({"key": "SEC-100"}), json!("not a key"), json!(7)] {
            let issue = json!({"key": "PUB-7", "fields": {"customfield_10014": odd}});
            assert!(Guard::linked_keys(&issue, &declared).is_empty());
            let (scrubbed, removed) = Guard::scrub_links(&issue, &allow, &declared);
            assert_eq!(scrubbed["fields"]["customfield_10014"], Value::Null);
            assert!(removed.is_empty());
        }
        // Null stays null; an absent field stays absent.
        let issue = json!({"key": "PUB-7", "fields": {"customfield_10014": Value::Null}});
        let (scrubbed, removed) = Guard::scrub_links(&issue, &allow, &declared);
        assert_eq!(scrubbed["fields"]["customfield_10014"], Value::Null);
        assert!(removed.is_empty());
        let issue = json!({"key": "PUB-7", "fields": {}});
        let (scrubbed, _) = Guard::scrub_links(&issue, &allow, &declared);
        assert!(scrubbed["fields"].get("customfield_10014").is_none());
    }

    fn gated_issue() -> Value {
        json!({
            "key": "HR-3",
            "fields": {
                "summary": "s",
                "attachment": [{"filename": "severance-agreement-smith.pdf"}],
                "comment": {
                    "comments": [
                        {"id": "1", "body": "public"},
                        {"id": "2", "body": "secret",
                         "visibility": {"type": "role", "value": "HR"}},
                    ],
                    "maxResults": 2,
                    "total": 2,
                    "startAt": 0,
                },
                "worklog": {"worklogs": [{"comment": "billing note"}], "total": 1},
                "watches": {"watchCount": 3, "isWatching": false},
                "votes": {"votes": 1, "hasVoted": false},
            }
        })
    }

    #[test]
    fn scrub_gated_fields_read_only_strips_gated_families() {
        let read_only = Access::Granted {
            caps: BTreeSet::from([Capability::Read]),
            rule: "r".into(),
        };
        let out = Guard::scrub_gated_fields(&read_only, gated_issue());
        assert!(out["fields"].get("attachment").is_none());
        assert!(out["fields"].get("comment").is_none());
        assert!(out["fields"].get("worklog").is_none());
        // Count-only families stay under Read (documented in I6).
        assert_eq!(out["fields"]["watches"]["watchCount"], json!(3));
        assert_eq!(out["fields"]["votes"]["votes"], json!(1));
        assert_eq!(out["fields"]["summary"], json!("s"));
    }

    #[test]
    fn scrub_gated_fields_comments_grant_filters_restricted() {
        let with_comments = Access::Granted {
            caps: BTreeSet::from([Capability::Read, Capability::Comments]),
            rule: "r".into(),
        };
        let out = Guard::scrub_gated_fields(&with_comments, gated_issue());
        let comments = out["fields"]["comment"]["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1, "restricted comment must be removed (I5)");
        assert_eq!(comments[0]["id"], json!("1"));
        // Silent removal (I3): total tracks the served list.
        assert_eq!(out["fields"]["comment"]["total"], json!(1));
        assert!(out["fields"].get("attachment").is_none());
        assert!(out["fields"].get("worklog").is_none());
    }

    #[test]
    fn scrub_gated_fields_attachments_grant_keeps_attachment() {
        let with_attachments = Access::Granted {
            caps: BTreeSet::from([Capability::Read, Capability::Attachments]),
            rule: "r".into(),
        };
        let out = Guard::scrub_gated_fields(&with_attachments, gated_issue());
        assert!(out["fields"].get("attachment").is_some());
        assert!(out["fields"].get("comment").is_none());
        assert!(out["fields"].get("worklog").is_none());
    }

    #[test]
    fn scrub_gated_fields_denied_strips_everything_gated() {
        let denied = Access::Denied { rule: "d".into() };
        let out = Guard::scrub_gated_fields(&denied, gated_issue());
        assert!(out["fields"].get("attachment").is_none());
        assert!(out["fields"].get("comment").is_none());
        assert!(out["fields"].get("worklog").is_none());
    }

    #[test]
    fn scrub_gated_fields_malformed_comment_container_fails_closed() {
        let with_comments = Access::Granted {
            caps: BTreeSet::from([Capability::Read, Capability::Comments]),
            rule: "r".into(),
        };
        let issue = json!({
            "key": "HR-3",
            "fields": {"summary": "s", "comment": {"comments": "not-an-array"}}
        });
        let out = Guard::scrub_gated_fields(&with_comments, issue);
        assert!(
            out["fields"].get("comment").is_none(),
            "strip, never serve (I4)"
        );
    }

    #[test]
    fn looks_like_issue_key_shape() {
        assert!(super::looks_like_issue_key("PROJ-123"));
        assert!(!super::looks_like_issue_key("not a key"));
        assert!(!super::looks_like_issue_key("PROJ-"));
    }
}
