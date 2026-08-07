//! Operator-controlled guard policy for jirakeep.
//!
//! The policy comes ONLY from a TOML file given at startup (`--policy` /
//! `JIRAKEEP_POLICY`) and is immutable at runtime (invariant I1). Unknown
//! keys are rejected so a typo can never silently weaken a policy.
//!
//! Classification is fail-closed (I4): unreadable metadata makes consulted
//! criteria undecidable, which never grants access. Jira-specific: an
//! absent security level is **not** world-readable — see [`IssueMeta`] and
//! `global.public_projects`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context as _};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// A capability a policy grant can carry.
///
/// The only implication is `read` ⇒ `summary` (invariant I6), applied in
/// [`Access::allows`] — never stored in the set itself.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Full issue details (implies [`Capability::Summary`], I6).
    Read,
    /// Redacted summary-only view of an issue.
    Summary,
    /// Read comments.
    Comments,
    /// Read change history / changelog.
    History,
    /// List attachment metadata and download attachment content.
    Attachments,
    /// Write: add a comment.
    Comment,
    /// Write: transition status / resolve / mark duplicate.
    Status,
    /// Write: change fields (summary, labels, priority, …).
    Fields,
    /// Write: change the assignee.
    Assign,
    /// Write: change watchers.
    Watchers,
    /// Write: create or remove issue links.
    Links,
    /// Write: file a new issue.
    Create,
    /// Write: upload a new attachment.
    Attach,
}

impl Capability {
    /// Every capability, in declaration order. Used to expand `allow` grants.
    pub const ALL: [Capability; 13] = [
        Capability::Read,
        Capability::Summary,
        Capability::Comments,
        Capability::History,
        Capability::Attachments,
        Capability::Comment,
        Capability::Status,
        Capability::Fields,
        Capability::Assign,
        Capability::Watchers,
        Capability::Links,
        Capability::Create,
        Capability::Attach,
    ];

    /// Whether this capability permits mutating Jira state.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Capability::Comment
                | Capability::Status
                | Capability::Fields
                | Capability::Assign
                | Capability::Watchers
                | Capability::Links
                | Capability::Create
                | Capability::Attach
        )
    }
}

/// Case-insensitive glob match; `'*'` matches any (possibly empty) substring.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let val: Vec<char> = value.to_lowercase().chars().collect();
    let (mut p, mut s) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while s < val.len() {
        if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            p += 1;
            resume = s;
        } else if p < pat.len() && pat[p] == val[s] {
            p += 1;
            s += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            resume += 1;
            s = resume;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

fn any_glob(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, value))
}

fn any_glob_multi(patterns: &[String], values: &[String]) -> bool {
    patterns
        .iter()
        .any(|p| values.iter().any(|v| glob_match(p, v)))
}

fn contains_any(needles: &[String], haystack: &str) -> bool {
    let hay = haystack.to_lowercase();
    needles.iter().any(|n| hay.contains(&n.to_lowercase()))
}

fn age_cutoff(now: DateTime<Utc>, days: i64) -> Option<DateTime<Utc>> {
    Duration::try_days(days).and_then(|d| now.checked_sub_signed(d))
}

/// What a matching rule (or the policy default) does with an issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Restrict,
}

/// Kind of evaluation a classification is performed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Prospective issue (create gate).
    Create,
    /// Existing issue (read, search, update, …).
    Access,
}

/// Result of classifying an issue against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Denied {
        rule: String,
    },
    Granted {
        caps: BTreeSet<Capability>,
        rule: String,
    },
}

impl Access {
    /// Whether `cap` is granted. `read` implies `summary` (I6).
    pub fn allows(&self, cap: Capability) -> bool {
        match self {
            Access::Denied { .. } => false,
            Access::Granted { caps, .. } => {
                if caps.contains(&cap) {
                    return true;
                }
                cap == Capability::Summary && caps.contains(&Capability::Read)
            }
        }
    }
}

/// Three-valued match outcome (fail-closed classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOutcome {
    Yes,
    No,
    Unknown,
}

/// Classification metadata extracted from a Jira issue (or create request).
///
/// Every field is optional; `None` means UNKNOWN — never silently empty.
/// Visibility: `security_level` None with project not in public_projects is
/// **not** public (DESIGN.md § visibility).
#[derive(Debug, Clone, Default)]
pub struct IssueMeta {
    /// Issue key (`PROJ-123`), empty when unknown.
    pub key: String,
    /// Opaque numeric id when known.
    pub id: Option<String>,
    pub summary: Option<String>,
    /// Project key (e.g. `PROJ`).
    pub project: Option<String>,
    pub components: Option<Vec<String>>,
    pub labels: Option<Vec<String>>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub issue_type: Option<String>,
    /// Security level name; `Some("")` is not used — absent level is `None`.
    pub security_level: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
    /// Whether the requesting account reported the issue (`None` = unknown).
    pub created_by_me: Option<bool>,
    /// Operator-declared public project keys (copied from policy for matching).
    pub public_projects: Vec<String>,
}

impl IssueMeta {
    /// Whether this issue's project is on the operator public list.
    pub fn project_is_public(&self) -> Option<bool> {
        let project = self.project.as_deref()?;
        Some(
            self.public_projects
                .iter()
                .any(|p| p.eq_ignore_ascii_case(project)),
        )
    }

    /// Build metadata from a Jira issue JSON object.
    ///
    /// `caller_account_id` is the Cloud `accountId` from `/myself` when
    /// resolved; compared to `fields.reporter.accountId`.
    pub fn from_jira_issue(
        issue: &Value,
        caller_account_id: Option<&str>,
        public_projects: &[String],
    ) -> Self {
        let fields = issue.get("fields").unwrap_or(issue);
        let project = fields
            .get("project")
            .and_then(|p| p.get("key"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let components = fields.get("components").and_then(|c| {
            c.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
        });
        let labels = fields.get("labels").and_then(|l| {
            l.as_array().map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
        });
        let status = fields
            .get("status")
            .and_then(|s| s.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let priority = fields
            .get("priority")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let issue_type = fields
            .get("issuetype")
            .and_then(|t| t.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        // Security level: null field => None (unknown / none). Present object
        // with name => Some(name). Missing key entirely => None.
        let security_level = match fields.get("security") {
            None | Some(Value::Null) => None,
            // Name when present; unreadable shapes stay None (unknown).
            Some(v) => v.get("name").and_then(Value::as_str).map(str::to_owned),
        };
        // If "security" key was present as a non-null non-object, we cannot
        // read it — still None (unknown).
        let creation_time = fields
            .get("created")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        let reporter_id = fields
            .get("reporter")
            .and_then(|r| r.get("accountId"))
            .and_then(Value::as_str);
        let created_by_me = match (caller_account_id, reporter_id) {
            (Some(caller), Some(rep)) => Some(caller.eq_ignore_ascii_case(rep)),
            _ => None,
        };
        Self {
            key: issue
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            id: issue
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    issue
                        .get("id")
                        .and_then(Value::as_u64)
                        .map(|n| n.to_string())
                }),
            summary: fields
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_owned),
            project,
            components,
            labels,
            status,
            priority,
            issue_type,
            security_level,
            creation_time,
            created_by_me,
            public_projects: public_projects.to_vec(),
        }
    }
}

/// Issue-matching criteria of a rule.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub statuses: Vec<String>,
    #[serde(default)]
    pub priorities: Vec<String>,
    #[serde(default)]
    pub issue_types: Vec<String>,
    #[serde(default)]
    pub security_levels: Vec<String>,
    #[serde(default)]
    pub summary_contains: Vec<String>,
    /// `true` = project is in `global.public_projects`; `false` = not.
    #[serde(default)]
    pub project_public: Option<bool>,
    /// `true` = issue has a security level set; `false` = no security level.
    ///
    /// **Warning:** `has_security_level = false` is knowledge that no level
    /// is set — it is NOT "public". Combine with `project_public` for
    /// visibility intent.
    #[serde(default)]
    pub has_security_level: Option<bool>,
    #[serde(default)]
    pub created_by_me: Option<bool>,
    #[serde(default)]
    pub younger_than_days: Option<i64>,
}

impl Matcher {
    /// Test `issue` against every criterion present.
    pub fn evaluate(&self, issue: &IssueMeta, now: DateTime<Utc>) -> MatchOutcome {
        let mut unknown = false;

        for (patterns, value) in [
            (&self.projects, &issue.project),
            (&self.statuses, &issue.status),
            (&self.priorities, &issue.priority),
            (&self.issue_types, &issue.issue_type),
        ] {
            if patterns.is_empty() {
                continue;
            }
            match value {
                None => unknown = true,
                Some(v) => {
                    if !any_glob(patterns, v) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        for (patterns, values) in [
            (&self.components, &issue.components),
            (&self.labels, &issue.labels),
        ] {
            if patterns.is_empty() {
                continue;
            }
            match values {
                None => unknown = true,
                Some(vs) => {
                    if !any_glob_multi(patterns, vs) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if !self.security_levels.is_empty() {
            match &issue.security_level {
                None => unknown = true,
                Some(level) => {
                    if !any_glob(&self.security_levels, level) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if !self.summary_contains.is_empty() {
            match &issue.summary {
                None => unknown = true,
                Some(s) => {
                    if !contains_any(&self.summary_contains, s) {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if let Some(want_public) = self.project_public {
            match issue.project_is_public() {
                None => unknown = true,
                Some(is_public) => {
                    if is_public != want_public {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if let Some(want_level) = self.has_security_level {
            // Presence of a security *level name* is known when we parsed the
            // field: security_level Some means has level; None means no level
            // OR unreadable. Distinguishing unreadable vs absent is hard from
            // JSON alone when key is missing — treat None as "no level set"
            // when project is known (Jira omits/nulls the field when unset).
            // If project is also unknown, mark unknown.
            if issue.project.is_none() && issue.security_level.is_none() {
                unknown = true;
            } else {
                let has = issue.security_level.is_some();
                if has != want_level {
                    return MatchOutcome::No;
                }
            }
        }

        if let Some(want_mine) = self.created_by_me {
            match issue.created_by_me {
                None => unknown = true,
                Some(mine) => {
                    if mine != want_mine {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if let Some(days) = self.younger_than_days {
            match (issue.creation_time, age_cutoff(now, days)) {
                (None, _) => unknown = true,
                (Some(_), None) => {}
                (Some(ct), Some(cutoff)) => {
                    if ct <= cutoff {
                        return MatchOutcome::No;
                    }
                }
            }
        }

        if unknown {
            MatchOutcome::Unknown
        } else {
            MatchOutcome::Yes
        }
    }
}

/// One policy rule.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match", default)]
    pub matcher: Matcher,
    pub action: Action,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub operations: Option<Vec<Operation>>,
}

impl Rule {
    /// Whether this rule is consulted for `op`.
    pub fn applies_to(&self, op: Operation) -> bool {
        match &self.operations {
            None => true,
            Some(ops) => ops.is_empty() || ops.contains(&op),
        }
    }
}

/// Global policy switches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Global {
    pub min_issue_age_days: i64,
    pub allow_restricted_comments: bool,
    pub read_only: bool,
    pub disabled_tools: Vec<String>,
    pub max_attachment_bytes: u64,
    /// Project keys declared publicly browsable by the operator.
    pub public_projects: Vec<String>,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            min_issue_age_days: 0,
            allow_restricted_comments: false,
            read_only: false,
            disabled_tools: Vec::new(),
            max_attachment_bytes: 2 * 1024 * 1024,
            public_projects: Vec::new(),
        }
    }
}

/// The full guard policy.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_action_allow")]
    pub default_action: Action,
    #[serde(default)]
    pub global: Global,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

fn default_action_allow() -> Action {
    Action::Allow
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            global: Global::default(),
            rules: Vec::new(),
        }
    }
}

impl Policy {
    /// Load and validate a policy TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                if mode & 0o022 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode & 0o777),
                        "guard policy file is writable by group or others"
                    );
                }
            }
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy from {}", path.display()))?;
        Self::from_toml_str(&text)
            .with_context(|| format!("failed to parse policy from {}", path.display()))
    }

    /// Parse a policy from a TOML string.
    pub fn from_toml_str(text: &str) -> anyhow::Result<Self> {
        let policy: Self = toml::from_str(text).context("invalid policy TOML")?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.default_action == Action::Restrict {
            bail!("default_action must be \"allow\" or \"deny\", not \"restrict\"");
        }
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                bail!("every rule needs a non-empty name");
            }
            match rule.action {
                Action::Restrict if rule.capabilities.is_empty() => {
                    bail!(
                        "rule \"{}\": action \"restrict\" requires at least one capability",
                        rule.name
                    );
                }
                Action::Allow | Action::Deny if !rule.capabilities.is_empty() => {
                    bail!(
                        "rule \"{}\": capabilities only allowed with action \"restrict\"",
                        rule.name
                    );
                }
                _ => {}
            }
            if let Some(ops) = &rule.operations {
                if ops.is_empty() {
                    bail!(
                        "rule \"{}\": operations = [] is invalid; omit the key for all ops",
                        rule.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Number of rules (exposed by `mcp_server_info`; names stay hidden — I1).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Whether access classification may consult caller identity.
    pub fn needs_identity(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.applies_to(Operation::Access) && r.matcher.created_by_me.is_some())
    }

    /// Classify one issue into an [`Access`] decision.
    pub fn classify(&self, issue: &IssueMeta, now: DateTime<Utc>, op: Operation) -> Access {
        if self.global.min_issue_age_days > 0 {
            let too_young = match (
                issue.creation_time,
                age_cutoff(now, self.global.min_issue_age_days),
            ) {
                (None, _) => true,
                (Some(_), None) => true,
                (Some(ct), Some(cutoff)) => ct > cutoff,
            };
            if too_young {
                return Access::Denied {
                    rule: "min_issue_age_days".to_string(),
                };
            }
        }
        for rule in &self.rules {
            if !rule.applies_to(op) {
                continue;
            }
            match rule.matcher.evaluate(issue, now) {
                MatchOutcome::No => continue,
                MatchOutcome::Yes => {
                    return match rule.action {
                        Action::Deny => Access::Denied {
                            rule: rule.name.clone(),
                        },
                        Action::Allow => self.grant(Capability::ALL.iter().copied(), &rule.name),
                        Action::Restrict => {
                            self.grant(rule.capabilities.iter().copied(), &rule.name)
                        }
                    };
                }
                MatchOutcome::Unknown => {
                    return match rule.action {
                        Action::Deny => Access::Denied {
                            rule: rule.name.clone(),
                        },
                        Action::Allow | Action::Restrict => Access::Denied {
                            rule: format!("{}:unreadable-metadata", rule.name),
                        },
                    };
                }
            }
        }
        match self.default_action {
            Action::Allow => self.grant(Capability::ALL.iter().copied(), "default"),
            Action::Deny | Action::Restrict => Access::Denied {
                rule: "default".to_string(),
            },
        }
    }

    fn grant(&self, caps: impl IntoIterator<Item = Capability>, rule: &str) -> Access {
        let mut set: BTreeSet<Capability> = caps.into_iter().collect();
        if self.global.read_only {
            set.retain(|c| !c.is_write());
        }
        Access::Granted {
            caps: set,
            rule: rule.to_string(),
        }
    }

    /// Skeleton-era helper: default_action grant only (no issue meta).
    pub fn default_access(&self) -> Access {
        match self.default_action {
            Action::Allow => self.grant(Capability::ALL.iter().copied(), "default"),
            Action::Deny | Action::Restrict => Access::Denied {
                rule: "default".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issue_json(project: &str, security: Option<&str>) -> Value {
        let mut fields = json!({
            "summary": "t",
            "project": {"key": project},
            "status": {"name": "Open"},
            "priority": {"name": "Medium"},
            "issuetype": {"name": "Bug"},
            "labels": ["a"],
            "components": [{"name": "core"}],
            "created": "2020-01-01T00:00:00.000+0000",
            "reporter": {"accountId": "user-1"},
        });
        match security {
            Some(name) => {
                fields["security"] = json!({"name": name});
            }
            None => {
                fields["security"] = Value::Null;
            }
        }
        json!({"key": format!("{project}-1"), "id": "10001", "fields": fields})
    }

    #[test]
    fn deny_security_project() {
        let p = Policy::from_toml_str(
            r#"
default_action = "allow"
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC*"]
"#,
        )
        .unwrap();
        let meta = IssueMeta::from_jira_issue(&issue_json("SEC", None), None, &[]);
        let a = p.classify(&meta, Utc::now(), Operation::Access);
        assert!(!a.allows(Capability::Read));
    }

    #[test]
    fn public_project_matcher() {
        let p = Policy::from_toml_str(
            r#"
default_action = "deny"
[global]
public_projects = ["OPEN"]
[[rule]]
name = "open-ok"
action = "allow"
[rule.match]
project_public = true
"#,
        )
        .unwrap();
        let meta =
            IssueMeta::from_jira_issue(&issue_json("OPEN", None), None, &p.global.public_projects);
        assert!(p
            .classify(&meta, Utc::now(), Operation::Access)
            .allows(Capability::Read));
        let meta2 =
            IssueMeta::from_jira_issue(&issue_json("PRIV", None), None, &p.global.public_projects);
        assert!(!p
            .classify(&meta2, Utc::now(), Operation::Access)
            .allows(Capability::Read));
    }

    #[test]
    fn security_level_glob() {
        let p = Policy::from_toml_str(
            r#"
default_action = "allow"
[[rule]]
name = "embargo"
action = "deny"
[rule.match]
security_levels = ["*Embargo*"]
"#,
        )
        .unwrap();
        let meta = IssueMeta::from_jira_issue(&issue_json("X", Some("Red Embargo")), None, &[]);
        assert!(!p
            .classify(&meta, Utc::now(), Operation::Access)
            .allows(Capability::Summary));
    }

    #[test]
    fn created_by_me_unknown_fails_closed_on_deny_rule() {
        let p = Policy::from_toml_str(
            r#"
default_action = "allow"
[[rule]]
name = "not-mine"
action = "deny"
[rule.match]
created_by_me = false
"#,
        )
        .unwrap();
        let meta = IssueMeta::from_jira_issue(&issue_json("X", None), None, &[]);
        // created_by_me unknown → Unknown on deny rule → Denied
        assert!(!p
            .classify(&meta, Utc::now(), Operation::Access)
            .allows(Capability::Read));
    }

    #[test]
    fn created_by_me_resolves() {
        let p = Policy::from_toml_str(
            r#"
default_action = "deny"
[[rule]]
name = "mine"
action = "allow"
[rule.match]
created_by_me = true
"#,
        )
        .unwrap();
        let meta = IssueMeta::from_jira_issue(&issue_json("X", None), Some("user-1"), &[]);
        assert!(p
            .classify(&meta, Utc::now(), Operation::Access)
            .allows(Capability::Read));
        let meta2 = IssueMeta::from_jira_issue(&issue_json("X", None), Some("other"), &[]);
        assert!(!p
            .classify(&meta2, Utc::now(), Operation::Access)
            .allows(Capability::Read));
    }

    #[test]
    fn read_only_strips_writes() {
        let mut p = Policy::default();
        p.global.read_only = true;
        let meta = IssueMeta::from_jira_issue(&issue_json("X", None), None, &[]);
        let a = p.classify(&meta, Utc::now(), Operation::Access);
        assert!(a.allows(Capability::Read));
        assert!(!a.allows(Capability::Comment));
    }

    #[test]
    fn unknown_key_rejected() {
        assert!(Policy::from_toml_str("default_action = \"allow\"\nnope = 1\n").is_err());
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("SEC*", "SECURITY"));
        assert!(!glob_match("SEC*", "OPEN"));
        assert!(glob_match("*a*b*", "xaybz"));
    }
}
