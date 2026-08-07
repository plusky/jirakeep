//! Operator-controlled guard policy for jirakeep.
//!
//! The policy comes ONLY from a TOML file given at startup (`--policy` /
//! `JIRAKEEP_POLICY`) and is immutable at runtime (invariant I1). Unknown
//! keys are rejected so a typo can never silently weaken a policy.
//!
//! This skeleton ships a real load path and the global switches that the
//! MCP binary needs (`read_only`, `disabled_tools`, …). Match criteria and
//! first-match classification land in Phase 1; until then every issue is
//! classified with [`Policy::default_access`].

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context as _};

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

/// Rule / default action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Restrict,
}

/// Result of classifying an issue against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// No capabilities; the deciding rule name is retained for the audit
    /// stream only (never exposed to the MCP client — I1).
    Denied { rule: String },
    /// The listed capabilities (after read_only stripping).
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
                // I6: read implies summary.
                cap == Capability::Summary && caps.contains(&Capability::Read)
            }
        }
    }
}

/// Global policy switches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Global {
    /// Issues created less than N days ago are invisible (0 = disabled).
    pub min_issue_age_days: u32,
    /// Master switch for restricted-visibility comments/attachments.
    pub allow_restricted_comments: bool,
    /// Strip write capabilities and remove write tools from the listing.
    pub read_only: bool,
    /// Tool names removed from the MCP tool listing entirely (I13).
    pub disabled_tools: Vec<String>,
    /// Largest attachment download/upload in bytes (0 = no policy cap).
    pub max_attachment_bytes: u64,
    /// Project keys the operator declares publicly browsable. An issue with
    /// no security level is still not "world-readable" unless its project is
    /// listed here (or a future rule proves visibility). See DESIGN.md §2a.
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

/// A single policy rule (skeleton: stored for counting / future matching).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Operator-facing identifier; audit stream only (I1).
    pub name: String,
    /// Free-form operator documentation.
    #[serde(default)]
    pub description: String,
    pub action: Action,
    /// Required and non-empty when `action = "restrict"`; must be empty for
    /// allow/deny.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Match criteria table — accepted but not yet evaluated in the skeleton.
    /// (`toml::Table` is not `Eq`, so `Rule`/`Policy` are `PartialEq` only.)
    #[serde(default, rename = "match")]
    pub match_: toml::Table,
}

/// The full guard policy.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Applied when no rule matches. Must not be `restrict`.
    #[serde(default = "default_action_allow")]
    pub default_action: Action,
    #[serde(default)]
    pub global: Global,
    #[serde(default)]
    pub rule: Vec<Rule>,
}

fn default_action_allow() -> Action {
    Action::Allow
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            global: Global::default(),
            rule: Vec::new(),
        }
    }
}

impl Policy {
    /// Load and validate a policy TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be read, the TOML is invalid,
    /// unknown keys are present, or the semantic checks in [`Self::validate`]
    /// fail.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy from {}", path.display()))?;
        Self::from_toml_str(&text)
            .with_context(|| format!("failed to parse policy from {}", path.display()))
    }

    /// Parse a policy from a TOML string (tests and load path).
    ///
    /// # Errors
    ///
    /// Returns an error on parse failure or failed validation.
    pub fn from_toml_str(text: &str) -> anyhow::Result<Self> {
        let policy: Self = toml::from_str(text).context("invalid policy TOML")?;
        policy.validate()?;
        Ok(policy)
    }

    /// Semantic checks that serde cannot express.
    fn validate(&self) -> anyhow::Result<()> {
        if self.default_action == Action::Restrict {
            bail!("default_action must be \"allow\" or \"deny\", not \"restrict\"");
        }
        for rule in &self.rule {
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
                        "rule \"{}\": action \"{:?}\" must not list capabilities",
                        rule.name,
                        rule.action
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Number of rules (exposed by `mcp_server_info`; names stay hidden — I1).
    pub fn rule_count(&self) -> usize {
        self.rule.len()
    }

    /// Skeleton classification: apply `default_action` only. Real first-match
    /// evaluation lands in Phase 1; callers must still treat unknown metadata
    /// as deny (I4) once matching exists.
    pub fn default_access(&self) -> Access {
        let rule = "default".to_owned();
        match self.default_action {
            Action::Allow => {
                let mut caps: BTreeSet<Capability> = Capability::ALL.into_iter().collect();
                if self.global.read_only {
                    caps.retain(|c| !c.is_write());
                }
                Access::Granted { caps, rule }
            }
            Action::Deny => Access::Denied { rule },
            Action::Restrict => unreachable!("validated out of default_action"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows_reads() {
        let p = Policy::default();
        let a = p.default_access();
        assert!(a.allows(Capability::Read));
        assert!(a.allows(Capability::Summary));
        assert!(a.allows(Capability::Comment));
    }

    #[test]
    fn read_only_strips_writes() {
        let mut p = Policy::default();
        p.global.read_only = true;
        let a = p.default_access();
        assert!(a.allows(Capability::Read));
        assert!(!a.allows(Capability::Comment));
        assert!(!a.allows(Capability::Create));
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = Policy::from_toml_str("default_action = \"allow\"\nnope = 1\n").unwrap_err();
        assert!(
            err.to_string().contains("invalid policy TOML") || err.to_string().contains("nope")
        );
    }

    #[test]
    fn restrict_default_is_rejected() {
        let err = Policy::from_toml_str("default_action = \"restrict\"\n").unwrap_err();
        assert!(err.to_string().contains("default_action"));
    }

    #[test]
    fn rule_count_and_load() {
        let p = Policy::from_toml_str(
            r#"
default_action = "deny"
[global]
read_only = true
public_projects = ["OPEN"]
[[rule]]
name = "hide-sec"
action = "deny"
[rule.match]
projects = ["SEC*"]
"#,
        )
        .expect("parses");
        assert_eq!(p.rule_count(), 1);
        assert!(p.global.read_only);
        assert_eq!(p.global.public_projects, vec!["OPEN"]);
        assert!(!p.default_access().allows(Capability::Read));
    }
}
