//! Runtime enforcement on top of the policy.
//!
//! Full classification, redaction, and silent search filtering land later.
//! The skeleton exposes the uniform denial text (I2) and a thin wrapper so
//! the binary can hold a policy without depending on TOML types alone.

use crate::policy::{Access, Capability, Policy};

/// Runtime guard: holds the operator policy loaded at startup (I1).
#[derive(Debug, Clone)]
pub struct Guard {
    pub policy: Policy,
}

impl Guard {
    /// Wrap a loaded (or default) policy.
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Uniform denial text for a policy-denied or nonexistent issue (I2).
    ///
    /// `key` is the issue key the client asked about (e.g. `PROJ-123`). The
    /// wording must not differ between "denied by policy" and "not found".
    pub fn denial(key: &str) -> String {
        format!("Issue {key} is not accessible through this server")
    }

    /// Skeleton access decision — default_action only until Phase 1 matching.
    pub fn access(&self) -> Access {
        self.policy.default_access()
    }

    /// Whether the skeleton default grant allows `cap`.
    pub fn allows(&self, cap: Capability) -> bool {
        self.access().allows(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_is_uniform_and_key_shaped() {
        assert_eq!(
            Guard::denial("SEC-1"),
            "Issue SEC-1 is not accessible through this server"
        );
    }
}
