//! Independent consent for the Tier-A aggregate stream.
//!
//! Tier-A is a **separate stream** from Tier-B's crash-reports / manual-issues
//! (`itasha_report_core::config`). It therefore has its OWN consent posture,
//! default-OFF, never bundled with the detailed-payload toggles. A user who
//! consents to Tier-A (truly-anonymous aggregate signals) has NOT thereby
//! consented to Tier-B (pseudonymous detailed payloads), and vice-versa.
//!
//! Mirroring `itasha_report_core::consent::ConsentToken`, the
//! [`AggregateConsentToken`] is the type-level gate on submission: every
//! Tier-A submit path requires one, and it is constructible only via
//! [`AggregateConsentToken::granted`] — which a host calls only after the user
//! opts the aggregate stream in. The token is deliberately NOT `Default`, NOT
//! `Deserialize`, and carries no identifying data.

/// Per-stream consent posture for the Tier-A aggregate stream. Defaults to
/// [`AggregateMode::Off`] — the opt-in, never-opt-out invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AggregateMode {
    /// Never submit aggregate signals (the default).
    #[default]
    Off,
    /// The user has opted the aggregate stream in.
    On,
}

impl AggregateMode {
    /// Whether this mode permits any aggregate submission at all.
    #[must_use]
    pub fn permits_aggregation(self) -> bool {
        matches!(self, AggregateMode::On)
    }
}

/// A non-forgeable, non-serializable marker proving the host obtained explicit
/// user consent for the Tier-A aggregate stream. Construct via
/// [`AggregateConsentToken::granted`].
#[derive(Debug, Clone)]
pub struct AggregateConsentToken {
    _private: (),
}

impl AggregateConsentToken {
    /// Mint an aggregate-consent token. The host calls this **only after** the
    /// user has opted the Tier-A aggregate stream in. Carries no identity — a
    /// STAR message already has no per-user identifier, and the token adds none.
    #[must_use]
    pub fn granted() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_defaults_to_off() {
        assert_eq!(AggregateMode::default(), AggregateMode::Off);
        assert!(!AggregateMode::default().permits_aggregation());
    }

    #[test]
    fn on_permits_aggregation() {
        assert!(AggregateMode::On.permits_aggregation());
    }

    #[test]
    fn token_is_constructible_only_via_granted() {
        // The struct field is private; the ONLY constructor is `granted`.
        let _t = AggregateConsentToken::granted();
    }
}
