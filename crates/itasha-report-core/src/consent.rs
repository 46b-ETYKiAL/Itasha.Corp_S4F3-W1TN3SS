//! The consent token — the type-level gate on transmission.
//!
//! A [`ConsentToken`] can only be constructed by the host calling
//! [`ConsentToken::granted`], which the host does **only after** the user
//! has explicitly agreed to send a specific report. Because every
//! [`crate::backend::IngestBackend::send`] call requires a `&ConsentToken`
//! argument, there is no transmission path that does not pass through an
//! explicit, host-minted consent decision.
//!
//! The token carries **no identifying data** — it is a pure capability marker
//! plus an ephemeral per-report nonce used once and discarded. It is
//! deliberately NOT `Default`, NOT `Deserialize`, and NOT constructible from
//! untrusted input.

/// A non-forgeable, non-serializable marker proving the host obtained explicit
/// user consent for a single transmission.
///
/// Construct via [`ConsentToken::granted`]. The token holds a fresh ephemeral
/// nonce ([`ConsentToken::nonce`]) for de-duplication on the receiving side;
/// the nonce is per-report and is never a stable device/install identifier.
#[derive(Debug, Clone)]
pub struct ConsentToken {
    nonce: String,
}

impl ConsentToken {
    /// Mint a consent token. The host calls this **only after** the user has
    /// explicitly agreed to send a report. Each call yields a fresh ephemeral
    /// nonce; the token carries no persistent identity.
    #[must_use]
    pub fn granted() -> Self {
        Self {
            nonce: generate_ephemeral_nonce(),
        }
    }

    /// The ephemeral per-report nonce. Used once for receive-side
    /// de-duplication, then discarded. NEVER a stable device/install id.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

/// Generate a fresh, non-identifying nonce.
///
/// Uses process-local, time-and-counter entropy — deliberately NOT a stable
/// machine fingerprint, MAC address, or install id. Two calls always differ;
/// the value reveals nothing about the host machine.
fn generate_ephemeral_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix nanos and a per-process counter so concurrent calls never collide.
    // No machine-stable input is used.
    format!("{nanos:x}-{seq:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granted_token_has_nonempty_nonce() {
        let t = ConsentToken::granted();
        assert!(!t.nonce().is_empty());
    }

    #[test]
    fn nonces_are_ephemeral_and_unique() {
        let a = ConsentToken::granted();
        let b = ConsentToken::granted();
        // Two tokens minted in the same process differ — the nonce is NOT a
        // stable identifier.
        assert_ne!(a.nonce(), b.nonce());
    }

    #[test]
    fn many_nonces_are_all_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(ConsentToken::granted().nonce().to_string()));
        }
    }
}
