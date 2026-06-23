//! Convenience wiring of Tier-A submission onto the concrete Arti Tor onion
//! transport (the `tor` feature).
//!
//! The generic [`crate::submit::submit_over_transport`] works with ANY
//! [`itasha_report_core::backend::IngestBackend`]. This module adds a typed
//! helper for the specific, recommended one — the truly-anonymous
//! [`itasha_report_transport_tor::TorOnionTransport`] — so a host gets
//! content-anonymity (STAR, no identifier) + sender-anonymity (Tor, no IP) in
//! one call. It is feature-gated so the base aggregate crate stays free of the
//! Arti `tor-*` dependency tree for apps that wire their own transport.

use itasha_report_core::backend::SendOutcome;
use itasha_report_core::consent::ConsentToken;
use itasha_report_transport_tor::TorOnionTransport;

use crate::consent::AggregateConsentToken;
use crate::measurement::AggregateMeasurement;
use crate::star::StarProducer;
use crate::submit::{submit_over_transport, SubmitError};

/// Submit a Tier-A measurement over the Arti Tor onion transport.
///
/// This is the truly-anonymous happy path: the STAR message (no per-user
/// identifier) is spooled by the [`TorOnionTransport`] for anonymous delivery
/// over a v3 onion service (no client IP). Both consents are required — Tier-A's
/// stream consent and the transport's per-send consent.
pub fn submit_over_tor(
    producer: &StarProducer,
    measurement: &AggregateMeasurement,
    transport: &TorOnionTransport,
    aggregate_consent: &AggregateConsentToken,
    send_consent: &ConsentToken,
) -> Result<SendOutcome, SubmitError> {
    submit_over_transport(
        producer,
        measurement,
        transport,
        aggregate_consent,
        send_consent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use itasha_report_transport_tor::config::JitterBounds;
    use itasha_report_transport_tor::TorTransportConfig;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "w1tn3ss-agg-tor-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn tier_a_spools_a_star_message_over_the_tor_transport() {
        let dir = tmp_dir("submit");
        let cfg = TorTransportConfig::new(
            "a".repeat(56) + ".onion",
            80,
            dir.join("state"),
            dir.join("cache"),
        )
        .with_jitter(JitterBounds::none());
        let transport = TorOnionTransport::new(cfg, &dir).unwrap();

        let producer = StarProducer::new("2026-W25").unwrap();
        let measurement = AggregateMeasurement::new(
            "a".repeat(64),
            &[("app_version".to_string(), "1.0.0".to_string())],
        );

        assert_eq!(transport.spool().count().unwrap(), 0);
        let outcome = submit_over_tor(
            &producer,
            &measurement,
            &transport,
            &AggregateConsentToken::granted(),
            &ConsentToken::granted(),
        )
        .unwrap();
        assert_eq!(outcome, SendOutcome::Sent);
        // Fire-and-forget: the STAR message is durably spooled for anonymous
        // Tor delivery, not transmitted inline.
        assert_eq!(transport.spool().count().unwrap(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
