//! Live `.onion` end-to-end test — **`#[ignore]`d by default**.
//!
//! A live Tor onion service is not available in CI (no network, no `.onion`
//! descriptor), so this test is ignored by default. It exercises the full real
//! path — embedded Arti bootstrap → onion connect → POST → spool drain — and is
//! run manually against a real W1TN3SS ingest onion:
//!
//! ```text
//! W1TN3SS_TEST_ONION=<56char>.onion W1TN3SS_TEST_ONION_PORT=80 \
//!   cargo test -p itasha-report-transport-tor --test live_onion_e2e -- --ignored --nocapture
//! ```
//!
//! The CI gate asserts the transport *builds and configures* correctly and that
//! all the offline logic (framing, padding, jitter, queue/retry) is green; the
//! live bootstrap+connect is proven here, out of band.

use std::time::Duration;

use itasha_report_core::backend::{IngestBackend, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::report::Report;

use itasha_report_transport_tor::config::{JitterBounds, TorTransportConfig};
use itasha_report_transport_tor::TorOnionTransport;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live W1TN3SS ingest .onion (set W1TN3SS_TEST_ONION); not available in CI"]
async fn live_onion_roundtrip() {
    let onion = std::env::var("W1TN3SS_TEST_ONION")
        .expect("set W1TN3SS_TEST_ONION to a live 56-char v3 .onion host");
    let port: u16 = std::env::var("W1TN3SS_TEST_ONION_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    let dir = std::env::temp_dir().join(format!("w1tn3ss-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = TorTransportConfig::new(onion, port, dir.join("state"), dir.join("cache"))
        // No jitter for a deterministic manual run.
        .with_jitter(JitterBounds::none())
        .with_timeout(Duration::from_secs(180));

    let transport = TorOnionTransport::new(cfg, &dir).expect("transport構築");

    // Fire-and-forget enqueue.
    let report = Report::crash("e2e: thread 'main' panicked at <HOME>/x.rs:1");
    let consent = ConsentToken::granted();
    assert_eq!(
        transport.send(&report, &consent).unwrap(),
        SendOutcome::Sent
    );
    assert_eq!(transport.spool().count().unwrap(), 1);

    // Drain over real Tor — bootstraps Arti, connects to the onion, POSTs.
    let drain = transport.drain_spool().await.expect("drain over tor");
    eprintln!("drain report: {drain:?}");
    assert_eq!(drain.sent, 1, "the report should be accepted by the onion");
    assert_eq!(transport.spool().count().unwrap(), 0);

    std::fs::remove_dir_all(&dir).ok();
}
