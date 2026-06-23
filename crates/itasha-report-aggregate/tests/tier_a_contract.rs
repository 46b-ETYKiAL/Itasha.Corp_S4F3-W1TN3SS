//! Tier-A end-to-end contract tests: the truly-anonymous aggregate path, from
//! raw (path-bearing) frames to a STAR message that leaks no PII and recovers
//! only at threshold k.

use itasha_report_aggregate::consent::{AggregateConsentToken, AggregateMode};
use itasha_report_aggregate::measurement::AggregateMeasurement;
use itasha_report_aggregate::signature::crash_signature;
use itasha_report_aggregate::star::{StarProducer, DEFAULT_K};
use itasha_report_aggregate::submit::{submit_over_transport, STAR_CONTENT_TYPE};

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::report::Report;

/// Adversarial raw frames: PIE addresses, home paths (username!), line:col,
/// rustc monomorphization hashes, and user-typed generics.
fn adversarial_frames(home_user: &str) -> Vec<String> {
    vec![
        format!(
            "0x7ffd00112233 myapp::editor::save_buffer::h0123456789abcdef at /home/{home_user}/proj/src/editor.rs:42:9"
        ),
        format!(
            "#1 Vec<myapp::secret::{home_user}Record>::push at C:\\Users\\{home_user}\\app\\vec.rs:1:1"
        ),
        "core::option::Option::unwrap at /rustc/abc/library/core/src/option.rs:1:1".to_string(),
    ]
}

#[test]
fn same_crash_two_users_self_collide_without_leaking_username() {
    // Two different users crash in the SAME code path. The signatures must be
    // IDENTICAL (so STAR counts them toward k) and must NOT contain either
    // username / home path.
    let sig_ada = crash_signature(&adversarial_frames("ada")).unwrap();
    let sig_bob = crash_signature(&adversarial_frames("bob")).unwrap();

    // NOTE: the generic `Vec<...secret::adaRecord>` carries the username INSIDE
    // a generic arg — which `normalize_frame` strips entirely (the whole `<...>`
    // group is removed). So the two signatures self-collide.
    assert_eq!(
        sig_ada, sig_bob,
        "same code path on two machines must produce one signature"
    );
    // The signature is a one-way hash; neither username can appear in it.
    assert!(!sig_ada.contains("ada"));
    assert!(!sig_ada.contains("bob"));
    assert_eq!(sig_ada.len(), 64);
}

#[test]
fn full_measurement_aux_carries_only_coarse_tuple() {
    let sig = crash_signature(&adversarial_frames("carol")).unwrap();
    let metadata = vec![
        ("app_version".to_string(), "1.4.37-rc2+sha".to_string()),
        ("os".to_string(), "Windows 11 26100.1234".to_string()),
        ("locale".to_string(), "en-US".to_string()),
        // Quasi-identifiers that must NOT enter the aux.
        ("timezone".to_string(), "America/New_York".to_string()),
        ("hostname".to_string(), "carol-laptop".to_string()),
        ("build_hash".to_string(), "deadbeefcafe".to_string()),
    ];
    let m = AggregateMeasurement::new(sig, &metadata);
    let aux = String::from_utf8(m.aux_bytes()).unwrap();
    assert_eq!(aux, "app_version=1.4|os=Windows 11|locale=en");
    for needle in [
        "1.4.37", "26100", "en-US", "timezone", "America", "carol", "deadbeef",
    ] {
        assert!(!aux.contains(needle), "quasi-id leaked into aux: {needle}");
    }
}

/// A recording transport stands in for the live Tor onion (no `.onion` needed).
#[derive(Default)]
struct RecordingTransport {
    last: std::sync::Mutex<Option<Report>>,
}

impl IngestBackend for RecordingTransport {
    fn send(&self, report: &Report, _c: &ConsentToken) -> Result<SendOutcome, SendError> {
        *self.last.lock().unwrap() = Some(report.clone());
        Ok(SendOutcome::Sent)
    }
}

#[test]
fn end_to_end_submission_leaks_no_pii_on_the_wire() {
    let producer = StarProducer::new("2026-W25").unwrap();
    assert_eq!(producer.threshold(), DEFAULT_K);

    let sig = crash_signature(&adversarial_frames("dave")).unwrap();
    let m = AggregateMeasurement::new(
        sig.clone(),
        &[
            ("app_version".to_string(), "2.0.0".to_string()),
            ("locale".to_string(), "fr-FR".to_string()),
        ],
    );

    let transport = RecordingTransport::default();
    let outcome = submit_over_transport(
        &producer,
        &m,
        &transport,
        &AggregateConsentToken::granted(),
        &ConsentToken::granted(),
    )
    .unwrap();
    assert_eq!(outcome, SendOutcome::Sent);

    // The wire bytes the operator would receive.
    let sent = transport.last.lock().unwrap().clone().unwrap();
    assert_eq!(sent.attachments.len(), 1);
    assert_eq!(sent.attachments[0].content_type, STAR_CONTENT_TYPE);
    let wire = &sent.attachments[0].bytes;
    let wire_str = String::from_utf8_lossy(wire);

    // The STAR message is encrypted below threshold → none of these appear:
    assert!(
        !wire_str.contains(&sig),
        "signature must not appear in cleartext"
    );
    assert!(!wire_str.contains("dave"), "username must never appear");
    assert!(!wire_str.contains("fr-FR"), "raw locale must not appear");
    assert!(
        !wire_str.contains("app_version=2.0"),
        "aux tuple must be encrypted"
    );
    // It IS a valid STAR message.
    assert!(sta_rs::Message::from_bytes(wire).is_some());
}

#[test]
fn aggregate_stream_is_default_off() {
    // The aggregate stream's resting state is OFF — opt-in only.
    assert_eq!(AggregateMode::default(), AggregateMode::Off);
    assert!(!AggregateMode::default().permits_aggregation());
}
