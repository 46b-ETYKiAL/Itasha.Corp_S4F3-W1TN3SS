//! The consent + no-stable-identifier contract test.
//!
//! Two privacy invariants are asserted here against a recording backend:
//!
//! 1. **No send without consent.** `IngestBackend::send` requires a
//!    `&ConsentToken` at the type level — there is no overload that omits it.
//!    This test proves the recording backend never observes a transmission
//!    that was not accompanied by a host-minted consent token, and that a
//!    `send` call cannot even be expressed without one (the commented line
//!    below does not compile).
//! 2. **No stable identifier.** The only per-report identifier is the
//!    ephemeral consent nonce; two sends of the *same* report under fresh
//!    consent tokens carry different identifiers, so nothing stable leaks.

use std::cell::RefCell;

use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
use itasha_report_core::consent::ConsentToken;
use itasha_report_core::report::Report;

/// A backend that records the nonces it was asked to send under (proving every
/// send carried a consent token) and never transmits.
#[derive(Default)]
struct RecordingBackend {
    seen_nonces: RefCell<Vec<String>>,
}

impl IngestBackend for RecordingBackend {
    fn send(&self, _report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError> {
        // The mere fact this method ran means a ConsentToken was supplied — the
        // signature makes a consent-free send unrepresentable.
        self.seen_nonces
            .borrow_mut()
            .push(consent.nonce().to_string());
        Ok(SendOutcome::Sent)
    }
}

#[test]
fn send_requires_consent_token_at_type_level() {
    let backend = RecordingBackend::default();
    let report = Report::crash("panic");

    // This is the ONLY way to call send — a consent token is mandatory:
    let token = ConsentToken::granted();
    let outcome = backend.send(&report, &token).unwrap();
    assert_eq!(outcome, SendOutcome::Sent);

    // The following line is intentionally NOT compilable — uncommenting it is a
    // type error, which is the static proof that send refuses without consent:
    //
    //   let _ = backend.send(&report);   // error[E0061]: missing `consent`
    //
    assert_eq!(backend.seen_nonces.borrow().len(), 1);
}

#[test]
fn every_send_carries_a_fresh_ephemeral_nonce_not_a_stable_id() {
    let backend = RecordingBackend::default();
    let report = Report::crash("panic");

    // Send the SAME report three times under fresh consent tokens.
    for _ in 0..3 {
        let token = ConsentToken::granted();
        backend.send(&report, &token).unwrap();
    }

    let nonces = backend.seen_nonces.borrow();
    assert_eq!(nonces.len(), 3);
    // All three nonces differ — there is no stable per-install identifier.
    let unique: std::collections::HashSet<_> = nonces.iter().collect();
    assert_eq!(unique.len(), 3, "nonces must be ephemeral, not a stable id");
}
