//! `itasha-report-aggregate` — **Tier-A: the truly-anonymous aggregate-signal
//! stream** of the W1TN3SS reporting SDK.
//!
//! This is the **only** W1TN3SS stream that can honestly carry the word
//! *anonymous*. It submits a low-dimensional **crash-signature** (a one-way
//! hash of symbol-only stack-frame names — no addresses, paths, lines, or
//! build hashes) plus a **coarse quasi-tuple** (`app_version`→minor,
//! `os`→major.minor, `locale`→language) through the
//! [STAR](https://arxiv.org/abs/2109.10074) k-anonymous threshold-aggregation
//! protocol. The ingest operator learns a signature **only once ≥ k (default
//! 25) distinct clients independently submit it**, with **no per-user
//! identifier** — so it survives the GDPR Recital 26 / WP216 singling-out,
//! linkability, and inference tests (research: `C-aggregation-legal-bar.md`).
//!
//! ## The honest two-tier boundary
//!
//! | Tier | What | Honest label |
//! |---|---|---|
//! | **A (this crate)** | k-anonymous crash-signature + coarse-tuple counts | **truly anonymous** |
//! | **B (`itasha-report-core` + transport-tor)** | detailed scrubbed stack / minidump | **pseudonymous** (personal data) |
//!
//! A detailed payload is irreducibly high-dimensional: every stack is ~unique,
//! never reaches k, and a minidump can structurally carry usernames/paths. No
//! scrubbing makes it anonymous — so Tier-B stays honestly *pseudonymous*. Only
//! the *aggregate* signal (this crate) is truly anonymous.
//!
//! ## What makes Tier-A truly anonymous (the four invariants)
//!
//! 1. **No singling out** — STAR reveals a signature only at k ≥ 25 distinct
//!    submitters; a singleton (unique crash) is never revealed.
//! 2. **No linkability** — there is **no per-user identifier** anywhere on the
//!    path. Identical signatures self-collide by construction; the
//!    [`consent::AggregateConsentToken`] adds none, and a STAR message contains
//!    none.
//! 3. **No inference** — the only quasi-identifiers carried are the coarse tuple
//!    (three low-entropy dimensions), revealed only at threshold.
//! 4. **Sender-anonymity** — submission rides the Arti Tor onion transport (the
//!    optional `tor` feature), so the operator never learns the client IP.
//!
//! ## Default-OFF, separate consent
//!
//! Tier-A is its OWN stream with its OWN consent ([`consent::AggregateMode`],
//! default [`consent::AggregateMode::Off`]). Opting into Tier-A does **not**
//! opt into Tier-B, and vice-versa — the streams are never bundled.
//!
//! ## Packaging — why a separate crate
//!
//! STAR pulls a crypto dependency tree (`ppoprf`, `adss`, `strobe-rs`,
//! `curve25519-dalek` via ppoprf). Keeping Tier-A in a **separate crate** (the
//! same rationale as the Arti transport) means apps that do NOT use Tier-A keep
//! `itasha-report-core`'s dependency tree, its `#![forbid(unsafe_code)]`
//! surface, and its `cargo-vet` burden **completely unchanged**. The base crate
//! is untouched.
//!
//! ## End-to-end usage
//!
//! ```no_run
//! use itasha_report_aggregate::{
//!     consent::AggregateConsentToken,
//!     measurement::AggregateMeasurement,
//!     signature::crash_signature,
//!     star::StarProducer,
//!     submit::submit_over_transport,
//! };
//! use itasha_report_core::consent::ConsentToken;
//! # use itasha_report_core::backend::{IngestBackend, SendError, SendOutcome};
//! # use itasha_report_core::report::Report;
//! # struct MyTransport;
//! # impl IngestBackend for MyTransport {
//! #   fn send(&self, _r: &Report, _c: &ConsentToken) -> Result<SendOutcome, SendError> {
//! #     Ok(SendOutcome::Sent)
//! #   }
//! # }
//! # let anonymous_transport = MyTransport;
//!
//! // 1. Build the leak-free signature from symbol-only frames.
//! let frames = vec![
//!     "myapp::editor::save_buffer".to_string(),
//!     "core::option::Option::unwrap".to_string(),
//! ];
//! let signature = crash_signature(&frames).expect("a signature");
//!
//! // 2. Build the measurement (signature + coarse tuple from raw metadata).
//! let metadata = vec![
//!     ("app_version".to_string(), "1.4.37".to_string()),
//!     ("os".to_string(), "Windows 11 26100.1234".to_string()),
//!     ("locale".to_string(), "en-US".to_string()),
//! ];
//! let measurement = AggregateMeasurement::new(signature, &metadata);
//!
//! // 3. Produce the STAR message at k = 25 for this epoch, and submit it over
//! //    the anonymous (Tor) transport — gated by Tier-A's own consent.
//! let producer = StarProducer::new("2026-W25").expect("producer");
//! let _ = submit_over_transport(
//!     &producer,
//!     &measurement,
//!     &anonymous_transport,
//!     &AggregateConsentToken::granted(), // user opted Tier-A in
//!     &ConsentToken::granted(),          // per-send consent
//! );
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod consent;
pub mod measurement;
pub mod signature;
pub mod star;
pub mod submit;

#[cfg(feature = "tor")]
pub mod tor;

/// The crate / SDK name.
pub const AGGREGATE_NAME: &str = "itasha-report-aggregate";

/// The crate version.
pub const AGGREGATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The truly-anonymous tier label, surfaced in docs/diagnostics.
pub const TIER: &str = "Tier-A (truly anonymous, k-anonymous aggregate signals)";
