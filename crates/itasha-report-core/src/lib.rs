//! `itasha-report-core` — the safe spine of the W1TN3SS reporting SDK.
//!
//! Privacy invariants this crate will enforce (built out in plan-731):
//! two-stream opt-in config (default OFF), a path/identity sanitizer, a
//! local-first spool, a hardened transport that carries **no persistent
//! identifier**, the `IngestBackend` boundary over the Sentry-envelope wire,
//! a previewable/redactable payload, and the manual-issue intake helpers.
//!
//! This crate transmits nothing on its own — the host calls its APIs only
//! after the user consents. It is `#![forbid(unsafe_code)]` by construction;
//! native crash capture lives in the isolated sibling crate
//! `itasha-crash-capture`.
#![forbid(unsafe_code)]

/// Crate scaffold marker (plan-730 foundation). Real surface lands in plan-731.
pub const SDK_NAME: &str = "itasha-report-core";
