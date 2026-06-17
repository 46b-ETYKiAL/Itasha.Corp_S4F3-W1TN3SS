//! `itasha-crash-capture` — the UNSAFE-ISOLATED native crash-capture sibling.
//!
//! This is the ONLY W1TN3SS crate permitted to use `unsafe` (built out in
//! plan-734: out-of-process minidump capture via the Embark crash-handler /
//! minidumper / minidump-writer stack, with minimized-memory capture and a
//! separate monitor process). Isolating the unsafe here is what lets every
//! consuming app keep `#![forbid(unsafe_code)]`.
//!
//! Captured minidumps are spooled locally and NEVER auto-sent; transmission is
//! gated by the host on SEPARATE heightened consent.

/// Crate scaffold marker (plan-730 foundation). Real surface lands in plan-734.
pub const CRATE_NAME: &str = "itasha-crash-capture";
