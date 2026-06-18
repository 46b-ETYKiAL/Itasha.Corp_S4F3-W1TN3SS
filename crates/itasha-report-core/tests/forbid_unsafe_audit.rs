//! Audit: `itasha-report-core` stays `#![forbid(unsafe_code)]` after the E2E
//! hardening (plan task T1.1 — "no new unsafe in the forbid-unsafe client
//! crate").
//!
//! `#![forbid(unsafe_code)]` is a **compile-time** gate: if any `unsafe` block,
//! `unsafe fn`, or `unsafe impl` is added anywhere in this crate's own sources,
//! the crate fails to compile — so the fact that this test compiles and runs at
//! all is itself the proof. The `age` E2E dependency is pure-safe-Rust at this
//! crate's surface (the X25519 + ChaCha20-Poly1305 primitives it wraps live in
//! their own audited crates, behind `age`'s safe API).
//!
//! Below we additionally scan this crate's `src/` tree for the `unsafe` keyword
//! as a belt-and-suspenders check that no `#[allow(unsafe_code)]` escape hatch
//! was smuggled in.

use std::fs;
use std::path::Path;

#[test]
fn crate_source_contains_no_unsafe_keyword() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "found `unsafe` usage in a #![forbid(unsafe_code)] crate: {offenders:?}"
    );
}

#[test]
fn crate_source_contains_no_allow_unsafe_escape_hatch() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for path in rust_files(&src) {
        let body = fs::read_to_string(&path).unwrap();
        if body.contains("allow(unsafe_code)") || body.contains("allow(unsafe)") {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "found an unsafe-code allow escape hatch: {offenders:?}"
    );
}

/// Collect every `.rs` file under `dir`.
fn rust_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(rust_files(&path));
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

/// Scan for a standalone `unsafe` token (not inside a string/comment heuristic —
/// the forbid-attr is the real gate; this is a cheap second line).
fn scan(dir: &Path, offenders: &mut Vec<String>) {
    for path in rust_files(dir) {
        let body = fs::read_to_string(&path).unwrap();
        for (lineno, line) in body.lines().enumerate() {
            // Skip the crate-level attribute line and doc/comment lines.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            if trimmed.contains("forbid(unsafe_code)") {
                continue;
            }
            // A real `unsafe` keyword is bounded by non-word chars.
            if has_keyword(line, "unsafe") {
                offenders.push(format!("{}:{}", path.display(), lineno + 1));
            }
        }
    }
}

fn has_keyword(line: &str, kw: &str) -> bool {
    let bytes = line.as_bytes();
    let mut idx = 0;
    while let Some(found) = line[idx..].find(kw) {
        let start = idx + found;
        let end = start + kw.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        idx = end;
    }
    false
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
