//! The crash-signature: a stable, low-dimensional, leak-free hash of the
//! symbolicated stack-frame *names* of a crash.
//!
//! Tier-A is "truly anonymous" only because the value the operator can ever
//! learn (at threshold k) is **low-dimensional and bounded** — it survives the
//! WP216 singling-out test. A raw stack trace is the OPPOSITE: high-dimensional,
//! ~unique per machine, never reaches k. So Tier-A never submits a stack — it
//! submits a **signature**: a hash of the *function/symbol names* in the top
//! frames, with **every address, offset, source path, line number, column,
//! template-arg, and hash-suffix stripped first**.
//!
//! Two devices that crash in the same code path produce the **same** signature;
//! the address/PIE-slide/source-path differences that make raw frames unique are
//! removed *before* hashing. That self-collision is what lets STAR count k
//! distinct submitters of the same signature without any per-user identifier.
//!
//! ## The leak-free guarantee (what NEVER enters the hash)
//!
//! [`normalize_frame`] strips, before a frame name is hashed:
//! * hex addresses / offsets (`0x7ffd…`, `+0x2a`) — PIE slide is per-process,
//!   identifying;
//! * absolute/relative source PATHS (`/home/ada/…`, `C:\Users\…`, `src/x.rs`) —
//!   a path carries the username (gap A: paths are the #1 minidump PII vector);
//! * `:line:col` site suffixes — a line number narrows to a build;
//! * Rust monomorphization hash suffixes (`::h1a2b3c4d`) and closure ordinals
//!   (`::{{closure}}#3`) — build-specific entropy;
//! * generic/template arguments (`<…>`) — can embed user types.
//!
//! The result is a normalized symbol like `core::option::Option::unwrap` or
//! `myapp::editor::save_buffer`. Only those normalized names feed the hash. The
//! hash output is a 32-byte BLAKE3 digest, hex-encoded — it is one-way, so even
//! the digest cannot be reversed to the (already path-free) names.

/// Number of top frames that contribute to the signature. Keeping it small (the
/// crashing site + a little context) maximizes self-collision across devices —
/// deep tails diverge and would fracture the anonymity set.
pub const SIGNATURE_FRAME_DEPTH: usize = 8;

/// Compute the stable crash-signature from an ordered list of raw stack-frame
/// strings (top frame first). Each frame is normalized (addresses/paths/lines/
/// hash-suffixes/generics stripped), the top [`SIGNATURE_FRAME_DEPTH`] kept,
/// joined with `\n`, and BLAKE3-hashed to a 64-char lowercase hex digest.
///
/// Returns `None` if, after normalization, no frame name survives (nothing to
/// sign) — the caller then has no Tier-A signal to submit (never a placeholder).
#[must_use]
pub fn crash_signature(frames: &[String]) -> Option<String> {
    let normalized: Vec<String> = frames
        .iter()
        .filter_map(|f| normalize_frame(f))
        .take(SIGNATURE_FRAME_DEPTH)
        .collect();
    if normalized.is_empty() {
        return None;
    }
    let joined = normalized.join("\n");
    let digest = blake3::hash(joined.as_bytes());
    Some(digest.to_hex().to_string())
}

/// Normalize a single raw stack-frame string to a path/address/line-free symbol
/// name, or `None` if nothing identifiable-as-a-symbol survives.
///
/// This is the leak floor for Tier-A: a frame that still carried a path or an
/// address after this function would poison the anonymity set. The strategy is
/// allowlist-shaped: we extract the symbol token, then aggressively strip every
/// known entropy-bearing suffix/argument.
#[must_use]
pub fn normalize_frame(raw: &str) -> Option<String> {
    let mut s = raw.trim();

    // 1. Drop a leading frame index like "12:" or "#3 " that backtrace crates
    //    prepend (it is an ordinal, but also varies with inlining — drop it).
    if let Some(rest) = strip_frame_ordinal(s) {
        s = rest;
    }

    // 2. Cut off everything at the first " at " / "@" path separator that
    //    backtrace formatters use to append `at /path/file.rs:line:col`.
    //    Everything after is a SOURCE PATH + line:col → never hashed.
    let s = s
        .split(" at ")
        .next()
        .unwrap_or(s)
        .split(" @ ")
        .next()
        .unwrap_or(s)
        .trim();

    // 3. Remove generic/template argument groups `<...>` (balanced) — they can
    //    embed user-defined type names. Replace each group with nothing.
    let s = strip_angle_groups(s);

    // 4. Tokenize on whitespace and keep only the FIRST token that looks like a
    //    symbol path (contains `::` or is a bare identifier). Anything with a
    //    path separator (`/` or `\`) or a hex address is discarded outright.
    let mut symbol: Option<String> = None;
    for tok in s.split_whitespace() {
        if looks_like_path(tok) || looks_like_address(tok) {
            // A raw path or address token → never part of the symbol.
            continue;
        }
        // The first symbol-shaped token is the frame name.
        symbol = Some(tok.to_string());
        break;
    }
    let mut symbol = symbol?;

    // 5. Strip a trailing Rust monomorphization hash `::h<hex>` and closure
    //    ordinal `::{{closure}}#N` / `::{{closure}}`.
    symbol = strip_rust_hash_suffix(&symbol);

    // 6. Strip any trailing `+0x..` offset and a trailing `:line:col` that
    //    survived (defense in depth).
    symbol = strip_trailing_offset_and_line(&symbol);

    let symbol = symbol.trim_matches(|c: char| c == ':' || c.is_whitespace());
    if symbol.is_empty() || looks_like_path(symbol) || looks_like_address(symbol) {
        return None;
    }
    Some(symbol.to_string())
}

/// Strip a leading `"<n>:"` or `"#<n>"` frame ordinal, returning the remainder.
fn strip_frame_ordinal(s: &str) -> Option<&str> {
    // "12: foo" → "foo"
    if let Some((head, tail)) = s.split_once(':') {
        if !head.is_empty() && head.chars().all(|c| c.is_ascii_digit()) {
            return Some(tail.trim_start());
        }
    }
    // "#3 foo" → "foo"
    if let Some(rest) = s.strip_prefix('#') {
        let rest = rest.trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return Some(rest[digits.len()..].trim_start());
        }
    }
    None
}

/// Remove balanced `<...>` groups (generic/template args) from a symbol string.
fn strip_angle_groups(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// True if a token is a filesystem path (contains `/` or `\`, or a drive
/// prefix like `C:`), which must never enter a signature.
fn looks_like_path(tok: &str) -> bool {
    tok.contains('/')
        || tok.contains('\\')
        // Windows drive prefix "C:\..." — the ':' form. Bare "::" is a Rust path
        // separator, not a drive; require a single ':' preceded by one letter.
        || (tok.len() >= 2
            && tok.as_bytes()[1] == b':'
            && tok.as_bytes()[0].is_ascii_alphabetic()
            && tok.as_bytes().get(2) != Some(&b':'))
}

/// True if a token looks like a hex address / offset (`0x…`, `+0x…`).
fn looks_like_address(tok: &str) -> bool {
    let t = tok.trim_start_matches('+');
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}

/// Strip a trailing Rust monomorphization hash (`::h1a2b3c4d5e6f7a8b`) and a
/// trailing `::{{closure}}` / `::{{closure}}#N` ordinal.
fn strip_rust_hash_suffix(symbol: &str) -> String {
    let mut s = symbol.to_string();
    // Closure ordinals.
    while let Some(idx) = s.rfind("::{{closure}}") {
        s.truncate(idx);
    }
    // `::h<hex>` monomorphization hash (rustc appends a 16-hex hash).
    if let Some(idx) = s.rfind("::h") {
        let suffix = &s[idx + 3..];
        if suffix.len() >= 8 && suffix.len() <= 20 && suffix.chars().all(|c| c.is_ascii_hexdigit())
        {
            s.truncate(idx);
        }
    }
    s
}

/// Strip a trailing `+0x..` offset and a trailing `:line:col` suffix.
fn strip_trailing_offset_and_line(symbol: &str) -> String {
    // Offset.
    let s = symbol.split('+').next().unwrap_or(symbol);
    // `:line:col` — cut at the first ':' that is followed by a digit (so a Rust
    // `::` separator, whose next char is ':' or a letter, is preserved).
    let bytes = s.as_bytes();
    let mut cut = s.len();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            cut = i;
            break;
        }
        i += 1;
    }
    s[..cut].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_for_same_frames() {
        let frames = vec![
            "myapp::editor::save_buffer".to_string(),
            "core::option::Option::unwrap".to_string(),
        ];
        let a = crash_signature(&frames).unwrap();
        let b = crash_signature(&frames.clone()).unwrap();
        assert_eq!(a, b, "same frames must yield the same signature");
        // 64-char lowercase hex (BLAKE3-256).
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn different_call_paths_differ() {
        let a = crash_signature(&["myapp::a::foo".to_string()]).unwrap();
        let b = crash_signature(&["myapp::b::bar".to_string()]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn two_devices_same_path_different_addresses_collide() {
        // The WHOLE POINT: the same crash on two machines (different PIE slide,
        // different home path, different build hash) must produce the SAME
        // signature so STAR can count them as k distinct submitters of one value.
        let device_a = vec![
            "myapp::editor::save_buffer::h1a2b3c4d5e6f7a8b at /home/ada/src/editor.rs:42:9"
                .to_string(),
            "core::option::Option::unwrap at /rustc/abc/library/core/src/option.rs:1:1".to_string(),
        ];
        let device_b = vec![
            "myapp::editor::save_buffer::hffeeddccbbaa9988 at C:\\Users\\bob\\src\\editor.rs:42:9"
                .to_string(),
            "core::option::Option::unwrap at C:\\rustc\\xyz\\option.rs:1:1".to_string(),
        ];
        let sa = crash_signature(&device_a).unwrap();
        let sb = crash_signature(&device_b).unwrap();
        assert_eq!(
            sa, sb,
            "same code path on different machines must self-collide"
        );
    }

    #[test]
    fn normalize_strips_address() {
        assert!(!normalize_frame("0x7ffd1234 myapp::foo")
            .unwrap()
            .contains("0x"));
        // An address-only frame yields the symbol after it.
        assert_eq!(
            normalize_frame("0x7ffd1234 myapp::foo").as_deref(),
            Some("myapp::foo")
        );
    }

    #[test]
    fn normalize_strips_source_path_and_line() {
        let n = normalize_frame("myapp::io::read at /home/ada/project/src/io.rs:88:13").unwrap();
        assert_eq!(n, "myapp::io::read");
        assert!(!n.contains("ada"));
        assert!(!n.contains('/'));
        assert!(!n.contains("88"));
    }

    #[test]
    fn normalize_strips_windows_path() {
        let n = normalize_frame("app::win::open at C:\\Users\\carol\\app\\win.rs:1").unwrap();
        assert_eq!(n, "app::win::open");
        assert!(!n.to_lowercase().contains("carol"));
        assert!(!n.contains('\\'));
    }

    #[test]
    fn normalize_strips_rust_hash_and_closure() {
        assert_eq!(
            normalize_frame("myapp::run::h0123456789abcdef").as_deref(),
            Some("myapp::run")
        );
        assert_eq!(
            normalize_frame("myapp::run::{{closure}}#2::haabbccddeeff0011").as_deref(),
            Some("myapp::run")
        );
    }

    #[test]
    fn normalize_strips_generics() {
        assert_eq!(
            normalize_frame("Vec<myapp::secret::UserRecord>::push").as_deref(),
            Some("Vec::push")
        );
    }

    #[test]
    fn pure_path_frame_yields_none() {
        // A frame that is ONLY a path (no symbol) must NOT become a signature
        // input — it would carry the username.
        assert_eq!(normalize_frame("/home/ada/secret/notes.txt"), None);
        assert_eq!(normalize_frame("C:\\Users\\dave\\private.docx"), None);
    }

    #[test]
    fn empty_frames_yield_no_signature() {
        assert_eq!(crash_signature(&[]), None);
        assert_eq!(crash_signature(&["   ".to_string()]), None);
        assert_eq!(crash_signature(&["/only/a/path".to_string()]), None);
    }

    #[test]
    fn signature_input_never_contains_path_or_address_chars() {
        // Property: across a battery of adversarial frames carrying paths,
        // addresses, lines, and home dirs, the NORMALIZED inputs that feed the
        // hash contain none of those leak markers.
        let adversarial = vec![
            "frame0: 0xdeadbeef app::a::b at /home/eve/.ssh/id_rsa.rs:1:1+0x2a".to_string(),
            "#1 app::c::d::h00112233aabbccdd at C:\\Users\\eve\\AppData\\x.rs:9".to_string(),
        ];
        for f in &adversarial {
            if let Some(n) = normalize_frame(f) {
                assert!(!n.contains('/'), "path leaked: {n}");
                assert!(!n.contains('\\'), "win path leaked: {n}");
                assert!(!n.to_lowercase().contains("0x"), "address leaked: {n}");
                assert!(!n.contains("eve"), "username leaked: {n}");
                assert!(!n.contains(".ssh"), "secret path leaked: {n}");
            }
        }
        // And the resulting signature still computes.
        assert!(crash_signature(&adversarial).is_some());
    }

    #[test]
    fn depth_is_bounded() {
        // More than SIGNATURE_FRAME_DEPTH frames: only the top frames count, so
        // a divergent deep tail does not fracture the anonymity set.
        let mut deep_a: Vec<String> = (0..SIGNATURE_FRAME_DEPTH)
            .map(|i| format!("app::frame{i}"))
            .collect();
        let mut deep_b = deep_a.clone();
        // Append DIFFERENT tails beyond the depth cap.
        deep_a.push("app::tail_variant_a".to_string());
        deep_b.push("app::tail_variant_b".to_string());
        assert_eq!(
            crash_signature(&deep_a),
            crash_signature(&deep_b),
            "frames beyond the depth cap must not affect the signature"
        );
    }
}
