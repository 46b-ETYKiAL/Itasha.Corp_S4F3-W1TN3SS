//! Metadata-hygiene primitives applied in the anonymous transport
//! (research `B-transport-metadata-anonymity.md` §5 / item 9).
//!
//! Three orthogonal, pure-and-testable defenses:
//!
//! * [`pad_envelope_bytes`] — pad the serialized envelope up to a fixed size
//!   bucket so an on-path size observer cannot correlate a report's true size
//!   to a known crash.
//! * [`build_request_headers`] — a fixed, minimal HTTP/1.1 header set with **no**
//!   `User-Agent` (no OS/arch/locale leak), no `Accept-*`, no `X-Forwarded`.
//! * [`sample_jitter`] — a bounded random send-time delay that decouples
//!   crash-time from send-time.
//!
//! Padding rides *inside* the POST body as a Sentry `attachment` item named
//! `_pad`, so the padded envelope is still a valid envelope the server parses
//! unchanged (it ignores the unknown attachment).

use std::time::Duration;

use rand::Rng;

use itasha_report_core::envelope::{Envelope, EnvelopeItem};

/// The logical name of the padding attachment item.
pub const PAD_ITEM_NAME: &str = "_pad";

/// The content-type of the padding attachment item.
pub const PAD_ITEM_CONTENT_TYPE: &str = "application/octet-stream";

/// Choose the smallest bucket in `buckets` that is `>= size`, or `None` if
/// `size` exceeds every bucket (then the payload is sent un-padded — its size
/// is already its own bucket). `buckets` need not be sorted.
#[must_use]
pub fn target_bucket(size: usize, buckets: &[usize]) -> Option<usize> {
    buckets.iter().copied().filter(|&b| b >= size).min()
}

/// The number of random bytes a padding item must carry so the **whole
/// serialized envelope** lands exactly on `target` bytes, given the current
/// serialized size `current` and the fixed per-item framing overhead.
///
/// The padding item adds its header line + a newline before the payload + a
/// trailing newline after it. We compute the random-byte count that makes the
/// final serialized envelope length equal `target`, accounting for the fact
/// that the JSON `length` field grows as the byte count grows (a small,
/// bounded fixpoint).
#[must_use]
fn pad_random_len(current: usize, target: usize, item_fixed_overhead: usize) -> Option<usize> {
    if target <= current {
        return None;
    }
    // available = target - current = item_fixed_overhead + digits(len) + len
    let available = target - current;
    if available <= item_fixed_overhead {
        // Not enough room even for an empty padding item — caller bumps to the
        // next bucket. Return Some(0) so an empty item is still appended only
        // when it exactly fits; otherwise None.
        return (available == item_fixed_overhead).then_some(0);
    }
    let mut budget = available - item_fixed_overhead;
    // `budget` must cover digits(len) + len. Iterate to a fixpoint (digit count
    // changes at powers of ten; converges in <=2 steps for realistic sizes).
    let mut len = budget; // upper bound
    for _ in 0..4 {
        let digits = decimal_digits(len);
        if budget < digits {
            return Some(0);
        }
        let candidate = budget - digits;
        if candidate == len {
            break;
        }
        len = candidate;
    }
    // Final clamp: ensure digits(len) + len <= budget.
    while decimal_digits(len) + len > budget && len > 0 {
        len -= 1;
    }
    let _ = &mut budget;
    Some(len)
}

/// Decimal digit count of a usize (`0` has 1 digit).
#[must_use]
fn decimal_digits(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut d = 0;
    while n > 0 {
        d += 1;
        n /= 10;
    }
    d
}

/// The fixed framing overhead a padding item adds to the serialized envelope,
/// EXCLUDING the variable `length` digits and the payload bytes themselves.
///
/// Layout per item: `{header-json}\n{payload}\n`. The header JSON for the pad
/// item is a stable shape; we measure it with a zero-length placeholder and add
/// the two newlines.
#[must_use]
fn pad_item_fixed_overhead() -> usize {
    // Serialize a representative pad item with length 0 to measure header bytes,
    // then subtract the single '0' digit (added back as variable digits) and add
    // the two framing newlines.
    let probe = EnvelopeItem {
        item_type: "attachment".to_string(),
        attachment_type: None,
        filename: Some(PAD_ITEM_NAME.to_string()),
        content_type: Some(PAD_ITEM_CONTENT_TYPE.to_string()),
        payload: Vec::new(),
    };
    let header_len = serialize_item_header_len(&probe, 0);
    // header bytes (with a '0' length) - 1 (the '0') + '\n' after header + '\n' after payload
    header_len - 1 + 1 + 1
}

/// Serialize just the item header JSON line length for a given payload length
/// (mirrors `Envelope::to_bytes`'s item-header shape).
#[must_use]
fn serialize_item_header_len(item: &EnvelopeItem, length: usize) -> usize {
    // Reconstruct the same header JSON the core emits.
    let mut map = serde_json::Map::new();
    map.insert("type".to_string(), item.item_type.clone().into());
    map.insert("length".to_string(), serde_json::Value::from(length));
    if let Some(at) = &item.attachment_type {
        map.insert("attachment_type".to_string(), at.clone().into());
    }
    if let Some(fname) = &item.filename {
        map.insert("filename".to_string(), fname.clone().into());
    }
    if let Some(ct) = &item.content_type {
        map.insert("content_type".to_string(), ct.clone().into());
    }
    serde_json::to_vec(&serde_json::Value::Object(map))
        .map(|v| v.len())
        .unwrap_or(0)
}

/// Pad the serialized envelope bytes up to the smallest bucket `>= len`.
///
/// Returns the padded bytes. If the envelope already exceeds every bucket, the
/// original bytes are returned unchanged. The padding is appended as a `_pad`
/// Sentry attachment item carrying random bytes, so the result is still a valid
/// envelope. The final length lands **on** the bucket exactly when arithmetic
/// permits; if exact landing is impossible for a tiny gap, the next bucket is
/// targeted so the result is never *between* buckets.
#[must_use]
pub fn pad_envelope_bytes(envelope: &Envelope, buckets: &[usize]) -> Vec<u8> {
    let base = envelope.to_bytes();
    pad_bytes_with_rng(envelope, &base, buckets, &mut rand::thread_rng())
}

/// Deterministic core of [`pad_envelope_bytes`] (rng injected for tests).
#[must_use]
pub fn pad_bytes_with_rng(
    envelope: &Envelope,
    base: &[u8],
    buckets: &[usize],
    rng: &mut impl Rng,
) -> Vec<u8> {
    let current = base.len();
    let overhead = pad_item_fixed_overhead();

    // Find a bucket we can land on exactly. Walk ascending buckets >= current
    // and pick the first that admits an exact (or empty-item) pad length.
    let mut candidates: Vec<usize> = buckets.iter().copied().filter(|&b| b >= current).collect();
    candidates.sort_unstable();

    for target in candidates {
        if target == current {
            // Already exactly on a bucket — no pad needed.
            return base.to_vec();
        }
        if let Some(rand_len) = pad_random_len(current, target, overhead) {
            return assemble_padded(envelope, rand_len, rng);
        }
        // else: this bucket can't be hit exactly (gap smaller than overhead);
        // try the next, larger bucket.
    }
    // No bucket fits (already larger than all) — send unchanged.
    base.to_vec()
}

/// Build the padded envelope bytes by appending a `_pad` item of `rand_len`
/// random bytes.
#[must_use]
fn assemble_padded(envelope: &Envelope, rand_len: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut padded = envelope.clone();
    let mut bytes = vec![0u8; rand_len];
    rng.fill(&mut bytes[..]);
    padded.items.push(EnvelopeItem {
        item_type: "attachment".to_string(),
        attachment_type: None,
        filename: Some(PAD_ITEM_NAME.to_string()),
        content_type: Some(PAD_ITEM_CONTENT_TYPE.to_string()),
        payload: bytes,
    });
    padded.to_bytes()
}

/// Build the fixed, minimal HTTP/1.1 request header lines for the envelope POST.
///
/// Deliberately omits `User-Agent`, `Accept`, `Accept-Encoding`, and every
/// `X-Forwarded`/geo header. Every W1TN3SS client emits **identical** header
/// bytes, so the header set identifies the *tool*, never the *user* (research
/// §5, "HTTP header fingerprint").
#[must_use]
pub fn build_request_headers(host: &str, path: &str, content_length: usize) -> Vec<u8> {
    let mut req = String::new();
    req.push_str(&format!("POST {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host}\r\n"));
    req.push_str("Content-Type: application/x-sentry-envelope\r\n");
    req.push_str(&format!("Content-Length: {content_length}\r\n"));
    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");
    req.into_bytes()
}

/// Sample a uniform random delay within the jitter bounds.
#[must_use]
pub fn sample_jitter(min: Duration, max: Duration) -> Duration {
    sample_jitter_with_rng(min, max, &mut rand::thread_rng())
}

/// Deterministic core of [`sample_jitter`] (rng injected for tests).
#[must_use]
pub fn sample_jitter_with_rng(min: Duration, max: Duration, rng: &mut impl Rng) -> Duration {
    if max <= min {
        return min;
    }
    let span = max.as_millis().saturating_sub(min.as_millis());
    if span == 0 {
        return min;
    }
    let extra = rng.gen_range(0..=span);
    min + Duration::from_millis(extra.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itasha_report_core::report::Report;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn env_for(body: &str) -> Envelope {
        Envelope::from_report(&Report::crash(body), Some("a".repeat(32)))
    }

    #[test]
    fn target_bucket_picks_smallest_fitting() {
        let buckets = [4096, 16384, 65536];
        assert_eq!(target_bucket(10, &buckets), Some(4096));
        assert_eq!(target_bucket(4096, &buckets), Some(4096));
        assert_eq!(target_bucket(5000, &buckets), Some(16384));
        assert_eq!(target_bucket(100_000, &buckets), None);
    }

    #[test]
    fn small_report_pads_up_to_first_bucket_exactly() {
        let env = env_for("panic");
        let base_len = env.to_bytes().len();
        assert!(base_len < 4096, "fixture should be smaller than 4 KiB");
        let buckets = [4096usize, 16384, 65536];
        let mut rng = StdRng::seed_from_u64(7);
        let padded = pad_bytes_with_rng(&env, &env.to_bytes(), &buckets, &mut rng);
        assert_eq!(
            padded.len(),
            4096,
            "padded envelope must land exactly on the 4 KiB bucket"
        );
    }

    #[test]
    fn padding_is_monotonic_across_buckets() {
        let buckets = [4096usize, 16384, 65536, 262_144];
        let mut rng = StdRng::seed_from_u64(11);
        // A ~5 KiB body → must land on 16 KiB.
        let env = env_for(&"x".repeat(5000));
        let base = env.to_bytes();
        assert!(base.len() > 4096 && base.len() < 16384);
        let padded = pad_bytes_with_rng(&env, &base, &buckets, &mut rng);
        assert_eq!(padded.len(), 16384);
    }

    #[test]
    fn oversize_report_sent_unpadded() {
        let buckets = [4096usize, 16384];
        let mut rng = StdRng::seed_from_u64(3);
        let env = env_for(&"y".repeat(50_000));
        let base = env.to_bytes();
        assert!(base.len() > 16384);
        let padded = pad_bytes_with_rng(&env, &base, &buckets, &mut rng);
        assert_eq!(padded, base, "over-bucket payload must be sent unchanged");
    }

    #[test]
    fn padded_envelope_is_still_parseable_and_size_hidden() {
        // Two different-sized small reports must produce identical padded sizes,
        // so the on-wire size reveals nothing about the true report size.
        let buckets = [4096usize, 16384];
        let mut rng = StdRng::seed_from_u64(99);
        let a = env_for("short");
        let b = env_for(&"medium-ish body content here".repeat(10));
        let pa = pad_bytes_with_rng(&a, &a.to_bytes(), &buckets, &mut rng);
        let pb = pad_bytes_with_rng(&b, &b.to_bytes(), &buckets, &mut rng);
        assert_eq!(pa.len(), 4096);
        assert_eq!(pb.len(), 4096);
        assert_eq!(pa.len(), pb.len(), "size correlation must be defeated");
        // Still a valid envelope (round-trips through the core parser).
        let parsed = Envelope::from_bytes(&pa).expect("padded envelope must parse");
        assert!(
            parsed
                .items
                .iter()
                .any(|i| i.filename.as_deref() == Some(PAD_ITEM_NAME)),
            "pad item present"
        );
    }

    #[test]
    fn headers_have_no_user_agent_or_fingerprint() {
        let h = build_request_headers("abcd.onion", "/api/1/envelope/", 1234);
        let s = String::from_utf8(h).unwrap();
        assert!(s.starts_with("POST /api/1/envelope/ HTTP/1.1\r\n"));
        assert!(s.contains("Host: abcd.onion\r\n"));
        assert!(s.contains("Content-Type: application/x-sentry-envelope\r\n"));
        assert!(s.contains("Content-Length: 1234\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        // The hygiene invariant: NO identity/fingerprint headers.
        let lower = s.to_lowercase();
        assert!(!lower.contains("user-agent"), "must not send User-Agent");
        assert!(!lower.contains("accept"), "must not send Accept-*");
        assert!(!lower.contains("x-forwarded"), "must not send X-Forwarded");
        assert!(!lower.contains("cookie"), "must not send Cookie");
    }

    #[test]
    fn jitter_is_bounded() {
        let mut rng = StdRng::seed_from_u64(42);
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(10);
        for _ in 0..1000 {
            let d = sample_jitter_with_rng(min, max, &mut rng);
            assert!(
                d >= min && d <= max,
                "jitter {d:?} out of [{min:?},{max:?}]"
            );
        }
    }

    #[test]
    fn jitter_zero_span_is_immediate() {
        let mut rng = StdRng::seed_from_u64(1);
        let d = sample_jitter_with_rng(Duration::ZERO, Duration::ZERO, &mut rng);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn jitter_varies_within_bounds() {
        // Across many samples we should see spread (not a constant), proving the
        // delay is actually randomized.
        let mut rng = StdRng::seed_from_u64(123);
        let min = Duration::from_secs(0);
        let max = Duration::from_secs(60);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(sample_jitter_with_rng(min, max, &mut rng).as_millis());
        }
        assert!(seen.len() > 50, "jitter should produce varied delays");
    }
}
