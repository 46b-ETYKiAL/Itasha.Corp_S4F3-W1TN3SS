//! The Tier-A measurement: the low-dimensional, k-anonymity-friendly value the
//! STAR protocol aggregates.
//!
//! A measurement is two parts:
//!
//! 1. The **STAR secret** — the [`crash_signature`](crate::signature::crash_signature):
//!    the value that must reach k *distinct* submitters before the operator can
//!    read it. Two devices crashing in the same path produce the same secret,
//!    so they self-collide toward the threshold with **no per-user identifier**.
//! 2. The **coarse quasi-tuple** — `app_version`→MAJOR.MINOR, `os`→MAJOR.MINOR,
//!    `locale`→LANGUAGE — carried as STAR **associated data** and revealed ONLY
//!    once the secret reaches k. This is reused VERBATIM from
//!    `itasha_report_core::quasi` (the same coarsening the Tier-B lean path uses)
//!    so there is one coarsening home, not two.
//!
//! Why the tuple is coarse (and *only* these three keys): k-anonymity defeats
//! singling-out, but quasi-identifiers riding along can re-enable
//! inference/linkability (WP216). The coarser the tuple, the larger the
//! anonymity set per signature. We deliberately carry NO timezone, build-hash,
//! timestamp, hostname, module-set, or locale region — exactly the
//! `quasi::ALWAYS_DROPPED` set.
//!
//! The associated-data tuple is serialized as a stable, newline-free,
//! delimiter-joined string (`app_version=1.4|os=Windows 11|locale=en`) so two
//! devices with the same coarse class produce byte-identical aux — which keeps
//! the (signature, aux) pair itself low-cardinality.

use itasha_report_core::quasi::{coarsen_locale, coarsen_os, coarsen_version};

/// The coarse quasi-identifier tuple carried as STAR associated data.
///
/// Every field is already coarsened (or `None` if it was absent/unparseable).
/// The tuple is intentionally tiny — three low-entropy dimensions — so the
/// (signature, tuple) pair stays k-anonymity-friendly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoarseTuple {
    /// App version, coarsened to MAJOR.MINOR (patch/build/sha dropped).
    pub app_version: Option<String>,
    /// OS, coarsened to NAME MAJOR.MINOR (build number dropped).
    pub os: Option<String>,
    /// Locale, coarsened to the LANGUAGE subtag only (region/script dropped).
    pub locale: Option<String>,
}

impl CoarseTuple {
    /// Build the coarse tuple from raw (uncoarsened) metadata key/values,
    /// reading ONLY `app_version`, `os`, and `locale` (case-insensitive) and
    /// coarsening each via the shared `itasha_report_core::quasi` functions.
    /// Every other key is ignored — the tuple is allowlist-shaped.
    #[must_use]
    pub fn from_metadata(metadata: &[(String, String)]) -> Self {
        let find = |key: &str| {
            metadata
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.as_str())
        };
        Self {
            app_version: find("app_version").and_then(coarsen_version),
            os: find("os").and_then(coarsen_os),
            locale: find("locale").and_then(coarsen_locale),
        }
    }

    /// Serialize to the stable associated-data wire form
    /// `app_version=<v>|os=<o>|locale=<l>`, omitting absent fields. Order is
    /// fixed (version, os, locale) so two devices in the same coarse class
    /// produce byte-identical aux. Never contains a newline (STAR aux is opaque
    /// bytes; we keep it human-auditable and delimiter-stable).
    #[must_use]
    pub fn to_aux_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = &self.app_version {
            parts.push(format!("app_version={v}"));
        }
        if let Some(o) = &self.os {
            parts.push(format!("os={o}"));
        }
        if let Some(l) = &self.locale {
            parts.push(format!("locale={l}"));
        }
        parts.join("|")
    }
}

/// A complete Tier-A measurement ready for STAR message construction: the secret
/// signature plus the coarse associated-data tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateMeasurement {
    /// The STAR secret (crash signature) — gated to k distinct submitters.
    pub signature: String,
    /// The coarse quasi-tuple carried as associated data, revealed at threshold.
    pub tuple: CoarseTuple,
}

impl AggregateMeasurement {
    /// Construct a measurement from a precomputed signature and raw metadata.
    #[must_use]
    pub fn new(signature: impl Into<String>, metadata: &[(String, String)]) -> Self {
        Self {
            signature: signature.into(),
            tuple: CoarseTuple::from_metadata(metadata),
        }
    }

    /// The bytes used as the STAR secret (the value that must reach k submitters).
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }

    /// The bytes used as the STAR associated data (revealed only at threshold).
    #[must_use]
    pub fn aux_bytes(&self) -> Vec<u8> {
        self.tuple.to_aux_string().into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn tuple_coarsens_via_shared_quasi() {
        let t = CoarseTuple::from_metadata(&meta(&[
            ("app_version", "1.4.37-rc2+sha"),
            ("os", "Windows 11 26100.1234"),
            ("locale", "en-US"),
        ]));
        assert_eq!(t.app_version.as_deref(), Some("1.4"));
        assert_eq!(t.os.as_deref(), Some("Windows 11"));
        assert_eq!(t.locale.as_deref(), Some("en"));
    }

    #[test]
    fn tuple_drops_everything_outside_the_three_keys() {
        // No timezone / build-hash / hostname / module-set may enter the tuple.
        let t = CoarseTuple::from_metadata(&meta(&[
            ("timezone", "America/New_York"),
            ("build_hash", "deadbeef"),
            ("hostname", "ada-laptop"),
            ("modules", "ntdll.dll,evil.dll"),
            ("app_version", "2.0.0"),
        ]));
        assert_eq!(t.app_version.as_deref(), Some("2.0"));
        assert_eq!(t.os, None);
        assert_eq!(t.locale, None);
        let aux = t.to_aux_string();
        for needle in [
            "timezone",
            "America",
            "deadbeef",
            "ada-laptop",
            "ntdll",
            "evil",
        ] {
            assert!(!aux.contains(needle), "quasi-id leaked into aux: {needle}");
        }
    }

    #[test]
    fn aux_string_is_stable_and_order_fixed() {
        let raw_a = meta(&[
            ("locale", "fr-FR"),
            ("app_version", "9.9.9"),
            ("os", "linux"),
        ]);
        let raw_b = meta(&[
            ("os", "linux"),
            ("locale", "fr-FR"),
            ("app_version", "9.9.9"),
        ]);
        // Same coarse class regardless of input order → byte-identical aux.
        let a = CoarseTuple::from_metadata(&raw_a).to_aux_string();
        let b = CoarseTuple::from_metadata(&raw_b).to_aux_string();
        assert_eq!(a, b);
        assert_eq!(a, "app_version=9.9|os=linux|locale=fr");
        assert!(!a.contains('\n'), "aux must never contain a newline");
    }

    #[test]
    fn empty_metadata_yields_empty_aux() {
        let t = CoarseTuple::from_metadata(&[]);
        assert_eq!(t, CoarseTuple::default());
        assert_eq!(t.to_aux_string(), "");
    }

    #[test]
    fn measurement_exposes_secret_and_aux_bytes() {
        let m = AggregateMeasurement::new(
            "a".repeat(64),
            &meta(&[("app_version", "1.2.3"), ("os", "macOS 14.5 23F79")]),
        );
        assert_eq!(m.secret_bytes(), m.signature.as_bytes());
        let aux = String::from_utf8(m.aux_bytes()).unwrap();
        assert_eq!(aux, "app_version=1.2|os=macOS 14.5");
        // The build suffix never survives.
        assert!(!aux.contains("23F79"));
    }
}
