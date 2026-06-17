//! The two-stream reporting configuration model.
//!
//! Each of the two independent data streams (crash reports, manual issues) has
//! its own [`ReportingMode`]. Both default to [`ReportingMode::Off`] — the
//! opt-in, never-opt-out invariant. The streams are never bundled under one
//! toggle.

use serde::{Deserialize, Serialize};

use crate::report::Stream;

/// Per-stream consent posture.
///
/// The default is [`ReportingMode::Off`] for every stream — there is no
/// constructor anywhere in this crate that yields an on-by-default mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportingMode {
    /// Never report for this stream (the default).
    #[default]
    Off,
    /// Ask the user each time a report is available.
    AskEachTime,
    /// Always report for this stream (user previously chose "Always").
    Always,
}

impl ReportingMode {
    /// Whether this mode permits transmission **without** a fresh per-event
    /// prompt. Only [`ReportingMode::Always`] does; `Off` and `AskEachTime`
    /// both require an explicit per-event consent decision by the host.
    #[must_use]
    pub fn is_always(self) -> bool {
        matches!(self, ReportingMode::Always)
    }

    /// Whether this mode permits *any* transmission at all (i.e. not `Off`).
    #[must_use]
    pub fn permits_reporting(self) -> bool {
        !matches!(self, ReportingMode::Off)
    }
}

/// The complete reporting configuration: one [`ReportingMode`] per stream.
///
/// `schema_version` supports forward migration (the host bumps it when the
/// shape evolves); unknown future fields are ignored on read by serde's
/// default-on-missing behaviour for the modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Config schema version for forward migration.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Consent posture for the crash-report stream. Default: `Off`.
    #[serde(default)]
    pub crash_reports: ReportingMode,
    /// Consent posture for the manual-issue stream. Default: `Off`.
    #[serde(default)]
    pub manual_issues: ReportingMode,
}

const CURRENT_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

impl Default for ReportingConfig {
    /// Both streams `Off` — the privacy-default posture.
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            crash_reports: ReportingMode::Off,
            manual_issues: ReportingMode::Off,
        }
    }
}

impl ReportingConfig {
    /// The privacy-default config: every stream `Off`. Identical to
    /// [`ReportingConfig::default`]; named for call-site clarity.
    #[must_use]
    pub fn all_off() -> Self {
        Self::default()
    }

    /// The configured mode for a given stream.
    #[must_use]
    pub fn mode_for(&self, stream: Stream) -> ReportingMode {
        match stream {
            Stream::CrashReports => self.crash_reports,
            Stream::ManualIssues => self.manual_issues,
        }
    }

    /// Set the mode for a stream, returning `self` for chaining.
    #[must_use]
    pub fn with_mode(mut self, stream: Stream, mode: ReportingMode) -> Self {
        match stream {
            Stream::CrashReports => self.crash_reports = mode,
            Stream::ManualIssues => self.manual_issues = mode,
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_is_off() {
        assert_eq!(ReportingMode::default(), ReportingMode::Off);
    }

    #[test]
    fn default_config_is_off_for_both_streams() {
        let c = ReportingConfig::default();
        assert_eq!(c.crash_reports, ReportingMode::Off);
        assert_eq!(c.manual_issues, ReportingMode::Off);
        assert_eq!(c.mode_for(Stream::CrashReports), ReportingMode::Off);
        assert_eq!(c.mode_for(Stream::ManualIssues), ReportingMode::Off);
    }

    #[test]
    fn all_off_matches_default() {
        assert_eq!(ReportingConfig::all_off(), ReportingConfig::default());
    }

    #[test]
    fn off_does_not_permit_reporting() {
        assert!(!ReportingMode::Off.permits_reporting());
        assert!(ReportingMode::AskEachTime.permits_reporting());
        assert!(ReportingMode::Always.permits_reporting());
    }

    #[test]
    fn only_always_is_always() {
        assert!(ReportingMode::Always.is_always());
        assert!(!ReportingMode::AskEachTime.is_always());
        assert!(!ReportingMode::Off.is_always());
    }

    #[test]
    fn empty_json_object_deserializes_to_all_off() {
        // The critical default-OFF invariant: a config file with NO stream
        // entries (e.g. an upgrade that introduced the streams) reads as Off,
        // never on-by-default.
        let c: ReportingConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c.crash_reports, ReportingMode::Off);
        assert_eq!(c.manual_issues, ReportingMode::Off);
        assert_eq!(c.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn config_round_trips_through_json() {
        let c = ReportingConfig::default()
            .with_mode(Stream::CrashReports, ReportingMode::AskEachTime)
            .with_mode(Stream::ManualIssues, ReportingMode::Always);
        let json = serde_json::to_string(&c).unwrap();
        let back: ReportingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn with_mode_sets_correct_stream() {
        let c = ReportingConfig::default().with_mode(Stream::CrashReports, ReportingMode::Always);
        assert_eq!(c.crash_reports, ReportingMode::Always);
        // The other stream is untouched — streams are independent.
        assert_eq!(c.manual_issues, ReportingMode::Off);
    }
}
