//! The in-memory report model carried through sanitize → preview → spool →
//! send. A [`Report`] is plain data; it never executes its own content
//! (AES Clause 9 — inbound content is data, never instructions).

use serde::{Deserialize, Serialize};

/// Which of the two independent data streams a report belongs to. The streams
/// are never bundled under one consent toggle (the cardinal privacy rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// High-sensitivity crash reports (panic backtrace; Tier-2 minidump opt-in).
    CrashReports,
    /// User-initiated manual issue / feedback submissions.
    ManualIssues,
}

/// A single report awaiting preview / spool / transmission.
///
/// The `body` holds the Tier-1 previewable text (a sanitized backtrace or a
/// user-typed issue). `attachments` carries optional opaque Tier-2 blobs (e.g.
/// a minidump produced by `itasha-crash-capture`) that are NOT previewable and
/// require heightened consent downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Stream classification (drives which consent toggle gates the send).
    pub stream: Stream,
    /// A short, non-identifying title for the report.
    pub title: String,
    /// The Tier-1 previewable, redactable text payload.
    pub body: String,
    /// Structured key/value metadata (already-sanitized; e.g. os, app_version).
    pub metadata: Vec<(String, String)>,
    /// Optional Tier-2 opaque attachments (name, bytes). Not previewable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

/// An opaque Tier-2 attachment (e.g. a minidump). Carried, never inspected
/// or executed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Logical name of the attachment (e.g. `"minidump"`).
    pub name: String,
    /// MIME content-type for the envelope part.
    pub content_type: String,
    /// Raw bytes. Opaque to this crate.
    pub bytes: Vec<u8>,
}

impl Report {
    /// Construct a crash report from a (raw, not-yet-sanitized) backtrace text.
    /// Run it through [`crate::sanitize::Sanitizer`] before preview / send.
    pub fn crash(backtrace: impl Into<String>) -> Self {
        Self {
            stream: Stream::CrashReports,
            title: "crash report".to_string(),
            body: backtrace.into(),
            metadata: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// Construct a manual issue report from user-typed text.
    pub fn manual_issue(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            stream: Stream::ManualIssues,
            title: title.into(),
            body: body.into(),
            metadata: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// Attach already-sanitized structured metadata. Returns `self` for chaining.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_report_is_crash_stream() {
        let r = Report::crash("boom");
        assert_eq!(r.stream, Stream::CrashReports);
        assert_eq!(r.body, "boom");
        assert!(r.attachments.is_empty());
    }

    #[test]
    fn manual_issue_is_manual_stream() {
        let r = Report::manual_issue("title", "body").with_metadata("os", "linux");
        assert_eq!(r.stream, Stream::ManualIssues);
        assert_eq!(r.metadata, vec![("os".to_string(), "linux".to_string())]);
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = Report::crash("panic").with_metadata("app_version", "0.1.0");
        let json = serde_json::to_string(&r).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
