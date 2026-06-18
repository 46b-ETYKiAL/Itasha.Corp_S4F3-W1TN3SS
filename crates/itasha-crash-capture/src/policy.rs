//! The MINIMIZED-MEMORY minidump policy — the privacy control.
//!
//! A minidump's thread-list stream embeds raw thread-stack memory. For a note
//! editor that memory can hold fragments of the user's open documents. The
//! defense-in-depth privacy posture (tech-crash-capture.md § 1.3) starts at
//! WRITE time by capturing as little memory as possible: enough to reconstruct
//! a stack trace + register state, but dropping heap / full process memory
//! wherever the `MiniDumpWriteDump` flag surface allows.
//!
//! This module centralizes that policy as a single [`MinidumpPolicy`] so the
//! "drop heap where possible" decision is one auditable constant, not scattered
//! across capture sites. On Windows the policy maps to a `MinidumpType` flag
//! set; the monitor binary applies it via [`write_minidump`].

#[cfg(target_os = "windows")]
use minidump_writer::MinidumpType;

/// The crate-wide minidump capture policy.
///
/// The only supported policy is [`MinidumpPolicy::Minimized`] — the privacy
/// default. A `FullMemory` variant is deliberately NOT offered: this crate
/// exists to make native capture privacy-conservative, and a full-heap dump
/// would defeat that. The enum exists so the policy is a named, documented
/// value rather than a bare flag literal at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinidumpPolicy {
    /// Capture stacks + registers needed for a stack trace, and drop optional
    /// / private memory regions wherever the platform flag surface allows.
    #[default]
    Minimized,
}

impl MinidumpPolicy {
    /// The Windows `MinidumpType` flag set this policy maps to.
    ///
    /// `Normal` (= 0) already restricts the dump to "just the information
    /// necessary to capture stack traces for all existing threads" — i.e. NO
    /// full heap. We additionally OR in:
    ///
    /// * `FilterMemory` — "Stack and backing-store memory written to the
    ///   minidump should be filtered to remove all but the pointer values
    ///   necessary to reconstruct a stack trace." This is the strongest
    ///   available reduction of stack-resident document fragments.
    /// * `WithoutOptionalData` — "Reduce the data that is dumped by
    ///   eliminating memory regions that are not essential ... This can avoid
    ///   dumping memory that may contain data that is private to the user."
    ///
    /// We explicitly do NOT set any `WithFullMemory*` /
    /// `WithPrivateReadWriteMemory` / `WithIndirectlyReferencedMemory` flag —
    /// those would re-expand the captured surface.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn windows_minidump_type(self) -> MinidumpType {
        match self {
            MinidumpPolicy::Minimized => {
                MinidumpType::Normal
                    | MinidumpType::FilterMemory
                    | MinidumpType::WithoutOptionalData
            }
        }
    }

    /// Assert the policy never enables a full-memory / private-memory flag.
    ///
    /// This is a runtime cross-check the monitor and tests use to prove the
    /// privacy control is actually applied (no accidental full-heap capture).
    #[cfg(target_os = "windows")]
    #[must_use]
    pub fn is_minimized(self) -> bool {
        let t = self.windows_minidump_type();
        let forbidden = MinidumpType::WithFullMemory
            | MinidumpType::WithPrivateReadWriteMemory
            | MinidumpType::WithIndirectlyReferencedMemory
            | MinidumpType::WithFullMemoryInfo;
        !t.intersects(forbidden)
    }

    /// Non-Windows platforms: the minimized policy is the documented intent;
    /// the per-OS minidump-writer applies a stacks+registers dump. (The
    /// out-of-process monitor on Linux/macOS uses minidumper's default writer,
    /// which captures stack traces, not the full heap.)
    #[cfg(not(target_os = "windows"))]
    #[must_use]
    pub fn is_minimized(self) -> bool {
        matches!(self, MinidumpPolicy::Minimized)
    }
}

/// Write a minimized-memory minidump for the supplied crash context to
/// `destination`, applying [`MinidumpPolicy::Minimized`].
///
/// This is the single place the unsafe native write happens for the Windows
/// out-of-process path. It is a SAFE public function (it exposes no unsafe to
/// callers); the unsafe is fully internal and `// SAFETY:`-justified.
///
/// # Errors
///
/// Returns the underlying `minidump-writer` error if the OS minidump write
/// fails (e.g. the crashing process could not be opened, or the file could not
/// be written).
#[cfg(target_os = "windows")]
pub fn write_minidump(
    crash_context: &crash_context::CrashContext,
    policy: MinidumpPolicy,
    destination: &mut std::fs::File,
) -> Result<(), minidump_writer::errors::Error> {
    // SAFETY: `dump_crash_context` is `unsafe`-adjacent because, when
    // `crash_context.exception_pointers` is non-null, the caller must ensure
    // that pointer stays valid for the duration of the call. In the
    // out-of-process monitor this `crash_context` was just received over the
    // minidumper IPC from the still-suspended crashing client, so its interior
    // EXCEPTION_POINTERS are valid for this synchronous call. `dump_crash_context`
    // itself is a safe fn signature in minidump-writer 0.12 (the unsafe FFI is
    // internal to it); we wrap the call site here to document the validity
    // contract we are upholding.
    minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
        crash_context,
        Some(policy.windows_minidump_type()),
        destination,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_minimized() {
        assert_eq!(MinidumpPolicy::default(), MinidumpPolicy::Minimized);
        assert!(MinidumpPolicy::Minimized.is_minimized());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn minimized_type_excludes_full_and_private_memory() {
        let t = MinidumpPolicy::Minimized.windows_minidump_type();
        // The privacy control: NO full-heap / private-RW memory flags.
        assert!(!t.contains(MinidumpType::WithFullMemory));
        assert!(!t.contains(MinidumpType::WithPrivateReadWriteMemory));
        assert!(!t.contains(MinidumpType::WithIndirectlyReferencedMemory));
        // The reduction flags ARE set.
        assert!(t.contains(MinidumpType::FilterMemory));
        assert!(t.contains(MinidumpType::WithoutOptionalData));
        assert!(MinidumpPolicy::Minimized.is_minimized());
    }
}
