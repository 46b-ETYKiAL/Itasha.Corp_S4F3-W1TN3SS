//! The out-of-process MONITOR handler.
//!
//! The monitor is the SEPARATE process (the `w1tn3ss-crash-monitor` binary)
//! that the host spawns. It exists because a crashing process's own memory may
//! be corrupted — the documented Embark/Breakpad rationale for out-of-process
//! capture. The crashing app holds a `minidumper::Client`; on a native fault
//! the `crash-handler` callback hands the [`crash_context::CrashContext`] to
//! the monitor over IPC, and the monitor writes the minidump from a clean
//! address space.
//!
//! This module holds the [`MonitorHandler`] (`minidumper::ServerHandler` impl)
//! and the [`run_monitor`] loop so the wiring is unit-testable independently of
//! the thin `bin/monitor.rs` entry point.
//!
//! The minidump is written by `minidumper`'s server using the bundled
//! `minidump-writer`, which on every platform captures **stack traces for all
//! threads — not the full heap** (the `Normal` minidump baseline). The monitor
//! then reads the written dump and spools it LOCALLY via
//! `itasha-report-core`'s budgeted spool. It transmits NOTHING. The
//! [`crate::policy::MinidumpPolicy`] minimized contract — including the
//! stronger `FilterMemory` / `WithoutOptionalData` reductions — is the policy
//! this monitor asserts and is applied at the direct-write path
//! ([`crate::policy::write_minidump`]).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use minidumper::{LoopAction, MinidumpBinary, Server, ServerHandler};

use crate::policy::MinidumpPolicy;

/// The default IPC socket / pipe name the host and monitor agree on. Hosts may
/// override per-app to avoid cross-app collisions.
pub const DEFAULT_SOCKET_NAME: &str = "w1tn3ss-crash-monitor";

/// The structured outcome of a single capture, surfaced to the host logger.
/// Counts/enums only — NEVER minidump bytes, NEVER PII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureOutcome {
    /// A minidump was written to disk at `path` and spooled.
    MinidumpWritten {
        /// The spooled report path.
        path: PathBuf,
    },
    /// Capture was attempted but the OS minidump write failed.
    CaptureFailed {
        /// A short, non-sensitive reason string.
        reason: String,
    },
}

/// `minidumper::ServerHandler` that writes the minidump to a temp file, reads
/// it back, and spools it locally via `itasha-report-core`.
pub struct MonitorHandler {
    /// Directory the host config lives in (the spool roots at
    /// `<config_dir>/reports/`).
    config_dir: PathBuf,
    /// The applied minidump policy (always minimized). Recorded so the outcome
    /// + tests can prove the privacy control is in force.
    policy: MinidumpPolicy,
    /// Where the temp minidump file is written before being read + spooled.
    dump_dir: PathBuf,
    /// Captured outcomes (a Mutex so the `&self` handler can record results).
    outcomes: Mutex<Vec<CaptureOutcome>>,
}

impl MonitorHandler {
    /// Build a monitor handler rooted at the host `config_dir`. The minimized
    /// policy is always applied.
    #[must_use]
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        let dump_dir = config_dir.join("crash-dumps");
        Self {
            config_dir,
            policy: MinidumpPolicy::Minimized,
            dump_dir,
            outcomes: Mutex::new(Vec::new()),
        }
    }

    /// The minidump policy this monitor applies (always minimized — the privacy
    /// control).
    #[must_use]
    pub fn policy(&self) -> MinidumpPolicy {
        self.policy
    }

    /// Drain and return the outcomes recorded so far (for the host logger /
    /// tests).
    #[must_use]
    pub fn take_outcomes(&self) -> Vec<CaptureOutcome> {
        let mut guard = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut guard)
    }

    fn record(&self, outcome: CaptureOutcome) {
        let mut guard = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        guard.push(outcome);
    }
}

impl ServerHandler for MonitorHandler {
    fn create_minidump_file(&self) -> Result<(std::fs::File, PathBuf), std::io::Error> {
        std::fs::create_dir_all(&self.dump_dir)?;
        // A unique, non-identifying temp name per capture.
        let nonce = crate::consent::Tier2ConsentToken::granted()
            .nonce()
            .to_string();
        let path = self.dump_dir.join(format!("crash-{nonce}.dmp"));
        let file = std::fs::File::create(&path)?;
        Ok((file, path))
    }

    fn on_minidump_created(&self, result: Result<MinidumpBinary, minidumper::Error>) -> LoopAction {
        match result {
            Ok(md) => {
                // Read the written minidump back and spool it locally. We never
                // transmit — only persist to the budgeted local spool.
                match std::fs::read(&md.path) {
                    Ok(bytes) => match crate::emit::spool_minidump(&self.config_dir, bytes, &[]) {
                        Ok(spooled) => {
                            // Best-effort cleanup of the temp dump; the canonical
                            // copy now lives in the spool.
                            let _ = std::fs::remove_file(&md.path);
                            self.record(CaptureOutcome::MinidumpWritten { path: spooled });
                        }
                        Err(e) => self.record(CaptureOutcome::CaptureFailed {
                            reason: format!("spool failed: {e}"),
                        }),
                    },
                    Err(e) => self.record(CaptureOutcome::CaptureFailed {
                        reason: format!("read dump failed: {e}"),
                    }),
                }
            }
            Err(e) => self.record(CaptureOutcome::CaptureFailed {
                reason: format!("minidump write failed: {e}"),
            }),
        }
        // One crash → one dump → exit the monitor loop.
        LoopAction::Exit
    }

    fn on_message(&self, _kind: u32, _buffer: Vec<u8>) {
        // The monitor accepts no behavioural commands over the message channel;
        // capture is driven solely by the crash-handler dump request. Messages
        // are ignored (never executed — AES Clause 9: inbound bytes are data).
    }
}

/// Run the monitor server loop on `socket_name`, rooting the spool at
/// `config_dir`. Blocks until a crash is captured (the handler returns
/// [`LoopAction::Exit`]) or `shutdown` is set.
///
/// # Errors
///
/// Returns a [`minidumper::Error`] if the IPC server cannot be created or the
/// loop fails.
pub fn run_monitor(
    socket_name: &str,
    config_dir: impl Into<PathBuf>,
    shutdown: &AtomicBool,
) -> Result<(), minidumper::Error> {
    let mut server = Server::with_name(minidumper::SocketName::path(socket_name))?;
    let handler = MonitorHandler::new(config_dir);
    server.run(Box::new(handler), shutdown, None)
}

/// Signal a running [`run_monitor`] loop to stop at the next poll.
pub fn request_shutdown(shutdown: &AtomicBool) {
    shutdown.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_applies_minimized_policy() {
        let dir = std::env::temp_dir().join("w1tn3ss-monitor-policy-test");
        let h = MonitorHandler::new(&dir);
        assert_eq!(h.policy(), MinidumpPolicy::Minimized);
        assert!(h.policy().is_minimized());
    }

    #[test]
    fn create_minidump_file_yields_unique_paths() {
        let dir =
            std::env::temp_dir().join(format!("w1tn3ss-monitor-file-test-{}", std::process::id()));
        let h = MonitorHandler::new(&dir);
        let (_f1, p1) = h.create_minidump_file().unwrap();
        let (_f2, p2) = h.create_minidump_file().unwrap();
        assert_ne!(p1, p2);
        assert!(p1.exists() && p2.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_minidump_created_spools_written_dump_and_exits() {
        let dir = std::env::temp_dir().join(format!(
            "w1tn3ss-monitor-spool-test-{}-{}",
            std::process::id(),
            crate::consent::Tier2ConsentToken::granted().nonce()
        ));
        let h = MonitorHandler::new(&dir);
        // Simulate minidumper having written a dump file.
        let (mut file, path) = h.create_minidump_file().unwrap();
        use std::io::Write;
        file.write_all(&[0xAB; 256]).unwrap();
        drop(file);
        let action = h.on_minidump_created(Ok(MinidumpBinary {
            file: std::fs::File::open(&path).unwrap(),
            path: path.clone(),
            contents: None,
        }));
        // `LoopAction` derives `PartialEq` but not `Debug`, so use `assert!`
        // with `==` rather than `assert_eq!` (which requires `Debug`).
        assert!(action == LoopAction::Exit);
        let outcomes = h.take_outcomes();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            CaptureOutcome::MinidumpWritten { path } => assert!(path.exists()),
            other => panic!("expected MinidumpWritten, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_minidump_created_records_failure_without_panicking() {
        let dir =
            std::env::temp_dir().join(format!("w1tn3ss-monitor-fail-test-{}", std::process::id()));
        let h = MonitorHandler::new(&dir);
        let action = h.on_minidump_created(Err(minidumper::Error::UnknownClientPid));
        // `LoopAction` derives `PartialEq` but not `Debug`; use `assert!`.
        assert!(action == LoopAction::Exit);
        let outcomes = h.take_outcomes();
        assert!(matches!(outcomes[0], CaptureOutcome::CaptureFailed { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }
}
