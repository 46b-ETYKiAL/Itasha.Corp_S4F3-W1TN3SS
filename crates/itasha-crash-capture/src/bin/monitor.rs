//! The `w1tn3ss-crash-monitor` binary — the SEPARATE out-of-process minidump
//! writer.
//!
//! This is a thin entry point: all logic lives in the library
//! (`itasha_crash_capture::run_monitor_main`) so it is unit-testable. Keeping
//! the monitor a distinct `[[bin]]` is load-bearing — the unsafe-isolation
//! structural test asserts it is a separate binary, so the unsafe native write
//! happens in a different process from the host app.
//!
//! Hosts that re-exec their own binary as the monitor (the self-spawn pattern)
//! should instead dispatch `itasha_crash_capture::is_monitor_invocation` /
//! `run_monitor_main` from their own `main`; this standalone binary is for hosts
//! that ship the monitor as a separate executable.

fn main() {
    let code = itasha_crash_capture::run_monitor_main(std::env::args());
    std::process::exit(code);
}
