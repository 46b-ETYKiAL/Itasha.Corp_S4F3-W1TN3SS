//! The local-first spool.
//!
//! Reports are written to `<config_dir>/reports/` as one JSON file per report
//! via an **atomic write-to-temp + rename**, so a crash mid-write never leaves
//! a half-written report. The spool enforces a **count budget** and a **byte
//! budget**: when adding a report would exceed either, the oldest reports are
//! evicted (retention) until the budgets hold.
//!
//! The spool transmits nothing — it is the durable, offline-first staging area
//! the host drains on consent.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::report::Report;

/// Spool error surface.
#[derive(Debug)]
pub enum SpoolError {
    /// An I/O error touching the spool directory or a report file.
    Io(std::io::Error),
    /// A report failed to (de)serialize.
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpoolError::Io(e) => write!(f, "spool io error: {e}"),
            SpoolError::Serialize(e) => write!(f, "spool serialize error: {e}"),
        }
    }
}

impl std::error::Error for SpoolError {}

impl From<std::io::Error> for SpoolError {
    fn from(e: std::io::Error) -> Self {
        SpoolError::Io(e)
    }
}

impl From<serde_json::Error> for SpoolError {
    fn from(e: serde_json::Error) -> Self {
        SpoolError::Serialize(e)
    }
}

/// Budget governing how much the spool may retain.
#[derive(Debug, Clone, Copy)]
pub struct SpoolBudget {
    /// Maximum number of spooled reports.
    pub max_reports: usize,
    /// Maximum total bytes of all spooled report files.
    pub max_total_bytes: u64,
}

impl Default for SpoolBudget {
    fn default() -> Self {
        Self {
            max_reports: 64,
            max_total_bytes: 8 * 1024 * 1024,
        }
    }
}

/// A local-first, budgeted report spool rooted at a directory.
#[derive(Debug, Clone)]
pub struct Spool {
    dir: PathBuf,
    budget: SpoolBudget,
}

impl Spool {
    /// Open (creating if needed) a spool at `<config_dir>/reports/`.
    pub fn open(config_dir: impl AsRef<Path>) -> Result<Self, SpoolError> {
        Self::open_with_budget(config_dir, SpoolBudget::default())
    }

    /// Open a spool with an explicit budget.
    pub fn open_with_budget(
        config_dir: impl AsRef<Path>,
        budget: SpoolBudget,
    ) -> Result<Self, SpoolError> {
        let dir = config_dir.as_ref().join("reports");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir, budget })
    }

    /// The directory backing this spool.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Persist a report atomically, then enforce the budget (evicting the
    /// oldest reports until count and byte budgets both hold). Returns the path
    /// of the written report.
    pub fn enqueue(&self, report: &Report) -> Result<PathBuf, SpoolError> {
        let json = serde_json::to_vec_pretty(report)?;
        let stamp = file_stamp();
        let final_path = self.dir.join(format!("report-{stamp}.json"));
        let tmp_path = self.dir.join(format!(".report-{stamp}.json.tmp"));

        // Atomic write: write to a temp file, flush+sync, then rename.
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&json)?;
            f.flush()?;
            f.sync_all()?;
        }
        // rename is atomic on the same filesystem on all target platforms.
        fs::rename(&tmp_path, &final_path)?;

        self.enforce_budget()?;
        Ok(final_path)
    }

    /// List spooled report file paths, oldest first (by filename stamp).
    pub fn list(&self) -> Result<Vec<PathBuf>, SpoolError> {
        let mut entries: Vec<PathBuf> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("json")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("report-"))
            })
            .collect();
        entries.sort();
        Ok(entries)
    }

    /// Number of spooled reports.
    pub fn count(&self) -> Result<usize, SpoolError> {
        Ok(self.list()?.len())
    }

    /// Total bytes consumed by spooled report files.
    pub fn total_bytes(&self) -> Result<u64, SpoolError> {
        let mut total = 0;
        for p in self.list()? {
            total += fs::metadata(&p)?.len();
        }
        Ok(total)
    }

    /// Load a spooled report from a path.
    pub fn load(&self, path: &Path) -> Result<Report, SpoolError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Remove a spooled report (e.g. after a successful send).
    pub fn remove(&self, path: &Path) -> Result<(), SpoolError> {
        fs::remove_file(path)?;
        Ok(())
    }

    /// Evict oldest reports until both budgets are satisfied.
    fn enforce_budget(&self) -> Result<(), SpoolError> {
        // Count budget.
        let mut files = self.list()?;
        while files.len() > self.budget.max_reports {
            let oldest = files.remove(0);
            let _ = fs::remove_file(&oldest);
        }
        // Byte budget.
        let mut total = self.total_bytes()?;
        let mut files = self.list()?;
        while total > self.budget.max_total_bytes && !files.is_empty() {
            let oldest = files.remove(0);
            let size = fs::metadata(&oldest).map(|m| m.len()).unwrap_or(0);
            let _ = fs::remove_file(&oldest);
            total = total.saturating_sub(size);
        }
        Ok(())
    }
}

/// A monotonically-increasing, collision-resistant filename stamp.
/// Combines nanos-since-epoch with a per-process counter so two enqueues in the
/// same nanosecond still sort and never collide.
fn file_stamp() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Zero-pad so lexical sort == chronological sort.
    format!("{nanos:039}-{seq:012}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "w1tn3ss-spool-test-{}-{}",
            std::process::id(),
            file_stamp()
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn enqueue_then_load_round_trips() {
        let dir = tmp_dir();
        let spool = Spool::open(&dir).unwrap();
        let r = Report::crash("panic at <HOME>/x.rs:1");
        let path = spool.enqueue(&r).unwrap();
        assert!(path.exists());
        let back = spool.load(&path).unwrap();
        assert_eq!(r, back);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn count_budget_evicts_oldest() {
        let dir = tmp_dir();
        let spool = Spool::open_with_budget(
            &dir,
            SpoolBudget {
                max_reports: 3,
                max_total_bytes: u64::MAX,
            },
        )
        .unwrap();
        for i in 0..10 {
            spool
                .enqueue(&Report::crash(format!("report {i}")))
                .unwrap();
        }
        assert_eq!(spool.count().unwrap(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn byte_budget_evicts_oldest() {
        let dir = tmp_dir();
        // A budget tight enough to hold only a couple of small reports.
        let spool = Spool::open_with_budget(
            &dir,
            SpoolBudget {
                max_reports: usize::MAX,
                max_total_bytes: 600,
            },
        )
        .unwrap();
        for i in 0..20 {
            spool
                .enqueue(&Report::crash(format!("report-number-{i}")))
                .unwrap();
        }
        assert!(spool.total_bytes().unwrap() <= 600);
        assert!(spool.count().unwrap() >= 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_temp_files_remain_after_enqueue() {
        let dir = tmp_dir();
        let spool = Spool::open(&dir).unwrap();
        spool.enqueue(&Report::crash("x")).unwrap();
        let leftovers: Vec<_> = fs::read_dir(spool.dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "atomic rename left a temp file");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_deletes_report() {
        let dir = tmp_dir();
        let spool = Spool::open(&dir).unwrap();
        let p = spool.enqueue(&Report::crash("gone")).unwrap();
        spool.remove(&p).unwrap();
        assert!(!p.exists());
        assert_eq!(spool.count().unwrap(), 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_is_oldest_first() {
        let dir = tmp_dir();
        let spool = Spool::open(&dir).unwrap();
        let p0 = spool.enqueue(&Report::crash("a")).unwrap();
        let p1 = spool.enqueue(&Report::crash("b")).unwrap();
        let listed = spool.list().unwrap();
        assert_eq!(listed, vec![p0, p1]);
        fs::remove_dir_all(&dir).ok();
    }
}
