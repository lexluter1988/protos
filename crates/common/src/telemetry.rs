use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct RuntimeStats {
    accepted: AtomicU64,
    active: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub accepted: u64,
    pub active: u64,
    pub succeeded: u64,
    pub failed: u64,
}

impl RuntimeStats {
    pub fn on_accept(&self) -> StatsSnapshot {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        self.snapshot()
    }

    pub fn on_finish(&self, success: bool) -> StatsSnapshot {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if success {
            self.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.snapshot()
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            succeeded: self.succeeded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }
}
