//! Scan statistics
//!
//! Tracks performance metrics using a mutex-protected rolling window. Atomics
//! alone cannot compute accurate averages across samples.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_SAMPLES: usize = 100;

#[derive(Debug, Clone)]
pub struct ScanStats {
    inner: Arc<Mutex<StatsInner>>,
}

#[derive(Debug)]
struct StatsInner {
    total_scans: u64,
    active_scans: u64,
    failed_scans: u64,
    duration_samples: VecDeque<u64>,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner {
                total_scans: 0,
                active_scans: 0,
                failed_scans: 0,
                duration_samples: VecDeque::with_capacity(MAX_SAMPLES),
            })),
        }
    }

    pub fn scan_started(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.total_scans += 1;
        inner.active_scans += 1;
    }

    pub fn scan_completed(&self, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_scans = inner.active_scans.saturating_sub(1);

        let duration_ms = duration.as_millis() as u64;
        if inner.duration_samples.len() >= MAX_SAMPLES {
            inner.duration_samples.pop_front();
        }
        inner.duration_samples.push_back(duration_ms);
    }

    pub fn scan_failed(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_scans = inner.active_scans.saturating_sub(1);
        inner.failed_scans += 1;
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let inner = self.inner.lock().unwrap();
        let avg_duration_ms = if inner.duration_samples.is_empty() {
            0
        } else {
            inner.duration_samples.iter().sum::<u64>() / inner.duration_samples.len() as u64
        };

        StatsSnapshot {
            total_scans: inner.total_scans,
            active_scans: inner.active_scans,
            failed_scans: inner.failed_scans,
            average_duration_ms: avg_duration_ms,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub total_scans: u64,
    pub active_scans: u64,
    pub failed_scans: u64,
    pub average_duration_ms: u64,
}
