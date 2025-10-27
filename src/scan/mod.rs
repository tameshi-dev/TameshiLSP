//! Scan orchestration
//!
//! Event-driven async architecture using tokio channels for concurrent analysis.
//! Caller provides runtime rather than creating one internally. Rolling window
//! statistics track scan performance accurately without atomics. Integrated
//! cancellation tokens work with select! for responsive shutdown.

pub mod errors;
pub mod messages;
pub mod stats;

use crate::{
    deterministic_scanner::{DeterministicScanner, ScanScope},
    proto::ScanResult as ProtoScanResult,
};
pub use errors::{ScanError, ScanResult as ScanErrorResult};
pub use messages::{ProgressEvent, ScanRequest as InternalScanRequest};
pub use stats::{ScanStats, StatsSnapshot};

use anyhow::Result;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug)]
pub enum ScanRequest {
    ScanWorkspace {
        root: PathBuf,
        progress_token: Option<String>,
        response_tx: std::sync::mpsc::Sender<Result<ProtoScanResult>>,
        exclude_patterns: Vec<String>,
    },
    ScanFile {
        path: PathBuf,
        content: Option<String>,
        progress_token: Option<String>,
        response_tx: std::sync::mpsc::Sender<Result<ProtoScanResult>>,
    },
    Cancel {
        token: String,
    },
    CancelAll,
    RefreshResults {
        response_tx: std::sync::mpsc::Sender<Result<()>>,
    },
    Shutdown,
}

pub struct ScanManager {
    scanner: DeterministicScanner,
    max_concurrent: usize,
}

struct ScanTaskContext {
    scanner: Arc<DeterministicScanner>,
    concurrency_limit: Arc<Semaphore>,
    stats: ScanStats,
    progress_tx: broadcast::Sender<ProgressEvent>,
    shutdown: CancellationToken,
}

impl ScanManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            scanner: DeterministicScanner::new(),
            max_concurrent: 4,
        })
    }

    pub fn run(self, request_rx: std::sync::mpsc::Receiver<ScanRequest>) {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        rt.block_on(async {
            match self.scanner.check_availability().await {
                Ok(true) => info!("Scanner is available and ready"),
                Ok(false) => warn!("Scanner is not available - scans will fail"),
                Err(e) => error!("Failed to check scanner availability: {}", e),
            }

            let (progress_tx, _progress_rx) = broadcast::channel(100);
            let stats = ScanStats::new();
            let concurrency_limit = Arc::new(Semaphore::new(self.max_concurrent));
            let scanner = Arc::new(self.scanner);
            let shutdown_token = CancellationToken::new();
            let mut active_tasks = JoinSet::new();

            loop {
                match request_rx.recv() {
                    Ok(ScanRequest::Shutdown) => {
                        info!("Shutdown requested");
                        shutdown_token.cancel();
                        break;
                    }
                    Ok(ScanRequest::CancelAll) => {
                        shutdown_token.cancel();
                        active_tasks.abort_all();
                    }
                    Ok(ScanRequest::ScanWorkspace {
                        root,
                        progress_token: _,
                        response_tx,
                        exclude_patterns,
                    }) => {
                        Self::spawn_scan_task(
                            &mut active_tasks,
                            ScanTaskContext {
                                scanner: Arc::clone(&scanner),
                                concurrency_limit: Arc::clone(&concurrency_limit),
                                stats: stats.clone(),
                                progress_tx: progress_tx.clone(),
                                shutdown: shutdown_token.clone(),
                            },
                            ScanScope::Workspace { root, exclude_patterns },
                            response_tx,
                        );
                    }
                    Ok(ScanRequest::ScanFile {
                        path,
                        content,
                        progress_token: _,
                        response_tx,
                    }) => {
                        Self::spawn_scan_task(
                            &mut active_tasks,
                            ScanTaskContext {
                                scanner: Arc::clone(&scanner),
                                concurrency_limit: Arc::clone(&concurrency_limit),
                                stats: stats.clone(),
                                progress_tx: progress_tx.clone(),
                                shutdown: shutdown_token.clone(),
                            },
                            ScanScope::File { path, content },
                            response_tx,
                        );
                    }
                    Ok(ScanRequest::RefreshResults { response_tx }) => {
                        let _ = response_tx.send(Ok(()));
                    }
                    Ok(ScanRequest::Cancel { .. }) => {
                        debug!("Token-based cancellation not yet implemented");
                    }
                    Err(_) => {
                        info!("Request channel disconnected, shutting down");
                        break;
                    }
                }

                while let Some(result) = active_tasks.try_join_next() {
                    match result {
                        Ok(()) => debug!("Task completed successfully"),
                        Err(e) if e.is_cancelled() => debug!("Task was cancelled"),
                        Err(e) => warn!("Task panicked: {}", e),
                    }
                }
            }

            while active_tasks.join_next().await.is_some() {}
            info!("ScanManager shutdown complete");
        });
    }

    fn spawn_scan_task(
        tasks: &mut JoinSet<()>,
        ctx: ScanTaskContext,
        scope: ScanScope,
        response_tx: std::sync::mpsc::Sender<Result<ProtoScanResult>>,
    ) {
        let operation_id = Uuid::new_v4();

        tasks.spawn(async move {
            let _permit = ctx.concurrency_limit.acquire().await.unwrap();

            ctx.stats.scan_started();
            let start = std::time::Instant::now();

            let _ = ctx.progress_tx.send(ProgressEvent::Started {
                operation_id,
                scope: (&scope).into(),
            });

            tokio::select! {
                result = ctx.scanner.scan_async(&scope) => {
                    let duration = start.elapsed();
                    match result {
                        Ok(scan_result) => {
                            ctx.stats.scan_completed(duration);
                            let _ = ctx.progress_tx.send(ProgressEvent::Completed {
                                operation_id,
                                total_findings: scan_result.findings.len(),
                                duration_ms: duration.as_millis() as u64,
                            });
                            let _ = response_tx.send(Ok(scan_result));
                        }
                        Err(e) => {
                            ctx.stats.scan_failed();
                            let _ = ctx.progress_tx.send(ProgressEvent::Failed {
                                operation_id,
                                error: e.to_string(),
                            });
                            let _ = response_tx.send(Err(e));
                        }
                    }
                }
                _ = ctx.shutdown.cancelled() => {
                    ctx.stats.scan_failed();
                    let _ = response_tx.send(Err(anyhow::anyhow!("Scan cancelled")));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_scan_manager_creation() {
        let manager = ScanManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_scan_request_variants() {
        let (tx, _rx) = std::sync::mpsc::channel();

        let _req = ScanRequest::ScanWorkspace {
            root: PathBuf::from("/test"),
            exclude_patterns: vec![],
            progress_token: None,
            response_tx: tx.clone(),
        };

        let _req = ScanRequest::ScanFile {
            path: PathBuf::from("/test/file.sol"),
            content: None,
            progress_token: None,
            response_tx: tx.clone(),
        };

        let _req = ScanRequest::Cancel {
            token: "test-token".to_string(),
        };

        let _req = ScanRequest::Shutdown;
    }
}
