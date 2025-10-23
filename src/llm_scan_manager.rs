//! LLM scan manager
//!
//! Orchestrates LLM-based vulnerability scanning with progress reporting and
//! cancellation. Manages concurrent requests and resource limits for LLM providers.

use anyhow::{anyhow, Result};
use chrono;
use dashmap::DashMap;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::mpsc,
    time::{interval, sleep},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    llm_scanner::{LLMScanOptions, LLMScanner},
    proto::{ScanProgressNotification, ScanResult},
};

#[derive(Debug, Clone)]
pub enum LLMScanStage {
    Initializing,
    ExtractingRepresentation,
    RunningScanners,
    AnalyzingResults,
    Completed,
    Failed,
}

impl LLMScanStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            LLMScanStage::Initializing => "Initializing",
            LLMScanStage::ExtractingRepresentation => "Extracting representation",
            LLMScanStage::RunningScanners => "Running scanners",
            LLMScanStage::AnalyzingResults => "Analyzing results",
            LLMScanStage::Completed => "Completed",
            LLMScanStage::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LLMScanOperation {
    pub id: Uuid,
    pub scope: ScanScope,
    pub stage: LLMScanStage,
    pub current_scanner: Option<String>,
    pub progress: f64,
    pub message: String,
    pub progress_token: Option<String>,
    pub cancellation_token: Arc<AtomicBool>,
    pub started_at: Instant,
    pub options: LLMScanOptions,
    pub result_tx: Option<mpsc::UnboundedSender<Result<ScanResult>>>,
}

#[derive(Debug, Clone)]
pub enum ScanScope {
    File {
        path: std::path::PathBuf,
    },
    Workspace {
        root: std::path::PathBuf,
        files: Vec<std::path::PathBuf>,
    },
    MultipleFiles {
        files: Vec<std::path::PathBuf>,
    },
}

#[derive(Debug)]
pub enum LLMScanRequest {
    ScanFile {
        path: std::path::PathBuf,
        options: LLMScanOptions,
        progress_token: Option<String>,
        response_tx: mpsc::UnboundedSender<Result<ScanResult>>,
    },
    ScanWorkspace {
        root: std::path::PathBuf,
        options: LLMScanOptions,
        progress_token: Option<String>,
        response_tx: mpsc::UnboundedSender<Result<ScanResult>>,
    },
    ScanMultipleFiles {
        files: Vec<std::path::PathBuf>,
        options: LLMScanOptions,
        progress_token: Option<String>,
        response_tx: mpsc::UnboundedSender<Result<ScanResult>>,
    },
    Cancel {
        token: String,
    },
    CancelAll,
    UpdateConfig {
        config: Box<crate::config::TameshiConfig>,
        response_tx: mpsc::UnboundedSender<Result<()>>,
    },
    GetScanners {
        response_tx: mpsc::UnboundedSender<Result<Vec<String>>>,
    },
    Shutdown,
}

#[derive(Debug, Default)]
pub struct LLMScanStats {
    pub total_scans: AtomicU64,
    pub successful_scans: AtomicU64,
    pub failed_scans: AtomicU64,
    pub cancelled_scans: AtomicU64,
    pub average_duration_ms: AtomicU64,
}

pub struct LLMScanManager {
    adapter: LLMScanner,
    pending_operations: Arc<Mutex<VecDeque<LLMScanOperation>>>,
    active_operations: Arc<DashMap<Uuid, LLMScanOperation>>,
    stats: Arc<LLMScanStats>,
    progress_tx: Option<mpsc::UnboundedSender<ScanProgressNotification>>,
}

impl LLMScanManager {
    pub fn new(config: crate::config::TameshiConfig) -> Result<Self> {
        debug!("Attempting to create LLM scan manager");

        let llm_config = match config.load_llm_config() {
            Some(config) => {
                debug!("LLM configuration loaded successfully");
                config
            }
            None => {
                error!("LLM configuration not available");
                return Err(anyhow!("LLM configuration not available"));
            }
        };

        debug!("Creating LLM scanner adapter");
        let use_ir_scanning = config.llm.global.use_ir_scanning;
        let adapter = match LLMScanner::new(llm_config, use_ir_scanning) {
            Ok(adapter) => {
                debug!("LLM scanner adapter created successfully");
                adapter
            }
            Err(e) => {
                error!("Failed to create LLM scanner adapter: {}", e);
                return Err(e);
            }
        };

        debug!("LLM scan manager created successfully");
        Ok(Self {
            adapter,
            pending_operations: Arc::new(Mutex::new(VecDeque::new())),
            active_operations: Arc::new(DashMap::new()),
            stats: Arc::new(LLMScanStats::default()),
            progress_tx: None,
        })
    }

    pub fn with_adapter(adapter: LLMScanner) -> Self {
        Self {
            adapter,
            pending_operations: Arc::new(Mutex::new(VecDeque::new())),
            active_operations: Arc::new(DashMap::new()),
            stats: Arc::new(LLMScanStats::default()),
            progress_tx: None,
        }
    }

    pub fn set_progress_sender(&mut self, tx: mpsc::UnboundedSender<ScanProgressNotification>) {
        self.progress_tx = Some(tx);
    }

    pub fn get_stats(&self) -> &LLMScanStats {
        &self.stats
    }

    pub fn get_available_scanners(&self) -> Vec<String> {
        self.adapter.get_available_scanners()
    }

    pub fn update_config(&mut self, config: crate::config::TameshiConfig) -> Result<()> {
        let llm_config = config
            .load_llm_config()
            .ok_or_else(|| anyhow!("LLM configuration not available"))?;

        let use_ir_scanning = config.llm.global.use_ir_scanning;
        self.adapter = LLMScanner::new(llm_config, use_ir_scanning)?;
        info!("LLM scanner adapter updated with new configuration");
        Ok(())
    }

    pub fn run(mut self, request_rx: std::sync::mpsc::Receiver<LLMScanRequest>) {
        let rt = tokio::runtime::Runtime::new()
            .expect("Failed to create tokio runtime for LLM scan manager");

        rt.block_on(async {
            info!("Starting LLM scan manager main loop");

            let mut cleanup_interval = interval(Duration::from_secs(30));
            let mut stats_interval = interval(Duration::from_secs(60));

            let (async_tx, mut async_rx) = tokio::sync::mpsc::unbounded_channel();

            let _bridge_handle = tokio::task::spawn_blocking(move || {
                while let Ok(request) = request_rx.recv() {
                    if async_tx.send(request).is_err() {
                        break; // Receiver dropped
                    }
                }
            });

            loop {
                select! {
                    request = async_rx.recv() => {
                        match request {
                            Some(request) => {
                                if !self.handle_request(request).await {
                                    break; // Shutdown requested
                                }
                            }
                            None => {
                                info!("Request channel disconnected, shutting down");
                                break;
                            }
                        }
                    }

                    _ = sleep(Duration::from_millis(100)) => {
                        self.process_pending_operations().await;
                    }

                    _ = cleanup_interval.tick() => {
                        self.cleanup_operations();
                    }

                    _ = stats_interval.tick() => {
                        self.report_stats();
                    }
                }
            }

            self.cancel_all_operations().await;
            info!("LLM scan manager shut down");
        });
    }

    async fn handle_request(&mut self, request: LLMScanRequest) -> bool {
        match request {
            LLMScanRequest::ScanFile {
                path,
                options,
                progress_token,
                response_tx,
            } => {
                let scope = ScanScope::File { path };
                self.queue_scan(scope, options, progress_token, response_tx)
                    .await;
            }

            LLMScanRequest::ScanWorkspace {
                root,
                options,
                progress_token,
                response_tx,
            } => match self.discover_workspace_files(&root).await {
                Ok(files) => {
                    let scope = ScanScope::Workspace { root, files };
                    self.queue_scan(scope, options, progress_token, response_tx)
                        .await;
                }
                Err(e) => {
                    error!("Failed to discover workspace files: {}", e);
                    let _ = response_tx.send(Err(e));
                }
            },

            LLMScanRequest::ScanMultipleFiles {
                files,
                options,
                progress_token,
                response_tx,
            } => {
                let scope = ScanScope::MultipleFiles { files };
                self.queue_scan(scope, options, progress_token, response_tx)
                    .await;
            }

            LLMScanRequest::Cancel { token } => {
                self.cancel_operation(&token).await;
            }

            LLMScanRequest::CancelAll => {
                self.cancel_all_operations().await;
            }

            LLMScanRequest::UpdateConfig {
                config,
                response_tx,
            } => {
                let result = self.update_config(*config);
                let _ = response_tx.send(result);
            }

            LLMScanRequest::GetScanners { response_tx } => {
                let scanners = self.get_available_scanners();
                let _ = response_tx.send(Ok(scanners));
            }

            LLMScanRequest::Shutdown => {
                info!("Shutdown requested");
                return false;
            }
        }

        true
    }

    async fn queue_scan(
        &self,
        scope: ScanScope,
        options: LLMScanOptions,
        progress_token: Option<String>,
        response_tx: mpsc::UnboundedSender<Result<ScanResult>>,
    ) {
        let operation = LLMScanOperation {
            id: Uuid::new_v4(),
            scope,
            stage: LLMScanStage::Initializing,
            current_scanner: None,
            progress: 0.0,
            message: "Queued for processing".to_string(),
            progress_token,
            cancellation_token: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
            options,
            result_tx: Some(response_tx),
        };

        debug!("Queueing LLM scan operation: {:?}", operation.id);

        let mut pending = self.pending_operations.lock().unwrap();
        pending.push_back(operation);
    }

    async fn process_pending_operations(&self) {
        let max_concurrent = self.adapter.get_config().global.concurrent_requests;

        while self.active_operations.len() < max_concurrent {
            let operation = {
                let mut pending = self.pending_operations.lock().unwrap();
                pending.pop_front()
            };

            if let Some(operation) = operation {
                let id = operation.id;
                debug!("Starting LLM scan operation: {:?}", id);

                if let Some(ref progress_token) = operation.progress_token {
                    self.send_progress(
                        progress_token,
                        0.0,
                        "Starting LLM scan...".to_string(),
                        "Initializing".to_string(),
                    );
                }

                self.active_operations.insert(id, operation.clone());

                let adapter_clone = self.adapter.clone();
                let active_ops = self.active_operations.clone();
                let stats = self.stats.clone();
                let progress_tx = self.progress_tx.clone();

                tokio::spawn(async move {
                    Self::execute_llm_scan(id, adapter_clone, active_ops, stats, progress_tx).await;
                });
            } else {
                break; // No more pending operations
            }
        }
    }

    async fn execute_llm_scan(
        operation_id: Uuid,
        adapter: LLMScanner,
        active_operations: Arc<DashMap<Uuid, LLMScanOperation>>,
        stats: Arc<LLMScanStats>,
        progress_tx: Option<mpsc::UnboundedSender<ScanProgressNotification>>,
    ) {
        let operation = match active_operations.get(&operation_id) {
            Some(op) => op.value().clone(),
            None => {
                error!("LLM scan operation not found: {:?}", operation_id);
                return;
            }
        };

        let start_time = Instant::now();
        stats.total_scans.fetch_add(1, Ordering::Relaxed);

        if let Some(progress_token) = &operation.progress_token {
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(ScanProgressNotification {
                    token: progress_token.clone(),
                    progress: 0.1,
                    message: "Initializing LLM scan...".to_string(),
                    files_processed: 0,
                    total_files: 1,
                });
            }
        }

        if let Some(mut op) = active_operations.get_mut(&operation_id) {
            op.stage = LLMScanStage::RunningScanners;
            op.message = "Running LLM scanners...".to_string();
        }

        let result = match operation.scope {
            ScanScope::File { path } => adapter.scan_file(&path, operation.options).await,
            ScanScope::Workspace { root: _, files } => {
                let mut all_results = Vec::new();
                for file in &files {
                    if !operation.cancellation_token.load(Ordering::Relaxed) {
                        match adapter.scan_file(file, operation.options.clone()).await {
                            Ok(result) => all_results.push(result),
                            Err(e) => {
                                warn!("Failed to scan file {:?}: {}", file, e);
                            }
                        }
                    }
                }
                Ok(Self::merge_scan_results(all_results))
            }
            ScanScope::MultipleFiles { files } => {
                let mut all_results = Vec::new();
                for file in &files {
                    if !operation.cancellation_token.load(Ordering::Relaxed) {
                        match adapter.scan_file(file, operation.options.clone()).await {
                            Ok(result) => all_results.push(result),
                            Err(e) => {
                                warn!("Failed to scan file {:?}: {}", file, e);
                            }
                        }
                    }
                }
                Ok(Self::merge_scan_results(all_results))
            }
        };

        if operation.cancellation_token.load(Ordering::Relaxed) {
            stats.cancelled_scans.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if let Some(progress_token) = &operation.progress_token {
            if let Some(ref tx) = progress_tx {
                let message = match &result {
                    Ok(_) => "LLM scan completed successfully".to_string(),
                    Err(_) => "LLM scan failed".to_string(),
                };

                let _ = tx.send(ScanProgressNotification {
                    token: progress_token.clone(),
                    progress: 1.0,
                    message,
                    files_processed: 1,
                    total_files: 1,
                });
            }
        }

        let duration = start_time.elapsed();
        match &result {
            Ok(_) => {
                stats.successful_scans.fetch_add(1, Ordering::Relaxed);
                info!("LLM scan completed successfully in {:?}", duration);
            }
            Err(e) => {
                stats.failed_scans.fetch_add(1, Ordering::Relaxed);
                error!("LLM scan failed after {:?}: {}", duration, e);
            }
        }

        if let Some((_, mut operation)) = active_operations.remove(&operation_id) {
            operation.stage = match &result {
                Ok(_) => LLMScanStage::Completed,
                Err(_) => LLMScanStage::Failed,
            };
            operation.progress = 1.0;

            if let Some(response_tx) = operation.result_tx.take() {
                let _ = response_tx.send(result);
            }
        }
    }

    fn merge_scan_results(results: Vec<ScanResult>) -> ScanResult {
        if results.is_empty() {
            return ScanResult {
                version: "1.0".to_string(),
                findings: vec![],
                metadata: crate::proto::ScanMetadata {
                    start_time: chrono::Utc::now().to_rfc3339(),
                    duration_ms: 0,
                    scanned_files: vec![],
                    skipped_files: std::collections::HashMap::new(),
                    scanner_config: Some(serde_json::json!({
                        "scanner_type": "llm_adapter"
                    })),
                },
                errors: vec![],
            };
        }

        let mut all_findings = Vec::new();
        let mut total_time_ms = 0u64;

        for result in results {
            all_findings.extend(result.findings);
            total_time_ms += result.metadata.duration_ms;
        }

        all_findings.sort_by(|a, b| a.id.cmp(&b.id));
        all_findings.dedup_by(|f, other| f.id == other.id);

        ScanResult {
            version: "1.0".to_string(),
            findings: all_findings.clone(),
            metadata: crate::proto::ScanMetadata {
                start_time: chrono::Utc::now().to_rfc3339(),
                duration_ms: total_time_ms,
                scanned_files: all_findings
                    .iter()
                    .filter_map(|f| f.locations.first())
                    .map(|loc| loc.file.clone())
                    .collect(),
                skipped_files: std::collections::HashMap::new(),
                scanner_config: Some(serde_json::json!({
                    "scanner_type": "llm_adapter",
                    "findings_count": all_findings.len()
                })),
            },
            errors: vec![],
        }
    }

    async fn discover_workspace_files(&self, root: &Path) -> Result<Vec<std::path::PathBuf>> {
        let mut files = Vec::new();

        if root.exists() {
            let mut entries = tokio::fs::read_dir(root).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                if path.extension().and_then(|s| s.to_str()) == Some("sol") {
                    files.push(path);
                } else if path.is_dir() {
                    match Box::pin(self.discover_workspace_files(&path)).await {
                        Ok(sub_files) => files.extend(sub_files),
                        Err(_) => continue, // Skip directories we can't read
                    }
                }
            }
        }

        Ok(files)
    }

    async fn cancel_operation(&self, token: &str) {
        for operation in self.active_operations.iter() {
            if let Some(ref progress_token) = operation.progress_token {
                if progress_token == token {
                    operation.cancellation_token.store(true, Ordering::Relaxed);
                    info!("Cancelled LLM operation with token: {}", token);
                    return;
                }
            }
        }
    }

    #[allow(clippy::await_holding_lock)]
    async fn cancel_all_operations(&self) {
        info!("Cancelling all LLM scan operations");

        for operation in self.active_operations.iter() {
            operation.cancellation_token.store(true, Ordering::Relaxed);
        }

        let mut pending = self.pending_operations.lock().unwrap();
        for operation in pending.iter() {
            operation.cancellation_token.store(true, Ordering::Relaxed);
        }
        pending.clear();

        drop(pending);
        sleep(Duration::from_millis(100)).await;
    }

    fn cleanup_operations(&self) {
        let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
        self.active_operations
            .retain(|_, op| op.started_at > cutoff);
    }

    fn report_stats(&self) {
        let total = self.stats.total_scans.load(Ordering::Relaxed);
        if total > 0 {
            let successful = self.stats.successful_scans.load(Ordering::Relaxed);
            let failed = self.stats.failed_scans.load(Ordering::Relaxed);
            let cancelled = self.stats.cancelled_scans.load(Ordering::Relaxed);

            debug!(
                "LLM scan stats - Total: {}, Success: {}, Failed: {}, Cancelled: {}",
                total, successful, failed, cancelled
            );
        }
    }

    fn send_progress(&self, token: &str, progress: f64, message: String, _current_scanner: String) {
        if let Some(ref tx) = self.progress_tx {
            let notification = ScanProgressNotification {
                token: token.to_string(),
                progress,
                message,
                files_processed: 0,
                total_files: 1,
            };
            let _ = tx.send(notification);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_llm_scan_manager_creation() {
        let _config = crate::config::TameshiConfig::default();
    }

    #[test]
    fn test_scan_scope_creation() {
        let file_scope = ScanScope::File {
            path: std::path::PathBuf::from("/tmp/test.sol"),
        };

        match file_scope {
            ScanScope::File { path } => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/test.sol"));
            }
            _ => panic!("Expected file scope"),
        }
    }

    #[test]
    fn test_llm_scan_stage_display() {
        assert_eq!(LLMScanStage::Initializing.as_str(), "Initializing");
        assert_eq!(LLMScanStage::RunningScanners.as_str(), "Running scanners");
        assert_eq!(LLMScanStage::Completed.as_str(), "Completed");
        assert_eq!(LLMScanStage::Failed.as_str(), "Failed");
    }

    #[test]
    fn test_scan_stats_creation() {
        let stats = LLMScanStats::default();

        assert_eq!(stats.total_scans.load(Ordering::Relaxed), 0);
        assert_eq!(stats.successful_scans.load(Ordering::Relaxed), 0);
        assert_eq!(stats.failed_scans.load(Ordering::Relaxed), 0);
        assert_eq!(stats.cancelled_scans.load(Ordering::Relaxed), 0);
    }
}
