//! Scan messages
//!
//! Defines typed messages for scan requests and responses instead of generic
//! serde_json::Value, enabling compile-time validation of channel communication.

use crate::deterministic_scanner::ScanScope;
use crate::proto::ScanResult;
use std::path::PathBuf;
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Debug)]
pub struct ScanRequest {
    pub scope: ScanScope,
    pub progress_token: Option<String>,
    pub response_tx: oneshot::Sender<super::errors::ScanResult<ScanResult>>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Started {
        operation_id: Uuid,
        scope: ScanScopeInfo,
    },
    FileScanning {
        operation_id: Uuid,
        path: PathBuf,
        current: usize,
        total: usize,
    },
    FileCompleted {
        operation_id: Uuid,
        path: PathBuf,
        findings_count: usize,
    },
    Completed {
        operation_id: Uuid,
        total_findings: usize,
        duration_ms: u64,
    },
    Failed {
        operation_id: Uuid,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub enum ScanScopeInfo {
    File { path: PathBuf },
    Files { count: usize },
    Workspace { path: PathBuf },
}

impl From<&ScanScope> for ScanScopeInfo {
    fn from(scope: &ScanScope) -> Self {
        match scope {
            ScanScope::File { path, .. } => ScanScopeInfo::File { path: path.clone() },
            ScanScope::Files { paths } => ScanScopeInfo::Files { count: paths.len() },
            ScanScope::Workspace { root, .. } => ScanScopeInfo::Workspace { path: root.clone() },
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Scan(ScanRequest),
    CancelOperation(Uuid),
    CancelAllOperations,
    Shutdown,
}
