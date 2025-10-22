//! Scan errors
//!
//! Uses thiserror for type-safe error matching rather than opaque anyhow errors.
//! Distinguishes scanner failures from orchestration failures with preserved context.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Failed to scan {path}: {source}")]
    ScanFailed {
        path: PathBuf,
        #[source]
        source: anyhow::Error,
    },

    #[error("Operation {operation_id} was cancelled")]
    Cancelled { operation_id: uuid::Uuid },

    #[error("Scan timeout after {timeout_secs}s for {path}")]
    Timeout { path: PathBuf, timeout_secs: u64 },

    #[error("Invalid scan scope: {reason}")]
    InvalidScope { reason: String },

    #[error("Scanner adapter error: {0}")]
    AdapterError(#[from] anyhow::Error),

    #[error("Workspace not initialized")]
    WorkspaceNotInitialized,

    #[error("Queue is full (max {max_size} pending scans)")]
    QueueFull { max_size: usize },
}

pub type ScanResult<T> = std::result::Result<T, ScanError>;
