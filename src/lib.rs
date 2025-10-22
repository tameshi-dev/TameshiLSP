//! Tameshi LSP Server
//!
//! Integrates smart contract security analysis with code editors through LSP. Developers
//! see vulnerabilities as they write rather than after deployment. Async operations allow
//! concurrent scans and LLM streaming without blocking the UI.
//!
//! Separating raw findings from LSP diagnostics supports multiple export formats and
//! enables caching without re-serialization. Running both deterministic and LLM scanners
//! produces better coverage but requires correlation to identify when different methods
//! find the same issue, boosting confidence and reducing duplicate warnings.

pub mod config;
pub mod correlation;
pub mod deterministic_scanner;
pub mod diagnostics;
pub mod export;
pub mod findings_store;
pub mod llm_scan_manager;
pub mod llm_scanner;
pub mod proto;
pub mod scan;
pub mod server;
pub mod workspace;

pub use config::TameshiConfig;
pub use correlation::{CorrelationConfig, CorrelationService};
pub use deterministic_scanner::DeterministicScanner;
pub use diagnostics::DiagnosticsMapper;
pub use findings_store::FindingsStore;
pub use llm_scan_manager::LLMScanManager;
pub use llm_scanner::{LLMScanOptions, LLMScanner};
pub use scan::ScanManager;
pub use server::TameshiLspServer;
pub use workspace::WorkspaceManager;
