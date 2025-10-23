//! Deterministic scanner
//!
//! Direct interface to Tameshi's deterministic pattern-based scanning engine.
//! Transforms Solidity to ThalIR and runs static analysis scanners.

use crate::proto::ScanResult;
use anyhow::{anyhow, Context, Result};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thalir_transform::transform_solidity_to_ir;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub timeout: Duration,

    pub max_concurrent: usize,

    pub working_dir: Option<PathBuf>,

    pub parallel_execution: bool,

    pub enabled_scanners: Vec<String>,

    pub min_severity: Option<crate::proto::Severity>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes default
            max_concurrent: 1,
            working_dir: None,
            parallel_execution: true, // Enable parallel execution by default
            enabled_scanners: Vec::new(), // Empty = run all scanners
            min_severity: None,       // Report all severities by default
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanScope {
    Workspace {
        root: PathBuf,
    },
    File {
        path: PathBuf,
        content: Option<String>,
    },
    Files {
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug)]
pub struct ScanRequest {
    pub scope: ScanScope,
    pub cancellation_token: Arc<AtomicBool>,
}

#[derive(Debug)]
pub enum ScannerResult {
    Success(ScanResult),
    Cancelled,
    Error(anyhow::Error),
}

#[derive(Clone)]
pub struct DeterministicScanner;

impl Default for DeterministicScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn check_availability(&self) -> Result<bool> {
        info!("Scanner API is available");
        Ok(true)
    }

    pub async fn scan(&self, request: ScanRequest) -> ScannerResult {
        let start_time = Instant::now();
        let scan_start_time = chrono::Utc::now().to_rfc3339();

        if request.cancellation_token.load(Ordering::Relaxed) {
            return ScannerResult::Cancelled;
        }

        info!("Performing API-based scan for scope: {:?}", request.scope);

        let mut all_findings = Vec::new();
        let mut scanned_files = Vec::new();
        let mut errors = Vec::new();
        let mut skipped_files = std::collections::HashMap::new();

        match &request.scope {
            ScanScope::File { path, content } => {
                match self.scan_single_file(path, content.as_deref(), &request.cancellation_token) {
                    Ok((findings, file_path, _raw)) => {
                        all_findings.extend(findings);
                        scanned_files.push(file_path.to_string_lossy().to_string());
                    }
                    Err(e) => {
                        error!("Failed to scan file {:?}: {}", path, e);
                        errors.push(crate::proto::ScanError {
                            code: "SCAN_ERROR".to_string(),
                            message: format!("Failed to scan file: {}", e),
                            file: Some(path.to_string_lossy().to_string()),
                            details: None,
                        });
                    }
                }
            }
            ScanScope::Files { paths } => {
                for path in paths {
                    if request.cancellation_token.load(Ordering::Relaxed) {
                        return ScannerResult::Cancelled;
                    }

                    match self.scan_single_file(path, None, &request.cancellation_token) {
                        Ok((findings, file_path, _raw)) => {
                            all_findings.extend(findings);
                            scanned_files.push(file_path.to_string_lossy().to_string());
                        }
                        Err(e) => {
                            warn!("Skipping file {:?}: {}", path, e);
                            skipped_files.insert(path.to_string_lossy().to_string(), e.to_string());
                        }
                    }
                }
            }
            ScanScope::Workspace { root } => match self.find_solidity_files(root) {
                Ok(files) => {
                    info!("Found {} Solidity files in workspace", files.len());
                    for path in files {
                        if request.cancellation_token.load(Ordering::Relaxed) {
                            return ScannerResult::Cancelled;
                        }

                        match self.scan_single_file(&path, None, &request.cancellation_token) {
                            Ok((findings, file_path, _raw)) => {
                                all_findings.extend(findings);
                                scanned_files.push(file_path.to_string_lossy().to_string());
                            }
                            Err(e) => {
                                warn!("Skipping file {:?}: {}", path, e);
                                skipped_files
                                    .insert(path.to_string_lossy().to_string(), e.to_string());
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to find Solidity files in workspace: {}", e);
                    errors.push(crate::proto::ScanError {
                        code: "WORKSPACE_SCAN_ERROR".to_string(),
                        message: format!("Failed to scan workspace: {}", e),
                        file: None,
                        details: None,
                    });
                }
            },
        }

        let scan_result = ScanResult {
            version: crate::proto::PROTOCOL_VERSION.to_string(),
            findings: all_findings,
            metadata: crate::proto::ScanMetadata {
                start_time: scan_start_time,
                duration_ms: start_time.elapsed().as_millis() as u64,
                scanned_files,
                skipped_files,
                scanner_config: None,
            },
            errors,
        };

        let duration = start_time.elapsed();
        info!(
            "API scan completed in {:?} with {} findings",
            duration,
            scan_result.findings.len()
        );
        ScannerResult::Success(scan_result)
    }

    pub async fn scan_async(&self, scope: &ScanScope) -> Result<ScanResult> {
        let cancellation_token = Arc::new(AtomicBool::new(false));
        let request = ScanRequest {
            scope: scope.clone(),
            cancellation_token,
        };

        match self.scan(request).await {
            ScannerResult::Success(result) => Ok(result),
            ScannerResult::Cancelled => Err(anyhow!("Scan was cancelled")),
            ScannerResult::Error(e) => Err(anyhow!("Scan failed: {}", e)),
        }
    }

    fn scan_single_file(
        &self,
        path: &Path,
        content_opt: Option<&str>,
        cancellation_token: &Arc<AtomicBool>,
    ) -> Result<(
        Vec<crate::proto::Finding>,
        PathBuf,
        Vec<tameshi_scanners::Finding>,
    )> {
        info!("Starting analysis of: {:?}", path);

        if cancellation_token.load(Ordering::Relaxed) {
            return Err(anyhow!("Scan cancelled"));
        }

        info!("Analysis Phase 1/5: Reading source file...");
        let content = if let Some(content) = content_opt {
            info!(
                "Using in-memory content from LSP ({} lines)",
                content.lines().count()
            );
            content.to_string()
        } else {
            info!("Reading content from disk");
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read file: {}", path.display()))?
        };

        info!("Analysis Phase 2/5: Transforming to IR representation...");
        let contracts = transform_solidity_to_ir(&content)
            .with_context(|| format!("Failed to transform Solidity to IR: {}", path.display()))?;

        if contracts.is_empty() {
            debug!("No contracts found in {:?}", path);
            return Ok((Vec::new(), path.to_path_buf(), vec![]));
        }

        info!(
            "Analysis Phase 2/5: Transformed {} contracts",
            contracts.len()
        );

        let mut bundle = tameshi_scanners::RepresentationBundle::new();
        for contract in contracts {
            bundle = bundle.add(contract);
        }

        info!("Analysis Phase 3/5: Running deterministic analysis...");
        let config = tameshi_scanners::core::ScannerConfig::default();
        let engine = self.create_scanning_engine(config, &bundle)?;

        let report = engine
            .run(bundle)
            .with_context(|| format!("Failed to run scanners on {}", path.display()))?;

        info!(
            "Analysis Phase 3/5: Found {} initial findings",
            report.findings().len()
        );

        let raw_findings = report.findings().to_vec();

        info!("Analysis Phase 4/5: Processing and converting findings...");
        let findings: Vec<crate::proto::Finding> = raw_findings
            .iter()
            .map(|f| self.convert_finding_to_lsp(f, path))
            .collect();

        info!("Analysis Phase 5/5: Finalizing {} findings", findings.len());

        Ok((findings, path.to_path_buf(), raw_findings))
    }

    fn create_scanning_engine(
        &self,
        config: tameshi_scanners::core::ScannerConfig,
        _bundle: &tameshi_scanners::RepresentationBundle,
    ) -> Result<tameshi_scanners::ScanningEngine> {
        let mut engine = tameshi_scanners::ScanningEngine::new(config);

        engine = engine
            .add_scanner(tameshi_scanners::IRReentrancyScanner::new())
            .add_scanner(tameshi_scanners::IRAccessControlScanner::new())
            .add_scanner(tameshi_scanners::IRUncheckedReturnScanner::new())
            .add_scanner(tameshi_scanners::IRStateModificationScanner::new())
            .add_scanner(tameshi_scanners::IRDangerousFunctionsScanner::new())
            .add_scanner(tameshi_scanners::IRIntegerOverflowScanner::new())
            .add_scanner(tameshi_scanners::IRTimeVulnerabilityScanner::new())
            .add_scanner(tameshi_scanners::IRDoSVulnerabilityScanner::new())
            .add_scanner(tameshi_scanners::IRPriceManipulationScanner::new())
            .add_scanner(tameshi_scanners::IRCrossFunctionReentrancyScanner::new());

        #[cfg(feature = "llm")]
        {
            if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
                if !api_key.is_empty() {
                    debug!("LLM scanning enabled - adding LLM scanners");
                    engine = self.add_llm_scanners(engine)?;
                } else {
                    debug!("OPENAI_API_KEY is empty, skipping LLM scanners");
                }
            } else {
                debug!("OPENAI_API_KEY not set, skipping LLM scanners");
            }
        }

        Ok(engine)
    }

    #[cfg(feature = "llm")]
    fn add_llm_scanners(
        &self,
        mut engine: tameshi_scanners::ScanningEngine,
    ) -> Result<tameshi_scanners::ScanningEngine> {
        use tameshi_scanners::llm::LLMScannerFactory;

        let llm_config = match tameshi_scanners::llm::LLMConfig::from_env() {
            Ok(config) => config,
            Err(e) => {
                warn!("Failed to load LLM config, using defaults: {}", e);
                tameshi_scanners::llm::LLMConfig::default()
            }
        };

        let factory = match &llm_config.provider {
            tameshi_scanners::llm::config::ProviderConfig::OpenAI { model, .. } => {
                match LLMScannerFactory::new_openai(Some(model.clone())) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Failed to create LLM scanner factory: {}", e);
                        return Ok(engine);
                    }
                }
            }
            _ => {
                warn!("Unsupported LLM provider, skipping LLM scanners");
                return Ok(engine);
            }
        };

        for scanner_id in &llm_config.enabled_scanners {
            let scanner = match scanner_id.as_str() {
                "reentrancy" => factory.create_reentrancy_scanner(),
                "access_control" => factory.create_access_control_scanner(),
                "overflow" => factory.create_overflow_scanner(),
                "logic_error" => factory.create_logic_error_scanner(),
                "unchecked_returns" => factory.create_unchecked_returns_scanner(),
                "dos" => factory.create_dos_patterns_scanner(),
                "timestamp" => factory.create_timestamp_dependence_scanner(),
                "front_running" => factory.create_front_running_scanner(),
                "general" => factory.create_general_scanner(),
                "source_reentrancy" => factory.create_source_reentrancy_scanner(),
                "source_access_control" => factory.create_source_access_control_scanner(),
                "source_unchecked_returns" => factory.create_source_unchecked_returns_scanner(),
                "source_dos" => factory.create_source_dos_scanner(),
                "source_timestamp" => factory.create_source_timestamp_scanner(),
                "source_front_running" => factory.create_source_front_running_scanner(),
                "source_overflow" => factory.create_source_overflow_scanner(),
                "hybrid_reentrancy" => factory.create_hybrid_reentrancy_scanner(),
                "hybrid_access_control" => factory.create_hybrid_access_control_scanner(),
                _ => {
                    warn!("Unknown LLM scanner: {}", scanner_id);
                    continue;
                }
            };

            info!("Added LLM scanner: {}", scanner_id);
            engine = engine.add_scanner(scanner);
        }

        Ok(engine)
    }

    fn convert_finding_to_lsp(
        &self,
        finding: &tameshi_scanners::Finding,
        file_path: &Path,
    ) -> crate::proto::Finding {
        use crate::proto::{Confidence, Finding, Location, Severity};

        let severity = match finding.severity {
            tameshi_scanners::Severity::Critical => Severity::Critical,
            tameshi_scanners::Severity::High => Severity::High,
            tameshi_scanners::Severity::Medium => Severity::Medium,
            tameshi_scanners::Severity::Low => Severity::Low,
            tameshi_scanners::Severity::Informational => Severity::Informational,
        };

        let confidence = match finding.confidence {
            tameshi_scanners::Confidence::High => Confidence::High,
            tameshi_scanners::Confidence::Medium => Confidence::Medium,
            tameshi_scanners::Confidence::Low => Confidence::Low,
        };

        let scanner_id_lower = finding.scanner_id.to_lowercase();
        let is_llm_finding = scanner_id_lower.starts_with("llm_")
            || scanner_id_lower.contains("openai")
            || scanner_id_lower.contains("anthropic")
            || scanner_id_lower.contains("claude")
            || scanner_id_lower.contains("gpt")
            || scanner_id_lower.contains("gemini")
            || scanner_id_lower.contains("ai_");

        let locations: Vec<Location> = if finding.locations.is_empty() {
            vec![Location {
                file: file_path.to_string_lossy().to_string(),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
                snippet: Some(format!(
                    "Scanner '{}' did not provide specific location",
                    finding.scanner_id
                )),
            }]
        } else {
            finding
                .locations
                .iter()
                .map(|loc| Location {
                    file: file_path.to_string_lossy().to_string(),
                    line: loc.line,
                    column: loc.column,
                    end_line: loc.end_line,
                    end_column: loc.end_column,
                    snippet: loc.snippet.clone(),
                })
                .collect()
        };

        let analysis_type = if is_llm_finding {
            Some(crate::proto::AnalysisType::LLM)
        } else {
            Some(crate::proto::AnalysisType::Deterministic)
        };

        let provenance = Some(crate::proto::Provenance {
            finding_id: uuid::Uuid::new_v4().to_string(),
            source: if is_llm_finding {
                crate::proto::ProvenanceSource::LLM {
                    scanner_id: finding.scanner_id.clone(),
                    model: "gpt-4".to_string(), // Default model name for LLM findings
                    prompt_hash: "".to_string(),
                }
            } else {
                crate::proto::ProvenanceSource::Deterministic {
                    scanner_id: finding.scanner_id.clone(),
                    pattern_id: finding.scanner_id.clone(),
                    pattern_description: finding.title.clone(),
                }
            },
            confidence_factors: vec![],
            analysis_metadata: crate::proto::AnalysisMetadata {
                scan_timestamp: chrono::Utc::now().to_rfc3339(),
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                ir_transform_success: true,
                analysis_duration_ms: 0,
            },
            validation_status: crate::proto::ValidationStatus::Unvalidated,
        });

        let evidence = vec![];

        let metadata = Some(crate::proto::FindingMetadata {
            affected_functions: vec![],
            affected_variables: vec![],
            affected_contracts: vec![],
            recommendation: None,
            references: vec![],
            gas_impact: None,
            representation_info: None,
            provenance,
            correlations: vec![],
            analysis_type,
            evidence,
        });

        Finding {
            id: uuid::Uuid::new_v4(),
            scanner_id: finding.scanner_id.clone(),
            swc_id: None,
            finding_type: finding.scanner_id.clone(),
            severity,
            base_severity: severity,
            confidence,
            confidence_score: confidence.to_score(),
            title: if is_llm_finding {
                format!("[AI] {}", finding.title)
            } else {
                finding.title.clone()
            },
            description: finding.description.clone(),
            locations,
            metadata,
            severity_context: None,
        }
    }

    fn find_solidity_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        for entry in WalkDir::new(root) {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().is_some_and(|ext| ext == "sol") {
                files.push(path.to_path_buf());
            }
        }

        Ok(files)
    }
}
