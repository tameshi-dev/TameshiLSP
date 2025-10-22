//! LLM scanner
//!
//! Integrates LLM-based semantic vulnerability analysis. Uses the same builder pattern
//! as the CLI to create scanner suites. Supports both direct source code analysis and
//! ThalIR intermediate representation scanning depending on configuration.

use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::proto::{Confidence, Finding, Location, ScanResult, Severity};

use tameshi_scanners::llm::OpenAIProvider;
use thalir_transform::transform_solidity_to_ir_with_filename;

#[derive(Debug, Clone)]
pub struct ScannerMetadata {
    pub name: String,
    pub description: String,
    pub focus_areas: Vec<String>,
    pub estimated_duration_ms: u64,
    pub confidence_threshold: f32,
    pub template_name: String,
}

#[derive(Debug, Clone)]
pub struct LLMScanOptions {
    pub enabled_scanners: Vec<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub confidence_threshold: Option<f32>,
    pub include_low_severity: bool,
    pub timeout_seconds: u64,
    pub concurrent_scanners: usize,
}

impl Default for LLMScanOptions {
    fn default() -> Self {
        Self {
            enabled_scanners: vec![
                "reentrancy".to_string(),
                "access_control".to_string(),
                "unchecked_returns".to_string(),
            ],
            temperature: None,
            max_tokens: None,
            confidence_threshold: None,
            include_low_severity: false,
            timeout_seconds: 60,
            concurrent_scanners: 2,
        }
    }
}

#[derive(Clone)]
pub struct LLMScanner {
    scanners: Vec<Arc<dyn tameshi_scanners::core::Scanner>>,
    scanner_metadata: HashMap<String, ScannerMetadata>,
    config: tameshi_scanners::llm::config::LLMConfig,
    use_ir_scanning: bool,
}

impl LLMScanner {
    pub fn new(
        config: tameshi_scanners::llm::config::LLMConfig,
        use_ir_scanning: bool,
    ) -> Result<Self> {
        let (api_key, model_name) = match &config.provider {
            tameshi_scanners::llm::config::ProviderConfig::OpenAI { model, api_key, .. } => {
                let key = if let Some(key) = api_key {
                    if !key.is_empty() {
                        info!("Using API key from configuration");
                        key.clone()
                    } else {
                        std::env::var("OPENAI_API_KEY")
                            .context("OPENAI_API_KEY not provided in config or environment")?
                    }
                } else {
                    std::env::var("OPENAI_API_KEY")
                        .context("OPENAI_API_KEY not provided in config or environment")?
                };
                (key, model.clone())
            }
            _ => {
                return Err(anyhow!("Only OpenAI provider is currently supported"));
            }
        };

        std::env::set_var("OPENAI_API_KEY", &api_key);
        info!("API key configured for OpenAI provider");

        let provider = Arc::new(OpenAIProvider::new(Some(model_name))?);

        let lib_suite = tameshi_scanners::llm_scanners::LLMScannerSuite::SingleComprehensive;
        let scanners = tameshi_scanners::llm_scanners::LLMScannerSuiteBuilder::new(lib_suite)
            .with_provider(provider)
            .build()?;

        info!(
            "Created {} LLM scanner(s) using library API (SingleComprehensive mode)",
            scanners.len()
        );
        info!("IR-based scanning: {}", use_ir_scanning);

        let adapter = Self {
            scanners,
            scanner_metadata: Self::create_scanner_metadata(),
            config: config.clone(),
            use_ir_scanning,
        };

        Ok(adapter)
    }

    fn create_scanner_metadata() -> HashMap<String, ScannerMetadata> {
        let mut metadata = HashMap::new();

        metadata.insert("llm_comprehensive".to_string(), ScannerMetadata {
            name: "LLM Comprehensive Security Scanner".to_string(),
            description: "Detects ALL major vulnerability types in a single analysis: reentrancy, access control, integer issues, unchecked calls, DoS, weak randomness, front-running, timestamp dependence, tx.origin, and delegatecall issues".to_string(),
            focus_areas: vec![
                "reentrancy".to_string(),
                "access_control".to_string(),
                "integer_overflow".to_string(),
                "unchecked_calls".to_string(),
                "dos".to_string(),
                "randomness".to_string(),
                "front_running".to_string(),
                "timestamp_dependence".to_string(),
                "tx_origin".to_string(),
                "delegatecall".to_string(),
            ],
            estimated_duration_ms: 8000,
            confidence_threshold: 0.6,
            template_name: "comprehensive".to_string(),
        });

        metadata
    }

    pub fn get_scanner_metadata(&self, scanner_name: &str) -> Option<&ScannerMetadata> {
        self.scanner_metadata.get(scanner_name)
    }

    pub fn get_available_scanners(&self) -> Vec<String> {
        self.scanners.iter().map(|s| s.name().to_string()).collect()
    }

    pub fn get_config(&self) -> &tameshi_scanners::llm::config::LLMConfig {
        &self.config
    }

    pub async fn scan_file(&self, file_path: &Path, options: LLMScanOptions) -> Result<ScanResult> {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/tameshi-llm-debug.log")
        {
            use std::io::Write;
            let _ = writeln!(file, "\n========================================");
            let _ = writeln!(file, "[LSP ADAPTER] 🚀 scan_file() CALLED");
            let _ = writeln!(file, "[LSP ADAPTER]    File: {:?}", file_path);
            let _ = writeln!(
                file,
                "[LSP ADAPTER]    Number of scanners: {}",
                self.scanners.len()
            );
            let _ = writeln!(
                file,
                "[LSP ADAPTER]    IR scanning enabled: {}",
                self.use_ir_scanning
            );
            let _ = writeln!(file, "========================================");
        }

        info!("Starting LLM scan for file: {:?}", file_path);

        if !file_path.exists() {
            return Err(anyhow!("File not found: {:?}", file_path));
        }

        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {:?}", file_path))?;

        let start_time = Instant::now();

        debug!(
            "Running {} LLM scanners for file: {:?} (IR-based: {})",
            self.scanners.len(),
            file_path,
            self.use_ir_scanning
        );

        let timeout = Duration::from_secs(options.timeout_seconds);

        let concurrent_limit = options.concurrent_scanners.max(1);
        let mut all_findings = Vec::new();
        let mut scanner_info = std::collections::HashMap::new();

        for chunk in self.scanners.chunks(concurrent_limit) {
            let futures: Vec<_> = chunk
                .iter()
                .map(|scanner| {
                    let scanner = Arc::clone(scanner); // Clone the Arc to avoid borrowing issues
                    let file_path = file_path.to_path_buf();
                    let content = content.clone();
                    let timeout = timeout;
                    let scanner_name = scanner.name();
                    let use_ir = self.use_ir_scanning;

                    async move {
                        let start_time = Instant::now();
                        let scan_result = tokio::time::timeout(timeout, async move {
                            let filename = file_path
                                .file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("unknown.sol");

                            let mut bundle =
                                tameshi_scanners::representations::RepresentationBundle::new();

                            if use_ir {
                                let contracts = match transform_solidity_to_ir_with_filename(
                                    &content,
                                    Some(filename),
                                ) {
                                    Ok(contracts) => contracts,
                                    Err(e) => {
                                        warn!(
                                            "Failed to transform Solidity to IR for {}: {}",
                                            scanner_name, e
                                        );
                                        return Vec::new();
                                    }
                                };

                                if contracts.is_empty() {
                                    warn!(
                                        "No contracts found in file for scanner {}",
                                        scanner_name
                                    );
                                    return Vec::new();
                                }

                                for contract in &contracts {
                                    bundle = bundle.add(contract.clone());
                                }
                            }

                            let mut context =
                                tameshi_scanners::core::context::AnalysisContext::new(bundle);

                            let contract_info = tameshi_scanners::core::context::ContractInfo {
                                name: filename.trim_end_matches(".sol").to_string(),
                                source_path: Some(file_path.to_string_lossy().to_string()),
                                source_code: Some(content.clone()),
                                compiler_version: None,
                                optimization_enabled: false,
                            };

                            context.set_contract_info(contract_info);

                            if let Ok(mut file) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/tmp/tameshi-llm-debug.log")
                            {
                                use std::io::Write;
                                let _ = writeln!(
                                    file,
                                    "[LSP ADAPTER] 🎬 About to call scanner.scan() for: {}",
                                    scanner_name
                                );
                                let _ = writeln!(file, "[LSP ADAPTER]    File: {:?}", file_path);
                                let _ = writeln!(file, "[LSP ADAPTER]    IR scanning: {}", use_ir);
                            }

                            let scan_result = tokio::task::spawn_blocking(move || {
                                match scanner.scan(&context) {
                                    Ok(results) => {
                                        if let Ok(mut file) = std::fs::OpenOptions::new()
                                            .create(true)
                                            .append(true)
                                            .open("/tmp/tameshi-llm-debug.log")
                                        {
                                            use std::io::Write;
                                            let _ = writeln!(
                                                file,
                                                "[LSP ADAPTER] ✅ Scanner {} returned {} results",
                                                scanner_name,
                                                results.len()
                                            );
                                        }
                                        results
                                    }
                                    Err(e) => {
                                        warn!("Scanner {} execution failed: {}", scanner_name, e);
                                        if let Ok(mut file) = std::fs::OpenOptions::new()
                                            .create(true)
                                            .append(true)
                                            .open("/tmp/tameshi-llm-debug.log")
                                        {
                                            use std::io::Write;
                                            let _ = writeln!(
                                                file,
                                                "[LSP ADAPTER] ❌ Scanner {} execution failed: {}",
                                                scanner_name, e
                                            );
                                        }
                                        Vec::new()
                                    }
                                }
                            })
                            .await;

                            match scan_result {
                                Ok(results) => results,
                                Err(e) => {
                                    warn!("Scanner {} task failed: {}", scanner_name, e);
                                    Vec::new()
                                }
                            }
                        })
                        .await;

                        let duration = start_time.elapsed();

                        match scan_result {
                            Ok(scanner_findings) => {
                                debug!(
                                    "Scanner {} found {} vulnerabilities",
                                    scanner_name,
                                    scanner_findings.len()
                                );
                                (scanner_name.to_string(), scanner_findings, duration, None)
                            }
                            Err(_) => {
                                let error_msg = format!("Scanner timed out after {:?}", timeout);
                                (
                                    scanner_name.to_string(),
                                    Vec::new(),
                                    duration,
                                    Some(error_msg),
                                )
                            }
                        }
                    }
                })
                .collect();

            let results = join_all(futures).await;

            for (scanner_name, scanner_findings, duration, error) in results {
                scanner_info.insert(
                    scanner_name.clone(),
                    format!(
                        "Duration: {}ms, Findings: {}, Error: {}",
                        duration.as_millis(),
                        scanner_findings.len(),
                        error.clone().unwrap_or_else(|| "None".to_string())
                    ),
                );

                if let Some(error_msg) = error {
                    warn!("Scanner {} failed: {}", scanner_name, error_msg);
                    continue;
                }

                debug!(
                    "Scanner {} returned {} findings",
                    scanner_name,
                    scanner_findings.len()
                );
                for (i, scanner_finding) in scanner_findings.iter().enumerate() {
                    debug!(
                        "Converting finding {}: {} - {}",
                        i, scanner_finding.finding_type, scanner_finding.title
                    );
                    if let Ok(converted_finding) = self.convert_tameshi_finding_to_proto(
                        scanner_finding,
                        &scanner_name,
                        file_path,
                    ) {
                        all_findings.push(converted_finding);
                    } else {
                        warn!(
                            "Failed to convert finding {} from scanner {}",
                            i, scanner_name
                        );
                    }
                }
            }
        }

        let duration = start_time.elapsed();
        info!("LLM scan completed for {:?}. Found {} vulnerabilities (confidence >= {:?}). Duration: {}ms",
              file_path, all_findings.len(), options.confidence_threshold.unwrap_or(0.5), duration.as_millis());

        Ok(ScanResult {
            version: "1.0".to_string(),
            findings: all_findings,
            metadata: crate::proto::ScanMetadata {
                start_time: chrono::Utc::now().to_rfc3339(),
                duration_ms: duration.as_millis() as u64,
                scanned_files: vec![file_path.to_string_lossy().to_string()],
                skipped_files: std::collections::HashMap::new(),
                scanner_config: Some(serde_json::json!(scanner_info)),
            },
            errors: vec![],
        })
    }

    fn convert_tameshi_finding_to_proto(
        &self,
        tameshi_finding: &tameshi_scanners::Finding,
        scanner_name: &str,
        file_path: &Path,
    ) -> Result<Finding> {
        let severity = match tameshi_finding.severity {
            tameshi_scanners::Severity::Critical => Severity::Critical,
            tameshi_scanners::Severity::High => Severity::High,
            tameshi_scanners::Severity::Medium => Severity::Medium,
            tameshi_scanners::Severity::Low => Severity::Low,
            tameshi_scanners::Severity::Informational => Severity::Informational,
        };

        let base_severity = match tameshi_finding.base_severity {
            tameshi_scanners::Severity::Critical => Severity::Critical,
            tameshi_scanners::Severity::High => Severity::High,
            tameshi_scanners::Severity::Medium => Severity::Medium,
            tameshi_scanners::Severity::Low => Severity::Low,
            tameshi_scanners::Severity::Informational => Severity::Informational,
        };

        let confidence = match tameshi_finding.confidence {
            tameshi_scanners::Confidence::High => Confidence::High,
            tameshi_scanners::Confidence::Medium => Confidence::Medium,
            tameshi_scanners::Confidence::Low => Confidence::Low,
        };

        let locations: Result<Vec<Location>> = tameshi_finding
            .locations
            .iter()
            .map(|loc| {
                let file = if loc.file.is_empty() {
                    file_path.to_string_lossy().to_string()
                } else {
                    loc.file.clone()
                };
                Ok(Location {
                    file,
                    line: loc.line,
                    column: loc.column,
                    end_line: loc.end_line,
                    end_column: loc.end_column,
                    snippet: loc.snippet.clone(),
                })
            })
            .collect();

        let locations = locations?;

        let locations = if locations.is_empty() {
            vec![Location {
                file: file_path.to_string_lossy().to_string(),
                line: 1,
                column: 1,
                end_line: None,
                end_column: None,
                snippet: None,
            }]
        } else {
            locations
        };

        let metadata = Some(crate::proto::FindingMetadata {
            affected_functions: vec![],
            affected_variables: vec![],
            affected_contracts: vec![],
            recommendation: None,
            references: vec![],
            gas_impact: None,
            representation_info: None,
            provenance: None,
            correlations: vec![],
            analysis_type: Some(crate::proto::AnalysisType::LLM),
            evidence: vec![],
        });

        Ok(Finding {
            id: Uuid::new_v4(),
            scanner_id: scanner_name.to_string(),
            swc_id: tameshi_finding.swc_id.clone(),
            finding_type: tameshi_finding.finding_type.clone(),
            severity,
            base_severity,
            confidence,
            confidence_score: tameshi_finding.confidence_score,
            title: tameshi_finding.title.clone(),
            description: tameshi_finding.description.clone(),
            locations,
            metadata,
            severity_context: None,
        })
    }
}
