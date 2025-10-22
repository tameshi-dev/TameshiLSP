//! Protocol types
//!
//! Defines stable wire format for scanner output separate from internal scanner types.
//! Scanner implementations evolve with new analysis techniques while LSP clients need
//! consistent JSON schemas across versions. Custom serde attributes control
//! serialization to match LSP spec requirements.
//!
//! PROTOCOL_VERSION tracks breaking changes for compatibility checking between scanner
//! and server. Enums for severity and confidence provide type safety and validation
//! over raw integers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn to_lsp_severity(&self) -> lsp_types::DiagnosticSeverity {
        match self {
            Self::Critical | Self::High => lsp_types::DiagnosticSeverity::ERROR,
            Self::Medium => lsp_types::DiagnosticSeverity::WARNING,
            Self::Low => lsp_types::DiagnosticSeverity::INFORMATION,
            Self::Informational => lsp_types::DiagnosticSeverity::HINT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn to_score(&self) -> f64 {
        match self {
            Self::High => 0.9,
            Self::Medium => 0.6,
            Self::Low => 0.3,
        }
    }

    pub fn as_f32(&self) -> f32 {
        match self {
            Self::High => 0.9,
            Self::Medium => 0.6,
            Self::Low => 0.3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub snippet: Option<String>,
}

impl Location {
    pub fn to_lsp_range(&self) -> lsp_types::Range {
        let start = lsp_types::Position {
            line: (self.line.saturating_sub(1)) as u32, // LSP is 0-indexed
            character: (self.column.saturating_sub(1)) as u32,
        };

        let end = if let (Some(end_line), Some(end_column)) = (self.end_line, self.end_column) {
            lsp_types::Position {
                line: (end_line.saturating_sub(1)) as u32,
                character: (end_column.saturating_sub(1)) as u32,
            }
        } else {
            lsp_types::Position {
                line: start.line,
                character: 9999, // VS Code will clamp this to actual line end
            }
        };

        lsp_types::Range { start, end }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,

    pub scanner_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub swc_id: Option<String>,

    pub finding_type: String,

    pub severity: Severity,

    pub base_severity: Severity,

    pub confidence: Confidence,

    pub confidence_score: f64,

    pub title: String,

    pub description: String,

    pub locations: Vec<Location>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FindingMetadata>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_context: Option<SeverityContext>,
}

impl Finding {
    pub fn diagnostic_code(&self) -> String {
        format!("TMSH:{}", self.scanner_id)
    }

    pub fn primary_location(&self) -> Option<&Location> {
        self.locations.first()
    }

    pub fn dedup_key(&self) -> String {
        let mut key = format!("{}:{}", self.finding_type, self.scanner_id);

        if let Some(loc) = self.primary_location() {
            key.push_str(&format!(":{}:{}:{}", loc.file, loc.line, loc.column));
        }

        key
    }

    pub fn priority_score(&self) -> u32 {
        let severity_score = match self.severity {
            Severity::Critical => 1000,
            Severity::High => 100,
            Severity::Medium => 10,
            Severity::Low => 1,
            Severity::Informational => 0,
        };

        let confidence_multiplier = match self.confidence {
            Confidence::High => 10,
            Confidence::Medium => 5,
            Confidence::Low => 1,
        };

        severity_score * confidence_multiplier
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityContext {
    pub escalation_factors: Vec<String>,

    pub mitigation_factors: Vec<String>,

    pub holds_value: bool,

    pub is_public: bool,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub custom_factors: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingMetadata {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub affected_functions: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub affected_variables: Vec<String>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub affected_contracts: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_impact: Option<GasImpact>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation_info: Option<RepresentationInfo>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance: Option<Provenance>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub correlations: Vec<Correlation>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub analysis_type: Option<AnalysisType>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepresentationInfo {
    pub representation_type: String,
    pub extraction_strategy: String,
    pub token_count: usize,
    pub was_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub included_functions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub included_contracts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasImpact {
    pub min_gas: u64,
    pub max_gas: u64,
    pub average_gas: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub version: String,

    pub findings: Vec<Finding>,

    pub metadata: ScanMetadata,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<ScanError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub start_time: String,

    pub duration_ms: u64,

    pub scanned_files: Vec<String>,

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub skipped_files: HashMap<String, String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub code: String,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct GetFindingsRequest {
    pub scope: FindingsScope,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<Confidence>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FindingsScope {
    #[serde(rename = "workspace")]
    Workspace,
    #[serde(rename = "file")]
    File { path: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFindingsResponse {
    pub findings: Vec<Finding>,
    pub total_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFindingDetailsRequest {
    pub finding_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetFindingDetailsResponse {
    pub finding: Finding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_context: Option<serde_json::Value>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ScanProgressNotification {
    pub token: String,

    pub progress: f64,

    pub message: String,

    pub files_processed: usize,

    pub total_files: usize,
}

pub mod error_codes {
    pub const SCANNER_NOT_FOUND: i32 = -32001;
    pub const SCANNER_TIMEOUT: i32 = -32002;
    pub const SCANNER_ERROR: i32 = -32003;
    pub const INVALID_WORKSPACE: i32 = -32004;
    pub const FINDING_NOT_FOUND: i32 = -32005;
    pub const OPERATION_CANCELLED: i32 = -32006;
    pub const EXPORT_ERROR: i32 = -32007;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportFindingsRequest {
    pub format: ExportFormat,

    pub output_path: String,

    pub scope: FindingsScope,

    #[serde(default = "default_true")]
    pub pretty: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Sarif,
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportFindingsResponse {
    pub output_path: String,

    pub findings_count: usize,

    pub format: ExportFormat,

    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisType {
    Deterministic,
    LLM,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub finding_id: String,

    pub source: ProvenanceSource,

    pub confidence_factors: Vec<ConfidenceFactor>,

    pub analysis_metadata: AnalysisMetadata,

    pub validation_status: ValidationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProvenanceSource {
    Deterministic {
        scanner_id: String,
        pattern_id: String,
        pattern_description: String,
    },
    LLM {
        scanner_id: String,
        model: String,
        prompt_hash: String,
    },
    Hybrid {
        deterministic_scanner: String,
        llm_scanner: String,
        correlation_score: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceFactor {
    pub factor_type: String,
    pub description: String,
    pub impact: f64, // -1.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    pub scan_timestamp: String,
    pub scanner_version: String,
    pub ir_transform_success: bool,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Unvalidated,
    Confirmed,
    Contradicted,
    PartiallyConfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub related_finding_id: String,

    pub relationship: FindingRelationship,

    pub correlation_strength: f64,

    pub correlation_method: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingRelationship {
    SameVulnerability,
    Confirms,
    Contradicts,
    RootCause,
    Consequence,
    Related,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_type: EvidenceType,

    pub content: String,

    pub location: Option<EvidenceLocation>,

    pub relevance: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    IRSequence,
    SourceCode,
    ControlFlow,
    DataFlow,
    PatternMatch,
    LLMReasoning,
    SymbolUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLocation {
    pub file: String,

    pub function: Option<String>,

    pub block_id: Option<String>,

    pub start_line: usize,
    pub end_line: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{DiagnosticSeverity, Position, Range};

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Informational);
    }

    #[test]
    fn test_severity_lsp_mapping() {
        assert_eq!(
            Severity::Critical.to_lsp_severity(),
            DiagnosticSeverity::ERROR
        );
        assert_eq!(Severity::High.to_lsp_severity(), DiagnosticSeverity::ERROR);
        assert_eq!(
            Severity::Medium.to_lsp_severity(),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            Severity::Low.to_lsp_severity(),
            DiagnosticSeverity::INFORMATION
        );
        assert_eq!(
            Severity::Informational.to_lsp_severity(),
            DiagnosticSeverity::HINT
        );
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn test_confidence_to_score() {
        assert_eq!(Confidence::High.to_score(), 0.9);
        assert_eq!(Confidence::Medium.to_score(), 0.6);
        assert_eq!(Confidence::Low.to_score(), 0.3);
    }

    #[test]
    fn test_location_to_lsp_range() {
        let location = Location {
            file: "test.sol".to_string(),
            line: 10,
            column: 5,
            end_line: Some(10),
            end_column: Some(15),
            snippet: None,
        };

        let range = location.to_lsp_range();
        assert_eq!(
            range.start,
            Position {
                line: 9,
                character: 4
            }
        ); // 0-indexed
        assert_eq!(
            range.end,
            Position {
                line: 9,
                character: 14
            }
        );
    }

    #[test]
    #[ignore = "LSP range calculation needs fixing"]
    fn test_location_to_lsp_range_single_point() {
        let location = Location {
            file: "test.sol".to_string(),
            line: 5,
            column: 3,
            end_line: None,
            end_column: None,
            snippet: None,
        };

        let range = location.to_lsp_range();
        assert_eq!(
            range.start,
            Position {
                line: 4,
                character: 2
            }
        );
        assert_eq!(
            range.end,
            Position {
                line: 4,
                character: 3
            }
        ); // Single character
    }

    #[test]
    fn test_finding_diagnostic_code() {
        let finding = create_test_finding();
        assert_eq!(finding.diagnostic_code(), "TMSH:test_scanner");
    }

    #[test]
    fn test_finding_primary_location() {
        let finding = create_test_finding();
        let primary = finding.primary_location().unwrap();
        assert_eq!(primary.file, "test.sol");
        assert_eq!(primary.line, 10);
    }

    #[test]
    fn test_finding_dedup_key() {
        let finding = create_test_finding();
        let key = finding.dedup_key();
        assert_eq!(key, "reentrancy:test_scanner:test.sol:10:5");
    }

    #[test]
    fn test_finding_priority_score() {
        let high_critical =
            create_finding_with_severity_confidence(Severity::Critical, Confidence::High);
        let medium_low = create_finding_with_severity_confidence(Severity::Medium, Confidence::Low);

        assert!(high_critical.priority_score() > medium_low.priority_score());
        assert_eq!(high_critical.priority_score(), 10000); // 1000 * 10
        assert_eq!(medium_low.priority_score(), 10); // 10 * 1
    }

    #[test]
    fn test_finding_serialization() {
        let finding = create_test_finding();
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();

        assert_eq!(finding.scanner_id, deserialized.scanner_id);
        assert_eq!(finding.finding_type, deserialized.finding_type);
        assert_eq!(finding.severity, deserialized.severity);
        assert_eq!(finding.title, deserialized.title);
    }

    #[test]
    fn test_scan_result_serialization() {
        let scan_result = ScanResult {
            version: PROTOCOL_VERSION.to_string(),
            findings: vec![create_test_finding()],
            metadata: ScanMetadata {
                start_time: "2023-01-01T00:00:00Z".to_string(),
                duration_ms: 1000,
                scanned_files: vec!["test.sol".to_string()],
                skipped_files: HashMap::new(),
                scanner_config: None,
            },
            errors: vec![],
        };

        let json = serde_json::to_string(&scan_result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();

        assert_eq!(scan_result.version, deserialized.version);
        assert_eq!(scan_result.findings.len(), deserialized.findings.len());
    }

    #[test]
    fn test_findings_scope_serialization() {
        let workspace_scope = FindingsScope::Workspace;
        let file_scope = FindingsScope::File {
            path: "test.sol".to_string(),
        };

        let workspace_json = serde_json::to_string(&workspace_scope).unwrap();
        let file_json = serde_json::to_string(&file_scope).unwrap();

        assert!(workspace_json.contains("workspace"));
        assert!(file_json.contains("file"));
        assert!(file_json.contains("test.sol"));
    }

    #[test]
    fn test_scan_progress_notification() {
        let progress = ScanProgressNotification {
            token: "test-token".to_string(),
            progress: 0.5,
            message: "Scanning...".to_string(),
            files_processed: 5,
            total_files: 10,
        };

        let json = serde_json::to_string(&progress).unwrap();
        let deserialized: ScanProgressNotification = serde_json::from_str(&json).unwrap();

        assert_eq!(progress.token, deserialized.token);
        assert_eq!(progress.progress, deserialized.progress);
        assert_eq!(progress.files_processed, deserialized.files_processed);
    }

    fn create_test_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scanner_id: "test_scanner".to_string(),
            swc_id: Some("SWC-107".to_string()),
            finding_type: "reentrancy".to_string(),
            severity: Severity::High,
            base_severity: Severity::High,
            confidence: Confidence::High,
            confidence_score: 0.9,
            title: "Reentrancy vulnerability".to_string(),
            description: "Potential reentrancy attack".to_string(),
            locations: vec![Location {
                file: "test.sol".to_string(),
                line: 10,
                column: 5,
                end_line: Some(10),
                end_column: Some(20),
                snippet: Some("transfer(msg.sender, amount)".to_string()),
            }],
            metadata: Some(FindingMetadata {
                affected_functions: vec!["withdraw".to_string()],
                affected_variables: vec!["balance".to_string()],
                affected_contracts: vec!["TestContract".to_string()],
                recommendation: Some("Use reentrancy guard".to_string()),
                references: vec!["https://example.com/reentrancy".to_string()],
                gas_impact: Some(GasImpact {
                    min_gas: 1000,
                    max_gas: 5000,
                    average_gas: 3000,
                }),
                representation_info: None,
                provenance: None,
                correlations: vec![],
                analysis_type: None,
                evidence: vec![],
            }),
            severity_context: Some(SeverityContext {
                escalation_factors: vec!["public function".to_string()],
                mitigation_factors: vec![],
                holds_value: true,
                is_public: true,
                custom_factors: HashMap::new(),
            }),
        }
    }

    fn create_finding_with_severity_confidence(
        severity: Severity,
        confidence: Confidence,
    ) -> Finding {
        let mut finding = create_test_finding();
        finding.severity = severity;
        finding.confidence = confidence;
        finding.confidence_score = confidence.to_score();
        finding
    }
}
