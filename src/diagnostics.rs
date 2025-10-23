//! Diagnostic conversion
//!
//! Translates rich security findings into LSP diagnostics. Findings carry metadata like
//! confidence scores, provenance, and cross-references that don't map directly to LSP's
//! simpler diagnostic model. We encode finding IDs in diagnostic codes to enable
//! "show details" actions and use related information for secondary locations.
//!
//! Filters findings by severity and confidence thresholds before publishing to avoid
//! overwhelming users. Groups diagnostics by file for batch publishing since editors
//! expect per-file updates.

use crate::proto::{Finding, Location};
use anyhow::Result;
use lsp_types::{
    Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, NumberOrString, Url,
};
use std::{collections::HashMap, path::PathBuf};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct DiagnosticsMapper {
    max_related_locations: usize,

    include_code_descriptions: bool,

    documentation_base_url: Option<String>,
}

impl DiagnosticsMapper {
    pub fn new() -> Self {
        Self {
            max_related_locations: 10,
            include_code_descriptions: true,
            documentation_base_url: Some("https://docs.tameshi.io/findings/".to_string()),
        }
    }

    pub fn with_config(
        max_related_locations: usize,
        include_code_descriptions: bool,
        documentation_base_url: Option<String>,
    ) -> Self {
        Self {
            max_related_locations,
            include_code_descriptions,
            documentation_base_url,
        }
    }

    pub fn map_findings_to_diagnostics(
        &self,
        findings: &[Finding],
    ) -> Result<HashMap<PathBuf, Vec<Diagnostic>>> {
        let mut diagnostics_by_file: HashMap<PathBuf, Vec<Diagnostic>> = HashMap::new();

        for finding in findings {
            if finding.locations.is_empty() {
                warn!("Finding {} has no locations, skipping", finding.id);
                continue;
            }

            let primary_location = &finding.locations[0];
            let file_path = PathBuf::from(&primary_location.file);

            let diagnostic = self.finding_to_diagnostic(finding)?;

            diagnostics_by_file
                .entry(file_path)
                .or_default()
                .push(diagnostic);
        }

        debug!(
            "Mapped {} findings to diagnostics across {} files",
            findings.len(),
            diagnostics_by_file.len()
        );

        Ok(diagnostics_by_file)
    }

    pub fn finding_to_diagnostic(&self, finding: &Finding) -> Result<Diagnostic> {
        let primary_location = finding
            .primary_location()
            .ok_or_else(|| anyhow::anyhow!("Finding has no primary location"))?;

        let range = primary_location.to_lsp_range();

        let severity = Some(finding.severity.to_lsp_severity());

        let analysis_prefix = if let Some(ref metadata) = finding.metadata {
            match metadata.analysis_type {
                Some(crate::proto::AnalysisType::LLM) => "[AI] ",
                Some(crate::proto::AnalysisType::Hybrid) => "[Hybrid] ",
                _ => "",
            }
        } else {
            ""
        };

        let correlation_suffix = if let Some(ref metadata) = finding.metadata {
            if !metadata.correlations.is_empty() {
                format!(" (✓ {} correlated)", metadata.correlations.len())
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let base_message = if finding.title.len() > 100 {
            format!(
                "{}: {}...",
                finding.title,
                &finding.description[..97.min(finding.description.len())]
            )
        } else {
            format!("{}: {}", finding.title, finding.description)
        };

        let message = format!("{}{}{}", analysis_prefix, base_message, correlation_suffix);

        let code = Some(NumberOrString::String(finding.diagnostic_code()));

        let code_description = if self.include_code_descriptions {
            self.create_code_description(finding)
        } else {
            None
        };

        let related_information = self.create_related_information(finding)?;

        let tags = self.create_diagnostic_tags(finding);

        let mut data_obj = serde_json::json!({
            "finding_id": finding.id,
            "scanner_id": finding.scanner_id,
            "finding_type": finding.finding_type,
            "confidence": finding.confidence,
            "confidence_score": finding.confidence_score
        });

        if let Some(ref metadata) = finding.metadata {
            if let Some(ref analysis_type) = metadata.analysis_type {
                data_obj["analysis_type"] = serde_json::json!(analysis_type);
            }
            if !metadata.correlations.is_empty() {
                data_obj["correlation_count"] = serde_json::json!(metadata.correlations.len());
                data_obj["correlated_findings"] = serde_json::json!(metadata
                    .correlations
                    .iter()
                    .map(|c| c.related_finding_id.clone())
                    .collect::<Vec<_>>());
            }
            if let Some(ref provenance) = metadata.provenance {
                data_obj["validation_status"] = serde_json::json!(provenance.validation_status);
            }
        }

        let data = Some(data_obj);

        Ok(Diagnostic {
            range,
            severity,
            code,
            code_description,
            source: Some("tameshi".to_string()),
            message,
            related_information,
            tags,
            data,
        })
    }

    fn create_code_description(&self, finding: &Finding) -> Option<lsp_types::CodeDescription> {
        if let Some(ref base_url) = self.documentation_base_url {
            let href = if let Some(ref swc_id) = finding.swc_id {
                format!("{}/swc/{}", base_url, swc_id)
            } else {
                format!("{}/{}", base_url, finding.finding_type)
            };

            if let Ok(url) = href.parse() {
                Some(lsp_types::CodeDescription { href: url })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn create_related_information(
        &self,
        finding: &Finding,
    ) -> Result<Option<Vec<DiagnosticRelatedInformation>>> {
        if finding.locations.len() <= 1 {
            return Ok(None);
        }

        let mut related_info = Vec::new();

        for location in finding
            .locations
            .iter()
            .skip(1)
            .take(self.max_related_locations)
        {
            if let Ok(related) = self.location_to_related_info(location, finding) {
                related_info.push(related);
            }
        }

        if related_info.is_empty() {
            Ok(None)
        } else {
            Ok(Some(related_info))
        }
    }

    fn location_to_related_info(
        &self,
        location: &Location,
        finding: &Finding,
    ) -> Result<DiagnosticRelatedInformation> {
        let file_path = PathBuf::from(&location.file);
        let uri = Url::from_file_path(&file_path)
            .map_err(|_| anyhow::anyhow!("Invalid file path: {:?}", file_path))?;

        let range = location.to_lsp_range();

        let message = if let Some(ref snippet) = location.snippet {
            format!(
                "Related to {}: {}",
                finding.finding_type,
                snippet.chars().take(50).collect::<String>()
            )
        } else {
            format!("Related to {}", finding.finding_type)
        };

        Ok(DiagnosticRelatedInformation {
            location: lsp_types::Location { uri, range },
            message,
        })
    }

    fn create_diagnostic_tags(&self, finding: &Finding) -> Option<Vec<lsp_types::DiagnosticTag>> {
        let mut tags = Vec::new();

        if finding.confidence_score < 0.5 {
            tags.push(lsp_types::DiagnosticTag::UNNECESSARY);
        }

        if let Some(ref metadata) = finding.metadata {
            if let Some(ref recommendation) = metadata.recommendation {
                if recommendation.to_lowercase().contains("deprecated") {
                    tags.push(lsp_types::DiagnosticTag::DEPRECATED);
                }
            }
        }

        if tags.is_empty() {
            None
        } else {
            Some(tags)
        }
    }

    pub fn update_config(
        &mut self,
        max_related_locations: Option<usize>,
        include_code_descriptions: Option<bool>,
        documentation_base_url: Option<String>,
    ) {
        if let Some(max_related) = max_related_locations {
            self.max_related_locations = max_related;
        }
        if let Some(include_code_desc) = include_code_descriptions {
            self.include_code_descriptions = include_code_desc;
        }
        if let Some(base_url) = documentation_base_url {
            self.documentation_base_url = Some(base_url);
        }
    }

    pub fn clear_diagnostics_for_file(
        &self,
        file_path: &Path,
    ) -> HashMap<PathBuf, Vec<Diagnostic>> {
        let mut result = HashMap::new();
        result.insert(file_path.to_path_buf(), Vec::new());
        result
    }

    pub fn filter_by_severity(
        diagnostics: &[Diagnostic],
        min_severity: DiagnosticSeverity,
    ) -> Vec<Diagnostic> {
        diagnostics
            .iter()
            .filter(|diag| {
                if let Some(severity) = diag.severity {
                    severity <= min_severity // Lower numeric value = higher severity
                } else {
                    true // Include diagnostics without severity
                }
            })
            .cloned()
            .collect()
    }

    pub fn group_by_severity(diagnostics: &[Diagnostic]) -> HashMap<i32, Vec<Diagnostic>> {
        let mut grouped = HashMap::new();

        for diagnostic in diagnostics {
            let severity = diagnostic
                .severity
                .unwrap_or(DiagnosticSeverity::INFORMATION);
            let severity_key = match severity {
                DiagnosticSeverity::ERROR => 1,
                DiagnosticSeverity::WARNING => 2,
                DiagnosticSeverity::INFORMATION => 3,
                DiagnosticSeverity::HINT => 4,
                _ => 5, // Unknown severity
            };
            grouped
                .entry(severity_key)
                .or_insert_with(Vec::new)
                .push(diagnostic.clone());
        }

        grouped
    }

    pub fn get_diagnostic_stats(
        diagnostics_by_file: &HashMap<PathBuf, Vec<Diagnostic>>,
    ) -> DiagnosticStats {
        let mut stats = DiagnosticStats::default();

        for diagnostics in diagnostics_by_file.values() {
            stats.total_count += diagnostics.len();

            for diagnostic in diagnostics {
                match diagnostic
                    .severity
                    .unwrap_or(DiagnosticSeverity::INFORMATION)
                {
                    DiagnosticSeverity::ERROR => stats.error_count += 1,
                    DiagnosticSeverity::WARNING => stats.warning_count += 1,
                    DiagnosticSeverity::INFORMATION => stats.info_count += 1,
                    DiagnosticSeverity::HINT => stats.hint_count += 1,
                    #[allow(unreachable_patterns)]
                    _ => stats.info_count += 1, // Future-proofing
                }
            }
        }

        stats.file_count = diagnostics_by_file.len();
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Confidence, Finding, Location, Severity};
    use lsp_types::{DiagnosticSeverity, Position, Range};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_finding_to_diagnostic_basic() {
        let mapper = DiagnosticsMapper::new();
        let finding = create_test_finding();

        let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();

        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(diagnostic.source, Some("tameshi".to_string()));
        assert!(diagnostic.message.contains("Test vulnerability"));
        assert!(diagnostic.message.contains("Test description"));

        if let Some(code) = diagnostic.code {
            match code {
                lsp_types::NumberOrString::String(s) => assert_eq!(s, "TMSH:test_scanner"),
                _ => panic!("Expected string code"),
            }
        } else {
            panic!("Expected diagnostic code");
        }
    }

    #[test]
    fn test_finding_to_diagnostic_severity_mapping() {
        let mapper = DiagnosticsMapper::new();

        let severities = vec![
            (Severity::Critical, DiagnosticSeverity::ERROR),
            (Severity::High, DiagnosticSeverity::ERROR),
            (Severity::Medium, DiagnosticSeverity::WARNING),
            (Severity::Low, DiagnosticSeverity::INFORMATION),
            (Severity::Informational, DiagnosticSeverity::HINT),
        ];

        for (severity, expected_lsp_severity) in severities {
            let finding = create_finding_with_severity(severity);
            let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();
            assert_eq!(diagnostic.severity, Some(expected_lsp_severity));
        }
    }

    #[test]
    fn test_finding_to_diagnostic_range_conversion() {
        let mapper = DiagnosticsMapper::new();
        let finding = create_test_finding();

        let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();

        let expected_range = Range {
            start: Position {
                line: 9,
                character: 4,
            },
            end: Position {
                line: 9,
                character: 19,
            }, // end_column 20 -> char 19
        };

        assert_eq!(diagnostic.range, expected_range);
    }

    #[test]
    fn test_finding_to_diagnostic_related_information() {
        let mapper = DiagnosticsMapper::new();
        let mut finding = create_test_finding();

        #[cfg(windows)]
        let other_file = "C:\\tmp\\other.sol".to_string();
        #[cfg(not(windows))]
        let other_file = "/tmp/other.sol".to_string();

        finding.locations.push(Location {
            file: other_file,
            line: 5,
            column: 10,
            end_line: Some(5),
            end_column: Some(20),
            snippet: Some("related code".to_string()),
        });

        let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();

        assert!(diagnostic.related_information.is_some());
        let related = diagnostic.related_information.unwrap();
        assert_eq!(related.len(), 1);
        assert!(related[0].message.contains("test_vulnerability"));
    }

    #[test]
    fn test_finding_to_diagnostic_long_message_truncation() {
        let mapper = DiagnosticsMapper::new();
        let mut finding = create_test_finding();

        finding.title = "A".repeat(150);
        finding.description = "B".repeat(150);

        let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();

        assert!(diagnostic.message.len() < finding.title.len() + finding.description.len());
        assert!(diagnostic.message.contains("..."));
    }

    #[test]
    fn test_finding_to_diagnostic_data_field() {
        let mapper = DiagnosticsMapper::new();
        let finding = create_test_finding();

        let diagnostic = mapper.finding_to_diagnostic(&finding).unwrap();

        assert!(diagnostic.data.is_some());
        let data = diagnostic.data.unwrap();
        assert!(data.get("finding_id").is_some());
        assert!(data.get("scanner_id").is_some());
        assert!(data.get("confidence").is_some());
    }

    #[test]
    fn test_map_findings_to_diagnostics() {
        let mapper = DiagnosticsMapper::new();
        let findings = vec![create_test_finding(), create_finding_with_file("other.sol")];

        let diagnostics_by_file = mapper.map_findings_to_diagnostics(&findings).unwrap();

        assert_eq!(diagnostics_by_file.len(), 2);
        assert!(diagnostics_by_file.contains_key(&PathBuf::from("test.sol")));
        assert!(diagnostics_by_file.contains_key(&PathBuf::from("other.sol")));

        let test_diagnostics = &diagnostics_by_file[&PathBuf::from("test.sol")];
        assert_eq!(test_diagnostics.len(), 1);
    }

    #[test]
    fn test_map_findings_to_diagnostics_no_locations() {
        let mapper = DiagnosticsMapper::new();
        let mut finding = create_test_finding();
        finding.locations.clear(); // Remove all locations

        let diagnostics_by_file = mapper.map_findings_to_diagnostics(&vec![finding]).unwrap();

        assert!(diagnostics_by_file.is_empty());
    }

    #[test]
    fn test_create_code_description() {
        let mapper = DiagnosticsMapper::new();
        let mut finding = create_test_finding();
        finding.swc_id = None; // Remove swc_id to test finding_type path

        let code_desc = mapper.create_code_description(&finding);

        assert!(code_desc.is_some());
        let desc = code_desc.unwrap();
        assert!(desc.href.to_string().contains("docs.tameshi.io"));
        assert!(desc.href.to_string().contains("test_vulnerability"));
    }

    #[test]
    fn test_create_code_description_with_swc() {
        let mapper = DiagnosticsMapper::new();
        let mut finding = create_test_finding();
        finding.swc_id = Some("SWC-107".to_string());

        let code_desc = mapper.create_code_description(&finding);

        assert!(code_desc.is_some());
        let desc = code_desc.unwrap();
        assert!(desc.href.to_string().contains("SWC-107"));
    }

    #[test]
    fn test_create_diagnostic_tags_low_confidence() {
        let mapper = DiagnosticsMapper::new();
        let finding = create_finding_with_confidence(Confidence::Low);

        let tags = mapper.create_diagnostic_tags(&finding);

        assert!(tags.is_some());
        let tags = tags.unwrap();
        assert!(tags.contains(&lsp_types::DiagnosticTag::UNNECESSARY));
    }

    #[test]
    fn test_filter_by_severity() {
        let diagnostics = vec![
            create_diagnostic_with_severity(DiagnosticSeverity::ERROR),
            create_diagnostic_with_severity(DiagnosticSeverity::WARNING),
            create_diagnostic_with_severity(DiagnosticSeverity::INFORMATION),
        ];

        let filtered =
            DiagnosticsMapper::filter_by_severity(&diagnostics, DiagnosticSeverity::WARNING);

        assert_eq!(filtered.len(), 2);
        assert!(filtered
            .iter()
            .all(|d| d.severity == Some(DiagnosticSeverity::ERROR)
                || d.severity == Some(DiagnosticSeverity::WARNING)));
    }

    #[test]
    fn test_group_by_severity() {
        let diagnostics = vec![
            create_diagnostic_with_severity(DiagnosticSeverity::ERROR),
            create_diagnostic_with_severity(DiagnosticSeverity::ERROR),
            create_diagnostic_with_severity(DiagnosticSeverity::WARNING),
        ];

        let grouped = DiagnosticsMapper::group_by_severity(&diagnostics);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&1].len(), 2); // ERROR = 1
        assert_eq!(grouped[&2].len(), 1); // WARNING = 2
    }

    #[test]
    fn test_get_diagnostic_stats() {
        let mut diagnostics_by_file = HashMap::new();
        diagnostics_by_file.insert(
            PathBuf::from("test.sol"),
            vec![
                create_diagnostic_with_severity(DiagnosticSeverity::ERROR),
                create_diagnostic_with_severity(DiagnosticSeverity::WARNING),
            ],
        );
        diagnostics_by_file.insert(
            PathBuf::from("other.sol"),
            vec![create_diagnostic_with_severity(
                DiagnosticSeverity::INFORMATION,
            )],
        );

        let stats = DiagnosticsMapper::get_diagnostic_stats(&diagnostics_by_file);

        assert_eq!(stats.total_count, 3);
        assert_eq!(stats.error_count, 1);
        assert_eq!(stats.warning_count, 1);
        assert_eq!(stats.info_count, 1);
        assert_eq!(stats.hint_count, 0);
        assert_eq!(stats.file_count, 2);
    }

    #[test]
    fn test_diagnostic_stats_has_high_severity_issues() {
        let stats = DiagnosticStats {
            total_count: 2,
            error_count: 1,
            warning_count: 0,
            info_count: 1,
            hint_count: 0,
            file_count: 1,
        };

        assert!(stats.has_high_severity_issues());

        let stats_low = DiagnosticStats {
            total_count: 1,
            error_count: 0,
            warning_count: 0,
            info_count: 1,
            hint_count: 0,
            file_count: 1,
        };

        assert!(!stats_low.has_high_severity_issues());
    }

    #[test]
    fn test_diagnostic_stats_highest_severity() {
        let stats = DiagnosticStats {
            total_count: 3,
            error_count: 1,
            warning_count: 1,
            info_count: 1,
            hint_count: 0,
            file_count: 1,
        };

        assert_eq!(stats.highest_severity(), Some(DiagnosticSeverity::ERROR));

        let stats_warning_only = DiagnosticStats {
            total_count: 1,
            error_count: 0,
            warning_count: 1,
            info_count: 0,
            hint_count: 0,
            file_count: 1,
        };

        assert_eq!(
            stats_warning_only.highest_severity(),
            Some(DiagnosticSeverity::WARNING)
        );
    }

    fn create_test_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            scanner_id: "test_scanner".to_string(),
            swc_id: Some("SWC-123".to_string()),
            finding_type: "test_vulnerability".to_string(),
            severity: Severity::High,
            base_severity: Severity::High,
            confidence: Confidence::High,
            confidence_score: 0.9,
            title: "Test vulnerability".to_string(),
            description: "Test description".to_string(),
            locations: vec![Location {
                file: "test.sol".to_string(),
                line: 10,
                column: 5,
                end_line: Some(10),
                end_column: Some(20),
                snippet: Some("test code".to_string()),
            }],
            metadata: None,
            severity_context: None,
        }
    }

    fn create_finding_with_severity(severity: Severity) -> Finding {
        let mut finding = create_test_finding();
        finding.severity = severity;
        finding
    }

    fn create_finding_with_confidence(confidence: Confidence) -> Finding {
        let mut finding = create_test_finding();
        finding.confidence = confidence;
        finding.confidence_score = confidence.to_score();
        finding
    }

    fn create_finding_with_file(file: &str) -> Finding {
        let mut finding = create_test_finding();
        finding.locations[0].file = file.to_string();
        finding
    }

    fn create_diagnostic_with_severity(severity: DiagnosticSeverity) -> Diagnostic {
        Diagnostic {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 1,
                },
            },
            severity: Some(severity),
            code: None,
            code_description: None,
            source: Some("tameshi".to_string()),
            message: "Test diagnostic".to_string(),
            related_information: None,
            tags: None,
            data: None,
        }
    }
}

impl Default for DiagnosticsMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiagnosticStats {
    pub total_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub hint_count: usize,
    pub file_count: usize,
}

impl DiagnosticStats {
    pub fn has_high_severity_issues(&self) -> bool {
        self.error_count > 0 || self.warning_count > 0
    }

    pub fn highest_severity(&self) -> Option<DiagnosticSeverity> {
        if self.error_count > 0 {
            Some(DiagnosticSeverity::ERROR)
        } else if self.warning_count > 0 {
            Some(DiagnosticSeverity::WARNING)
        } else if self.info_count > 0 {
            Some(DiagnosticSeverity::INFORMATION)
        } else if self.hint_count > 0 {
            Some(DiagnosticSeverity::HINT)
        } else {
            None
        }
    }
}
use std::path::Path;
