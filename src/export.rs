//! Export module for findings
//!
//! Provides functionality to export findings to various formats:
//! - SARIF (Static Analysis Results Interchange Format)
//! - JSON (simplified format)

use crate::proto::{AnalysisType, Confidence, Finding, ScanResult, Severity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<SarifArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifRuleConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub message: SarifMessage,
    pub level: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "startColumn")]
    pub start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "endLine")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "endColumn")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifArtifactContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "startTimeUtc")]
    pub start_time_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "endTimeUtc")]
    pub end_time_utc: Option<String>,
}

pub struct SarifExporter;

impl SarifExporter {
    pub fn export(scan_result: &ScanResult) -> Result<SarifReport> {
        let mut scanner_rules: HashMap<String, (usize, SarifRule)> = HashMap::new();
        let mut rule_index = 0;

        for finding in &scan_result.findings {
            let rule_id = format!("{}::{}", finding.scanner_id, finding.finding_type);

            if !scanner_rules.contains_key(&rule_id) {
                let rule = Self::finding_to_rule(finding);
                scanner_rules.insert(rule_id.clone(), (rule_index, rule));
                rule_index += 1;
            }
        }

        let mut rules: Vec<_> = scanner_rules.values().cloned().collect();
        rules.sort_by_key(|(idx, _)| *idx);
        let rules: Vec<SarifRule> = rules.into_iter().map(|(_, rule)| rule).collect();

        let results: Vec<SarifResult> = scan_result
            .findings
            .iter()
            .map(|finding| {
                let rule_id = format!("{}::{}", finding.scanner_id, finding.finding_type);
                let rule_index = scanner_rules.get(&rule_id).unwrap().0;
                Self::finding_to_result(finding, rule_index)
            })
            .collect();

        let mut artifact_map: HashMap<String, SarifArtifact> = HashMap::new();
        for finding in &scan_result.findings {
            for location in &finding.locations {
                artifact_map
                    .entry(location.file.clone())
                    .or_insert_with(|| SarifArtifact {
                        location: SarifArtifactLocation {
                            uri: location.file.clone(),
                            uri_base_id: Some("%SRCROOT%".to_string()),
                        },
                        length: None,
                        roles: Some(vec!["analysisTarget".to_string()]),
                    });
            }
        }
        let artifacts: Vec<SarifArtifact> = artifact_map.into_values().collect();

        let invocations = vec![SarifInvocation {
            execution_successful: true,
            start_time_utc: Some(scan_result.metadata.start_time.clone()),
            end_time_utc: None,
        }];

        Ok(SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Tameshi Security Scanner".to_string(),
                        version: Some(scan_result.version.clone()),
                        information_uri: Some("https://github.com/your-org/tameshi".to_string()),
                        rules,
                    },
                },
                results,
                artifacts,
                invocations: Some(invocations),
            }],
        })
    }

    fn finding_to_rule(finding: &Finding) -> SarifRule {
        let mut properties = HashMap::new();
        properties.insert(
            "scanner_id".to_string(),
            serde_json::json!(finding.scanner_id),
        );

        if let Some(swc_id) = &finding.swc_id {
            properties.insert("swc_id".to_string(), serde_json::json!(swc_id));
        }

        if let Some(metadata) = &finding.metadata {
            if let Some(analysis_type) = metadata.analysis_type {
                properties.insert(
                    "analysis_type".to_string(),
                    serde_json::json!(match analysis_type {
                        AnalysisType::Deterministic => "deterministic",
                        AnalysisType::LLM => "llm",
                        AnalysisType::Hybrid => "hybrid",
                    }),
                );
            }
        }

        let help_text = if let Some(metadata) = &finding.metadata {
            if let Some(recommendation) = &metadata.recommendation {
                format!(
                    "{}\n\nRecommendation: {}",
                    finding.description, recommendation
                )
            } else {
                finding.description.clone()
            }
        } else {
            finding.description.clone()
        };

        SarifRule {
            id: format!("{}::{}", finding.scanner_id, finding.finding_type),
            name: finding.finding_type.clone(),
            short_description: Some(SarifMessage {
                text: finding.title.clone(),
                markdown: None,
            }),
            full_description: Some(SarifMessage {
                text: finding.description.clone(),
                markdown: None,
            }),
            help: Some(SarifMessage {
                text: help_text.clone(),
                markdown: Some(help_text),
            }),
            help_uri: finding
                .metadata
                .as_ref()
                .and_then(|m| m.references.first().cloned()),
            properties: Some(properties),
            default_configuration: Some(SarifRuleConfiguration {
                level: Self::severity_to_sarif_level(finding.severity),
                rank: Some(Self::calculate_rank(finding.severity, finding.confidence)),
            }),
        }
    }

    fn finding_to_result(finding: &Finding, rule_index: usize) -> SarifResult {
        let locations: Vec<SarifLocation> = finding
            .locations
            .iter()
            .map(|loc| SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: loc.file.clone(),
                        uri_base_id: Some("%SRCROOT%".to_string()),
                    },
                    region: SarifRegion {
                        start_line: loc.line,
                        start_column: if loc.column > 0 {
                            Some(loc.column)
                        } else {
                            None
                        },
                        end_line: loc.end_line,
                        end_column: loc.end_column,
                        snippet: loc
                            .snippet
                            .as_ref()
                            .map(|s| SarifArtifactContent { text: s.clone() }),
                    },
                },
            })
            .collect();

        let mut properties = HashMap::new();
        properties.insert(
            "finding_id".to_string(),
            serde_json::json!(finding.id.to_string()),
        );
        properties.insert(
            "confidence".to_string(),
            serde_json::json!(match finding.confidence {
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
            }),
        );
        properties.insert(
            "confidence_score".to_string(),
            serde_json::json!(finding.confidence_score),
        );
        properties.insert(
            "base_severity".to_string(),
            serde_json::json!(match finding.base_severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Informational => "informational",
            }),
        );

        if let Some(metadata) = &finding.metadata {
            if !metadata.affected_functions.is_empty() {
                properties.insert(
                    "affected_functions".to_string(),
                    serde_json::json!(metadata.affected_functions),
                );
            }
            if !metadata.affected_contracts.is_empty() {
                properties.insert(
                    "affected_contracts".to_string(),
                    serde_json::json!(metadata.affected_contracts),
                );
            }
            if !metadata.correlations.is_empty() {
                let correlated_ids: Vec<String> = metadata
                    .correlations
                    .iter()
                    .map(|c| c.related_finding_id.clone())
                    .collect();
                properties.insert(
                    "correlated_findings".to_string(),
                    serde_json::json!(correlated_ids),
                );
            }
        }

        let code_flows = if locations.len() > 1 {
            vec![SarifCodeFlow {
                thread_flows: vec![SarifThreadFlow {
                    locations: locations
                        .iter()
                        .enumerate()
                        .map(|(idx, loc)| SarifThreadFlowLocation {
                            location: loc.clone(),
                            index: Some(idx),
                        })
                        .collect(),
                }],
            }]
        } else {
            vec![]
        };

        let mut fingerprints = HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(), finding.dedup_key());

        SarifResult {
            rule_id: format!("{}::{}", finding.scanner_id, finding.finding_type),
            rule_index,
            message: SarifMessage {
                text: finding.title.clone(),
                markdown: Some(finding.description.clone()),
            },
            level: Self::severity_to_sarif_level(finding.severity),
            locations,
            properties: Some(properties),
            code_flows,
            partial_fingerprints: Some(fingerprints),
        }
    }

    fn severity_to_sarif_level(severity: Severity) -> String {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Informational => "none",
        }
        .to_string()
    }

    fn calculate_rank(severity: Severity, confidence: Confidence) -> f64 {
        let severity_score = match severity {
            Severity::Critical => 100.0,
            Severity::High => 80.0,
            Severity::Medium => 60.0,
            Severity::Low => 40.0,
            Severity::Informational => 20.0,
        };

        let confidence_multiplier = match confidence {
            Confidence::High => 1.0,
            Confidence::Medium => 0.8,
            Confidence::Low => 0.6,
        };

        severity_score * confidence_multiplier
    }

    pub fn to_json(report: &SarifReport, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(report)?)
        } else {
            Ok(serde_json::to_string(report)?)
        }
    }
}

pub struct JsonExporter;

impl JsonExporter {
    pub fn export(scan_result: &ScanResult, pretty: bool) -> Result<String> {
        if pretty {
            Ok(serde_json::to_string_pretty(scan_result)?)
        } else {
            Ok(serde_json::to_string(scan_result)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{FindingMetadata, Location, ScanMetadata};
    use uuid::Uuid;

    fn create_test_scan_result() -> ScanResult {
        ScanResult {
            version: "1.0.0".to_string(),
            findings: vec![Finding {
                id: Uuid::new_v4(),
                scanner_id: "llm_comprehensive".to_string(),
                swc_id: Some("SWC-107".to_string()),
                finding_type: "reentrancy".to_string(),
                severity: Severity::High,
                base_severity: Severity::High,
                confidence: Confidence::High,
                confidence_score: 0.9,
                title: "Reentrancy vulnerability in withdraw".to_string(),
                description: "External call before state update".to_string(),
                locations: vec![
                    Location {
                        file: "VulnerableContract.sol".to_string(),
                        line: 21,
                        column: 1,
                        end_line: Some(21),
                        end_column: Some(50),
                        snippet: Some(
                            "(bool success, ) = msg.sender.call{value: amount}(\"\");".to_string(),
                        ),
                    },
                    Location {
                        file: "VulnerableContract.sol".to_string(),
                        line: 25,
                        column: 1,
                        end_line: Some(25),
                        end_column: Some(35),
                        snippet: Some("balances[msg.sender] -= amount;".to_string()),
                    },
                ],
                metadata: Some(FindingMetadata {
                    affected_functions: vec!["withdraw".to_string()],
                    affected_variables: vec!["balances".to_string()],
                    affected_contracts: vec!["VulnerableContract".to_string()],
                    recommendation: Some("Use checks-effects-interactions pattern".to_string()),
                    references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
                    gas_impact: None,
                    representation_info: None,
                    provenance: None,
                    correlations: vec![],
                    analysis_type: Some(AnalysisType::LLM),
                    evidence: vec![],
                }),
                severity_context: None,
            }],
            metadata: ScanMetadata {
                start_time: "2025-10-16T05:27:00Z".to_string(),
                duration_ms: 1000,
                scanned_files: vec!["VulnerableContract.sol".to_string()],
                skipped_files: HashMap::new(),
                scanner_config: None,
            },
            errors: vec![],
        }
    }

    #[test]
    fn test_sarif_export() {
        let scan_result = create_test_scan_result();
        let sarif = SarifExporter::export(&scan_result).unwrap();

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);

        let run = &sarif.runs[0];
        assert_eq!(run.tool.driver.name, "Tameshi Security Scanner");
        assert_eq!(run.results.len(), 1);
        assert!(!run.artifacts.is_empty());

        let result = &run.results[0];
        assert_eq!(result.level, "error");
        assert_eq!(result.locations.len(), 2);
    }

    #[test]
    fn test_sarif_to_json() {
        let scan_result = create_test_scan_result();
        let sarif = SarifExporter::export(&scan_result).unwrap();
        let json = SarifExporter::to_json(&sarif, true).unwrap();

        assert!(json.contains("$schema"));
        assert!(json.contains("2.1.0"));
        assert!(json.contains("Tameshi Security Scanner"));
    }

    #[test]
    fn test_json_export() {
        let scan_result = create_test_scan_result();
        let json = JsonExporter::export(&scan_result, true).unwrap();

        assert!(json.contains("findings"));
        assert!(json.contains("reentrancy"));
        assert!(json.contains("VulnerableContract.sol"));
    }

    #[test]
    fn test_severity_to_sarif_level() {
        assert_eq!(
            SarifExporter::severity_to_sarif_level(Severity::Critical),
            "error"
        );
        assert_eq!(
            SarifExporter::severity_to_sarif_level(Severity::High),
            "error"
        );
        assert_eq!(
            SarifExporter::severity_to_sarif_level(Severity::Medium),
            "warning"
        );
        assert_eq!(
            SarifExporter::severity_to_sarif_level(Severity::Low),
            "note"
        );
        assert_eq!(
            SarifExporter::severity_to_sarif_level(Severity::Informational),
            "none"
        );
    }

    #[test]
    fn test_calculate_rank() {
        assert_eq!(
            SarifExporter::calculate_rank(Severity::Critical, Confidence::High),
            100.0
        );
        assert_eq!(
            SarifExporter::calculate_rank(Severity::High, Confidence::High),
            80.0
        );
        assert_eq!(
            SarifExporter::calculate_rank(Severity::Medium, Confidence::Medium),
            48.0
        );
    }
}
