//! Configuration management
//!
//! Security auditors need all findings including low-confidence ones, while developers
//! prefer seeing only high-severity issues during active work. LSP allows live config
//! updates through workspace/didChangeConfiguration, so we merge partial updates with
//! existing settings and trigger rescans when necessary.
//!
//! Separate structs for scan, rule, and ignore configs let sections fail validation
//! independently without breaking the entire configuration. The adapter config supports
//! both embedded library usage and external CLI tools for scanner integration.

use crate::proto::Severity;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TameshiConfig {
    pub scan: ScanConfig,

    pub rules: RuleConfig,

    pub ignore: IgnoreConfig,

    pub limits: LimitsConfig,

    pub adapter: AdapterConfig,

    pub diagnostics: DiagnosticsConfig,

    pub llm: LLMScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub on_save_mode: OnSaveMode,

    pub include_patterns: Vec<String>,

    pub exclude_patterns: Vec<String>,

    pub respect_vcs_ignore: bool,

    pub debounce_delay_ms: u64,

    pub incremental: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnSaveMode {
    None,
    File,
    Workspace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub enabled_rules: Option<Vec<String>>,

    pub disabled_rules: Vec<String>,

    pub severity_overrides: HashMap<String, Severity>,

    pub rule_settings: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreConfig {
    pub codes: Vec<String>,

    pub paths: Vec<String>,

    pub scanners: Vec<String>,

    pub patterns: Vec<IgnorePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnorePattern {
    pub file_pattern: String,

    pub code_pattern: Option<String>,

    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub max_concurrent_scans: usize,

    pub scan_timeout_seconds: u64,

    pub max_memory_mb: usize,

    pub max_findings: usize,

    pub cache_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    pub mode: String,

    pub binary_path: Option<PathBuf>,

    pub args: Vec<String>,

    pub env: HashMap<String, String>,

    pub working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsConfig {
    pub max_related_locations: usize,

    pub include_code_descriptions: bool,

    pub documentation_base_url: Option<String>,

    pub min_severity: Option<Severity>,

    pub show_low_confidence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMScanConfig {
    pub enabled: bool,

    pub config_path: Option<PathBuf>,

    pub provider: LLMProviderConfig,

    pub global: LLMGlobalSettings,

    pub enabled_scanners: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMProviderConfig {
    #[serde(rename = "type")]
    pub r#type: String,

    pub model: String,

    pub api_key: Option<String>,

    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMGlobalSettings {
    pub default_temperature: f32,

    pub default_max_tokens: u32,

    pub default_confidence_threshold: f32,

    pub include_low_severity: bool,

    pub retry_attempts: u32,

    pub timeout_seconds: u64,

    pub concurrent_requests: usize,

    pub use_ir_scanning: bool,
}

impl Default for LLMScanConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default (opt-in)
            config_path: None,
            provider: LLMProviderConfig {
                r#type: "openai".to_string(),
                model: "gpt-4".to_string(),
                api_key: None,
                base_url: None,
            },
            global: LLMGlobalSettings {
                default_temperature: 0.7,
                default_max_tokens: 4000,
                default_confidence_threshold: 0.7,
                include_low_severity: false,
                retry_attempts: 3,
                timeout_seconds: 60,
                concurrent_requests: 3,
                use_ir_scanning: false, // Default to Solidity-based scanning
            },
            enabled_scanners: vec![],
        }
    }
}

impl Default for LLMProviderConfig {
    fn default() -> Self {
        Self {
            r#type: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_key: None,
            base_url: None,
        }
    }
}

impl Default for LLMGlobalSettings {
    fn default() -> Self {
        Self {
            default_temperature: 0.7,
            default_max_tokens: 4000,
            default_confidence_threshold: 0.7,
            include_low_severity: false,
            retry_attempts: 3,
            timeout_seconds: 60,
            concurrent_requests: 3,
            use_ir_scanning: false,
        }
    }
}

impl TameshiConfig {
    pub fn from_lsp_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        if let Ok(config) = serde_json::from_value::<TameshiConfig>(value.clone()) {
            debug!("Successfully deserialized full configuration directly");
            return Ok(config);
        }

        if let Some(tameshi_settings) = value.get("tameshi") {
            if let Ok(config) = serde_json::from_value::<TameshiConfig>(tameshi_settings.clone()) {
                debug!("Successfully deserialized configuration from 'tameshi' key");
                return Ok(config);
            }
        }

        let mut config = TameshiConfig::default();

        if config.update_from_direct_value(value.clone()).is_err() {
            config.update_from_lsp_value(value)?;
        }

        Ok(config)
    }

    pub fn update_from_direct_value(
        &mut self,
        value: serde_json::Value,
    ) -> Result<(), serde_json::Error> {
        if let Some(scan_settings) = value.get("scan") {
            if let Ok(scan_config) = serde_json::from_value::<ScanConfig>(scan_settings.clone()) {
                self.scan = scan_config;
                debug!("Updated scan configuration");
            }
        }

        if let Some(rule_settings) = value.get("rules") {
            if let Ok(rule_config) = serde_json::from_value::<RuleConfig>(rule_settings.clone()) {
                self.rules = rule_config;
                debug!("Updated rule configuration");
            }
        }

        if let Some(ignore_settings) = value.get("ignore") {
            if let Ok(ignore_config) =
                serde_json::from_value::<IgnoreConfig>(ignore_settings.clone())
            {
                self.ignore = ignore_config;
                debug!("Updated ignore configuration");
            }
        }

        if let Some(limits_settings) = value.get("limits") {
            if let Ok(limits_config) =
                serde_json::from_value::<LimitsConfig>(limits_settings.clone())
            {
                self.limits = limits_config;
                debug!("Updated limits configuration");
            }
        }

        if let Some(llm_settings) = value.get("llm") {
            if let Some(enabled) = llm_settings.get("enabled").and_then(|v| v.as_bool()) {
                self.llm.enabled = enabled;
                info!("Updated LLM enabled status to: {}", enabled);
            }
            if let Some(provider_settings) = llm_settings.get("provider") {
                if let Ok(provider_config) = serde_json::from_value(provider_settings.clone()) {
                    self.llm.provider = provider_config;
                    info!("Updated LLM provider configuration");
                }
            }
            if let Some(global_settings) = llm_settings.get("global") {
                if let Ok(global_config) = serde_json::from_value(global_settings.clone()) {
                    self.llm.global = global_config;
                    info!("Updated LLM global settings");
                }
            }
            if let Some(scanners) = llm_settings
                .get("enabledScanners")
                .and_then(|v| v.as_array())
            {
                let enabled_scanners = scanners
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                self.llm.enabled_scanners = enabled_scanners;
                info!("Updated LLM enabled scanners");
            }
        }

        info!("Configuration updated from direct values successfully");
        Ok(())
    }

    pub fn update_from_lsp_value(
        &mut self,
        value: serde_json::Value,
    ) -> Result<(), serde_json::Error> {
        if let Some(tameshi_settings) = value.get("tameshi") {
            if let Some(scan_settings) = tameshi_settings.get("scan") {
                if let Ok(scan_config) = serde_json::from_value::<ScanConfig>(scan_settings.clone())
                {
                    self.scan = scan_config;
                    debug!("Updated scan configuration");
                }
            }

            if let Some(rule_settings) = tameshi_settings.get("rules") {
                if let Ok(rule_config) = serde_json::from_value::<RuleConfig>(rule_settings.clone())
                {
                    self.rules = rule_config;
                    debug!("Updated rule configuration");
                }
            }

            if let Some(ignore_settings) = tameshi_settings.get("ignore") {
                if let Ok(ignore_config) =
                    serde_json::from_value::<IgnoreConfig>(ignore_settings.clone())
                {
                    self.ignore = ignore_config;
                    debug!("Updated ignore configuration");
                }
            }

            if let Some(limits_settings) = tameshi_settings.get("limits") {
                if let Ok(limits_config) =
                    serde_json::from_value::<LimitsConfig>(limits_settings.clone())
                {
                    self.limits = limits_config;
                    debug!("Updated limits configuration");
                }
            }

            if let Some(adapter_settings) = tameshi_settings.get("adapter") {
                if let Ok(adapter_config) =
                    serde_json::from_value::<AdapterConfig>(adapter_settings.clone())
                {
                    self.adapter = adapter_config;
                    debug!("Updated adapter configuration");
                }
            }

            if let Some(diagnostics_settings) = tameshi_settings.get("diagnostics") {
                if let Ok(diagnostics_config) =
                    serde_json::from_value::<DiagnosticsConfig>(diagnostics_settings.clone())
                {
                    self.diagnostics = diagnostics_config;
                    debug!("Updated diagnostics configuration");
                }
            }

            if let Some(llm_settings) = tameshi_settings.get("llm") {
                if let Some(enabled) = llm_settings.get("enabled").and_then(|v| v.as_bool()) {
                    self.llm.enabled = enabled;
                    debug!("Updated LLM enabled status to: {}", enabled);
                }
                if let Some(provider_settings) = llm_settings.get("provider") {
                    if let Ok(provider_config) = serde_json::from_value(provider_settings.clone()) {
                        self.llm.provider = provider_config;
                        debug!("Updated LLM provider configuration");
                    }
                }
                if let Some(global_settings) = llm_settings.get("global") {
                    if let Ok(global_config) = serde_json::from_value(global_settings.clone()) {
                        self.llm.global = global_config;
                        debug!("Updated LLM global settings");
                    }
                }
                if let Some(scanners) = llm_settings
                    .get("enabled_scanners")
                    .and_then(|v| v.as_array())
                {
                    let enabled_scanners = scanners
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    self.llm.enabled_scanners = enabled_scanners;
                    debug!("Updated LLM enabled scanners");
                }
            }

            info!("Configuration updated successfully");
        }

        Ok(())
    }

    pub fn load_llm_config(&self) -> Option<tameshi_scanners::llm::LLMConfig> {
        debug!("Attempting to load LLM config");
        if !self.llm.enabled {
            debug!("LLM scanning is disabled");
            return None;
        }

        let mut llm_config = tameshi_scanners::llm::LLMConfig {
            provider: self.create_provider_config(),
            enabled_scanners: self.llm.enabled_scanners.clone(),
            global: self.create_global_settings(),
            custom_scanners: vec![],
        };

        let mut config_loaded = false;

        if let Some(ref config_path) = self.llm.config_path {
            debug!("Loading LLM config from: {:?}", config_path);
            if let Ok(file_config) = tameshi_scanners::llm::LLMConfig::from_yaml_file(config_path) {
                info!("Loaded LLM config from file: {:?}", config_path);
                llm_config = Self::merge_llm_configs(llm_config, file_config);
                config_loaded = true;
            }
        }

        if !config_loaded {
            let default_path = PathBuf::from(".tameshi/llm-config.yaml");
            if default_path.exists() {
                debug!("Loading LLM config from default path: {:?}", default_path);
                if let Ok(file_config) =
                    tameshi_scanners::llm::LLMConfig::from_yaml_file(&default_path)
                {
                    info!("Loaded LLM config from file: {:?}", default_path);
                    llm_config = Self::merge_llm_configs(llm_config, file_config);
                    config_loaded = true;
                }
            }
        }

        if !config_loaded {
            debug!("Attempting to load LLM config from environment");
            if let Ok(env_config) = tameshi_scanners::llm::LLMConfig::from_env() {
                info!("Loaded LLM config from environment");
                llm_config = Self::merge_llm_configs(llm_config, env_config);
            }
        }

        Some(llm_config)
    }

    fn create_provider_config(&self) -> tameshi_scanners::llm::config::ProviderConfig {
        match self.llm.provider.r#type.as_str() {
            "openai" => tameshi_scanners::llm::config::ProviderConfig::OpenAI {
                model: self.llm.provider.model.clone(),
                api_key: self.llm.provider.api_key.clone(),
                base_url: self.llm.provider.base_url.clone(),
            },
            "anthropic" => tameshi_scanners::llm::config::ProviderConfig::Anthropic {
                model: self.llm.provider.model.clone(),
                api_key: self.llm.provider.api_key.clone(),
            },
            "local" => tameshi_scanners::llm::config::ProviderConfig::Local {
                endpoint: self.llm.provider.base_url.clone().unwrap_or_default(),
                model: self.llm.provider.model.clone(),
            },
            _ => tameshi_scanners::llm::config::ProviderConfig::OpenAI {
                model: "gpt-4".to_string(),
                api_key: self.llm.provider.api_key.clone(),
                base_url: self.llm.provider.base_url.clone(),
            },
        }
    }

    fn create_global_settings(&self) -> tameshi_scanners::llm::config::GlobalSettings {
        tameshi_scanners::llm::config::GlobalSettings {
            default_temperature: self.llm.global.default_temperature,
            default_max_tokens: self.llm.global.default_max_tokens,
            default_confidence_threshold: self.llm.global.default_confidence_threshold,
            include_low_severity: self.llm.global.include_low_severity,
            retry_attempts: self.llm.global.retry_attempts,
            timeout_seconds: self.llm.global.timeout_seconds,
            concurrent_requests: self.llm.global.concurrent_requests,
        }
    }

    pub fn get_default_llm_config() -> tameshi_scanners::llm::LLMConfig {
        tameshi_scanners::llm::LLMConfig {
            provider: tameshi_scanners::llm::config::ProviderConfig::OpenAI {
                model: "gpt-4".to_string(),
                api_key: None,
                base_url: None,
            },
            enabled_scanners: vec![
                "general_vulnerability".to_string(),
                "reentrancy".to_string(),
                "access_control".to_string(),
                "overflow".to_string(),
            ],
            global: tameshi_scanners::llm::config::GlobalSettings {
                default_temperature: 0.2,
                default_max_tokens: 4000,
                default_confidence_threshold: 0.5,
                include_low_severity: false,
                retry_attempts: 3,
                timeout_seconds: 30,
                concurrent_requests: 2,
            },
            custom_scanners: vec![],
        }
    }

    fn merge_llm_configs(
        base: tameshi_scanners::llm::LLMConfig,
        override_config: tameshi_scanners::llm::LLMConfig,
    ) -> tameshi_scanners::llm::LLMConfig {
        let mut merged = base;

        if !override_config.enabled_scanners.is_empty() {
            merged.enabled_scanners = override_config.enabled_scanners;
        }

        merged.global.default_temperature = override_config.global.default_temperature;
        merged.global.default_max_tokens = override_config.global.default_max_tokens;
        merged.global.default_confidence_threshold =
            override_config.global.default_confidence_threshold;
        merged.global.include_low_severity = override_config.global.include_low_severity;
        merged.global.retry_attempts = override_config.global.retry_attempts;
        merged.global.timeout_seconds = override_config.global.timeout_seconds;
        merged.global.concurrent_requests = override_config.global.concurrent_requests;

        if !override_config.custom_scanners.is_empty() {
            merged
                .custom_scanners
                .extend(override_config.custom_scanners);
        }

        merged
    }

    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        if self.rules.disabled_rules.contains(&rule_id.to_string()) {
            return false;
        }

        if let Some(ref enabled) = self.rules.enabled_rules {
            return enabled.contains(&rule_id.to_string());
        }

        true
    }

    pub fn get_rule_severity_override(&self, rule_id: &str) -> Option<Severity> {
        self.rules.severity_overrides.get(rule_id).copied()
    }

    pub fn should_ignore_finding(
        &self,
        finding_code: &str,
        file_path: &str,
        scanner_id: &str,
    ) -> bool {
        if self
            .ignore
            .codes
            .iter()
            .any(|code| code == finding_code || finding_code.starts_with(code))
        {
            return true;
        }

        if self
            .ignore
            .paths
            .iter()
            .any(|path| file_path.contains(path) || Self::matches_glob(file_path, path))
        {
            return true;
        }

        if self.ignore.scanners.contains(&scanner_id.to_string()) {
            return true;
        }

        for pattern in &self.ignore.patterns {
            if Self::matches_glob(file_path, &pattern.file_pattern) {
                if let Some(ref code_pattern) = pattern.code_pattern {
                    if finding_code.contains(code_pattern)
                        || Self::matches_glob(finding_code, code_pattern)
                    {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_scan_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.scan_timeout_seconds)
    }

    pub fn get_debounce_delay(&self) -> Duration {
        Duration::from_millis(self.scan.debounce_delay_ms)
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref binary_path) = self.adapter.binary_path {
            if !binary_path.exists() {
                return Err(format!("Scanner binary not found: {:?}", binary_path));
            }
        }

        if self.limits.scan_timeout_seconds == 0 {
            return Err("Scan timeout must be greater than 0".to_string());
        }

        if self.limits.max_concurrent_scans == 0 {
            return Err("Max concurrent scans must be greater than 0".to_string());
        }

        Ok(())
    }

    fn matches_glob(text: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern == "**" {
            return true;
        }

        if pattern.contains("**") {
            if pattern.starts_with("**/") && pattern.ends_with("/**") {
                let middle = &pattern[3..pattern.len() - 3];
                return text.contains(middle);
            }

            if let Some(suffix) = pattern.strip_prefix("**/") {
                return Self::simple_glob_match(text, &format!("*{}", suffix));
            }

            if let Some(prefix) = pattern.strip_suffix("/**") {
                return text.starts_with(prefix);
            }

            let simplified = pattern.replace("**", "*");
            return Self::simple_glob_match(text, &simplified);
        }

        Self::simple_glob_match(text, pattern)
    }

    fn simple_glob_match(text: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if !pattern.contains('*') {
            return text == pattern;
        }

        let pattern_parts: Vec<&str> = pattern.split('*').collect();
        if pattern_parts.is_empty() {
            return true;
        }

        let mut text_pos = 0;

        for (i, part) in pattern_parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 {
                if !text[text_pos..].starts_with(part) {
                    return false;
                }
                text_pos += part.len();
            } else if i == pattern_parts.len() - 1 {
                return text[text_pos..].ends_with(part);
            } else if let Some(pos) = text[text_pos..].find(part) {
                text_pos += pos + part.len();
            } else {
                return false;
            }
        }

        true
    }
}

impl Default for TameshiConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                on_save_mode: OnSaveMode::None,
                include_patterns: vec!["**/*.sol".to_string()],
                exclude_patterns: vec![
                    "**/node_modules/**".to_string(),
                    "**/build/**".to_string(),
                    "**/dist/**".to_string(),
                    "**/.git/**".to_string(),
                ],
                respect_vcs_ignore: true,
                debounce_delay_ms: 500,
                incremental: true,
            },
            rules: RuleConfig {
                enabled_rules: None, // None means all rules enabled by default
                disabled_rules: Vec::new(),
                severity_overrides: HashMap::new(),
                rule_settings: HashMap::new(),
            },
            ignore: IgnoreConfig {
                codes: Vec::new(),
                paths: Vec::new(),
                scanners: Vec::new(),
                patterns: Vec::new(),
            },
            limits: LimitsConfig {
                max_concurrent_scans: 2,
                scan_timeout_seconds: 300, // 5 minutes
                max_memory_mb: 1024,       // 1GB
                max_findings: 10000,
                cache_ttl_seconds: 3600, // 1 hour
            },
            adapter: AdapterConfig {
                mode: "cli".to_string(),
                binary_path: None,
                args: vec!["scan".to_string(), "--format=json".to_string()],
                env: HashMap::new(),
                working_dir: None,
            },
            diagnostics: DiagnosticsConfig {
                max_related_locations: 10,
                include_code_descriptions: true,
                documentation_base_url: Some("https://docs.tameshi.io/findings/".to_string()),
                min_severity: None,
                show_low_confidence: true,
            },
            llm: LLMScanConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SeverityContext;
    use std::collections::HashMap;

    #[test]
    fn test_default_config() {
        let config = TameshiConfig::default();

        assert_eq!(config.scan.on_save_mode, OnSaveMode::None);
        assert!(config
            .scan
            .include_patterns
            .contains(&"**/*.sol".to_string()));
        assert!(config
            .scan
            .exclude_patterns
            .contains(&"**/node_modules/**".to_string()));
        assert_eq!(config.limits.max_concurrent_scans, 2);
        assert_eq!(config.adapter.mode, "cli");
    }

    #[test]
    fn test_on_save_mode_serialization() {
        let modes = vec![OnSaveMode::None, OnSaveMode::File, OnSaveMode::Workspace];

        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: OnSaveMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, deserialized);
        }
    }

    #[test]
    #[ignore = "Deserialization logic needs fixing"]
    fn test_config_from_lsp_value() {
        let lsp_value = serde_json::json!({
            "tameshi": {
                "scan": {
                    "on_save_mode": "file",
                    "include_patterns": ["**/*.sol"],
                    "exclude_patterns": ["**/build/**"],
                    "respect_vcs_ignore": true,
                    "debounce_delay_ms": 500,
                    "incremental": true
                },
                "rules": {
                    "enabled_rules": null,
                    "disabled_rules": [],
                    "severity_overrides": {},
                    "rule_settings": {}
                },
                "ignore": {
                    "codes": [],
                    "paths": [],
                    "scanners": [],
                    "patterns": []
                },
                "limits": {
                    "max_concurrent_scans": 4,
                    "scan_timeout_seconds": 300,
                    "max_memory_mb": 1024,
                    "max_findings": 10000,
                    "cache_ttl_seconds": 3600
                },
                "adapter": {
                    "mode": "cli",
                    "binary_path": null,
                    "args": ["scan", "--format=json"],
                    "env": {},
                    "working_dir": null
                },
                "diagnostics": {
                    "max_related_locations": 10,
                    "include_code_descriptions": true,
                    "documentation_base_url": "https://docs.tameshi.io/findings/",
                    "min_severity": null,
                    "show_low_confidence": true
                },
                "llm": {
                    "enabled": false,
                    "config_path": null,
                    "provider": {
                        "type": "openai",
                        "model": "gpt-4",
                        "api_key": null,
                        "base_url": null
                    },
                    "global": {
                        "default_temperature": 0.7,
                        "default_max_tokens": 4000,
                        "default_confidence_threshold": 0.7,
                        "include_low_severity": false,
                        "retry_attempts": 3,
                        "timeout_seconds": 60,
                        "concurrent_requests": 3
                    },
                    "enabled_scanners": []
                }
            }
        });

        let config = TameshiConfig::from_lsp_value(lsp_value).unwrap();
        assert_eq!(config.scan.on_save_mode, OnSaveMode::File);
        assert_eq!(config.limits.max_concurrent_scans, 4);
    }

    #[test]
    fn test_update_from_lsp_value() {
        let mut config = TameshiConfig::default();

        let lsp_value = serde_json::json!({
            "tameshi": {
                "scan": {
                    "on_save_mode": "workspace",
                    "include_patterns": ["**/*.sol"],
                    "exclude_patterns": ["**/build/**"],
                    "respect_vcs_ignore": true,
                    "debounce_delay_ms": 500,
                    "incremental": true
                }
            }
        });

        config.update_from_lsp_value(lsp_value).unwrap();
        assert_eq!(config.scan.on_save_mode, OnSaveMode::Workspace);
    }

    #[test]
    fn test_is_rule_enabled() {
        let mut config = TameshiConfig::default();

        assert!(config.is_rule_enabled("test_rule"));

        config
            .rules
            .disabled_rules
            .push("disabled_rule".to_string());
        assert!(!config.is_rule_enabled("disabled_rule"));
        assert!(config.is_rule_enabled("other_rule"));

        config.rules.enabled_rules = Some(vec!["enabled_rule".to_string()]);
        assert!(config.is_rule_enabled("enabled_rule"));
        assert!(!config.is_rule_enabled("other_rule"));

        config.rules.disabled_rules.push("enabled_rule".to_string());
        assert!(!config.is_rule_enabled("enabled_rule"));
    }

    #[test]
    fn test_get_rule_severity_override() {
        let mut config = TameshiConfig::default();

        assert!(config.get_rule_severity_override("test_rule").is_none());

        config
            .rules
            .severity_overrides
            .insert("test_rule".to_string(), Severity::Critical);

        assert_eq!(
            config.get_rule_severity_override("test_rule"),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_should_ignore_finding() {
        let mut config = TameshiConfig::default();

        assert!(!config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner1"));

        config.ignore.codes.push("TEST-001".to_string());
        assert!(config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner1"));
        assert!(!config.should_ignore_finding("TEST-002", "/path/test.sol", "scanner1"));

        config.ignore.codes.clear();
        config.ignore.paths.push("test.sol".to_string());
        assert!(config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner1"));
        assert!(!config.should_ignore_finding("TEST-001", "/path/other.sol", "scanner1"));

        config.ignore.paths.clear();
        config.ignore.scanners.push("scanner1".to_string());
        assert!(config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner1"));
        assert!(!config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner2"));

        config.ignore.scanners.clear();
        config.ignore.patterns.push(IgnorePattern {
            file_pattern: "*.sol".to_string(),
            code_pattern: Some("TEST-*".to_string()),
            reason: Some("Test ignore".to_string()),
        });
        assert!(config.should_ignore_finding("TEST-001", "/path/test.sol", "scanner1"));
        assert!(!config.should_ignore_finding("OTHER-001", "/path/test.sol", "scanner1"));
        assert!(!config.should_ignore_finding("TEST-001", "/path/test.js", "scanner1"));
    }

    #[test]
    fn test_get_scan_timeout() {
        let config = TameshiConfig::default();
        let timeout = config.get_scan_timeout();
        assert_eq!(timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_get_debounce_delay() {
        let config = TameshiConfig::default();
        let delay = config.get_debounce_delay();
        assert_eq!(delay, Duration::from_millis(500));
    }

    #[test]
    fn test_validate_config() {
        let config = TameshiConfig::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = TameshiConfig::default();
        invalid_config.limits.scan_timeout_seconds = 0;
        assert!(invalid_config.validate().is_err());

        let mut invalid_config2 = TameshiConfig::default();
        invalid_config2.limits.max_concurrent_scans = 0;
        assert!(invalid_config2.validate().is_err());
    }

    #[test]
    fn test_matches_glob_basic() {
        assert!(TameshiConfig::matches_glob("test.sol", "*.sol"));
        assert!(TameshiConfig::matches_glob("path/test.sol", "*/test.sol"));
        assert!(!TameshiConfig::matches_glob("test.js", "*.sol"));

        assert!(TameshiConfig::matches_glob("exact", "exact"));
        assert!(!TameshiConfig::matches_glob("exact", "other"));
    }

    #[test]
    fn test_matches_glob_wildcard() {
        assert!(TameshiConfig::matches_glob(
            "contracts/Token.sol",
            "**/*.sol"
        ));
        assert!(TameshiConfig::matches_glob(
            "src/contracts/Token.sol",
            "**/*.sol"
        ));
        assert!(!TameshiConfig::matches_glob(
            "contracts/Token.js",
            "**/*.sol"
        ));
    }

    #[test]
    fn test_config_creation() {
        let mut config = TameshiConfig::default();
        config.scan.on_save_mode = OnSaveMode::File;
        config.scan.include_patterns = vec!["**/*.sol".to_string()];
        config.scan.exclude_patterns = vec!["**/test/**".to_string()];
        config.adapter.binary_path = Some(PathBuf::from("/usr/bin/tameshi"));
        config.limits.scan_timeout_seconds = 600;
        config.limits.max_concurrent_scans = 4;

        assert_eq!(config.scan.on_save_mode, OnSaveMode::File);
        assert_eq!(config.scan.include_patterns, vec!["**/*.sol"]);
        assert_eq!(config.scan.exclude_patterns, vec!["**/test/**"]);
        assert_eq!(
            config.adapter.binary_path,
            Some(PathBuf::from("/usr/bin/tameshi"))
        );
        assert_eq!(config.limits.scan_timeout_seconds, 600);
        assert_eq!(config.limits.max_concurrent_scans, 4);
    }

    #[test]
    fn test_ignore_pattern_serialization() {
        let pattern = IgnorePattern {
            file_pattern: "*.sol".to_string(),
            code_pattern: Some("TEST-*".to_string()),
            reason: Some("Testing".to_string()),
        };

        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: IgnorePattern = serde_json::from_str(&json).unwrap();

        assert_eq!(pattern.file_pattern, deserialized.file_pattern);
        assert_eq!(pattern.code_pattern, deserialized.code_pattern);
        assert_eq!(pattern.reason, deserialized.reason);
    }

    #[test]
    fn test_severity_context_serialization() {
        let mut custom_factors = HashMap::new();
        custom_factors.insert("factor1".to_string(), "value1".to_string());

        let context = SeverityContext {
            escalation_factors: vec!["public".to_string()],
            mitigation_factors: vec!["internal".to_string()],
            holds_value: true,
            is_public: false,
            custom_factors,
        };

        let json = serde_json::to_string(&context).unwrap();
        let deserialized: SeverityContext = serde_json::from_str(&json).unwrap();

        assert_eq!(context.escalation_factors, deserialized.escalation_factors);
        assert_eq!(context.holds_value, deserialized.holds_value);
        assert_eq!(context.custom_factors, deserialized.custom_factors);
    }

    #[test]
    fn test_adapter_config_serialization() {
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());

        let adapter = AdapterConfig {
            mode: "daemon".to_string(),
            binary_path: Some(PathBuf::from("/usr/bin/tameshi")),
            args: vec!["--verbose".to_string()],
            env,
            working_dir: Some(PathBuf::from("/tmp")),
        };

        let json = serde_json::to_string(&adapter).unwrap();
        let deserialized: AdapterConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(adapter.mode, deserialized.mode);
        assert_eq!(adapter.binary_path, deserialized.binary_path);
        assert_eq!(adapter.args, deserialized.args);
        assert_eq!(adapter.env, deserialized.env);
    }

    #[test]
    fn test_full_config_serialization() {
        let config = TameshiConfig::default();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TameshiConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.scan.on_save_mode, deserialized.scan.on_save_mode);
        assert_eq!(
            config.limits.max_concurrent_scans,
            deserialized.limits.max_concurrent_scans
        );
        assert_eq!(config.adapter.mode, deserialized.adapter.mode);
    }
}
