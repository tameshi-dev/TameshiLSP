//! Findings store
//!
//! Caches scan results to avoid re-analyzing unchanged files. Full workspace scans can
//! take minutes, so we track findings per file with content hashes as cache keys.
//! When files change or scanner versions update, only affected files need rescanning.
//!
//! Findings can be queried by file, type, or severity to support code actions and
//! cross-file correlation. Users can suppress false positives without losing the
//! finding data for audit purposes.
//!
//! DashMap allows concurrent scans and LSP queries without whole-map locking or
//! writer starvation from frequent reads.

use crate::correlation::{CorrelationConfig, CorrelationService};
use crate::proto::{Confidence, Finding, FindingsScope, ScanResult, Severity};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    content_hash: String,

    config_hash: String,

    timestamp: u64,

    result: ScanResult,
}

#[derive(Debug, Default)]
struct FindingIndex {
    by_file: HashMap<PathBuf, HashSet<Uuid>>,

    by_severity: HashMap<Severity, HashSet<Uuid>>,

    by_scanner: HashMap<String, HashSet<Uuid>>,

    by_type: HashMap<String, HashSet<Uuid>>,
}

#[derive(Debug, Clone, Default)]
pub struct FindingsStoreStats {
    pub total_findings: usize,
    pub total_files: usize,
    pub cache_entries: usize,
    pub memory_usage_bytes: usize,
}

#[derive(Debug)]
pub struct FindingsStore {
    findings: Arc<DashMap<Uuid, Finding>>,

    cache: Arc<DashMap<String, CacheEntry>>,

    index: Arc<RwLock<FindingIndex>>,

    ignored_findings: Arc<RwLock<HashSet<Uuid>>>,

    max_cache_size: usize,

    cache_ttl_seconds: u64,

    correlation_service: CorrelationService,

    auto_correlate: bool,
}

impl FindingsStore {
    pub fn new() -> Self {
        Self {
            findings: Arc::new(DashMap::new()),
            cache: Arc::new(DashMap::new()),
            index: Arc::new(RwLock::new(FindingIndex::default())),
            ignored_findings: Arc::new(RwLock::new(HashSet::new())),
            max_cache_size: 1000,
            cache_ttl_seconds: 3600, // 1 hour
            correlation_service: CorrelationService::with_defaults(),
            auto_correlate: true,
        }
    }

    pub fn with_config(max_cache_size: usize, cache_ttl_seconds: u64) -> Self {
        Self {
            findings: Arc::new(DashMap::new()),
            cache: Arc::new(DashMap::new()),
            index: Arc::new(RwLock::new(FindingIndex::default())),
            ignored_findings: Arc::new(RwLock::new(HashSet::new())),
            max_cache_size,
            cache_ttl_seconds,
            correlation_service: CorrelationService::with_defaults(),
            auto_correlate: true,
        }
    }

    pub fn with_correlation_config(
        max_cache_size: usize,
        cache_ttl_seconds: u64,
        correlation_config: CorrelationConfig,
    ) -> Self {
        Self {
            findings: Arc::new(DashMap::new()),
            cache: Arc::new(DashMap::new()),
            index: Arc::new(RwLock::new(FindingIndex::default())),
            ignored_findings: Arc::new(RwLock::new(HashSet::new())),
            max_cache_size,
            cache_ttl_seconds,
            correlation_service: CorrelationService::new(correlation_config),
            auto_correlate: true,
        }
    }

    pub fn set_auto_correlate(&mut self, enabled: bool) {
        self.auto_correlate = enabled;
    }

    pub fn store_scan_result(&self, scan_result: ScanResult) {
        info!(
            "Storing scan result with {} findings",
            scan_result.findings.len()
        );

        let scanner_ids: HashSet<String> = scan_result
            .findings
            .iter()
            .map(|f| f.scanner_id.clone())
            .collect();

        let scanned_files: HashSet<PathBuf> = scan_result
            .metadata
            .scanned_files
            .iter()
            .map(PathBuf::from)
            .collect();

        if scanner_ids.is_empty() && !scanned_files.is_empty() {
            debug!("Scan found 0 findings, clearing ALL findings for scanned files");
            self.clear_findings_for_files(&scanned_files);
        } else {
            self.clear_findings_for_files_by_scanners(&scanned_files, &scanner_ids);
        }

        for finding in &scan_result.findings {
            self.store_finding(finding.clone());
        }

        info!(
            "Stored {} findings from scan. Checking if correlation should run (auto_correlate: {})",
            scan_result.findings.len(),
            self.auto_correlate
        );

        if self.auto_correlate {
            let mut findings_to_correlate: Vec<Finding> = self
                .findings
                .iter()
                .map(|entry| entry.value().clone())
                .collect();

            info!(
                "Auto-correlate is enabled. Store has {} total findings",
                findings_to_correlate.len()
            );

            if findings_to_correlate.len() > 1 {
                info!(
                    "Running correlation on {} findings from entire store",
                    findings_to_correlate.len()
                );
                match self
                    .correlation_service
                    .correlate_findings(&mut findings_to_correlate)
                {
                    Ok(stats) => {
                        info!(
                            "Correlation complete: {} duplicates, {} augmentations, {} conflicts",
                            stats.duplicates, stats.augmentations, stats.conflicts
                        );

                        for finding in findings_to_correlate {
                            if let Some(metadata) = &finding.metadata {
                                if !metadata.correlations.is_empty() {
                                    self.findings.insert(finding.id, finding);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Correlation failed: {}", e);
                    }
                }
            }
        }

        let cache_key = self.generate_cache_key(&scanned_files);
        let cache_entry = CacheEntry {
            content_hash: "unknown".to_string(), // Cache currently keyed by file paths only
            config_hash: "unknown".to_string(),  // Cache currently keyed by file paths only
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            result: scan_result,
        };

        self.cache.insert(cache_key, cache_entry);
        self.cleanup_old_cache_entries();

        debug!("Stored scan result in cache");
    }

    pub fn store_finding(&self, finding: Finding) {
        let finding_id = finding.id;

        self.add_to_index(&finding);

        self.findings.insert(finding_id, finding);

        debug!("Stored finding: {}", finding_id);
    }

    pub fn get_finding(&self, id: &Uuid) -> Option<Finding> {
        self.findings.get(id).map(|entry| entry.value().clone())
    }

    pub fn get_findings(
        &self,
        scope: &FindingsScope,
        min_severity: Option<Severity>,
        min_confidence: Option<Confidence>,
    ) -> Vec<Finding> {
        let index = self.index.read().unwrap();
        let ignored = self.ignored_findings.read().unwrap();

        let candidate_ids: Vec<Uuid> = match scope {
            FindingsScope::Workspace => {
                self.findings.iter().map(|entry| *entry.key()).collect()
            }
            FindingsScope::File { path } => {
                let path_buf = PathBuf::from(path);
                index
                    .by_file
                    .get(&path_buf)
                    .map(|ids| ids.iter().cloned().collect())
                    .unwrap_or_default()
            }
        };

        let mut results = Vec::new();
        for id in candidate_ids {
            if ignored.contains(&id) {
                continue;
            }

            if let Some(finding) = self.findings.get(&id) {
                let finding = finding.value();

                if let Some(min_sev) = min_severity {
                    if finding.severity < min_sev {
                        continue;
                    }
                }

                if let Some(min_conf) = min_confidence {
                    if finding.confidence < min_conf {
                        continue;
                    }
                }

                results.push(finding.clone());
            }
        }

        results.sort_by_key(|f| std::cmp::Reverse(f.priority_score()));

        debug!("Retrieved {} findings for scope {:?}", results.len(), scope);
        results
    }

    pub fn get_findings_for_files(&self, file_paths: &[PathBuf]) -> Vec<Finding> {
        let index = self.index.read().unwrap();
        let ignored = self.ignored_findings.read().unwrap();
        let mut results = Vec::new();

        for file_path in file_paths {
            if let Some(finding_ids) = index.by_file.get(file_path) {
                for id in finding_ids {
                    if ignored.contains(id) {
                        continue;
                    }

                    if let Some(finding) = self.findings.get(id) {
                        results.push(finding.value().clone());
                    }
                }
            }
        }

        results.sort_by_key(|f| std::cmp::Reverse(f.priority_score()));
        results
    }

    pub fn clear_findings_for_files(&self, file_paths: &HashSet<PathBuf>) {
        let mut index = self.index.write().unwrap();
        let mut findings_to_remove = HashSet::new();

        for file_path in file_paths {
            if let Some(finding_ids) = index.by_file.get(file_path) {
                findings_to_remove.extend(finding_ids.iter().cloned());
            }
        }

        for id in &findings_to_remove {
            if let Some((_, finding)) = self.findings.remove(id) {
                self.remove_from_index_locked(&mut index, &finding);
            }
        }

        debug!(
            "Cleared {} findings for {} files",
            findings_to_remove.len(),
            file_paths.len()
        );
    }

    pub fn clear_findings_for_files_by_scanners(
        &self,
        file_paths: &HashSet<PathBuf>,
        scanner_ids: &HashSet<String>,
    ) {
        let mut index = self.index.write().unwrap();
        let mut findings_to_remove = HashSet::new();

        for file_path in file_paths {
            if let Some(finding_ids) = index.by_file.get(file_path) {
                for id in finding_ids {
                    if let Some(finding) = self.findings.get(id) {
                        if scanner_ids.contains(&finding.scanner_id) {
                            findings_to_remove.insert(*id);
                        }
                    }
                }
            }
        }

        for id in &findings_to_remove {
            if let Some((_, finding)) = self.findings.remove(id) {
                self.remove_from_index_locked(&mut index, &finding);
            }
        }

        debug!(
            "Cleared {} findings for {} files from {} scanners",
            findings_to_remove.len(),
            file_paths.len(),
            scanner_ids.len()
        );
    }

    pub fn clear(&self) {
        self.findings.clear();
        self.cache.clear();
        *self.index.write().unwrap() = FindingIndex::default();
        self.ignored_findings.write().unwrap().clear();

        info!("Cleared all findings and cache");
    }

    pub fn ignore_finding(&self, finding_id: Uuid) {
        self.ignored_findings.write().unwrap().insert(finding_id);
        debug!("Ignored finding: {}", finding_id);
    }

    pub fn unignore_finding(&self, finding_id: Uuid) {
        self.ignored_findings.write().unwrap().remove(&finding_id);
        debug!("Unignored finding: {}", finding_id);
    }

    pub fn is_finding_ignored(&self, finding_id: &Uuid) -> bool {
        self.ignored_findings.read().unwrap().contains(finding_id)
    }

    pub fn get_stats(&self) -> FindingsStoreStats {
        let index = self.index.read().unwrap();

        FindingsStoreStats {
            total_findings: self.findings.len(),
            total_files: index.by_file.len(),
            cache_entries: self.cache.len(),
            memory_usage_bytes: self.estimate_memory_usage(),
        }
    }

    pub fn deduplicate(&self) {
        let mut seen_keys = HashSet::new();
        let mut to_remove = Vec::new();

        for entry in self.findings.iter() {
            let finding = entry.value();
            let dedup_key = finding.dedup_key();

            if seen_keys.contains(&dedup_key) {
                to_remove.push(*entry.key());
            } else {
                seen_keys.insert(dedup_key);
            }
        }

        let removed_count = to_remove.len();
        for id in to_remove {
            if let Some((_, finding)) = self.findings.remove(&id) {
                self.remove_from_index(&finding);
            }
        }

        info!(
            "Deduplicated findings, removed {} duplicates",
            removed_count
        );
    }

    fn add_to_index(&self, finding: &Finding) {
        let mut index = self.index.write().unwrap();

        for location in &finding.locations {
            let file_path = PathBuf::from(&location.file);
            index
                .by_file
                .entry(file_path)
                .or_default()
                .insert(finding.id);
        }

        index
            .by_severity
            .entry(finding.severity)
            .or_default()
            .insert(finding.id);

        index
            .by_scanner
            .entry(finding.scanner_id.clone())
            .or_default()
            .insert(finding.id);

        index
            .by_type
            .entry(finding.finding_type.clone())
            .or_default()
            .insert(finding.id);
    }

    fn remove_from_index(&self, finding: &Finding) {
        let mut index = self.index.write().unwrap();
        self.remove_from_index_locked(&mut index, finding);
    }

    fn remove_from_index_locked(&self, index: &mut FindingIndex, finding: &Finding) {
        for location in &finding.locations {
            let file_path = PathBuf::from(&location.file);
            if let Some(ids) = index.by_file.get_mut(&file_path) {
                ids.remove(&finding.id);
                if ids.is_empty() {
                    index.by_file.remove(&file_path);
                }
            }
        }

        if let Some(ids) = index.by_severity.get_mut(&finding.severity) {
            ids.remove(&finding.id);
            if ids.is_empty() {
                index.by_severity.remove(&finding.severity);
            }
        }

        if let Some(ids) = index.by_scanner.get_mut(&finding.scanner_id) {
            ids.remove(&finding.id);
            if ids.is_empty() {
                index.by_scanner.remove(&finding.scanner_id);
            }
        }

        if let Some(ids) = index.by_type.get_mut(&finding.finding_type) {
            ids.remove(&finding.id);
            if ids.is_empty() {
                index.by_type.remove(&finding.finding_type);
            }
        }
    }

    fn generate_cache_key(&self, files: &HashSet<PathBuf>) -> String {
        let mut sorted_files: Vec<_> = files.iter().collect();
        sorted_files.sort();

        let mut hasher = Sha256::new();
        for file in sorted_files {
            hasher.update(file.to_string_lossy().as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    fn cleanup_old_cache_entries(&self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.cache
            .retain(|_, entry| current_time - entry.timestamp < self.cache_ttl_seconds);

        if self.cache.len() > self.max_cache_size {
            let excess = self.cache.len() - self.max_cache_size;
            let mut to_remove = Vec::new();

            for entry in self.cache.iter().take(excess) {
                to_remove.push(entry.key().clone());
            }

            for key in to_remove {
                self.cache.remove(&key);
            }
        }
    }

    fn estimate_memory_usage(&self) -> usize {
        let findings_size = self.findings.len() * 1024; // ~1KB per finding
        let cache_size = self.cache.len() * 2048; // ~2KB per cache entry
        findings_size + cache_size
    }
}

impl Default for FindingsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FindingsStore {
    fn clone(&self) -> Self {
        Self {
            findings: Arc::clone(&self.findings),
            cache: Arc::clone(&self.cache),
            index: Arc::clone(&self.index),
            ignored_findings: Arc::clone(&self.ignored_findings),
            max_cache_size: self.max_cache_size,
            cache_ttl_seconds: self.cache_ttl_seconds,
            correlation_service: CorrelationService::with_defaults(), // Create new service for clone
            auto_correlate: self.auto_correlate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        Confidence, Finding, FindingsScope, Location, ScanMetadata, ScanResult, Severity,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_findings_store_new() {
        let store = FindingsStore::new();
        assert_eq!(store.findings.len(), 0);

        let stats = store.get_stats();
        assert_eq!(stats.total_findings, 0);
        assert_eq!(stats.total_files, 0);
    }

    #[test]
    fn test_store_and_get_finding() {
        let store = FindingsStore::new();
        let finding = create_test_finding();
        let finding_id = finding.id;

        store.store_finding(finding.clone());

        let retrieved = store.get_finding(&finding_id);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, finding_id);
        assert_eq!(retrieved.scanner_id, finding.scanner_id);
    }

    #[test]
    fn test_store_scan_result() {
        let store = FindingsStore::new();
        let scan_result = create_test_scan_result();
        let finding_count = scan_result.findings.len();

        store.store_scan_result(scan_result);

        let stats = store.get_stats();
        assert_eq!(stats.total_findings, finding_count);
        assert_eq!(stats.cache_entries, 1);
    }

    #[test]
    fn test_get_findings_workspace_scope() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding();
        let finding2 = create_finding_with_severity(Severity::Low);

        store.store_finding(finding1);
        store.store_finding(finding2);

        let findings = store.get_findings(&FindingsScope::Workspace, None, None);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_get_findings_file_scope() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding(); // file: test.sol
        let finding2 = create_finding_with_file("other.sol");

        store.store_finding(finding1);
        store.store_finding(finding2);

        let findings = store.get_findings(
            &FindingsScope::File {
                path: "test.sol".to_string(),
            },
            None,
            None,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].locations[0].file, "test.sol");
    }

    #[test]
    fn test_get_findings_with_severity_filter() {
        let store = FindingsStore::new();
        let critical_finding = create_finding_with_severity(Severity::Critical);
        let low_finding = create_finding_with_severity(Severity::Low);

        store.store_finding(critical_finding);
        store.store_finding(low_finding);

        let findings = store.get_findings(&FindingsScope::Workspace, Some(Severity::Medium), None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_get_findings_with_confidence_filter() {
        let store = FindingsStore::new();
        let high_confidence = create_finding_with_confidence(Confidence::High);
        let low_confidence = create_finding_with_confidence(Confidence::Low);

        store.store_finding(high_confidence);
        store.store_finding(low_confidence);

        let findings =
            store.get_findings(&FindingsScope::Workspace, None, Some(Confidence::Medium));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn test_get_findings_for_files() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding(); // test.sol
        let finding2 = create_finding_with_file("other.sol");
        let finding3 = create_finding_with_file("third.sol");

        store.store_finding(finding1);
        store.store_finding(finding2);
        store.store_finding(finding3);

        let file_paths = vec![PathBuf::from("test.sol"), PathBuf::from("other.sol")];
        let findings = store.get_findings_for_files(&file_paths);

        assert_eq!(findings.len(), 2);
        let files: HashSet<String> = findings
            .iter()
            .map(|f| f.locations[0].file.clone())
            .collect();
        assert!(files.contains("test.sol"));
        assert!(files.contains("other.sol"));
        assert!(!files.contains("third.sol"));
    }

    #[test]
    fn test_clear_findings_for_files() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding(); // test.sol
        let finding2 = create_finding_with_file("other.sol");

        store.store_finding(finding1);
        store.store_finding(finding2);

        let files_to_clear = [PathBuf::from("test.sol")].iter().cloned().collect();
        store.clear_findings_for_files(&files_to_clear);

        let remaining_findings = store.get_findings(&FindingsScope::Workspace, None, None);
        assert_eq!(remaining_findings.len(), 1);
        assert_eq!(remaining_findings[0].locations[0].file, "other.sol");
    }

    #[test]
    fn test_ignore_finding() {
        let store = FindingsStore::new();
        let finding = create_test_finding();
        let finding_id = finding.id;

        store.store_finding(finding);
        store.ignore_finding(finding_id);

        assert!(store.is_finding_ignored(&finding_id));

        let findings = store.get_findings(&FindingsScope::Workspace, None, None);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_unignore_finding() {
        let store = FindingsStore::new();
        let finding = create_test_finding();
        let finding_id = finding.id;

        store.store_finding(finding);
        store.ignore_finding(finding_id);
        store.unignore_finding(finding_id);

        assert!(!store.is_finding_ignored(&finding_id));

        let findings = store.get_findings(&FindingsScope::Workspace, None, None);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_clear_all() {
        let store = FindingsStore::new();
        let finding = create_test_finding();

        store.store_finding(finding.clone());
        store.ignore_finding(finding.id);

        assert_eq!(store.findings.len(), 1);
        assert!(store.is_finding_ignored(&finding.id));

        store.clear();

        assert_eq!(store.findings.len(), 0);
        assert!(!store.is_finding_ignored(&finding.id));
        let stats = store.get_stats();
        assert_eq!(stats.total_findings, 0);
        assert_eq!(stats.cache_entries, 0);
    }

    #[test]
    fn test_deduplicate() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding();
        let mut finding2 = create_test_finding();
        finding2.id = Uuid::new_v4(); // Different ID but same content

        store.store_finding(finding1);
        store.store_finding(finding2);

        assert_eq!(store.findings.len(), 2);

        store.deduplicate();

        assert_eq!(store.findings.len(), 1);
    }

    #[test]
    fn test_generate_cache_key() {
        let store = FindingsStore::new();
        let files1: HashSet<PathBuf> = [PathBuf::from("a.sol"), PathBuf::from("b.sol")]
            .iter()
            .cloned()
            .collect();
        let files2: HashSet<PathBuf> = [PathBuf::from("b.sol"), PathBuf::from("a.sol")]
            .iter()
            .cloned()
            .collect();
        let files3: HashSet<PathBuf> = [PathBuf::from("c.sol")].iter().cloned().collect();

        let key1 = store.generate_cache_key(&files1);
        let key2 = store.generate_cache_key(&files2);
        let key3 = store.generate_cache_key(&files3);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_findings_priority_sorting() {
        let store = FindingsStore::new();

        let critical_high =
            create_finding_with_severity_confidence(Severity::Critical, Confidence::High);
        let medium_low = create_finding_with_severity_confidence(Severity::Medium, Confidence::Low);
        let high_medium =
            create_finding_with_severity_confidence(Severity::High, Confidence::Medium);

        store.store_finding(medium_low.clone());
        store.store_finding(critical_high.clone());
        store.store_finding(high_medium.clone());

        let findings = store.get_findings(&FindingsScope::Workspace, None, None);

        assert_eq!(findings[0].id, critical_high.id); // 1000 * 10 = 10000
        assert_eq!(findings[1].id, high_medium.id); // 100 * 5 = 500
        assert_eq!(findings[2].id, medium_low.id); // 10 * 1 = 10
    }

    #[test]
    fn test_findings_store_stats() {
        let store = FindingsStore::new();
        let finding1 = create_test_finding();
        let finding2 = create_finding_with_file("other.sol");

        store.store_finding(finding1);
        store.store_finding(finding2);

        let stats = store.get_stats();
        assert_eq!(stats.total_findings, 2);
        assert_eq!(stats.total_files, 2); // Two different files
        assert!(stats.memory_usage_bytes > 0);
    }

    #[test]
    fn test_with_config() {
        let store = FindingsStore::with_config(500, 1800);
        assert_eq!(store.max_cache_size, 500);
        assert_eq!(store.cache_ttl_seconds, 1800);
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

    fn create_finding_with_file(file: &str) -> Finding {
        let mut finding = create_test_finding();
        finding.locations[0].file = file.to_string();
        finding
    }

    fn create_test_scan_result() -> ScanResult {
        ScanResult {
            version: crate::proto::PROTOCOL_VERSION.to_string(),
            findings: vec![create_test_finding(), create_finding_with_file("other.sol")],
            metadata: ScanMetadata {
                start_time: "2023-01-01T00:00:00Z".to_string(),
                duration_ms: 1000,
                scanned_files: vec!["test.sol".to_string(), "other.sol".to_string()],
                skipped_files: HashMap::new(),
                scanner_config: None,
            },
            errors: vec![],
        }
    }
}
