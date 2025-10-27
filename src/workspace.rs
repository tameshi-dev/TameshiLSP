//! Workspace management
//!
//! Maintains in-memory state for open documents because editors send content changes
//! before writing to disk. Without tracking this, we'd scan stale file contents and
//! report diagnostics for code the user already changed. We also need to know which
//! files match include/exclude patterns to avoid scanning node_modules and build artifacts.
//!
//! DashMap enables concurrent scans to read the file list while edits update individual
//! documents without blocking. Version numbers correlate scan results with the exact
//! document state that produced them.

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use lsp_types::{InitializeParams, TextDocumentItem, Url, WorkspaceFolder};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct DocumentInfo {
    pub uri: Url,
    pub language_id: String,
    pub version: i32,
    pub content: String,
    pub is_dirty: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceManager {
    workspace_folders: Arc<RwLock<Vec<WorkspaceFolder>>>,

    open_documents: Arc<DashMap<Url, DocumentInfo>>,

    dirty_files: Arc<RwLock<HashSet<PathBuf>>>,

    workspace_root: Option<PathBuf>,

    include_patterns: Vec<String>,

    exclude_patterns: Vec<String>,
}

impl WorkspaceManager {
    pub fn new(
        init_params: InitializeParams,
        include_patterns: Vec<String>,
        exclude_patterns: Vec<String>,
    ) -> Result<Self> {
        let workspace_folders = init_params.workspace_folders.clone().unwrap_or_default();
        let workspace_root = Self::determine_workspace_root(&init_params)?;

        info!("Initialized workspace with root: {:?}", workspace_root);
        if !workspace_folders.is_empty() {
            info!(
                "Workspace folders: {:?}",
                workspace_folders.iter().map(|f| &f.uri).collect::<Vec<_>>()
            );
        }

        info!(
            "Using include patterns: {:?}, exclude patterns: {:?}",
            include_patterns, exclude_patterns
        );

        Ok(Self {
            workspace_folders: Arc::new(RwLock::new(workspace_folders)),
            open_documents: Arc::new(DashMap::new()),
            dirty_files: Arc::new(RwLock::new(HashSet::new())),
            workspace_root,
            include_patterns,
            exclude_patterns,
        })
    }

    pub fn get_workspace_root(&self) -> Option<PathBuf> {
        self.workspace_root.clone()
    }

    pub fn get_workspace_folders(&self) -> Vec<WorkspaceFolder> {
        self.workspace_folders.read().unwrap().clone()
    }

    pub fn add_document(&self, document: TextDocumentItem) -> Result<()> {
        let doc_info = DocumentInfo {
            uri: document.uri.clone(),
            language_id: document.language_id,
            version: document.version,
            content: document.text,
            is_dirty: false,
        };

        debug!("Adding document: {}", document.uri);
        self.open_documents.insert(document.uri, doc_info);
        Ok(())
    }

    pub fn update_document(&self, uri: &Url, version: i32, content: String) -> Result<()> {
        if let Some(mut doc) = self.open_documents.get_mut(uri) {
            doc.version = version;
            doc.content = content;
            doc.is_dirty = true;

            if let Ok(path) = uri.to_file_path() {
                self.dirty_files.write().unwrap().insert(path);
            }

            debug!("Updated document: {} (version {})", uri, version);
            Ok(())
        } else {
            Err(anyhow!("Document not found: {}", uri))
        }
    }

    pub fn remove_document(&self, uri: &Url) -> Result<()> {
        debug!("Removing document: {}", uri);
        self.open_documents.remove(uri);
        Ok(())
    }

    pub fn get_document(&self, uri: &Url) -> Option<DocumentInfo> {
        self.open_documents.get(uri).map(|doc| doc.clone())
    }

    pub fn get_open_documents(&self) -> Vec<DocumentInfo> {
        self.open_documents
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn mark_document_saved(&self, uri: &Url) -> Result<()> {
        if let Some(mut doc) = self.open_documents.get_mut(uri) {
            doc.is_dirty = false;
            debug!("Marked document as saved: {}", uri);
        }

        if let Ok(path) = uri.to_file_path() {
            self.dirty_files.write().unwrap().remove(&path);
        }

        Ok(())
    }

    pub fn get_dirty_files(&self) -> HashSet<PathBuf> {
        self.dirty_files.read().unwrap().clone()
    }

    pub fn clear_dirty_files(&self) {
        self.dirty_files.write().unwrap().clear();
    }

    pub fn mark_file_dirty(&self, path: PathBuf) {
        self.dirty_files.write().unwrap().insert(path);
    }

    pub fn find_scannable_files(&self) -> Result<Vec<PathBuf>> {
        let workspace_root = self
            .workspace_root
            .as_ref()
            .ok_or_else(|| anyhow!("No workspace root available"))?;

        let mut files = Vec::new();

        for entry in WalkDir::new(workspace_root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if !self.matches_include_patterns(path) {
                continue;
            }

            if self.matches_exclude_patterns(path) {
                continue;
            }

            files.push(path.to_path_buf());
        }

        debug!("Found {} scannable files in workspace", files.len());
        Ok(files)
    }

    pub fn update_workspace_folders(&self, folders: Vec<WorkspaceFolder>) -> Result<()> {
        info!(
            "Updating workspace folders: {:?}",
            folders.iter().map(|f| &f.uri).collect::<Vec<_>>()
        );
        *self.workspace_folders.write().unwrap() = folders;
        Ok(())
    }

    pub fn set_include_patterns(&mut self, patterns: Vec<String>) {
        debug!("Setting include patterns: {:?}", patterns);
        self.include_patterns = patterns;
    }

    pub fn set_exclude_patterns(&mut self, patterns: Vec<String>) {
        debug!("Setting exclude patterns: {:?}", patterns);
        self.exclude_patterns = patterns;
    }

    pub fn get_include_patterns(&self) -> &[String] {
        &self.include_patterns
    }

    pub fn get_exclude_patterns(&self) -> &[String] {
        &self.exclude_patterns
    }

    pub fn should_exclude_file(&self, uri: &Url) -> bool {
        if let Ok(path) = uri.to_file_path() {
            return self.matches_exclude_patterns(&path);
        }
        false
    }

    pub fn is_document_open(&self, uri: &Url) -> bool {
        self.open_documents.contains_key(uri)
    }

    pub fn get_stats(&self) -> WorkspaceStats {
        let open_docs = self.open_documents.len();
        let dirty_files = self.dirty_files.read().unwrap().len();
        let workspace_folders = self.workspace_folders.read().unwrap().len();

        WorkspaceStats {
            open_documents: open_docs,
            dirty_files,
            workspace_folders,
        }
    }

    fn determine_workspace_root(init_params: &InitializeParams) -> Result<Option<PathBuf>> {
        if let Some(folders) = &init_params.workspace_folders {
            if let Some(first_folder) = folders.first() {
                if let Ok(path) = first_folder.uri.to_file_path() {
                    return Ok(Some(path));
                }
            }
        }

        #[allow(deprecated)]
        if let Some(root_uri) = &init_params.root_uri {
            if let Ok(path) = root_uri.to_file_path() {
                return Ok(Some(path));
            }
        }

        #[allow(deprecated)]
        if let Some(root_path) = &init_params.root_path {
            return Ok(Some(PathBuf::from(root_path)));
        }

        warn!("No workspace root found in initialization parameters");
        Ok(None)
    }

    fn matches_include_patterns(&self, path: &Path) -> bool {
        if self.include_patterns.is_empty() {
            return true; // No patterns means include all
        }

        let path_str = path.to_string_lossy();
        for pattern in &self.include_patterns {
            if Self::matches_glob_pattern(&path_str, pattern) {
                return true;
            }
        }
        false
    }

    fn matches_exclude_patterns(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.exclude_patterns {
            if Self::matches_glob_pattern(&path_str, pattern) {
                return true;
            }
        }
        false
    }

    fn matches_glob_pattern(path: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern == "**" {
            return true;
        }

        if pattern.contains("**") {
            if pattern.starts_with("**/") && pattern.ends_with("/**") {
                let middle = &pattern[3..pattern.len() - 3];
                let search_pattern = format!("/{}/", middle);
                return path.contains(&search_pattern) || path.ends_with(&format!("/{}", middle));
            }

            if let Some(suffix) = pattern.strip_prefix("**/") {
                return Self::simple_glob_match(path, &format!("*{}", suffix));
            }

            if let Some(prefix) = pattern.strip_suffix("/**") {
                return path.starts_with(prefix);
            }

            let simplified = pattern.replace("**", "*");
            return Self::simple_glob_match(path, &simplified);
        }

        Self::simple_glob_match(path, pattern)
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

#[derive(Debug, Clone)]
pub struct WorkspaceStats {
    pub open_documents: usize,
    pub dirty_files: usize,
    pub workspace_folders: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{InitializeParams, TextDocumentItem, Url, WorkspaceFolder};
    use std::path::PathBuf;

    fn default_include_patterns() -> Vec<String> {
        vec!["**/*.sol".to_string()]
    }

    fn default_exclude_patterns() -> Vec<String> {
        vec![
            "**/node_modules/**".to_string(),
            "**/build/**".to_string(),
            "**/dist/**".to_string(),
            "**/.git/**".to_string(),
        ]
    }

    fn create_test_init_params() -> InitializeParams {
        #[cfg(windows)]
        let workspace_uri = Url::parse("file:///C:/test/workspace").unwrap();
        #[cfg(not(windows))]
        let workspace_uri = Url::parse("file:///test/workspace").unwrap();

        InitializeParams {
            workspace_folders: Some(vec![WorkspaceFolder {
                uri: workspace_uri,
                name: "test".to_string(),
            }]),
            ..Default::default()
        }
    }

    fn create_test_document() -> TextDocumentItem {
        #[cfg(windows)]
        let doc_uri = Url::parse("file:///C:/test/workspace/test.sol").unwrap();
        #[cfg(not(windows))]
        let doc_uri = Url::parse("file:///test/workspace/test.sol").unwrap();

        TextDocumentItem {
            uri: doc_uri,
            language_id: "solidity".to_string(),
            version: 1,
            text: "contract Test {}".to_string(),
        }
    }

    #[test]
    fn test_workspace_manager_new() {
        let init_params = create_test_init_params();
        let manager = WorkspaceManager::new(
            init_params,
            default_include_patterns(),
            default_exclude_patterns(),
        )
        .unwrap();

        assert!(manager.get_workspace_root().is_some());
        assert_eq!(manager.get_workspace_folders().len(), 1);
        assert_eq!(manager.get_open_documents().len(), 0);
    }

    #[test]
    fn test_workspace_manager_new_no_workspace() {
        let init_params = InitializeParams::default();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        assert!(manager.get_workspace_root().is_none());
        assert_eq!(manager.get_workspace_folders().len(), 0);
    }

    #[test]
    fn test_add_document() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let document = create_test_document();
        let uri = document.uri.clone();

        manager.add_document(document).unwrap();

        assert!(manager.is_document_open(&uri));
        assert_eq!(manager.get_open_documents().len(), 1);

        let doc_info = manager.get_document(&uri).unwrap();
        assert_eq!(doc_info.language_id, "solidity");
        assert_eq!(doc_info.version, 1);
        assert!(!doc_info.is_dirty);
    }

    #[test]
    fn test_update_document() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let document = create_test_document();
        let uri = document.uri.clone();

        manager.add_document(document).unwrap();

        let new_content = "contract Updated {}".to_string();
        manager
            .update_document(&uri, 2, new_content.clone())
            .unwrap();

        let doc_info = manager.get_document(&uri).unwrap();
        assert_eq!(doc_info.version, 2);
        assert_eq!(doc_info.content, new_content);
        assert!(doc_info.is_dirty);
    }

    #[test]
    fn test_update_nonexistent_document() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let uri = Url::parse("file:///test/nonexistent.sol").unwrap();

        let result = manager.update_document(&uri, 1, "content".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_document() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let document = create_test_document();
        let uri = document.uri.clone();

        manager.add_document(document).unwrap();
        assert!(manager.is_document_open(&uri));

        manager.remove_document(&uri).unwrap();
        assert!(!manager.is_document_open(&uri));
        assert_eq!(manager.get_open_documents().len(), 0);
    }

    #[test]
    fn test_mark_document_saved() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let document = create_test_document();
        let uri = document.uri.clone();

        manager.add_document(document).unwrap();
        manager
            .update_document(&uri, 2, "updated content".to_string())
            .unwrap();

        assert!(manager.get_document(&uri).unwrap().is_dirty);

        manager.mark_document_saved(&uri).unwrap();

        assert!(!manager.get_document(&uri).unwrap().is_dirty);
    }

    #[test]
    fn test_dirty_files_tracking() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();
        let path = PathBuf::from("/test/file.sol");

        assert_eq!(manager.get_dirty_files().len(), 0);

        manager.mark_file_dirty(path.clone());
        assert_eq!(manager.get_dirty_files().len(), 1);
        assert!(manager.get_dirty_files().contains(&path));

        manager.clear_dirty_files();
        assert_eq!(manager.get_dirty_files().len(), 0);
    }

    #[test]
    fn test_update_workspace_folders() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        let new_folders = vec![
            WorkspaceFolder {
                uri: Url::parse("file:///new/workspace1").unwrap(),
                name: "workspace1".to_string(),
            },
            WorkspaceFolder {
                uri: Url::parse("file:///new/workspace2").unwrap(),
                name: "workspace2".to_string(),
            },
        ];

        manager
            .update_workspace_folders(new_folders.clone())
            .unwrap();

        let folders = manager.get_workspace_folders();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].name, "workspace1");
        assert_eq!(folders[1].name, "workspace2");
    }

    #[test]
    fn test_include_exclude_patterns() {
        let init_params = create_test_init_params();
        let mut manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        assert_eq!(manager.get_include_patterns(), &["**/*.sol"]);
        assert!(manager
            .get_exclude_patterns()
            .contains(&"**/node_modules/**".to_string()));

        let new_include = vec!["**/*.rs".to_string(), "**/*.sol".to_string()];
        let new_exclude = vec!["**/target/**".to_string()];

        manager.set_include_patterns(new_include.clone());
        manager.set_exclude_patterns(new_exclude.clone());

        assert_eq!(manager.get_include_patterns(), &new_include);
        assert_eq!(manager.get_exclude_patterns(), &new_exclude);
    }

    #[test]
    fn test_workspace_stats() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.open_documents, 0);
        assert_eq!(stats.dirty_files, 0);
        assert_eq!(stats.workspace_folders, 1);

        manager.add_document(create_test_document()).unwrap();
        manager.mark_file_dirty(PathBuf::from("/test/dirty.sol"));

        let stats = manager.get_stats();
        assert_eq!(stats.open_documents, 1);
        assert_eq!(stats.dirty_files, 1);
        assert_eq!(stats.workspace_folders, 1);
    }

    #[test]
    fn test_custom_exclude_patterns_respected() {
        let init_params = create_test_init_params();

        let custom_exclude_patterns = vec![
            "**/lib/**".to_string(),
            "**/out/**".to_string(),
            "**/node_modules/**".to_string(),
        ];

        let manager = WorkspaceManager::new(
            init_params,
            default_include_patterns(),
            custom_exclude_patterns.clone(),
        )
        .unwrap();

        assert!(manager.matches_exclude_patterns(Path::new("lib/forge-std/Test.sol")));
        assert!(manager.matches_exclude_patterns(Path::new("contracts/lib/utils/Helper.sol")));
        assert!(manager.matches_exclude_patterns(Path::new("out/Contract.sol")));
        assert!(manager.matches_exclude_patterns(Path::new("node_modules/package/file.js")));

        assert!(!manager.matches_exclude_patterns(Path::new("contracts/MyContract.sol")));
        assert!(!manager.matches_exclude_patterns(Path::new("src/Token.sol")));
    }

    #[test]
    fn test_glob_pattern_matching() {
        assert!(WorkspaceManager::matches_glob_pattern("test.sol", "*.sol"));
        assert!(WorkspaceManager::matches_glob_pattern(
            "path/to/file.sol",
            "**/*.sol"
        ));
        assert!(WorkspaceManager::matches_glob_pattern(
            "node_modules/package/file.js",
            "**/node_modules/**"
        ));
        assert!(!WorkspaceManager::matches_glob_pattern("test.rs", "*.sol"));
        assert!(!WorkspaceManager::matches_glob_pattern(
            "test.sol",
            "**/node_modules/**"
        ));
    }

    #[test]
    fn test_include_exclude_pattern_matching() {
        let init_params = create_test_init_params();
        let mut manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        manager.set_include_patterns(vec!["**/*.sol".to_string()]);
        manager.set_exclude_patterns(vec!["**/test/**".to_string()]);

        assert!(manager.matches_include_patterns(&PathBuf::from("contract.sol")));
        assert!(manager.matches_include_patterns(&PathBuf::from("path/to/contract.sol")));

        assert!(!manager.matches_include_patterns(&PathBuf::from("file.rs")));

        assert!(manager.matches_exclude_patterns(&PathBuf::from("test/contract.sol")));
        assert!(manager.matches_exclude_patterns(&PathBuf::from("path/test/contract.sol")));

        assert!(!manager.matches_exclude_patterns(&PathBuf::from("contract.sol")));
    }

    #[test]
    fn test_find_scannable_files_no_workspace() {
        let init_params = InitializeParams::default();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        let result = manager.find_scannable_files();
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_workspace_root_fallbacks() {
        #[cfg(windows)]
        let root_uri = Url::parse("file:///C:/root/uri").unwrap();
        #[cfg(not(windows))]
        let root_uri = Url::parse("file:///root/uri").unwrap();

        let init_params = InitializeParams {
            workspace_folders: Some(vec![WorkspaceFolder {
                uri: root_uri,
                name: "root".to_string(),
            }]),
            ..Default::default()
        };

        let root = WorkspaceManager::determine_workspace_root(&init_params).unwrap();
        assert!(root.is_some());

        let init_params = InitializeParams::default();
        let root = WorkspaceManager::determine_workspace_root(&init_params).unwrap();
        assert!(root.is_none());
    }

    #[test]
    fn test_multiple_documents() {
        let init_params = create_test_init_params();
        let manager =
            WorkspaceManager::new(init_params, default_include_patterns(), default_exclude_patterns())
                .unwrap();

        let doc1 = TextDocumentItem {
            uri: Url::parse("file:///test/contract1.sol").unwrap(),
            language_id: "solidity".to_string(),
            version: 1,
            text: "contract Test1 {}".to_string(),
        };

        let doc2 = TextDocumentItem {
            uri: Url::parse("file:///test/contract2.sol").unwrap(),
            language_id: "solidity".to_string(),
            version: 1,
            text: "contract Test2 {}".to_string(),
        };

        manager.add_document(doc1.clone()).unwrap();
        manager.add_document(doc2.clone()).unwrap();

        assert_eq!(manager.get_open_documents().len(), 2);
        assert!(manager.is_document_open(&doc1.uri));
        assert!(manager.is_document_open(&doc2.uri));

        let docs = manager.get_open_documents();
        let uris: std::collections::HashSet<_> = docs.iter().map(|d| &d.uri).collect();
        assert!(uris.contains(&doc1.uri));
        assert!(uris.contains(&doc2.uri));
    }
}
