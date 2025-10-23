//! LSP server implementation
//!
//! Routes protocol requests to specialized components rather than implementing analysis
//! logic directly. This separation keeps protocol concerns isolated from scanning,
//! caching, and diagnostics logic that needs to be testable independently.
//!
//! LSP clients expect immediate acknowledgment but scans take time, so we spawn
//! background tasks and use progress notifications. Helper functions centralize
//! the pattern of extracting typed values from LSP's `Vec<serde_json::Value>` arguments.

use crate::llm_scanner;
use crate::{
    config::TameshiConfig,
    diagnostics::DiagnosticsMapper,
    findings_store::FindingsStore,
    llm_scan_manager::{LLMScanManager, LLMScanRequest},
    proto::{self, GetFindingDetailsRequest, GetFindingsRequest, GetFindingsResponse},
    scan::ScanRequest,
    workspace::WorkspaceManager,
};
use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use lsp_server::{Connection, Notification, Request, Response};
use lsp_types::{
    notification::{
        DidChangeTextDocument, DidOpenTextDocument, DidSaveTextDocument, Notification as _,
    },
    request::{ExecuteCommand, Request as _},
    ExecuteCommandParams, InitializeParams, Url, WorkDoneProgressBegin, WorkDoneProgressEnd,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{atomic::AtomicU64, mpsc, Arc, Mutex},
};
use tokio::sync::mpsc::unbounded_channel;
use tracing::{debug, error, info};
use uuid::Uuid;

pub struct TameshiLspServer {
    workspace_manager: WorkspaceManager,
    findings_store: FindingsStore,
    diagnostics_mapper: DiagnosticsMapper,
    config: TameshiConfig,
    scan_tx: mpsc::Sender<ScanRequest>,
    llm_scan_tx: Option<mpsc::Sender<LLMScanRequest>>,
    progress_tokens: Arc<std::sync::Mutex<HashMap<String, bool>>>,
    scan_epoch: Arc<std::sync::atomic::AtomicU64>,
}

impl TameshiLspServer {
    pub fn new(
        init_params: InitializeParams,
        scan_tx: mpsc::Sender<ScanRequest>,
        config: TameshiConfig,
    ) -> Result<Self> {
        let workspace_manager = WorkspaceManager::new(init_params)?;
        let findings_store = FindingsStore::new();
        let diagnostics_mapper = DiagnosticsMapper::new();

        let llm_scan_tx = match LLMScanManager::new(config.clone()) {
            Ok(manager) => {
                let (llm_tx, llm_rx) = mpsc::channel();
                std::thread::spawn(move || {
                    manager.run(llm_rx);
                });
                Some(llm_tx)
            }
            Err(e) => {
                error!(
                    "Failed to initialize LLM scan manager: {}. LLM scanning will be disabled.",
                    e
                );
                None
            }
        };

        Ok(Self {
            workspace_manager,
            findings_store,
            diagnostics_mapper,
            config,
            scan_tx,
            llm_scan_tx,
            progress_tokens: Arc::new(Mutex::new(HashMap::new())),
            scan_epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn process_request(&self, connection: &Connection, req: Request) {
        let req_id = req.id.clone();

        let result = match req.method.as_str() {
            ExecuteCommand::METHOD => self.handle_execute_command(connection, req).await,
            "tameshi/getFindings" => self.handle_get_findings(connection, req),
            "tameshi/getFindingDetails" => self.handle_get_finding_details(connection, req),
            _ => {
                debug!("Received unhandled request: {}", req.method);
                Ok(())
            }
        };

        if let Err(e) = result {
            let response = Response::new_err(req_id, -32603, e.to_string());
            let _ = connection.sender.send(response.into());
        }
    }

    pub fn process_notification(&self, connection: &Connection, not: Notification) {
        let method = not.method.clone();
        let result = match not.method.as_str() {
            DidOpenTextDocument::METHOD => self.handle_did_open(not),
            DidChangeTextDocument::METHOD => self.handle_did_change(not),
            DidSaveTextDocument::METHOD => self.handle_did_save(connection, not),
            _ => {
                debug!("Received unhandled notification: {}", method);
                Ok(())
            }
        };

        if let Err(e) = result {
            error!("Error processing notification {}: {}", method, e);
        }
    }

    async fn handle_execute_command(&self, connection: &Connection, req: Request) -> Result<()> {
        let params: ExecuteCommandParams = serde_json::from_value(req.params)?;

        match params.command.as_str() {
            "tameshi.scanWorkspace" => {
                self.execute_scan_workspace(connection, req.id, Some(params.arguments.as_slice()))?;
            }
            "tameshi.scanFile" => {
                self.execute_scan_file(connection, req.id, Some(params.arguments.as_slice()))?;
            }
            "tameshi.refreshResults" => {
                self.execute_refresh_results(connection, req.id)?;
            }
            "tameshi.exportReport" => {
                self.execute_export_report(connection, req.id, Some(params.arguments.clone()))?;
            }
            "tameshi.ignoreFinding" => {
                self.execute_ignore_finding(connection, req.id, Some(params.arguments))?;
            }
            "tameshi.toggleLLM" => {
                self.execute_toggle_llm(connection, req.id)?;
            }
            "tameshi.reloadLLMConfig" => {
                self.execute_reload_llm_config(connection, req.id)?;
            }
            "tameshi.runHybridAnalysis" => {
                self.execute_hybrid_analysis(
                    connection,
                    req.id,
                    Some(params.arguments.as_slice()),
                )?;
            }
            "tameshi.showCorrelations" => {
                self.execute_show_correlations(
                    connection,
                    req.id,
                    Some(params.arguments.as_slice()),
                )?;
            }
            "tameshi.showProvenance" => {
                self.execute_show_provenance(
                    connection,
                    req.id,
                    Some(params.arguments.as_slice()),
                )?;
            }
            "tameshi.toggleAnalysisMode" => {
                self.execute_toggle_analysis_mode(connection, req.id)?;
            }
            "tameshi.llmScanFile" => {
                self.execute_llm_scan_file(connection, req.id, Some(&params.arguments))
                    .await?;
            }
            "tameshi.llmScanWorkspace" => {
                self.execute_llm_scan_workspace(connection, req.id, Some(&params.arguments))?;
            }
            "tameshi.getLLMScanners" => {
                self.execute_get_llm_scanners(connection, req.id)?;
            }
            "tameshi.llmUpdateConfig" => {
                self.execute_llm_update_config(connection, req.id, Some(&params.arguments))?;
            }
            "tameshi.llmCancelScan" => {
                self.execute_llm_cancel_scan(connection, req.id, Some(&params.arguments))?;
            }
            _ => {
                let response = Response::new_err(
                    req.id,
                    -32601,
                    format!("Unknown command: {}", params.command),
                );
                connection.sender.send(response.into())?;
            }
        }

        Ok(())
    }

    fn execute_toggle_llm(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
    ) -> Result<()> {
        let llm_enabled = self.config.llm.enabled;

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "llm_enabled": llm_enabled,
                "message": format!("LLM scanning is currently {}", if llm_enabled { "enabled" } else { "disabled" })
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_hybrid_analysis(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        args: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        let file_path = self.extract_path_or_workspace(args)?;

        let progress_token = format!("tameshi-hybrid-{}", Uuid::new_v4());
        self.send_progress_begin(connection, &progress_token, "Running hybrid analysis...")?;

        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let scan_request = if file_path.is_file() {
            let file_uri = Url::from_file_path(&file_path).ok();
            let content = file_uri.and_then(|uri| {
                self.workspace_manager
                    .get_document(&uri)
                    .map(|doc| doc.content)
            });

            ScanRequest::ScanFile {
                path: file_path,
                content,
                progress_token: Some(progress_token.clone()),
                response_tx,
            }
        } else {
            ScanRequest::ScanWorkspace {
                root: file_path,
                progress_token: Some(progress_token.clone()),
                response_tx,
            }
        };

        self.scan_tx.send(scan_request)?;

        let connection_sender = connection.sender.clone();
        let progress_token_clone = progress_token.clone();
        std::thread::spawn(move || {
            match response_rx.recv() {
                Ok(Ok(scan_result)) => {
                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": true,
                            "findings_count": scan_result.findings.len(),
                            "analysis_mode": "hybrid",
                            "message": "Hybrid analysis completed successfully"
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
                Ok(Err(e)) => {
                    let response = Response::new_err(req_id, -32603, e.to_string());
                    let _ = connection_sender.send(response.into());
                }
                Err(e) => {
                    let response =
                        Response::new_err(req_id, -32603, format!("Internal error: {}", e));
                    let _ = connection_sender.send(response.into());
                }
            }
            let _ = Self::send_progress_end_static(&connection_sender, &progress_token_clone);
        });

        Ok(())
    }

    fn execute_show_correlations(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        args: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        let finding_id = Self::extract_first_arg_as_string(args)?;

        use crate::proto::FindingsScope;
        let correlations = self
            .findings_store
            .get_findings(&FindingsScope::Workspace, None, None)
            .iter()
            .find(|f| f.id.to_string() == finding_id)
            .and_then(|f| f.metadata.as_ref())
            .map(|m| &m.correlations)
            .cloned()
            .unwrap_or_else(Vec::new);

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "finding_id": finding_id,
                "correlations": correlations,
                "correlation_count": correlations.len()
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_show_provenance(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        args: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        let finding_id = Self::extract_first_arg_as_string(args)?;

        use crate::proto::FindingsScope;
        let (provenance, evidence) = self
            .findings_store
            .get_findings(&FindingsScope::Workspace, None, None)
            .iter()
            .find(|f| f.id.to_string() == finding_id)
            .and_then(|f| f.metadata.as_ref())
            .map(|m| (m.provenance.clone(), m.evidence.clone()))
            .unwrap_or((None, vec![]));

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "finding_id": finding_id,
                "provenance": provenance,
                "evidence": evidence,
                "evidence_count": evidence.len()
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_toggle_analysis_mode(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
    ) -> Result<()> {
        let current_mode = if self.config.llm.enabled {
            "hybrid"
        } else {
            "deterministic"
        };

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "current_mode": current_mode,
                "available_modes": ["deterministic", "llm", "hybrid"],
                "message": format!("Analysis mode: {}", current_mode)
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_reload_llm_config(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
    ) -> Result<()> {
        match self.config.load_llm_config() {
            Some(llm_config) => {
                let scanner_count = llm_config.enabled_scanners.len();
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": true,
                        "message": format!("LLM config reloaded with {} scanners", scanner_count),
                        "enabled_scanners": llm_config.enabled_scanners
                    }),
                );
                connection.sender.send(response.into())?;
            }
            None => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": "LLM scanning is disabled or no config found"
                    }),
                );
                connection.sender.send(response.into())?;
            }
        }
        Ok(())
    }

    fn execute_scan_workspace(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        _arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        let workspace_root = self
            .workspace_manager
            .get_workspace_root()
            .ok_or_else(|| anyhow!("No workspace root available"))?;

        let progress_token = format!("tameshi-scan-workspace-{}", Uuid::new_v4());

        self.send_progress_begin(connection, &progress_token, "Scanning workspace...")?;

        let (response_tx, response_rx) = std::sync::mpsc::channel();

        let scan_request = ScanRequest::ScanWorkspace {
            root: workspace_root,
            progress_token: Some(progress_token.clone()),
            response_tx,
        };

        self.scan_tx.send(scan_request)?;

        let connection_sender = connection.sender.clone();
        let progress_token_clone = progress_token.clone();
        let findings_store = self.findings_store.clone();
        let diagnostics_mapper = self.diagnostics_mapper.clone();
        let workspace_manager = self.workspace_manager.clone();
        let scan_epoch = Arc::clone(&self.scan_epoch);

        std::thread::spawn(move || {
            match response_rx.recv() {
                Ok(Ok(scan_result)) => {
                    findings_store.store_scan_result(scan_result.clone());

                    if let Err(e) = Self::publish_diagnostics_for_scan_result(
                        &connection_sender,
                        &diagnostics_mapper,
                        &scan_result,
                        &workspace_manager,
                        &scan_epoch,
                    ) {
                        error!("Failed to publish diagnostics: {}", e);
                    }

                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": true,
                            "findings_count": scan_result.findings.len(),
                            "errors_count": scan_result.errors.len(),
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
                Ok(Err(e)) => {
                    let response = Response::new_err(req_id, -32603, e.to_string());
                    let _ = connection_sender.send(response.into());
                }
                Err(e) => {
                    let response =
                        Response::new_err(req_id, -32603, format!("Internal error: {}", e));
                    let _ = connection_sender.send(response.into());
                }
            }

            let _ = Self::send_progress_end_static(&connection_sender, &progress_token_clone);
        });

        Ok(())
    }

    fn execute_scan_file(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        debug!("execute_scan_file called with arguments: {:?}", arguments);

        let file_path = self.extract_first_arg_as_path(arguments)?;
        debug!("Extracted file path: {:?}", file_path);

        let progress_token = format!("tameshi-scan-file-{}", Uuid::new_v4());

        self.send_progress_begin(
            connection,
            &progress_token,
            &format!("Scanning file: {:?}", file_path),
        )?;

        let file_uri = Url::from_file_path(&file_path).ok();
        let content = file_uri.and_then(|uri| {
            self.workspace_manager.get_document(&uri).map(|doc| {
                debug!(
                    "Using in-memory content for scan: {} ({} lines)",
                    uri,
                    doc.content.lines().count()
                );
                doc.content
            })
        });

        if content.is_none() {
            debug!("No in-memory content available, scanner will read from disk");
        }

        let (response_tx, response_rx) = std::sync::mpsc::channel();

        let scan_request = ScanRequest::ScanFile {
            path: file_path,
            content,
            progress_token: Some(progress_token.clone()),
            response_tx,
        };

        self.scan_tx.send(scan_request)?;

        let connection_sender = connection.sender.clone();
        let progress_token_clone = progress_token.clone();
        let findings_store = self.findings_store.clone();
        let diagnostics_mapper = self.diagnostics_mapper.clone();
        let workspace_manager = self.workspace_manager.clone();
        let scan_epoch = Arc::clone(&self.scan_epoch);

        std::thread::spawn(move || {
            match response_rx.recv() {
                Ok(Ok(scan_result)) => {
                    findings_store.store_scan_result(scan_result.clone());

                    if let Err(e) = Self::publish_diagnostics_for_scan_result(
                        &connection_sender,
                        &diagnostics_mapper,
                        &scan_result,
                        &workspace_manager,
                        &scan_epoch,
                    ) {
                        error!("Failed to publish diagnostics: {}", e);
                    }

                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": true,
                            "findings_count": scan_result.findings.len(),
                            "errors_count": scan_result.errors.len(),
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
                Ok(Err(e)) => {
                    let response = Response::new_err(req_id, -32603, e.to_string());
                    let _ = connection_sender.send(response.into());
                }
                Err(e) => {
                    let response =
                        Response::new_err(req_id, -32603, format!("Internal error: {}", e));
                    let _ = connection_sender.send(response.into());
                }
            }

            let _ = Self::send_progress_end_static(&connection_sender, &progress_token_clone);
        });

        Ok(())
    }

    fn execute_refresh_results(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
    ) -> Result<()> {
        let (response_tx, response_rx) = std::sync::mpsc::channel();

        let scan_request = ScanRequest::RefreshResults { response_tx };
        self.scan_tx.send(scan_request)?;

        let connection_sender = connection.sender.clone();
        let findings_store = self.findings_store.clone();

        std::thread::spawn(move || match response_rx.recv() {
            Ok(Ok(())) => {
                findings_store.clear();

                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": true,
                        "message": "Results refreshed successfully"
                    }),
                );
                let _ = connection_sender.send(response.into());
            }
            Ok(Err(e)) => {
                let response = Response::new_err(req_id, -32603, e.to_string());
                let _ = connection_sender.send(response.into());
            }
            Err(e) => {
                let response = Response::new_err(req_id, -32603, format!("Internal error: {}", e));
                let _ = connection_sender.send(response.into());
            }
        });

        Ok(())
    }

    fn execute_export_report(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<Vec<serde_json::Value>>,
    ) -> Result<()> {
        use crate::export::{JsonExporter, SarifExporter};
        use crate::proto::{ExportFindingsRequest, ExportFindingsResponse, ExportFormat};
        use std::fs;

        let export_req: ExportFindingsRequest = if let Some(args) = arguments {
            if let Some(first_arg) = args.first() {
                serde_json::from_value(first_arg.clone())
                    .map_err(|e| anyhow!("Invalid export request: {}", e))?
            } else {
                return Err(anyhow!("Missing export parameters"));
            }
        } else {
            return Err(anyhow!("Missing arguments"));
        };

        let findings = self
            .findings_store
            .get_findings(&export_req.scope, None, None);

        let scan_result = proto::ScanResult {
            version: proto::PROTOCOL_VERSION.to_string(),
            findings,
            metadata: proto::ScanMetadata {
                start_time: chrono::Utc::now().to_rfc3339(),
                duration_ms: 0,
                scanned_files: vec![],
                skipped_files: std::collections::HashMap::new(),
                scanner_config: None,
            },
            errors: vec![],
        };

        let export_result = match export_req.format {
            ExportFormat::Sarif => {
                let sarif = SarifExporter::export(&scan_result)?;
                SarifExporter::to_json(&sarif, export_req.pretty)?
            }
            ExportFormat::Json => JsonExporter::export(&scan_result, export_req.pretty)?,
        };

        fs::write(&export_req.output_path, &export_result)?;

        let metadata = fs::metadata(&export_req.output_path)?;

        let response = ExportFindingsResponse {
            output_path: export_req.output_path.clone(),
            findings_count: scan_result.findings.len(),
            format: export_req.format,
            file_size: metadata.len(),
        };

        let response = Response::new_ok(req_id, serde_json::to_value(response)?);
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_ignore_finding(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        _arguments: Option<Vec<serde_json::Value>>,
    ) -> Result<()> {
        let response = Response::new_err(
            req_id,
            -32601,
            "Ignore functionality not yet implemented".to_string(),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn handle_get_findings(&self, connection: &Connection, req: Request) -> Result<()> {
        let params: GetFindingsRequest = serde_json::from_value(req.params)?;

        let findings = self.findings_store.get_findings(
            &params.scope,
            params.min_severity,
            params.min_confidence,
        );

        let total_count = findings.len();

        let response = GetFindingsResponse {
            findings,
            total_count,
        };

        let response = Response::new_ok(req.id, serde_json::to_value(response)?);
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn handle_get_finding_details(&self, connection: &Connection, req: Request) -> Result<()> {
        let _params: GetFindingDetailsRequest = serde_json::from_value(req.params)?;

        let response = Response::new_err(
            req.id,
            proto::error_codes::FINDING_NOT_FOUND,
            "Finding not found".to_string(),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn handle_did_open(&self, not: Notification) -> Result<()> {
        let params: lsp_types::DidOpenTextDocumentParams = serde_json::from_value(not.params)?;

        debug!("Document opened: {}", params.text_document.uri);

        self.workspace_manager.add_document(params.text_document)?;

        Ok(())
    }

    fn handle_did_change(&self, not: Notification) -> Result<()> {
        let params: lsp_types::DidChangeTextDocumentParams = serde_json::from_value(not.params)?;

        debug!(
            "Document changed: {} (version {})",
            params.text_document.uri, params.text_document.version
        );

        if let Some(change) = params.content_changes.first() {
            self.workspace_manager.update_document(
                &params.text_document.uri,
                params.text_document.version,
                change.text.clone(),
            )?;
        }

        Ok(())
    }

    fn handle_did_save(&self, _connection: &Connection, not: Notification) -> Result<()> {
        let params: lsp_types::DidSaveTextDocumentParams = serde_json::from_value(not.params)?;

        debug!("Document saved: {}", params.text_document.uri);

        self.workspace_manager
            .mark_document_saved(&params.text_document.uri)?;

        if let Some(text) = params.text {
            let version = self
                .workspace_manager
                .get_document(&params.text_document.uri)
                .map(|doc| doc.version)
                .unwrap_or(0);

            debug!(
                "Updating document content from didSave notification: {} lines",
                text.lines().count()
            );
            self.workspace_manager
                .update_document(&params.text_document.uri, version + 1, text)?;

            self.workspace_manager
                .mark_document_saved(&params.text_document.uri)?;
        }

        if self.config.scan.on_save_mode != crate::config::OnSaveMode::None {
            let file_path = params
                .text_document
                .uri
                .to_file_path()
                .map_err(|_| anyhow!("Invalid file URI"))?;

            match self.config.scan.on_save_mode {
                crate::config::OnSaveMode::File => {
                    let content = self
                        .workspace_manager
                        .get_document(&params.text_document.uri)
                        .map(|doc| {
                            debug!(
                                "Using in-memory content from workspace for on-save scan: {} lines",
                                doc.content.lines().count()
                            );
                            doc.content
                        });

                    let (response_tx, _response_rx) = std::sync::mpsc::channel();

                    let scan_request = ScanRequest::ScanFile {
                        path: file_path,
                        content,
                        progress_token: None,
                        response_tx,
                    };

                    self.scan_tx.send(scan_request)?;
                }
                crate::config::OnSaveMode::Workspace => {
                    if let Some(workspace_root) = self.workspace_manager.get_workspace_root() {
                        let (response_tx, _response_rx) = std::sync::mpsc::channel();

                        let scan_request = ScanRequest::ScanWorkspace {
                            root: workspace_root,
                            progress_token: None,
                            response_tx,
                        };

                        self.scan_tx.send(scan_request)?;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn send_progress_begin(&self, connection: &Connection, token: &str, title: &str) -> Result<()> {
        let progress = WorkDoneProgressBegin {
            title: title.to_string(),
            cancellable: Some(true),
            message: None,
            percentage: None,
        };

        let notification = Notification::new(
            "$/progress".to_string(),
            serde_json::json!({
                "token": token,
                "value": progress
            }),
        );

        connection.sender.send(notification.into())?;
        Ok(())
    }

    fn send_progress_end_static(
        connection_sender: &Sender<lsp_server::Message>,
        token: &str,
    ) -> Result<()> {
        let progress = WorkDoneProgressEnd {
            message: Some("Scan completed".to_string()),
        };

        let notification = Notification::new(
            "$/progress".to_string(),
            serde_json::json!({
                "token": token,
                "value": progress
            }),
        );

        connection_sender.send(notification.into())?;
        Ok(())
    }

    fn register_progress_token(&self, token: &str) {
        if let Ok(mut tokens) = self.progress_tokens.lock() {
            tokens.insert(token.to_string(), true);
        }
    }

    fn begin_progress(
        &self,
        connection: &Connection,
        token: &str,
        message: &str,
        _percentage: Option<u32>,
        _current: u32,
        _total: u32,
    ) -> Result<()> {
        self.send_progress_begin(connection, token, message)
    }

    fn publish_diagnostics_for_scan_result(
        connection_sender: &Sender<lsp_server::Message>,
        diagnostics_mapper: &DiagnosticsMapper,
        scan_result: &proto::ScanResult,
        workspace_manager: &crate::workspace::WorkspaceManager,
        scan_epoch: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<()> {
        use lsp_types::PublishDiagnosticsParams;
        use std::collections::{HashMap, HashSet};

        let diagnostics_by_file =
            diagnostics_mapper.map_findings_to_diagnostics(&scan_result.findings)?;

        let mut published_uris = HashSet::new();
        let mut uri_versions: HashMap<String, Option<i32>> = HashMap::new();

        for (file_path, diagnostics) in diagnostics_by_file.iter() {
            if let Ok(uri) = Url::from_file_path(file_path) {
                let version = workspace_manager.get_document(&uri).map(|doc| doc.version);

                debug!(
                    "Publishing diagnostics for {} (with findings): {} diagnostics, version: {:?}",
                    uri,
                    diagnostics.len(),
                    version
                );

                let params = PublishDiagnosticsParams {
                    uri: uri.clone(),
                    diagnostics: diagnostics.clone(),
                    version,
                };

                let notification = Notification::new(
                    "textDocument/publishDiagnostics".to_string(),
                    serde_json::to_value(params)?,
                );

                connection_sender.send(notification.into())?;

                uri_versions.insert(uri.to_string(), version);
                published_uris.insert(uri);
            }
        }

        for scanned_file in &scan_result.metadata.scanned_files {
            if let Ok(uri) = Url::from_file_path(scanned_file) {
                if published_uris.contains(&uri) {
                    continue;
                }

                let version = workspace_manager.get_document(&uri).map(|doc| doc.version);

                debug!(
                    "Publishing diagnostics for {} (no findings): 0 diagnostics, version: {:?}",
                    uri, version
                );

                let params = PublishDiagnosticsParams {
                    uri: uri.clone(),
                    diagnostics: Vec::new(),
                    version,
                };

                let notification = Notification::new(
                    "textDocument/publishDiagnostics".to_string(),
                    serde_json::to_value(params)?,
                );

                connection_sender.send(notification.into())?;

                uri_versions.insert(uri.to_string(), version);
                published_uris.insert(uri);
            }
        }

        let current_epoch = scan_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let files: Vec<String> = published_uris.iter().map(|uri| uri.to_string()).collect();
        let total_findings = scan_result.findings.len();

        debug!(
            "Sending tameshi/findingsUpdated notification for {} files (epoch: {}, count: {})",
            files.len(),
            current_epoch,
            total_findings
        );

        let findings_updated_notification = Notification::new(
            "tameshi/findingsUpdated".to_string(),
            serde_json::json!({
                "files": files,
                "versions": uri_versions,
                "scanEpoch": current_epoch,
                "count": total_findings,
            }),
        );

        connection_sender.send(findings_updated_notification.into())?;

        Ok(())
    }

    async fn execute_llm_scan_file(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        if self.llm_scan_tx.is_none() {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": "LLM scanning is not available"
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        let file_path = if let Some(args) = arguments {
            if let Some(path_value) = args.first() {
                if let Some(path_str) = path_value.as_str() {
                    if path_str.starts_with("file://") {
                        Url::parse(path_str)
                            .ok()
                            .and_then(|uri| uri.to_file_path().ok())
                            .ok_or_else(|| anyhow!("Invalid file URI: {}", path_str))?
                    } else {
                        PathBuf::from(path_str)
                    }
                } else {
                    return Err(anyhow!("Invalid file path argument: expected a string"));
                }
            } else {
                return Err(anyhow!("Missing file path argument"));
            }
        } else {
            return Err(anyhow!("Missing arguments for llmScanFile"));
        };

        let progress_token = format!("tameshi-llm-scan-file-{}", Uuid::new_v4());
        self.register_progress_token(&progress_token);

        let options = self.parse_llm_scan_options(arguments.and_then(|args| args.get(1)));

        let (response_tx, mut response_rx) = unbounded_channel();

        let scan_request = LLMScanRequest::ScanFile {
            path: file_path.clone(),
            options,
            progress_token: Some(progress_token.clone()),
            response_tx,
        };

        if let Err(e) = self.llm_scan_tx.as_ref().unwrap().send(scan_request) {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": format!("Failed to queue LLM scan: {}", e)
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        self.begin_progress(
            connection,
            &progress_token,
            "Starting LLM scan...",
            None,
            0,
            1,
        )?;

        let connection_sender = connection.sender.clone();
        let diagnostics_mapper = self.diagnostics_mapper.clone();
        let findings_store = self.findings_store.clone();
        let workspace_manager = self.workspace_manager.clone();
        let scan_epoch = Arc::clone(&self.scan_epoch);

        tokio::spawn(async move {
            match response_rx.recv().await {
                Some(Ok(scan_result)) => {
                    info!(
                        "LLM scan completed successfully. Received {} findings",
                        scan_result.findings.len()
                    );
                    for (i, finding) in scan_result.findings.iter().enumerate() {
                        info!(
                            "Storing finding {}: {} - {} (confidence: {:?})",
                            i, finding.finding_type, finding.title, finding.confidence
                        );
                    }

                    findings_store.store_scan_result(scan_result.clone());

                    if let Err(e) = Self::publish_diagnostics_for_scan_result(
                        &connection_sender,
                        &diagnostics_mapper,
                        &scan_result,
                        &workspace_manager,
                        &scan_epoch,
                    ) {
                        error!("Failed to publish diagnostics: {}", e);
                    }

                    if let Err(e) =
                        Self::send_progress_end_static(&connection_sender, &progress_token)
                    {
                        error!("Failed to send completion notification: {}", e);
                    }

                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": true,
                            "message": "LLM scan completed successfully",
                            "result": {
                                "findings_count": scan_result.findings.len(),
                                "scan_time_ms": scan_result.metadata.duration_ms,
                            }
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
                Some(Err(e)) => {
                    error!("LLM scan failed: {}", e);
                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": false,
                            "message": format!("LLM scan failed: {}", e)
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
                None => {
                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": false,
                            "message": "LLM scan channel disconnected"
                        }),
                    );
                    let _ = connection_sender.send(response.into());
                }
            }
        });

        Ok(())
    }

    fn execute_llm_scan_workspace(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        if self.llm_scan_tx.is_none() {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": "LLM scanning is not available"
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        let workspace_root = self
            .workspace_manager
            .get_workspace_root()
            .ok_or_else(|| anyhow!("No workspace root available"))?;

        let progress_token = format!("tameshi-llm-scan-workspace-{}", Uuid::new_v4());
        self.register_progress_token(&progress_token);

        let options = self.parse_llm_scan_options(arguments.and_then(|args| args.first()));

        let (response_tx, mut response_rx) = unbounded_channel();

        let scan_request = LLMScanRequest::ScanWorkspace {
            root: workspace_root.clone(),
            options,
            progress_token: Some(progress_token.clone()),
            response_tx,
        };

        if let Err(e) = self.llm_scan_tx.as_ref().unwrap().send(scan_request) {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": format!("Failed to queue LLM workspace scan: {}", e)
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        self.begin_progress(
            connection,
            &progress_token,
            "Starting LLM workspace scan...",
            None,
            0,
            1,
        )?;

        let connection_sender = connection.sender.clone();
        let diagnostics_mapper = self.diagnostics_mapper.clone();
        let findings_store = self.findings_store.clone();
        let workspace_manager = self.workspace_manager.clone();
        let scan_epoch = Arc::clone(&self.scan_epoch);

        std::thread::spawn(move || match response_rx.blocking_recv() {
            Some(Ok(scan_result)) => {
                findings_store.store_scan_result(scan_result.clone());

                if let Err(e) = Self::publish_diagnostics_for_scan_result(
                    &connection_sender,
                    &diagnostics_mapper,
                    &scan_result,
                    &workspace_manager,
                    &scan_epoch,
                ) {
                    error!("Failed to publish diagnostics: {}", e);
                }

                if let Err(e) = Self::send_progress_end_static(&connection_sender, &progress_token)
                {
                    error!("Failed to send completion notification: {}", e);
                }

                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": true,
                        "message": "LLM workspace scan completed successfully",
                        "result": {
                            "findings_count": scan_result.findings.len(),
                            "scan_time_ms": scan_result.metadata.duration_ms,
                            "workspace_root": workspace_root.to_string_lossy(),
                        }
                    }),
                );
                let _ = connection_sender.send(response.into());
            }
            Some(Err(e)) => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": format!("LLM workspace scan failed: {}", e)
                    }),
                );
                let _ = connection_sender.send(response.into());
            }
            None => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": "LLM workspace scan channel disconnected"
                    }),
                );
                let _ = connection_sender.send(response.into());
            }
        });

        Ok(())
    }

    fn execute_get_llm_scanners(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
    ) -> Result<()> {
        let scanners = if let Some(llm_tx) = &self.llm_scan_tx {
            let (response_tx, mut response_rx) = unbounded_channel();

            let request = LLMScanRequest::GetScanners { response_tx };

            if let Err(e) = llm_tx.send(request) {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": format!("Failed to get LLM scanners: {}", e)
                    }),
                );
                connection.sender.send(response.into())?;
                return Ok(());
            }

            match response_rx.blocking_recv() {
                Some(Ok(scanners)) => scanners,
                Some(Err(e)) => {
                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": false,
                            "message": format!("Failed to get LLM scanners: {}", e)
                        }),
                    );
                    connection.sender.send(response.into())?;
                    return Ok(());
                }
                None => {
                    let response = Response::new_ok(
                        req_id,
                        serde_json::json!({
                            "success": false,
                            "message": "LLM scanners channel disconnected"
                        }),
                    );
                    connection.sender.send(response.into())?;
                    return Ok(());
                }
            }
        } else {
            Vec::new()
        };

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "scanners": scanners,
                "llm_available": self.llm_scan_tx.is_some(),
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn execute_llm_update_config(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        if self.llm_scan_tx.is_none() {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": "LLM scanning is not available"
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        let config_json = arguments
            .and_then(|args| args.first())
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

        let new_config: crate::config::TameshiConfig = serde_json::from_value(config_json)
            .map_err(|e| anyhow!("Invalid LLM configuration: {}", e))?;

        let (response_tx, mut response_rx) = unbounded_channel();

        let request = LLMScanRequest::UpdateConfig {
            config: Box::new(new_config),
            response_tx,
        };

        if let Err(e) = self.llm_scan_tx.as_ref().unwrap().send(request) {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": format!("Failed to update LLM configuration: {}", e)
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        match response_rx.blocking_recv() {
            Some(Ok(())) => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": true,
                        "message": "LLM configuration updated successfully"
                    }),
                );
                connection.sender.send(response.into())?;
            }
            Some(Err(e)) => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": format!("Failed to update LLM configuration: {}", e)
                    }),
                );
                connection.sender.send(response.into())?;
            }
            None => {
                let response = Response::new_ok(
                    req_id,
                    serde_json::json!({
                        "success": false,
                        "message": "LLM configuration update channel disconnected"
                    }),
                );
                connection.sender.send(response.into())?;
            }
        }

        Ok(())
    }

    fn execute_llm_cancel_scan(
        &self,
        connection: &Connection,
        req_id: lsp_server::RequestId,
        arguments: Option<&[serde_json::Value]>,
    ) -> Result<()> {
        if self.llm_scan_tx.is_none() {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": "LLM scanning is not available"
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        let token = arguments
            .and_then(|args| args.first())
            .and_then(|v| v.as_str())
            .ok_or("all");

        let request = if token == Ok("all") {
            LLMScanRequest::CancelAll
        } else {
            LLMScanRequest::Cancel {
                token: token.unwrap_or("unknown").to_string(),
            }
        };

        if let Err(e) = self.llm_scan_tx.as_ref().unwrap().send(request) {
            let response = Response::new_ok(
                req_id,
                serde_json::json!({
                    "success": false,
                    "message": format!("Failed to cancel LLM scan: {}", e)
                }),
            );
            connection.sender.send(response.into())?;
            return Ok(());
        }

        let response = Response::new_ok(
            req_id,
            serde_json::json!({
                "success": true,
                "message": format!("LLM scan cancellation requested for token: {:?}", token)
            }),
        );
        connection.sender.send(response.into())?;
        Ok(())
    }

    fn parse_llm_scan_options(
        &self,
        options_json: Option<&serde_json::Value>,
    ) -> llm_scanner::LLMScanOptions {
        use llm_scanner::LLMScanOptions;

        let mut options = LLMScanOptions::default();

        if let Some(json) = options_json {
            if let Some(obj) = json.as_object() {
                if let Some(enabled_scanners) =
                    obj.get("enabledScanners").and_then(|v| v.as_array())
                {
                    options.enabled_scanners = enabled_scanners
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                }

                if let Some(temperature) = obj.get("temperature").and_then(|v| v.as_f64()) {
                    options.temperature = Some(temperature as f32);
                }

                if let Some(max_tokens) = obj.get("maxTokens").and_then(|v| v.as_u64()) {
                    options.max_tokens = Some(max_tokens as u32);
                }

                if let Some(confidence_threshold) =
                    obj.get("confidenceThreshold").and_then(|v| v.as_f64())
                {
                    options.confidence_threshold = Some(confidence_threshold as f32);
                }

                if let Some(include_low_severity) =
                    obj.get("includeLowSeverity").and_then(|v| v.as_bool())
                {
                    options.include_low_severity = include_low_severity;
                }

                if let Some(timeout_seconds) = obj.get("timeoutSeconds").and_then(|v| v.as_u64()) {
                    options.timeout_seconds = timeout_seconds;
                }

                if let Some(concurrent_scanners) =
                    obj.get("concurrentScanners").and_then(|v| v.as_u64())
                {
                    options.concurrent_scanners = concurrent_scanners as usize;
                }
            }
        }

        options
    }

    fn extract_first_arg_as_string(args: Option<&[serde_json::Value]>) -> Result<String> {
        args.ok_or_else(|| anyhow!("Missing arguments"))?
            .first()
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Invalid or missing string argument"))
    }

    fn extract_path_from_value(value: &serde_json::Value) -> Result<PathBuf> {
        if let Some(path_str) = value.as_str() {
            return if path_str.starts_with("file://") {
                Url::parse(path_str)?
                    .to_file_path()
                    .map_err(|_| anyhow!("Invalid file URI: {}", path_str))
            } else {
                Ok(PathBuf::from(path_str))
            };
        }

        if let Some(obj) = value.as_object() {
            if let Some(fs_path) = obj.get("fsPath").and_then(|v| v.as_str()) {
                return Ok(PathBuf::from(fs_path));
            }

            if let Some(external) = obj.get("external").and_then(|v| v.as_str()) {
                return if external.starts_with("file://") {
                    Url::parse(external)?
                        .to_file_path()
                        .map_err(|_| anyhow!("Invalid file URI: {}", external))
                } else {
                    Ok(PathBuf::from(external))
                };
            }

            if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                return Ok(PathBuf::from(path));
            }

            return Err(anyhow!("URI object has no recognizable path field"));
        }

        Err(anyhow!(
            "Invalid path argument: expected string or URI object"
        ))
    }

    fn extract_first_arg_as_path(&self, args: Option<&[serde_json::Value]>) -> Result<PathBuf> {
        let args = args.ok_or_else(|| anyhow!("Missing arguments"))?;
        let path_value = args
            .first()
            .ok_or_else(|| anyhow!("Missing file path argument"))?;
        Self::extract_path_from_value(path_value)
    }

    fn extract_path_or_workspace(&self, args: Option<&[serde_json::Value]>) -> Result<PathBuf> {
        match args.and_then(|a| a.first()) {
            Some(path_value) => Self::extract_path_from_value(path_value),
            None => self
                .workspace_manager
                .get_workspace_root()
                .ok_or_else(|| anyhow!("No workspace or file specified")),
        }
    }
}
