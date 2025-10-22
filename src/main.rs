//! Tameshi LSP Server entry point
//!
//! Spawns a dedicated worker thread for scanning operations to keep the LSP message
//! loop responsive during expensive analysis.

use anyhow::Result;
use lsp_server::{Connection, Message};
use lsp_types::{
    CodeActionOptions, InitializeParams, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, WorkDoneProgressOptions,
};
use std::{env, sync::mpsc, thread};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use tameshi_lsp::{scan::ScanRequest, *};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("tameshi-lsp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Tameshi LSP server");

    let (connection, io_threads) = Connection::stdio();

    let server_capabilities = serde_json::to_value(ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        completion_provider: None,
        hover_provider: None,
        code_lens_provider: Some(lsp_types::CodeLensOptions {
            resolve_provider: Some(false),
        }),
        code_action_provider: Some(lsp_types::CodeActionProviderCapability::Options(
            CodeActionOptions {
                code_action_kinds: Some(vec![
                    lsp_types::CodeActionKind::QUICKFIX,
                    lsp_types::CodeActionKind::SOURCE,
                ]),
                work_done_progress_options: WorkDoneProgressOptions {
                    work_done_progress: Some(true),
                },
                resolve_provider: Some(false),
            },
        )),
        execute_command_provider: Some(lsp_types::ExecuteCommandOptions {
            commands: vec![
                "tameshi.scanWorkspace".to_string(),
                "tameshi.scanFile".to_string(),
                "tameshi.refreshResults".to_string(),
                "tameshi.exportReport".to_string(),
                "tameshi.ignoreFinding".to_string(),
                "tameshi.toggleLLM".to_string(),
                "tameshi.reloadLLMConfig".to_string(),
                "tameshi.runHybridAnalysis".to_string(),
                "tameshi.showCorrelations".to_string(),
                "tameshi.showProvenance".to_string(),
                "tameshi.toggleAnalysisMode".to_string(),
            ],
            work_done_progress_options: WorkDoneProgressOptions {
                work_done_progress: Some(true),
            },
        }),
        diagnostic_provider: Some(lsp_types::DiagnosticServerCapabilities::Options(
            lsp_types::DiagnosticOptions {
                identifier: Some("tameshi".to_string()),
                inter_file_dependencies: true,
                workspace_diagnostics: true,
                work_done_progress_options: WorkDoneProgressOptions {
                    work_done_progress: Some(true),
                },
            },
        )),
        workspace: Some(lsp_types::WorkspaceServerCapabilities {
            workspace_folders: Some(lsp_types::WorkspaceFoldersServerCapabilities {
                supported: Some(true),
                change_notifications: Some(lsp_types::OneOf::Left(true)),
            }),
            file_operations: None,
        }),
        ..Default::default()
    })?;

    let init_params = connection.initialize(server_capabilities)?;
    let init_params: InitializeParams = serde_json::from_value(init_params)?;

    let config = if let Some(options) = &init_params.initialization_options {
        config::TameshiConfig::from_lsp_value(options.clone()).unwrap_or_default()
    } else {
        config::TameshiConfig::default()
    };

    main_loop(connection, init_params, config).await?;

    io_threads.join()?;
    info!("Shutting down Tameshi LSP server");
    Ok(())
}

use std::sync::Arc;

async fn main_loop(
    connection: Connection,
    init_params: InitializeParams,
    config: config::TameshiConfig,
) -> Result<()> {
    info!("Starting main loop");

    let (scan_tx, scan_rx) = mpsc::channel::<ScanRequest>();

    let scan_thread = thread::spawn(move || {
        ScanManager::new().unwrap().run(scan_rx);
    });

    let server = Arc::new(TameshiLspServer::new(init_params, scan_tx.clone(), config)?);
    let connection = Arc::new(connection);

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    let _ = scan_tx.send(ScanRequest::Shutdown);
                    break;
                }

                let server = server.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    server.process_request(&connection, req).await;
                });
            }
            Message::Notification(not) => {
                server.process_notification(&connection, not);
            }
            Message::Response(_) => {}
        }
    }

    scan_thread.join().unwrap();

    Ok(())
}
