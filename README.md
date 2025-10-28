# Tameshi LSP Server

[![Tests](https://github.com/tameshi-dev/TameshiLSP/actions/workflows/test.yml/badge.svg)](https://github.com/tameshi-dev/TameshiLSP/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/tameshi-dev/TameshiLSP?display_name=tag)](https://github.com/tameshi-dev/TameshiLSP/releases/latest)
[![Version](https://img.shields.io/badge/version-0.1.1-blue)](https://github.com/tameshi-dev/TameshiLSP/releases)

Language Server Protocol implementation for [Tameshi](https://github.com/tameshi-dev/Tameshi) security analysis, providing real-time vulnerability detection for Solidity smart contracts.

## Features

- **Hybrid Analysis**: Combines deterministic pattern matching with LLM-based semantic analysis
- **Real-time Detection**: Vulnerabilities appear as you write code
- **Finding Correlation**: Links related findings from multiple scanners to boost confidence
- **Background Processing**: Analysis runs in separate thread to keep UI responsive

## Build

```bash
cargo build --release
```

The binary will be at `target/release/tameshi-lsp`

## Architecture

The LSP server communicates via stdio and supports both file-level and workspace-level analysis. Background worker threads handle expensive scanning operations to keep the main message loop responsive.

## LSP Capabilities

### Workspace Commands

The server implements the following commands via `workspace/executeCommand`:

| Command | Description | Parameters |
|---------|-------------|------------|
| `tameshi.scanWorkspace` | Scan entire workspace | None |
| `tameshi.scanFile` | Scan specific file | `file_path`: string (URI or path) |
| `tameshi.refreshResults` | Clear cache and refresh | None |
| `tameshi.exportReport` | Export findings | `format`: "sarif" \| "json"<br>`output_path`: string<br>`scope`: workspace \| file |
| `tameshi.ignoreFinding` | Suppress false positive | `finding_id`: string |
| `tameshi.toggleLLM` | Toggle LLM scanning on/off | None |
| `tameshi.reloadLLMConfig` | Reload LLM configuration | None |
| `tameshi.runHybridAnalysis` | Run both deterministic and LLM | `file_path`: string (optional) |
| `tameshi.showCorrelations` | Show correlated findings | `finding_id`: string |
| `tameshi.showProvenance` | Show finding provenance | `finding_id`: string |
| `tameshi.toggleAnalysisMode` | Toggle analysis mode | None |
| `tameshi.llmScanFile` | LLM scan specific file | `file_path`: string (URI or path) |
| `tameshi.llmScanWorkspace` | LLM scan entire workspace | `options`: object (optional) |
| `tameshi.getLLMScanners` | Get available LLM scanners | None |
| `tameshi.llmUpdateConfig` | Update LLM configuration | `config`: object |
| `tameshi.llmCancelScan` | Cancel LLM scan | `token`: string (or "all") |

#### Example Command Request

```json
{
  "command": "tameshi.scanFile",
  "arguments": [
    "file:///path/to/contract.sol"
  ]
}
```

### Output

All findings are provided as LSP diagnostics with severity mapping:
- **Critical/High** → Error
- **Medium** → Warning
- **Low** → Information

Export formats: SARIF, JSON

## IDE Integration

### VS Code

Install from [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=tameshi.tameshi-vscode)

Repository: [tameshi-dev/tameshi-vscode](https://github.com/tameshi-dev/tameshi-vscode)

### Neovim

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

if not configs.tameshi then
  configs.tameshi = {
    default_config = {
      cmd = { 'tameshi-lsp' },
      filetypes = { 'solidity' },
      root_dir = lspconfig.util.root_pattern('.git', 'foundry.toml', 'hardhat.config.js'),
    },
  }
end

lspconfig.tameshi.setup({})
```

Ensure `tameshi-lsp` is in your PATH or use absolute path: `cmd = { '/path/to/tameshi-lsp' }`

### Other IDEs

Any IDE with LSP support can use this server. Configure your IDE to:
1. Run `tameshi-lsp` as the language server for Solidity files
2. Use stdio for communication
3. Send workspace commands for analysis

## Configuration

Environment variables:
- `RUST_LOG=debug` - Enable debug logging
- `OPENAI_API_KEY` - API key for OpenAI LLM analysis

## Testing

```bash
cargo test
```

## License

MIT
