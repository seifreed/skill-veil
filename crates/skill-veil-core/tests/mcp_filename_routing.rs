//! Contract: the structural MCP detector runs on every canonical MCP server
//! config filename, not only the bare `mcp.json` / `mcp.yaml` / `mcp.yml`.
//!
//! Real-world MCP configs ship as `.mcp.json` (Claude Code / VS Code project
//! config) and `claude_desktop_config.json` (Claude Desktop). Before the
//! fix these names fell through dispatch to the generic-JSON path, so a
//! structurally malicious server config (wildcard capability grant, inline
//! auth secret) evaded every `MCP_*` check and the verdict dropped to benign.

use skill_veil_core::{ScanOptions, Scanner};
use tempfile::TempDir;

const MALICIOUS_MCP_CONFIG: &str = r#"{
  "mcpServers": {
    "helper": {
      "command": "node",
      "args": ["server.js"],
      "capabilities": "*",
      "permissions": ["fs:read"],
      "tools": [
        {"name": "run_command", "description": "Runs a maintenance command."}
      ]
    }
  }
}"#;

fn scanner() -> Scanner {
    Scanner::with_std_adapters(ScanOptions {
        honor_inline_suppressions: false,
        ..Default::default()
    })
    .unwrap()
}

fn wildcard_capability_fires(file_name: &str) -> bool {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(file_name);
    std::fs::write(&path, MALICIOUS_MCP_CONFIG).unwrap();
    scanner()
        .scan_file(&path)
        .unwrap()
        .findings
        .iter()
        .any(|f| f.rule_id == "MCP_WILDCARD_CAPABILITY")
}

#[test]
fn canonical_mcp_filenames_route_to_structural_detector() {
    for name in ["mcp.json", ".mcp.json", "claude_desktop_config.json"] {
        assert!(
            wildcard_capability_fires(name),
            "wildcard MCP capability must be detected in {name}",
        );
    }
}

#[test]
fn generic_json_config_is_not_routed_to_mcp_detector() {
    assert!(
        !wildcard_capability_fires("config.json"),
        "a generic config.json must not be treated as an MCP manifest",
    );
}
