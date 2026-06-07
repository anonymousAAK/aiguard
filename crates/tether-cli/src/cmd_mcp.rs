//! `tether mcp` — MCP server management subcommands.
//!
//! Subcommands:
//! - `scan`    — One-shot MCP tool description audit
//! - `approve` — Approve a changed tool pin for a server

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use aiguard_scanner_mcp::McpScanner;

#[derive(Parser)]
pub struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Subcommand)]
enum McpCommand {
    /// Run a one-shot audit of MCP tool descriptions
    Scan {
        /// Path to a JSON file containing tools/list response
        #[arg(long)]
        file: Option<String>,

        /// Read tools JSON from stdin
        #[arg(long)]
        stdin: bool,
    },

    /// Approve a changed tool pin for a server
    Approve {
        /// Server ID to approve
        server_id: String,

        /// Path to a JSON file containing the new tools/list response
        #[arg(long)]
        file: Option<String>,

        /// Read tools JSON from stdin
        #[arg(long)]
        stdin: bool,
    },

    /// List all pinned MCP servers
    List,
}

pub async fn run(args: McpArgs) -> Result<()> {
    match args.command {
        McpCommand::Scan { file, stdin } => cmd_scan(file, stdin).await,
        McpCommand::Approve {
            server_id,
            file,
            stdin,
        } => cmd_approve(&server_id, file, stdin).await,
        McpCommand::List => cmd_list(),
    }
}

/// Run a one-shot MCP audit scan.
async fn cmd_scan(file: Option<String>, stdin: bool) -> Result<()> {
    let tools_json = read_tools_json(file, stdin)?;
    let scanner = McpScanner::new();
    let findings = scanner.audit_tools(&tools_json);

    if findings.is_empty() {
        println!("No issues found. All tool descriptions look clean.");
        return Ok(());
    }

    println!("Found {} issue(s) in tool descriptions:\n", findings.len());

    for (i, finding) in findings.iter().enumerate() {
        println!("  {}. [{}] {}", i + 1, finding.rule_id, finding.message);
        println!("     Tool: {}", finding.tool_name);
        println!("     Match: \"{}\"", finding.matched_text);
        println!();
    }

    println!("Review these findings carefully. Suspicious tool descriptions may indicate");
    println!("a compromised or malicious MCP server.");

    // Exit with non-zero if issues found
    std::process::exit(1);
}

/// Approve a changed tool pin.
async fn cmd_approve(server_id: &str, file: Option<String>, stdin: bool) -> Result<()> {
    let tools_json = read_tools_json(file, stdin)?;
    let scanner = McpScanner::new();

    scanner
        .approve_pin(server_id, &tools_json)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Pin updated for server '{server_id}'.");
    println!("The current tool set is now the accepted baseline.");

    Ok(())
}

/// List all pinned MCP servers.
fn cmd_list() -> Result<()> {
    let scanner = McpScanner::new();
    let pinner = aiguard_scanner_mcp::pin::ToolPinner::new();
    let _ = scanner; // just to verify construction works

    let pinned = pinner.list_pinned();

    if pinned.is_empty() {
        println!("No MCP servers are currently pinned.");
        println!("Pins are created automatically when aiguard first sees a server's tools.");
        return Ok(());
    }

    println!("Pinned MCP servers:\n");
    for server in &pinned {
        println!("  - {server}");
    }
    println!("\nUse `aiguard mcp approve <server-id>` to update a pin after review.");

    Ok(())
}

/// Read tools JSON from either a file or stdin.
fn read_tools_json(file: Option<String>, stdin: bool) -> Result<serde_json::Value> {
    let content = if stdin {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("Failed to read from stdin")?;
        buf
    } else if let Some(path) = file {
        std::fs::read_to_string(&path).with_context(|| format!("Failed to read file: {path}"))?
    } else {
        anyhow::bail!("Provide --file <path> or --stdin to specify the tools JSON input");
    };

    serde_json::from_str(&content).context("Failed to parse input as JSON")
}
