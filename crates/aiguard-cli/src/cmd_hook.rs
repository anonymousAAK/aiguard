//! `aiguard hook <agent> <stage>` — The hook entry point (hot path).
//!
//! This is called by agent shell hooks. It:
//! 1. Reads stdin to get the JSON payload
//! 2. Parses the agent and stage from CLI args
//! 3. Creates a PolicyEngine with loaded config
//! 4. Runs the scanner pipeline
//! 5. Writes a response JSON to stdout
//! 6. Sets the exit code (0 = allow, 2 = block)

use std::io::{self, Read};
use std::process;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use aiguard_core::{
    load_policy, AgentKind, AuditLog, Decision, PolicyEngine, Redactor, ScanContext, Scanner, Stage,
};

#[derive(Parser)]
pub struct HookArgs {
    /// The agent invoking the hook (e.g. claude-code, codex, gemini)
    agent: String,

    /// The lifecycle stage (pre_tool, post_tool, user_prompt, session_start)
    stage: String,

    /// Tool name override (if not embedded in stdin JSON)
    #[arg(long)]
    tool: Option<String>,
}

pub async fn run(args: HookArgs) -> Result<()> {
    // 1. Read stdin
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read from stdin")?;

    // 2. Parse agent and stage
    let agent = parse_agent(&args.agent)?;
    let stage = parse_stage(&args.stage)?;

    // 3. Parse input JSON
    let payload: serde_json::Value = if input.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(&input).context("Failed to parse stdin as JSON")?
    };

    // 4. Load policy and create engine
    let policy = load_policy()?;

    let scanners: Vec<Arc<dyn Scanner>> = build_scanners(&policy);
    let audit = AuditLog::open(&policy.logging)?;
    let redactor = Redactor::from_config(&policy.redact)?;
    let engine = PolicyEngine::new(policy, scanners, audit, redactor)?;

    // 5. Build scan context
    let tool_name = args
        .tool
        .as_deref()
        .or_else(|| payload.get("tool").and_then(|v| v.as_str()));

    let session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let tool_input = payload.get("input");
    let tool_response = payload.get("output");
    let raw_text = payload.get("text").and_then(|v| v.as_str());

    let ctx = ScanContext {
        session_id,
        agent,
        stage,
        tool_name,
        tool_input,
        tool_response,
        raw_text,
    };

    // 6. Evaluate
    let decision = engine.evaluate(&ctx).await?;

    // 7. Build response
    let response = build_response(&decision);
    let output = serde_json::to_string(&response)?;
    println!("{output}");

    // 8. Set exit code
    match decision {
        Decision::Block(_) => process::exit(2),
        Decision::Mutate(_) => process::exit(0),
        _ => process::exit(0),
    }
}

/// Parse agent string into AgentKind.
fn parse_agent(s: &str) -> Result<AgentKind> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "claude_code" | "claude" => Ok(AgentKind::ClaudeCode),
        "codex" => Ok(AgentKind::Codex),
        "gemini" => Ok(AgentKind::Gemini),
        "crush" => Ok(AgentKind::Crush),
        "opencode" => Ok(AgentKind::Opencode),
        "cline" => Ok(AgentKind::Cline),
        "aider" => Ok(AgentKind::Aider),
        "goose" => Ok(AgentKind::Goose),
        other => anyhow::bail!("Unknown agent: '{other}'. Valid agents: claude-code, codex, gemini, crush, opencode, cline, aider, goose"),
    }
}

/// Parse stage string into Stage.
fn parse_stage(s: &str) -> Result<Stage> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "pre_tool" | "pretool" => Ok(Stage::PreTool),
        "post_tool" | "posttool" => Ok(Stage::PostTool),
        "user_prompt" | "userprompt" => Ok(Stage::UserPrompt),
        "session_start" | "sessionstart" => Ok(Stage::SessionStart),
        other => anyhow::bail!("Unknown stage: '{other}'. Valid stages: pre_tool, post_tool, user_prompt, session_start"),
    }
}

/// Build the set of scanners based on policy configuration.
fn build_scanners(policy: &aiguard_core::Policy) -> Vec<Arc<dyn Scanner>> {
    let mut scanners: Vec<Arc<dyn Scanner>> = Vec::new();

    if policy.scanners.prompt_injection.enabled {
        match aiguard_scanner_prompt_injection::PromptInjectionScanner::new() {
            Ok(s) => scanners.push(Arc::new(s)),
            Err(e) => tracing::warn!("Failed to initialize prompt injection scanner: {e}"),
        }
    }

    if policy.scanners.secrets.enabled {
        let action = match policy.scanners.secrets.action {
            aiguard_core::DefaultAction::Block => aiguard_scanner_secrets::Action::Block,
            aiguard_core::DefaultAction::Warn => aiguard_scanner_secrets::Action::Warn,
            aiguard_core::DefaultAction::Allow => aiguard_scanner_secrets::Action::Warn,
        };
        match aiguard_scanner_secrets::SecretsScanner::new(
            action,
            policy.scanners.secrets.entropy_threshold,
        ) {
            Ok(s) => scanners.push(Arc::new(s)),
            Err(e) => tracing::warn!("Failed to initialize secrets scanner: {e}"),
        }
    }

    if policy.scanners.mcp.enabled {
        scanners.push(Arc::new(aiguard_scanner_mcp::McpScanner::new()));
    }

    scanners
}

/// Build the JSON response for the hook caller.
fn build_response(decision: &Decision) -> serde_json::Value {
    match decision {
        Decision::Allow => serde_json::json!({
            "action": "allow",
        }),
        Decision::AllowWithContext(ctx) => serde_json::json!({
            "action": "allow",
            "context": ctx,
        }),
        Decision::Mutate(replacement) => serde_json::json!({
            "action": "mutate",
            "replacement": replacement,
        }),
        Decision::Block(reason) => serde_json::json!({
            "action": "block",
            "reason": reason,
        }),
        Decision::Ask => serde_json::json!({
            "action": "ask",
            "message": "Manual approval required",
        }),
    }
}
