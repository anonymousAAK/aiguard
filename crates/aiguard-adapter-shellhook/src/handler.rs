use anyhow::{anyhow, Context as _};
use serde_json::Value;
use tracing::debug;

use crate::claude_code::ClaudeCodeNormalizer;
use crate::cline::ClineNormalizer;
use crate::codex::CodexNormalizer;
use crate::crush::CrushNormalizer;
use crate::gemini::GeminiNormalizer;
use crate::normalize::{HookEventType, HookResponse, Normalizer};

/// Main hook handler entry point.
///
/// This function:
/// 1. Selects the correct normalizer for the agent
/// 2. Parses stdin JSON via the normalizer
/// 3. Maps the event type to a `aiguard_core::Stage`
/// 4. Builds a `ScanContext`
/// 5. Calls `engine.evaluate()`
/// 6. Converts the `Decision` to a `HookResponse`
/// 7. Formats via normalizer and returns (JSON, exit_code)
pub async fn handle_hook(
    agent: &str,
    stage: &str,
    stdin_json: Value,
    engine: &aiguard_core::PolicyEngine,
) -> anyhow::Result<(Value, i32)> {
    let normalizer: Box<dyn Normalizer> = get_normalizer(agent)?;

    let event = normalizer
        .parse(stdin_json)
        .context("failed to parse hook event")?;

    debug!(
        agent = agent,
        event_type = ?event.event_type,
        tool = ?event.tool_name,
        "parsed hook event"
    );

    // For Crush PostToolUse, always allow (Crush doesn't support post-tool hooks).
    if agent == "crush" && event.event_type == HookEventType::PostToolUse {
        let response = HookResponse::Allow;
        return Ok(normalizer.format_response(&response));
    }

    // Map event type to aiguard_core::Stage
    let core_stage = map_stage(&event.event_type, stage)?;

    // Build ScanContext
    let tool_name_ref = event.tool_name.as_deref();
    let tool_input_ref = event.tool_input.as_ref();
    let tool_response_ref = event.tool_response.as_ref();

    let ctx = aiguard_core::ScanContext {
        session_id: &event.session_id,
        agent: normalizer.agent_kind(),
        stage: core_stage,
        tool_name: tool_name_ref,
        tool_input: tool_input_ref,
        tool_response: tool_response_ref,
        raw_text: None,
    };

    // Evaluate via policy engine
    let decision = engine
        .evaluate(&ctx)
        .await
        .map_err(|e| anyhow!("policy engine error: {}", e))?;

    debug!(decision = %decision, "policy engine decision");

    // Convert Decision to HookResponse
    let response = decision_to_response(decision, &event.event_type);

    Ok(normalizer.format_response(&response))
}

/// Get the appropriate normalizer for the given agent identifier.
fn get_normalizer(agent: &str) -> anyhow::Result<Box<dyn Normalizer>> {
    match agent {
        "claude-code" | "claude_code" => Ok(Box::new(ClaudeCodeNormalizer)),
        "codex" => Ok(Box::new(CodexNormalizer)),
        "gemini" => Ok(Box::new(GeminiNormalizer)),
        "crush" => Ok(Box::new(CrushNormalizer)),
        "cline" => Ok(Box::new(ClineNormalizer)),
        other => Err(anyhow!("unknown agent: {}", other)),
    }
}

/// Map the hook event type and optional stage hint to a `aiguard_core::Stage`.
fn map_stage(event_type: &HookEventType, _stage_hint: &str) -> anyhow::Result<aiguard_core::Stage> {
    match event_type {
        HookEventType::PreToolUse => Ok(aiguard_core::Stage::PreTool),
        HookEventType::PostToolUse => Ok(aiguard_core::Stage::PostTool),
        HookEventType::SessionStart => Ok(aiguard_core::Stage::SessionStart),
        HookEventType::UserPromptSubmit => Ok(aiguard_core::Stage::UserPrompt),
        HookEventType::Stop => Ok(aiguard_core::Stage::PostTool),
    }
}

/// Convert a `aiguard_core::Decision` to a `HookResponse`.
fn decision_to_response(
    decision: aiguard_core::Decision,
    event_type: &HookEventType,
) -> HookResponse {
    match decision {
        aiguard_core::Decision::Allow => HookResponse::Allow,
        aiguard_core::Decision::AllowWithContext(ctx) => HookResponse::AllowWithContext(ctx),
        aiguard_core::Decision::Block(reason) => HookResponse::Block { message: reason },
        aiguard_core::Decision::Mutate(value) => match event_type {
            HookEventType::PostToolUse => HookResponse::Mutate {
                updated_input: None,
                updated_output: Some(value),
            },
            _ => HookResponse::Mutate {
                updated_input: Some(value),
                updated_output: None,
            },
        },
        aiguard_core::Decision::Ask => {
            // Ask is treated as a block with a special message indicating
            // the user should be prompted.
            HookResponse::Block {
                message: "policy requires manual approval".to_string(),
            }
        }
    }
}
