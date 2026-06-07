use anyhow::anyhow;
use serde_json::{json, Value};

use crate::normalize::{HookEvent, HookEventType, HookResponse, Normalizer};

/// Normalizer for the Claude Code agent shell hooks.
pub struct ClaudeCodeNormalizer;

impl Normalizer for ClaudeCodeNormalizer {
    fn parse(&self, raw: Value) -> anyhow::Result<HookEvent> {
        let event_name = raw
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing hook_event_name field"))?;

        let event_type = match event_name {
            "PreToolUse" => HookEventType::PreToolUse,
            "PostToolUse" => HookEventType::PostToolUse,
            "SessionStart" => HookEventType::SessionStart,
            "UserPromptSubmit" => HookEventType::UserPromptSubmit,
            "Stop" => HookEventType::Stop,
            other => return Err(anyhow!("unknown hook_event_name: {}", other)),
        };

        let session_id = raw
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let tool_name = raw
            .get("tool_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let tool_input = raw.get("tool_input").cloned();
        let tool_response = raw.get("tool_response").cloned();

        let project_dir = std::env::var("CLAUDE_PROJECT_DIR").ok();

        Ok(HookEvent {
            session_id,
            event_type,
            tool_name,
            tool_input,
            tool_response,
            project_dir,
            raw,
        })
    }

    fn format_response(&self, response: &HookResponse) -> (Value, i32) {
        match response {
            HookResponse::Allow => (
                json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
                0,
            ),
            HookResponse::AllowWithContext(ctx) => {
                (json!({"hookSpecificOutput": {"additionalContext": ctx}}), 0)
            }
            HookResponse::Block { message } => (json!({"error": message}), 2),
            HookResponse::Mutate {
                updated_input,
                updated_output,
            } => {
                if let Some(output) = updated_output {
                    // PostToolUse mutation: updatedToolOutput
                    let output_str = match output.as_str() {
                        Some(s) => s.to_string(),
                        None => serde_json::to_string(output).unwrap_or_default(),
                    };
                    (
                        json!({"hookSpecificOutput": {"updatedToolOutput": output_str}}),
                        0,
                    )
                } else if let Some(input) = updated_input {
                    // PreToolUse mutation: updatedToolInput
                    (
                        json!({"hookSpecificOutput": {"updatedToolInput": input}}),
                        0,
                    )
                } else {
                    (
                        json!({"hookSpecificOutput": {"permissionDecision": "allow"}}),
                        0,
                    )
                }
            }
        }
    }

    fn agent_kind(&self) -> aiguard_core::AgentKind {
        aiguard_core::AgentKind::ClaudeCode
    }
}

/// Known tool names for the agent.
pub const TOOL_NAMES: &[&str] = &[
    "Bash",
    "Write",
    "Edit",
    "Read",
    "Grep",
    "Glob",
    "WebFetch",
    "Task",
    "apply_patch",
];
