use anyhow::anyhow;
use serde_json::{json, Value};

use crate::normalize::{HookEvent, HookEventType, HookResponse, Normalizer};

/// Normalizer for the Gemini CLI agent shell hooks.
///
/// Gemini uses `BeforeTool` / `AfterTool` event names and returns
/// decisions as `{"decision": "approve"|"deny", ...}`.
pub struct GeminiNormalizer;

impl Normalizer for GeminiNormalizer {
    fn parse(&self, raw: Value) -> anyhow::Result<HookEvent> {
        let event_name = raw
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing hook_event_name field"))?;

        let event_type = match event_name {
            "BeforeTool" => HookEventType::PreToolUse,
            "AfterTool" => HookEventType::PostToolUse,
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

        let project_dir = std::env::var("GEMINI_PROJECT_DIR")
            .or_else(|_| std::env::var("CLAUDE_PROJECT_DIR"))
            .ok();

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
            HookResponse::Allow => (json!({"decision": "approve", "hookSpecificOutput": {}}), 0),
            HookResponse::AllowWithContext(ctx) => (
                json!({"decision": "approve", "hookSpecificOutput": {"additionalContext": ctx}}),
                0,
            ),
            HookResponse::Block { message } => (
                json!({"decision": "deny", "hookSpecificOutput": {"reason": message}}),
                2,
            ),
            HookResponse::Mutate {
                updated_input,
                updated_output,
            } => {
                let mut hook_output = serde_json::Map::new();
                if let Some(input) = updated_input {
                    hook_output.insert("updatedToolInput".to_string(), input.clone());
                }
                if let Some(output) = updated_output {
                    hook_output.insert("updatedToolOutput".to_string(), output.clone());
                }
                (
                    json!({"decision": "approve", "hookSpecificOutput": hook_output}),
                    0,
                )
            }
        }
    }

    fn agent_kind(&self) -> aiguard_core::AgentKind {
        aiguard_core::AgentKind::Gemini
    }
}

/// Known tool names for Gemini CLI.
pub const TOOL_NAMES: &[&str] = &["read_file", "write_file", "replace", "run_shell_command"];
