use anyhow::anyhow;
use serde_json::{json, Value};

use crate::normalize::{HookEvent, HookEventType, HookResponse, Normalizer};

/// Normalizer for the Crush agent shell hooks.
///
/// Crush uses the `event` field for event type. Only PreToolUse is meaningful;
/// PostToolUse always returns Allow (Crush does not support post-tool hooks).
pub struct CrushNormalizer;

impl Normalizer for CrushNormalizer {
    fn parse(&self, raw: Value) -> anyhow::Result<HookEvent> {
        let event_name = raw
            .get("event")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing event field"))?;

        let event_type = match event_name {
            "PreToolUse" | "pre_tool_use" => HookEventType::PreToolUse,
            "PostToolUse" | "post_tool_use" => HookEventType::PostToolUse,
            "SessionStart" | "session_start" => HookEventType::SessionStart,
            "UserPromptSubmit" | "user_prompt_submit" => HookEventType::UserPromptSubmit,
            "Stop" | "stop" => HookEventType::Stop,
            other => return Err(anyhow!("unknown event: {}", other)),
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

        let project_dir = std::env::var("CRUSH_PROJECT_DIR").ok();

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
            HookResponse::Allow => (json!({"decision": "allow"}), 0),
            // Crush does not support context injection; treat as allow.
            HookResponse::AllowWithContext(_) => (json!({"decision": "allow"}), 0),
            HookResponse::Block { message } => (json!({"decision": "block", "reason": message}), 2),
            HookResponse::Mutate { updated_input, .. } => {
                if let Some(input) = updated_input {
                    (json!({"decision": "allow", "updatedInput": input}), 0)
                } else {
                    (json!({"decision": "allow"}), 0)
                }
            }
        }
    }

    fn agent_kind(&self) -> aiguard_core::AgentKind {
        aiguard_core::AgentKind::Crush
    }
}

/// Known tool names for Crush.
pub const TOOL_NAMES: &[&str] = &["bash", "edit", "write", "multiedit", "view", "grep", "glob"];
