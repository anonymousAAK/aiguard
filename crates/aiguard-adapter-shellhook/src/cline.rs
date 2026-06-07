use anyhow::anyhow;
use serde_json::{json, Value};

use crate::normalize::{HookEvent, HookEventType, HookResponse, Normalizer};

/// Normalizer for the Cline agent shell hooks.
///
/// Cline uses camelCase `hookName` field for event type.
/// Response format: `{"cancel": bool, "errorMessage": "...", "contextModification": {...}}`
pub struct ClineNormalizer;

impl Normalizer for ClineNormalizer {
    fn parse(&self, raw: Value) -> anyhow::Result<HookEvent> {
        let hook_name = raw
            .get("hookName")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing hookName field"))?;

        let event_type = match hook_name {
            "preToolUse" => HookEventType::PreToolUse,
            "postToolUse" => HookEventType::PostToolUse,
            "sessionStart" => HookEventType::SessionStart,
            "userPromptSubmit" => HookEventType::UserPromptSubmit,
            "stop" => HookEventType::Stop,
            other => return Err(anyhow!("unknown hookName: {}", other)),
        };

        let session_id = raw
            .get("sessionId")
            .or_else(|| raw.get("session_id"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let tool_name = raw
            .get("toolName")
            .or_else(|| raw.get("tool_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let tool_input = raw
            .get("toolInput")
            .or_else(|| raw.get("tool_input"))
            .cloned();

        let tool_response = raw
            .get("toolResponse")
            .or_else(|| raw.get("tool_response"))
            .cloned();

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
            HookResponse::Allow => (json!({"cancel": false}), 0),
            HookResponse::AllowWithContext(ctx) => (
                json!({
                    "cancel": false,
                    "contextModification": {
                        "additionalContext": ctx
                    }
                }),
                0,
            ),
            HookResponse::Block { message } => (
                json!({
                    "cancel": true,
                    "errorMessage": message
                }),
                0,
            ),
            HookResponse::Mutate {
                updated_input,
                updated_output,
            } => {
                let mut modification = serde_json::Map::new();
                if let Some(input) = updated_input {
                    modification.insert("updatedInput".to_string(), input.clone());
                }
                if let Some(output) = updated_output {
                    modification.insert("updatedOutput".to_string(), output.clone());
                }
                (
                    json!({
                        "cancel": false,
                        "contextModification": modification
                    }),
                    0,
                )
            }
        }
    }

    fn agent_kind(&self) -> aiguard_core::AgentKind {
        aiguard_core::AgentKind::Cline
    }
}
