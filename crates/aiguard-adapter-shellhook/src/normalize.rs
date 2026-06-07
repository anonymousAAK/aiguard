use serde_json::Value;

/// Canonical hook event parsed from agent-specific stdin JSON.
#[derive(Debug, Clone)]
pub struct HookEvent {
    pub session_id: String,
    pub event_type: HookEventType,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub tool_response: Option<Value>,
    pub project_dir: Option<String>,
    pub raw: Value,
}

/// The type of hook event being processed.
#[derive(Debug, Clone, PartialEq)]
pub enum HookEventType {
    PreToolUse,
    PostToolUse,
    SessionStart,
    UserPromptSubmit,
    Stop,
}

/// Canonical response that the hook handler returns.
#[derive(Debug, Clone)]
pub enum HookResponse {
    Allow,
    AllowWithContext(String),
    Block {
        message: String,
    },
    Mutate {
        updated_input: Option<Value>,
        updated_output: Option<Value>,
    },
}

/// Trait that each agent normalizer must implement.
///
/// Normalizers translate between agent-specific wire formats and
/// the canonical `HookEvent` / `HookResponse` types.
pub trait Normalizer: Send + Sync {
    /// Parse raw stdin JSON into a canonical `HookEvent`.
    fn parse(&self, raw: Value) -> anyhow::Result<HookEvent>;

    /// Format a `HookResponse` into (JSON body, exit code) for the agent.
    fn format_response(&self, response: &HookResponse) -> (Value, i32);

    /// Which agent kind this normalizer handles.
    fn agent_kind(&self) -> aiguard_core::AgentKind;
}
