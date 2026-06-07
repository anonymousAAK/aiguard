use serde::{Deserialize, Serialize};

use crate::error::Result;

// ---------------------------------------------------------------------------
// AgentKind
// ---------------------------------------------------------------------------

/// Identifies which coding agent is being monitored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    ClaudeCode,
    Codex,
    Gemini,
    Crush,
    Opencode,
    Cline,
    Aider,
    Goose,
}

impl std::fmt::Display for AgentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ClaudeCode => "claude_code",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Crush => "crush",
            Self::Opencode => "opencode",
            Self::Cline => "cline",
            Self::Aider => "aider",
            Self::Goose => "goose",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// Where in the tool-call lifecycle we are scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Before the tool executes.
    PreTool,
    /// After the tool executes, inspecting its output.
    PostTool,
    /// Scanning the user's prompt before it reaches the agent.
    UserPrompt,
    /// At session start (e.g. checking environment).
    SessionStart,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::PreTool => "pre_tool",
            Self::PostTool => "post_tool",
            Self::UserPrompt => "user_prompt",
            Self::SessionStart => "session_start",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ScanContext
// ---------------------------------------------------------------------------

/// Everything a scanner needs to make its decision.
#[derive(Debug, Clone)]
pub struct ScanContext<'a> {
    /// Unique session identifier.
    pub session_id: &'a str,

    /// Which coding agent is being monitored.
    pub agent: AgentKind,

    /// Where in the lifecycle we are.
    pub stage: Stage,

    /// Name of the tool being invoked (if applicable).
    pub tool_name: Option<&'a str>,

    /// JSON input to the tool (if applicable).
    pub tool_input: Option<&'a serde_json::Value>,

    /// JSON response from the tool (post-tool only).
    pub tool_response: Option<&'a serde_json::Value>,

    /// Raw text content (e.g. the user prompt, or a file being read).
    pub raw_text: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Hit
// ---------------------------------------------------------------------------

/// A specific match found by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    /// Identifier for the rule that matched (e.g. "PI-001", "SECRET-AWS").
    pub rule_id: String,

    /// The text that matched the rule.
    pub matched_text: String,

    /// Byte offset into the scanned content where the match starts.
    pub offset: usize,

    /// Length of the match in bytes.
    pub length: usize,
}

// ---------------------------------------------------------------------------
// ScanVerdict
// ---------------------------------------------------------------------------

/// The outcome of a single scanner's evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanVerdict {
    /// Nothing suspicious found.
    Pass,

    /// Something looks off but doesn't warrant blocking.
    Warn {
        message: String,
        score: f32,
        hits: Vec<Hit>,
    },

    /// The action must be blocked.
    Block {
        message: String,
        score: f32,
        hits: Vec<Hit>,
    },

    /// Rewrite the tool input/output before passing it on.
    Mutate {
        replacement: serde_json::Value,
        message: String,
    },
}

impl ScanVerdict {
    /// Numeric severity for ordering: Pass=0, Warn=1, Mutate=2, Block=3.
    pub fn severity(&self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn { .. } => 1,
            Self::Mutate { .. } => 2,
            Self::Block { .. } => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Scanner trait
// ---------------------------------------------------------------------------

/// Trait that all scanners must implement.
///
/// Scanners are stateless evaluators: given a `ScanContext`, they return a
/// `ScanVerdict`. The policy engine runs all enabled scanners and aggregates
/// their verdicts into a final `Decision`.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    /// A unique, human-readable name for this scanner (e.g. "prompt_injection").
    fn name(&self) -> &'static str;

    /// Evaluate the given context and return a verdict.
    async fn scan(&self, ctx: &ScanContext<'_>) -> Result<ScanVerdict>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        let pass = ScanVerdict::Pass;
        let warn = ScanVerdict::Warn {
            message: "test".into(),
            score: 0.5,
            hits: vec![],
        };
        let mutate = ScanVerdict::Mutate {
            replacement: serde_json::Value::Null,
            message: "test".into(),
        };
        let block = ScanVerdict::Block {
            message: "test".into(),
            score: 0.9,
            hits: vec![],
        };

        assert!(pass.severity() < warn.severity());
        assert!(warn.severity() < mutate.severity());
        assert!(mutate.severity() < block.severity());
    }

    #[test]
    fn scan_verdict_round_trips_json() {
        let v = ScanVerdict::Block {
            message: "injection detected".into(),
            score: 0.95,
            hits: vec![Hit {
                rule_id: "PI-001".into(),
                matched_text: "ignore previous".into(),
                offset: 42,
                length: 15,
            }],
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ScanVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.severity(), 3);
    }
}
