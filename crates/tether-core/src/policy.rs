use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level Policy
// ---------------------------------------------------------------------------

/// Root configuration structure, mirroring `tether.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    /// Schema version string, e.g. "1.0".
    #[serde(default = "default_schema")]
    pub schema: String,

    /// Core policy knobs.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Per-agent configuration.
    #[serde(default)]
    pub agents: AgentsConfig,

    /// Scanner sub-system configuration.
    #[serde(default)]
    pub scanners: ScannersConfig,

    /// Tool allow/deny rules.
    #[serde(default)]
    pub tools: ToolsConfig,

    /// Audit logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Secret redaction settings.
    #[serde(default)]
    pub redact: RedactConfig,

    /// Replay / session-review settings.
    #[serde(default)]
    pub replay: ReplayConfig,
}

fn default_schema() -> String {
    "1.0".to_string()
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema: default_schema(),
            policy: PolicyConfig::default(),
            agents: AgentsConfig::default(),
            scanners: ScannersConfig::default(),
            tools: ToolsConfig::default(),
            logging: LoggingConfig::default(),
            redact: RedactConfig::default(),
            replay: ReplayConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    /// What to do when no scanner explicitly allows or blocks.
    #[serde(default)]
    pub default_action: DefaultAction,

    /// If true, treat any scanner error as a block.
    #[serde(default)]
    pub strict: bool,

    /// If true, allow the action when an internal error occurs (opposite of strict).
    #[serde(default)]
    pub fail_open: bool,

    /// Prompt the user for confirmation on the very first run.
    #[serde(default)]
    pub ask_on_first_run: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: DefaultAction::Warn,
            strict: false,
            fail_open: false,
            ask_on_first_run: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DefaultAction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    #[default]
    Warn,
    Block,
    Allow,
}

impl std::fmt::Display for DefaultAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warn => write!(f, "warn"),
            Self::Block => write!(f, "block"),
            Self::Allow => write!(f, "allow"),
        }
    }
}

// ---------------------------------------------------------------------------
// AgentsConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentsConfig {
    #[serde(default)]
    pub claude_code: AgentEntry,
    #[serde(default)]
    pub codex: AgentEntry,
    #[serde(default)]
    pub gemini: AgentEntry,
    #[serde(default)]
    pub crush: AgentEntry,
    #[serde(default)]
    pub opencode: AgentEntry,
    #[serde(default)]
    pub cline: AgentEntry,
    #[serde(default)]
    pub aider: AgentEntry,
    #[serde(default)]
    pub goose: AgentEntry,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentEntry {
    /// Whether this agent adapter is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Auto-install the hook/adapter on first use.
    #[serde(default)]
    pub auto_install: bool,

    /// Per-agent overrides for tool rules, scanners, etc.
    #[serde(default)]
    pub overrides: AgentOverrides,
}

impl Default for AgentEntry {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_install: false,
            overrides: AgentOverrides::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentOverrides {
    /// Override the default action for this agent only.
    pub default_action: Option<DefaultAction>,

    /// Extra deny patterns specific to this agent.
    #[serde(default)]
    pub extra_deny_shell_patterns: Vec<String>,

    /// Extra allow patterns specific to this agent.
    #[serde(default)]
    pub extra_allow_shell_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// ScannersConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ScannersConfig {
    #[serde(default)]
    pub prompt_injection: PromptInjectionConfig,

    #[serde(default)]
    pub secrets: SecretsConfig,

    #[serde(default)]
    pub mcp: McpScannerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Score threshold above which we block (0.0 - 1.0).
    #[serde(default = "default_pi_threshold")]
    pub threshold: f32,

    /// Action to take when injection is detected.
    #[serde(default)]
    pub action: DefaultAction,

    /// Extra rules / signatures (regex patterns).
    #[serde(default)]
    pub extra_signatures: Vec<String>,
}

fn default_pi_threshold() -> f32 {
    0.7
}

impl Default for PromptInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_pi_threshold(),
            action: DefaultAction::Warn,
            extra_signatures: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Action when a secret is found in tool output.
    #[serde(default = "default_block")]
    pub action: DefaultAction,

    /// Additional regex patterns for custom secret formats.
    #[serde(default)]
    pub extra_patterns: Vec<String>,

    /// Entropy threshold for high-entropy string detection.
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,
}

fn default_block() -> DefaultAction {
    DefaultAction::Block
}

fn default_entropy_threshold() -> f32 {
    4.5
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DefaultAction::Block,
            extra_patterns: Vec::new(),
            entropy_threshold: default_entropy_threshold(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Action when suspicious MCP traffic is detected.
    #[serde(default)]
    pub action: DefaultAction,

    /// Allow-listed MCP server names.
    #[serde(default)]
    pub allowed_servers: Vec<String>,

    /// Deny-listed MCP tool names.
    #[serde(default)]
    pub denied_tools: Vec<String>,
}

impl Default for McpScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DefaultAction::Warn,
            allowed_servers: Vec::new(),
            denied_tools: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ToolsConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolsConfig {
    /// Shell command patterns to deny (glob-style).
    #[serde(default)]
    pub deny_shell_patterns: Vec<String>,

    /// Shell command patterns to allow (glob-style). Checked after deny.
    #[serde(default)]
    pub allow_shell_patterns: Vec<String>,

    /// File path patterns to deny.
    #[serde(default)]
    pub deny_path_patterns: Vec<String>,

    /// File path patterns to allow. Checked after deny.
    #[serde(default)]
    pub allow_path_patterns: Vec<String>,

    /// Per-tool overrides: tool_name -> action.
    #[serde(default)]
    pub tool_overrides: HashMap<String, DefaultAction>,
}

// ---------------------------------------------------------------------------
// LoggingConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Directory for JSONL audit files.
    #[serde(default = "default_audit_dir")]
    pub audit_dir: String,

    /// Path to the SQLite audit database.
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,

    /// How many days to retain audit records before pruning.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Log level for the tracing subscriber.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_audit_dir() -> String {
    "~/.local/share/tether/audit".to_string()
}

fn default_sqlite_path() -> String {
    "~/.local/share/tether/audit.db".to_string()
}

fn default_retention_days() -> u32 {
    90
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            audit_dir: default_audit_dir(),
            sqlite_path: default_sqlite_path(),
            retention_days: default_retention_days(),
            log_level: default_log_level(),
        }
    }
}

// ---------------------------------------------------------------------------
// RedactConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedactConfig {
    /// Regex patterns for secrets to redact.
    #[serde(default = "default_redact_patterns")]
    pub patterns: Vec<RedactPattern>,

    /// Replacement template. Use `{rule}` as placeholder for the rule name.
    #[serde(default = "default_replacement_template")]
    pub replacement_template: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedactPattern {
    /// A human-readable name for this rule.
    pub name: String,
    /// The regex pattern to match.
    pub regex: String,
}

fn default_redact_patterns() -> Vec<RedactPattern> {
    vec![
        RedactPattern {
            name: "aws_key".to_string(),
            regex: r"AKIA[0-9A-Z]{16}".to_string(),
        },
        RedactPattern {
            name: "github_token".to_string(),
            regex: r"gh[pousr]_[A-Za-z0-9_]{36,}".to_string(),
        },
        RedactPattern {
            name: "generic_secret".to_string(),
            regex: r#"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*["']?[^\s"']{8,}"#
                .to_string(),
        },
    ]
}

fn default_replacement_template() -> String {
    "[REDACTED:{rule}]".to_string()
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            patterns: default_redact_patterns(),
            replacement_template: default_replacement_template(),
        }
    }
}

// ---------------------------------------------------------------------------
// ReplayConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReplayConfig {
    /// Session id to load by default in the TUI.
    #[serde(default)]
    pub default_session: Option<String>,

    /// TUI color theme.
    #[serde(default = "default_theme")]
    pub theme: String,

    /// Whether to mask secrets in the replay view.
    #[serde(default = "default_true")]
    pub mask_secrets: bool,
}

fn default_theme() -> String {
    "dark".to_string()
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            default_session: None,
            theme: default_theme(),
            mask_secrets: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_round_trips_through_toml() {
        let policy = Policy::default();
        let toml_str = toml::to_string_pretty(&policy).expect("serialize");
        let parsed: Policy = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(parsed.schema, "1.0");
        assert!(!parsed.policy.strict);
        assert_eq!(parsed.policy.default_action, DefaultAction::Warn);
    }

    #[test]
    fn deserialize_minimal_toml() {
        let input = r#"
            schema = "1.0"
            [policy]
            default_action = "block"
        "#;
        let policy: Policy = toml::from_str(input).expect("parse");
        assert_eq!(policy.policy.default_action, DefaultAction::Block);
        // Everything else should be defaults
        assert!(policy.agents.claude_code.enabled);
        assert_eq!(policy.logging.retention_days, 90);
    }
}
