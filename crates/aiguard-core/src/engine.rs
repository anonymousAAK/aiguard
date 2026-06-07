use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use regex::Regex;
use tracing::{debug, info, warn};

use crate::audit::{AuditEvent, AuditLog};
use crate::decision::{self, Decision};
use crate::error::{Result, AiguardError};
use crate::policy::Policy;
use crate::redact::Redactor;
use crate::scanner::{ScanContext, ScanVerdict, Scanner};

/// The main policy engine that ties together scanners, audit logging,
/// tool allow/deny rules, and secret redaction.
pub struct PolicyEngine {
    policy: Policy,
    scanners: Vec<Arc<dyn Scanner>>,
    audit: AuditLog,
    redactor: Redactor,
    deny_shell: Vec<Regex>,
    allow_shell: Vec<Regex>,
    deny_path: Vec<Regex>,
    allow_path: Vec<Regex>,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policy_schema", &self.policy.schema)
            .field("scanner_count", &self.scanners.len())
            .field("deny_shell_count", &self.deny_shell.len())
            .field("allow_shell_count", &self.allow_shell.len())
            .finish_non_exhaustive()
    }
}

impl PolicyEngine {
    /// Build a new policy engine from its components.
    pub fn new(
        policy: Policy,
        scanners: Vec<Arc<dyn Scanner>>,
        audit: AuditLog,
        redactor: Redactor,
    ) -> Result<Self> {
        let deny_shell = compile_patterns(&policy.tools.deny_shell_patterns)?;
        let allow_shell = compile_patterns(&policy.tools.allow_shell_patterns)?;
        let deny_path = compile_patterns(&policy.tools.deny_path_patterns)?;
        let allow_path = compile_patterns(&policy.tools.allow_path_patterns)?;

        Ok(Self {
            policy,
            scanners,
            audit,
            redactor,
            deny_shell,
            allow_shell,
            deny_path,
            allow_path,
        })
    }

    /// Create a minimal engine with no scanners and in-memory audit (for testing).
    pub fn noop(policy: Policy) -> Result<Self> {
        let audit = AuditLog::open_in_memory()?;
        let redactor = Redactor::noop();
        Self::new(policy, Vec::new(), audit, redactor)
    }

    /// Evaluate a scan context: run tool rules, scanners, aggregate, audit, return.
    pub async fn evaluate(&self, ctx: &ScanContext<'_>) -> Result<Decision> {
        let start = Instant::now();

        // ---- Fast path: check tool deny/allow rules ----
        if let Some(tool_name) = ctx.tool_name {
            // Check per-tool overrides
            if let Some(action) = self.policy.tools.tool_overrides.get(tool_name) {
                match action {
                    crate::policy::DefaultAction::Block => {
                        let decision = Decision::Block(format!(
                            "tool `{tool_name}` is explicitly blocked by policy"
                        ));
                        self.record_event(ctx, &decision, &[], start).ok();
                        return Ok(decision);
                    }
                    crate::policy::DefaultAction::Allow => {
                        let decision = Decision::Allow;
                        self.record_event(ctx, &decision, &[], start).ok();
                        return Ok(decision);
                    }
                    crate::policy::DefaultAction::Warn => {
                        // Fall through to scanners
                    }
                }
            }

            // Check shell command patterns for shell-like tools.
            if let Some(input) = ctx.tool_input {
                if let Some(cmd) = extract_command(input) {
                    if let Some(pattern) = matches_any(&cmd, &self.deny_shell) {
                        // Denied -- check if an allow pattern rescues it.
                        if !matches_any_bool(&cmd, &self.allow_shell) {
                            let decision = Decision::Block(format!(
                                "shell command matched deny pattern `{pattern}`"
                            ));
                            self.record_event(ctx, &decision, &[], start).ok();
                            return Ok(decision);
                        }
                    }
                }

                // Check path patterns for file-operation tools.
                if let Some(path) = extract_path(input) {
                    if let Some(pattern) = matches_any(&path, &self.deny_path) {
                        if !matches_any_bool(&path, &self.allow_path) {
                            let decision =
                                Decision::Block(format!("path matched deny pattern `{pattern}`"));
                            self.record_event(ctx, &decision, &[], start).ok();
                            return Ok(decision);
                        }
                    }
                }
            }
        }

        // ---- Run all scanners concurrently ----
        let mut verdicts: Vec<(String, ScanVerdict)> = Vec::with_capacity(self.scanners.len());

        let futures: Vec<_> = self
            .scanners
            .iter()
            .map(|s| {
                let scanner = Arc::clone(s);
                async move {
                    let name = scanner.name().to_string();
                    let result = scanner.scan(ctx).await;
                    (name, result)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (name, result) in results {
            match result {
                Ok(verdict) => {
                    debug!(scanner = %name, severity = verdict.severity(), "scanner completed");
                    verdicts.push((name, verdict));
                }
                Err(err) => {
                    warn!(scanner = %name, error = %err, "scanner error");
                    if self.policy.policy.strict {
                        let decision = Decision::Block(format!(
                            "scanner `{name}` failed and strict mode is on: {err}"
                        ));
                        self.record_event(ctx, &decision, &verdicts, start).ok();
                        return Ok(decision);
                    }
                    if self.policy.policy.fail_open {
                        verdicts.push((name, ScanVerdict::Pass));
                    } else {
                        verdicts.push((
                            name.clone(),
                            ScanVerdict::Warn {
                                message: format!("scanner `{name}` errored: {err}"),
                                score: 0.0,
                                hits: vec![],
                            },
                        ));
                    }
                }
            }
        }

        // ---- Aggregate verdicts ----
        let raw_verdicts: Vec<ScanVerdict> = verdicts.iter().map(|(_, v)| v.clone()).collect();
        let decision = decision::aggregate(&raw_verdicts);

        // Apply default_action semantics when everything passes.
        let decision = if matches!(decision, Decision::Allow) {
            match self.policy.policy.default_action {
                crate::policy::DefaultAction::Allow => Decision::Allow,
                crate::policy::DefaultAction::Warn => Decision::Allow,
                crate::policy::DefaultAction::Block => Decision::Ask,
            }
        } else {
            decision
        };

        info!(decision = %decision, duration_us = start.elapsed().as_micros() as u64, "evaluation complete");

        // ---- Audit ----
        self.record_event(ctx, &decision, &verdicts, start).ok();

        Ok(decision)
    }

    /// Record an audit event. Errors are logged but not propagated to the caller.
    fn record_event(
        &self,
        ctx: &ScanContext<'_>,
        decision: &Decision,
        verdicts: &[(String, ScanVerdict)],
        start: Instant,
    ) -> Result<()> {
        let scanner_map: serde_json::Value = verdicts
            .iter()
            .map(|(name, v)| (name.clone(), serde_json::to_value(v).unwrap_or_default()))
            .collect::<serde_json::Map<String, serde_json::Value>>()
            .into();

        // Build the payload from the tool input, redacting secrets.
        let payload = ctx.tool_input.map(|input| {
            let raw = serde_json::to_string(input).unwrap_or_default();
            let (redacted, _) = self.redactor.redact(&raw);
            redacted.into_bytes()
        });

        let input_bytes = ctx
            .tool_input
            .map(|v| serde_json::to_vec(v).unwrap_or_default())
            .unwrap_or_default();

        let event = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            session_id: ctx.session_id.to_string(),
            agent: ctx.agent.to_string(),
            stage: ctx.stage.to_string(),
            tool_name: ctx.tool_name.map(String::from),
            decision: decision.label().to_string(),
            scanners: scanner_map,
            duration_us: start.elapsed().as_micros() as u64,
            input_hash: AuditEvent::hash_input(&input_bytes),
            payload,
        };

        self.audit.log_event(&event)
    }

    /// Get a reference to the loaded policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Get a reference to the redactor.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Get a reference to the audit log.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Prune old audit records according to retention policy.
    pub fn prune_audit(&self) -> Result<u64> {
        self.audit.prune()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compile a list of glob-style patterns into regexes.
fn compile_patterns(patterns: &[String]) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| {
            let regex_str = glob_to_regex(p);
            Regex::new(&regex_str).map_err(AiguardError::from)
        })
        .collect()
}

/// Convert a simple glob pattern to a regex string.
fn glob_to_regex(glob: &str) -> String {
    let mut regex = String::with_capacity(glob.len() * 2 + 2);
    regex.push('^');
    for ch in glob.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    regex
}

/// Check if `text` matches any of the compiled patterns.
/// Returns the regex source of the first match.
fn matches_any(text: &str, patterns: &[Regex]) -> Option<String> {
    for pat in patterns {
        if pat.is_match(text) {
            return Some(pat.to_string());
        }
    }
    None
}

/// Check if `text` matches any of the compiled patterns (bool version).
fn matches_any_bool(text: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|p| p.is_match(text))
}

/// Try to extract a shell command string from a tool input JSON value.
fn extract_command(input: &serde_json::Value) -> Option<String> {
    for key in &["command", "cmd", "shell", "script", "input"] {
        if let Some(val) = input.get(key) {
            if let Some(s) = val.as_str() {
                return Some(s.to_string());
            }
        }
    }
    input.as_str().map(String::from)
}

/// Try to extract a file path from a tool input JSON value.
fn extract_path(input: &serde_json::Value) -> Option<String> {
    for key in &["path", "file", "file_path", "filename", "target"] {
        if let Some(val) = input.get(key) {
            if let Some(s) = val.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_to_regex_basic() {
        assert_eq!(glob_to_regex("rm -rf *"), "^rm -rf .*$");
        assert_eq!(glob_to_regex("*.env"), "^.*\\.env$");
        assert_eq!(glob_to_regex("/etc/passwd"), "^/etc/passwd$");
    }

    #[test]
    fn extract_command_from_json() {
        let input = serde_json::json!({"command": "ls -la"});
        assert_eq!(extract_command(&input), Some("ls -la".into()));

        let input = serde_json::json!({"cmd": "echo hello"});
        assert_eq!(extract_command(&input), Some("echo hello".into()));

        let input = serde_json::json!({"irrelevant": 42});
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn extract_path_from_json() {
        let input = serde_json::json!({"file_path": "/etc/shadow"});
        assert_eq!(extract_path(&input), Some("/etc/shadow".into()));
    }

    #[test]
    fn deny_pattern_matching() {
        let patterns = compile_patterns(&["rm -rf *".to_string(), "curl *".to_string()]).unwrap();

        assert!(matches_any("rm -rf /", &patterns).is_some());
        assert!(matches_any("curl http://evil.com", &patterns).is_some());
        assert!(matches_any("ls -la", &patterns).is_none());
    }

    #[tokio::test]
    async fn noop_engine_allows_everything() {
        let policy = Policy::default();
        let engine = PolicyEngine::noop(policy).unwrap();

        let ctx = ScanContext {
            session_id: "test",
            agent: crate::scanner::AgentKind::Codex,
            stage: crate::scanner::Stage::PreTool,
            tool_name: Some("bash"),
            tool_input: Some(&serde_json::json!({"command": "echo hello"})),
            tool_response: None,
            raw_text: None,
        };

        let decision = engine.evaluate(&ctx).await.unwrap();
        assert!(matches!(decision, Decision::Allow));
    }
}
