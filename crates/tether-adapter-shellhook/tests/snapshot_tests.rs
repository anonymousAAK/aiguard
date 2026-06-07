//! Insta snapshot tests for all shell-hook normalizers.
//!
//! Each normalizer is tested for:
//! - Parsing every event type
//! - Formatting every response variant

use insta::assert_yaml_snapshot;
use serde_json::json;

use aiguard_adapter_shellhook::claude_code::ClaudeCodeNormalizer;
use aiguard_adapter_shellhook::cline::ClineNormalizer;
use aiguard_adapter_shellhook::codex::CodexNormalizer;
use aiguard_adapter_shellhook::crush::CrushNormalizer;
use aiguard_adapter_shellhook::gemini::GeminiNormalizer;
use aiguard_adapter_shellhook::normalize::{HookResponse, Normalizer};

// ---------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------

#[test]
fn claude_code_parse_pre_tool_use() {
    let n = ClaudeCodeNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "PreToolUse",
            "session_id": "sess-123",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "claude_code_pre_tool_use",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
            "tool_input": event.tool_input,
        })
    );
}

#[test]
fn claude_code_parse_post_tool_use() {
    let n = ClaudeCodeNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-123",
            "tool_name": "Bash",
            "tool_response": {"stdout": "hello world"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "claude_code_post_tool_use",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
            "tool_response": event.tool_response,
        })
    );
}

#[test]
fn claude_code_parse_session_start() {
    let n = ClaudeCodeNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "SessionStart",
            "session_id": "sess-abc"
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "claude_code_session_start",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
        })
    );
}

#[test]
fn claude_code_parse_user_prompt() {
    let n = ClaudeCodeNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "sess-abc"
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "claude_code_user_prompt",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
        })
    );
}

#[test]
fn claude_code_response_allow() {
    let n = ClaudeCodeNormalizer;
    let (json, code) = n.format_response(&HookResponse::Allow);
    assert_yaml_snapshot!(
        "claude_code_resp_allow",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn claude_code_response_allow_with_context() {
    let n = ClaudeCodeNormalizer;
    let (json, code) = n.format_response(&HookResponse::AllowWithContext(
        "aiguard: scanned, no issues found".to_string(),
    ));
    assert_yaml_snapshot!(
        "claude_code_resp_context",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn claude_code_response_block() {
    let n = ClaudeCodeNormalizer;
    let (json, code) = n.format_response(&HookResponse::Block {
        message: "denied by aiguard: rm -rf / matched deny rule".to_string(),
    });
    assert_yaml_snapshot!(
        "claude_code_resp_block",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn claude_code_response_mutate_output() {
    let n = ClaudeCodeNormalizer;
    let (json, code) = n.format_response(&HookResponse::Mutate {
        updated_input: None,
        updated_output: Some(json!("[REDACTED]")),
    });
    assert_yaml_snapshot!(
        "claude_code_resp_mutate_output",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn claude_code_response_mutate_input() {
    let n = ClaudeCodeNormalizer;
    let (json, code) = n.format_response(&HookResponse::Mutate {
        updated_input: Some(json!({"command": "echo safe"})),
        updated_output: None,
    });
    assert_yaml_snapshot!(
        "claude_code_resp_mutate_input",
        json!({"body": json, "exit_code": code})
    );
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

#[test]
fn codex_parse_pre_tool_use() {
    let n = CodexNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "PreToolUse",
            "session_id": "codex-sess",
            "tool_name": "apply_patch",
            "tool_input": {"patch": "diff --git a/foo"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "codex_pre_tool_use",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
            "tool_input": event.tool_input,
        })
    );
}

#[test]
fn codex_response_context_downgraded() {
    let n = CodexNormalizer;
    // Codex rejects additionalContext — should downgrade to plain allow
    let (json, code) = n.format_response(&HookResponse::AllowWithContext(
        "this context is rejected by codex".to_string(),
    ));
    assert_yaml_snapshot!(
        "codex_resp_context_downgraded",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn codex_response_block() {
    let n = CodexNormalizer;
    let (json, code) = n.format_response(&HookResponse::Block {
        message: "blocked by policy".to_string(),
    });
    assert_yaml_snapshot!("codex_resp_block", json!({"body": json, "exit_code": code}));
}

// ---------------------------------------------------------------------------
// Gemini
// ---------------------------------------------------------------------------

#[test]
fn gemini_parse_before_tool() {
    let n = GeminiNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "BeforeTool",
            "session_id": "gem-sess",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "cat /etc/passwd"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "gemini_before_tool",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
        })
    );
}

#[test]
fn gemini_parse_after_tool() {
    let n = GeminiNormalizer;
    let event = n
        .parse(json!({
            "hook_event_name": "AfterTool",
            "session_id": "gem-sess",
            "tool_name": "read_file",
            "tool_response": {"content": "file data"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "gemini_after_tool",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
        })
    );
}

#[test]
fn gemini_response_approve() {
    let n = GeminiNormalizer;
    let (json, code) = n.format_response(&HookResponse::Allow);
    assert_yaml_snapshot!(
        "gemini_resp_approve",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn gemini_response_deny() {
    let n = GeminiNormalizer;
    let (json, code) = n.format_response(&HookResponse::Block {
        message: "path /etc/passwd denied".to_string(),
    });
    assert_yaml_snapshot!("gemini_resp_deny", json!({"body": json, "exit_code": code}));
}

#[test]
fn gemini_response_context() {
    let n = GeminiNormalizer;
    let (json, code) =
        n.format_response(&HookResponse::AllowWithContext("scanned clean".to_string()));
    assert_yaml_snapshot!(
        "gemini_resp_context",
        json!({"body": json, "exit_code": code})
    );
}

// ---------------------------------------------------------------------------
// Crush
// ---------------------------------------------------------------------------

#[test]
fn crush_parse_pre_tool() {
    let n = CrushNormalizer;
    let event = n
        .parse(json!({
            "event": "PreToolUse",
            "session_id": "crush-sess",
            "tool_name": "bash",
            "tool_input": {"command": "ls"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "crush_pre_tool",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
        })
    );
}

#[test]
fn crush_parse_snake_case_event() {
    let n = CrushNormalizer;
    let event = n
        .parse(json!({
            "event": "pre_tool_use",
            "session_id": "crush-sess",
            "tool_name": "edit"
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "crush_snake_case_event",
        json!({
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
        })
    );
}

#[test]
fn crush_response_allow() {
    let n = CrushNormalizer;
    let (json, code) = n.format_response(&HookResponse::Allow);
    assert_yaml_snapshot!("crush_resp_allow", json!({"body": json, "exit_code": code}));
}

#[test]
fn crush_response_block() {
    let n = CrushNormalizer;
    let (json, code) = n.format_response(&HookResponse::Block {
        message: "denied".to_string(),
    });
    assert_yaml_snapshot!("crush_resp_block", json!({"body": json, "exit_code": code}));
}

#[test]
fn crush_response_context_downgraded() {
    // Crush doesn't support context — should downgrade to allow
    let n = CrushNormalizer;
    let (json, code) = n.format_response(&HookResponse::AllowWithContext("ignored".to_string()));
    assert_yaml_snapshot!(
        "crush_resp_context_downgraded",
        json!({"body": json, "exit_code": code})
    );
}

// ---------------------------------------------------------------------------
// Cline
// ---------------------------------------------------------------------------

#[test]
fn cline_parse_pre_tool() {
    let n = ClineNormalizer;
    let event = n
        .parse(json!({
            "hookName": "preToolUse",
            "sessionId": "cline-sess",
            "toolName": "Bash",
            "toolInput": {"command": "whoami"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "cline_pre_tool",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
            "tool_input": event.tool_input,
        })
    );
}

#[test]
fn cline_parse_post_tool() {
    let n = ClineNormalizer;
    let event = n
        .parse(json!({
            "hookName": "postToolUse",
            "sessionId": "cline-sess",
            "toolName": "Read",
            "toolResponse": {"content": "data"}
        }))
        .unwrap();
    assert_yaml_snapshot!(
        "cline_post_tool",
        json!({
            "session_id": event.session_id,
            "event_type": format!("{:?}", event.event_type),
            "tool_name": event.tool_name,
        })
    );
}

#[test]
fn cline_response_allow() {
    let n = ClineNormalizer;
    let (json, code) = n.format_response(&HookResponse::Allow);
    assert_yaml_snapshot!("cline_resp_allow", json!({"body": json, "exit_code": code}));
}

#[test]
fn cline_response_cancel() {
    let n = ClineNormalizer;
    let (json, code) = n.format_response(&HookResponse::Block {
        message: "blocked by aiguard".to_string(),
    });
    assert_yaml_snapshot!(
        "cline_resp_cancel",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn cline_response_context() {
    let n = ClineNormalizer;
    let (json, code) = n.format_response(&HookResponse::AllowWithContext(
        "aiguard: all clear".to_string(),
    ));
    assert_yaml_snapshot!(
        "cline_resp_context",
        json!({"body": json, "exit_code": code})
    );
}

#[test]
fn cline_response_mutate() {
    let n = ClineNormalizer;
    let (json, code) = n.format_response(&HookResponse::Mutate {
        updated_input: Some(json!({"command": "echo safe"})),
        updated_output: None,
    });
    assert_yaml_snapshot!(
        "cline_resp_mutate",
        json!({"body": json, "exit_code": code})
    );
}
