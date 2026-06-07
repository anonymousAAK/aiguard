use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helper: build a Command targeting the tether binary.
// ---------------------------------------------------------------------------
fn tether() -> Command {
    Command::cargo_bin("aiguard").expect("aiguard binary not found")
}

// ---------------------------------------------------------------------------
// Helper: write a minimal aiguard.toml with deny_shell_patterns to a temp dir
// and return the path.  Used by hook tests that need deterministic blocking.
// ---------------------------------------------------------------------------
fn write_blocking_config(dir: &std::path::Path) -> std::path::PathBuf {
    let cfg = dir.join("aiguard.toml");
    std::fs::write(
        &cfg,
        r#"
schema = "1.0"

[policy]
default_action = "allow"
strict = false
fail_open = false
ask_on_first_run = false

[scanners.prompt_injection]
enabled = false

[scanners.secrets]
enabled = false

[scanners.mcp]
enabled = false

[tools]
deny_shell_patterns = [
    "rm -rf /",
    "rm -rf /*",
]
"#,
    )
    .expect("write aiguard.toml");
    cfg
}

// ---------------------------------------------------------------------------
// Test 1: tether --help exits 0 and mentions subcommands
// ---------------------------------------------------------------------------
#[test]
fn help_exits_zero() {
    tether()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("hook"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("log"));
}

// ---------------------------------------------------------------------------
// Test 2: tether --version exits 0 and prints a version string
// ---------------------------------------------------------------------------
#[test]
fn version_exits_zero() {
    tether()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").unwrap());
}

// ---------------------------------------------------------------------------
// Test 3: hook claude-code pre_tool with a benign Read payload — allow
//
// JSON fields used by cmd_hook.rs:
//   "tool"       -> tool_name
//   "session_id" -> session_id
//   "input"      -> tool_input  (engine reads payload.get("input"))
// ---------------------------------------------------------------------------
#[test]
fn hook_claude_code_pre_allow() {
    let tmp = tempdir().expect("tempdir");
    let cfg = write_blocking_config(tmp.path());

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-123",
        "tool": "Read",
        "input": { "file_path": "/tmp/test.txt" }
    })
    .to_string();

    tether()
        .args(["hook", "claude-code", "pre_tool"])
        .env("AIGUARD_CONFIG", cfg.to_str().unwrap())
        .write_stdin(payload)
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}

// ---------------------------------------------------------------------------
// Test 4: hook claude-code pre_tool with rm -rf / — expect exit code 2 (block)
//
// The engine looks for the command in payload.get("input").get("command").
// We set TETHER_CONFIG to a file that has "rm -rf /" in deny_shell_patterns.
// ---------------------------------------------------------------------------
#[test]
fn hook_claude_code_pre_block_rm_rf() {
    let tmp = tempdir().expect("tempdir");
    let cfg = write_blocking_config(tmp.path());

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-456",
        "tool": "Bash",
        "input": { "command": "rm -rf /" }
    })
    .to_string();

    tether()
        .args(["hook", "claude-code", "pre_tool"])
        .env("AIGUARD_CONFIG", cfg.to_str().unwrap())
        .write_stdin(payload)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("block"));
}

// ---------------------------------------------------------------------------
// Test 5: tether doctor runs without crashing.
//
// The binary may not be in PATH in the test environment, so doctor may exit
// with code 1 (failures found).  We only assert it doesn't panic / segfault,
// i.e. the process exits with code 0 or 1 and produces recognisable output.
// ---------------------------------------------------------------------------
#[test]
fn doctor_exits_zero_or_one() {
    let output = tether()
        .arg("doctor")
        .output()
        .expect("failed to run tether doctor");

    // Must be a clean exit (not a signal / panic).
    let code = output.status.code().expect("process was killed by signal");
    assert!(
        code == 0 || code == 1,
        "doctor exited with unexpected code {code}"
    );

    // stdout should mention the doctor header
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("aiguard doctor") || stdout.contains("Summary"),
        "unexpected doctor output: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: tether log --help exits 0
// ---------------------------------------------------------------------------
#[test]
fn log_help_exits_zero() {
    tether()
        .args(["log", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tail").or(predicate::str::contains("log")));
}

// ---------------------------------------------------------------------------
// Test 7: tether replay --help exits 0
// ---------------------------------------------------------------------------
#[test]
fn replay_help_exits_zero() {
    tether()
        .args(["replay", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("replay").or(predicate::str::contains("session")));
}

// ---------------------------------------------------------------------------
// Test 8: invalid JSON on stdin causes a non-zero exit
// ---------------------------------------------------------------------------
#[test]
fn hook_invalid_json_exits_nonzero() {
    let tmp = tempdir().expect("tempdir");
    let cfg = write_blocking_config(tmp.path());

    tether()
        .args(["hook", "claude-code", "pre_tool"])
        .env("AIGUARD_CONFIG", cfg.to_str().unwrap())
        .write_stdin("this is not json }{")
        .assert()
        .failure(); // any non-zero exit code
}
