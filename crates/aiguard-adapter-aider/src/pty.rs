//! PTY-style wrapper for Aider — spawns Aider as a child process, forwards
//! stdin/stdout/stderr, and monitors output for sensitive patterns.

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

/// Sensitive output patterns to watch for in Aider's output.
static SENSITIVE_PATTERNS: &[&str] = &[
    "sk-ant-",
    "sk-proj-",
    "AKIA",
    "ghp_",
    "ghs_",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
];

/// Check a line of output against known sensitive patterns.
/// Returns the first matching pattern name if found.
fn check_sensitive(line: &str) -> Option<&'static str> {
    SENSITIVE_PATTERNS
        .iter()
        .find(|p| line.contains(*p))
        .copied()
}

/// Run Aider as a monitored subprocess. Forwards stdin/stdout/stderr.
/// Logs warnings when sensitive content appears in output.
/// Returns the exit code of the Aider process.
pub async fn run_aider(args: &[String]) -> Result<i32> {
    info!("Spawning aider with {} argument(s)", args.len());

    let mut child = Command::new("aider")
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn aider — is it installed and on PATH?")?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();

    let mut stdout_done = false;
    let mut stderr_done = false;

    let mut real_stdout = tokio::io::stdout();
    let mut real_stderr = tokio::io::stderr();

    loop {
        if stdout_done && stderr_done {
            break;
        }

        tokio::select! {
            line = stdout_reader.next_line(), if !stdout_done => {
                match line.context("Error reading aider stdout")? {
                    Some(l) => {
                        if let Some(pattern) = check_sensitive(&l) {
                            warn!(target: "aiguard", "sensitive content in aider output: {}", pattern);
                        }
                        real_stdout.write_all(l.as_bytes()).await?;
                        real_stdout.write_all(b"\n").await?;
                    }
                    None => { stdout_done = true; }
                }
            }
            line = stderr_reader.next_line(), if !stderr_done => {
                match line.context("Error reading aider stderr")? {
                    Some(l) => {
                        if let Some(pattern) = check_sensitive(&l) {
                            warn!(target: "aiguard", "sensitive content in aider stderr: {}", pattern);
                        }
                        real_stderr.write_all(l.as_bytes()).await?;
                        real_stderr.write_all(b"\n").await?;
                    }
                    None => { stderr_done = true; }
                }
            }
        }
    }

    let status = child
        .wait()
        .await
        .context("Failed to wait for aider process")?;
    let code = status.code().unwrap_or(1);
    info!("aider exited with code {}", code);
    Ok(code)
}
