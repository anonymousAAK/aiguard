use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

/// The YAML key / block we inject into `.aider.conf.yml`.
const MCP_SERVER_ENTRY: &str = "mcp-server:\n  - aiguard mcp-proxy\n";

/// Manages Aider configuration, specifically registering aiguard's MCP proxy
/// as an MCP server so Aider routes tool calls through aiguard.
pub struct AiderConfig;

impl AiderConfig {
    /// Register `aiguard mcp-proxy` as an MCP server in the project's
    /// `.aider.conf.yml`.
    ///
    /// If the file does not exist it is created. If the entry is already
    /// present the file is left unchanged.
    pub fn register_proxy(project_dir: &Path) -> Result<()> {
        let config_path = project_dir.join(".aider.conf.yml");

        let existing = if config_path.exists() {
            fs::read_to_string(&config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?
        } else {
            String::new()
        };

        // Check whether the proxy is already registered.
        if existing.contains("aiguard mcp-proxy") {
            info!(
                path = %config_path.display(),
                "aiguard mcp-proxy already registered in aider config"
            );
            return Ok(());
        }

        // Append the mcp-server block (with a preceding newline if the file
        // already has content).
        let mut new_content = existing;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        if !new_content.is_empty() {
            new_content.push('\n');
        }
        new_content.push_str(MCP_SERVER_ENTRY);

        fs::write(&config_path, &new_content)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        info!(
            path = %config_path.display(),
            "registered aiguard mcp-proxy in aider config"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn creates_config_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        AiderConfig::register_proxy(dir.path()).unwrap();

        let content = fs::read_to_string(dir.path().join(".aider.conf.yml")).unwrap();
        assert!(content.contains("aiguard mcp-proxy"));
        assert!(content.contains("mcp-server:"));
    }

    #[test]
    fn appends_to_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".aider.conf.yml");
        fs::write(&config_path, "model: gpt-4\n").unwrap();

        AiderConfig::register_proxy(dir.path()).unwrap();

        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("model: gpt-4"));
        assert!(content.contains("aiguard mcp-proxy"));
    }

    #[test]
    fn idempotent_registration() {
        let dir = tempfile::tempdir().unwrap();
        AiderConfig::register_proxy(dir.path()).unwrap();
        AiderConfig::register_proxy(dir.path()).unwrap();

        let content = fs::read_to_string(dir.path().join(".aider.conf.yml")).unwrap();
        // Should appear only once.
        assert_eq!(content.matches("aiguard mcp-proxy").count(), 1);
    }
}
