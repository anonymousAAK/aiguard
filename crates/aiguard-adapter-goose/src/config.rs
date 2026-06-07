use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::info;

/// The YAML block we inject into the goose configuration file.
const AIGUARD_MCP_SECTION: &str = r#"
# -- aiguard-mcp-proxy --
mcpServers:
  aiguard:
    command: aiguard
    args:
      - mcp-proxy
"#;

/// Marker string used to detect whether the aiguard section is already present.
const AIGUARD_MARKER: &str = "# -- aiguard-mcp-proxy --";

/// Manages Goose's configuration file, specifically for registering aiguard's
/// MCP proxy so that Goose routes tool calls through aiguard.
pub struct GooseConfig {
    pub config_path: PathBuf,
}

impl Default for GooseConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl GooseConfig {
    /// Create a new `GooseConfig` pointing at the default goose config
    /// location: `~/.config/goose/config.yaml`.
    pub fn new() -> Self {
        let config_path = dirs_default_config().join("goose").join("config.yaml");
        Self { config_path }
    }

    /// Register `aiguard mcp-proxy` as an MCP server in goose's config.
    ///
    /// If the config file does not exist it is created (along with parent
    /// directories). If the aiguard section already exists the file is left
    /// unchanged.
    pub fn register_proxy(&self) -> Result<()> {
        let existing = if self.config_path.exists() {
            fs::read_to_string(&self.config_path)
                .with_context(|| format!("failed to read {}", self.config_path.display()))?
        } else {
            String::new()
        };

        if existing.contains(AIGUARD_MARKER) {
            info!(
                path = %self.config_path.display(),
                "aiguard mcp-proxy already registered in goose config"
            );
            return Ok(());
        }

        // Ensure parent directory exists.
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut new_content = existing;
        if !new_content.is_empty() && !new_content.ends_with('\n') {
            new_content.push('\n');
        }
        new_content.push_str(AIGUARD_MCP_SECTION);

        fs::write(&self.config_path, &new_content)
            .with_context(|| format!("failed to write {}", self.config_path.display()))?;

        info!(
            path = %self.config_path.display(),
            "registered aiguard mcp-proxy in goose config"
        );
        Ok(())
    }

    /// List the names of downstream MCP servers currently configured in goose.
    ///
    /// This does a simple string-based scan of the YAML for indented keys
    /// under `mcpServers:` blocks, since `serde_yaml` is not available.
    pub fn list_downstream_servers(&self) -> Result<Vec<String>> {
        if !self.config_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&self.config_path)
            .with_context(|| format!("failed to read {}", self.config_path.display()))?;

        Ok(parse_mcp_server_names(&content))
    }
}

/// Simple line-based parser that extracts server names from `mcpServers:`
/// blocks.  We look for a line matching `mcpServers:` and then collect
/// subsequent indented lines that look like YAML mapping keys (i.e.
/// `  name:`) until we hit a non-indented line or EOF.
fn parse_mcp_server_names(yaml: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_section = false;

    for line in yaml.lines() {
        let trimmed = line.trim();

        if trimmed == "mcpServers:" || trimmed.starts_with("mcpServers:") {
            in_section = true;
            continue;
        }

        if in_section {
            // Still inside the mcpServers block if the line is indented.
            if line.starts_with(' ') || line.starts_with('\t') {
                // A direct child key has exactly one level of indentation and
                // ends with `:`.  We accept 2-space or 4-space indent as the
                // first child level.
                let child = trimmed;
                if let Some(name) = child.strip_suffix(':') {
                    // Only pick direct children: exactly 2 spaces of indent.
                    let indent = line.len() - line.trim_start().len();
                    if indent == 2 {
                        names.push(name.to_string());
                    }
                }
            } else if !trimmed.is_empty() {
                // Non-indented, non-empty line — we've left the section.
                in_section = false;
            }
        }
    }

    names
}

/// Return the platform-appropriate config directory (`~/.config` on Unix,
/// `%APPDATA%` on Windows, etc.) using the `directories` approach, but
/// without pulling in the crate — we just use the `HOME` / `APPDATA` env vars.
fn dirs_default_config() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg);
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config");
    }

    // Fallback
    PathBuf::from(".config")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a GooseConfig pointing at a temp directory.
    fn test_config(dir: &Path) -> GooseConfig {
        GooseConfig {
            config_path: dir.join("config.yaml"),
        }
    }

    use std::path::Path;

    #[test]
    fn register_creates_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());

        cfg.register_proxy().unwrap();
        assert!(cfg.config_path.exists());

        let content = fs::read_to_string(&cfg.config_path).unwrap();
        assert!(content.contains("aiguard-mcp-proxy"));
        assert!(content.contains("mcpServers:"));
    }

    #[test]
    fn register_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());

        cfg.register_proxy().unwrap();
        cfg.register_proxy().unwrap();

        let content = fs::read_to_string(&cfg.config_path).unwrap();
        assert_eq!(content.matches("aiguard-mcp-proxy").count(), 1);
    }

    #[test]
    fn register_preserves_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        fs::write(&cfg.config_path, "existing: value\n").unwrap();

        cfg.register_proxy().unwrap();

        let content = fs::read_to_string(&cfg.config_path).unwrap();
        assert!(content.contains("existing: value"));
        assert!(content.contains("aiguard-mcp-proxy"));
    }

    #[test]
    fn list_servers_empty_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());

        let servers = cfg.list_downstream_servers().unwrap();
        assert!(servers.is_empty());
    }

    #[test]
    fn list_servers_finds_entries() {
        let yaml = r#"
mcpServers:
  aiguard:
    command: aiguard
    args:
      - mcp-proxy
  other-server:
    command: other
"#;
        let names = parse_mcp_server_names(yaml);
        assert!(names.contains(&"aiguard".to_string()));
        assert!(names.contains(&"other-server".to_string()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn list_servers_after_register() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());

        cfg.register_proxy().unwrap();
        let servers = cfg.list_downstream_servers().unwrap();
        assert!(servers.contains(&"aiguard".to_string()));
    }

    #[test]
    fn new_uses_default_path() {
        let cfg = GooseConfig::new();
        assert!(cfg.config_path.ends_with("goose/config.yaml"));
    }
}
