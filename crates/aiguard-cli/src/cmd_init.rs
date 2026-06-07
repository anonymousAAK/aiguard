//! `aiguard init` — Detect installed agents and write hook configurations.
//!
//! For each detected agent, writes the appropriate hook config file:
//! - claude-code: ~/.claude/settings.json
//! - codex: ~/.codex/config.toml
//! - gemini: ~/.gemini/settings.json
//! - crush: crush.json (project-local)
//! - cline: ~/Documents/Cline/Rules/Hooks/ or .clinerules/hooks/
//! - opencode: .opencode/plugin/aiguard.ts

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
pub struct InitArgs {
    /// Only initialize for a specific agent (skip auto-detection)
    #[arg(long)]
    agent: Option<String>,

    /// Force overwrite existing configurations without prompting
    #[arg(long, short)]
    force: bool,

    /// Dry-run: show what would be done without making changes
    #[arg(long)]
    dry_run: bool,
}

/// Agent detection result.
struct DetectedAgent {
    name: &'static str,
    binary: &'static str,
    found: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    println!("aiguard init - detecting installed agents...\n");

    let agents = detect_agents();
    let aiguard_bin = which::which("aiguard")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "aiguard".to_string());

    let mut configured = 0;

    for agent in &agents {
        if !agent.found {
            println!("  [ ] {} (not found: {})", agent.name, agent.binary);
            continue;
        }

        // If --agent is specified, skip others
        if let Some(ref filter) = args.agent {
            if agent.name != filter.as_str() {
                continue;
            }
        }

        println!("  [*] {} (found)", agent.name);

        if args.dry_run {
            println!("      (dry-run) Would configure hook for {}", agent.name);
            configured += 1;
            continue;
        }

        let result = match agent.name {
            "claude-code" => configure_claude_code(&aiguard_bin, args.force),
            "codex" => configure_codex(&aiguard_bin, args.force),
            "gemini" => configure_gemini(&aiguard_bin, args.force),
            "crush" => configure_crush(&aiguard_bin, args.force),
            "cline" => configure_cline(&aiguard_bin, args.force),
            "opencode" => configure_opencode(&aiguard_bin, args.force),
            _ => Ok(()),
        };

        match result {
            Ok(()) => {
                println!("      Configured successfully.");
                configured += 1;
            }
            Err(e) => {
                println!("      Error: {e}");
            }
        }
    }

    println!("\nDone. Configured {configured} agent(s).");
    if configured > 0 {
        println!("Run `aiguard doctor` to verify the installation.");
    }

    Ok(())
}

/// Detect which agents are installed by checking for their binaries.
fn detect_agents() -> Vec<DetectedAgent> {
    vec![
        DetectedAgent {
            name: "claude-code",
            binary: "claude",
            found: which::which("claude").is_ok(),
        },
        DetectedAgent {
            name: "codex",
            binary: "codex",
            found: which::which("codex").is_ok(),
        },
        DetectedAgent {
            name: "gemini",
            binary: "gemini",
            found: which::which("gemini").is_ok(),
        },
        DetectedAgent {
            name: "crush",
            binary: "crush",
            found: which::which("crush").is_ok(),
        },
        DetectedAgent {
            name: "cline",
            binary: "cline",
            found: which::which("cline").is_ok() || cline_dir_exists(),
        },
        DetectedAgent {
            name: "opencode",
            binary: "opencode",
            found: which::which("opencode").is_ok(),
        },
    ]
}

/// Check if the Cline settings directory exists (Cline is often a VS Code extension).
fn cline_dir_exists() -> bool {
    if let Some(home) = home_dir() {
        home.join("Documents").join("Cline").exists() || Path::new(".clinerules").exists()
    } else {
        false
    }
}

/// Configure hook for claude-code: ~/.claude/settings.json
fn configure_claude_code(aiguard_bin: &str, force: bool) -> Result<()> {
    let home = home_dir().context("Cannot determine home directory")?;
    let config_path = home.join(".claude").join("settings.json");

    let hook_config = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "type": "command",
                "command": format!("\"{}\" hook claude-code pre_tool", aiguard_bin)
            }],
            "PostToolUse": [{
                "type": "command",
                "command": format!("\"{}\" hook claude-code post_tool", aiguard_bin)
            }]
        }
    });

    write_json_config(&config_path, &hook_config, force, "hooks")
}

/// Configure hook for codex: ~/.codex/config.toml
fn configure_codex(aiguard_bin: &str, force: bool) -> Result<()> {
    let home = home_dir().context("Cannot determine home directory")?;
    let config_path = home.join(".codex").join("config.toml");

    let hook_content = format!(
        r#"
[hooks]
pre_tool = "\"{}\" hook codex pre_tool"
post_tool = "\"{}\" hook codex post_tool"
"#,
        aiguard_bin, aiguard_bin
    );

    write_toml_config(&config_path, &hook_content, force)
}

/// Configure hook for gemini: ~/.gemini/settings.json
fn configure_gemini(aiguard_bin: &str, force: bool) -> Result<()> {
    let home = home_dir().context("Cannot determine home directory")?;
    let config_path = home.join(".gemini").join("settings.json");

    let hook_config = serde_json::json!({
        "hooks": {
            "pre_tool": format!("\"{}\" hook gemini pre_tool", aiguard_bin),
            "post_tool": format!("\"{}\" hook gemini post_tool", aiguard_bin)
        }
    });

    write_json_config(&config_path, &hook_config, force, "hooks")
}

/// Configure hook for crush: ./crush.json (project-local)
fn configure_crush(aiguard_bin: &str, force: bool) -> Result<()> {
    let config_path = PathBuf::from("crush.json");

    let hook_config = serde_json::json!({
        "hooks": {
            "pre_tool": format!("\"{}\" hook crush pre_tool", aiguard_bin),
            "post_tool": format!("\"{}\" hook crush post_tool", aiguard_bin)
        }
    });

    write_json_config(&config_path, &hook_config, force, "hooks")
}

/// Configure hook for cline: ~/Documents/Cline/Rules/Hooks/ or .clinerules/hooks/
fn configure_cline(aiguard_bin: &str, force: bool) -> Result<()> {
    // Prefer project-local .clinerules/hooks/ if .clinerules exists
    let hooks_dir = if Path::new(".clinerules").exists() {
        PathBuf::from(".clinerules/hooks")
    } else if let Some(home) = home_dir() {
        home.join("Documents")
            .join("Cline")
            .join("Rules")
            .join("Hooks")
    } else {
        PathBuf::from(".clinerules/hooks")
    };

    fs::create_dir_all(&hooks_dir)?;

    let hook_script = format!(
        "#!/bin/sh\n# aiguard hook for Cline\n# This script is called by Cline before and after tool execution.\nexec \"{}\" hook cline \"$@\"\n",
        aiguard_bin
    );

    let hook_path = hooks_dir.join("aiguard.sh");
    backup_if_exists(&hook_path, force)?;
    fs::write(&hook_path, hook_script)?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}

/// Configure hook for opencode: .opencode/plugin/aiguard.ts
fn configure_opencode(aiguard_bin: &str, _force: bool) -> Result<()> {
    let plugin_dir = PathBuf::from(".opencode/plugin");
    fs::create_dir_all(&plugin_dir)?;

    let plugin_content = format!(
        r#"// aiguard plugin for opencode
// Intercepts tool calls for security scanning.

import {{ execSync }} from "child_process";

export default {{
  name: "aiguard",
  hooks: {{
    preTool(ctx: any) {{
      const input = JSON.stringify(ctx);
      const result = execSync(`echo '${{input}}' | "{aiguard_bin}" hook opencode pre_tool`, {{
        encoding: "utf-8",
        timeout: 5000,
      }});
      return JSON.parse(result);
    }},
    postTool(ctx: any) {{
      const input = JSON.stringify(ctx);
      const result = execSync(`echo '${{input}}' | "{aiguard_bin}" hook opencode post_tool`, {{
        encoding: "utf-8",
        timeout: 5000,
      }});
      return JSON.parse(result);
    }},
  }},
}};
"#
    );

    let plugin_path = plugin_dir.join("aiguard.ts");
    fs::write(&plugin_path, plugin_content)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a JSON config file, merging with existing content if present.
fn write_json_config(
    path: &Path,
    new_config: &serde_json::Value,
    force: bool,
    merge_key: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if path.exists() {
        backup_if_exists(path, force)?;

        // Merge with existing config
        let existing_content = fs::read_to_string(path)?;
        let mut existing: serde_json::Value = serde_json::from_str(&existing_content)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        if let (Some(existing_obj), Some(new_obj)) =
            (existing.as_object_mut(), new_config.as_object())
        {
            if let Some(new_section) = new_obj.get(merge_key) {
                existing_obj.insert(merge_key.to_string(), new_section.clone());
            }
        }

        let output = serde_json::to_string_pretty(&existing)?;
        fs::write(path, output)?;
    } else {
        let output = serde_json::to_string_pretty(new_config)?;
        fs::write(path, output)?;
    }

    Ok(())
}

/// Write a TOML config file, appending hook section to existing content.
fn write_toml_config(path: &Path, hook_content: &str, force: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if path.exists() {
        backup_if_exists(path, force)?;

        let existing = fs::read_to_string(path)?;
        // Remove existing [hooks] section if present
        let cleaned = remove_toml_section(&existing, "[hooks]");
        let combined = format!("{cleaned}\n{hook_content}");
        fs::write(path, combined)?;
    } else {
        fs::write(path, hook_content)?;
    }

    Ok(())
}

/// Backup a file before modifying it.
fn backup_if_exists(path: &Path, _force: bool) -> Result<()> {
    if path.exists() {
        let backup_path = path.with_extension(format!(
            "{}.bak",
            path.extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default()
        ));
        fs::copy(path, &backup_path).with_context(|| {
            format!(
                "Failed to backup {} to {}",
                path.display(),
                backup_path.display()
            )
        })?;
        println!("      Backed up: {}", backup_path.display());
    }
    Ok(())
}

/// Remove a TOML section and everything until the next section or end.
fn remove_toml_section(content: &str, section_header: &str) -> String {
    let mut result = String::new();
    let mut in_section = false;

    for line in content.lines() {
        if line.trim() == section_header {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with('[') {
            in_section = false;
        }
        if !in_section {
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|d| d.home_dir().to_path_buf())
}
