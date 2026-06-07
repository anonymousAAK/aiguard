//! `aiguard doctor` — Validate the aiguard installation.
//!
//! Checks:
//! - aiguard binary is in PATH
//! - Each agent's hook config points to aiguard
//! - SQLite database exists and is writable
//! - Data directory permissions are correct

use std::fs;
use std::path::PathBuf;

use anyhow::Result;

/// Status of a single check.
#[derive(Debug)]
enum CheckStatus {
    Ok(String),
    Warn(String),
    Fail(String),
}

impl CheckStatus {
    fn icon(&self) -> &'static str {
        match self {
            Self::Ok(_) => "[OK]",
            Self::Warn(_) => "[!!]",
            Self::Fail(_) => "[XX]",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Ok(m) | Self::Warn(m) | Self::Fail(m) => m,
        }
    }
}

pub async fn run() -> Result<()> {
    println!("aiguard doctor - checking installation health\n");

    let checks = vec![
        ("Binary in PATH", check_binary_in_path()),
        ("Configuration file", check_config_file()),
        ("Data directory", check_data_directory()),
        ("SQLite database", check_sqlite_db()),
        (
            "claude-code hook",
            check_agent_hook("claude-code", ".claude/settings.json"),
        ),
        (
            "codex hook",
            check_agent_hook("codex", ".codex/config.toml"),
        ),
        (
            "gemini hook",
            check_agent_hook("gemini", ".gemini/settings.json"),
        ),
    ];

    let mut ok_count = 0;
    let mut warn_count = 0;
    let mut fail_count = 0;

    for (label, status) in &checks {
        println!("  {} {:<25} {}", status.icon(), label, status.message());
        match status {
            CheckStatus::Ok(_) => ok_count += 1,
            CheckStatus::Warn(_) => warn_count += 1,
            CheckStatus::Fail(_) => fail_count += 1,
        }
    }

    println!();
    println!(
        "Summary: {} ok, {} warnings, {} failures",
        ok_count, warn_count, fail_count
    );

    if fail_count > 0 {
        println!("\nRun `aiguard init` to fix configuration issues.");
        std::process::exit(1);
    } else if warn_count > 0 {
        println!("\nSome checks have warnings. Review above for details.");
    } else {
        println!("\nAll checks passed. aiguard is correctly installed.");
    }

    Ok(())
}

/// Check that the tether binary is discoverable in PATH.
fn check_binary_in_path() -> CheckStatus {
    match which::which("aiguard") {
        Ok(path) => CheckStatus::Ok(format!("found at {}", path.display())),
        Err(_) => {
            CheckStatus::Fail("aiguard binary not found in PATH. Add it to your PATH.".to_string())
        }
    }
}

/// Check that a configuration file can be found.
fn check_config_file() -> CheckStatus {
    match aiguard_core::locate_config() {
        Some(path) => CheckStatus::Ok(format!("found: {}", path.display())),
        None => CheckStatus::Warn(
            "no aiguard.toml found (using defaults). Create one with `aiguard init`.".to_string(),
        ),
    }
}

/// Check that the data directory exists and is writable.
fn check_data_directory() -> CheckStatus {
    let data_dir = data_dir_path();

    if !data_dir.exists() {
        return CheckStatus::Warn(format!(
            "data directory does not exist: {}. It will be created on first use.",
            data_dir.display()
        ));
    }

    // Try to write a temp file to test writability
    let test_file = data_dir.join(".aiguard-doctor-test");
    match fs::write(&test_file, "test") {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
            CheckStatus::Ok(format!("writable at {}", data_dir.display()))
        }
        Err(e) => CheckStatus::Fail(format!(
            "data directory not writable ({}): {}",
            data_dir.display(),
            e
        )),
    }
}

/// Check that the SQLite audit database exists and is accessible.
fn check_sqlite_db() -> CheckStatus {
    let db_path = sqlite_path();

    if !db_path.exists() {
        return CheckStatus::Warn(format!(
            "audit database does not exist yet: {}. It will be created on first event.",
            db_path.display()
        ));
    }

    // Try to open it
    match rusqlite::Connection::open(&db_path) {
        Ok(conn) => {
            // Verify the schema
            match conn.prepare("SELECT COUNT(*) FROM events") {
                Ok(_) => CheckStatus::Ok(format!("accessible at {}", db_path.display())),
                Err(_) => CheckStatus::Warn(format!(
                    "database exists but schema may be outdated: {}",
                    db_path.display()
                )),
            }
        }
        Err(e) => CheckStatus::Fail(format!(
            "cannot open database at {}: {}",
            db_path.display(),
            e
        )),
    }
}

/// Check that an agent's hook config exists and references tether.
fn check_agent_hook(agent_name: &str, config_rel_path: &str) -> CheckStatus {
    let home = match home_dir() {
        Some(h) => h,
        None => {
            return CheckStatus::Warn("Cannot determine home directory.".to_string());
        }
    };

    let config_path = home.join(config_rel_path);

    if !config_path.exists() {
        // Check if the agent binary exists at all
        let binary = match agent_name {
            "claude-code" => "claude",
            other => other,
        };
        if which::which(binary).is_err() {
            return CheckStatus::Ok(format!("{agent_name} not installed (skipped)"));
        }
        return CheckStatus::Warn(format!(
            "config not found: {}. Run `aiguard init`.",
            config_path.display()
        ));
    }

    // Read the config and check for tether reference
    match fs::read_to_string(&config_path) {
        Ok(content) => {
            if content.contains("aiguard") {
                CheckStatus::Ok(format!("configured in {}", config_path.display()))
            } else {
                CheckStatus::Warn(format!(
                    "config exists but does not reference aiguard: {}",
                    config_path.display()
                ))
            }
        }
        Err(e) => CheckStatus::Fail(format!("cannot read {}: {}", config_path.display(), e)),
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn data_dir_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("", "", "aiguard") {
        dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from("~/.local/share/aiguard")
    }
}

fn sqlite_path() -> PathBuf {
    data_dir_path().join("audit.db")
}

fn home_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|d| d.home_dir().to_path_buf())
}
