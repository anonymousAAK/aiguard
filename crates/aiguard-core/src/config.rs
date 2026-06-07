use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Toml};
use figment::Figment;

use crate::error::{Result, AiguardError};
use crate::policy::Policy;

/// Name of the config file to search for.
const CONFIG_FILE_NAME: &str = "aiguard.toml";

/// Environment variable that can point to a config file.
const CONFIG_ENV_VAR: &str = "AIGUARD_CONFIG";

/// Environment variable prefix for individual overrides (e.g. AIGUARD_POLICY_STRICT=true).
const ENV_PREFIX: &str = "AIGUARD_";

/// Load the policy configuration using figment's layered provider system.
///
/// Precedence (highest to lowest):
/// 1. Environment variables with `AIGUARD_` prefix
/// 2. `./aiguard.toml` found by walking up from `cwd`
/// 3. File pointed to by `$AIGUARD_CONFIG`
/// 4. `~/.config/aiguard/aiguard.toml`
/// 5. Compiled-in defaults (via `Policy::default()`)
///
/// Lower-precedence layers are merged first, then higher-precedence layers
/// override them.
pub fn load_policy() -> Result<Policy> {
    load_policy_from(std::env::current_dir().ok())
}

/// Load policy with an explicit starting directory (useful for testing).
pub fn load_policy_from(cwd: Option<PathBuf>) -> Result<Policy> {
    let mut figment = Figment::new()
        // Start with compiled-in defaults serialized as a base.
        .merge(figment::providers::Serialized::defaults(Policy::default()));

    // Layer 4: ~/.config/aiguard/aiguard.toml (lowest file precedence)
    if let Some(global_config) = global_config_path() {
        if global_config.is_file() {
            figment = figment.merge(Toml::file(&global_config));
        }
    }

    // Layer 3: $AIGUARD_CONFIG env var
    if let Ok(env_path) = std::env::var(CONFIG_ENV_VAR) {
        let p = PathBuf::from(&env_path);
        if p.is_file() {
            figment = figment.merge(Toml::file(&p));
        }
    }

    // Layer 2: walk up from cwd to find aiguard.toml
    if let Some(dir) = cwd {
        if let Some(local_config) = find_config_upward(&dir) {
            figment = figment.merge(Toml::file(&local_config));
        }
    }

    // Layer 1: environment variable overrides (highest precedence)
    // e.g. AIGUARD_POLICY__STRICT=true (double underscore = nested key)
    figment = figment.merge(Env::prefixed(ENV_PREFIX).split("__").lowercase(true));

    let policy: Policy = figment.extract().map_err(AiguardError::Figment)?;
    Ok(policy)
}

/// Walk upward from `start` looking for `aiguard.toml`.
fn find_config_upward(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Return `~/.config/aiguard/aiguard.toml` on the current platform.
fn global_config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "aiguard")
        .map(|dirs| dirs.config_dir().join(CONFIG_FILE_NAME))
}

/// Return the path that `find_config_upward` would find, or `None`.
/// Useful for diagnostics / `aiguard doctor`.
pub fn locate_config() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    find_config_upward(&cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_loads_without_any_files() {
        // Even with no config files on disk, compiled-in defaults should work.
        let policy = load_policy_from(None).expect("should load defaults");
        assert_eq!(policy.schema, "1.0");
        assert!(!policy.policy.strict);
    }

    #[test]
    fn find_config_upward_returns_none_for_missing() {
        let tmp = std::env::temp_dir().join("aiguard-test-no-config");
        let _ = std::fs::create_dir_all(&tmp);
        assert!(find_config_upward(&tmp).is_none());
    }

    #[test]
    fn find_config_upward_finds_file() {
        let tmp = std::env::temp_dir().join("aiguard-test-config-up");
        let nested = tmp.join("a").join("b").join("c");
        let _ = std::fs::create_dir_all(&nested);
        let config_path = tmp.join(CONFIG_FILE_NAME);
        std::fs::write(&config_path, "schema = \"1.0\"\n").unwrap();

        let found = find_config_upward(&nested);
        assert_eq!(found, Some(config_path.clone()));

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
