//! Tool pinning and rug-pull detection for MCP servers.
//!
//! Computes a SHA-256 hash of the `tools/list` response and stores it as a pin.
//! On subsequent checks, if the hash differs, it indicates the server's tools
//! have changed (potential rug-pull attack).

use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use aiguard_core::Result;

/// The result of checking a tool pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// The tools match the stored pin.
    Match,
    /// No pin exists yet for this server.
    New,
    /// The tools have changed since the pin was stored.
    Changed { old_hash: String, new_hash: String },
}

/// Stored pin data for an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinRecord {
    /// SHA-256 hex digest of the canonical tools/list response.
    hash: String,
    /// ISO-8601 timestamp when the pin was last updated.
    pinned_at: String,
    /// Number of tools at the time of pinning.
    tool_count: usize,
    /// Server identifier.
    server_id: String,
}

/// Manages tool pins for MCP servers.
pub struct ToolPinner {
    pin_dir: PathBuf,
}

impl ToolPinner {
    /// Create a pinner using the default storage location:
    /// `~/.local/share/aiguard/mcp-pins/`
    pub fn new() -> Self {
        let dir = default_pin_dir();
        Self { pin_dir: dir }
    }

    /// Create a pinner with a custom storage directory.
    pub fn with_dir(pin_dir: PathBuf) -> Self {
        Self { pin_dir }
    }

    /// Check whether the given tools JSON matches the stored pin for `server_id`.
    pub fn check(&self, server_id: &str, tools_json: &serde_json::Value) -> PinStatus {
        let new_hash = compute_tools_hash(tools_json);

        let pin_path = self.pin_path(server_id);
        let existing = match fs::read_to_string(&pin_path) {
            Ok(content) => content,
            Err(_) => return PinStatus::New,
        };

        let record: PinRecord = match serde_json::from_str(&existing) {
            Ok(r) => r,
            Err(_) => return PinStatus::New,
        };

        if record.hash == new_hash {
            PinStatus::Match
        } else {
            PinStatus::Changed {
                old_hash: record.hash,
                new_hash,
            }
        }
    }

    /// Approve (store or update) the pin for a server. This records the current
    /// hash as the accepted baseline.
    pub fn approve(&self, server_id: &str, tools_json: &serde_json::Value) -> Result<()> {
        let hash = compute_tools_hash(tools_json);
        let tool_count = count_tools(tools_json);

        let record = PinRecord {
            hash,
            pinned_at: Utc::now().to_rfc3339(),
            tool_count,
            server_id: server_id.to_string(),
        };

        // Ensure the pin directory exists
        fs::create_dir_all(&self.pin_dir).map_err(aiguard_core::AiguardError::Io)?;

        let pin_path = self.pin_path(server_id);
        let json =
            serde_json::to_string_pretty(&record).map_err(aiguard_core::AiguardError::Serde)?;

        fs::write(&pin_path, json).map_err(aiguard_core::AiguardError::Io)?;

        Ok(())
    }

    /// Get the file path for a server's pin.
    pub fn pin_path(&self, server_id: &str) -> PathBuf {
        // Sanitize server_id to be filesystem-safe
        let safe_name: String = server_id
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.pin_dir.join(format!("{safe_name}.json"))
    }

    /// List all pinned server IDs.
    pub fn list_pinned(&self) -> Vec<String> {
        let entries = match fs::read_dir(&self.pin_dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut servers = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(server_id) = name_str.strip_suffix(".json") {
                servers.push(server_id.to_string());
            }
        }
        servers
    }

    /// Remove a pin for a server.
    pub fn remove_pin(&self, server_id: &str) -> Result<()> {
        let pin_path = self.pin_path(server_id);
        if pin_path.exists() {
            fs::remove_file(&pin_path).map_err(aiguard_core::AiguardError::Io)?;
        }
        Ok(())
    }
}

impl Default for ToolPinner {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a deterministic SHA-256 hash of a tools JSON value.
///
/// The value is canonicalized by serializing with sorted keys (serde_json
/// serializes object keys in insertion order, so we re-parse through a
/// BTreeMap-based representation for determinism).
fn compute_tools_hash(tools_json: &serde_json::Value) -> String {
    // Canonicalize: serialize to a canonical JSON string
    let canonical = canonical_json(tools_json);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Produce a canonical JSON string with sorted object keys.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let entries: Vec<String> = sorted
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Count the number of tools in a tools JSON value.
fn count_tools(tools_json: &serde_json::Value) -> usize {
    if let Some(arr) = tools_json.as_array() {
        arr.len()
    } else if let Some(tools) = tools_json.get("tools") {
        tools.as_array().map(|a| a.len()).unwrap_or(0)
    } else {
        0
    }
}

/// Default pin directory: `~/.local/share/aiguard/mcp-pins/`
fn default_pin_dir() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("", "", "aiguard") {
        dirs.data_dir().join("mcp-pins")
    } else {
        PathBuf::from(".aiguard/mcp-pins")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn test_pinner() -> (ToolPinner, TempDir) {
        let tmp = TempDir::new().unwrap();
        let pinner = ToolPinner::with_dir(tmp.path().to_path_buf());
        (pinner, tmp)
    }

    #[test]
    fn new_server_returns_new_status() {
        let (pinner, _tmp) = test_pinner();
        let tools = json!([{"name": "tool_a", "description": "does stuff"}]);
        assert_eq!(pinner.check("my-server", &tools), PinStatus::New);
    }

    #[test]
    fn approve_then_check_matches() {
        let (pinner, _tmp) = test_pinner();
        let tools = json!([{"name": "tool_a", "description": "does stuff"}]);
        pinner.approve("my-server", &tools).unwrap();
        assert_eq!(pinner.check("my-server", &tools), PinStatus::Match);
    }

    #[test]
    fn changed_tools_detected() {
        let (pinner, _tmp) = test_pinner();
        let tools_v1 = json!([{"name": "tool_a", "description": "v1"}]);
        let tools_v2 = json!([
            {"name": "tool_a", "description": "v1"},
            {"name": "tool_b", "description": "new sneaky tool"}
        ]);
        pinner.approve("my-server", &tools_v1).unwrap();
        match pinner.check("my-server", &tools_v2) {
            PinStatus::Changed { .. } => {} // expected
            other => panic!("expected Changed, got {:?}", other),
        }
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let v1 = json!({"b": 2, "a": 1});
        let v2 = json!({"a": 1, "b": 2});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }

    #[test]
    fn hash_is_deterministic() {
        let tools = json!([{"name": "x", "description": "y"}]);
        let h1 = compute_tools_hash(&tools);
        let h2 = compute_tools_hash(&tools);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn list_pinned_servers() {
        let (pinner, _tmp) = test_pinner();
        let tools = json!([{"name": "t"}]);
        pinner.approve("server-a", &tools).unwrap();
        pinner.approve("server-b", &tools).unwrap();
        let mut pinned = pinner.list_pinned();
        pinned.sort();
        assert_eq!(pinned, vec!["server-a", "server-b"]);
    }

    #[test]
    fn remove_pin_works() {
        let (pinner, _tmp) = test_pinner();
        let tools = json!([{"name": "t"}]);
        pinner.approve("server-x", &tools).unwrap();
        assert_eq!(pinner.check("server-x", &tools), PinStatus::Match);
        pinner.remove_pin("server-x").unwrap();
        assert_eq!(pinner.check("server-x", &tools), PinStatus::New);
    }

    #[test]
    fn sanitizes_server_id_for_filesystem() {
        let (pinner, _tmp) = test_pinner();
        let path = pinner.pin_path("evil/../../etc/passwd");
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(!filename.contains('/'));
        assert!(!filename.contains(".."));
    }
}
