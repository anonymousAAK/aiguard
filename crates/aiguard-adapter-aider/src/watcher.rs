use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tracing::{debug, info, warn};

/// Sensitive path patterns that trigger warnings when modified.
const SENSITIVE_PATTERNS: &[&str] = &[
    ".env",
    ".ssh",
    "credentials",
    ".netrc",
    ".aws/credentials",
    ".docker/config.json",
    "id_rsa",
    "id_ed25519",
    ".pgpass",
];

/// Filesystem watcher that monitors a project directory for changes
/// and logs events via tracing, with extra warnings for sensitive paths.
pub struct FsWatcher {
    pub root: PathBuf,
}

impl FsWatcher {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Start watching the project directory recursively.
    ///
    /// Runs until the current async task is cancelled (e.g. via `tokio::select!`
    /// or dropping the future). File-system events are forwarded from notify's
    /// synchronous callback through a standard channel and polled from an async
    /// blocking task.
    pub async fn start(&self) -> Result<()> {
        let root = self.root.clone();
        info!(path = %root.display(), "starting filesystem watcher");

        let (tx, rx) = std_mpsc::channel::<Event>();

        // Create the notify watcher with a channel-based callback.
        let mut _watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                // Best-effort send; if the receiver is gone we drop the event.
                let _ = tx.send(event);
            }
        })?;

        _watcher.watch(root.as_path(), RecursiveMode::Recursive)?;

        // Move into a blocking task so we don't block the tokio runtime.
        let watch_root = root.clone();
        tokio::task::spawn_blocking(move || {
            // Keep _watcher alive for the duration of this closure.
            let _keep = _watcher;
            while let Ok(event) = rx.recv() {
                Self::handle_event(&watch_root, &event);
            }
        })
        .await?;

        info!("filesystem watcher stopped");
        Ok(())
    }

    /// Inspect a single notify event: log it and warn on sensitive paths.
    fn handle_event(root: &Path, event: &Event) {
        let kind_label = match event.kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "remove",
            EventKind::Access(_) => "access",
            _ => "other",
        };

        for path in &event.paths {
            let relative = path.strip_prefix(root).unwrap_or(path);

            debug!(
                kind = kind_label,
                path = %relative.display(),
                "fs event"
            );

            if is_sensitive(relative) {
                warn!(
                    kind = kind_label,
                    path = %relative.display(),
                    "sensitive file changed"
                );
            }
        }
    }
}

/// Check whether a path (relative to the project root) matches any known
/// sensitive pattern.
fn is_sensitive(path: &Path) -> bool {
    let s = path.to_string_lossy();
    // Normalise Windows backslashes for pattern matching.
    let normalised = s.replace('\\', "/");

    for pattern in SENSITIVE_PATTERNS {
        // Match if any component equals the pattern or the path contains it
        // as a segment.
        if normalised == *pattern
            || normalised.ends_with(&format!("/{pattern}"))
            || normalised.starts_with(&format!("{pattern}/"))
            || normalised.contains(&format!("/{pattern}/"))
            || normalised.contains(&format!("/{pattern}"))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_env_file() {
        assert!(is_sensitive(Path::new(".env")));
        assert!(is_sensitive(Path::new("subdir/.env")));
    }

    #[test]
    fn detects_ssh_directory() {
        assert!(is_sensitive(Path::new(".ssh")));
        assert!(is_sensitive(Path::new(".ssh/id_rsa")));
    }

    #[test]
    fn detects_credentials() {
        assert!(is_sensitive(Path::new("credentials")));
        assert!(is_sensitive(Path::new(".aws/credentials")));
    }

    #[test]
    fn ignores_normal_files() {
        assert!(!is_sensitive(Path::new("src/main.rs")));
        assert!(!is_sensitive(Path::new("Cargo.toml")));
        assert!(!is_sensitive(Path::new("README.md")));
    }

    #[test]
    fn constructor_sets_root() {
        let w = FsWatcher::new(PathBuf::from("/tmp/project"));
        assert_eq!(w.root, PathBuf::from("/tmp/project"));
    }
}
