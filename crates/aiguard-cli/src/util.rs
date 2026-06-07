/// Resolve the path to the SQLite audit database.
///
/// Uses the platform-appropriate data directory (via `directories`) with a
/// fallback to `~/.local/share/aiguard/audit.db`.
pub fn resolve_db_path() -> String {
    if let Some(dirs) = directories::ProjectDirs::from("", "", "aiguard") {
        dirs.data_dir()
            .join("audit.db")
            .to_string_lossy()
            .to_string()
    } else {
        "~/.local/share/aiguard/audit.db".to_string()
    }
}
