use std::path::PathBuf;

/// Central error type for aiguard-core.
#[derive(Debug, thiserror::Error)]
pub enum AiguardError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("configuration file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    #[error("scanner error in `{scanner}`: {message}")]
    Scanner { scanner: String, message: String },

    #[error("audit log error: {0}")]
    Audit(String),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("figment error: {0}")]
    Figment(#[from] figment::Error),

    #[error("zstd compression error: {0}")]
    Compression(String),

    #[error("tool denied by policy: {tool} matched deny pattern `{pattern}`")]
    ToolDenied { tool: String, pattern: String },

    #[error("path denied by policy: {path} matched deny pattern `{pattern}`")]
    PathDenied { path: String, pattern: String },
}

pub type Result<T> = std::result::Result<T, AiguardError>;
