pub mod config;
pub mod pty;
pub mod watcher;

pub use config::AiderConfig;
pub use pty::run_aider;
pub use watcher::FsWatcher;
