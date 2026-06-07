//! Shell-hook adapter for coding agents.
//!
//! This crate provides normalizers that translate between agent-specific
//! shell hook wire formats (stdin JSON / stdout JSON + exit code) and
//! tether-core's `PolicyEngine`.

pub mod claude_code;
pub mod cline;
pub mod codex;
pub mod crush;
pub mod gemini;
pub mod handler;
pub mod normalize;

pub use handler::handle_hook;
pub use normalize::{HookEvent, HookEventType, HookResponse, Normalizer};
