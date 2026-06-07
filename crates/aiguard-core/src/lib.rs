#![allow(clippy::result_large_err)]

pub mod audit;
pub mod config;
pub mod decision;
pub mod engine;
pub mod error;
pub mod policy;
pub mod redact;
pub mod scanner;

pub use audit::{AuditEvent, AuditLog};
pub use config::{load_policy, load_policy_from, locate_config};
pub use decision::{aggregate, Decision};
pub use engine::PolicyEngine;
pub use error::{AiguardError, Result};
pub use policy::*;
pub use redact::{RedactMatch, Redactor};
pub use scanner::*;
