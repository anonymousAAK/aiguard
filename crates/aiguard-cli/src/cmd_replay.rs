//! `aiguard replay [session-id]` — Launch the session replay TUI.
//!
//! Thin wrapper around the aiguard-replay crate.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub struct ReplayArgs {
    /// Session ID to replay. Omit to list available sessions.
    session_id: Option<String>,

    /// Replay the most recent session
    #[arg(long)]
    last: bool,
}

pub fn run(args: ReplayArgs) -> Result<()> {
    let db_path = crate::util::resolve_db_path();

    if args.last {
        return aiguard_replay::run_replay_last(&db_path);
    }

    match args.session_id {
        Some(session_id) => aiguard_replay::run_replay(&session_id, &db_path),
        None => {
            // List available sessions
            let sessions = aiguard_replay::events::list_sessions(&db_path)?;
            if sessions.is_empty() {
                println!("No sessions found in the audit log.");
                println!("Events will appear here after aiguard hooks process tool calls.");
                return Ok(());
            }

            println!(
                "{:<40} {:<12} {:<20} EVENTS",
                "SESSION ID", "AGENT", "LAST ACTIVITY"
            );
            println!("{}", "-".repeat(85));
            for session in &sessions {
                println!(
                    "{:<40} {:<12} {:<20} {}",
                    session.session_id,
                    session.agent,
                    &session.last_ts[..std::cmp::min(19, session.last_ts.len())],
                    session.event_count,
                );
            }
            println!("\nUse `aiguard replay <session-id>` to view a session.");
            println!("Use `aiguard replay --last` to view the most recent session.");
            Ok(())
        }
    }
}
