//! `aiguard log` — Audit log management subcommands.
//!
//! Subcommands:
//! - `tail`   — Show recent events
//! - `show`   — Show a single event detail
//! - `prune`  — Delete events older than retention period
//! - `export` — Export events as JSONL

use std::fs::OpenOptions;
use std::io::Write as IoWrite;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use aiguard_core::{load_policy, AuditLog};
use aiguard_replay::events;

#[derive(Parser)]
pub struct LogArgs {
    #[command(subcommand)]
    command: LogCommand,
}

#[derive(Subcommand)]
enum LogCommand {
    /// Show recent audit events
    Tail {
        /// Number of events to show
        #[arg(short = 'n', long, default_value = "20")]
        count: usize,

        /// Filter by decision type (allow, block, warn)
        #[arg(long)]
        filter: Option<String>,
    },

    /// Show a single event by ID
    Show {
        /// Event ID to display
        id: String,
    },

    /// Prune old events (honors retention_days from config)
    Prune {
        /// Override retention days from config
        #[arg(long)]
        days: Option<u32>,

        /// Actually delete (without this flag, only shows what would be deleted)
        #[arg(long)]
        confirm: bool,
    },

    /// Export events as JSONL
    Export {
        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Filter by session ID
        #[arg(long)]
        session: Option<String>,

        /// Export as JSONL format
        #[arg(long)]
        jsonl: bool,
    },
}

pub async fn run(args: LogArgs) -> Result<()> {
    let db_path = crate::util::resolve_db_path();

    match args.command {
        LogCommand::Tail { count, filter } => cmd_tail(&db_path, count, filter),
        LogCommand::Show { id } => cmd_show(&db_path, &id),
        LogCommand::Prune { days, confirm } => cmd_prune(days, confirm),
        LogCommand::Export {
            output,
            session,
            jsonl: _,
        } => cmd_export(&db_path, output, session),
    }
}

/// Show recent events.
fn cmd_tail(db_path: &str, count: usize, filter: Option<String>) -> Result<()> {
    let events = events::tail_events(db_path, count)?;

    if events.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    println!(
        "{:<8} {:<20} {:<12} {:<12} {:<15} DECISION",
        "ID", "TIMESTAMP", "AGENT", "STAGE", "TOOL"
    );
    println!("{}", "-".repeat(85));

    for event in &events {
        if let Some(ref f) = filter {
            if !event.decision.contains(f.as_str()) {
                continue;
            }
        }

        let ts_short = if event.ts.len() > 19 {
            &event.ts[..19]
        } else {
            &event.ts
        };
        let tool = event.tool_name.as_deref().unwrap_or("-");
        let id_short = if event.id.len() > 8 {
            &event.id[..8]
        } else {
            &event.id
        };

        println!(
            "{:<8} {:<20} {:<12} {:<12} {:<15} {}",
            id_short, ts_short, event.agent, event.stage, tool, event.decision
        );
    }

    println!("\n{} event(s) shown.", events.len());
    Ok(())
}

/// Show a single event in detail.
fn cmd_show(db_path: &str, event_id: &str) -> Result<()> {
    let event = events::get_event(db_path, event_id)?
        .with_context(|| format!("Event not found: {event_id}"))?;

    println!("Event ID:    {}", event.id);
    println!("Timestamp:   {}", event.ts);
    println!("Session:     {}", event.session_id);
    println!("Agent:       {}", event.agent);
    println!("Stage:       {}", event.stage);
    println!(
        "Tool:        {}",
        event.tool_name.as_deref().unwrap_or("<none>")
    );
    println!("Decision:    {}", event.decision);
    println!("Duration:    {}us", event.duration_us);
    println!("Input Hash:  {}", event.input_hash);
    println!();
    println!("--- Scanner Results ---");
    let scanners_pretty =
        serde_json::to_string_pretty(&event.scanners).unwrap_or_else(|_| "{}".to_string());
    println!("{scanners_pretty}");

    if let Some(ref payload) = event.payload {
        println!();
        println!("--- Payload ({} bytes) ---", payload.len());
        match String::from_utf8(payload.clone()) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("<binary data, {} bytes>", payload.len()),
        }
    }

    Ok(())
}

/// Prune old events.
fn cmd_prune(days_override: Option<u32>, confirm: bool) -> Result<()> {
    let policy = load_policy()?;
    let mut logging_config = policy.logging.clone();

    if let Some(days) = days_override {
        logging_config.retention_days = days;
    }

    let log = AuditLog::open(&logging_config)?;

    if !confirm {
        println!(
            "Would prune events older than {} days.",
            logging_config.retention_days
        );
        println!("Use --confirm to actually delete events.");
        return Ok(());
    }

    let deleted = log.prune()?;
    println!(
        "Pruned {deleted} event(s) older than {} days.",
        logging_config.retention_days
    );

    Ok(())
}

/// Export events as JSONL.
fn cmd_export(db_path: &str, output: Option<String>, session: Option<String>) -> Result<()> {
    let events = if let Some(ref session_id) = session {
        events::load_events(db_path, session_id)?
    } else {
        // Export all recent events
        events::tail_events(db_path, 10000)?
    };

    if events.is_empty() {
        eprintln!("No events to export.");
        return Ok(());
    }

    match output {
        Some(path) => {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .with_context(|| format!("Failed to open output file: {path}"))?;

            for event in &events {
                let line = serde_json::to_string(event)?;
                writeln!(file, "{line}")?;
            }
            println!("Exported {} events to {path}", events.len());
        }
        None => {
            // Write to stdout
            for event in &events {
                let line = serde_json::to_string(event)?;
                println!("{line}");
            }
        }
    }

    Ok(())
}
