//! aiguard CLI — the unified entry point for the aiguard security tool.
//!
//! Subcommands:
//! - `init`    — Detect agents and write hook configurations
//! - `doctor`  — Validate the installation
//! - `hook`    — The hook entry point (reads stdin, runs engine, writes stdout)
//! - `replay`  — Launch the session replay TUI
//! - `log`     — Audit log management (tail, show, prune, export)
//! - `mcp`     — MCP server management (scan, approve)
//! - `models`  — Model management (pull)
//! - `wrap`    — Wrap an agent process with aiguard monitoring

mod cmd_doctor;
mod cmd_hook;
mod cmd_init;
mod cmd_log;
mod cmd_mcp;
mod cmd_models;
mod cmd_replay;
mod cmd_wrap;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aiguard",
    about = "Security guardrails for AI coding agents",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect installed agents and write hook configurations
    Init(cmd_init::InitArgs),

    /// Validate the aiguard installation
    Doctor,

    /// Hook entry point — called by agent shell hooks
    Hook(cmd_hook::HookArgs),

    /// Launch the session replay TUI
    Replay(cmd_replay::ReplayArgs),

    /// Audit log management
    Log(cmd_log::LogArgs),

    /// MCP server management
    Mcp(cmd_mcp::McpArgs),

    /// Model management
    Models(ModelsArgs),

    /// Wrap an agent process with aiguard monitoring
    Wrap(cmd_wrap::WrapArgs),
}

#[derive(Parser)]
struct ModelsArgs {
    #[command(subcommand)]
    command: ModelsCommand,
}

#[derive(Subcommand)]
enum ModelsCommand {
    /// Download an ONNX model for local inference
    Pull {
        /// Model identifier (e.g. "prompt-injection-v1")
        model: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    match cli.command {
        Commands::Init(args) => cmd_init::run(args).await,
        Commands::Doctor => cmd_doctor::run().await,
        Commands::Hook(args) => cmd_hook::run(args).await,
        Commands::Replay(args) => cmd_replay::run(args),
        Commands::Log(args) => cmd_log::run(args).await,
        Commands::Mcp(args) => cmd_mcp::run(args).await,
        Commands::Models(args) => match args.command {
            ModelsCommand::Pull { model } => cmd_models::run_pull(&model).await,
        },
        Commands::Wrap(args) => cmd_wrap::run(args).await,
    }
}
