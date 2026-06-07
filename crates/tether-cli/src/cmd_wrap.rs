use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct WrapArgs {
    #[command(subcommand)]
    pub command: WrapTarget,
}

#[derive(Subcommand)]
pub enum WrapTarget {
    /// Run Aider with aiguard monitoring
    Aider {
        /// Arguments to pass to aider
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

pub async fn run(args: WrapArgs) -> anyhow::Result<()> {
    match args.command {
        WrapTarget::Aider { args } => {
            aiguard_adapter_aider::run_aider(&args).await?;
            Ok(())
        }
    }
}
