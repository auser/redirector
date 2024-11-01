use clap::{Parser, Subcommand};
use serve::ServeCommand;

use crate::{config::Config, error::RedirectorResult};

mod serve;
mod version;

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long, default_value = "config/config.yaml")]
    pub config: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the redirector server (default)
    Serve(ServeCommand),
    /// Display version information
    Version,
}

pub async fn run_cli() -> RedirectorResult<()> {
    let cli = Cli::parse();
    let config = Config::load(cli.config)?;

    match cli.command {
        Some(Commands::Version) => version::run().await,
        Some(Commands::Serve(serve_command)) => serve::run(config, Some(serve_command)).await,
        _ => serve::run(config, None).await,
    }
}
