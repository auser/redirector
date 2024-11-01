use clap::Args;

use crate::{config::Config, error::RedirectorResult, server::create_server};

#[derive(Args)]
pub struct ServeCommand {
    /// Path to config file
    #[arg(short, long, default_value_t = 3000)]
    port: u16,
}
pub async fn run(mut config: Config, serve_command: Option<ServeCommand>) -> RedirectorResult<()> {
    if let Some(serve_command) = serve_command {
        config.server.port = serve_command.port;
    }

    let server = create_server(config)?;

    server.serve().await?;
    Ok(())
}
