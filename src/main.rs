use redirector::{config::Config, error::RedirectorResult, server::create_server};

// Example usage in your main.rs
#[tokio::main]
async fn main() -> RedirectorResult<()> {
    let config = Config::load()?;

    let server = create_server(config)?;

    server.serve().await?;

    Ok(())
}
