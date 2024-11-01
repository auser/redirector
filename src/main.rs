use redirector::{cli::run_cli, error::RedirectorResult};

#[tokio::main]
async fn main() -> RedirectorResult<()> {
    run_cli().await?;
    Ok(())
}
