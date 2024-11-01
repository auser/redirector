use crate::error::RedirectorResult;

pub async fn run() -> RedirectorResult<()> {
    println!("Redirector {}", env!("CARGO_PKG_VERSION"));
    println!("Version: {}", crate::get_version());
    Ok(())
}
