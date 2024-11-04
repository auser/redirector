use crate::error::RedirectorResult;

pub async fn run() -> RedirectorResult<()> {
    println!("Redirector {}", env!("CARGO_PKG_VERSION"));
    println!(
        "Build time: {}",
        std::env::var("VERGEN_BUILD_TIMESTAMP").unwrap_or_else(|_| "unknown".to_string())
    );
    println!(
        "Git branch: {}",
        std::env::var("VERGEN_GIT_BRANCH").unwrap_or_else(|_| "unknown".to_string())
    );
    println!(
        "Git SHA: {}",
        std::env::var("VERGEN_GIT_SHA").unwrap_or_else(|_| "unknown".to_string())
    );
    Ok(())
}
