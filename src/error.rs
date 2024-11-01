use crate::config;

pub type RedirectorResult<T = (), E = RedirectorError> = Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum RedirectorError {
    #[error("Failed to load config")]
    Config(#[from] config::ConfigError),
    #[error("Failed to create server")]
    Server(#[from] axum::Error),
    #[error("Failed to bind to address")]
    Bind(#[from] std::io::Error),
    #[error("Failed to parse header: {0}")]
    HeaderParsing(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Config parsing error: {0}")]
    ConfigParsing(#[from] serde_yaml::Error),
}
