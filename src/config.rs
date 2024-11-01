// src/config.rs
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::RedirectorResult;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub redis: RedisConfig,
    #[serde(default)]
    pub redirect: RedirectConfig,
    #[serde(default)]
    pub app: AppConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    #[serde(default = "default_redis_url")]
    pub url: String,
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_redis_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedirectConfig {
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u32,
    #[serde(default = "default_forward_headers")]
    pub forward_headers: bool,
    #[serde(default = "default_match_header")]
    pub match_header: String,
    #[serde(default = "default_allow_location_header")]
    pub allow_location_header: String,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            max_redirects: default_max_redirects(),
            forward_headers: default_forward_headers(),
            match_header: default_match_header(),
            allow_location_header: default_allow_location_header(),
        }
    }
}

impl RedirectConfig {
    pub fn matches_header(&self, header_name: &str) -> bool {
        self.match_header.to_lowercase() == header_name.to_lowercase()
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AppConfig {
    #[serde(default = "default_account_id")]
    pub account_id: String,
    #[serde(default = "default_state_ttl")]
    pub state_ttl_seconds: u64,
}

fn default_max_redirects() -> u32 {
    5
}
fn default_forward_headers() -> bool {
    true
}
fn default_match_header() -> String {
    "X-Forwarded-Server".to_string()
}
fn default_allow_location_header() -> String {
    "X-Allow-Location".to_string()
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_request_timeout() -> u64 {
    30
}
fn default_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}
fn default_redis_pool_size() -> u32 {
    20
}
fn default_redis_timeout() -> u64 {
    5
}

fn default_account_id() -> String {
    "default".to_string()
}

fn default_state_ttl() -> u64 {
    300
}

impl Config {
    pub fn load(config_path: Option<String>) -> RedirectorResult<Self> {
        // Try loading from config file first
        let config_path = match config_path {
            Some(path) => path.to_string(),
            None => {
                std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/config.yaml".to_owned())
            }
        };

        let mut config = if Path::new(&config_path).exists() {
            Config::from_file(&config_path)?
        } else {
            Config::default()
        };

        // Override with environment variables
        config.update_from_env();

        Ok(config)
    }

    fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| ConfigError::FileError(e.to_string()))?;

        serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    pub fn load_from_path(path: &str) -> RedirectorResult<Self> {
        let file = std::fs::File::open(path)?;
        let config = serde_yaml::from_reader(file)?;
        Ok(config)
    }

    fn update_from_env(&mut self) {
        if let Ok(val) = std::env::var("SERVER_HOST") {
            self.server.host = val;
        }
        if let Ok(val) = std::env::var("SERVER_PORT") {
            if let Ok(port) = val.parse() {
                self.server.port = port;
            }
        }
        if let Ok(val) = std::env::var("REDIS_URL") {
            self.redis.url = val;
        }
        if let Ok(val) = std::env::var("REDIS_POOL_SIZE") {
            if let Ok(size) = val.parse() {
                self.redis.pool_size = size;
            }
        }

        if let Ok(val) = std::env::var("ACCOUNT_ID") {
            self.app.account_id = val;
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
                request_timeout_seconds: default_request_timeout(),
            },
            redis: RedisConfig {
                url: default_redis_url(),
                pool_size: default_redis_pool_size(),
                timeout_seconds: default_redis_timeout(),
            },
            redirect: RedirectConfig::default(),
            app: AppConfig::default(),
        }
    }
}

pub fn get_version() -> String {
    let system_name =
        std::env::var("VERGEN_SYSINFO_NAME").unwrap_or_else(|_| "unknown".to_string());
    let branch = std::env::var("VERGEN_GIT_BRANCH").unwrap_or_else(|_| "main".to_string());
    let sha = std::env::var("VERGEN_GIT_SHA").unwrap_or_else(|_| "unknown".to_string());
    let time = std::env::var("VERGEN_BUILD_TIMESTAMP").unwrap_or_else(|_| "unknown".to_string());
    format!("{} {} {} {}", system_name, branch, sha, time)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    FileError(String),
    #[error("Failed to parse config: {0}")]
    ParseError(String),
}
