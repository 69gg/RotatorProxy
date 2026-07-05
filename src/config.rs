use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_LISTEN: &str = "127.0.0.1:7890";
const DEFAULT_MAX_RETRIES: usize = 10;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_SUBSCRIPTION_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_USER_AGENT: &str = "RotatorProxy/0.1";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub listen: String,
    pub proxy_dirs: Vec<PathBuf>,
    pub max_retries: usize,
    pub connect_timeout_ms: u64,
    pub subscription_timeout_ms: u64,
    pub subscription_user_agent: String,
    pub log_level: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_owned(),
            proxy_dirs: vec![PathBuf::from("./proxies")],
            max_retries: DEFAULT_MAX_RETRIES,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            subscription_timeout_ms: DEFAULT_SUBSCRIPTION_TIMEOUT_MS,
            subscription_user_agent: DEFAULT_USER_AGENT.to_owned(),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
        }
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_retries == 0 {
            bail!("max_retries must be greater than 0");
        }
        if self.connect_timeout_ms == 0 {
            bail!("connect_timeout_ms must be greater than 0");
        }
        if self.subscription_timeout_ms == 0 {
            bail!("subscription_timeout_ms must be greater than 0");
        }
        if self.subscription_user_agent.trim().is_empty() {
            bail!("subscription_user_agent must not be empty");
        }
        Ok(())
    }
}

pub fn config_path_from_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                if let Some(path) = args.next() {
                    return PathBuf::from(path);
                }
            }
            _ if !arg.starts_with('-') => return PathBuf::from(arg),
            _ => {}
        }
    }
    PathBuf::from("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        AppConfig::default().validate().unwrap();
    }

    #[test]
    fn parses_config_with_defaults() {
        let raw = r#"
listen = "127.0.0.1:9000"
proxy_dirs = ["./fixtures"]
"#;
        let config: AppConfig = toml::from_str(raw).unwrap();
        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(config.proxy_dirs, vec![PathBuf::from("./fixtures")]);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_zero_retries() {
        let config = AppConfig {
            max_retries: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
