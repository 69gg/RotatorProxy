use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::NaiveTime;
use serde::Deserialize;
use url::Url;

const DEFAULT_LISTEN: &str = "127.0.0.1:7890";
const DEFAULT_MAX_RETRIES: usize = 10;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_SUBSCRIPTION_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_USER_AGENT: &str = "RotatorProxy/0.1";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_HEALTH_CHECK_URL: &str = "http://example.com/";
const DEFAULT_HEALTH_CHECK_ATTEMPTS: usize = 3;
const DEFAULT_HEALTH_CHECK_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_HEALTH_CHECK_CONCURRENCY: usize = 32;
const DEFAULT_RUNTIME_FAILURE_THRESHOLD: usize = 3;
const DEFAULT_COOLDOWN_SECONDS: u64 = 300;
const DEFAULT_DAILY_REFRESH_TIME: &str = "04:00";
const DEFAULT_MIHOMO_ENABLED: bool = true;
const DEFAULT_MIHOMO_AUTO_DOWNLOAD: bool = true;
const DEFAULT_MIHOMO_WORK_DIR: &str = ".rotator-proxy/mihomo";
const DEFAULT_MIHOMO_LOG_LEVEL: &str = "warning";
const DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MIHOMO_RETIRE_GRACE_SECONDS: u64 = 300;

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
    pub health_check_url: String,
    pub health_check_attempts: usize,
    pub health_check_timeout_ms: u64,
    pub health_check_concurrency: usize,
    pub runtime_failure_threshold: usize,
    pub cooldown_seconds: u64,
    pub daily_refresh_time: String,
    pub mihomo_enabled: bool,
    pub mihomo_binary: Option<PathBuf>,
    pub mihomo_auto_download: bool,
    pub mihomo_work_dir: PathBuf,
    pub mihomo_log_level: String,
    pub mihomo_startup_timeout_ms: u64,
    pub mihomo_retire_grace_seconds: u64,
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
            health_check_url: DEFAULT_HEALTH_CHECK_URL.to_owned(),
            health_check_attempts: DEFAULT_HEALTH_CHECK_ATTEMPTS,
            health_check_timeout_ms: DEFAULT_HEALTH_CHECK_TIMEOUT_MS,
            health_check_concurrency: DEFAULT_HEALTH_CHECK_CONCURRENCY,
            runtime_failure_threshold: DEFAULT_RUNTIME_FAILURE_THRESHOLD,
            cooldown_seconds: DEFAULT_COOLDOWN_SECONDS,
            daily_refresh_time: DEFAULT_DAILY_REFRESH_TIME.to_owned(),
            mihomo_enabled: DEFAULT_MIHOMO_ENABLED,
            mihomo_binary: None,
            mihomo_auto_download: DEFAULT_MIHOMO_AUTO_DOWNLOAD,
            mihomo_work_dir: PathBuf::from(DEFAULT_MIHOMO_WORK_DIR),
            mihomo_log_level: DEFAULT_MIHOMO_LOG_LEVEL.to_owned(),
            mihomo_startup_timeout_ms: DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS,
            mihomo_retire_grace_seconds: DEFAULT_MIHOMO_RETIRE_GRACE_SECONDS,
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
        let health_url = Url::parse(&self.health_check_url)
            .with_context(|| format!("invalid health_check_url {}", self.health_check_url))?;
        if health_url.scheme() != "http" {
            bail!("health_check_url currently supports only http:// URLs");
        }
        if health_url.host_str().is_none() {
            bail!("health_check_url must include a host");
        }
        if self.health_check_attempts == 0 {
            bail!("health_check_attempts must be greater than 0");
        }
        if self.health_check_timeout_ms == 0 {
            bail!("health_check_timeout_ms must be greater than 0");
        }
        if self.health_check_concurrency == 0 {
            bail!("health_check_concurrency must be greater than 0");
        }
        if self.runtime_failure_threshold == 0 {
            bail!("runtime_failure_threshold must be greater than 0");
        }
        if self.cooldown_seconds == 0 {
            bail!("cooldown_seconds must be greater than 0");
        }
        NaiveTime::parse_from_str(&self.daily_refresh_time, "%H:%M").with_context(|| {
            format!(
                "daily_refresh_time must use HH:MM, got {}",
                self.daily_refresh_time
            )
        })?;
        if self.mihomo_enabled {
            if self.mihomo_work_dir.as_os_str().is_empty() {
                bail!("mihomo_work_dir must not be empty when mihomo_enabled is true");
            }
            if self.mihomo_log_level.trim().is_empty() {
                bail!("mihomo_log_level must not be empty when mihomo_enabled is true");
            }
            if self.mihomo_startup_timeout_ms == 0 {
                bail!("mihomo_startup_timeout_ms must be greater than 0");
            }
            if self.mihomo_retire_grace_seconds == 0 {
                bail!("mihomo_retire_grace_seconds must be greater than 0");
            }
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
        assert_eq!(config.health_check_attempts, DEFAULT_HEALTH_CHECK_ATTEMPTS);
        assert_eq!(
            config.mihomo_startup_timeout_ms,
            DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS
        );
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

    #[test]
    fn rejects_https_health_check_url() {
        let config = AppConfig {
            health_check_url: "https://example.com/".to_owned(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_daily_refresh_time() {
        let config = AppConfig {
            daily_refresh_time: "25:00".to_owned(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_mihomo_startup_timeout() {
        let config = AppConfig {
            mihomo_startup_timeout_ms: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
