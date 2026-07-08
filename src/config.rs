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
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const SUPPORTED_SUBSCRIPTION_PROXY_SCHEMES: &[&str] =
    &["http", "https", "socks4", "socks4a", "socks5", "socks5h"];
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_HEALTH_CHECK_ENABLED: bool = true;
const DEFAULT_HEALTH_CHECK_URL: &str = "http://cp.cloudflare.com/generate_204";
const DEFAULT_HEALTH_CHECK_EXPECTED_STATUS: &str = "200-399";
const DEFAULT_HEALTH_CHECK_ATTEMPTS: usize = 3;
const DEFAULT_HEALTH_CHECK_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_HEALTH_CHECK_CONCURRENCY: usize = 256;
const DEFAULT_HEALTH_CHECK_TLS_SKIP_VERIFY: bool = false;
const DEFAULT_RUNTIME_FAILURE_THRESHOLD: usize = 3;
const DEFAULT_RUNTIME_DISABLE_AFTER_COOLDOWNS: usize = 2;
const DEFAULT_COOLDOWN_SECONDS: u64 = 300;
const DEFAULT_POOL_STATE_ENABLED: bool = true;
const DEFAULT_POOL_STATE_PATH: &str = ".rotator-proxy/pool-state.json";
const DEFAULT_DAILY_REFRESH_TIME: &str = "04:00";
const DEFAULT_MIHOMO_ENABLED: bool = false;
const DEFAULT_MIHOMO_AUTO_DOWNLOAD: bool = false;
const DEFAULT_MIHOMO_WORK_DIR: &str = ".rotator-proxy/mihomo";
const DEFAULT_MIHOMO_LOG_LEVEL: &str = "warning";
const DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MIHOMO_RETIRE_GRACE_SECONDS: u64 = 300;
const DEFAULT_MIHOMO_GENERATION_BATCH_SIZE: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub listen: String,
    pub proxy_dirs: Vec<PathBuf>,
    pub max_retries: usize,
    pub connect_timeout_ms: u64,
    pub subscription_timeout_ms: u64,
    pub subscription_user_agent: String,
    pub subscription_proxy: Option<String>,
    pub log_level: String,
    pub health_check_enabled: bool,
    pub health_check_url: String,
    pub health_check_expected_status: String,
    pub health_check_attempts: usize,
    pub health_check_timeout_ms: u64,
    pub health_check_concurrency: usize,
    pub health_check_tls_skip_verify: bool,
    pub runtime_failure_threshold: usize,
    pub runtime_disable_after_cooldowns: usize,
    pub cooldown_seconds: u64,
    pub pool_state_enabled: bool,
    pub pool_state_path: PathBuf,
    pub daily_refresh_time: String,
    pub refresh_interval_seconds: Option<u64>,
    pub mihomo_enabled: bool,
    pub mihomo_binary: Option<PathBuf>,
    pub mihomo_auto_download: bool,
    pub mihomo_work_dir: PathBuf,
    pub mihomo_log_level: String,
    pub mihomo_startup_timeout_ms: u64,
    pub mihomo_retire_grace_seconds: u64,
    pub mihomo_generation_batch_size: usize,
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
            subscription_proxy: None,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            health_check_enabled: DEFAULT_HEALTH_CHECK_ENABLED,
            health_check_url: DEFAULT_HEALTH_CHECK_URL.to_owned(),
            health_check_expected_status: DEFAULT_HEALTH_CHECK_EXPECTED_STATUS.to_owned(),
            health_check_attempts: DEFAULT_HEALTH_CHECK_ATTEMPTS,
            health_check_timeout_ms: DEFAULT_HEALTH_CHECK_TIMEOUT_MS,
            health_check_concurrency: DEFAULT_HEALTH_CHECK_CONCURRENCY,
            health_check_tls_skip_verify: DEFAULT_HEALTH_CHECK_TLS_SKIP_VERIFY,
            runtime_failure_threshold: DEFAULT_RUNTIME_FAILURE_THRESHOLD,
            runtime_disable_after_cooldowns: DEFAULT_RUNTIME_DISABLE_AFTER_COOLDOWNS,
            cooldown_seconds: DEFAULT_COOLDOWN_SECONDS,
            pool_state_enabled: DEFAULT_POOL_STATE_ENABLED,
            pool_state_path: PathBuf::from(DEFAULT_POOL_STATE_PATH),
            daily_refresh_time: DEFAULT_DAILY_REFRESH_TIME.to_owned(),
            refresh_interval_seconds: None,
            mihomo_enabled: DEFAULT_MIHOMO_ENABLED,
            mihomo_binary: None,
            mihomo_auto_download: DEFAULT_MIHOMO_AUTO_DOWNLOAD,
            mihomo_work_dir: PathBuf::from(DEFAULT_MIHOMO_WORK_DIR),
            mihomo_log_level: DEFAULT_MIHOMO_LOG_LEVEL.to_owned(),
            mihomo_startup_timeout_ms: DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS,
            mihomo_retire_grace_seconds: DEFAULT_MIHOMO_RETIRE_GRACE_SECONDS,
            mihomo_generation_batch_size: DEFAULT_MIHOMO_GENERATION_BATCH_SIZE,
        }
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败：{}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("解析配置文件失败：{}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.connect_timeout_ms == 0 {
            bail!("connect_timeout_ms 必须大于 0");
        }
        if self.subscription_timeout_ms == 0 {
            bail!("subscription_timeout_ms 必须大于 0");
        }
        if self.subscription_user_agent.trim().is_empty() {
            bail!("subscription_user_agent 不能为空");
        }
        if let Some(proxy) = &self.subscription_proxy {
            validate_subscription_proxy(proxy)?;
        }
        if self.health_check_enabled {
            let health_url = Url::parse(&self.health_check_url)
                .with_context(|| format!("health_check_url 无效：{}", self.health_check_url))?;
            if !matches!(health_url.scheme(), "http" | "https") {
                bail!("health_check_url 只支持 http:// 或 https:// URL");
            }
            if health_url.host_str().is_none() {
                bail!("health_check_url 必须包含 host");
            }
            parse_health_check_expected_status(&self.health_check_expected_status)?;
            if self.health_check_attempts == 0 {
                bail!("health_check_attempts 必须大于 0");
            }
            if self.health_check_timeout_ms == 0 {
                bail!("health_check_timeout_ms 必须大于 0");
            }
            if self.health_check_concurrency == 0 {
                bail!("health_check_concurrency 必须大于 0");
            }
        }
        if self.runtime_failure_threshold == 0 {
            bail!("runtime_failure_threshold 必须大于 0");
        }
        if self.runtime_disable_after_cooldowns == 0 {
            bail!("runtime_disable_after_cooldowns 必须大于 0");
        }
        if self.cooldown_seconds == 0 {
            bail!("cooldown_seconds 必须大于 0");
        }
        if self.pool_state_enabled && self.pool_state_path.as_os_str().is_empty() {
            bail!("pool_state_enabled=true 时 pool_state_path 不能为空");
        }
        if self
            .refresh_interval_seconds
            .is_some_and(|seconds| seconds == 0)
        {
            bail!("refresh_interval_seconds 必须大于 0");
        }
        if self.refresh_interval_seconds.is_none() {
            NaiveTime::parse_from_str(&self.daily_refresh_time, "%H:%M").with_context(|| {
                format!(
                    "daily_refresh_time 必须使用 HH:MM 格式，当前值为 {}",
                    self.daily_refresh_time
                )
            })?;
        }
        if self.mihomo_enabled {
            if self.mihomo_work_dir.as_os_str().is_empty() {
                bail!("mihomo_enabled=true 时 mihomo_work_dir 不能为空");
            }
            if self.mihomo_log_level.trim().is_empty() {
                bail!("mihomo_enabled=true 时 mihomo_log_level 不能为空");
            }
            if self.mihomo_startup_timeout_ms == 0 {
                bail!("mihomo_startup_timeout_ms 必须大于 0");
            }
            if self.mihomo_retire_grace_seconds == 0 {
                bail!("mihomo_retire_grace_seconds 必须大于 0");
            }
            if self.mihomo_generation_batch_size == 0 {
                bail!("mihomo_generation_batch_size 必须大于 0");
            }
        }
        Ok(())
    }
}

pub fn supported_subscription_proxy_scheme(scheme: &str) -> bool {
    SUPPORTED_SUBSCRIPTION_PROXY_SCHEMES.contains(&scheme)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StatusRange {
    pub start: u16,
    pub end: u16,
}

impl StatusRange {
    pub fn contains(self, status: u16) -> bool {
        (self.start..=self.end).contains(&status)
    }
}

pub fn parse_health_check_expected_status(value: &str) -> Result<Vec<StatusRange>> {
    let value = value.trim();
    if value.is_empty() {
        bail!("health_check_expected_status 不能为空");
    }

    let ranges = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(parse_status_range)
        .collect::<Result<Vec<_>>>()?;
    if ranges.is_empty() {
        bail!("health_check_expected_status 必须包含至少一个状态码或范围");
    }
    Ok(ranges)
}

fn parse_status_range(value: &str) -> Result<StatusRange> {
    let (start, end) = value.split_once('-').unwrap_or((value, value));
    let start = parse_http_status_code(start)?;
    let end = parse_http_status_code(end)?;
    if start > end {
        bail!("health_check_expected_status 范围起点不能大于终点：{value}");
    }
    Ok(StatusRange { start, end })
}

fn parse_http_status_code(value: &str) -> Result<u16> {
    let status = value
        .parse::<u16>()
        .with_context(|| format!("health_check_expected_status 状态码无效：{value}"))?;
    if !(100..=599).contains(&status) {
        bail!("health_check_expected_status 状态码必须在 100-599：{status}");
    }
    Ok(status)
}

fn validate_subscription_proxy(proxy: &str) -> Result<()> {
    let proxy = proxy.trim();
    if proxy.is_empty() {
        bail!("subscription_proxy 设置后不能为空");
    }
    let url = Url::parse(proxy).with_context(|| format!("subscription_proxy URL 无效：{proxy}"))?;
    if !supported_subscription_proxy_scheme(url.scheme()) {
        bail!(
            "subscription_proxy 只支持这些协议：{}",
            SUPPORTED_SUBSCRIPTION_PROXY_SCHEMES.join(", ")
        );
    }
    if url.host_str().is_none() {
        bail!("subscription_proxy 必须包含 host");
    }
    Ok(())
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
        assert_eq!(
            config.health_check_url,
            "http://cp.cloudflare.com/generate_204"
        );
        assert_eq!(config.health_check_expected_status, "200-399");
        assert_eq!(config.health_check_attempts, DEFAULT_HEALTH_CHECK_ATTEMPTS);
        assert!(config.health_check_enabled);
        assert_eq!(
            config.runtime_disable_after_cooldowns,
            DEFAULT_RUNTIME_DISABLE_AFTER_COOLDOWNS
        );
        assert!(config.pool_state_enabled);
        assert_eq!(
            config.pool_state_path,
            PathBuf::from(".rotator-proxy/pool-state.json")
        );
        assert_eq!(config.refresh_interval_seconds, None);
        assert!(config.subscription_proxy.is_none());
        assert!(!config.mihomo_enabled);
        assert!(!config.mihomo_auto_download);
        assert_eq!(
            config.mihomo_startup_timeout_ms,
            DEFAULT_MIHOMO_STARTUP_TIMEOUT_MS
        );
        assert_eq!(
            config.mihomo_generation_batch_size,
            DEFAULT_MIHOMO_GENERATION_BATCH_SIZE
        );
        assert_eq!(config.proxy_dirs, vec![PathBuf::from("./fixtures")]);
        config.validate().unwrap();
    }

    #[test]
    fn accepts_zero_retries_as_full_pool_attempts() {
        let config = AppConfig {
            max_retries: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_https_health_check_url() {
        let config = AppConfig {
            health_check_url: "https://example.com/".to_owned(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_socks_subscription_proxy() {
        let config = AppConfig {
            subscription_proxy: Some("socks5h://127.0.0.1:1080".to_owned()),
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_unsupported_subscription_proxy_scheme() {
        let config = AppConfig {
            subscription_proxy: Some("ftp://127.0.0.1:21".to_owned()),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unsupported_health_check_url_scheme() {
        let config = AppConfig {
            health_check_url: "ftp://example.com/".to_owned(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_health_check_ignores_health_target_settings() {
        let config = AppConfig {
            health_check_enabled: false,
            health_check_url: "not a url".to_owned(),
            health_check_expected_status: String::new(),
            health_check_attempts: 0,
            health_check_timeout_ms: 0,
            health_check_concurrency: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn parses_health_check_expected_status_ranges() {
        let ranges = parse_health_check_expected_status("204, 200-299").unwrap();
        assert!(ranges.iter().any(|range| range.contains(204)));
        assert!(ranges.iter().any(|range| range.contains(250)));
        assert!(!ranges.iter().any(|range| range.contains(404)));
    }

    #[test]
    fn rejects_invalid_health_check_expected_status() {
        let config = AppConfig {
            health_check_expected_status: "600".to_owned(),
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
    fn refresh_interval_overrides_daily_refresh_validation() {
        let config = AppConfig {
            refresh_interval_seconds: Some(3600),
            daily_refresh_time: "25:00".to_owned(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_zero_refresh_interval() {
        let config = AppConfig {
            refresh_interval_seconds: Some(0),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_runtime_disable_after_cooldowns() {
        let config = AppConfig {
            runtime_disable_after_cooldowns: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_pool_state_allows_empty_path() {
        let config = AppConfig {
            pool_state_enabled: false,
            pool_state_path: PathBuf::new(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn enabled_pool_state_rejects_empty_path() {
        let config = AppConfig {
            pool_state_enabled: true,
            pool_state_path: PathBuf::new(),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_mihomo_startup_timeout() {
        let config = AppConfig {
            mihomo_enabled: true,
            mihomo_startup_timeout_ms: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_mihomo_generation_batch_size() {
        let config = AppConfig {
            mihomo_enabled: true,
            mihomo_generation_batch_size: 0,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
