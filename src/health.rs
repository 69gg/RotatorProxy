use std::{io, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, NaiveTime, TimeZone};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::sleep,
};
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    config::AppConfig,
    load_proxies_from_dirs,
    mihomo::{MihomoManager, MihomoPreparedGeneration},
    outbound::{BoxedStream, connect_via_proxy_node},
    proxy::{ProxyNode, ProxyPool, TargetAddr},
};

const HEALTH_RESPONSE_HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RefreshSummary {
    pub loaded: usize,
    pub active: usize,
}

#[derive(Debug, Clone)]
struct HealthCheckTarget {
    target: TargetAddr,
    request: Vec<u8>,
    display: String,
}

impl HealthCheckTarget {
    fn from_config(config: &AppConfig) -> Result<Self> {
        let url = Url::parse(&config.health_check_url)
            .with_context(|| format!("invalid health_check_url {}", config.health_check_url))?;
        if url.scheme() != "http" {
            bail!("health_check_url currently supports only http:// URLs");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("health_check_url must include a host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("health_check_url is missing a port"))?;

        let mut path = url.path().to_owned();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let target = TargetAddr::new(host, port)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
            config.subscription_user_agent
        )
        .into_bytes();
        Ok(Self {
            target,
            request,
            display: config.health_check_url.clone(),
        })
    }
}

pub async fn refresh_proxy_pool(
    config: &AppConfig,
    pool: &ProxyPool,
    mihomo: &MihomoManager,
    reason: &str,
) -> Result<RefreshSummary> {
    info!(reason, "starting proxy source reload and health check");
    let loaded_set = load_proxies_from_dirs(config).await?;
    let loaded = loaded_set.total_len();
    info!(
        reason,
        loaded_nodes = loaded,
        native_nodes = loaded_set.native.len(),
        mihomo_nodes = loaded_set.mihomo.len(),
        "loaded proxy nodes"
    );

    let mut candidates = loaded_set.native;
    let prepared_mihomo = match mihomo.prepare_generation(config, loaded_set.mihomo).await {
        Ok(prepared) => prepared,
        Err(err) => {
            warn!("failed to prepare mihomo nodes; complex nodes will be skipped: {err:#}");
            None
        }
    };
    if let Some(prepared) = &prepared_mihomo {
        candidates.extend_from_slice(prepared.nodes());
    }

    let active = health_check_proxies(config, candidates).await?;
    let active_len = active.len();
    if loaded > 0 && active_len == 0 {
        warn!(
            reason,
            loaded_nodes = loaded,
            "all configured proxy nodes failed health checks; pool will be empty"
        );
    }

    apply_mihomo_generation(mihomo, prepared_mihomo, &active, config).await;
    pool.replace(active);
    info!(
        reason,
        loaded_nodes = loaded,
        active_nodes = active_len,
        rejected_nodes = loaded.saturating_sub(active_len),
        "proxy refresh completed"
    );

    Ok(RefreshSummary {
        loaded,
        active: active_len,
    })
}

async fn apply_mihomo_generation(
    mihomo: &MihomoManager,
    prepared: Option<MihomoPreparedGeneration>,
    active: &[ProxyNode],
    config: &AppConfig,
) {
    let retire_grace = Duration::from_secs(config.mihomo_retire_grace_seconds);
    let Some(prepared) = prepared else {
        if !active
            .iter()
            .any(|proxy| proxy.mihomo_generation().is_some())
        {
            mihomo.deactivate(retire_grace).await;
        }
        return;
    };
    let generation = prepared.generation_id();
    let active_generation = active
        .iter()
        .any(|proxy| proxy.mihomo_generation() == Some(generation));
    if active_generation {
        mihomo
            .activate(prepared.into_generation(), retire_grace)
            .await;
    } else {
        warn!(
            generation,
            "all mihomo-backed nodes failed health checks; generation will not be activated"
        );
        mihomo.deactivate(retire_grace).await;
    }
}

pub fn spawn_daily_refresh(
    config: AppConfig,
    pool: ProxyPool,
    mihomo: MihomoManager,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let refresh_time = match parse_daily_refresh_time(&config.daily_refresh_time) {
            Ok(refresh_time) => refresh_time,
            Err(err) => {
                error!("daily refresh scheduler disabled: {err:#}");
                return;
            }
        };

        loop {
            let wait = duration_until_next_refresh(refresh_time);
            info!(
                daily_refresh_time = %config.daily_refresh_time,
                wait_seconds = wait.as_secs(),
                "next proxy refresh scheduled"
            );
            sleep(wait).await;

            if let Err(err) = refresh_proxy_pool(&config, &pool, &mihomo, "scheduled").await {
                error!("scheduled proxy refresh failed; keeping previous active pool: {err:#}");
            }
        }
    })
}

pub fn parse_daily_refresh_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .with_context(|| format!("daily_refresh_time must use HH:MM, got {value}"))
}

pub fn duration_until_next_refresh(refresh_time: NaiveTime) -> Duration {
    duration_until_next_refresh_from(Local::now(), refresh_time)
}

fn duration_until_next_refresh_from(now: DateTime<Local>, refresh_time: NaiveTime) -> Duration {
    let Some(next) = next_refresh_after(now, refresh_time) else {
        return Duration::from_secs(24 * 60 * 60);
    };
    (next - now)
        .to_std()
        .unwrap_or_else(|_| Duration::from_secs(0))
}

fn next_refresh_after(now: DateTime<Local>, refresh_time: NaiveTime) -> Option<DateTime<Local>> {
    let mut date = now.date_naive();
    for _ in 0..3 {
        if let Some(candidate) = Local
            .from_local_datetime(&date.and_time(refresh_time))
            .earliest()
            && candidate > now
        {
            return Some(candidate);
        }
        date = date.succ_opt()?;
    }
    None
}

async fn health_check_proxies(
    config: &AppConfig,
    proxies: Vec<ProxyNode>,
) -> Result<Vec<ProxyNode>> {
    if proxies.is_empty() {
        info!("no proxy nodes loaded; direct mode remains available");
        return Ok(Vec::new());
    }

    let target = Arc::new(HealthCheckTarget::from_config(config)?);
    let attempts = config.health_check_attempts;
    let timeout = Duration::from_millis(config.health_check_timeout_ms);
    let semaphore = Arc::new(Semaphore::new(config.health_check_concurrency));
    let mut checks = JoinSet::new();

    for proxy in proxies {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("health check semaphore closed");
        let target = Arc::clone(&target);
        checks.spawn(async move {
            let _permit = permit;
            let label = proxy.label();
            let healthy = check_proxy_node(proxy.clone(), &target, attempts, timeout).await;
            (proxy, label, healthy)
        });
    }

    let mut active = Vec::new();
    while let Some(result) = checks.join_next().await {
        match result {
            Ok((proxy, label, true)) => {
                debug!(node = %label, "proxy admitted to active pool");
                active.push(proxy);
            }
            Ok((_proxy, label, false)) => {
                warn!(node = %label, "proxy rejected by health check");
            }
            Err(err) => warn!("health check task failed: {err}"),
        }
    }

    Ok(active)
}

async fn check_proxy_node(
    proxy: ProxyNode,
    target: &HealthCheckTarget,
    attempts: usize,
    timeout: Duration,
) -> bool {
    let label = proxy.label();
    let mut last_error = None;
    for attempt in 1..=attempts {
        match run_health_check(proxy.clone(), target, timeout).await {
            Ok(()) => {
                if attempt == 1 {
                    debug!(node = %label, target = %target.display, "proxy health check passed");
                } else {
                    info!(
                        node = %label,
                        target = %target.display,
                        attempt,
                        "proxy health check passed after retry"
                    );
                }
                return true;
            }
            Err(err) => {
                debug!(
                    node = %label,
                    target = %target.display,
                    attempt,
                    "proxy health check failed: {err}"
                );
                last_error = Some(err);
            }
        }
    }

    warn!(
        node = %label,
        attempts,
        "proxy health check failed all attempts: {}",
        last_error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown error".to_owned())
    );
    false
}

async fn run_health_check(
    proxy: ProxyNode,
    target: &HealthCheckTarget,
    timeout: Duration,
) -> io::Result<()> {
    let mut stream = connect_via_proxy_node(proxy, &target.target, timeout).await?;
    stream.write_all(&target.request).await?;
    let status = read_health_status(&mut stream).await?;
    if (200..400).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "health endpoint returned HTTP {status}"
        )))
    }
}

async fn read_health_status(stream: &mut BoxedStream) -> io::Result<u16> {
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < HEALTH_RESPONSE_HEADER_LIMIT {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before health response header finished",
            ));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return parse_http_status(&header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "health response header exceeded limit",
    ))
}

fn parse_http_status(header: &[u8]) -> io::Result<u16> {
    let text = String::from_utf8_lossy(header);
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty health response"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing health status"))?;
    if !version.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid health response version",
        ));
    }
    status
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid health status"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn parses_daily_refresh_time() {
        let time = parse_daily_refresh_time("04:30").unwrap();
        assert_eq!(time.hour(), 4);
        assert_eq!(time.minute(), 30);
    }

    #[test]
    fn rejects_invalid_daily_refresh_time() {
        assert!(parse_daily_refresh_time("24:00").is_err());
    }

    #[test]
    fn computes_next_refresh_duration() {
        let refresh_time = parse_daily_refresh_time("04:30").unwrap();
        let duration = duration_until_next_refresh(refresh_time);
        assert!(duration <= Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn parses_http_status() {
        assert_eq!(
            parse_http_status(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap(),
            204
        );
    }
}
