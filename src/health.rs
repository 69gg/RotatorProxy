use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, NaiveTime, TimeZone};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    config::{AppConfig, StatusRange, parse_health_check_expected_status},
    load_proxies_from_dirs,
    meow::build_meow_nodes,
    mihomo::MihomoManager,
    outbound::connect_via_proxy_node,
    proxy::{DisabledRecheckFailure, ProxyNode, ProxyPool, TargetAddr},
};

const HEALTH_RESPONSE_HEADER_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HealthCheckScheme {
    Http,
    Https,
}

#[derive(Clone)]
struct HealthCheckTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RefreshSummary {
    pub loaded: usize,
    pub active: usize,
}

struct HealthyProxy {
    proxy: ProxyNode,
    delay: Duration,
}

#[derive(Debug, Default)]
struct DisabledRecheckStats {
    checked: usize,
    recovered: usize,
    still_disabled: usize,
    removed: usize,
}

impl DisabledRecheckStats {
    fn add(&mut self, other: Self) {
        self.checked += other.checked;
        self.recovered += other.recovered;
        self.still_disabled += other.still_disabled;
        self.removed += other.removed;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LatencyStats {
    min_ms: u128,
    p50_ms: u128,
    p90_ms: u128,
    max_ms: u128,
}

#[derive(Debug, Clone)]
struct HealthCheckTarget {
    scheme: HealthCheckScheme,
    target: TargetAddr,
    request: Arc<[u8]>,
    display: String,
    expected_status: Vec<StatusRange>,
    expected_display: String,
    tls: Option<HealthCheckTls>,
}

impl HealthCheckTarget {
    fn from_config(config: &AppConfig) -> Result<Self> {
        let url = Url::parse(&config.health_check_url)
            .with_context(|| format!("health_check_url 无效：{}", config.health_check_url))?;
        let scheme = match url.scheme() {
            "http" => HealthCheckScheme::Http,
            "https" => HealthCheckScheme::Https,
            _ => bail!("health_check_url 只支持 http:// 或 https:// URL"),
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("health_check_url 必须包含 host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("health_check_url 缺少端口"))?;

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
        let tls = match scheme {
            HealthCheckScheme::Http => None,
            HealthCheckScheme::Https => Some(HealthCheckTls::new(
                host,
                config.health_check_tls_skip_verify,
            )?),
        };
        let expected_status =
            parse_health_check_expected_status(&config.health_check_expected_status)?;
        Ok(Self {
            scheme,
            target,
            request: request.into(),
            display: config.health_check_url.clone(),
            expected_status,
            expected_display: config.health_check_expected_status.clone(),
            tls,
        })
    }
}

impl fmt::Debug for HealthCheckTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthCheckTls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl HealthCheckTls {
    fn new(host: &str, skip_verify: bool) -> Result<Self> {
        let server_name = ServerName::try_from(host.to_owned())
            .with_context(|| format!("health_check_url 的 TLS server name 无效：{host}"))?;
        Ok(Self {
            connector: build_health_tls_connector(skip_verify)
                .context("构建 HTTPS 测活 TLS 连接器失败")?,
            server_name,
        })
    }
}

#[derive(Debug)]
struct InsecureHealthCertVerifier;

impl ServerCertVerifier for InsecureHealthCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_health_tls_connector(skip_verify: bool) -> io::Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let wants_verifier = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| io::Error::other(format!("rustls 协议初始化失败：{err}")))?;

    let builder = if skip_verify {
        warn!("health_check_tls_skip_verify=true：HTTPS 测活证书校验已关闭");
        wants_verifier
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureHealthCertVerifier))
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        wants_verifier.with_root_certificates(root_store)
    };

    Ok(TlsConnector::from(Arc::new(builder.with_no_client_auth())))
}

pub async fn refresh_proxy_pool(
    config: &AppConfig,
    pool: &ProxyPool,
    _mihomo: &MihomoManager,
    reason: &str,
) -> Result<RefreshSummary> {
    info!(reason, "开始重新加载代理来源");
    let loaded_set = load_proxies_from_dirs(config).await?;
    let loaded = loaded_set.total_len();
    info!(
        reason,
        loaded_nodes = loaded,
        native_nodes = loaded_set.native.len(),
        complex_nodes = loaded_set.mihomo.len(),
        "代理节点加载完成"
    );

    let mut candidates = loaded_set.native;
    let meow_result = build_meow_nodes(loaded_set.mihomo);
    let meow_active_candidates = meow_result.nodes.len();
    let fallback_candidates = meow_result.fallback.len();
    candidates.extend(meow_result.nodes);
    info!(
        reason,
        meow_nodes = meow_active_candidates,
        skipped_fallback_nodes = fallback_candidates,
        "复杂代理原生后端准备完成"
    );
    if fallback_candidates > 0 {
        warn!(
            reason,
            skipped_fallback_nodes = fallback_candidates,
            "Mihomo fallback 已停用，原生后端不支持的复杂节点已跳过"
        );
    }

    recheck_disabled_proxies(config, pool, reason).await;
    let active = select_active_proxies(config, candidates).await?;
    let selected_len = active.len();
    if loaded > 0 && selected_len == 0 {
        warn!(
            reason,
            loaded_nodes = loaded,
            retained_active_nodes = pool.len(),
            "本次刷新没有新的健康节点，现有活动代理池保持不变"
        );
    }

    let merge = pool.merge(active);
    info!(
        reason,
        loaded_nodes = loaded,
        selected_nodes = selected_len,
        added_nodes = merge.added,
        active_nodes = merge.active,
        rejected_nodes = loaded.saturating_sub(selected_len),
        "代理刷新完成"
    );

    Ok(RefreshSummary {
        loaded,
        active: merge.active,
    })
}

async fn recheck_disabled_proxies(config: &AppConfig, pool: &ProxyPool, reason: &str) {
    let disabled = pool.disabled_proxies();
    if disabled.is_empty() {
        return;
    }

    let target = match HealthCheckTarget::from_config(config) {
        Ok(target) => Arc::new(target),
        Err(err) => {
            warn!(
                reason,
                disabled_nodes = disabled.len(),
                "失效代理静默测活配置无效，本轮跳过恢复检查：{err:#}"
            );
            return;
        }
    };
    let attempts = config.health_check_attempts.max(1);
    let timeout_ms = config.health_check_timeout_ms.max(1);
    let timeout = Duration::from_millis(timeout_ms);
    let worker_count = config
        .disabled_recheck_concurrency
        .max(1)
        .min(disabled.len());
    info!(
        reason,
        disabled_nodes = disabled.len(),
        target = %target.display,
        expected_status = %target.expected_display,
        attempts,
        timeout_ms,
        concurrency = worker_count,
        "失效代理静默健康检查开始"
    );

    let queue = Arc::new(Mutex::new(disabled.into_iter()));
    let mut checks = JoinSet::new();
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let target = Arc::clone(&target);
        let pool = pool.clone();
        checks.spawn(async move {
            let mut stats = DisabledRecheckStats::default();
            loop {
                let disabled = {
                    match queue.lock() {
                        Ok(mut queue) => queue.next(),
                        Err(err) => {
                            warn!("失效代理静默健康检查队列锁已损坏，本任务提前结束：{err}");
                            break;
                        }
                    }
                };
                let Some(disabled) = disabled else {
                    break;
                };
                let healthy = check_proxy_node(&disabled.node, &target, attempts, timeout)
                    .await
                    .is_some();
                stats.checked += 1;
                if healthy {
                    if pool.report_disabled_recheck_success(&disabled.key) {
                        stats.recovered += 1;
                        info!(
                            node = %disabled.label,
                            kind = disabled.node.kind(),
                            upstream = %disabled.node.upstream_addr(),
                            "失效代理静默测活成功，已恢复到轮询池"
                        );
                    }
                    continue;
                }

                match pool.report_disabled_recheck_failure(&disabled.key) {
                    DisabledRecheckFailure::StillDisabled {
                        failures,
                        threshold,
                    } => {
                        stats.still_disabled += 1;
                        debug!(
                            node = %disabled.label,
                            kind = disabled.node.kind(),
                            upstream = %disabled.node.upstream_addr(),
                            failures,
                            threshold,
                            "失效代理静默测活失败，继续保留在失效名单"
                        );
                    }
                    DisabledRecheckFailure::Removed {
                        failures,
                        threshold,
                    } => {
                        stats.removed += 1;
                        warn!(
                            node = %disabled.label,
                            kind = disabled.node.kind(),
                            upstream = %disabled.node.upstream_addr(),
                            failures,
                            threshold,
                            "失效代理连续静默测活失败，已从代理池删除"
                        );
                    }
                    DisabledRecheckFailure::NotDisabled => {}
                }
            }
            stats
        });
    }

    let mut stats = DisabledRecheckStats::default();
    while let Some(result) = checks.join_next().await {
        match result {
            Ok(worker_stats) => stats.add(worker_stats),
            Err(err) => warn!("失效代理静默健康检查任务失败：{err}"),
        }
    }
    info!(
        reason,
        checked_nodes = stats.checked,
        recovered_nodes = stats.recovered,
        still_disabled_nodes = stats.still_disabled,
        removed_nodes = stats.removed,
        "失效代理静默健康检查完成"
    );
}

pub fn spawn_refresh_scheduler(
    config: AppConfig,
    pool: ProxyPool,
    mihomo: MihomoManager,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(interval_seconds) = config.refresh_interval_seconds {
            let wait = Duration::from_secs(interval_seconds);
            loop {
                info!(
                    refresh_interval_seconds = interval_seconds,
                    wait_seconds = wait.as_secs(),
                    "下一次代理刷新已计划"
                );
                sleep(wait).await;

                if let Err(err) = refresh_proxy_pool(&config, &pool, &mihomo, "scheduled").await {
                    error!("定时代理刷新失败，将继续使用上一版活动代理池：{err:#}");
                }
            }
        }

        let refresh_time = match parse_daily_refresh_time(&config.daily_refresh_time) {
            Ok(refresh_time) => refresh_time,
            Err(err) => {
                error!("每日刷新调度已禁用：{err:#}");
                return;
            }
        };

        loop {
            let wait = duration_until_next_refresh(refresh_time);
            info!(
                daily_refresh_time = %config.daily_refresh_time,
                wait_seconds = wait.as_secs(),
                "下一次代理刷新已计划"
            );
            sleep(wait).await;

            if let Err(err) = refresh_proxy_pool(&config, &pool, &mihomo, "scheduled").await {
                error!("定时代理刷新失败，将继续使用上一版活动代理池：{err:#}");
            }
        }
    })
}

#[deprecated(note = "改用 spawn_refresh_scheduler，支持按间隔刷新和每日定时刷新")]
pub fn spawn_daily_refresh(
    config: AppConfig,
    pool: ProxyPool,
    mihomo: MihomoManager,
) -> JoinHandle<()> {
    spawn_refresh_scheduler(config, pool, mihomo)
}

pub fn parse_daily_refresh_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .with_context(|| format!("daily_refresh_time 必须使用 HH:MM 格式，当前值为 {value}"))
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
        info!("未加载到代理节点，将保持直连模式可用");
        return Ok(Vec::new());
    }

    let target = Arc::new(HealthCheckTarget::from_config(config)?);
    let attempts = config.health_check_attempts;
    let timeout = Duration::from_millis(config.health_check_timeout_ms);
    let total = proxies.len();
    let worker_count = config.health_check_concurrency.min(total).max(1);
    info!(
        target = %target.display,
        expected_status = %target.expected_display,
        total_nodes = total,
        attempts,
        timeout_ms = config.health_check_timeout_ms,
        concurrency = worker_count,
        "批量健康检查开始"
    );
    let queue = Arc::new(Mutex::new(proxies.into_iter()));
    let mut checks = JoinSet::new();

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let target = Arc::clone(&target);
        checks.spawn(async move {
            let mut active = Vec::new();
            loop {
                let proxy = {
                    queue
                        .lock()
                        .expect("health check queue lock poisoned")
                        .next()
                };
                let Some(proxy) = proxy else {
                    break;
                };

                let label = proxy.label();
                if let Some(delay) = check_proxy_node(&proxy, &target, attempts, timeout).await {
                    debug!(
                        node = %label,
                        delay_ms = delay.as_millis(),
                        "代理节点已加入活动代理池"
                    );
                    active.push(HealthyProxy { proxy, delay });
                } else {
                    debug!(node = %label, "代理节点未通过健康检查");
                }
            }
            active
        });
    }

    let mut active: Vec<HealthyProxy> = Vec::new();
    while let Some(result) = checks.join_next().await {
        match result {
            Ok(mut worker_active) => active.append(&mut worker_active),
            Err(err) => warn!("健康检查任务失败：{err}"),
        }
    }

    active.sort_by_key(|result| result.delay);
    let stats = latency_stats(&active);
    if let Some(stats) = stats {
        info!(
            target = %target.display,
            expected_status = %target.expected_display,
            checked_nodes = total,
            active_nodes = active.len(),
            rejected_nodes = total.saturating_sub(active.len()),
            concurrency = worker_count,
            min_delay_ms = stats.min_ms,
            p50_delay_ms = stats.p50_ms,
            p90_delay_ms = stats.p90_ms,
            max_delay_ms = stats.max_ms,
            "批量健康检查完成"
        );
    } else {
        info!(
            target = %target.display,
            expected_status = %target.expected_display,
            checked_nodes = total,
            active_nodes = 0,
            rejected_nodes = total,
            concurrency = worker_count,
            "批量健康检查完成"
        );
    }
    Ok(active.into_iter().map(|result| result.proxy).collect())
}

async fn select_active_proxies(
    config: &AppConfig,
    proxies: Vec<ProxyNode>,
) -> Result<Vec<ProxyNode>> {
    if config.health_check_enabled {
        return health_check_proxies(config, proxies).await;
    }

    let total = proxies.len();
    if total == 0 {
        info!("未加载到代理节点，将保持直连模式可用");
    } else {
        info!(
            active_nodes = total,
            "健康预检查已关闭，所有候选代理节点将直接加入活动代理池"
        );
    }
    Ok(proxies)
}

async fn check_proxy_node(
    proxy: &ProxyNode,
    target: &HealthCheckTarget,
    attempts: usize,
    timeout: Duration,
) -> Option<Duration> {
    let label = proxy.label();
    let mut last_error = None;
    for attempt in 1..=attempts {
        match run_health_check(proxy, target, timeout).await {
            Ok(delay) => {
                if attempt == 1 {
                    debug!(
                        node = %label,
                        target = %target.display,
                        delay_ms = delay.as_millis(),
                        "代理健康检查通过"
                    );
                } else {
                    debug!(
                        node = %label,
                        target = %target.display,
                        attempt,
                        delay_ms = delay.as_millis(),
                        "代理重试后健康检查通过"
                    );
                }
                return Some(delay);
            }
            Err(err) => {
                debug!(
                    node = %label,
                    target = %target.display,
                    attempt,
                    "代理健康检查失败：{err}"
                );
                last_error = Some(err);
            }
        }
    }

    debug!(
        node = %label,
        attempts,
        "代理健康检查全部尝试失败：{}",
        last_error
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "未知错误".to_owned())
    );
    None
}

async fn run_health_check(
    proxy: &ProxyNode,
    target: &HealthCheckTarget,
    attempt_timeout: Duration,
) -> io::Result<Duration> {
    let start = Instant::now();
    match timeout(
        attempt_timeout,
        run_health_check_inner(proxy, target, attempt_timeout),
    )
    .await
    {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("测活超时，耗时 {attempt_timeout:?}"),
        )),
    }
}

async fn run_health_check_inner(
    proxy: &ProxyNode,
    target: &HealthCheckTarget,
    timeout: Duration,
) -> io::Result<()> {
    let mut stream = connect_via_proxy_node(proxy, &target.target, timeout).await?;
    let status = match target.scheme {
        HealthCheckScheme::Http => {
            stream.write_all(&target.request).await?;
            read_health_status(&mut stream).await?
        }
        HealthCheckScheme::Https => {
            let tls = target
                .tls
                .as_ref()
                .ok_or_else(|| io::Error::other("HTTPS 测活 TLS 状态缺失"))?;
            let mut tls_stream = tls
                .connector
                .connect(tls.server_name.clone(), stream)
                .await?;
            tls_stream.write_all(&target.request).await?;
            read_health_status(&mut tls_stream).await?
        }
    };
    if target
        .expected_status
        .iter()
        .any(|range| range.contains(status))
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "测活端点返回 HTTP {status}，期望 {}",
            target.expected_display
        )))
    }
}

async fn read_health_status<S>(stream: &mut S) -> io::Result<u16>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < HEALTH_RESPONSE_HEADER_LIMIT {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "连接在测活响应头读取完成前关闭",
            ));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return parse_http_status(&header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "测活响应头超过大小限制",
    ))
}

fn parse_http_status(header: &[u8]) -> io::Result<u16> {
    let text = String::from_utf8_lossy(header);
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "测活响应为空"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "测活响应缺少状态码"))?;
    if !version.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "测活响应 HTTP 版本无效",
        ));
    }
    status
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "测活响应状态码无效"))
}

fn latency_stats(active: &[HealthyProxy]) -> Option<LatencyStats> {
    if active.is_empty() {
        return None;
    }
    let delays = active
        .iter()
        .map(|result| result.delay.as_millis())
        .collect::<Vec<_>>();
    Some(LatencyStats {
        min_ms: *delays.first()?,
        p50_ms: percentile(&delays, 50)?,
        p90_ms: percentile(&delays, 90)?,
        max_ms: *delays.last()?,
    })
}

fn percentile(sorted_values: &[u128], percentile: usize) -> Option<u128> {
    if sorted_values.is_empty() {
        return None;
    }
    let index = (sorted_values.len() * percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted_values.len() - 1);
    sorted_values.get(index).copied()
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
