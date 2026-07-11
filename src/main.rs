use std::time::Duration;

use anyhow::{Context, Result};
use rotator_proxy::{
    AppConfig, MihomoManager, ProxyPool, config::config_path_from_args, health,
    outbound::Connector, server,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = config_path_from_args();
    let config = AppConfig::load(&config_path)?;
    init_logging(&config.log_level)?;

    let pool = ProxyPool::with_runtime_failure_policy_and_state(
        Vec::new(),
        config.max_retries,
        config.runtime_failure_threshold,
        Duration::from_secs(config.cooldown_seconds),
        config.runtime_disable_after_cooldowns,
        config
            .pool_state_enabled
            .then(|| config.pool_state_path.clone()),
    );
    let mihomo = MihomoManager::new();
    info!("启动阶段开始加载历史代理和代理来源");
    let prepared = health::prepare_proxy_refresh(&config, "startup").await?;
    let loaded_nodes = prepared.loaded();

    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("绑定代理服务监听地址 {} 失败", config.listen))?;
    let local_addr = listener.local_addr()?;
    info!(
        %local_addr,
        loaded_nodes,
        cached_nodes = pool.len(),
        "历史代理和代理来源加载完成，监听端口已绑定；健康检查转入后台"
    );

    let connector = Connector::new(
        pool.clone(),
        Duration::from_millis(config.connect_timeout_ms),
    );
    let startup_refresh =
        health::spawn_prepared_proxy_refresh(config.clone(), pool.clone(), prepared, "startup");
    let _refresh_handle =
        health::spawn_refresh_scheduler_after(startup_refresh, config.clone(), pool, mihomo);
    server::run_listener(listener, connector)
        .await
        .with_context(|| format!("代理服务在 {} 上运行失败", config.listen))
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    fmt().with_env_filter(filter).init();
    Ok(())
}
