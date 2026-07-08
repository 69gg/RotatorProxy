use std::time::Duration;

use anyhow::{Context, Result};
use rotator_proxy::{
    AppConfig, MihomoManager, ProxyPool, config::config_path_from_args, health,
    outbound::Connector, server,
};
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
    info!("启动阶段开始刷新代理，完成前暂不提供服务");
    let summary = health::refresh_proxy_pool(&config, &pool, &mihomo, "startup").await?;
    info!(
        loaded_nodes = summary.loaded,
        active_nodes = summary.active,
        "启动阶段代理刷新完成，开始提供服务"
    );

    let connector = Connector::new(
        pool.clone(),
        Duration::from_millis(config.connect_timeout_ms),
    );
    let _refresh_handle = health::spawn_refresh_scheduler(config.clone(), pool, mihomo);
    server::run(&config.listen, connector)
        .await
        .with_context(|| format!("代理服务在 {} 上运行失败", config.listen))
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    fmt().with_env_filter(filter).init();
    Ok(())
}
