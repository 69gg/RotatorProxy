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

    let pool = ProxyPool::with_runtime_options(
        Vec::new(),
        config.max_retries,
        config.runtime_failure_threshold,
        Duration::from_secs(config.cooldown_seconds),
    );
    let mihomo = MihomoManager::new();
    info!("startup proxy refresh begins before service starts");
    let summary = health::refresh_proxy_pool(&config, &pool, &mihomo, "startup").await?;
    info!(
        loaded_nodes = summary.loaded,
        active_nodes = summary.active,
        "startup proxy refresh finished; starting service"
    );

    let connector = Connector::new(
        pool.clone(),
        Duration::from_millis(config.connect_timeout_ms),
    );
    let _refresh_handle = health::spawn_daily_refresh(config.clone(), pool, mihomo);
    server::run(&config.listen, connector)
        .await
        .with_context(|| format!("proxy server failed on {}", config.listen))
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    fmt().with_env_filter(filter).init();
    Ok(())
}
