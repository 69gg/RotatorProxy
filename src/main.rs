use std::time::Duration;

use anyhow::{Context, Result};
use rotator_proxy::{
    AppConfig, ProxyPool, config::config_path_from_args, load_proxies_from_dirs,
    outbound::Connector, server,
};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = config_path_from_args();
    let config = AppConfig::load(&config_path)?;
    init_logging(&config.log_level)?;

    let proxies = load_proxies_from_dirs(&config).await?;
    info!("loaded {} outbound proxies", proxies.len());

    let pool = ProxyPool::new(proxies, config.max_retries);
    let connector = Connector::new(pool, Duration::from_millis(config.connect_timeout_ms));
    server::run(&config.listen, connector)
        .await
        .with_context(|| format!("proxy server failed on {}", config.listen))
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    fmt().with_env_filter(filter).init();
    Ok(())
}
