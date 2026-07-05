use std::{
    fmt,
    fs::File,
    io,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{debug, info, warn};

use crate::{
    config::AppConfig,
    parser::MihomoProxyConfig,
    proxy::{HostPort, ProxyNode},
};

const LOCAL_LISTEN_HOST: &str = "127.0.0.1";
const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest";
const MIHOMO_STARTUP_PROBE_INTERVAL: Duration = Duration::from_millis(100);
const MIHOMO_STARTUP_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct MihomoManager {
    inner: Arc<MihomoManagerInner>,
}

struct MihomoManagerInner {
    current: Mutex<Option<MihomoGeneration>>,
    next_generation: AtomicU64,
}

impl fmt::Debug for MihomoManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MihomoManager").finish_non_exhaustive()
    }
}

impl Default for MihomoManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MihomoManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MihomoManagerInner {
                current: Mutex::new(None),
                next_generation: AtomicU64::new(1),
            }),
        }
    }

    pub async fn prepare_generation(
        &self,
        config: &AppConfig,
        proxies: Vec<MihomoProxyConfig>,
    ) -> Result<Option<MihomoPreparedGeneration>> {
        if proxies.is_empty() {
            return Ok(None);
        }
        if !config.mihomo_enabled {
            warn!(
                nodes = proxies.len(),
                "mihomo is disabled; skipping complex Clash-compatible nodes"
            );
            return Ok(None);
        }

        let binary = ensure_mihomo_binary(config).await?;
        let generation_id = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let generation_dir = config
            .mihomo_work_dir
            .join("generations")
            .join(format!("gen-{generation_id}"));
        tokio::fs::create_dir_all(&generation_dir)
            .await
            .with_context(|| format!("failed to create {}", generation_dir.display()))?;

        let reserved_ports = reserve_local_ports(proxies.len())?;
        let ports = reserved_ports
            .iter()
            .map(|listener| listener.local_addr().map(|addr| addr.port()))
            .collect::<io::Result<Vec<_>>>()
            .context("failed to inspect reserved mihomo listener ports")?;
        let generated =
            build_generation_config(generation_id, &proxies, &ports, &config.mihomo_log_level)?;
        let config_path = generation_dir.join("config.yaml");
        let yaml = serde_yaml::to_string(&generated.config)
            .context("failed to serialize mihomo generation config")?;
        tokio::fs::write(&config_path, yaml)
            .await
            .with_context(|| format!("failed to write {}", config_path.display()))?;
        drop(reserved_ports);

        let mut child = spawn_mihomo(&binary, &config_path, &generation_dir, generation_id)
            .await
            .with_context(|| format!("failed to start mihomo {}", binary.display()))?;
        wait_for_listeners(
            &mut child,
            &ports,
            Duration::from_millis(config.mihomo_startup_timeout_ms),
        )
        .await?;

        info!(
            generation = generation_id,
            nodes = generated.nodes.len(),
            "mihomo generation is ready"
        );
        Ok(Some(MihomoPreparedGeneration {
            generation: MihomoGeneration {
                id: generation_id,
                child,
                work_dir: generation_dir,
                node_count: generated.nodes.len(),
            },
            nodes: generated.nodes,
        }))
    }

    pub async fn activate(&self, generation: MihomoGeneration, retire_grace: Duration) {
        let id = generation.id;
        let node_count = generation.node_count;
        let old = {
            let mut guard = self.inner.current.lock().await;
            guard.replace(generation)
        };
        info!(
            generation = id,
            nodes = node_count,
            "mihomo generation activated"
        );
        retire_old_generation(old, retire_grace);
    }

    pub async fn deactivate(&self, retire_grace: Duration) {
        let old = {
            let mut guard = self.inner.current.lock().await;
            guard.take()
        };
        retire_old_generation(old, retire_grace);
    }
}

pub struct MihomoPreparedGeneration {
    generation: MihomoGeneration,
    nodes: Vec<ProxyNode>,
}

impl MihomoPreparedGeneration {
    pub fn generation_id(&self) -> u64 {
        self.generation.id
    }

    pub fn nodes(&self) -> &[ProxyNode] {
        &self.nodes
    }

    pub fn into_generation(self) -> MihomoGeneration {
        self.generation
    }
}

pub struct MihomoGeneration {
    id: u64,
    child: Child,
    work_dir: PathBuf,
    node_count: usize,
}

struct GeneratedMihomoConfig {
    config: serde_yaml::Value,
    nodes: Vec<ProxyNode>,
}

fn build_generation_config(
    generation_id: u64,
    proxies: &[MihomoProxyConfig],
    ports: &[u16],
    log_level: &str,
) -> Result<GeneratedMihomoConfig> {
    if proxies.len() != ports.len() {
        bail!("mihomo proxy count and listener port count differ");
    }

    let mut proxy_values = Vec::with_capacity(proxies.len());
    let mut listeners = Vec::with_capacity(proxies.len());
    let mut nodes = Vec::with_capacity(proxies.len());

    for (index, (proxy, port)) in proxies.iter().zip(ports.iter()).enumerate() {
        let internal_name = format!("rp-{generation_id}-{index}");
        let mut proxy_mapping = match proxy.value.clone() {
            serde_yaml::Value::Mapping(mapping) => mapping,
            _ => bail!("mihomo proxy {} is not a YAML mapping", proxy.name),
        };
        proxy_mapping.insert(
            serde_yaml::Value::String("name".to_owned()),
            serde_yaml::Value::String(internal_name.clone()),
        );
        proxy_mapping
            .entry(serde_yaml::Value::String("type".to_owned()))
            .or_insert_with(|| serde_yaml::Value::String(proxy.kind.clone()));
        proxy_values.push(serde_yaml::Value::Mapping(proxy_mapping));

        let mut listener = serde_yaml::Mapping::new();
        insert_yaml(
            &mut listener,
            "name",
            format!("rp-listener-{generation_id}-{index}"),
        )?;
        insert_yaml(&mut listener, "type", "mixed")?;
        insert_yaml(&mut listener, "listen", LOCAL_LISTEN_HOST)?;
        insert_yaml(&mut listener, "port", *port)?;
        insert_yaml(&mut listener, "proxy", internal_name)?;
        listeners.push(serde_yaml::Value::Mapping(listener));

        nodes.push(ProxyNode::LocalMihomo {
            addr: HostPort::new(LOCAL_LISTEN_HOST, *port)?,
            label: format!("mihomo:{}:{}", proxy.kind, proxy.name),
            generation: generation_id,
        });
    }

    let mut root = serde_yaml::Mapping::new();
    insert_yaml(&mut root, "allow-lan", false)?;
    insert_yaml(&mut root, "mode", "rule")?;
    insert_yaml(&mut root, "log-level", log_level)?;
    root.insert(
        serde_yaml::Value::String("proxies".to_owned()),
        serde_yaml::Value::Sequence(proxy_values),
    );
    root.insert(
        serde_yaml::Value::String("listeners".to_owned()),
        serde_yaml::Value::Sequence(listeners),
    );
    root.insert(
        serde_yaml::Value::String("rules".to_owned()),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("MATCH,DIRECT".to_owned())]),
    );

    Ok(GeneratedMihomoConfig {
        config: serde_yaml::Value::Mapping(root),
        nodes,
    })
}

fn insert_yaml(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: impl serde::Serialize,
) -> Result<()> {
    mapping.insert(
        serde_yaml::Value::String(key.to_owned()),
        serde_yaml::to_value(value).context("failed to serialize mihomo YAML value")?,
    );
    Ok(())
}

async fn spawn_mihomo(
    binary: &Path,
    config_path: &Path,
    work_dir: &Path,
    generation_id: u64,
) -> Result<Child> {
    let mut command = Command::new(binary);
    command
        .arg("-f")
        .arg(config_path)
        .arg("-d")
        .arg(work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn()?;
    if let Some(stdout) = child.stdout.take() {
        spawn_pipe_logger(stdout, generation_id, "stdout", false);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_pipe_logger(stderr, generation_id, "stderr", true);
    }
    Ok(child)
}

fn spawn_pipe_logger<R>(
    reader: R,
    generation_id: u64,
    stream_name: &'static str,
    is_stderr: bool,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) if is_stderr => {
                    warn!(generation = generation_id, stream = stream_name, "{line}");
                }
                Ok(Some(line)) => {
                    debug!(generation = generation_id, stream = stream_name, "{line}");
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(
                        generation = generation_id,
                        stream = stream_name,
                        "failed to read mihomo output: {err}"
                    );
                    break;
                }
            }
        }
    })
}

async fn wait_for_listeners(
    child: &mut Child,
    ports: &[u16],
    startup_timeout: Duration,
) -> Result<()> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to poll mihomo process")? {
            bail!("mihomo exited before listeners became ready: {status}");
        }

        let mut ready = true;
        for port in ports {
            let connected = timeout(
                MIHOMO_STARTUP_CONNECT_TIMEOUT,
                TcpStream::connect((LOCAL_LISTEN_HOST, *port)),
            )
            .await
            .is_ok_and(|result| result.is_ok());
            if !connected {
                ready = false;
                break;
            }
        }
        if ready {
            return Ok(());
        }
        if start.elapsed() >= startup_timeout {
            bail!("mihomo listeners were not ready within {startup_timeout:?}");
        }
        sleep(MIHOMO_STARTUP_PROBE_INTERVAL).await;
    }
}

fn reserve_local_ports(count: usize) -> Result<Vec<StdTcpListener>> {
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = StdTcpListener::bind((LOCAL_LISTEN_HOST, 0))
            .context("failed to reserve local mihomo listener port")?;
        listeners.push(listener);
    }
    Ok(listeners)
}

async fn ensure_mihomo_binary(config: &AppConfig) -> Result<PathBuf> {
    if let Some(path) = &config.mihomo_binary {
        if path.is_file() {
            return Ok(path.clone());
        }
        bail!(
            "configured mihomo_binary does not exist: {}",
            path.display()
        );
    }

    if let Some(path) = find_binary_in_path(&["mihomo", "clash-meta", "clash"]) {
        return Ok(path);
    }

    if !config.mihomo_auto_download {
        bail!("mihomo binary not found in PATH and mihomo_auto_download is false");
    }

    download_linux_mihomo(config).await
}

fn find_binary_in_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

async fn download_linux_mihomo(config: &AppConfig) -> Result<PathBuf> {
    let arch = linux_mihomo_arch()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.subscription_timeout_ms))
        .user_agent(config.subscription_user_agent.clone())
        .build()
        .context("failed to build mihomo download HTTP client")?;
    let release_body = client
        .get(GITHUB_LATEST_RELEASE_URL)
        .send()
        .await
        .context("failed to query latest mihomo release")?
        .error_for_status()
        .context("mihomo release API returned non-success status")?
        .text()
        .await
        .context("failed to read mihomo release response")?;
    let release: GithubRelease =
        serde_json::from_str(&release_body).context("failed to parse mihomo release response")?;
    let asset = select_linux_asset(&release, arch)
        .ok_or_else(|| anyhow!("latest mihomo release has no linux {arch} gzip asset"))?;
    let safe_tag = release.tag_name.replace('/', "_");
    let binary_path = config
        .mihomo_work_dir
        .join("bin")
        .join(format!("mihomo-{safe_tag}-linux-{arch}"));
    if binary_path.is_file() {
        return Ok(binary_path);
    }

    info!(
        tag = %release.tag_name,
        asset = %asset.name,
        path = %binary_path.display(),
        "downloading mihomo binary"
    );
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("failed to download {}", asset.browser_download_url))?
        .error_for_status()
        .context("mihomo binary download returned non-success status")?
        .bytes()
        .await
        .context("failed to read mihomo binary download")?;

    let parent = binary_path
        .parent()
        .ok_or_else(|| anyhow!("invalid mihomo binary path {}", binary_path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let output_path = binary_path.clone();
    tokio::task::spawn_blocking(move || decompress_gzip_to_executable(&bytes, &output_path))
        .await
        .context("mihomo binary decompression task failed")??;
    Ok(binary_path)
}

fn linux_mihomo_arch() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("amd64"),
        ("linux", "aarch64") => Ok("arm64"),
        ("linux", other) => bail!("automatic mihomo download does not support linux {other}"),
        (os, arch) => bail!(
            "automatic mihomo download currently supports linux amd64/arm64 only; got {os}/{arch}"
        ),
    }
}

fn decompress_gzip_to_executable(bytes: &[u8], output_path: &Path) -> Result<()> {
    let temp_path = output_path.with_extension("tmp");
    let mut decoder = GzDecoder::new(bytes);
    let mut output = File::create(&temp_path)
        .with_context(|| format!("failed to create {}", temp_path.display()))?;
    io::copy(&mut decoder, &mut output).context("failed to decompress mihomo gzip asset")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = output
            .metadata()
            .context("failed to read decompressed mihomo metadata")?
            .permissions();
        permissions.set_mode(0o755);
        output
            .set_permissions(permissions)
            .context("failed to chmod mihomo binary")?;
    }
    drop(output);
    std::fs::rename(&temp_path, output_path).with_context(|| {
        format!(
            "failed to move {} to {}",
            temp_path.display(),
            output_path.display()
        )
    })?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn select_linux_asset<'a>(release: &'a GithubRelease, arch: &str) -> Option<&'a GithubAsset> {
    let exact = format!("mihomo-linux-{arch}-{}.gz", release.tag_name);
    release
        .assets
        .iter()
        .find(|asset| asset.name == exact)
        .or_else(|| {
            release.assets.iter().find(|asset| {
                asset.name.starts_with(&format!("mihomo-linux-{arch}-"))
                    && asset.name.ends_with(".gz")
                    && !asset.name.contains("compatible")
                    && !asset.name.contains("-v1-")
                    && !asset.name.contains("-v2-")
                    && !asset.name.contains("-v3-")
            })
        })
}

fn retire_old_generation(generation: Option<MihomoGeneration>, retire_grace: Duration) {
    let Some(generation) = generation else {
        return;
    };
    tokio::spawn(async move {
        let id = generation.id;
        info!(
            generation = id,
            grace_seconds = retire_grace.as_secs(),
            "mihomo generation scheduled for retirement"
        );
        sleep(retire_grace).await;
        retire_generation_now(generation).await;
    });
}

async fn retire_generation_now(mut generation: MihomoGeneration) {
    let id = generation.id;
    match generation.child.try_wait() {
        Ok(Some(status)) => debug!(generation = id, %status, "mihomo generation already exited"),
        Ok(None) => {
            if let Err(err) = generation.child.kill().await {
                warn!(generation = id, "failed to kill mihomo generation: {err}");
            }
            let _ = generation.child.wait().await;
            info!(generation = id, "mihomo generation retired");
        }
        Err(err) => warn!(
            generation = id,
            "failed to inspect mihomo generation: {err}"
        ),
    }
    if let Err(err) = tokio::fs::remove_dir_all(&generation.work_dir).await
        && err.kind() != io::ErrorKind::NotFound
    {
        warn!(
            generation = id,
            path = %generation.work_dir.display(),
            "failed to remove mihomo generation directory: {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mihomo_proxy(name: &str, kind: &str) -> MihomoProxyConfig {
        let value = serde_yaml::from_str(&format!(
            r#"
name: {name}
type: {kind}
server: example.com
port: 443
uuid: 00000000-0000-0000-0000-000000000000
"#
        ))
        .unwrap();
        MihomoProxyConfig {
            name: name.to_owned(),
            kind: kind.to_owned(),
            value,
        }
    }

    #[test]
    fn generation_config_binds_each_listener_to_one_proxy() {
        let generated = build_generation_config(
            7,
            &[
                mihomo_proxy("vmess-a", "vmess"),
                mihomo_proxy("trojan-a", "trojan"),
            ],
            &[21001, 21002],
            "warning",
        )
        .unwrap();
        let text = serde_yaml::to_string(&generated.config).unwrap();

        assert!(text.contains("proxy: rp-7-0"));
        assert!(text.contains("proxy: rp-7-1"));
        assert!(text.contains("type: mixed"));
        assert_eq!(generated.nodes.len(), 2);
        assert_eq!(generated.nodes[0].label(), "mihomo:vmess:vmess-a");
        assert_eq!(generated.nodes[1].mihomo_generation(), Some(7));
    }

    #[test]
    fn selects_exact_linux_asset_first() {
        let release = GithubRelease {
            tag_name: "v1.19.27".to_owned(),
            assets: vec![
                GithubAsset {
                    name: "mihomo-linux-amd64-v3-v1.19.27.gz".to_owned(),
                    browser_download_url: "https://example.com/v3.gz".to_owned(),
                },
                GithubAsset {
                    name: "mihomo-linux-amd64-v1.19.27.gz".to_owned(),
                    browser_download_url: "https://example.com/base.gz".to_owned(),
                },
            ],
        };

        let asset = select_linux_asset(&release, "amd64").unwrap();
        assert_eq!(asset.browser_download_url, "https://example.com/base.gz");
    }
}
