use std::{
    collections::HashSet,
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
    parser::{MihomoProxyConfig, SubscriptionOptions, build_subscription_client},
    proxy::{HostPort, ProxyNode},
    resource::is_file_descriptor_exhaustion,
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
    current: Mutex<Vec<MihomoGeneration>>,
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
                current: Mutex::new(Vec::new()),
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
                "Mihomo 未启用，将跳过这些复杂 Clash 兼容节点"
            );
            return Ok(None);
        }

        let binary = ensure_mihomo_binary(config).await?;
        let configured_batch_size = config.mihomo_generation_batch_size.max(1);
        let planned_batch_count =
            mihomo_generation_batch_count(proxies.len(), configured_batch_size);
        let mut active_batch_size = configured_batch_size;
        let mut generations = Vec::with_capacity(planned_batch_count);
        let mut nodes = Vec::with_capacity(proxies.len());
        let mut offset = 0;
        let mut batch_index = 0;
        while offset < proxies.len() {
            let end = (offset + active_batch_size).min(proxies.len());
            let batch = &proxies[offset..end];
            let reserved_ports = match reserve_local_ports(batch.len()) {
                Ok(listeners) => listeners,
                Err(err) if batch.len() > 1 && is_file_descriptor_exhaustion(&err) => {
                    active_batch_size = (batch.len() / 2).max(1);
                    warn!(
                        requested_nodes = batch.len(),
                        retry_batch_size = active_batch_size,
                        "预留 Mihomo 本地监听端口失败，已自动缩小批次后重试：{err}"
                    );
                    continue;
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("预留 {} 个本地 Mihomo 监听端口失败", batch.len())
                    });
                }
            };
            let prepared = self
                .prepare_generation_batch(config, &binary, batch, reserved_ports, batch_index)
                .await?;
            nodes.extend(prepared.nodes);
            generations.push(prepared.generation);
            offset = end;
            batch_index += 1;
        }
        info!(
            generations = generations.len(),
            nodes = nodes.len(),
            configured_batch_size,
            "Mihomo 批次全部准备就绪"
        );
        Ok(Some(MihomoPreparedGeneration { generations, nodes }))
    }

    async fn prepare_generation_batch(
        &self,
        config: &AppConfig,
        binary: &Path,
        proxies: &[MihomoProxyConfig],
        reserved_ports: Vec<StdTcpListener>,
        batch_index: usize,
    ) -> Result<PreparedBatch> {
        let generation_id = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let generation_dir = config
            .mihomo_work_dir
            .join("generations")
            .join(format!("gen-{generation_id}"));
        tokio::fs::create_dir_all(&generation_dir)
            .await
            .with_context(|| format!("创建目录失败：{}", generation_dir.display()))?;

        let ports = reserved_ports
            .iter()
            .map(|listener| listener.local_addr().map(|addr| addr.port()))
            .collect::<io::Result<Vec<_>>>()
            .context("读取已预留的 Mihomo 监听端口失败")?;
        let generated =
            build_generation_config(generation_id, proxies, &ports, &config.mihomo_log_level)?;
        let config_path = generation_dir.join("config.yaml");
        let yaml =
            serde_yaml::to_string(&generated.config).context("序列化 Mihomo 批次配置失败")?;
        tokio::fs::write(&config_path, yaml)
            .await
            .with_context(|| format!("写入配置失败：{}", config_path.display()))?;
        drop(reserved_ports);

        let mut child = spawn_mihomo(binary, &config_path, &generation_dir, generation_id)
            .await
            .with_context(|| format!("启动 Mihomo 失败：{}", binary.display()))?;
        wait_for_listeners(
            &mut child,
            &ports,
            Duration::from_millis(config.mihomo_startup_timeout_ms),
        )
        .await?;

        info!(
            generation = generation_id,
            nodes = generated.nodes.len(),
            batch = batch_index + 1,
            "Mihomo 批次已准备就绪"
        );
        Ok(PreparedBatch {
            generation: MihomoGeneration {
                id: generation_id,
                child,
                work_dir: generation_dir,
                node_count: generated.nodes.len(),
            },
            nodes: generated.nodes,
        })
    }

    pub async fn activate(&self, generations: Vec<MihomoGeneration>, retire_grace: Duration) {
        let generation_count = generations.len();
        let node_count = generations
            .iter()
            .map(|generation| generation.node_count)
            .sum::<usize>();
        let old = {
            let mut guard = self.inner.current.lock().await;
            std::mem::replace(&mut *guard, generations)
        };
        info!(
            generations = generation_count,
            nodes = node_count,
            "Mihomo 批次已激活"
        );
        retire_old_generations(old, retire_grace);
    }

    pub async fn deactivate(&self, retire_grace: Duration) {
        let old = {
            let mut guard = self.inner.current.lock().await;
            std::mem::take(&mut *guard)
        };
        retire_old_generations(old, retire_grace);
    }
}

pub struct MihomoPreparedGeneration {
    generations: Vec<MihomoGeneration>,
    nodes: Vec<ProxyNode>,
}

impl MihomoPreparedGeneration {
    pub fn nodes(&self) -> &[ProxyNode] {
        &self.nodes
    }

    pub fn split_active_generations(
        self,
        active_generation_ids: &HashSet<u64>,
    ) -> MihomoSplitGenerations {
        let mut active = Vec::new();
        let mut inactive = Vec::new();
        for generation in self.generations {
            if active_generation_ids.contains(&generation.id) {
                active.push(generation);
            } else {
                inactive.push(generation);
            }
        }
        MihomoSplitGenerations { active, inactive }
    }
}

pub struct MihomoSplitGenerations {
    pub active: Vec<MihomoGeneration>,
    pub inactive: Vec<MihomoGeneration>,
}

struct PreparedBatch {
    generation: MihomoGeneration,
    nodes: Vec<ProxyNode>,
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
        bail!("Mihomo 代理数量和监听端口数量不一致");
    }

    let mut proxy_values = Vec::with_capacity(proxies.len());
    let mut listeners = Vec::with_capacity(proxies.len());
    let mut nodes = Vec::with_capacity(proxies.len());

    for (index, (proxy, port)) in proxies.iter().zip(ports.iter()).enumerate() {
        let internal_name = format!("rp-{generation_id}-{index}");
        let mut proxy_mapping = match proxy.value.clone() {
            serde_yaml::Value::Mapping(mapping) => mapping,
            _ => bail!("Mihomo 代理 {} 不是 YAML mapping", proxy.name),
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

fn mihomo_generation_batch_count(nodes: usize, batch_size: usize) -> usize {
    if nodes == 0 {
        0
    } else {
        nodes.div_ceil(batch_size.max(1))
    }
}

fn insert_yaml(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
    value: impl serde::Serialize,
) -> Result<()> {
    mapping.insert(
        serde_yaml::Value::String(key.to_owned()),
        serde_yaml::to_value(value).context("序列化 Mihomo YAML 值失败")?,
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
                        "读取 Mihomo 输出失败：{err}"
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
        if let Some(status) = child.try_wait().context("检查 Mihomo 进程状态失败")? {
            bail!("Mihomo 在监听器就绪前退出：{status}");
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
            bail!("Mihomo 监听器在 {startup_timeout:?} 内未就绪");
        }
        sleep(MIHOMO_STARTUP_PROBE_INTERVAL).await;
    }
}

fn reserve_local_ports(count: usize) -> io::Result<Vec<StdTcpListener>> {
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = StdTcpListener::bind((LOCAL_LISTEN_HOST, 0))?;
        listeners.push(listener);
    }
    Ok(listeners)
}

async fn ensure_mihomo_binary(config: &AppConfig) -> Result<PathBuf> {
    if let Some(path) = &config.mihomo_binary {
        if path.is_file() {
            return Ok(path.clone());
        }
        bail!("配置的 mihomo_binary 不存在：{}", path.display());
    }

    if let Some(path) = find_binary_in_path(&["mihomo", "clash-meta", "clash"]) {
        return Ok(path);
    }

    if !config.mihomo_auto_download {
        bail!("PATH 中未找到 Mihomo 二进制文件，且 mihomo_auto_download=false");
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
    let client = build_subscription_client(&SubscriptionOptions::from(config))
        .context("构建 Mihomo 下载 HTTP 客户端失败")?;
    let release_body = client
        .get(GITHUB_LATEST_RELEASE_URL)
        .send()
        .await
        .context("查询最新 Mihomo release 失败")?
        .error_for_status()
        .context("Mihomo release API 返回非成功状态")?
        .text()
        .await
        .context("读取 Mihomo release 响应失败")?;
    let release: GithubRelease =
        serde_json::from_str(&release_body).context("解析 Mihomo release 响应失败")?;
    let asset = select_linux_asset(&release, arch)
        .ok_or_else(|| anyhow!("最新 Mihomo release 没有 linux {arch} gzip 资源"))?;
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
        "正在下载 Mihomo 二进制文件"
    );
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("下载失败：{}", asset.browser_download_url))?
        .error_for_status()
        .context("Mihomo 二进制下载返回非成功状态")?
        .bytes()
        .await
        .context("读取 Mihomo 二进制下载内容失败")?;

    let parent = binary_path
        .parent()
        .ok_or_else(|| anyhow!("Mihomo 二进制路径无效：{}", binary_path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("创建目录失败：{}", parent.display()))?;
    let output_path = binary_path.clone();
    tokio::task::spawn_blocking(move || decompress_gzip_to_executable(&bytes, &output_path))
        .await
        .context("Mihomo 二进制解压任务失败")??;
    Ok(binary_path)
}

fn linux_mihomo_arch() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("amd64"),
        ("linux", "aarch64") => Ok("arm64"),
        ("linux", other) => bail!("Mihomo 自动下载不支持 linux {other}"),
        (os, arch) => bail!("Mihomo 自动下载目前仅支持 linux amd64/arm64，当前为 {os}/{arch}"),
    }
}

fn decompress_gzip_to_executable(bytes: &[u8], output_path: &Path) -> Result<()> {
    let temp_path = output_path.with_extension("tmp");
    let mut decoder = GzDecoder::new(bytes);
    let mut output = File::create(&temp_path)
        .with_context(|| format!("创建文件失败：{}", temp_path.display()))?;
    io::copy(&mut decoder, &mut output).context("解压 Mihomo gzip 资源失败")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = output
            .metadata()
            .context("读取已解压 Mihomo 文件元数据失败")?
            .permissions();
        permissions.set_mode(0o755);
        output
            .set_permissions(permissions)
            .context("设置 Mihomo 二进制权限失败")?;
    }
    drop(output);
    std::fs::rename(&temp_path, output_path).with_context(|| {
        format!(
            "移动文件失败：{} -> {}",
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

fn retire_old_generations(generations: Vec<MihomoGeneration>, retire_grace: Duration) {
    if generations.is_empty() {
        return;
    }
    tokio::spawn(async move {
        info!(
            generations = generations.len(),
            grace_seconds = retire_grace.as_secs(),
            "Mihomo 批次已计划延迟退出"
        );
        sleep(retire_grace).await;
        for generation in generations {
            retire_generation_now(generation).await;
        }
    });
}

async fn retire_generation_now(mut generation: MihomoGeneration) {
    let id = generation.id;
    match generation.child.try_wait() {
        Ok(Some(status)) => debug!(generation = id, %status, "Mihomo 批次已经退出"),
        Ok(None) => {
            if let Err(err) = generation.child.kill().await {
                warn!(generation = id, "终止 Mihomo 批次失败：{err}");
            }
            let _ = generation.child.wait().await;
            info!(generation = id, "Mihomo 批次已退出");
        }
        Err(err) => warn!(generation = id, "检查 Mihomo 批次状态失败：{err}"),
    }
    if let Err(err) = tokio::fs::remove_dir_all(&generation.work_dir).await
        && err.kind() != io::ErrorKind::NotFound
    {
        warn!(
            generation = id,
            path = %generation.work_dir.display(),
            "删除 Mihomo 批次目录失败：{err}"
        );
    }
}

pub fn retire_unused_generations(generations: Vec<MihomoGeneration>) {
    retire_old_generations(generations, Duration::ZERO);
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
    fn counts_mihomo_generation_batches() {
        assert_eq!(mihomo_generation_batch_count(0, 256), 0);
        assert_eq!(mihomo_generation_batch_count(1, 256), 1);
        assert_eq!(mihomo_generation_batch_count(256, 256), 1);
        assert_eq!(mihomo_generation_batch_count(257, 256), 2);
        assert_eq!(mihomo_generation_batch_count(10, 0), 10);
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
