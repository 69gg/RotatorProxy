use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use meow_common::{AdapterType, ProxyAdapter};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shadowsocks::{
    ServerConfig, config::ServerAddr, crypto::CipherKind, relay::socks5::Address as ShadowAddress,
};
use tracing::{debug, info, warn};

use crate::{meow::build_meow_nodes, parser::MihomoProxyConfig};

const FAILURE_SHARDS: usize = 64;
const DEFAULT_RUNTIME_DISABLE_AFTER_COOLDOWNS: usize = 2;
const DEFAULT_DISABLED_RECHECK_DELETE_AFTER_FAILURES: usize = 3;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            bail!("host 不能为空");
        }
        Ok(Self { host, port })
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') && self.host.parse::<IpAddr>().is_ok() {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: Option<String>,
}

#[derive(Clone)]
pub struct MeowProxyNode {
    pub adapter: Arc<dyn ProxyAdapter>,
    pub key: String,
    pub label: String,
    pub source: MihomoProxyConfig,
}

impl fmt::Debug for MeowProxyNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MeowProxyNode")
            .field("key", &self.key)
            .field("label", &self.label)
            .field("adapter", &self.adapter.name())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum ProxyNode {
    Http {
        addr: HostPort,
        auth: Option<Credentials>,
    },
    Https {
        addr: HostPort,
        auth: Option<Credentials>,
        sni: Option<String>,
        skip_cert_verify: bool,
    },
    Socks5 {
        addr: HostPort,
        auth: Option<Credentials>,
        remote_dns: bool,
    },
    Socks4 {
        addr: HostPort,
        auth: Option<Credentials>,
        remote_dns: bool,
    },
    Shadowsocks {
        server: Arc<ServerConfig>,
        label: String,
    },
    LocalMihomo {
        addr: HostPort,
        label: String,
        generation: u64,
    },
    Meow(MeowProxyNode),
}

impl ProxyNode {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Https { .. } => "https",
            Self::Socks5 { .. } => "socks5",
            Self::Socks4 { .. } => "socks4",
            Self::Shadowsocks { .. } => "shadowsocks",
            Self::LocalMihomo { .. } => "mihomo",
            Self::Meow(node) => meow_adapter_kind(node.adapter.adapter_type()),
        }
    }

    pub fn upstream_addr(&self) -> String {
        match self {
            Self::Http { addr, .. }
            | Self::Https { addr, .. }
            | Self::Socks5 { addr, .. }
            | Self::Socks4 { addr, .. }
            | Self::LocalMihomo { addr, .. } => addr.to_string(),
            Self::Shadowsocks { server, .. } => server.addr().to_string(),
            Self::Meow(node) => node.adapter.addr().to_owned(),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Http { addr, .. } => format!("http://{addr}"),
            Self::Https { addr, .. } => format!("https://{addr}"),
            Self::Socks5 {
                addr, remote_dns, ..
            } => {
                let scheme = if *remote_dns { "socks5h" } else { "socks5" };
                format!("{scheme}://{addr}")
            }
            Self::Socks4 {
                addr, remote_dns, ..
            } => {
                let scheme = if *remote_dns { "socks4a" } else { "socks4" };
                format!("{scheme}://{addr}")
            }
            Self::Shadowsocks { label, .. } => label.clone(),
            Self::LocalMihomo { label, .. } => label.clone(),
            Self::Meow(node) => node.label.clone(),
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Http { addr, auth } => format!("http://{}{}", auth_key(auth.as_ref()), addr),
            Self::Https {
                addr,
                auth,
                sni,
                skip_cert_verify,
            } => format!(
                "https://{}{}?sni={}&skip-cert-verify={skip_cert_verify}",
                auth_key(auth.as_ref()),
                addr,
                sni.as_deref().unwrap_or("")
            ),
            Self::Socks5 {
                addr,
                auth,
                remote_dns,
            } => {
                let scheme = if *remote_dns { "socks5h" } else { "socks5" };
                format!("{scheme}://{}{}", auth_key(auth.as_ref()), addr)
            }
            Self::Socks4 {
                addr,
                auth,
                remote_dns,
            } => {
                let scheme = if *remote_dns { "socks4a" } else { "socks4" };
                format!("{scheme}://{}{}", auth_key(auth.as_ref()), addr)
            }
            Self::Shadowsocks { server, .. } => {
                format!("ss://{}@{}", server.method(), server.addr())
            }
            Self::LocalMihomo {
                addr,
                label,
                generation,
            } => {
                format!("mihomo://{generation}/{label}@{addr}")
            }
            Self::Meow(node) => node.key.clone(),
        }
    }

    pub fn mihomo_generation(&self) -> Option<u64> {
        match self {
            Self::LocalMihomo { generation, .. } => Some(*generation),
            _ => None,
        }
    }
}

fn auth_key(auth: Option<&Credentials>) -> String {
    auth.map(|auth| {
        let password = auth.password.as_deref().unwrap_or("");
        format!("{}:{password}@", auth.username)
    })
    .unwrap_or_default()
}

fn meow_adapter_kind(kind: AdapterType) -> &'static str {
    match kind {
        AdapterType::Direct => "direct",
        AdapterType::Reject => "reject",
        AdapterType::RejectDrop => "reject-drop",
        AdapterType::Selector => "selector",
        AdapterType::Fallback => "fallback",
        AdapterType::UrlTest => "url-test",
        AdapterType::LoadBalance => "load-balance",
        AdapterType::Relay => "relay",
        AdapterType::Shadowsocks => "shadowsocks",
        AdapterType::Socks5 => "socks5",
        AdapterType::Http => "http",
        AdapterType::Vmess => "vmess",
        AdapterType::Vless => "vless",
        AdapterType::Trojan => "trojan",
        AdapterType::Hysteria2 => "hysteria2",
        AdapterType::Anytls => "anytls",
        AdapterType::Snell => "snell",
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetAddr {
    pub host: String,
    pub port: u16,
}

impl TargetAddr {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            bail!("目标 host 不能为空");
        }
        Ok(Self { host, port })
    }

    pub fn parse(authority: &str, default_port: Option<u16>) -> Result<Self> {
        let authority = authority.trim();
        if authority.is_empty() {
            bail!("目标 authority 为空");
        }

        if let Some(rest) = authority.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| anyhow!("IPv6 authority 无效：{authority}"))?;
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse()?,
                None => default_port.ok_or_else(|| anyhow!("authority 缺少端口：{authority}"))?,
            };
            return Self::new(host, port);
        }

        if let Some((host, port)) = authority.rsplit_once(':')
            && !host.contains(':')
        {
            return Self::new(host, port.parse()?);
        }

        let port = default_port.ok_or_else(|| anyhow!("authority 缺少端口：{authority}"))?;
        Self::new(authority, port)
    }

    pub fn to_shadow_address(&self) -> ShadowAddress {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            ShadowAddress::SocketAddress(SocketAddr::new(ip, self.port))
        } else {
            ShadowAddress::DomainNameAddress(self.host.clone(), self.port)
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') && self.host.parse::<IpAddr>().is_ok() {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProxyChoice {
    Direct,
    Proxy(Arc<ProxyEntry>),
}

impl ProxyChoice {
    pub fn label(&self) -> String {
        match self {
            Self::Direct => "direct".to_owned(),
            Self::Proxy(entry) => entry.label.clone(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy(entry) => entry.node.kind(),
        }
    }

    pub fn upstream_addr(&self, target: &TargetAddr) -> String {
        match self {
            Self::Direct => target.to_string(),
            Self::Proxy(entry) => entry.node.upstream_addr(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEntry {
    pub key: String,
    pub label: String,
    pub node: Arc<ProxyNode>,
}

impl ProxyEntry {
    fn from_node(node: ProxyNode) -> Self {
        let key = node.key();
        let label = node.label();
        Self {
            key,
            label,
            node: Arc::new(node),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PoolMergeSummary {
    pub previous: usize,
    pub added: usize,
    pub skipped_existing: usize,
    pub skipped_retired: usize,
    pub active: usize,
}

#[derive(Debug, Clone)]
pub struct DisabledProxy {
    pub key: String,
    pub label: String,
    pub node: ProxyNode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DisabledRecheckFailure {
    StillDisabled { failures: usize, threshold: usize },
    Removed { failures: usize, threshold: usize },
    NotDisabled,
}

#[derive(Debug)]
pub struct ProxyPool {
    inner: Arc<ProxyPoolInner>,
}

#[derive(Debug)]
struct ProxyPoolInner {
    state: RwLock<PoolState>,
    selection: Mutex<SelectionBag>,
    state_path: Option<PathBuf>,
    state_persistence: Mutex<()>,
    max_retries: usize,
    runtime_failure_threshold: usize,
    runtime_disable_after_cooldowns: usize,
    cooldown: Duration,
    failures: Vec<Mutex<HashMap<String, FailureRecord>>>,
}

#[derive(Debug, Clone)]
struct FailureRecord {
    failures: usize,
    cooldowns: usize,
    cooldown_until: Option<Instant>,
    disabled: bool,
    disabled_recheck_failures: usize,
}

#[derive(Debug)]
struct PoolState {
    proxies: Arc<Vec<Arc<ProxyEntry>>>,
    retired_hashes: HashSet<String>,
    disabled_by_hash: HashMap<String, PersistedDisabledProxy>,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PersistedPoolState {
    version: u8,
    #[serde(default)]
    available: Vec<PersistedProxyNode>,
    #[serde(default)]
    disabled: Vec<PersistedDisabledProxy>,
    #[serde(default)]
    retired: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PersistedDisabledProxy {
    key_hash: String,
    disabled_recheck_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PersistedProxyNode {
    Http {
        addr: HostPort,
        auth: Option<Credentials>,
    },
    Https {
        addr: HostPort,
        auth: Option<Credentials>,
        sni: Option<String>,
        skip_cert_verify: bool,
    },
    Socks5 {
        addr: HostPort,
        auth: Option<Credentials>,
        remote_dns: bool,
    },
    Socks4 {
        addr: HostPort,
        auth: Option<Credentials>,
        remote_dns: bool,
    },
    Shadowsocks {
        host: String,
        port: u16,
        method: String,
        password: String,
        label: String,
    },
    Meow {
        source: MihomoProxyConfig,
    },
}

#[derive(Debug, Default)]
struct SelectionBag {
    generation: u64,
    remaining: Vec<usize>,
}

impl SelectionBag {
    fn reset(&mut self, generation: u64) {
        self.generation = generation;
        self.remaining.clear();
    }

    fn next_index(&mut self, generation: u64, len: usize) -> Option<(usize, bool)> {
        if len == 0 {
            return None;
        }
        let mut refilled = false;
        if self.generation != generation || self.remaining.is_empty() {
            self.generation = generation;
            self.remaining = (0..len).collect();
            self.remaining.shuffle(&mut rand::rng());
            refilled = true;
        }
        self.remaining.pop().map(|index| (index, refilled))
    }
}

impl ProxyPool {
    pub fn new(proxies: Vec<ProxyNode>, max_retries: usize) -> Self {
        Self::with_runtime_options(proxies, max_retries, 3, Duration::from_secs(300))
    }

    pub fn with_runtime_options(
        proxies: Vec<ProxyNode>,
        max_retries: usize,
        runtime_failure_threshold: usize,
        cooldown: Duration,
    ) -> Self {
        Self::with_runtime_failure_policy(
            proxies,
            max_retries,
            runtime_failure_threshold,
            cooldown,
            DEFAULT_RUNTIME_DISABLE_AFTER_COOLDOWNS,
        )
    }

    pub fn with_runtime_failure_policy(
        proxies: Vec<ProxyNode>,
        max_retries: usize,
        runtime_failure_threshold: usize,
        cooldown: Duration,
        runtime_disable_after_cooldowns: usize,
    ) -> Self {
        Self::with_runtime_failure_policy_and_state(
            proxies,
            max_retries,
            runtime_failure_threshold,
            cooldown,
            runtime_disable_after_cooldowns,
            None,
        )
    }

    pub fn with_runtime_failure_policy_and_state(
        proxies: Vec<ProxyNode>,
        max_retries: usize,
        runtime_failure_threshold: usize,
        cooldown: Duration,
        runtime_disable_after_cooldowns: usize,
        state_path: Option<PathBuf>,
    ) -> Self {
        let persisted =
            state_path
                .as_deref()
                .and_then(|path| match load_persisted_pool_state(path) {
                    Ok(state) => Some(state),
                    Err(err) => {
                        warn!(
                            path = %path.display(),
                            "代理池状态文件加载失败，将按空状态启动：{err:#}"
                        );
                        None
                    }
                });
        let retired_hashes = persisted
            .as_ref()
            .map(|state| state.retired.iter().cloned().collect::<HashSet<_>>())
            .unwrap_or_default();
        let disabled_by_hash = persisted
            .as_ref()
            .map(|state| {
                state
                    .disabled
                    .iter()
                    .cloned()
                    .map(|entry| (entry.key_hash.clone(), entry))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        let persisted_proxies = persisted
            .as_ref()
            .map(|state| restore_persisted_proxy_nodes(&state.available))
            .unwrap_or_default();
        let persisted_proxy_count = persisted_proxies.len();
        let mut initial_entries = entries_from_nodes(persisted_proxies);
        initial_entries.extend(entries_from_nodes(proxies));
        let mut known = HashSet::new();
        initial_entries.retain(|entry| {
            let key_hash = proxy_key_hash(&entry.key);
            !retired_hashes.contains(&key_hash) && known.insert(entry.key.clone())
        });

        let pool = Self {
            inner: Arc::new(ProxyPoolInner {
                state: RwLock::new(PoolState {
                    proxies: Arc::new(initial_entries),
                    retired_hashes,
                    disabled_by_hash,
                    generation: 0,
                }),
                selection: Mutex::new(SelectionBag::default()),
                state_path,
                state_persistence: Mutex::new(()),
                max_retries,
                runtime_failure_threshold: runtime_failure_threshold.max(1),
                runtime_disable_after_cooldowns: runtime_disable_after_cooldowns.max(1),
                cooldown,
                failures: (0..FAILURE_SHARDS)
                    .map(|_| Mutex::new(HashMap::new()))
                    .collect(),
            }),
        };
        pool.restore_persisted_failure_records();
        if persisted_proxy_count > 0 {
            info!(
                restored_nodes = persisted_proxy_count,
                active_nodes = pool.len(),
                "已从代理池状态文件恢复可用代理"
            );
        }
        pool.persist_state();
        pool
    }

    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshot().is_empty()
    }

    pub fn replace(&self, proxies: Vec<ProxyNode>) {
        let entries = entries_from_nodes(proxies);
        let new_len = entries.len();
        let generation = {
            let mut guard = self.inner.state.write().expect("proxy pool lock poisoned");
            guard.proxies = Arc::new(entries);
            guard.retired_hashes.clear();
            guard.disabled_by_hash.clear();
            guard.generation = guard.generation.wrapping_add(1);
            guard.generation
        };
        {
            let mut selection = self
                .inner
                .selection
                .lock()
                .expect("proxy selection lock poisoned");
            selection.reset(generation);
        }
        self.clear_failure_records();
        self.persist_state();
        info!("活动代理池已切换，active_nodes={new_len}");
    }

    pub fn merge(&self, proxies: Vec<ProxyNode>) -> PoolMergeSummary {
        let mut entries = entries_from_nodes(proxies);
        let mut generation_to_reset = None;
        let summary = {
            let mut guard = self.inner.state.write().expect("proxy pool lock poisoned");
            let previous = guard.proxies.len();
            let mut known = guard
                .proxies
                .iter()
                .map(|entry| entry.key.clone())
                .collect::<HashSet<_>>();
            let mut skipped_existing = 0;
            let mut skipped_retired = 0;
            let mut merged = Vec::with_capacity(previous + entries.len());
            merged.extend(guard.proxies.iter().cloned());

            for entry in entries.drain(..) {
                let key_hash = proxy_key_hash(&entry.key);
                if guard.retired_hashes.contains(&key_hash) {
                    skipped_retired += 1;
                    continue;
                }
                if !known.insert(entry.key.clone()) {
                    skipped_existing += 1;
                    continue;
                }
                if let Some(disabled) = guard.disabled_by_hash.get(&key_hash) {
                    let mut failures = self.failure_shard(&entry.key);
                    failures.insert(
                        entry.key.clone(),
                        FailureRecord {
                            failures: 0,
                            cooldowns: self.inner.runtime_disable_after_cooldowns,
                            cooldown_until: None,
                            disabled: true,
                            disabled_recheck_failures: disabled.disabled_recheck_failures,
                        },
                    );
                }
                merged.push(entry);
            }

            let added = merged.len().saturating_sub(previous);
            if added > 0 {
                guard.proxies = Arc::new(merged);
                guard.generation = guard.generation.wrapping_add(1);
                generation_to_reset = Some(guard.generation);
            }

            PoolMergeSummary {
                previous,
                added,
                skipped_existing,
                skipped_retired,
                active: guard.proxies.len(),
            }
        };

        if let Some(generation) = generation_to_reset {
            self.reset_selection(generation);
        }
        self.persist_state();
        info!(
            previous_nodes = summary.previous,
            added_nodes = summary.added,
            active_nodes = summary.active,
            skipped_existing = summary.skipped_existing,
            skipped_retired = summary.skipped_retired,
            "活动代理池已增量更新"
        );
        summary
    }

    pub fn attempts(&self) -> ProxyAttempts {
        let len = self.len();
        if len == 0 {
            debug!("活动代理池为空，本次请求将使用直连");
            return ProxyAttempts {
                pool: self.clone(),
                tried: HashSet::new(),
                remaining: 1,
                direct_pending: true,
            };
        }

        let remaining = if self.inner.max_retries == 0 {
            len
        } else {
            self.inner.max_retries.min(len)
        };
        debug!(
            active_nodes = len,
            attempt_limit = remaining,
            max_retries = self.inner.max_retries,
            "已创建本次出站候选迭代器"
        );
        ProxyAttempts {
            pool: self.clone(),
            tried: HashSet::with_capacity(remaining),
            remaining,
            direct_pending: false,
        }
    }

    pub fn candidates(&self) -> Vec<ProxyChoice> {
        self.attempts().collect()
    }

    pub fn disabled_proxies(&self) -> Vec<DisabledProxy> {
        let snapshot = self.snapshot();
        snapshot
            .iter()
            .filter_map(|entry| {
                let mut failures = self.failure_shard(&entry.key);
                let record = failures.get_mut(&entry.key)?;
                record.disabled.then(|| DisabledProxy {
                    key: entry.key.clone(),
                    label: entry.label.clone(),
                    node: (*entry.node).clone(),
                })
            })
            .collect()
    }

    pub fn report_success(&self, choice: &ProxyChoice) {
        let ProxyChoice::Proxy(entry) = choice else {
            return;
        };
        let mut failures = self.failure_shard(&entry.key);
        let Some(record) = failures.get_mut(&entry.key) else {
            return;
        };
        let was_disabled = record.disabled || record.disabled_recheck_failures > 0;
        let had_pending_state = record.failures > 0
            || record.cooldown_until.is_some()
            || record.disabled
            || record.disabled_recheck_failures > 0;
        record.failures = 0;
        record.cooldowns = 0;
        record.cooldown_until = None;
        record.disabled = false;
        record.disabled_recheck_failures = 0;
        failures.remove(&entry.key);
        drop(failures);
        if was_disabled {
            self.remove_persisted_disabled(&entry.key);
        }
        if had_pending_state {
            debug!(
                node = %entry.label,
                kind = entry.node.kind(),
                upstream = %entry.node.upstream_addr(),
                "代理运行时失败计数已在成功后重置"
            );
        }
    }

    pub fn report_failure(&self, choice: &ProxyChoice) {
        let ProxyChoice::Proxy(entry) = choice else {
            return;
        };
        let now = Instant::now();
        let mut failures = self.failure_shard(&entry.key);
        let record = failures.entry(entry.key.clone()).or_insert(FailureRecord {
            failures: 0,
            cooldowns: 0,
            cooldown_until: None,
            disabled: false,
            disabled_recheck_failures: 0,
        });
        if record.disabled {
            return;
        }
        if record.cooldown_until.is_some_and(|until| until <= now) {
            record.failures = 0;
            record.cooldown_until = None;
        }

        record.failures += 1;
        if record.failures >= self.inner.runtime_failure_threshold {
            record.failures = 0;
            record.cooldowns += 1;
            if record.cooldowns >= self.inner.runtime_disable_after_cooldowns {
                record.cooldown_until = None;
                record.disabled = true;
                record.disabled_recheck_failures = 0;
                let cooldowns = record.cooldowns;
                drop(failures);
                self.persist_disabled_entry(&entry.key, 0);
                warn!(
                    node = %entry.label,
                    kind = entry.node.kind(),
                    upstream = %entry.node.upstream_addr(),
                    cooldowns,
                    threshold = self.inner.runtime_disable_after_cooldowns,
                    "代理在当前运行周期内多次失败，已加入失效名单"
                );
            } else {
                record.cooldown_until = Some(now + self.inner.cooldown);
                warn!(
                    node = %entry.label,
                    kind = entry.node.kind(),
                    upstream = %entry.node.upstream_addr(),
                    cooldown_seconds = self.inner.cooldown.as_secs(),
                    cooldowns = record.cooldowns,
                    disable_threshold = self.inner.runtime_disable_after_cooldowns,
                    "代理连续运行失败，已进入冷却期"
                );
            }
        } else {
            warn!(
                node = %entry.label,
                kind = entry.node.kind(),
                upstream = %entry.node.upstream_addr(),
                failures = record.failures,
                threshold = self.inner.runtime_failure_threshold,
                "已记录代理运行时失败"
            );
        }
    }

    pub fn report_disabled_recheck_success(&self, key: &str) -> bool {
        self.report_disabled_recheck_success_inner(key, true)
    }

    pub(crate) fn report_disabled_recheck_success_deferred(&self, key: &str) -> bool {
        self.report_disabled_recheck_success_inner(key, false)
    }

    fn report_disabled_recheck_success_inner(&self, key: &str, persist: bool) -> bool {
        {
            let mut failures = self.failure_shard(key);
            let Some(record) = failures.get_mut(key) else {
                return false;
            };
            if !record.disabled {
                return false;
            }
            record.failures = 0;
            record.cooldowns = 0;
            record.cooldown_until = None;
            record.disabled = false;
            record.disabled_recheck_failures = 0;
            failures.remove(key);
        }
        self.remove_persisted_disabled_inner(key, persist);
        self.reset_selection_to_current_generation();
        true
    }

    pub fn report_disabled_recheck_failure(&self, key: &str) -> DisabledRecheckFailure {
        self.report_disabled_recheck_failure_inner(key, true)
    }

    pub(crate) fn report_disabled_recheck_failure_deferred(
        &self,
        key: &str,
    ) -> DisabledRecheckFailure {
        self.report_disabled_recheck_failure_inner(key, false)
    }

    fn report_disabled_recheck_failure_inner(
        &self,
        key: &str,
        persist: bool,
    ) -> DisabledRecheckFailure {
        let threshold = DEFAULT_DISABLED_RECHECK_DELETE_AFTER_FAILURES;
        let failures_count = {
            let mut failures = self.failure_shard(key);
            let Some(record) = failures.get_mut(key) else {
                return DisabledRecheckFailure::NotDisabled;
            };
            if !record.disabled {
                return DisabledRecheckFailure::NotDisabled;
            }
            record.disabled_recheck_failures += 1;
            record.disabled_recheck_failures
        };

        if failures_count >= threshold {
            let mut failures = self.failure_shard(key);
            failures.remove(key);
            drop(failures);
            self.remove_and_retire(key, persist);
            DisabledRecheckFailure::Removed {
                failures: failures_count,
                threshold,
            }
        } else {
            self.persist_disabled_entry_inner(key, failures_count, persist);
            DisabledRecheckFailure::StillDisabled {
                failures: failures_count,
                threshold,
            }
        }
    }

    fn snapshot(&self) -> Arc<Vec<Arc<ProxyEntry>>> {
        self.inner
            .state
            .read()
            .expect("proxy pool lock poisoned")
            .proxies
            .clone()
    }

    fn next_random_available(&self, tried: &HashSet<String>) -> Option<Arc<ProxyEntry>> {
        let now = Instant::now();
        let state = self.inner.state.read().expect("proxy pool lock poisoned");
        let len = state.proxies.len();
        if len == 0 {
            return None;
        }

        let mut selection = self
            .inner
            .selection
            .lock()
            .expect("proxy selection lock poisoned");
        let mut scanned_in_round = 0;
        loop {
            let (index, refilled) = selection.next_index(state.generation, len)?;
            if refilled {
                scanned_in_round = 0;
                debug!(
                    generation = state.generation,
                    candidates = len,
                    "代理随机轮换袋已重新洗牌"
                );
            }
            scanned_in_round += 1;
            let entry = Arc::clone(&state.proxies[index]);
            if tried.contains(&entry.key) || self.is_unavailable(&entry, now) {
                if scanned_in_round >= len {
                    return None;
                }
                continue;
            }
            return Some(entry);
        }
    }

    fn failure_shard(
        &self,
        key: &str,
    ) -> std::sync::MutexGuard<'_, HashMap<String, FailureRecord>> {
        self.inner.failures[failure_shard_index(key)]
            .lock()
            .expect("proxy failure lock poisoned")
    }

    fn is_unavailable(&self, entry: &ProxyEntry, now: Instant) -> bool {
        let mut failures = self.failure_shard(&entry.key);
        let Some(record) = failures.get_mut(&entry.key) else {
            return false;
        };
        if record.disabled {
            debug!(
                node = %entry.label,
                kind = entry.node.kind(),
                upstream = %entry.node.upstream_addr(),
                "代理已加入失效名单，已跳过"
            );
            return true;
        }
        let Some(until) = record.cooldown_until else {
            return false;
        };
        if until > now {
            debug!(
                node = %entry.label,
                kind = entry.node.kind(),
                upstream = %entry.node.upstream_addr(),
                "代理仍在冷却期，已跳过"
            );
            return true;
        }
        record.failures = 0;
        record.cooldown_until = None;
        debug!(
            node = %entry.label,
            kind = entry.node.kind(),
            upstream = %entry.node.upstream_addr(),
            "代理冷却期已结束"
        );
        false
    }

    fn clear_failure_records(&self) {
        for shard in &self.inner.failures {
            let mut failures = shard.lock().expect("proxy failure lock poisoned");
            failures.clear();
        }
    }

    fn restore_persisted_failure_records(&self) {
        let disabled_by_hash = {
            let guard = self.inner.state.read().expect("proxy pool lock poisoned");
            guard.disabled_by_hash.clone()
        };
        if disabled_by_hash.is_empty() {
            return;
        }
        for entry in self.snapshot().iter() {
            let key_hash = proxy_key_hash(&entry.key);
            let Some(disabled) = disabled_by_hash.get(&key_hash) else {
                continue;
            };
            let mut failures = self.failure_shard(&entry.key);
            failures.insert(
                entry.key.clone(),
                FailureRecord {
                    failures: 0,
                    cooldowns: self.inner.runtime_disable_after_cooldowns,
                    cooldown_until: None,
                    disabled: true,
                    disabled_recheck_failures: disabled.disabled_recheck_failures,
                },
            );
        }
    }

    fn persist_disabled_entry(&self, key: &str, disabled_recheck_failures: usize) {
        self.persist_disabled_entry_inner(key, disabled_recheck_failures, true);
    }

    fn persist_disabled_entry_inner(
        &self,
        key: &str,
        disabled_recheck_failures: usize,
        persist: bool,
    ) {
        {
            let mut guard = self.inner.state.write().expect("proxy pool lock poisoned");
            let key_hash = proxy_key_hash(key);
            guard.disabled_by_hash.insert(
                key_hash.clone(),
                PersistedDisabledProxy {
                    key_hash,
                    disabled_recheck_failures,
                },
            );
        }
        if persist {
            self.persist_state();
        }
    }

    fn remove_persisted_disabled(&self, key: &str) {
        self.remove_persisted_disabled_inner(key, true);
    }

    fn remove_persisted_disabled_inner(&self, key: &str, persist: bool) {
        {
            let mut guard = self.inner.state.write().expect("proxy pool lock poisoned");
            guard.disabled_by_hash.remove(&proxy_key_hash(key));
        }
        if persist {
            self.persist_state();
        }
    }

    pub(crate) fn persist_state(&self) {
        let Some(path) = &self.inner.state_path else {
            return;
        };
        let _persistence = self
            .inner
            .state_persistence
            .lock()
            .expect("proxy pool state persistence lock poisoned");
        let state = {
            let guard = self.inner.state.read().expect("proxy pool lock poisoned");
            PersistedPoolState {
                version: 2,
                available: guard
                    .proxies
                    .iter()
                    .filter_map(|entry| persisted_proxy_node_from_entry(entry))
                    .collect(),
                disabled: guard.disabled_by_hash.values().cloned().collect(),
                retired: guard.retired_hashes.iter().cloned().collect(),
            }
        };
        if let Err(err) = save_persisted_pool_state(path, &state) {
            warn!(
                path = %path.display(),
                "代理池状态文件保存失败：{err:#}"
            );
        }
    }

    fn reset_selection(&self, generation: u64) {
        let mut selection = self
            .inner
            .selection
            .lock()
            .expect("proxy selection lock poisoned");
        selection.reset(generation);
    }

    fn reset_selection_to_current_generation(&self) {
        let generation = self
            .inner
            .state
            .read()
            .expect("proxy pool lock poisoned")
            .generation;
        self.reset_selection(generation);
    }

    fn remove_and_retire(&self, key: &str, persist: bool) {
        let generation = {
            let mut guard = self.inner.state.write().expect("proxy pool lock poisoned");
            let key_hash = proxy_key_hash(key);
            guard.disabled_by_hash.remove(&key_hash);
            guard.retired_hashes.insert(key_hash);
            let retained = guard
                .proxies
                .iter()
                .filter(|entry| entry.key != key)
                .cloned()
                .collect::<Vec<_>>();
            if retained.len() == guard.proxies.len() {
                return;
            }
            guard.proxies = Arc::new(retained);
            guard.generation = guard.generation.wrapping_add(1);
            guard.generation
        };
        self.reset_selection(generation);
        if persist {
            self.persist_state();
        }
    }
}

#[derive(Debug)]
pub struct ProxyAttempts {
    pool: ProxyPool,
    tried: HashSet<String>,
    remaining: usize,
    direct_pending: bool,
}

impl Iterator for ProxyAttempts {
    type Item = ProxyChoice;

    fn next(&mut self) -> Option<Self::Item> {
        if self.direct_pending {
            self.direct_pending = false;
            self.remaining = 0;
            return Some(ProxyChoice::Direct);
        }

        if self.remaining == 0 {
            return None;
        }
        let entry = self.pool.next_random_available(&self.tried)?;
        self.tried.insert(entry.key.clone());
        self.remaining -= 1;
        Some(ProxyChoice::Proxy(entry))
    }
}

impl Clone for ProxyPool {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

fn entries_from_nodes(proxies: Vec<ProxyNode>) -> Vec<Arc<ProxyEntry>> {
    proxies
        .into_iter()
        .map(|node| Arc::new(ProxyEntry::from_node(node)))
        .collect()
}

fn restore_persisted_proxy_nodes(nodes: &[PersistedProxyNode]) -> Vec<ProxyNode> {
    let mut restored = Vec::new();
    for node in nodes {
        match proxy_node_from_persisted(node) {
            Ok(Some(node)) => restored.push(node),
            Ok(None) => {}
            Err(err) => warn!("代理池缓存节点恢复失败，已跳过：{err:#}"),
        }
    }
    restored
}

fn proxy_node_from_persisted(node: &PersistedProxyNode) -> Result<Option<ProxyNode>> {
    match node {
        PersistedProxyNode::Http { addr, auth } => Ok(Some(ProxyNode::Http {
            addr: addr.clone(),
            auth: auth.clone(),
        })),
        PersistedProxyNode::Https {
            addr,
            auth,
            sni,
            skip_cert_verify,
        } => Ok(Some(ProxyNode::Https {
            addr: addr.clone(),
            auth: auth.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
        })),
        PersistedProxyNode::Socks5 {
            addr,
            auth,
            remote_dns,
        } => Ok(Some(ProxyNode::Socks5 {
            addr: addr.clone(),
            auth: auth.clone(),
            remote_dns: *remote_dns,
        })),
        PersistedProxyNode::Socks4 {
            addr,
            auth,
            remote_dns,
        } => Ok(Some(ProxyNode::Socks4 {
            addr: addr.clone(),
            auth: auth.clone(),
            remote_dns: *remote_dns,
        })),
        PersistedProxyNode::Shadowsocks {
            host,
            port,
            method,
            password,
            label,
        } => {
            let method = CipherKind::from_str(method)
                .map_err(|err| anyhow!("无效的 Shadowsocks cipher {method}：{err:?}"))?;
            let server = ServerConfig::new(
                ServerAddr::DomainName(host.clone(), *port),
                password.clone(),
                method,
            )?;
            Ok(Some(ProxyNode::Shadowsocks {
                server: Arc::new(server),
                label: label.clone(),
            }))
        }
        PersistedProxyNode::Meow { source } => {
            let mut result = build_meow_nodes(vec![source.clone()]);
            Ok(result.nodes.pop())
        }
    }
}

fn persisted_proxy_node_from_entry(entry: &ProxyEntry) -> Option<PersistedProxyNode> {
    match entry.node.as_ref() {
        ProxyNode::Http { addr, auth } => Some(PersistedProxyNode::Http {
            addr: addr.clone(),
            auth: auth.clone(),
        }),
        ProxyNode::Https {
            addr,
            auth,
            sni,
            skip_cert_verify,
        } => Some(PersistedProxyNode::Https {
            addr: addr.clone(),
            auth: auth.clone(),
            sni: sni.clone(),
            skip_cert_verify: *skip_cert_verify,
        }),
        ProxyNode::Socks5 {
            addr,
            auth,
            remote_dns,
        } => Some(PersistedProxyNode::Socks5 {
            addr: addr.clone(),
            auth: auth.clone(),
            remote_dns: *remote_dns,
        }),
        ProxyNode::Socks4 {
            addr,
            auth,
            remote_dns,
        } => Some(PersistedProxyNode::Socks4 {
            addr: addr.clone(),
            auth: auth.clone(),
            remote_dns: *remote_dns,
        }),
        ProxyNode::Shadowsocks { server, label } => Some(PersistedProxyNode::Shadowsocks {
            host: server.addr().host(),
            port: server.addr().port(),
            method: server.method().to_string(),
            password: server.password().to_owned(),
            label: label.clone(),
        }),
        ProxyNode::Meow(node) => Some(PersistedProxyNode::Meow {
            source: node.source.clone(),
        }),
        ProxyNode::LocalMihomo { .. } => None,
    }
}

fn failure_shard_index(key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % FAILURE_SHARDS
}

fn proxy_key_hash(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_persisted_pool_state(path: &Path) -> Result<PersistedPoolState> {
    if !path.exists() {
        return Ok(PersistedPoolState {
            version: 2,
            available: Vec::new(),
            disabled: Vec::new(),
            retired: Vec::new(),
        });
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("读取代理池状态文件失败：{}", path.display()))?;
    let state: PersistedPoolState = serde_json::from_str(&raw)
        .with_context(|| format!("解析代理池状态文件失败：{}", path.display()))?;
    if !matches!(state.version, 1 | 2) {
        bail!("代理池状态文件版本不支持：{}", state.version);
    }
    Ok(state)
}

fn save_persisted_pool_state(path: &Path, state: &PersistedPoolState) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建代理池状态目录失败：{}", parent.display()))?;
    }
    let tmp_path = path.with_extension("tmp");
    let raw = serde_json::to_vec_pretty(state).context("序列化代理池状态失败")?;
    std::fs::write(&tmp_path, raw)
        .with_context(|| format!("写入代理池状态临时文件失败：{}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "替换代理池状态文件失败：{} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_proxy(port: u16) -> ProxyNode {
        ProxyNode::Http {
            addr: HostPort::new("127.0.0.1", port).unwrap(),
            auth: None,
        }
    }

    #[test]
    fn proxy_node_reports_safe_upstream_and_kind() {
        let node = ProxyNode::Http {
            addr: HostPort::new("127.0.0.1", 8080).unwrap(),
            auth: Some(Credentials {
                username: "user".to_owned(),
                password: Some("secret".to_owned()),
            }),
        };

        assert_eq!(node.kind(), "http");
        assert_eq!(node.upstream_addr(), "127.0.0.1:8080");
        assert_eq!(node.label(), "http://127.0.0.1:8080");
        assert!(!node.label().contains("secret"));

        let target = TargetAddr::new("example.com", 443).unwrap();
        let direct = ProxyChoice::Direct;
        assert_eq!(direct.kind(), "direct");
        assert_eq!(direct.upstream_addr(&target), "example.com:443");
    }

    #[test]
    fn parses_ipv4_target() {
        let target = TargetAddr::parse("example.com:443", None).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_ipv6_target() {
        let target = TargetAddr::parse("[::1]:443", None).unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn candidates_use_random_bag_without_replacement() {
        let pool = ProxyPool::new(vec![http_proxy(1), http_proxy(2), http_proxy(3)], 1);
        let labels: HashSet<String> = (0..3)
            .map(|_| {
                pool.candidates()
                    .into_iter()
                    .next()
                    .expect("one candidate should be available")
                    .label()
            })
            .collect();
        assert_eq!(labels.len(), 3);
        assert!(labels.contains("http://127.0.0.1:1"));
        assert!(labels.contains("http://127.0.0.1:2"));
        assert!(labels.contains("http://127.0.0.1:3"));

        let label = pool
            .candidates()
            .into_iter()
            .next()
            .expect("next random bag should start after exhaustion")
            .label();
        assert!(labels.contains(&label));
    }

    #[test]
    fn zero_retries_allows_full_pool_attempts() {
        let pool = ProxyPool::new(vec![http_proxy(1), http_proxy(2), http_proxy(3)], 0);
        let labels: HashSet<String> = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect();
        assert_eq!(labels.len(), 3);
        assert!(labels.contains("http://127.0.0.1:1"));
        assert!(labels.contains("http://127.0.0.1:2"));
        assert!(labels.contains("http://127.0.0.1:3"));
    }

    #[test]
    fn positive_retries_limits_attempts() {
        let pool = ProxyPool::new(vec![http_proxy(1), http_proxy(2), http_proxy(3)], 2);
        let labels: Vec<String> = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect();
        assert_eq!(labels.len(), 2);
        assert_ne!(labels[0], labels[1]);
    }

    #[test]
    fn empty_pool_uses_direct() {
        let pool = ProxyPool::new(Vec::new(), 10);
        assert!(matches!(pool.candidates()[0], ProxyChoice::Direct));
    }

    #[test]
    fn proxy_enters_and_leaves_cooldown() {
        let pool =
            ProxyPool::with_runtime_options(vec![http_proxy(1)], 1, 3, Duration::from_millis(30));
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);
        assert_eq!(pool.candidates().len(), 1);
        pool.report_failure(&choice);
        assert_eq!(pool.candidates().len(), 1);
        pool.report_failure(&choice);
        assert!(pool.candidates().is_empty());

        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(pool.candidates().len(), 1);
    }

    #[test]
    fn proxy_disables_after_repeated_cooldowns_until_recheck_success() {
        let pool = ProxyPool::with_runtime_failure_policy(
            vec![http_proxy(1)],
            1,
            1,
            Duration::from_millis(30),
            2,
        );

        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);
        assert!(pool.candidates().is_empty());

        std::thread::sleep(Duration::from_millis(40));
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);
        assert!(pool.candidates().is_empty());

        std::thread::sleep(Duration::from_millis(40));
        assert!(pool.candidates().is_empty());
        assert_eq!(pool.disabled_proxies().len(), 1);

        assert!(pool.report_disabled_recheck_success("http://127.0.0.1:1"));
        assert_eq!(pool.candidates().len(), 1);
    }

    #[test]
    fn merge_appends_new_nodes_and_skips_duplicates() {
        let pool = ProxyPool::new(vec![http_proxy(1)], 0);

        let summary = pool.merge(vec![http_proxy(1), http_proxy(2), http_proxy(3)]);

        assert_eq!(
            summary,
            PoolMergeSummary {
                previous: 1,
                added: 2,
                skipped_existing: 1,
                skipped_retired: 0,
                active: 3,
            }
        );
        let labels = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect::<HashSet<_>>();
        assert_eq!(labels.len(), 3);
        assert!(labels.contains("http://127.0.0.1:1"));
        assert!(labels.contains("http://127.0.0.1:2"));
        assert!(labels.contains("http://127.0.0.1:3"));
    }

    #[test]
    fn disabled_proxy_is_not_restored_by_merge() {
        let pool = ProxyPool::with_runtime_failure_policy(
            vec![http_proxy(1)],
            0,
            1,
            Duration::from_millis(30),
            1,
        );
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);
        assert!(pool.candidates().is_empty());

        let summary = pool.merge(vec![http_proxy(1), http_proxy(2)]);

        assert_eq!(summary.added, 1);
        let labels = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect::<HashSet<_>>();
        assert_eq!(labels, HashSet::from(["http://127.0.0.1:2".to_owned()]));
        assert_eq!(pool.disabled_proxies().len(), 1);
    }

    #[test]
    fn disabled_proxy_is_removed_after_three_recheck_failures_and_retired() {
        let pool = ProxyPool::with_runtime_failure_policy(
            vec![http_proxy(1), http_proxy(2)],
            0,
            1,
            Duration::from_millis(30),
            1,
        );
        let choice = pool
            .candidates()
            .into_iter()
            .find(|choice| choice.label() == "http://127.0.0.1:1")
            .unwrap();
        pool.report_failure(&choice);

        assert!(matches!(
            pool.report_disabled_recheck_failure("http://127.0.0.1:1"),
            DisabledRecheckFailure::StillDisabled { failures: 1, .. }
        ));
        assert!(matches!(
            pool.report_disabled_recheck_failure("http://127.0.0.1:1"),
            DisabledRecheckFailure::StillDisabled { failures: 2, .. }
        ));
        assert!(matches!(
            pool.report_disabled_recheck_failure("http://127.0.0.1:1"),
            DisabledRecheckFailure::Removed { failures: 3, .. }
        ));

        let summary = pool.merge(vec![http_proxy(1), http_proxy(3)]);

        assert_eq!(summary.added, 1);
        assert_eq!(summary.skipped_retired, 1);
        let labels = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect::<HashSet<_>>();
        assert_eq!(labels.len(), 2);
        assert!(labels.contains("http://127.0.0.1:2"));
        assert!(labels.contains("http://127.0.0.1:3"));
    }

    #[test]
    fn persisted_available_proxy_is_restored_with_plaintext_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        let sensitive = ProxyNode::Http {
            addr: HostPort::new("127.0.0.1", 8080).unwrap(),
            auth: Some(Credentials {
                username: "user".to_owned(),
                password: Some("secret".to_owned()),
            }),
        };
        let _pool = ProxyPool::with_runtime_failure_policy_and_state(
            vec![sensitive.clone()],
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path.clone()),
        );

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"version\": 2"));
        assert!(raw.contains("user"));
        assert!(raw.contains("secret"));

        let restored = ProxyPool::with_runtime_failure_policy_and_state(
            Vec::new(),
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path),
        );

        let labels = restored
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect::<HashSet<_>>();
        assert_eq!(labels, HashSet::from(["http://127.0.0.1:8080".to_owned()]));
    }

    #[test]
    fn persisted_available_disabled_proxy_is_restored_as_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        let pool = ProxyPool::with_runtime_failure_policy_and_state(
            vec![http_proxy(1)],
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path.clone()),
        );
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);

        let restored = ProxyPool::with_runtime_failure_policy_and_state(
            Vec::new(),
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path),
        );

        assert!(restored.candidates().is_empty());
        assert_eq!(restored.disabled_proxies().len(), 1);
    }

    #[test]
    fn persisted_disabled_success_clears_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        let pool = ProxyPool::with_runtime_failure_policy_and_state(
            vec![http_proxy(1)],
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path.clone()),
        );
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);

        assert!(pool.report_disabled_recheck_success("http://127.0.0.1:1"));

        let raw = std::fs::read_to_string(&path).unwrap();
        let state: PersistedPoolState = serde_json::from_str(&raw).unwrap();
        assert!(state.disabled.is_empty());
        assert!(state.retired.is_empty());
        assert_eq!(state.available.len(), 1);
    }

    #[test]
    fn concurrent_state_updates_are_atomically_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        let node_count = 16_u16;
        let pool = ProxyPool::with_runtime_failure_policy_and_state(
            (1..=node_count).map(http_proxy).collect(),
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path.clone()),
        );
        for choice in pool.candidates() {
            pool.report_failure(&choice);
        }

        let barrier = Arc::new(std::sync::Barrier::new(usize::from(node_count)));
        let handles = (1..=node_count)
            .map(|port| {
                let barrier = Arc::clone(&barrier);
                let pool = pool.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    assert!(matches!(
                        pool.report_disabled_recheck_failure(&format!("http://127.0.0.1:{port}")),
                        DisabledRecheckFailure::StillDisabled { failures: 1, .. }
                    ));
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let raw = std::fs::read_to_string(&path).unwrap();
        let state: PersistedPoolState = serde_json::from_str(&raw).unwrap();
        let disabled = state
            .disabled
            .into_iter()
            .map(|entry| (entry.key_hash, entry.disabled_recheck_failures))
            .collect::<HashMap<_, _>>();
        assert_eq!(disabled.len(), usize::from(node_count));
        for port in 1..=node_count {
            let key_hash = proxy_key_hash(&format!("http://127.0.0.1:{port}"));
            assert_eq!(disabled.get(&key_hash), Some(&1));
        }
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn persisted_retired_proxy_is_skipped_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        let pool = ProxyPool::with_runtime_failure_policy_and_state(
            vec![http_proxy(1)],
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path.clone()),
        );
        let choice = pool.candidates().pop().unwrap();
        pool.report_failure(&choice);
        for _ in 0..3 {
            let _ = pool.report_disabled_recheck_failure("http://127.0.0.1:1");
        }

        let restored = ProxyPool::with_runtime_failure_policy_and_state(
            Vec::new(),
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path),
        );
        let summary = restored.merge(vec![http_proxy(1), http_proxy(2)]);

        assert_eq!(summary.added, 1);
        assert_eq!(summary.skipped_retired, 1);
        let labels = restored
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect::<HashSet<_>>();
        assert_eq!(labels, HashSet::from(["http://127.0.0.1:2".to_owned()]));
    }

    #[test]
    fn persisted_v1_state_is_still_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool-state.json");
        std::fs::write(&path, r#"{"version":1,"disabled":[],"retired":[]}"#).unwrap();

        let pool = ProxyPool::with_runtime_failure_policy_and_state(
            Vec::new(),
            0,
            1,
            Duration::from_millis(30),
            1,
            Some(path),
        );

        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn replace_swaps_proxy_snapshot() {
        let pool = ProxyPool::new(vec![http_proxy(1)], 1);
        pool.replace(vec![http_proxy(2), http_proxy(3)]);
        let labels: Vec<String> = pool
            .candidates()
            .into_iter()
            .map(|choice| choice.label())
            .collect();
        assert_eq!(labels.len(), 1);
        assert_ne!(labels[0], "http://127.0.0.1:1");
    }
}
