use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use meow_common::ProxyAdapter;
use shadowsocks::{ServerConfig, relay::socks5::Address as ShadowAddress};
use tracing::{debug, info, warn};

const FAILURE_SHARDS: usize = 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

impl HostPort {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            bail!("host must not be empty");
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Credentials {
    pub username: String,
    pub password: Option<String>,
}

#[derive(Clone)]
pub struct MeowProxyNode {
    pub adapter: Arc<dyn ProxyAdapter>,
    pub key: String,
    pub label: String,
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
    pub fn label(&self) -> String {
        match self {
            Self::Http { addr, .. } => format!("http://{addr}"),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetAddr {
    pub host: String,
    pub port: u16,
}

impl TargetAddr {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            bail!("target host must not be empty");
        }
        Ok(Self { host, port })
    }

    pub fn parse(authority: &str, default_port: Option<u16>) -> Result<Self> {
        let authority = authority.trim();
        if authority.is_empty() {
            bail!("empty target authority");
        }

        if let Some(rest) = authority.strip_prefix('[') {
            let end = rest
                .find(']')
                .ok_or_else(|| anyhow!("invalid IPv6 authority {authority}"))?;
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse()?,
                None => default_port.ok_or_else(|| anyhow!("missing port in {authority}"))?,
            };
            return Self::new(host, port);
        }

        if let Some((host, port)) = authority.rsplit_once(':')
            && !host.contains(':')
        {
            return Self::new(host, port.parse()?);
        }

        let port = default_port.ok_or_else(|| anyhow!("missing port in {authority}"))?;
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

#[derive(Debug)]
pub struct ProxyPool {
    inner: Arc<ProxyPoolInner>,
}

#[derive(Debug)]
struct ProxyPoolInner {
    proxies: RwLock<Arc<Vec<Arc<ProxyEntry>>>>,
    next: AtomicUsize,
    max_retries: usize,
    runtime_failure_threshold: usize,
    cooldown: Duration,
    failures: Vec<Mutex<HashMap<String, FailureRecord>>>,
}

#[derive(Debug, Clone)]
struct FailureRecord {
    failures: usize,
    cooldown_until: Option<Instant>,
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
        Self {
            inner: Arc::new(ProxyPoolInner {
                proxies: RwLock::new(Arc::new(entries_from_nodes(proxies))),
                next: AtomicUsize::new(0),
                max_retries: max_retries.max(1),
                runtime_failure_threshold: runtime_failure_threshold.max(1),
                cooldown,
                failures: (0..FAILURE_SHARDS)
                    .map(|_| Mutex::new(HashMap::new()))
                    .collect(),
            }),
        }
    }

    pub fn len(&self) -> usize {
        self.snapshot().len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshot().is_empty()
    }

    pub fn replace(&self, proxies: Vec<ProxyNode>) {
        let entries = entries_from_nodes(proxies);
        let live_keys: HashSet<String> = entries.iter().map(|entry| entry.key.clone()).collect();
        let new_len = entries.len();
        {
            let mut guard = self
                .inner
                .proxies
                .write()
                .expect("proxy pool lock poisoned");
            *guard = Arc::new(entries);
        }
        for shard in &self.inner.failures {
            let mut failures = shard.lock().expect("proxy failure lock poisoned");
            failures.retain(|key, _| live_keys.contains(key));
        }
        info!("active proxy pool swapped, active_nodes={new_len}");
    }

    pub fn candidates(&self) -> Vec<ProxyChoice> {
        let proxies = self.snapshot();
        if proxies.is_empty() {
            return vec![ProxyChoice::Direct];
        }

        let len = proxies.len();
        let start = self.inner.next.fetch_add(1, Ordering::Relaxed) % len;
        let limit = self.inner.max_retries.min(len);
        let now = Instant::now();
        let mut choices = Vec::with_capacity(limit);

        for offset in 0..len {
            if choices.len() == limit {
                break;
            }
            let entry = Arc::clone(&proxies[(start + offset) % len]);
            if self.is_in_cooldown(&entry, now) {
                continue;
            }
            choices.push(ProxyChoice::Proxy(entry));
        }

        choices
    }

    pub fn report_success(&self, choice: &ProxyChoice) {
        let ProxyChoice::Proxy(entry) = choice else {
            return;
        };
        let mut failures = self.failure_shard(&entry.key);
        if failures.remove(&entry.key).is_some() {
            debug!(node = %entry.label, "proxy runtime failure counter reset after success");
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
            cooldown_until: None,
        });
        if record.cooldown_until.is_some_and(|until| until <= now) {
            record.failures = 0;
            record.cooldown_until = None;
        }

        record.failures += 1;
        if record.failures >= self.inner.runtime_failure_threshold {
            record.failures = 0;
            record.cooldown_until = Some(now + self.inner.cooldown);
            warn!(
                node = %entry.label,
                cooldown_seconds = self.inner.cooldown.as_secs(),
                "proxy entered cooldown after repeated runtime failures"
            );
        } else {
            warn!(
                node = %entry.label,
                failures = record.failures,
                threshold = self.inner.runtime_failure_threshold,
                "proxy runtime failure recorded"
            );
        }
    }

    fn snapshot(&self) -> Arc<Vec<Arc<ProxyEntry>>> {
        self.inner
            .proxies
            .read()
            .expect("proxy pool lock poisoned")
            .clone()
    }

    fn failure_shard(
        &self,
        key: &str,
    ) -> std::sync::MutexGuard<'_, HashMap<String, FailureRecord>> {
        self.inner.failures[failure_shard_index(key)]
            .lock()
            .expect("proxy failure lock poisoned")
    }

    fn is_in_cooldown(&self, entry: &ProxyEntry, now: Instant) -> bool {
        let mut failures = self.failure_shard(&entry.key);
        let Some(record) = failures.get(&entry.key) else {
            return false;
        };
        let Some(until) = record.cooldown_until else {
            return false;
        };
        if until > now {
            debug!(node = %entry.label, "skipping proxy in cooldown");
            return true;
        }
        failures.remove(&entry.key);
        debug!(node = %entry.label, "proxy cooldown expired");
        false
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

fn failure_shard_index(key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % FAILURE_SHARDS
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
    fn candidates_are_round_robin() {
        let pool = ProxyPool::new(vec![http_proxy(1), http_proxy(2), http_proxy(3)], 2);
        let labels: Vec<String> = pool
            .candidates()
            .into_iter()
            .map(|choice| match choice {
                ProxyChoice::Direct => "direct".to_owned(),
                ProxyChoice::Proxy(entry) => entry.label.clone(),
            })
            .collect();
        assert_eq!(labels, vec!["http://127.0.0.1:1", "http://127.0.0.1:2"]);

        let labels: Vec<String> = pool
            .candidates()
            .into_iter()
            .map(|choice| match choice {
                ProxyChoice::Direct => "direct".to_owned(),
                ProxyChoice::Proxy(entry) => entry.label.clone(),
            })
            .collect();
        assert_eq!(labels, vec!["http://127.0.0.1:2", "http://127.0.0.1:3"]);
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
