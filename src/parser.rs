use std::{
    collections::BTreeMap,
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use shadowsocks::{ServerConfig, config::ServerAddr, crypto::CipherKind};
use tracing::{debug, info, warn};
use url::{Url, form_urlencoded};

use crate::{
    config::{AppConfig, supported_subscription_proxy_scheme},
    proxy::{Credentials, HostPort, ProxyNode},
};

const MAX_SUBSCRIPTION_DEPTH: usize = 4;
const BASE64_MIN_LEN: usize = 8;

const BASE64_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const BASE64_URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, Clone, Default)]
pub struct LoadedProxySet {
    pub native: Vec<ProxyNode>,
    pub mihomo: Vec<MihomoProxyConfig>,
}

impl LoadedProxySet {
    pub fn len(&self) -> usize {
        self.total_len()
    }

    pub fn is_empty(&self) -> bool {
        self.total_len() == 0
    }

    pub fn total_len(&self) -> usize {
        self.native.len() + self.mihomo.len()
    }

    pub fn extend(&mut self, other: Self) {
        self.native.extend(other.native);
        self.mihomo.extend(other.mihomo);
    }
}

#[derive(Debug, Clone)]
pub struct MihomoProxyConfig {
    pub name: String,
    pub kind: String,
    pub value: serde_yaml::Value,
}

#[derive(Debug, Clone)]
pub struct SubscriptionOptions {
    pub timeout: Duration,
    pub user_agent: String,
    pub proxy: Option<String>,
}

impl From<&AppConfig> for SubscriptionOptions {
    fn from(config: &AppConfig) -> Self {
        Self {
            timeout: Duration::from_millis(config.subscription_timeout_ms),
            user_agent: config.subscription_user_agent.clone(),
            proxy: config.subscription_proxy.clone(),
        }
    }
}

pub async fn load_proxies_from_dirs(config: &AppConfig) -> Result<LoadedProxySet> {
    let options = SubscriptionOptions::from(config);
    load_proxies_from_paths(&config.proxy_dirs, &options).await
}

pub async fn load_proxies_from_paths(
    paths: &[PathBuf],
    options: &SubscriptionOptions,
) -> Result<LoadedProxySet> {
    let client = build_subscription_client(options)?;

    let mut proxies = LoadedProxySet::default();
    for path in paths {
        let mut files = collect_source_files(path)?;
        files.sort();
        for file in files {
            let content = fs::read_to_string(&file)
                .with_context(|| format!("failed to read proxy source {}", file.display()))?;
            let source = file.display().to_string();
            proxies.extend(parse_content_queue(&client, content, source).await?);
        }
    }
    Ok(proxies)
}

pub fn build_subscription_client(options: &SubscriptionOptions) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(options.timeout)
        .user_agent(options.user_agent.clone());
    if let Some(proxy) = options.proxy.as_deref().map(str::trim) {
        validate_reqwest_proxy_url(proxy)?;
        info!(
            proxy = %redact_proxy_url(proxy),
            "external fetch proxy enabled"
        );
        builder = builder.proxy(reqwest::Proxy::all(proxy).with_context(|| {
            format!("invalid subscription_proxy URL {}", redact_proxy_url(proxy))
        })?);
    }
    builder
        .build()
        .context("failed to build subscription HTTP client")
}

fn validate_reqwest_proxy_url(proxy: &str) -> Result<()> {
    if proxy.is_empty() {
        return Err(anyhow!("subscription_proxy must not be empty"));
    }
    let url =
        Url::parse(proxy).with_context(|| format!("invalid subscription_proxy URL {proxy}"))?;
    if !supported_subscription_proxy_scheme(url.scheme()) {
        return Err(anyhow!(
            "subscription_proxy scheme {} is not supported",
            url.scheme()
        ));
    }
    if url.host_str().is_none() {
        return Err(anyhow!("subscription_proxy must include a host"));
    }
    Ok(())
}

fn redact_proxy_url(proxy: &str) -> String {
    let Ok(mut url) = Url::parse(proxy) else {
        return "<invalid>".to_owned();
    };
    if !url.username().is_empty() {
        let _ = url.set_username("redacted");
    }
    if url.password().is_some() {
        let _ = url.set_password(Some("redacted"));
    }
    url.to_string()
}

fn collect_source_files(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        warn!("proxy source path does not exist: {}", path.display());
        return Ok(Vec::new());
    }
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        warn!(
            "proxy source path is not a file or directory: {}",
            path.display()
        );
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?
    {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.is_file() {
            files.push(entry_path);
        }
    }
    Ok(files)
}

async fn parse_content_queue(
    client: &reqwest::Client,
    content: String,
    source: String,
) -> Result<LoadedProxySet> {
    let mut queue = VecDeque::from([QueuedContent {
        content,
        source,
        depth: 0,
    }]);
    let mut proxies = LoadedProxySet::default();

    while let Some(item) = queue.pop_front() {
        let parsed = parse_local_content(&item.content, &item.source)?;
        proxies.extend(parsed.proxies);

        for decoded in parsed.decoded_contents {
            queue.push_back(QueuedContent {
                content: decoded,
                source: format!("{} <base64>", item.source),
                depth: item.depth,
            });
        }

        if item.depth >= MAX_SUBSCRIPTION_DEPTH {
            for url in parsed.subscription_urls {
                warn!("subscription depth limit reached, skipping {url}");
            }
            continue;
        }

        for url in parsed.subscription_urls {
            debug!("fetching subscription {url}");
            match fetch_subscription(client, &url).await {
                Ok(body) => queue.push_back(QueuedContent {
                    content: body,
                    source: url,
                    depth: item.depth + 1,
                }),
                Err(err) => warn!("failed to fetch subscription {url}: {err:#}"),
            }
        }
    }

    Ok(proxies)
}

async fn fetch_subscription(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch subscription {url}"))?
        .error_for_status()
        .with_context(|| format!("subscription returned non-success status {url}"))?;
    response
        .text()
        .await
        .with_context(|| format!("failed to read subscription body {url}"))
}

struct QueuedContent {
    content: String,
    source: String,
    depth: usize,
}

#[derive(Default)]
struct LocalParseResult {
    proxies: LoadedProxySet,
    subscription_urls: Vec<String>,
    decoded_contents: Vec<String>,
}

fn parse_local_content(content: &str, source: &str) -> Result<LocalParseResult> {
    if let Some(decoded) = decode_base64_subscription(content) {
        return Ok(LocalParseResult {
            decoded_contents: vec![decoded],
            ..LocalParseResult::default()
        });
    }

    if let Some(proxies) = parse_clash_yaml(content, source)? {
        return Ok(LocalParseResult {
            proxies,
            ..LocalParseResult::default()
        });
    }

    let mut result = LocalParseResult::default();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_proxy_line(line) {
            Ok(Some(ParsedProxyLine::Native(proxy))) => result.proxies.native.push(proxy),
            Ok(Some(ParsedProxyLine::Mihomo(proxy))) => result.proxies.mihomo.push(proxy),
            Ok(None) if is_subscription_url(line) => result.subscription_urls.push(line.to_owned()),
            Ok(None) => warn!(
                "unsupported proxy source line {}:{}: {}",
                source,
                index + 1,
                line
            ),
            Err(err) if is_subscription_url(line) => {
                debug!("treating line as subscription URL after proxy parse miss: {err}");
                result.subscription_urls.push(line.to_owned());
            }
            Err(err) => warn!("invalid proxy source line {}:{}: {err}", source, index + 1),
        }
    }
    Ok(result)
}

enum ParsedProxyLine {
    Native(ProxyNode),
    Mihomo(MihomoProxyConfig),
}

fn parse_proxy_line(line: &str) -> Result<Option<ParsedProxyLine>> {
    if let Some(proxy) = parse_proxy_url(line)? {
        return Ok(Some(ParsedProxyLine::Native(proxy)));
    }
    if let Some(proxy) = parse_mihomo_proxy_url(line)? {
        return Ok(Some(ParsedProxyLine::Mihomo(proxy)));
    }
    Ok(None)
}

pub fn parse_proxy_url(line: &str) -> Result<Option<ProxyNode>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    if line.starts_with("ss://") {
        let server =
            ServerConfig::from_url(line).map_err(|err| anyhow!("invalid ss URL: {err}"))?;
        let label = Url::parse(line)
            .ok()
            .and_then(|url| url.fragment().map(decode_url_component))
            .filter(|fragment| !fragment.is_empty())
            .unwrap_or_else(|| "ss".to_owned());
        return Ok(Some(ProxyNode::Shadowsocks {
            server: Arc::new(server),
            label,
        }));
    }

    let url = match Url::parse(line) {
        Ok(url) => url,
        Err(_) => return Ok(None),
    };

    let scheme = url.scheme().to_ascii_lowercase();
    match scheme.as_str() {
        "http" => {
            if !looks_like_http_proxy_url(&url) {
                return Ok(None);
            }
            let addr = host_port_from_url(&url)?;
            Ok(Some(ProxyNode::Http {
                addr,
                auth: credentials_from_url(&url),
            }))
        }
        "socks5" | "socks5h" => {
            let addr = host_port_from_url(&url)?;
            Ok(Some(ProxyNode::Socks5 {
                addr,
                auth: credentials_from_url(&url),
                remote_dns: scheme == "socks5h",
            }))
        }
        "socks4" | "socks4a" => {
            let addr = host_port_from_url(&url)?;
            Ok(Some(ProxyNode::Socks4 {
                addr,
                auth: credentials_from_url(&url),
                remote_dns: scheme == "socks4a",
            }))
        }
        _ => Ok(None),
    }
}

fn parse_mihomo_proxy_url(line: &str) -> Result<Option<MihomoProxyConfig>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    if let Some(rest) = line.strip_prefix("vmess://") {
        return parse_vmess_url(rest).map(Some);
    }
    if let Some(rest) = line.strip_prefix("ssr://") {
        return parse_ssr_url(rest).map(Some);
    }

    let url = match Url::parse(line) {
        Ok(url) => url,
        Err(_) => return Ok(None),
    };
    match url.scheme().to_ascii_lowercase().as_str() {
        "vless" => parse_vless_url(&url).map(Some),
        "trojan" => parse_trojan_url(&url).map(Some),
        "hysteria2" | "hy2" => parse_hysteria2_url(&url).map(Some),
        "tuic" => parse_tuic_url(&url).map(Some),
        "anytls" => parse_anytls_url(&url).map(Some),
        _ => Ok(None),
    }
}

fn parse_vmess_url(encoded: &str) -> Result<MihomoProxyConfig> {
    let decoded = decode_base64_text(encoded).context("invalid vmess base64 payload")?;
    let link: VmessLink = serde_json::from_str(&decoded).context("invalid vmess JSON payload")?;
    let name = non_empty(link.ps).unwrap_or_else(|| {
        format!(
            "vmess-{}",
            non_empty(link.add.clone()).unwrap_or_else(|| "node".to_owned())
        )
    });
    let server = non_empty(link.add).ok_or_else(|| anyhow!("vmess link missing server"))?;
    let port = parse_u16_string(&link.port, "vmess port")?;
    let uuid = non_empty(link.id).ok_or_else(|| anyhow!("vmess link missing id"))?;
    let alter_id = link
        .aid
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("0")
        .parse::<u16>()
        .context("invalid vmess alterId")?;

    let mut proxy = ClashProxyDocument::new(name, "vmess", server, port);
    proxy.insert_string("uuid", uuid);
    proxy.insert_u16("alterId", alter_id);
    proxy.insert_string(
        "cipher",
        non_empty(link.scy).unwrap_or_else(|| "auto".to_owned()),
    );
    if link.tls.as_deref().is_some_and(|value| value == "tls") {
        proxy.insert_bool("tls", true);
    }
    if let Some(servername) = non_empty(link.sni).or_else(|| non_empty(link.host.clone())) {
        proxy.insert_string("servername", servername);
    }
    if let Some(network) = non_empty(link.net) {
        proxy.insert_string("network", network.clone());
        apply_transport_opts(&mut proxy, &network, link.host, link.path, None)?;
    }
    proxy.into_mihomo("vmess")
}

fn parse_vless_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "vless");
    let server = required_host(url, "vless")?;
    let port = required_port(url, "vless")?;
    let uuid = decode_url_component(url.username());
    if uuid.is_empty() {
        return Err(anyhow!("vless link missing uuid"));
    }

    let mut proxy = ClashProxyDocument::new(name, "vless", server, port);
    proxy.insert_string("uuid", uuid);
    proxy.insert_string(
        "encryption",
        query_param(url, "encryption").unwrap_or_else(|| "none".to_owned()),
    );
    apply_security_query(&mut proxy, url);
    apply_network_query(&mut proxy, url)?;
    proxy.into_mihomo("vless")
}

fn parse_trojan_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "trojan");
    let server = required_host(url, "trojan")?;
    let port = required_port(url, "trojan")?;
    let password = decode_url_component(url.username());
    if password.is_empty() {
        return Err(anyhow!("trojan link missing password"));
    }

    let mut proxy = ClashProxyDocument::new(name, "trojan", server, port);
    proxy.insert_string("password", password);
    apply_security_query(&mut proxy, url);
    apply_network_query(&mut proxy, url)?;
    proxy.into_mihomo("trojan")
}

fn parse_hysteria2_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "hysteria2");
    let server = required_host(url, "hysteria2")?;
    let port = required_port(url, "hysteria2")?;
    let password = decode_url_component(url.username());
    if password.is_empty() {
        return Err(anyhow!("hysteria2 link missing password"));
    }

    let mut proxy = ClashProxyDocument::new(name, "hysteria2", server, port);
    proxy.insert_string("password", password);
    if query_param(url, "insecure").is_some_and(|value| value == "1" || value == "true") {
        proxy.insert_bool("skip-cert-verify", true);
    }
    if let Some(sni) = query_param(url, "sni").or_else(|| query_param(url, "peer")) {
        proxy.insert_string("sni", sni.clone());
        proxy.insert_string("servername", sni);
    }
    proxy.into_mihomo("hysteria2")
}

fn parse_tuic_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "tuic");
    let server = required_host(url, "tuic")?;
    let port = required_port(url, "tuic")?;
    let uuid = url.username();
    let password = url
        .password()
        .ok_or_else(|| anyhow!("tuic link username must be uuid:password"))?;

    let mut proxy = ClashProxyDocument::new(name, "tuic", server, port);
    proxy.insert_string("uuid", decode_url_component(uuid));
    proxy.insert_string("password", decode_url_component(password));
    if let Some(token) = query_param(url, "token") {
        proxy.insert_string("token", token);
    }
    apply_security_query(&mut proxy, url);
    proxy.into_mihomo("tuic")
}

fn parse_anytls_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "anytls");
    let server = required_host(url, "anytls")?;
    let port = url.port().unwrap_or(8443);
    let password = url
        .password()
        .map(decode_url_component)
        .or_else(|| query_param(url, "password"))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("anytls link missing password"))?;

    let mut proxy = ClashProxyDocument::new(name, "anytls", server, port);
    proxy.insert_string("password", password);
    if let Some(sni) = query_param(url, "sni").or_else(|| query_param(url, "servername")) {
        proxy.insert_string("sni", sni.clone());
        proxy.insert_string("servername", sni);
    }
    if query_param(url, "insecure").is_some_and(|value| value == "1" || value == "true") {
        proxy.insert_bool("skip-cert-verify", true);
    }
    proxy.into_mihomo("anytls")
}

fn parse_ssr_url(encoded: &str) -> Result<MihomoProxyConfig> {
    let decoded = decode_base64_text(encoded).context("invalid ssr base64 payload")?;
    let (main, query) = decoded.split_once("/?").unwrap_or((&decoded, ""));
    let mut parts = main.splitn(6, ':');
    let server = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr link missing server"))?
        .to_owned();
    let port = parts
        .next()
        .ok_or_else(|| anyhow!("ssr link missing port"))?
        .parse::<u16>()
        .context("invalid ssr port")?;
    let protocol = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr link missing protocol"))?
        .to_owned();
    let cipher = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr link missing cipher"))?
        .to_owned();
    let obfs = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr link missing obfs"))?
        .to_owned();
    let password = parts
        .next()
        .and_then(decode_base64_text)
        .ok_or_else(|| anyhow!("ssr link missing password"))?;

    let params = form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    let name = params
        .iter()
        .find(|(key, _)| key == "remarks")
        .and_then(|(_, value)| decode_base64_text(value).or_else(|| Some(value.to_string())))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("ssr-{server}"));

    let mut proxy = ClashProxyDocument::new(name, "ssr", server, port);
    proxy.insert_string("cipher", cipher);
    proxy.insert_string("password", password);
    proxy.insert_string("protocol", protocol);
    proxy.insert_string("obfs", obfs);
    for (query_key, clash_key) in [
        ("protoparam", "protocol-param"),
        ("obfsparam", "obfs-param"),
    ] {
        if let Some(value) = params
            .iter()
            .find(|(key, _)| key == query_key)
            .map(|(_, value)| value.as_ref())
            .and_then(decode_base64_text)
            .filter(|value| !value.is_empty())
        {
            proxy.insert_string(clash_key, value);
        }
    }
    proxy.into_mihomo("ssr")
}

fn looks_like_http_proxy_url(url: &Url) -> bool {
    url.port().is_some()
        && (url.path().is_empty() || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none()
}

fn host_port_from_url(url: &Url) -> Result<HostPort> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing host in proxy URL"))?;
    let port = url
        .port()
        .ok_or_else(|| anyhow!("missing port in proxy URL {url}"))?;
    HostPort::new(host, port)
}

fn credentials_from_url(url: &Url) -> Option<Credentials> {
    let username = url.username();
    if username.is_empty() {
        return None;
    }
    Some(Credentials {
        username: decode_url_component(username),
        password: url.password().map(decode_url_component),
    })
}

fn is_subscription_url(line: &str) -> bool {
    Url::parse(line)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

fn decode_url_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn decode_base64_text(value: &str) -> Option<String> {
    let normalized: String = value.chars().filter(|ch| !ch.is_whitespace()).collect();
    for engine in [&BASE64_STANDARD, &BASE64_URL_SAFE] {
        let Ok(decoded) = engine.decode(normalized.as_bytes()) else {
            continue;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };
        return Some(text);
    }
    None
}

fn decode_base64_subscription(content: &str) -> Option<String> {
    let normalized: String = content.chars().filter(|ch| !ch.is_whitespace()).collect();
    if normalized.len() < BASE64_MIN_LEN || !looks_like_base64(&normalized) {
        return None;
    }

    for engine in [&BASE64_STANDARD, &BASE64_URL_SAFE] {
        let Ok(decoded) = engine.decode(normalized.as_bytes()) else {
            continue;
        };
        let Ok(text) = String::from_utf8(decoded) else {
            continue;
        };
        if text.contains("://") || text.contains("proxies:") {
            return Some(text);
        }
    }
    None
}

fn looks_like_base64(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
    })
}

fn parse_clash_yaml(content: &str, source: &str) -> Result<Option<LoadedProxySet>> {
    let yaml_value = match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let config = match serde_yaml::from_value::<ClashConfig>(yaml_value.clone()) {
        Ok(config) => config,
        Err(_) => return Ok(None),
    };
    let Some(entries) = config.proxies else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(Some(LoadedProxySet::default()));
    }

    let raw_entries = raw_clash_proxy_values(&yaml_value);
    let mut proxies = LoadedProxySet::default();
    for (index, entry) in entries.into_iter().enumerate() {
        match clash_entry_to_proxy(&entry) {
            Ok(ClashProxyDecision::Native(proxy)) => proxies.native.push(proxy),
            Ok(ClashProxyDecision::Mihomo) => {
                let Some(value) = raw_entries.get(index).cloned() else {
                    warn!("missing raw Clash proxy value in {source} at index {index}");
                    continue;
                };
                proxies.mihomo.push(clash_entry_to_mihomo(entry, value));
            }
            Ok(ClashProxyDecision::Skip) => {}
            Err(err) => warn!("invalid Clash proxy in {source}: {err}"),
        }
    }
    Ok(Some(proxies))
}

fn raw_clash_proxy_values(root: &serde_yaml::Value) -> Vec<serde_yaml::Value> {
    root.get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .cloned()
        .unwrap_or_default()
}

enum ClashProxyDecision {
    Native(ProxyNode),
    Mihomo,
    Skip,
}

fn clash_entry_to_proxy(entry: &ClashProxy) -> Result<ClashProxyDecision> {
    let kind = entry.kind.to_ascii_lowercase();
    let name = entry.name.clone().unwrap_or_else(|| kind.clone());
    if is_mihomo_only_clash_type(&kind) {
        return Ok(ClashProxyDecision::Mihomo);
    }

    match kind.as_str() {
        "http" => {
            if entry.tls.unwrap_or(false) {
                return Ok(ClashProxyDecision::Mihomo);
            }
            let (server, port) = clash_server_port(entry, &name)?;
            Ok(ClashProxyDecision::Native(ProxyNode::Http {
                addr: HostPort::new(server, port)?,
                auth: credentials_from_parts(entry.username.clone(), entry.password.clone()),
            }))
        }
        "socks5" | "socks" => {
            let (server, port) = clash_server_port(entry, &name)?;
            Ok(ClashProxyDecision::Native(ProxyNode::Socks5 {
                addr: HostPort::new(server, port)?,
                auth: credentials_from_parts(entry.username.clone(), entry.password.clone()),
                remote_dns: true,
            }))
        }
        "ss" | "shadowsocks" => {
            if entry.plugin.is_some() {
                return Ok(ClashProxyDecision::Mihomo);
            }
            let (server, port) = clash_server_port(entry, &name)?;
            let cipher = entry
                .cipher
                .clone()
                .or(entry.method.clone())
                .ok_or_else(|| anyhow!("Shadowsocks proxy {name} missing cipher"))?;
            let password = entry
                .password
                .clone()
                .ok_or_else(|| anyhow!("Shadowsocks proxy {name} missing password"))?;
            let method = CipherKind::from_str(&cipher)
                .map_err(|err| anyhow!("invalid Shadowsocks cipher {cipher}: {err:?}"))?;
            let server = ServerConfig::new(ServerAddr::DomainName(server, port), password, method)?;
            Ok(ClashProxyDecision::Native(ProxyNode::Shadowsocks {
                server: Arc::new(server),
                label: name,
            }))
        }
        _ => {
            if entry.server.is_some() || !entry.extra.is_empty() {
                Ok(ClashProxyDecision::Mihomo)
            } else {
                warn!("skipping unsupported Clash proxy {name} of type {kind}");
                Ok(ClashProxyDecision::Skip)
            }
        }
    }
}

fn clash_server_port(entry: &ClashProxy, name: &str) -> Result<(String, u16)> {
    let server = entry
        .server
        .clone()
        .ok_or_else(|| anyhow!("proxy {name} missing server"))?;
    let port = entry
        .port
        .ok_or_else(|| anyhow!("proxy {name} missing port"))?;
    Ok((server, port))
}

fn is_mihomo_only_clash_type(kind: &str) -> bool {
    matches!(
        kind,
        "vmess"
            | "vless"
            | "trojan"
            | "ssr"
            | "hysteria"
            | "hysteria2"
            | "hy2"
            | "tuic"
            | "wireguard"
            | "wg"
            | "anytls"
            | "mieru"
            | "snell"
            | "ssh"
    )
}

fn clash_entry_to_mihomo(entry: ClashProxy, value: serde_yaml::Value) -> MihomoProxyConfig {
    let kind = entry.kind.to_ascii_lowercase();
    let name = entry.name.unwrap_or_else(|| format!("{kind}-node"));
    MihomoProxyConfig { name, kind, value }
}

struct ClashProxyDocument {
    name: String,
    value: serde_yaml::Mapping,
}

impl ClashProxyDocument {
    fn new(name: String, kind: impl Into<String>, server: String, port: u16) -> Self {
        let mut document = Self {
            name,
            value: serde_yaml::Mapping::new(),
        };
        document.insert_string("name", document.name.clone());
        document.insert_string("type", kind.into());
        document.insert_string("server", server);
        document.insert_u16("port", port);
        document
    }

    fn insert_string(&mut self, key: &str, value: String) {
        self.insert_value(key, value);
    }

    fn insert_u16(&mut self, key: &str, value: u16) {
        self.insert_value(key, value);
    }

    fn insert_bool(&mut self, key: &str, value: bool) {
        self.insert_value(key, value);
    }

    fn insert_strings(&mut self, key: &str, values: Vec<String>) {
        self.insert_value(key, values);
    }

    fn insert_mapping(&mut self, key: &str, mapping: serde_yaml::Mapping) {
        self.value.insert(
            serde_yaml::Value::String(key.to_owned()),
            serde_yaml::Value::Mapping(mapping),
        );
    }

    fn insert_value(&mut self, key: &str, value: impl Serialize) {
        let value =
            serde_yaml::to_value(value).expect("serializing scalar Clash value cannot fail");
        self.value
            .insert(serde_yaml::Value::String(key.to_owned()), value);
    }

    fn into_mihomo(self, kind: &str) -> Result<MihomoProxyConfig> {
        Ok(MihomoProxyConfig {
            name: self.name,
            kind: kind.to_owned(),
            value: serde_yaml::Value::Mapping(self.value),
        })
    }
}

fn apply_security_query(proxy: &mut ClashProxyDocument, url: &Url) {
    if let Some(security) = query_param(url, "security").or_else(|| query_param(url, "tls")) {
        if matches!(security.as_str(), "tls" | "reality" | "true" | "1") {
            proxy.insert_bool("tls", true);
        }
        if security == "reality" {
            let mut reality = serde_yaml::Mapping::new();
            if let Some(public_key) = query_param(url, "pbk") {
                insert_mapping_string(&mut reality, "public-key", public_key);
            }
            if let Some(short_id) = query_param(url, "sid") {
                insert_mapping_string(&mut reality, "short-id", short_id);
            }
            if !reality.is_empty() {
                proxy.insert_mapping("reality-opts", reality);
            }
        }
    }
    if let Some(servername) = query_param(url, "sni")
        .or_else(|| query_param(url, "servername"))
        .or_else(|| query_param(url, "peer"))
    {
        proxy.insert_string("servername", servername);
    }
    if let Some(alpn) = query_param(url, "alpn") {
        let values = alpn
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if !values.is_empty() {
            proxy.insert_strings("alpn", values);
        }
    }
    if let Some(fingerprint) = query_param(url, "fp")
        .or_else(|| query_param(url, "fingerprint"))
        .or_else(|| query_param(url, "client-fingerprint"))
    {
        proxy.insert_string("client-fingerprint", fingerprint);
    }
    if let Some(flow) = query_param(url, "flow") {
        proxy.insert_string("flow", flow);
    }
    if query_param(url, "allowInsecure")
        .or_else(|| query_param(url, "insecure"))
        .is_some_and(|value| matches!(value.as_str(), "1" | "true"))
    {
        proxy.insert_bool("skip-cert-verify", true);
    }
}

fn apply_network_query(proxy: &mut ClashProxyDocument, url: &Url) -> Result<()> {
    let Some(network) = query_param(url, "type")
        .or_else(|| query_param(url, "network"))
        .filter(|value| !value.is_empty() && value != "tcp")
    else {
        return Ok(());
    };
    proxy.insert_string("network", network.clone());
    let host = query_param(url, "host");
    let path = query_param(url, "path");
    let service_name = query_param(url, "serviceName").or_else(|| query_param(url, "service_name"));
    apply_transport_opts(proxy, &network, host, path, service_name)
}

fn apply_transport_opts(
    proxy: &mut ClashProxyDocument,
    network: &str,
    host: Option<String>,
    path: Option<String>,
    service_name: Option<String>,
) -> Result<()> {
    match network {
        "ws" | "websocket" => {
            let mut opts = serde_yaml::Mapping::new();
            if let Some(path) = path.filter(|value| !value.is_empty()) {
                insert_mapping_string(&mut opts, "path", path);
            }
            if let Some(host) = host.filter(|value| !value.is_empty()) {
                let mut headers = serde_yaml::Mapping::new();
                insert_mapping_string(&mut headers, "Host", host);
                opts.insert(
                    serde_yaml::Value::String("headers".to_owned()),
                    serde_yaml::Value::Mapping(headers),
                );
            }
            if !opts.is_empty() {
                proxy.insert_mapping("ws-opts", opts);
            }
        }
        "grpc" => {
            let service_name = service_name
                .or(path)
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_owned();
            if !service_name.is_empty() {
                let mut opts = serde_yaml::Mapping::new();
                insert_mapping_string(&mut opts, "grpc-service-name", service_name);
                proxy.insert_mapping("grpc-opts", opts);
            }
        }
        "h2" | "http" => {
            let mut opts = serde_yaml::Mapping::new();
            if let Some(host) = host.filter(|value| !value.is_empty()) {
                insert_mapping_value(&mut opts, "host", vec![host]);
            }
            if let Some(path) = path.filter(|value| !value.is_empty()) {
                insert_mapping_value(&mut opts, "path", vec![path]);
            }
            if !opts.is_empty() {
                proxy.insert_mapping("h2-opts", opts);
            }
        }
        _ => {}
    }
    Ok(())
}

fn insert_mapping_string(mapping: &mut serde_yaml::Mapping, key: &str, value: String) {
    insert_mapping_value(mapping, key, value);
}

fn insert_mapping_value(mapping: &mut serde_yaml::Mapping, key: &str, value: impl Serialize) {
    mapping.insert(
        serde_yaml::Value::String(key.to_owned()),
        serde_yaml::to_value(value).expect("serializing Clash mapping value cannot fail"),
    );
}

fn query_param(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

fn required_host(url: &Url, scheme: &str) -> Result<String> {
    url.host_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("{scheme} link missing host"))
}

fn required_port(url: &Url, scheme: &str) -> Result<u16> {
    url.port()
        .ok_or_else(|| anyhow!("{scheme} link missing port"))
}

fn proxy_name_from_url(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(decode_url_component)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn parse_u16_string(value: &Option<String>, label: &str) -> Result<u16> {
    value
        .as_deref()
        .ok_or_else(|| anyhow!("{label} missing"))?
        .parse::<u16>()
        .with_context(|| format!("invalid {label}"))
}

fn credentials_from_parts(
    username: Option<String>,
    password: Option<String>,
) -> Option<Credentials> {
    username
        .filter(|value| !value.is_empty())
        .map(|username| Credentials { username, password })
}

#[derive(Debug, Deserialize)]
struct ClashConfig {
    proxies: Option<Vec<ClashProxy>>,
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    server: Option<String>,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    cipher: Option<String>,
    method: Option<String>,
    tls: Option<bool>,
    plugin: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct VmessLink {
    ps: Option<String>,
    add: Option<String>,
    port: Option<String>,
    id: Option<String>,
    aid: Option<String>,
    net: Option<String>,
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    scy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };

    async fn spawn_subscription_proxy(
        body: &'static str,
    ) -> io::Result<(
        String,
        oneshot::Receiver<String>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(header) = read_test_http_header(&mut stream).await else {
                return;
            };
            let first_line = String::from_utf8_lossy(&header)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            let _ = tx.send(first_line);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        Ok((format!("http://{addr}"), rx, handle))
    }

    async fn read_test_http_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut header = Vec::new();
        let mut byte = [0_u8; 1];
        while header.len() < 16 * 1024 {
            stream.read_exact(&mut byte).await?;
            header.push(byte[0]);
            if header.ends_with(b"\r\n\r\n") {
                return Ok(header);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "test HTTP header exceeded limit",
        ))
    }

    #[test]
    fn parses_http_proxy_url() {
        let proxy = parse_proxy_url("http://user:pass@127.0.0.1:8080")
            .unwrap()
            .unwrap();
        match proxy {
            ProxyNode::Http { addr, auth } => {
                assert_eq!(addr.host, "127.0.0.1");
                assert_eq!(addr.port, 8080);
                assert_eq!(auth.unwrap().username, "user");
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
    }

    #[test]
    fn treats_https_line_as_subscription_url() {
        assert!(
            parse_proxy_url("https://example.com/sub")
                .unwrap()
                .is_none()
        );
        assert!(is_subscription_url("https://example.com/sub"));
    }

    #[test]
    fn parses_socks5h_proxy_url() {
        let proxy = parse_proxy_url("socks5h://127.0.0.1:1080")
            .unwrap()
            .unwrap();
        match proxy {
            ProxyNode::Socks5 {
                addr, remote_dns, ..
            } => {
                assert_eq!(addr.port, 1080);
                assert!(remote_dns);
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
    }

    #[test]
    fn decodes_base64_subscription() {
        let encoded = BASE64_STANDARD.encode("socks5://127.0.0.1:1080\nhttp://127.0.0.1:8080\n");
        let decoded = decode_base64_subscription(&encoded).unwrap();
        assert!(decoded.contains("socks5://127.0.0.1:1080"));
    }

    #[tokio::test]
    async fn fetches_subscription_through_configured_proxy() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let source_path = dir.path().join("sources.txt");
        fs::write(&source_path, "http://subscription.invalid/list\n")?;
        let (proxy_url, first_line_rx, _handle) =
            spawn_subscription_proxy("http://127.0.0.1:8080\n").await?;
        let options = SubscriptionOptions {
            timeout: Duration::from_secs(2),
            user_agent: "RotatorProxyTest/0.1".to_owned(),
            proxy: Some(proxy_url),
        };

        let proxies = load_proxies_from_paths(&[source_path], &options).await?;

        assert_eq!(proxies.native.len(), 1);
        assert_eq!(
            first_line_rx.await.unwrap(),
            "GET http://subscription.invalid/list HTTP/1.1"
        );
        Ok(())
    }

    #[test]
    fn parses_clash_yaml_nodes() {
        let yaml = r#"
proxies:
  - name: http-a
    type: http
    server: 127.0.0.1
    port: 8080
  - name: socks-a
    type: socks5
    server: 127.0.0.1
    port: 1080
"#;
        let proxies = parse_clash_yaml(yaml, "test").unwrap().unwrap();
        assert_eq!(proxies.native.len(), 2);
        assert_eq!(proxies.mihomo.len(), 0);
        assert!(matches!(proxies.native[0], ProxyNode::Http { .. }));
        assert!(matches!(proxies.native[1], ProxyNode::Socks5 { .. }));
    }

    #[test]
    fn sends_complex_clash_nodes_to_complex_queue() {
        let yaml = r#"
proxies:
  - name: vmess-a
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    tls: true
  - name: trojan-a
    type: trojan
    server: example.com
    port: 443
    password: pass
  - name: ss-plugin
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: pass
    plugin: obfs
"#;
        let proxies = parse_clash_yaml(yaml, "test").unwrap().unwrap();
        assert_eq!(proxies.native.len(), 0);
        assert_eq!(proxies.mihomo.len(), 3);
        assert_eq!(proxies.mihomo[0].name, "vmess-a");
        assert_eq!(proxies.mihomo[2].kind, "ss");
    }

    #[test]
    fn parses_vless_link_as_mihomo_node() {
        let parsed = parse_proxy_line(
            "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws#vless-a",
        )
        .unwrap()
        .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "vless-a");
                assert_eq!(proxy.kind, "vless");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("ws-opts"));
                assert!(text.contains("cdn.example.com"));
            }
            ParsedProxyLine::Native(_) => panic!("expected mihomo node"),
        }
    }

    #[test]
    fn parses_anytls_link_as_complex_node() {
        let parsed =
            parse_proxy_line("anytls://user:pass@example.com:8443?sni=tls.example.com#anytls-a")
                .unwrap()
                .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "anytls-a");
                assert_eq!(proxy.kind, "anytls");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("password: pass"));
                assert!(text.contains("sni: tls.example.com"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
        }
    }

    #[test]
    fn parses_local_content_with_decoded_queue_marker() {
        let encoded = BASE64_STANDARD.encode("socks5://127.0.0.1:1080\n");
        let parsed = parse_local_content(&encoded, "test").unwrap();
        assert_eq!(parsed.decoded_contents.len(), 1);
    }
}
