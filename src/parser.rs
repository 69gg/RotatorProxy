use std::{
    collections::BTreeMap,
    collections::VecDeque,
    fs,
    net::IpAddr,
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
use serde::{Deserialize, Deserializer, Serialize};
use shadowsocks::{ServerConfig, config::ServerAddr, crypto::CipherKind};
use tracing::{debug, info, warn};
use url::{Url, form_urlencoded};

use crate::{
    config::{AppConfig, supported_subscription_proxy_scheme},
    proxy::{Credentials, HostPort, ProxyNode},
};

const MAX_SUBSCRIPTION_DEPTH: usize = 4;
const BASE64_MIN_LEN: usize = 8;
const HYSTERIA2_DEFAULT_PORT: u16 = 443;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
                .with_context(|| format!("读取代理来源失败：{}", file.display()))?;
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
            "已启用配置获取代理"
        );
        builder = builder.proxy(reqwest::Proxy::all(proxy).with_context(|| {
            format!("subscription_proxy URL 无效：{}", redact_proxy_url(proxy))
        })?);
    }
    builder.build().context("构建订阅 HTTP 客户端失败")
}

fn validate_reqwest_proxy_url(proxy: &str) -> Result<()> {
    if proxy.is_empty() {
        return Err(anyhow!("subscription_proxy 不能为空"));
    }
    let url = Url::parse(proxy).with_context(|| format!("subscription_proxy URL 无效：{proxy}"))?;
    if !supported_subscription_proxy_scheme(url.scheme()) {
        return Err(anyhow!("subscription_proxy 协议不受支持：{}", url.scheme()));
    }
    if url.host_str().is_none() {
        return Err(anyhow!("subscription_proxy 必须包含 host"));
    }
    Ok(())
}

fn redact_proxy_url(proxy: &str) -> String {
    let Ok(mut url) = Url::parse(proxy) else {
        return "<无效>".to_owned();
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
        warn!("代理来源路径不存在：{}", path.display());
        return Ok(Vec::new());
    }
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        warn!("代理来源路径不是文件或目录：{}", path.display());
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("读取目录失败：{}", path.display()))?
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
        allow_subscriptions: true,
    }]);
    let mut proxies = LoadedProxySet::default();

    while let Some(item) = queue.pop_front() {
        let parsed = parse_local_content(&item.content, &item.source, item.allow_subscriptions)?;
        proxies.extend(parsed.proxies);

        for decoded in parsed.decoded_contents {
            queue.push_back(QueuedContent {
                content: decoded,
                source: format!("{} <base64>", item.source),
                depth: item.depth,
                allow_subscriptions: false,
            });
        }

        if item.depth >= MAX_SUBSCRIPTION_DEPTH {
            for url in parsed.subscription_urls {
                warn!("订阅展开深度已达到上限，跳过 {url}");
            }
            continue;
        }

        for url in parsed.subscription_urls {
            debug!("正在获取订阅 {url}");
            match fetch_subscription(client, &url).await {
                Ok(body) => queue.push_back(QueuedContent {
                    content: body,
                    source: url,
                    depth: item.depth + 1,
                    allow_subscriptions: false,
                }),
                Err(err) => warn!("订阅获取失败 {url}：{err:#}"),
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
        .with_context(|| format!("获取订阅失败：{url}"))?
        .error_for_status()
        .with_context(|| format!("订阅返回非成功状态：{url}"))?;
    response
        .text()
        .await
        .with_context(|| format!("读取订阅响应体失败：{url}"))
}

struct QueuedContent {
    content: String,
    source: String,
    depth: usize,
    allow_subscriptions: bool,
}

#[derive(Default)]
struct LocalParseResult {
    proxies: LoadedProxySet,
    subscription_urls: Vec<String>,
    decoded_contents: Vec<String>,
}

#[derive(Default)]
struct ParseIssueStats {
    invalid_lines: usize,
    unsupported_lines: usize,
}

fn parse_local_content(
    content: &str,
    source: &str,
    allow_subscriptions: bool,
) -> Result<LocalParseResult> {
    if let Some(decoded) = decode_base64_subscription(content) {
        return Ok(LocalParseResult {
            decoded_contents: vec![decoded],
            ..LocalParseResult::default()
        });
    }

    if let Some(parsed) = parse_clash_yaml_document(content, source)? {
        return Ok(LocalParseResult {
            proxies: parsed.proxies,
            subscription_urls: parsed.provider_urls,
            ..LocalParseResult::default()
        });
    }

    let mut result = LocalParseResult::default();
    let mut issues = ParseIssueStats::default();
    for (index, line) in content.lines().enumerate() {
        let Some(line) = normalize_source_line(line) else {
            continue;
        };

        match parse_proxy_line(line) {
            Ok(Some(ParsedProxyLine::Native(proxy))) => result.proxies.native.push(proxy),
            Ok(Some(ParsedProxyLine::Mihomo(proxy))) => result.proxies.mihomo.push(proxy),
            Ok(None) if allow_subscriptions && is_subscription_url(line) => {
                result.subscription_urls.push(line.to_owned());
            }
            Ok(None) => {
                issues.unsupported_lines += 1;
                debug!("不支持的代理来源行 {}:{}：{}", source, index + 1, line);
            }
            Err(err) if allow_subscriptions && is_subscription_url(line) => {
                debug!("代理解析未命中，按订阅 URL 处理该行：{err}");
                result.subscription_urls.push(line.to_owned());
            }
            Err(err) => {
                issues.invalid_lines += 1;
                debug!("无效的代理来源行 {}:{}：{err}", source, index + 1);
            }
        }
    }
    if issues.invalid_lines > 0 || issues.unsupported_lines > 0 {
        warn!(
            source,
            invalid_lines = issues.invalid_lines,
            unsupported_lines = issues.unsupported_lines,
            "代理来源中存在无法解析的行，已跳过；打开 debug 日志可查看逐行明细"
        );
    }
    Ok(result)
}

fn normalize_source_line(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    for (index, ch) in line.char_indices() {
        if ch != '#' {
            continue;
        }
        let previous = line[..index].chars().next_back()?;
        if previous.is_whitespace() {
            let stripped = line[..index].trim_end();
            return (!stripped.is_empty()).then_some(stripped);
        }
    }
    Some(line)
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
        let (server, label) = parse_shadowsocks_url(line)?;
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
            let addr = host_port_from_url(&url, Some(80))?;
            Ok(Some(ProxyNode::Http {
                addr,
                auth: credentials_from_url(&url),
            }))
        }
        "https" => {
            if !looks_like_https_proxy_url(&url) {
                return Ok(None);
            }
            let addr = host_port_from_url(&url, Some(443))?;
            Ok(Some(ProxyNode::Https {
                addr,
                auth: credentials_from_url(&url),
                sni: query_param(&url, "sni").or_else(|| query_param(&url, "servername")),
                skip_cert_verify: query_param(&url, "allowInsecure")
                    .or_else(|| query_param(&url, "skip-cert-verify"))
                    .or_else(|| query_param(&url, "insecure"))
                    .is_some_and(|value| matches!(value.as_str(), "1" | "true")),
            }))
        }
        "socks" | "socks5" | "socks5h" => {
            let addr = host_port_from_url(&url, None)?;
            Ok(Some(ProxyNode::Socks5 {
                addr,
                auth: socks_credentials_from_url(&url),
                remote_dns: scheme != "socks5",
            }))
        }
        "socks4" | "socks4a" => {
            let addr = host_port_from_url(&url, None)?;
            Ok(Some(ProxyNode::Socks4 {
                addr,
                auth: credentials_from_url(&url),
                remote_dns: scheme == "socks4a",
            }))
        }
        _ => Ok(None),
    }
}

fn parse_shadowsocks_url(line: &str) -> Result<(ServerConfig, String)> {
    let label = Url::parse(line)
        .ok()
        .and_then(|url| url.fragment().map(decode_url_component))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_else(|| "ss".to_owned());

    if let Ok(url) = Url::parse(line)
        && url.host_str().is_some()
        && url.port().is_some()
    {
        let host = required_host(&url, "ss")?;
        let port = required_port(&url, "ss")?;
        let (method, password) = ss_credentials_from_url(&url)?;
        let server = shadowsocks_server(host, port, method, password)?;
        return Ok((server, label));
    }

    let encoded = line
        .trim_start_matches("ss://")
        .split('#')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();
    let decoded = decode_base64_text(encoded).ok_or_else(|| anyhow!("无效的 ss URL"))?;
    let (method, password, host, port) = parse_ss_legacy_authority(&decoded)?;
    let server = shadowsocks_server(host, port, method, password)?;
    Ok((server, label))
}

fn shadowsocks_server(
    host: String,
    port: u16,
    method: String,
    password: String,
) -> Result<ServerConfig> {
    let method = normalize_ss_cipher(&method);
    let method = CipherKind::from_str(&method)
        .map_err(|err| anyhow!("无效的 Shadowsocks cipher {method}：{err:?}"))?;
    Ok(ServerConfig::new(
        ServerAddr::DomainName(host, port),
        password,
        method,
    )?)
}

fn ss_credentials_from_url(url: &Url) -> Result<(String, String)> {
    let username = decode_url_component(url.username());
    if let Some(password) = url.password().map(decode_url_component) {
        return Ok((username, password));
    }

    let credentials = decode_base64_text(url.username())
        .or_else(|| decode_base64_text(&username))
        .unwrap_or(username);
    split_credentials(&credentials).ok_or_else(|| anyhow!("ss URL 缺少 method/password"))
}

fn parse_ss_legacy_authority(value: &str) -> Result<(String, String, String, u16)> {
    let (userinfo, server) = value
        .rsplit_once('@')
        .ok_or_else(|| anyhow!("ss URL 缺少 server"))?;
    let (method, password) =
        split_credentials(userinfo).ok_or_else(|| anyhow!("ss URL 缺少 method/password"))?;
    let (host, port) = split_host_port(server)?;
    Ok((method, password, host, port))
}

fn split_credentials(value: &str) -> Option<(String, String)> {
    let (username, password) = value.split_once(':')?;
    Some((
        decode_url_component(username),
        decode_url_component(password),
    ))
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("IPv6 地址格式无效：{value}"))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("地址缺少 port：{value}"))?
            .parse::<u16>()?;
        return Ok((host.to_owned(), port));
    }

    let (host, port) = value
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':') || host.parse::<IpAddr>().is_ok())
        .ok_or_else(|| anyhow!("地址缺少 port：{value}"))?;
    Ok((host.to_owned(), port.parse::<u16>()?))
}

fn normalize_ss_cipher(method: &str) -> String {
    match method.to_ascii_lowercase().as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_owned(),
        other => other.to_owned(),
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
        "hysteria" => parse_hysteria_url(&url).map(Some),
        "hysteria2" | "hy2" => parse_hysteria2_url(&url).map(Some),
        "tuic" => parse_tuic_url(&url).map(Some),
        "anytls" => parse_anytls_url(&url).map(Some),
        _ => Ok(None),
    }
}

fn parse_vmess_url(encoded: &str) -> Result<MihomoProxyConfig> {
    let decoded = decode_base64_text(encoded).context("无效的 vmess base64 内容")?;
    let link: VmessLink = serde_json::from_str(&decoded).context("无效的 vmess JSON 内容")?;
    let name = non_empty(link.ps).unwrap_or_else(|| {
        format!(
            "vmess-{}",
            non_empty(link.add.clone()).unwrap_or_else(|| "node".to_owned())
        )
    });
    let server = non_empty(link.add).ok_or_else(|| anyhow!("vmess 链接缺少 server"))?;
    let port = parse_u16_string(&link.port, "vmess port")?;
    let uuid = non_empty(link.id).ok_or_else(|| anyhow!("vmess 链接缺少 id"))?;
    let alter_id = parse_vmess_alter_id(link.aid.as_deref())?;

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
        return Err(anyhow!("vless 链接缺少 uuid"));
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
        return Err(anyhow!("trojan 链接缺少 password"));
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
    let port = port_or_first_mport(url).unwrap_or(HYSTERIA2_DEFAULT_PORT);
    let password = query_param(url, "password")
        .or_else(|| query_param(url, "auth"))
        .or_else(|| {
            let username = decode_url_component(url.username());
            (!username.is_empty()).then_some(username)
        })
        .unwrap_or_default();
    if password.is_empty() {
        return Err(anyhow!("hysteria2 链接缺少 password"));
    }

    let mut proxy = ClashProxyDocument::new(name, "hysteria2", server, port);
    proxy.insert_string("password", password);
    apply_hysteria_common_query(&mut proxy, url);
    if let Some(mport) = query_param(url, "mport").or_else(|| query_param(url, "ports")) {
        proxy.insert_string("ports", mport);
    }
    if let Some(hop_interval) =
        query_param(url, "hop-interval").or_else(|| query_param(url, "hop_interval"))
    {
        proxy.insert_string("hop-interval", hop_interval);
    }
    if let Some(obfs) = query_param(url, "obfs").filter(|value| !value.is_empty()) {
        proxy.insert_string("obfs", obfs);
    }
    if let Some(obfs_password) = query_param(url, "obfs-password")
        .or_else(|| query_param(url, "obfs_password"))
        .filter(|value| !value.is_empty())
    {
        proxy.insert_string("obfs-password", obfs_password);
    }
    proxy.into_mihomo("hysteria2")
}

fn parse_hysteria_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "hysteria");
    let server = required_host(url, "hysteria")?;
    let port = required_port(url, "hysteria")?;
    let auth = query_param(url, "auth")
        .or_else(|| query_param(url, "password"))
        .or_else(|| {
            let username = decode_url_component(url.username());
            (!username.is_empty()).then_some(username)
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hysteria 链接缺少 auth/password"))?;

    let mut proxy = ClashProxyDocument::new(name, "hysteria", server, port);
    proxy.insert_string("auth", auth);
    apply_hysteria_common_query(&mut proxy, url);
    if let Some(protocol) = query_param(url, "protocol").filter(|value| !value.is_empty()) {
        proxy.insert_string("protocol", protocol);
    }
    proxy.into_mihomo("hysteria")
}

fn apply_hysteria_common_query(proxy: &mut ClashProxyDocument, url: &Url) {
    if query_param(url, "insecure").is_some_and(|value| value == "1" || value == "true") {
        proxy.insert_bool("skip-cert-verify", true);
    }
    if let Some(sni) = query_param(url, "sni").or_else(|| query_param(url, "peer")) {
        proxy.insert_string("sni", sni.clone());
        proxy.insert_string("servername", sni);
    }
    if let Some(alpn) = query_param(url, "alpn").filter(|value| !value.is_empty()) {
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
    for (query_key, clash_key) in [
        ("upmbps", "up-mbps"),
        ("up_mbps", "up-mbps"),
        ("up", "up"),
        ("downmbps", "down-mbps"),
        ("down_mbps", "down-mbps"),
        ("down", "down"),
        ("pinSHA256", "pinSHA256"),
        ("fingerprint", "fingerprint"),
    ] {
        if let Some(value) = query_param(url, query_key).filter(|value| !value.is_empty()) {
            proxy.insert_string(clash_key, value);
        }
    }
}

fn parse_tuic_url(url: &Url) -> Result<MihomoProxyConfig> {
    let name = proxy_name_from_url(url, "tuic");
    let server = required_host(url, "tuic")?;
    let port = required_port(url, "tuic")?;
    let uuid = url.username();
    let password = url
        .password()
        .ok_or_else(|| anyhow!("tuic 链接用户名必须是 uuid:password"))?;

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
    let password = query_param(url, "password")
        .or_else(|| url.password().map(decode_url_component))
        .or_else(|| {
            let username = decode_url_component(url.username());
            (!username.is_empty()).then_some(username)
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("anytls 链接缺少 password"))?;

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
    let decoded = decode_base64_text(encoded).context("无效的 ssr base64 内容")?;
    let (main, query) = decoded.split_once("/?").unwrap_or((&decoded, ""));
    let mut parts = main.splitn(6, ':');
    let server = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr 链接缺少 server"))?
        .to_owned();
    let port = parts
        .next()
        .ok_or_else(|| anyhow!("ssr 链接缺少 port"))?
        .parse::<u16>()
        .context("无效的 ssr port")?;
    let protocol = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr 链接缺少 protocol"))?
        .to_owned();
    let cipher = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr 链接缺少 cipher"))?
        .to_owned();
    let obfs = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("ssr 链接缺少 obfs"))?
        .to_owned();
    let password = parts
        .next()
        .and_then(decode_base64_text)
        .ok_or_else(|| anyhow!("ssr 链接缺少 password"))?;

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
    url_has_explicit_port(url)
        && (url.path().is_empty() || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none()
}

fn looks_like_https_proxy_url(url: &Url) -> bool {
    port_or_known_default(url, Some(443)).is_some()
        && (url.path().is_empty() || url.path() == "/")
        && (!url.username().is_empty()
            || url.fragment().is_some()
            || query_param(url, "sni").is_some()
            || query_param(url, "servername").is_some()
            || query_param(url, "allowInsecure").is_some()
            || query_param(url, "skip-cert-verify").is_some()
            || query_param(url, "insecure").is_some())
}

fn host_port_from_url(url: &Url, default_port: Option<u16>) -> Result<HostPort> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("代理 URL 缺少 host"))?;
    let port = port_or_known_default(url, default_port)
        .ok_or_else(|| anyhow!("代理 URL 缺少 port：{url}"))?;
    HostPort::new(host, port)
}

fn port_or_known_default(url: &Url, default_port: Option<u16>) -> Option<u16> {
    url.port().or_else(|| {
        let default_port = default_port?;
        (url_has_explicit_port(url) || url.port_or_known_default() == Some(default_port))
            .then_some(default_port)
    })
}

fn url_has_explicit_port(url: &Url) -> bool {
    let Some((_, rest)) = url.as_str().split_once("://") else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit_once('@')
        .map_or_else(|| authority_without_userinfo(rest), |(_, value)| value);

    if let Some(rest) = authority.strip_prefix('[') {
        return rest
            .split_once(']')
            .and_then(|(_, suffix)| suffix.strip_prefix(':'))
            .is_some_and(|port| !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()));
    }

    authority
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':'))
        .is_some_and(|(_, port)| !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()))
}

fn authority_without_userinfo(rest: &str) -> &str {
    rest.split(['/', '?', '#']).next().unwrap_or_default()
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

fn socks_credentials_from_url(url: &Url) -> Option<Credentials> {
    let username = url.username();
    if username.is_empty() {
        return None;
    }
    if url.password().is_some() {
        return credentials_from_url(url);
    }

    let decoded = decode_base64_text(username)
        .or_else(|| decode_base64_text(&decode_url_component(username)))
        .and_then(|credentials| split_credentials(&credentials));
    let (username, password) = decoded?;
    if username.is_empty() && password.is_empty() {
        return None;
    }
    Some(Credentials {
        username,
        password: (!password.is_empty()).then_some(password),
    })
}

fn is_subscription_url(line: &str) -> bool {
    Url::parse(line)
        .map(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
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

struct ClashYamlParse {
    proxies: LoadedProxySet,
    provider_urls: Vec<String>,
}

#[cfg(test)]
fn parse_clash_yaml(content: &str, source: &str) -> Result<Option<LoadedProxySet>> {
    Ok(parse_clash_yaml_document(content, source)?.map(|parsed| parsed.proxies))
}

fn parse_clash_yaml_document(content: &str, source: &str) -> Result<Option<ClashYamlParse>> {
    let yaml_value = match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let raw_entries = raw_clash_proxy_values(&yaml_value);
    let provider_urls = clash_proxy_provider_urls(&yaml_value);
    if raw_entries.is_empty() && provider_urls.is_empty() {
        return Ok(None);
    }

    let mut proxies = LoadedProxySet::default();
    for (index, value) in raw_entries.into_iter().enumerate() {
        let entry = match serde_yaml::from_value::<ClashProxy>(value.clone()) {
            Ok(entry) => entry,
            Err(err) => {
                warn!(
                    "来源 {source} 中存在无效 Clash 代理，索引 {}：{err}",
                    index + 1
                );
                continue;
            }
        };
        match clash_entry_to_proxy(&entry) {
            Ok(ClashProxyDecision::Native(proxy)) => proxies.native.push(proxy),
            Ok(ClashProxyDecision::Mihomo) => {
                proxies.mihomo.push(clash_entry_to_mihomo(entry, value))
            }
            Ok(ClashProxyDecision::Skip) => {}
            Err(err) => warn!("来源 {source} 中存在无效 Clash 代理：{err}"),
        }
    }
    Ok(Some(ClashYamlParse {
        proxies,
        provider_urls,
    }))
}

fn raw_clash_proxy_values(root: &serde_yaml::Value) -> Vec<serde_yaml::Value> {
    root.get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .cloned()
        .unwrap_or_default()
}

fn clash_proxy_provider_urls(root: &serde_yaml::Value) -> Vec<String> {
    let Some(providers) = root
        .get("proxy-providers")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return Vec::new();
    };

    providers
        .values()
        .filter_map(|provider| {
            provider
                .get("url")
                .and_then(serde_yaml::Value::as_str)
                .map(str::trim)
                .filter(|url| !url.is_empty() && is_subscription_url(url))
                .map(str::to_owned)
        })
        .collect()
}

enum ClashProxyDecision {
    Native(ProxyNode),
    Mihomo,
    Skip,
}

fn clash_entry_to_proxy(entry: &ClashProxy) -> Result<ClashProxyDecision> {
    let kind = entry.kind.to_ascii_lowercase();
    let name = entry.name.clone().unwrap_or_else(|| kind.clone());
    if is_clash_group_or_policy_type(&kind) {
        return Ok(ClashProxyDecision::Skip);
    }
    if is_mihomo_only_clash_type(&kind) {
        return Ok(ClashProxyDecision::Mihomo);
    }

    match kind.as_str() {
        "http" => {
            let (server, port) = clash_server_port(entry, &name)?;
            if entry.tls.unwrap_or(false) {
                return Ok(ClashProxyDecision::Native(ProxyNode::Https {
                    addr: HostPort::new(server, port)?,
                    auth: credentials_from_parts(entry.username.clone(), entry.password.clone()),
                    sni: clash_string_extra(entry, &["sni", "servername"]),
                    skip_cert_verify: clash_bool_extra(
                        entry,
                        &["skip-cert-verify", "allow-insecure", "insecure"],
                    )
                    .unwrap_or(false),
                }));
            }
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
                .ok_or_else(|| anyhow!("Shadowsocks 代理 {name} 缺少 cipher"))?;
            let password = entry
                .password
                .clone()
                .ok_or_else(|| anyhow!("Shadowsocks 代理 {name} 缺少 password"))?;
            let method = normalize_ss_cipher(&cipher);
            let method = CipherKind::from_str(&method)
                .map_err(|err| anyhow!("无效的 Shadowsocks cipher {cipher}：{err:?}"))?;
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
                warn!("跳过不支持的 Clash 代理 {name}，类型 {kind}");
                Ok(ClashProxyDecision::Skip)
            }
        }
    }
}

fn clash_server_port(entry: &ClashProxy, name: &str) -> Result<(String, u16)> {
    let server = entry
        .server
        .clone()
        .ok_or_else(|| anyhow!("代理 {name} 缺少 server"))?;
    let port = entry.port.ok_or_else(|| anyhow!("代理 {name} 缺少 port"))?;
    Ok((server, port))
}

fn clash_string_extra(entry: &ClashProxy, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| entry.extra.get(*key).and_then(yaml_value_to_string))
}

fn clash_bool_extra(entry: &ClashProxy, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| entry.extra.get(*key).and_then(yaml_value_to_bool))
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

fn is_clash_group_or_policy_type(kind: &str) -> bool {
    matches!(
        kind,
        "select"
            | "url-test"
            | "fallback"
            | "load-balance"
            | "relay"
            | "direct"
            | "reject"
            | "reject-drop"
            | "pass"
            | "dns"
            | "compatible"
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
        .ok_or_else(|| anyhow!("{scheme} 链接缺少 host"))
}

fn required_port(url: &Url, scheme: &str) -> Result<u16> {
    url.port().ok_or_else(|| anyhow!("{scheme} 链接缺少 port"))
}

fn port_or_first_mport(url: &Url) -> Option<u16> {
    if let Some(port) = url.port() {
        return Some(port);
    }
    query_param(url, "mport")
        .or_else(|| query_param(url, "ports"))
        .as_deref()
        .and_then(first_port_from_range)
}

fn first_port_from_range(value: &str) -> Option<u16> {
    value
        .split([',', '-'])
        .find_map(|part| part.trim().parse::<u16>().ok())
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
        .ok_or_else(|| anyhow!("{label} 缺失"))?
        .parse::<u16>()
        .with_context(|| format!("{label} 无效"))
}

fn parse_vmess_alter_id(value: Option<&str>) -> Result<u16> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    if let Ok(value) = value.parse::<u16>() {
        return Ok(value);
    }
    let mut chars = value.chars();
    if let (Some(ch), None) = (chars.next(), chars.next())
        && ch.is_control()
    {
        let codepoint = ch as u32;
        if codepoint <= u16::MAX as u32 {
            return Ok(codepoint as u16);
        }
    }
    Err(anyhow!("无效的 vmess alterId"))
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
struct ClashProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    server: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u16")]
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

fn deserialize_optional_u16<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_yaml::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    yaml_value_to_u64(&value)
        .and_then(|value| value.try_into().ok())
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("端口必须是 0-65535 的整数或数字字符串"))
}

fn yaml_value_to_u64(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn yaml_value_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn yaml_value_to_bool(value: &serde_yaml::Value) -> Option<bool> {
    match value {
        serde_yaml::Value::Bool(value) => Some(*value),
        serde_yaml::Value::Number(value) => Some(value.as_u64()? != 0),
        serde_yaml::Value::String(value) => Some(matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct VmessLink {
    ps: Option<String>,
    add: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_json_string")]
    port: Option<String>,
    id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_json_string")]
    aid: Option<String>,
    net: Option<String>,
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    scy: Option<String>,
}

fn deserialize_optional_json_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<serde_json::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(value) => Ok(Some(value)),
        serde_json::Value::Number(value) => Ok(Some(value.to_string())),
        serde_json::Value::Bool(value) => Ok(Some(value.to_string())),
        _ => Err(serde::de::Error::custom("字段必须是字符串、数字或布尔值")),
    }
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
            "测试 HTTP 头超过大小限制",
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
        assert!(!is_subscription_url(
            "https://user:pass@example.com:443?sni=example.com#node"
        ));
        assert!(
            parse_proxy_url("https://example.com:443/sub")
                .unwrap()
                .is_none()
        );
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
    fn parses_socks_alias_with_base64_auth() {
        let proxy = parse_proxy_url("socks://dXNlcjpwYXNz@127.0.0.1:1080#node")
            .unwrap()
            .unwrap();
        match proxy {
            ProxyNode::Socks5 {
                addr,
                auth,
                remote_dns,
            } => {
                assert_eq!(addr.host, "127.0.0.1");
                assert_eq!(addr.port, 1080);
                assert!(remote_dns);
                let auth = auth.unwrap();
                assert_eq!(auth.username, "user");
                assert_eq!(auth.password.as_deref(), Some("pass"));
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
    }

    #[test]
    fn parses_https_proxy_url() {
        let proxy = parse_proxy_url(
            "https://user:pass@127.0.0.1:8443?sni=proxy.example.com&allowInsecure=1#node",
        )
        .unwrap()
        .unwrap();
        match proxy {
            ProxyNode::Https {
                addr,
                auth,
                sni,
                skip_cert_verify,
            } => {
                assert_eq!(addr.host, "127.0.0.1");
                assert_eq!(addr.port, 8443);
                assert_eq!(auth.unwrap().username, "user");
                assert_eq!(sni.as_deref(), Some("proxy.example.com"));
                assert!(skip_cert_verify);
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
    }

    #[test]
    fn parses_https_proxy_url_from_subscription_sample() {
        let proxy = parse_proxy_url(
            "https://51362ab6-b5e6-11ea-ad28-f23c913c8d2b:51362ab6-b5e6-11ea-ad28-f23c913c8d2b@bfc8d59d-t9zts0-tnkuks-wujn.se.oshuawei.com:443?sni=bfc8d59d-t9zts0-tnkuks-wujn.se.oshuawei.com#US-Seattle-h-419420622-yupj",
        )
        .unwrap()
        .unwrap();
        match proxy {
            ProxyNode::Https {
                addr,
                auth,
                sni,
                skip_cert_verify,
            } => {
                assert_eq!(addr.host, "bfc8d59d-t9zts0-tnkuks-wujn.se.oshuawei.com");
                assert_eq!(addr.port, 443);
                assert_eq!(
                    auth.unwrap().username,
                    "51362ab6-b5e6-11ea-ad28-f23c913c8d2b"
                );
                assert_eq!(
                    sni.as_deref(),
                    Some("bfc8d59d-t9zts0-tnkuks-wujn.se.oshuawei.com")
                );
                assert!(!skip_cert_verify);
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
    }

    #[test]
    fn parses_ss_raw_userinfo_with_cipher_alias() {
        let proxy = parse_proxy_url("ss://chacha20-poly1305:pass@example.com:8388#ss-a")
            .unwrap()
            .unwrap();
        match &proxy {
            ProxyNode::Shadowsocks { label, .. } => {
                assert_eq!(label, "ss-a");
                assert!(proxy.key().starts_with("ss://chacha20-ietf-poly1305@"));
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

    #[test]
    fn strips_comment_lines_and_whitespace_comments() {
        assert_eq!(normalize_source_line("# comment"), None);
        assert_eq!(
            normalize_source_line("http://127.0.0.1:8080 # local proxy"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            normalize_source_line("vless://id@example.com:443#node"),
            Some("vless://id@example.com:443#node")
        );
    }

    #[test]
    fn fetched_proxy_lists_do_not_expand_nested_subscription_urls() {
        let parsed = parse_local_content(
            r#"
# comment
https://example.com/nested-sub
https://user:pass@example.com:443?sni=example.com#proxy-node
http://127.0.0.1:8080 # inline comment
"#,
            "fetched",
            false,
        )
        .unwrap();
        assert_eq!(parsed.subscription_urls.len(), 0);
        assert_eq!(parsed.proxies.native.len(), 2);
    }

    #[test]
    fn local_source_lists_can_still_contain_subscription_urls() {
        let parsed = parse_local_content(
            "https://example.com/subscription.txt # source list\n",
            "local",
            true,
        )
        .unwrap();
        assert_eq!(
            parsed.subscription_urls,
            vec!["https://example.com/subscription.txt"]
        );
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

    #[tokio::test]
    async fn clash_proxy_provider_urls_are_expanded() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let source_path = dir.path().join("clash.yaml");
        let (provider_url, first_line_rx, _handle) =
            spawn_subscription_proxy("http://127.0.0.1:8080\n").await?;
        fs::write(
            &source_path,
            format!(
                r#"
proxy-providers:
  provider-a:
    type: http
    url: {provider_url}
    path: ./provider.yaml
    interval: 3600
"#
            ),
        )?;
        let options = SubscriptionOptions {
            timeout: Duration::from_secs(2),
            user_agent: "RotatorProxyTest/0.1".to_owned(),
            proxy: None,
        };

        let proxies = load_proxies_from_paths(&[source_path], &options).await?;

        assert_eq!(proxies.native.len(), 1);
        assert_eq!(first_line_rx.await.unwrap(), "GET / HTTP/1.1");
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
    fn parses_clash_https_proxy_as_native_https_connect() {
        let yaml = r#"
proxies:
  - name: https-a
    type: http
    server: proxy.example.com
    port: "443"
    username: user
    password: pass
    tls: true
    sni: tls.example.com
    skip-cert-verify: true
"#;
        let proxies = parse_clash_yaml(yaml, "test").unwrap().unwrap();
        assert_eq!(proxies.native.len(), 1);
        assert_eq!(proxies.mihomo.len(), 0);
        match &proxies.native[0] {
            ProxyNode::Https {
                addr,
                auth,
                sni,
                skip_cert_verify,
            } => {
                assert_eq!(addr.host, "proxy.example.com");
                assert_eq!(addr.port, 443);
                assert_eq!(auth.as_ref().unwrap().username, "user");
                assert_eq!(sni.as_deref(), Some("tls.example.com"));
                assert!(*skip_cert_verify);
            }
            other => panic!("unexpected proxy: {other:?}"),
        }
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
    fn clash_yaml_parses_entries_individually_and_skips_groups() {
        let yaml = r#"
mixed-port: 7890
proxy-groups:
  - name: auto
    type: url-test
    proxies:
      - ss-a
proxies:
  - name: ss-a
    type: ss
    server: example.com
    port: '8388'
    cipher: chacha20-poly1305
    password: pass
  - name: bad-port
    type: http
    server: 127.0.0.1
    port: invalid
  - name: selector-in-proxies
    type: select
    proxies:
      - ss-a
  - name: vmess-a
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
"#;
        let proxies = parse_clash_yaml(yaml, "test").unwrap().unwrap();
        assert_eq!(proxies.native.len(), 1);
        assert_eq!(proxies.mihomo.len(), 1);
        assert_eq!(proxies.mihomo[0].name, "vmess-a");
        match &proxies.native[0] {
            ProxyNode::Shadowsocks { label, .. } => assert_eq!(label, "ss-a"),
            other => panic!("unexpected proxy: {other:?}"),
        }
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
    fn parses_vmess_with_numeric_fields() {
        let encoded = BASE64_STANDARD.encode(
            r#"{"v":"2","ps":"vmess-num","add":"example.com","port":443,"id":"00000000-0000-0000-0000-000000000000","aid":"\u0002","net":"tcp","tls":"tls","scy":"auto"}"#,
        );
        let parsed = parse_proxy_line(&format!("vmess://{encoded}"))
            .unwrap()
            .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "vmess-num");
                assert_eq!(proxy.kind, "vmess");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("port: 443"));
                assert!(text.contains("alterId: 2"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
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
    fn parses_anytls_username_as_password() {
        let parsed = parse_proxy_line("anytls://pass@example.com:8443#anytls-a")
            .unwrap()
            .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "anytls-a");
                assert_eq!(proxy.kind, "anytls");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("password: pass"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
        }
    }

    #[test]
    fn parses_hysteria2_link_with_obfs_and_port_hopping() {
        let parsed = parse_proxy_line(
            "hysteria2://pass@example.com/?insecure=1&sni=www.microsoft.com&mport=50000-50080&obfs=salamander&obfs-password=secret&upmbps=11&downmbps=55#hy2-a",
        )
        .unwrap()
        .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "hy2-a");
                assert_eq!(proxy.kind, "hysteria2");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("port: 50000"));
                assert!(text.contains("ports: 50000-50080"));
                assert!(text.contains("obfs: salamander"));
                assert!(text.contains("obfs-password: secret"));
                assert!(text.contains("up-mbps: '11'"));
                assert!(text.contains("down-mbps: '55'"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
        }
    }

    #[test]
    fn parses_hysteria2_link_without_port_as_default_443() {
        let parsed = parse_proxy_line("hysteria2://pass@example.com/?insecure=1#hy2-default")
            .unwrap()
            .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "hy2-default");
                assert_eq!(proxy.kind, "hysteria2");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("port: 443"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
        }
    }

    #[test]
    fn parses_hysteria_v1_link_as_complex_node() {
        let parsed = parse_proxy_line(
            "hysteria://163.172.117.163:36699?alpn=h3&auth=dongtaiwang.com&downmbps=55&insecure=1&protocol=udp&upmbps=11#hy-a",
        )
        .unwrap()
        .unwrap();

        match parsed {
            ParsedProxyLine::Mihomo(proxy) => {
                assert_eq!(proxy.name, "hy-a");
                assert_eq!(proxy.kind, "hysteria");
                let text = serde_yaml::to_string(&proxy.value).unwrap();
                assert!(text.contains("auth: dongtaiwang.com"));
                assert!(text.contains("protocol: udp"));
                assert!(text.contains("skip-cert-verify: true"));
            }
            ParsedProxyLine::Native(_) => panic!("expected complex node"),
        }
    }

    #[test]
    fn parses_local_content_with_decoded_queue_marker() {
        let encoded = BASE64_STANDARD.encode("socks5://127.0.0.1:1080\n");
        let parsed = parse_local_content(&encoded, "test", true).unwrap();
        assert_eq!(parsed.decoded_contents.len(), 1);
    }
}
