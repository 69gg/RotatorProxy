use std::{
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
use serde::Deserialize;
use shadowsocks::{ServerConfig, config::ServerAddr, crypto::CipherKind};
use tracing::{debug, warn};
use url::Url;

use crate::{
    config::AppConfig,
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

#[derive(Debug, Clone)]
pub struct SubscriptionOptions {
    pub timeout: Duration,
    pub user_agent: String,
}

impl From<&AppConfig> for SubscriptionOptions {
    fn from(config: &AppConfig) -> Self {
        Self {
            timeout: Duration::from_millis(config.subscription_timeout_ms),
            user_agent: config.subscription_user_agent.clone(),
        }
    }
}

pub async fn load_proxies_from_dirs(config: &AppConfig) -> Result<Vec<ProxyNode>> {
    let options = SubscriptionOptions::from(config);
    load_proxies_from_paths(&config.proxy_dirs, &options).await
}

pub async fn load_proxies_from_paths(
    paths: &[PathBuf],
    options: &SubscriptionOptions,
) -> Result<Vec<ProxyNode>> {
    let client = reqwest::Client::builder()
        .timeout(options.timeout)
        .user_agent(options.user_agent.clone())
        .build()
        .context("failed to build subscription HTTP client")?;

    let mut proxies = Vec::new();
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
) -> Result<Vec<ProxyNode>> {
    let mut queue = VecDeque::from([QueuedContent {
        content,
        source,
        depth: 0,
    }]);
    let mut proxies = Vec::new();

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
    proxies: Vec<ProxyNode>,
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

        match parse_proxy_url(line) {
            Ok(Some(proxy)) => result.proxies.push(proxy),
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

fn parse_clash_yaml(content: &str, source: &str) -> Result<Option<Vec<ProxyNode>>> {
    let config = match serde_yaml::from_str::<ClashConfig>(content) {
        Ok(config) => config,
        Err(_) => return Ok(None),
    };
    let Some(entries) = config.proxies else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let mut proxies = Vec::new();
    for entry in entries {
        match clash_entry_to_proxy(entry) {
            Ok(Some(proxy)) => proxies.push(proxy),
            Ok(None) => {}
            Err(err) => warn!("invalid Clash proxy in {source}: {err}"),
        }
    }
    Ok(Some(proxies))
}

fn clash_entry_to_proxy(entry: ClashProxy) -> Result<Option<ProxyNode>> {
    let kind = entry.kind.to_ascii_lowercase();
    let name = entry.name.unwrap_or_else(|| kind.clone());
    let server = entry
        .server
        .ok_or_else(|| anyhow!("proxy {name} missing server"))?;
    let port = entry
        .port
        .ok_or_else(|| anyhow!("proxy {name} missing port"))?;

    match kind.as_str() {
        "http" => {
            if entry.tls.unwrap_or(false) {
                warn!("skipping Clash HTTP proxy {name}: TLS proxy transport is not supported");
                return Ok(None);
            }
            Ok(Some(ProxyNode::Http {
                addr: HostPort::new(server, port)?,
                auth: credentials_from_parts(entry.username, entry.password),
            }))
        }
        "socks5" => Ok(Some(ProxyNode::Socks5 {
            addr: HostPort::new(server, port)?,
            auth: credentials_from_parts(entry.username, entry.password),
            remote_dns: true,
        })),
        "ss" | "shadowsocks" => {
            let cipher = entry
                .cipher
                .or(entry.method)
                .ok_or_else(|| anyhow!("Shadowsocks proxy {name} missing cipher"))?;
            let password = entry
                .password
                .ok_or_else(|| anyhow!("Shadowsocks proxy {name} missing password"))?;
            let method = CipherKind::from_str(&cipher)
                .map_err(|err| anyhow!("invalid Shadowsocks cipher {cipher}: {err:?}"))?;
            let server = ServerConfig::new(ServerAddr::DomainName(server, port), password, method)?;
            Ok(Some(ProxyNode::Shadowsocks {
                server: Arc::new(server),
                label: name,
            }))
        }
        _ => {
            warn!("skipping unsupported Clash proxy {name} of type {kind}");
            Ok(None)
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(proxies.len(), 2);
        assert!(matches!(proxies[0], ProxyNode::Http { .. }));
        assert!(matches!(proxies[1], ProxyNode::Socks5 { .. }));
    }

    #[test]
    fn parses_local_content_with_decoded_queue_marker() {
        let encoded = BASE64_STANDARD.encode("socks5://127.0.0.1:1080\n");
        let parsed = parse_local_content(&encoded, "test").unwrap();
        assert_eq!(parsed.decoded_contents.len(), 1);
    }
}
