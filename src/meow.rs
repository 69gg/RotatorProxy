use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
};
use meow_proxy::{
    AnytlsAdapter, Hy2Adapter, Hy2HopInterval, Hy2Obfs, Hy2Options, ShadowsocksAdapter,
    SnellAdapter, SnellObfs, SnellVersion, StreamConn, TrojanAdapter, VlessAdapter, VlessFlow,
    VmessAdapter, shadowsocks_adapter::is_builtin_obfs_plugin,
};
use meow_transport::{
    grpc::{GrpcConfig, GrpcLayer},
    h2::{H2Config, H2Layer},
    httpupgrade::{HttpUpgradeConfig, HttpUpgradeLayer},
    tls::{RealityConfig, TlsConfig, TlsLayer},
    ws::{WsConfig, WsLayer},
};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    parser::MihomoProxyConfig,
    proxy::{MeowProxyNode, ProxyNode},
};

pub struct MeowBuildResult {
    pub nodes: Vec<ProxyNode>,
    pub fallback: Vec<MihomoProxyConfig>,
}

const TROJAN_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

struct TrojanTransportAdapter {
    name: String,
    server: String,
    port: u16,
    addr: String,
    hex_password: String,
    transport: meow_proxy::TransportChain,
    health: ProxyHealth,
}

impl TrojanTransportAdapter {
    fn new(
        name: String,
        server: String,
        port: u16,
        password: &str,
        transport: meow_proxy::TransportChain,
    ) -> Self {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hex_password = hex_lower(&hasher.finalize());
        let addr = format!("{server}:{port}");
        Self {
            name,
            server,
            port,
            addr,
            hex_password,
            transport,
            health: ProxyHealth::new(),
        }
    }

    fn build_header(&self, metadata: &Metadata) -> meow_common::Result<Vec<u8>> {
        let mut header = Vec::with_capacity(320);
        header.extend_from_slice(self.hex_password.as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(TROJAN_CMD_CONNECT);
        encode_socks_addr_from_metadata(&mut header, metadata)?;
        header.extend_from_slice(b"\r\n");
        Ok(header)
    }
}

#[async_trait]
impl ProxyAdapter for TrojanTransportAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Trojan
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        debug!(
            "Trojan transport connecting to {} via {}",
            metadata.remote_address(),
            self.addr
        );
        let tcp = meow_common::connect_tcp_host(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        let mut stream = self.transport.connect(Box::new(tcp)).await?;
        let header = self.build_header(metadata)?;
        stream.write_all(&header).await.map_err(MeowError::Io)?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "Trojan transport UDP is not supported by RotatorProxy".to_owned(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

fn encode_socks_addr_from_metadata(
    out: &mut Vec<u8>,
    metadata: &Metadata,
) -> meow_common::Result<()> {
    if !metadata.host.is_empty() {
        let host = metadata.host.as_bytes();
        if host.len() > u8::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "trojan: domain name too long ({} > {})",
                host.len(),
                u8::MAX
            )));
        }
        out.push(SOCKS_ATYP_DOMAIN);
        out.push(host.len() as u8);
        out.extend_from_slice(host);
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            std::net::IpAddr::V4(ip) => {
                out.push(SOCKS_ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(SOCKS_ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        }
    } else {
        out.push(SOCKS_ATYP_IPV4);
        out.extend_from_slice(&[0, 0, 0, 0]);
    }
    out.extend_from_slice(&metadata.dst_port.to_be_bytes());
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn build_meow_nodes(proxies: Vec<MihomoProxyConfig>) -> MeowBuildResult {
    let mut nodes = Vec::with_capacity(proxies.len());
    let mut fallback = Vec::new();

    for proxy in proxies {
        match build_meow_node(&proxy) {
            Ok(node) => {
                debug!(node = %node.label(), "复杂代理已接入原生 meow 后端");
                nodes.push(node);
            }
            Err(err) => {
                debug!(
                    node = %proxy.name,
                    kind = %proxy.kind,
                    "复杂代理暂不支持原生 meow 后端，将在刷新阶段跳过：{err:#}"
                );
                fallback.push(proxy);
            }
        }
    }

    if !fallback.is_empty() {
        warn!(
            fallback_nodes = fallback.len(),
            "存在原生 meow 后端暂不支持的复杂代理，本轮刷新会跳过这些节点；打开 debug 日志可查看逐节点原因"
        );
    }

    MeowBuildResult { nodes, fallback }
}

fn build_meow_node(proxy: &MihomoProxyConfig) -> Result<ProxyNode> {
    let mapping = proxy_mapping(proxy)?;
    let kind = string_field(mapping, &["type"])
        .unwrap_or_else(|| proxy.kind.clone())
        .to_ascii_lowercase();
    match kind.as_str() {
        "vmess" => build_vmess(proxy, mapping),
        "vless" => build_vless(proxy, mapping),
        "trojan" => build_trojan(proxy, mapping),
        "hysteria2" | "hy2" => build_hysteria2(proxy, mapping),
        "snell" => build_snell(proxy, mapping),
        "anytls" => build_anytls(proxy, mapping),
        "ss" | "shadowsocks" => build_shadowsocks(proxy, mapping),
        _ => bail!("原生复杂代理类型暂不支持：{kind}"),
    }
}

fn build_vmess(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let uuid = uuid_bytes(&required_string(mapping, &["uuid", "id"], &name)?)?;
    let alter_id = u16_field(mapping, &["alterId", "alter-id", "aid"]).unwrap_or(0);
    if alter_id != 0 {
        bail!("旧版 VMess alterId={alter_id} 原生暂不支持");
    }
    let security = match string_field(mapping, &["cipher", "security", "scy"])
        .unwrap_or_else(|| "auto".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "auto" => meow_proxy::vmess::header::auto_security(),
        "aes-128-gcm" | "aead" => meow_proxy::vmess::Security::Aes128Gcm,
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
            meow_proxy::vmess::Security::ChaCha20Poly1305
        }
        "none" | "zero" => meow_proxy::vmess::Security::None,
        other => bail!("不支持的 VMess security：{other}"),
    };
    let transport = build_transport_chain(mapping, &server)?;
    let adapter = VmessAdapter::new(
        &name,
        &server,
        port,
        uuid,
        security,
        bool_field(mapping, &["udp"]).unwrap_or(false),
        transport,
    );
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_vless(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let uuid = uuid_bytes(&required_string(mapping, &["uuid", "id"], &name)?)?;
    if let Some(encryption) = string_field(mapping, &["encryption"])
        && !matches!(encryption.as_str(), "" | "none")
    {
        bail!("不支持的 VLESS encryption：{encryption}");
    }
    let flow = parse_vless_flow(mapping)?;
    let transport = build_transport_chain(mapping, &server)?;
    let adapter = VlessAdapter::new(
        &name,
        &server,
        port,
        uuid,
        flow,
        bool_field(mapping, &["udp"]).unwrap_or(false),
        transport,
    );
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_trojan(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let network = transport_network(mapping);
    let password = required_string(mapping, &["password"], &name)?;
    let sni = string_field(mapping, &["sni", "servername"]).unwrap_or_else(|| server.clone());
    validate_tls_server_name(&sni)?;
    if !matches!(network.as_str(), "" | "tcp" | "trojan") {
        let transport = build_trojan_transport_chain(mapping, &server, &sni)?;
        let adapter =
            TrojanTransportAdapter::new(name.clone(), server.clone(), port, &password, transport);
        return Ok(meow_node(proxy, name, server, port, Arc::new(adapter)));
    }
    let adapter = TrojanAdapter::new(
        &name,
        &server,
        port,
        &password,
        &sni,
        bool_field(mapping, &["skip-cert-verify", "allow-insecure"]).unwrap_or(false),
        bool_field(mapping, &["udp"]).unwrap_or(false),
    );
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_hysteria2(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let password = required_string(mapping, &["password", "auth"], &name)?;
    let obfs = string_field(mapping, &["obfs"])
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let options = Hy2Options {
        name: name.clone(),
        server: server.clone(),
        port,
        password,
        sni: string_field(mapping, &["sni", "servername"]),
        skip_cert_verify: bool_field(mapping, &["skip-cert-verify", "allow-insecure"])
            .unwrap_or(false),
        udp: bool_field(mapping, &["udp"]).unwrap_or(false),
        up_bps: hy_bandwidth_bps(mapping, &["up", "up-mbps", "upmbps", "up_mbps"]).unwrap_or(0),
        down_bps: hy_bandwidth_bps(mapping, &["down", "down-mbps", "downmbps", "down_mbps"])
            .unwrap_or(0),
        obfs: match obfs.as_deref() {
            Some("salamander") => Some(Hy2Obfs::Salamander),
            Some(other) => bail!("不支持的 Hysteria2 obfs：{other}"),
            None => None,
        },
        obfs_password: string_field(mapping, &["obfs-password", "obfs_password"]),
        ports: string_field(mapping, &["ports", "mport"]),
        hop_interval: parse_hy2_hop_interval(mapping),
        fingerprint: string_field(mapping, &["pinSHA256", "fingerprint"]),
        fast_open: bool_field(mapping, &["fast-open"]).unwrap_or(false),
    };
    let adapter = Hy2Adapter::new(options).map_err(|err| anyhow!(err))?;
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_snell(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let psk = required_string(mapping, &["psk", "password"], &name)?;
    let version = match string_field(mapping, &["version"])
        .unwrap_or_else(|| "3".to_owned())
        .trim_start_matches('v')
    {
        "3" => SnellVersion::V3,
        "4" => SnellVersion::V4,
        "5" => SnellVersion::V5,
        other => bail!("不支持的 Snell version：{other}"),
    };
    let obfs = parse_snell_obfs(mapping, &server)?;
    let adapter = SnellAdapter::new(
        &name,
        &server,
        port,
        &psk,
        obfs,
        version,
        bool_field(mapping, &["udp"]).unwrap_or(false),
        bool_field(mapping, &["reuse"]).unwrap_or(false),
    )?;
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_anytls(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = u16_field(mapping, &["port"]).unwrap_or(8443);
    let password = required_string(mapping, &["password"], &name)?;
    let adapter = AnytlsAdapter::new(
        &name,
        &server,
        port,
        &password,
        string_field(mapping, &["sni", "servername"]).as_deref(),
        bool_field(mapping, &["skip-cert-verify", "allow-insecure"]).unwrap_or(false),
    )
    .map_err(|err| anyhow!(err))?;
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_shadowsocks(
    proxy: &MihomoProxyConfig,
    mapping: &serde_yaml::Mapping,
) -> Result<ProxyNode> {
    let name = node_name(proxy, mapping);
    let server = required_string(mapping, &["server"], &name)?;
    let port = required_port(mapping, &["port"], &name)?;
    let cipher = required_string(mapping, &["cipher", "method"], &name)?;
    let password = required_string(mapping, &["password"], &name)?;
    let plugin = string_field(mapping, &["plugin"]);
    if let Some(plugin) = plugin.as_deref()
        && !is_builtin_obfs_plugin(plugin)
        && plugin != "v2ray-plugin"
    {
        bail!("Shadowsocks plugin {plugin} 原生暂不支持");
    }
    let adapter = ShadowsocksAdapter::new(
        &name,
        &server,
        port,
        &password,
        &cipher,
        bool_field(mapping, &["udp"]).unwrap_or(false),
        plugin.as_deref(),
        string_field(mapping, &["plugin-opts"]).as_deref(),
    )?;
    Ok(meow_node(proxy, name, server, port, Arc::new(adapter)))
}

fn build_transport_chain(
    mapping: &serde_yaml::Mapping,
    server: &str,
) -> Result<meow_proxy::transport_chain::TransportChain> {
    let mut chain = meow_proxy::transport_chain::TransportChain::empty();
    let reality = parse_reality_config(mapping)?;
    if bool_field(mapping, &["tls"]).unwrap_or(false) || reality.is_some() {
        push_tls_layer(
            &mut chain,
            mapping,
            string_field(mapping, &["servername", "sni"]).unwrap_or_else(|| server.to_owned()),
            reality,
        )?;
    }
    push_transport_layers(&mut chain, mapping, server)?;
    Ok(chain)
}

fn build_trojan_transport_chain(
    mapping: &serde_yaml::Mapping,
    server: &str,
    sni: &str,
) -> Result<meow_proxy::transport_chain::TransportChain> {
    let mut chain = meow_proxy::transport_chain::TransportChain::empty();
    push_tls_layer(&mut chain, mapping, sni.to_owned(), None)?;
    push_transport_layers(&mut chain, mapping, server)?;
    Ok(chain)
}

fn push_tls_layer(
    chain: &mut meow_proxy::transport_chain::TransportChain,
    mapping: &serde_yaml::Mapping,
    server_name: String,
    reality: Option<RealityConfig>,
) -> Result<()> {
    let mut config = TlsConfig::new(server_name);
    config.skip_cert_verify =
        bool_field(mapping, &["skip-cert-verify", "allow-insecure"]).unwrap_or(false);
    config.alpn = string_list_field(mapping, &["alpn"]).unwrap_or_default();
    config.fingerprint = string_field(mapping, &["client-fingerprint", "fingerprint"]);
    config.reality = reality;
    let layer = TlsLayer::new(&config).map_err(|err| anyhow!("{err}"))?;
    chain.push(Box::new(layer));
    Ok(())
}

fn push_transport_layers(
    chain: &mut meow_proxy::transport_chain::TransportChain,
    mapping: &serde_yaml::Mapping,
    server: &str,
) -> Result<()> {
    let network = transport_network(mapping);
    match network.as_str() {
        "" | "tcp" | "vmess" | "vless" | "trojan" => {}
        "ws" | "websocket" => {
            let options = mapping_field(mapping, "ws-opts");
            let host_header = string_field_in(options, &["host"])
                .or_else(|| header_field(options, "Host"))
                .or_else(|| string_field(mapping, &["host"]))
                .or_else(|| Some(server.to_owned()));
            let config = WsConfig {
                path: string_field_in(options, &["path"]).unwrap_or_else(|| "/".to_owned()),
                host_header,
                extra_headers: headers_from_mapping_without(options, &["host"]),
                max_early_data: usize_field_in(options, &["max-early-data"]).unwrap_or(0),
                early_data_header_name: string_field_in(options, &["early-data-header-name"]),
            };
            chain.push(Box::new(
                WsLayer::new(config).map_err(|err| anyhow!("{err}"))?,
            ));
        }
        "grpc" => {
            let options = mapping_field(mapping, "grpc-opts");
            let config = GrpcConfig {
                service_name: string_field_in(
                    options,
                    &["grpc-service-name", "serviceName", "service-name"],
                )
                .unwrap_or_else(|| "GunService".to_owned()),
                authority: string_field_in(options, &["authority", "host"])
                    .unwrap_or_else(|| server.to_owned()),
            };
            chain.push(Box::new(GrpcLayer::new(config)));
        }
        "h2" | "http" => {
            let options = mapping_field(mapping, "h2-opts");
            let config = H2Config {
                path: string_field_in(options, &["path"]).unwrap_or_else(|| "/".to_owned()),
                hosts: string_list_field_in(options, &["host"])
                    .or_else(|| string_field(mapping, &["host"]).map(|host| vec![host]))
                    .unwrap_or_else(|| vec![server.to_owned()]),
            };
            chain.push(Box::new(H2Layer::new(config)));
        }
        "httpupgrade" | "http-upgrade" => {
            let options = mapping_field(mapping, "http-upgrade-opts");
            let config = HttpUpgradeConfig {
                path: string_field_in(options, &["path"]).unwrap_or_else(|| "/".to_owned()),
                host_header: string_field_in(options, &["host"])
                    .or_else(|| Some(server.to_owned())),
                extra_headers: headers_from_mapping_without(options, &["host"]),
            };
            chain.push(Box::new(HttpUpgradeLayer::new(config)));
        }
        other => bail!("不支持的传输网络：{other}"),
    }
    Ok(())
}

fn transport_network(mapping: &serde_yaml::Mapping) -> String {
    string_field(mapping, &["network", "type"])
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn meow_node(
    proxy: &MihomoProxyConfig,
    name: String,
    server: String,
    port: u16,
    adapter: Arc<dyn ProxyAdapter>,
) -> ProxyNode {
    ProxyNode::Meow(MeowProxyNode {
        adapter,
        key: format!("meow://{}:{name}@{server}:{port}", proxy.kind),
        label: format!("meow:{}:{name}", proxy.kind),
        source: proxy.clone(),
    })
}

fn proxy_mapping(proxy: &MihomoProxyConfig) -> Result<&serde_yaml::Mapping> {
    proxy
        .value
        .as_mapping()
        .ok_or_else(|| anyhow!("复杂代理 {} 不是 YAML mapping", proxy.name))
}

fn node_name(proxy: &MihomoProxyConfig, mapping: &serde_yaml::Mapping) -> String {
    string_field(mapping, &["name"]).unwrap_or_else(|| proxy.name.clone())
}

fn required_string(mapping: &serde_yaml::Mapping, keys: &[&str], name: &str) -> Result<String> {
    string_field(mapping, keys).ok_or_else(|| anyhow!("代理 {name} 缺少 {}", keys.join("/")))
}

fn required_port(mapping: &serde_yaml::Mapping, keys: &[&str], name: &str) -> Result<u16> {
    u16_field(mapping, keys).ok_or_else(|| anyhow!("代理 {name} 缺少 {}", keys.join("/")))
}

fn parse_vless_flow(mapping: &serde_yaml::Mapping) -> Result<Option<VlessFlow>> {
    let Some(flow) = string_field(mapping, &["flow"]) else {
        return Ok(None);
    };
    let flow = flow.to_ascii_lowercase();
    match flow.as_str() {
        "" | "none" => Ok(None),
        "xtls-rprx-vision" => Ok(Some(VlessFlow::XtlsRprxVision)),
        value if value.starts_with("xtls-rprx-vision-") => Ok(Some(VlessFlow::XtlsRprxVision)),
        other => bail!("不支持的 VLESS flow：{other}"),
    }
}

fn uuid_bytes(value: &str) -> Result<[u8; 16]> {
    Ok(*Uuid::parse_str(value)
        .with_context(|| format!("uuid 无效：{value}"))?
        .as_bytes())
}

fn validate_tls_server_name(value: &str) -> Result<()> {
    ServerName::try_from(value.to_owned())
        .with_context(|| format!("TLS server name/SNI 无效：{value}"))?;
    Ok(())
}

fn parse_hy2_hop_interval(mapping: &serde_yaml::Mapping) -> Option<Hy2HopInterval> {
    let raw = string_field(mapping, &["hop-interval", "hop_interval"])?;
    let (min, max) = raw.split_once('-')?;
    Some(Hy2HopInterval {
        min_secs: min.parse().ok()?,
        max_secs: max.parse().ok()?,
    })
}

fn hy_bandwidth_bps(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        let raw = get(mapping, key)?;
        let raw = value_to_string(raw)?;
        parse_hy_bandwidth(&raw, key)
    })
}

fn parse_hy_bandwidth(value: &str, key: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let digits: String = value.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    let number = digits.parse::<u64>().ok()?;
    let suffix = value[digits.len()..].trim().to_ascii_lowercase();
    if key.contains("mbps") {
        return Some(number.saturating_mul(1_000_000));
    }
    match suffix.as_str() {
        "" => Some(number),
        "b" | "bps" => Some(number),
        "k" | "kb" | "kbps" => Some(number.saturating_mul(1_000)),
        "m" | "mb" | "mbps" => Some(number.saturating_mul(1_000_000)),
        "g" | "gb" | "gbps" => Some(number.saturating_mul(1_000_000_000)),
        _ => None,
    }
}

fn parse_snell_obfs(mapping: &serde_yaml::Mapping, server: &str) -> Result<SnellObfs> {
    let Some(options) = mapping_field(mapping, "obfs-opts") else {
        return Ok(SnellObfs::None);
    };
    let mode = string_field_in(Some(options), &["mode"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    match mode.as_str() {
        "" => Ok(SnellObfs::None),
        "http" => Ok(SnellObfs::Http {
            host: string_field_in(Some(options), &["host"]).unwrap_or_else(|| server.to_owned()),
        }),
        "tls" => Ok(SnellObfs::Tls {
            server: string_field_in(Some(options), &["host", "server"])
                .unwrap_or_else(|| server.to_owned()),
        }),
        other => bail!("不支持的 Snell obfs 模式：{other}"),
    }
}

fn parse_reality_config(mapping: &serde_yaml::Mapping) -> Result<Option<RealityConfig>> {
    let Some(options) = mapping_field(mapping, "reality-opts") else {
        return Ok(None);
    };
    let public_key = string_field_in(Some(options), &["public-key", "public_key", "pbk"])
        .ok_or_else(|| anyhow!("reality-opts 缺少 public-key"))?;
    Ok(Some(RealityConfig {
        public_key: decode_reality_public_key(&public_key)?,
        short_id: decode_reality_short_id(
            &string_field_in(Some(options), &["short-id", "short_id", "sid"]).unwrap_or_default(),
        )?,
        support_x25519_mlkem768: bool_field_in(
            Some(options),
            &[
                "support-x25519-mlkem768",
                "support_x25519_mlkem768",
                "x25519-mlkem768",
            ],
        )
        .unwrap_or(false),
    }))
}

fn decode_reality_public_key(value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    for engine in [&URL_SAFE_NO_PAD, &URL_SAFE] {
        let Ok(decoded) = engine.decode(value.as_bytes()) else {
            continue;
        };
        return decoded.try_into().map_err(|decoded: Vec<u8>| {
            anyhow!(
                "reality public-key 解码后必须是 32 字节，实际为 {}",
                decoded.len()
            )
        });
    }
    bail!("无效的 reality public-key base64")
}

fn decode_reality_short_id(value: &str) -> Result<[u8; 8]> {
    let bytes = decode_hex(value.trim()).context("无效的 reality short-id hex")?;
    if bytes.len() > 8 {
        bail!("reality short-id 最多 8 字节");
    }
    let mut short_id = [0_u8; 8];
    short_id[..bytes.len()].copy_from_slice(&bytes);
    Ok(short_id)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if !value.len().is_multiple_of(2) {
        bail!("hex 字符串长度必须为偶数");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("无效的 hex 字符：{}", byte as char),
    }
}

fn get<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.to_owned()))
}

fn mapping_field<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: &str,
) -> Option<&'a serde_yaml::Mapping> {
    get(mapping, key)?.as_mapping()
}

fn string_field(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Option<String> {
    string_field_in(Some(mapping), keys)
}

fn string_field_in(mapping: Option<&serde_yaml::Mapping>, keys: &[&str]) -> Option<String> {
    let mapping = mapping?;
    keys.iter()
        .find_map(|key| value_to_string(get(mapping, key)?))
}

fn string_list_field(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Option<Vec<String>> {
    string_list_field_in(Some(mapping), keys)
}

fn string_list_field_in(
    mapping: Option<&serde_yaml::Mapping>,
    keys: &[&str],
) -> Option<Vec<String>> {
    let mapping = mapping?;
    keys.iter()
        .find_map(|key| value_to_string_list(get(mapping, key)?))
}

fn header_field(mapping: Option<&serde_yaml::Mapping>, key: &str) -> Option<String> {
    let headers = mapping_field(mapping?, "headers")?;
    string_field_in(Some(headers), &[key])
}

fn headers_from_mapping_without(
    mapping: Option<&serde_yaml::Mapping>,
    excluded_keys: &[&str],
) -> Vec<(String, String)> {
    let Some(headers) = mapping.and_then(|mapping| mapping_field(mapping, "headers")) else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|(key, value)| {
            let key = value_to_string(key)?;
            if excluded_keys
                .iter()
                .any(|excluded| key.eq_ignore_ascii_case(excluded))
            {
                return None;
            }
            Some((key, value_to_string(value)?))
        })
        .collect()
}

fn bool_field(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Option<bool> {
    bool_field_in(Some(mapping), keys)
}

fn bool_field_in(mapping: Option<&serde_yaml::Mapping>, keys: &[&str]) -> Option<bool> {
    let mapping = mapping?;
    keys.iter()
        .find_map(|key| value_to_bool(get(mapping, key)?))
}

fn u16_field(mapping: &serde_yaml::Mapping, keys: &[&str]) -> Option<u16> {
    keys.iter()
        .find_map(|key| value_to_u64(get(mapping, key)?).and_then(|value| value.try_into().ok()))
}

fn usize_field_in(mapping: Option<&serde_yaml::Mapping>, keys: &[&str]) -> Option<usize> {
    let mapping = mapping?;
    keys.iter()
        .find_map(|key| value_to_u64(get(mapping, key)?).and_then(|value| value.try_into().ok()))
}

fn value_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_to_string_list(value: &serde_yaml::Value) -> Option<Vec<String>> {
    match value {
        serde_yaml::Value::Sequence(values) => {
            Some(values.iter().filter_map(value_to_string).collect())
        }
        _ => value_to_string(value).map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        }),
    }
}

fn value_to_bool(value: &serde_yaml::Value) -> Option<bool> {
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

fn value_to_u64(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complex(yaml: &str) -> MihomoProxyConfig {
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let mapping = value.as_mapping().unwrap();
        MihomoProxyConfig {
            name: string_field(mapping, &["name"]).unwrap(),
            kind: string_field(mapping, &["type"]).unwrap(),
            value,
        }
    }

    #[tokio::test]
    async fn builds_anytls_adapter() {
        let proxy = complex(
            r#"
name: anytls-a
type: anytls
server: example.com
port: 8443
password: pass
sni: example.com
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
        assert_eq!(result.nodes[0].label(), "meow:anytls:anytls-a");
    }

    #[test]
    fn unsupported_tuic_falls_back() {
        let proxy = complex(
            r#"
name: tuic-a
type: tuic
server: example.com
port: 443
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.fallback.len(), 1);
    }

    #[test]
    fn builds_reality_vless_adapter() {
        let proxy = complex(
            r#"
name: vless-reality
type: vless
server: example.com
port: 443
uuid: 00000000-0000-0000-0000-000000000000
tls: true
reality-opts:
  public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  short-id: 0123456789abcdef
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
    }

    #[test]
    fn builds_client_fingerprint_adapter() {
        let proxy = complex(
            r#"
name: vless-fp
type: vless
server: example.com
port: 443
uuid: 00000000-0000-0000-0000-000000000000
tls: true
client-fingerprint: chrome
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
    }

    #[test]
    fn normalizes_vless_vision_udp443_flow_suffix() {
        let proxy = complex(
            r#"
name: vless-vision-udp443
type: vless
server: example.com
port: 443
uuid: 00000000-0000-0000-0000-000000000000
tls: true
flow: xtls-rprx-vision-udp443
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
    }

    #[test]
    fn builds_trojan_websocket_transport_adapter() {
        let proxy = complex(
            r#"
name: trojan-ws
type: trojan
server: example.com
port: 443
password: pass
sni: example.com
network: ws
ws-opts:
  path: /ws
  headers:
    Host: cdn.example.com
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
        assert_eq!(result.nodes[0].label(), "meow:trojan:trojan-ws");
    }

    #[test]
    fn invalid_reality_public_key_falls_back() {
        let proxy = complex(
            r#"
name: vless-reality
type: vless
server: example.com
port: 443
uuid: 00000000-0000-0000-0000-000000000000
reality-opts:
  public-key: abc
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.fallback.len(), 1);
    }

    #[test]
    fn invalid_trojan_sni_falls_back_without_panic() {
        let proxy = complex(
            r#"
name: trojan-invalid-sni
type: trojan
server: example.com
port: 443
password: pass
sni: t.me%2Fripaojiedian
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.fallback.len(), 1);
    }

    #[test]
    fn builds_hysteria2_with_empty_obfs_and_aliases() {
        let proxy = complex(
            r#"
name: hy2-empty-obfs
type: hysteria2
server: example.com
port: 443
password: pass
obfs: ""
obfs_password: secret
mport: 443-445
upmbps: 11
downmbps: 55
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.fallback.len(), 0);
        assert_eq!(result.nodes[0].label(), "meow:hysteria2:hy2-empty-obfs");
    }

    #[test]
    fn hysteria_v1_still_reports_unsupported_native_adapter() {
        let proxy = complex(
            r#"
name: hy1
type: hysteria
server: example.com
port: 443
auth: pass
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.fallback.len(), 1);
    }

    #[test]
    fn mieru_still_reports_unsupported_native_adapter() {
        let proxy = complex(
            r#"
name: mieru-a
type: mieru
server: example.com
port: 443
username: user
password: pass
"#,
        );
        let result = build_meow_nodes(vec![proxy]);
        assert_eq!(result.nodes.len(), 0);
        assert_eq!(result.fallback.len(), 1);
    }

    #[test]
    fn host_header_is_removed_from_extra_headers() {
        let options: serde_yaml::Mapping = serde_yaml::from_str(
            r#"
headers:
  Host: cdn.example.com
  X-Test: ok
"#,
        )
        .unwrap();
        let headers = headers_from_mapping_without(Some(&options), &["host"]);
        assert_eq!(headers, vec![("X-Test".to_owned(), "ok".to_owned())]);
    }
}
