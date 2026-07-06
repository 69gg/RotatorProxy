use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use meow_common::{ConnType, Metadata, Network};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use shadowsocks::{
    ProxyClientStream,
    config::ServerType,
    context::{Context, SharedContext},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::proxy::{Credentials, HostPort, ProxyChoice, ProxyNode, ProxyPool, TargetAddr};

const HTTP_CONNECT_RESPONSE_LIMIT: usize = 16 * 1024;
static HTTPS_PROXY_TLS: OnceLock<TlsConnector> = OnceLock::new();
static INSECURE_HTTPS_PROXY_TLS: OnceLock<TlsConnector> = OnceLock::new();

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedStream = Box<dyn AsyncStream>;

pub struct Connector {
    pool: ProxyPool,
    connect_timeout: Duration,
    ss_context: SharedContext,
}

impl Connector {
    pub fn new(pool: ProxyPool, connect_timeout: Duration) -> Self {
        Self {
            pool,
            connect_timeout,
            ss_context: Context::new_shared(ServerType::Local),
        }
    }

    pub fn proxy_count(&self) -> usize {
        self.pool.len()
    }

    pub async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut attempts = self.pool.attempts();
        let mut last_error = None;
        let mut attempt_no = 0_usize;

        for choice in &mut attempts {
            attempt_no += 1;
            let label = choice.label();
            let kind = choice.kind();
            let upstream = choice.upstream_addr(target);
            let started_at = Instant::now();
            debug!(
                attempt = attempt_no,
                node = %label,
                kind,
                upstream = %upstream,
                target = %target,
                timeout_ms = self.connect_timeout.as_millis(),
                "开始出站连接尝试"
            );
            let attempt = timeout(self.connect_timeout, self.connect_once(&choice, target)).await;
            match attempt {
                Ok(Ok(stream)) => {
                    let elapsed_ms = started_at.elapsed().as_millis();
                    self.pool.report_success(&choice);
                    debug!(
                        attempt = attempt_no,
                        node = %label,
                        kind,
                        upstream = %upstream,
                        target = %target,
                        elapsed_ms,
                        "出站连接尝试成功"
                    );
                    return Ok(stream);
                }
                Ok(Err(err)) => {
                    let elapsed_ms = started_at.elapsed().as_millis();
                    warn!(
                        attempt = attempt_no,
                        node = %label,
                        kind,
                        upstream = %upstream,
                        target = %target,
                        elapsed_ms,
                        error_kind = ?err.kind(),
                        error = %err,
                        "出站连接尝试失败"
                    );
                    self.pool.report_failure(&choice);
                    last_error = Some(err);
                }
                Err(_) => {
                    let err = io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("连接超时，耗时 {:?}", self.connect_timeout),
                    );
                    warn!(
                        attempt = attempt_no,
                        node = %label,
                        kind,
                        upstream = %upstream,
                        target = %target,
                        timeout_ms = self.connect_timeout.as_millis(),
                        error_kind = ?err.kind(),
                        error = %err,
                        "出站连接尝试超时"
                    );
                    self.pool.report_failure(&choice);
                    last_error = Some(err);
                }
            }
        }

        let err = last_error.unwrap_or_else(|| io::Error::other("没有可用出站路由"));
        warn!(
            target = %target,
            attempts = attempt_no,
            error_kind = ?err.kind(),
            error = %err,
            "本次出站连接已耗尽可用候选"
        );
        Err(err)
    }

    async fn connect_once(
        &self,
        choice: &ProxyChoice,
        target: &TargetAddr,
    ) -> io::Result<BoxedStream> {
        match choice {
            ProxyChoice::Direct => connect_direct(target).await,
            ProxyChoice::Proxy(entry) => {
                connect_proxy_node(&self.ss_context, entry.node.as_ref(), target).await
            }
        }
    }
}

pub async fn connect_via_proxy_node(
    proxy: &ProxyNode,
    target: &TargetAddr,
    connect_timeout: Duration,
) -> io::Result<BoxedStream> {
    let context = Context::new_shared(ServerType::Local);
    match timeout(connect_timeout, connect_proxy_node(&context, proxy, target)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("连接超时，耗时 {connect_timeout:?}"),
        )),
    }
}

async fn connect_proxy_node(
    ss_context: &SharedContext,
    proxy: &ProxyNode,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    match proxy {
        ProxyNode::Http { addr, auth } => connect_http_proxy(addr, auth.as_ref(), target).await,
        ProxyNode::Https {
            addr,
            auth,
            sni,
            skip_cert_verify,
        } => {
            connect_https_proxy(
                addr,
                auth.as_ref(),
                sni.as_deref(),
                *skip_cert_verify,
                target,
            )
            .await
        }
        ProxyNode::Socks5 {
            addr,
            auth,
            remote_dns,
        } => connect_socks5_proxy(addr, auth.as_ref(), *remote_dns, target).await,
        ProxyNode::Socks4 {
            addr,
            auth,
            remote_dns,
        } => connect_socks4_proxy(addr, auth.as_ref(), *remote_dns, target).await,
        ProxyNode::Shadowsocks { server, .. } => {
            let stream = ProxyClientStream::connect(
                ss_context.clone(),
                server.as_ref(),
                target.to_shadow_address(),
            )
            .await?;
            Ok(Box::new(stream))
        }
        ProxyNode::LocalMihomo { addr, .. } => connect_http_proxy(addr, None, target).await,
        ProxyNode::Meow(node) => {
            let metadata = metadata_from_target(target);
            let stream = node
                .adapter
                .dial_tcp(&metadata)
                .await
                .map_err(|err| io::Error::other(format!("meow 代理拨号失败：{err}")))?;
            Ok(Box::new(stream))
        }
    }
}

fn metadata_from_target(target: &TargetAddr) -> Metadata {
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_port: target.port,
        ..Metadata::default()
    };
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        metadata.dst_ip = Some(ip);
    } else {
        metadata.host = Metadata::lower_host(&target.host);
    }
    metadata
}

async fn connect_direct(target: &TargetAddr) -> io::Result<BoxedStream> {
    debug!(target = %target, "正在直连目标地址");
    let stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    Ok(Box::new(stream))
}

async fn connect_proxy_tcp(addr: &HostPort) -> io::Result<TcpStream> {
    debug!(upstream = %addr, "正在直连出站代理第一跳");
    TcpStream::connect((addr.host.as_str(), addr.port)).await
}

async fn connect_http_proxy(
    addr: &HostPort,
    auth: Option<&Credentials>,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    let stream = connect_proxy_tcp(addr).await?;
    connect_http_tunnel(stream, auth, target).await
}

async fn connect_https_proxy(
    addr: &HostPort,
    auth: Option<&Credentials>,
    sni: Option<&str>,
    skip_cert_verify: bool,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    let stream = connect_proxy_tcp(addr).await?;
    let connector = https_proxy_tls_connector(skip_cert_verify)?;
    let server_name =
        ServerName::try_from(sni.unwrap_or(&addr.host).to_owned()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("HTTPS 代理 TLS server name/SNI 无效：{err}"),
            )
        })?;
    let stream = connector.connect(server_name, stream).await?;
    connect_http_tunnel(stream, auth, target).await
}

async fn connect_http_tunnel<S>(
    mut stream: S,
    auth: Option<&Credentials>,
    target: &TargetAddr,
) -> io::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(target = %target, auth = auth.is_some(), "正在发送 HTTP CONNECT 握手");
    let mut request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n");
    if let Some(auth) = auth {
        let password = auth.password.as_deref().unwrap_or("");
        let token = BASE64_STANDARD.encode(format!("{}:{password}", auth.username));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    let response = read_http_header(&mut stream, HTTP_CONNECT_RESPONSE_LIMIT).await?;
    validate_http_connect_response(&response)?;
    debug!(target = %target, "HTTP CONNECT 握手成功");
    Ok(Box::new(stream))
}

#[derive(Debug)]
struct InsecureHttpsProxyCertVerifier;

impl ServerCertVerifier for InsecureHttpsProxyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn https_proxy_tls_connector(skip_cert_verify: bool) -> io::Result<TlsConnector> {
    let cell = if skip_cert_verify {
        &INSECURE_HTTPS_PROXY_TLS
    } else {
        &HTTPS_PROXY_TLS
    };
    if let Some(connector) = cell.get() {
        return Ok(connector.clone());
    }

    let connector = build_https_proxy_tls_connector(skip_cert_verify)?;
    let _ = cell.set(connector);
    Ok(cell
        .get()
        .expect("HTTPS proxy TLS connector should be initialized")
        .clone())
}

fn build_https_proxy_tls_connector(skip_cert_verify: bool) -> io::Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let wants_verifier = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| io::Error::other(format!("rustls 协议初始化失败：{err}")))?;

    let builder = if skip_cert_verify {
        wants_verifier
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureHttpsProxyCertVerifier))
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        wants_verifier.with_root_certificates(root_store)
    };

    Ok(TlsConnector::from(Arc::new(builder.with_no_client_auth())))
}

async fn read_http_header<S>(stream: &mut S, limit: usize) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < limit {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "连接在 HTTP 头读取完成前关闭",
            ));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP 头超过大小限制",
    ))
}

fn validate_http_connect_response(response: &[u8]) -> io::Result<()> {
    let text = String::from_utf8_lossy(response);
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP 响应为空"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP 响应缺少状态码"))?;
    let status: u16 = status
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP 状态码无效"))?;
    if !version.starts_with("HTTP/") || !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "HTTP 代理 CONNECT 失败：{status_line}"
        )));
    }
    Ok(())
}

async fn connect_socks5_proxy(
    addr: &HostPort,
    auth: Option<&Credentials>,
    remote_dns: bool,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    let mut stream = connect_proxy_tcp(addr).await?;
    debug!(
        upstream = %addr,
        target = %target,
        remote_dns,
        auth = auth.is_some(),
        "正在执行 SOCKS5 握手"
    );
    socks5_authenticate(&mut stream, auth).await?;
    let target_addr = if remote_dns {
        encode_socks5_domain_or_ip(target)?
    } else {
        encode_socks5_resolved(target).await?
    };

    let mut request = Vec::with_capacity(4 + target_addr.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    request.extend_from_slice(&target_addr);
    stream.write_all(&request).await?;
    read_socks5_connect_response(&mut stream).await?;
    debug!(upstream = %addr, target = %target, "SOCKS5 CONNECT 成功");
    Ok(Box::new(stream))
}

async fn socks5_authenticate(stream: &mut TcpStream, auth: Option<&Credentials>) -> io::Result<()> {
    match auth {
        Some(_) => stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?,
        None => stream.write_all(&[0x05, 0x01, 0x00]).await?,
    }

    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 认证响应版本无效",
        ));
    }

    match response[1] {
        0x00 => Ok(()),
        0x02 => {
            let auth = auth.ok_or_else(|| io::Error::other("SOCKS5 代理要求认证"))?;
            send_socks5_password_auth(stream, auth).await
        }
        0xff => Err(io::Error::other("SOCKS5 代理拒绝认证方法")),
        method => Err(io::Error::other(format!(
            "不支持的 SOCKS5 认证方法 {method:#x}"
        ))),
    }
}

async fn send_socks5_password_auth(stream: &mut TcpStream, auth: &Credentials) -> io::Result<()> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_deref().unwrap_or("").as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 用户名或密码过长",
        ));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(io::Error::other("SOCKS5 用户名/密码认证失败"));
    }
    Ok(())
}

fn encode_socks5_domain_or_ip(target: &TargetAddr) -> io::Result<Vec<u8>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(encode_socks5_ip(ip, target.port));
    }

    let host = target.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 域名过长",
        ));
    }
    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    out.push(0x03);
    out.push(host.len() as u8);
    out.extend_from_slice(host);
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

async fn encode_socks5_resolved(target: &TargetAddr) -> io::Result<Vec<u8>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(encode_socks5_ip(ip, target.port));
    }

    let mut addrs = lookup_host((target.host.as_str(), target.port)).await?;
    let addr = addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS 查询未返回地址"))?;
    Ok(encode_socks5_ip(addr.ip(), target.port))
}

fn encode_socks5_ip(ip: IpAddr, port: u16) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let mut out = Vec::with_capacity(7);
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
            out
        }
        IpAddr::V6(ip) => {
            let mut out = Vec::with_capacity(19);
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
            out
        }
    }
}

async fn read_socks5_connect_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 连接响应版本无效",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 连接失败，响应码 {:#x}",
            head[1]
        )));
    }

    match head[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("不支持的 SOCKS5 响应地址类型 {atyp:#x}"),
            ));
        }
    }
    Ok(())
}

async fn connect_socks4_proxy(
    addr: &HostPort,
    auth: Option<&Credentials>,
    remote_dns: bool,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    let mut stream = connect_proxy_tcp(addr).await?;
    debug!(
        upstream = %addr,
        target = %target,
        remote_dns,
        auth = auth.is_some(),
        "正在执行 SOCKS4 握手"
    );
    let ip = if remote_dns {
        Ipv4Addr::new(0, 0, 0, 1)
    } else {
        resolve_ipv4(target).await?
    };

    let user = auth
        .map(|auth| auth.username.as_bytes())
        .unwrap_or_default();
    let mut request = Vec::with_capacity(9 + user.len() + target.host.len());
    request.extend_from_slice(&[0x04, 0x01]);
    request.extend_from_slice(&target.port.to_be_bytes());
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(user);
    request.push(0x00);
    if remote_dns {
        request.extend_from_slice(target.host.as_bytes());
        request.push(0x00);
    }
    stream.write_all(&request).await?;

    let mut response = [0_u8; 8];
    stream.read_exact(&mut response).await?;
    if response[1] != 90 {
        return Err(io::Error::other(format!(
            "SOCKS4 连接失败，响应码 {}",
            response[1]
        )));
    }
    debug!(upstream = %addr, target = %target, "SOCKS4 CONNECT 成功");
    Ok(Box::new(stream))
}

async fn resolve_ipv4(target: &TargetAddr) -> io::Result<Ipv4Addr> {
    if let Ok(IpAddr::V4(ip)) = target.host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if target.host.parse::<IpAddr>().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS4 不支持 IPv6 目标",
        ));
    }

    let mut addrs = lookup_host((target.host.as_str(), target.port)).await?;
    addrs
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS 查询未返回 IPv4 地址"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_socks5_domain_address() {
        let target = TargetAddr::new("example.com", 443).unwrap();
        let encoded = encode_socks5_domain_or_ip(&target).unwrap();
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], "example.com".len() as u8);
        assert!(encoded.ends_with(&443_u16.to_be_bytes()));
    }

    #[test]
    fn validates_http_connect_success() {
        validate_http_connect_response(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
    }

    #[test]
    fn rejects_http_connect_failure() {
        assert!(
            validate_http_connect_response(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n").is_err()
        );
    }
}
