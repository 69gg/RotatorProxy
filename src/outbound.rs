use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use meow_common::{ConnType, Metadata, Network};
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
use tracing::{debug, warn};

use crate::proxy::{Credentials, HostPort, ProxyChoice, ProxyNode, ProxyPool, TargetAddr};

const HTTP_CONNECT_RESPONSE_LIMIT: usize = 16 * 1024;

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
        let candidates = self.pool.candidates();
        let mut last_error = None;

        for choice in candidates {
            let label = choice.label();
            let attempt = timeout(self.connect_timeout, self.connect_once(&choice, target)).await;
            match attempt {
                Ok(Ok(stream)) => {
                    self.pool.report_success(&choice);
                    debug!("connected to {target} via {label}");
                    return Ok(stream);
                }
                Ok(Err(err)) => {
                    warn!("failed to connect to {target} via {label}: {err}");
                    self.pool.report_failure(&choice);
                    last_error = Some(err);
                }
                Err(_) => {
                    let err = io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect timeout after {:?}", self.connect_timeout),
                    );
                    warn!("failed to connect to {target} via {label}: {err}");
                    self.pool.report_failure(&choice);
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| io::Error::other("no outbound route available")))
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
            format!("connect timeout after {connect_timeout:?}"),
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
                .map_err(|err| io::Error::other(format!("meow proxy dial failed: {err}")))?;
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
    let stream = TcpStream::connect((target.host.as_str(), target.port)).await?;
    Ok(Box::new(stream))
}

async fn connect_proxy_tcp(addr: &HostPort) -> io::Result<TcpStream> {
    TcpStream::connect((addr.host.as_str(), addr.port)).await
}

async fn connect_http_proxy(
    addr: &HostPort,
    auth: Option<&Credentials>,
    target: &TargetAddr,
) -> io::Result<BoxedStream> {
    let mut stream = connect_proxy_tcp(addr).await?;
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
    Ok(Box::new(stream))
}

async fn read_http_header(stream: &mut TcpStream, limit: usize) -> io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < limit {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP header finished",
            ));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP header exceeded limit",
    ))
}

fn validate_http_connect_response(response: &[u8]) -> io::Result<()> {
    let text = String::from_utf8_lossy(response);
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP response"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
    let status: u16 = status
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    if !version.starts_with("HTTP/") || !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "HTTP proxy CONNECT failed: {status_line}"
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
            "invalid SOCKS5 auth response version",
        ));
    }

    match response[1] {
        0x00 => Ok(()),
        0x02 => {
            let auth =
                auth.ok_or_else(|| io::Error::other("SOCKS5 proxy requires authentication"))?;
            send_socks5_password_auth(stream, auth).await
        }
        0xff => Err(io::Error::other(
            "SOCKS5 proxy rejected authentication methods",
        )),
        method => Err(io::Error::other(format!(
            "unsupported SOCKS5 auth method {method:#x}"
        ))),
    }
}

async fn send_socks5_password_auth(stream: &mut TcpStream, auth: &Credentials) -> io::Result<()> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_deref().unwrap_or("").as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 username/password is too long",
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
        return Err(io::Error::other(
            "SOCKS5 username/password authentication failed",
        ));
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
            "SOCKS5 domain name is too long",
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
    let addr = addrs.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "DNS lookup returned no addresses")
    })?;
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
            "invalid SOCKS5 connect response version",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 connect failed with reply {:#x}",
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
                format!("unsupported SOCKS5 response address type {atyp:#x}"),
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
            "SOCKS4 connect failed with reply {}",
            response[1]
        )));
    }
    Ok(Box::new(stream))
}

async fn resolve_ipv4(target: &TargetAddr) -> io::Result<Ipv4Addr> {
    if let Ok(IpAddr::V4(ip)) = target.host.parse::<IpAddr>() {
        return Ok(ip);
    }
    if target.host.parse::<IpAddr>().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS4 does not support IPv6 targets",
        ));
    }

    let mut addrs = lookup_host((target.host.as_str(), target.port)).await?;
    addrs
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "DNS lookup returned no IPv4 address",
            )
        })
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
