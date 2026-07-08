use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
};
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, Runtime, SendStream, TransportConfig, VarInt,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    sync::Mutex,
    time::timeout,
};

const PROTOCOL_VERSION: u8 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 8_388_608;
const DEFAULT_CONN_RECEIVE_WINDOW: u32 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;
const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(10);
const XPLUS_SALT_LEN: usize = 16;

pub struct HysteriaAdapter {
    name: String,
    addr: String,
    options: Arc<HysteriaOptions>,
    conn: Mutex<Option<Arc<HysteriaConnection>>>,
    health: ProxyHealth,
}

#[derive(Debug, Clone)]
pub struct HysteriaOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub auth: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: String,
    pub skip_cert_verify: bool,
    pub up_bps: u64,
    pub down_bps: u64,
    pub obfs_password: Option<String>,
    pub fast_open: bool,
}

impl HysteriaAdapter {
    pub fn new(options: HysteriaOptions) -> meow_common::Result<Self> {
        if options.auth.is_empty() {
            return Err(MeowError::Proxy(format!(
                "hysteria[{}]: auth must not be empty",
                options.name
            )));
        }
        if options.port == 0 {
            return Err(MeowError::Proxy(format!(
                "hysteria[{}]: port must be non-zero",
                options.name
            )));
        }
        let addr = format!("{}:{}", options.server, options.port);
        Ok(Self {
            name: options.name.clone(),
            addr,
            options: Arc::new(options),
            conn: Mutex::new(None),
            health: ProxyHealth::new(),
        })
    }

    async fn connection(&self) -> meow_common::Result<Arc<HysteriaConnection>> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.is_active()
        {
            return Ok(Arc::clone(conn));
        }

        let conn = Arc::new(connect_hysteria(Arc::clone(&self.options)).await?);
        *guard = Some(Arc::clone(&conn));
        Ok(conn)
    }
}

#[async_trait]
impl ProxyAdapter for HysteriaAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Hysteria2
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> meow_common::Result<Box<dyn ProxyConn>> {
        let target = target_from_metadata(metadata)?;
        let client = self.connection().await?;
        let (mut send, mut recv) = client
            .connection
            .open_bi()
            .await
            .map_err(|err| MeowError::Proxy(format!("hysteria open stream: {err}")))?;
        let request = encode_client_request(&target)?;
        send.write_all(&request)
            .await
            .map_err(|err| MeowError::Proxy(format!("hysteria write request: {err}")))?;
        if !self.options.fast_open {
            read_server_response(&mut recv).await?;
        }
        Ok(Box::new(HysteriaConn::new(send, recv, target)))
    }

    async fn dial_udp(
        &self,
        _metadata: &Metadata,
    ) -> meow_common::Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "Hysteria v1 UDP associate is not supported by RotatorProxy".to_owned(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

struct HysteriaConnection {
    connection: Connection,
    _endpoint: Endpoint,
}

impl HysteriaConnection {
    fn is_active(&self) -> bool {
        self.connection.close_reason().is_none()
    }
}

async fn connect_hysteria(
    options: Arc<HysteriaOptions>,
) -> meow_common::Result<HysteriaConnection> {
    let addrs = meow_common::resolve_host_all(&options.server, options.port)
        .await
        .map_err(MeowError::Io)?;
    let server_name = options
        .sni
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&options.server)
        .to_owned();

    let mut last_error = None;
    for addr in addrs {
        match connect_addr(Arc::clone(&options), addr, &server_name).await {
            Ok(conn) => return Ok(conn),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| MeowError::Proxy("hysteria resolve returned no addresses".to_owned())))
}

async fn connect_addr(
    options: Arc<HysteriaOptions>,
    server_addr: SocketAddr,
    server_name: &str,
) -> meow_common::Result<HysteriaConnection> {
    let mut endpoint = build_endpoint(server_addr, options.obfs_password.as_deref())?;
    endpoint.set_default_client_config(build_client_config(&options)?);
    let connecting = endpoint
        .connect(server_addr, server_name)
        .map_err(|err| MeowError::Proxy(format!("hysteria connect start: {err}")))?;
    let connection = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            MeowError::Proxy(format!(
                "hysteria connect timeout after {CONNECT_TIMEOUT:?}"
            ))
        })?
        .map_err(|err| MeowError::Proxy(format!("hysteria connect: {err}")))?;

    let mut stream = timeout(CONNECT_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| MeowError::Proxy("hysteria control stream timeout".to_owned()))?
        .map_err(|err| MeowError::Proxy(format!("hysteria control stream: {err}")))?;
    authenticate(&options, &mut stream.0, &mut stream.1).await?;

    Ok(HysteriaConnection {
        connection,
        _endpoint: endpoint,
    })
}

fn build_endpoint(
    server_addr: SocketAddr,
    obfs_password: Option<&str>,
) -> meow_common::Result<Endpoint> {
    let bind_addr = if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let std_sock = std::net::UdpSocket::bind(bind_addr).map_err(MeowError::Io)?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let socket = runtime.wrap_udp_socket(std_sock).map_err(MeowError::Io)?;
    let socket: Arc<dyn quinn::AsyncUdpSocket> = match obfs_password {
        Some(password) if !password.is_empty() => {
            Arc::new(XPlusUdpSocket::new(socket, password.as_bytes().to_vec()))
        }
        _ => socket,
    };
    let mut endpoint_cfg = quinn::EndpointConfig::default();
    endpoint_cfg.grease_quic_bit(false);
    Endpoint::new_with_abstract_socket(endpoint_cfg, None, socket, runtime).map_err(MeowError::Io)
}

fn build_client_config(options: &HysteriaOptions) -> meow_common::Result<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = rustls::ClientConfig::builder();
    let mut tls_config = if options.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth()
    };
    tls_config.alpn_protocols = vec![options.alpn.as_bytes().to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .map_err(|err| MeowError::Proxy(format!("hysteria tls config: {err}")))?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        DEFAULT_MAX_IDLE_TIMEOUT
            .try_into()
            .map_err(|err| MeowError::Proxy(format!("hysteria quic idle timeout: {err}")))?,
    ));
    transport.stream_receive_window(VarInt::from_u32(DEFAULT_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(DEFAULT_CONN_RECEIVE_WINDOW));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    transport.max_concurrent_uni_streams(VarInt::from_u32(1024));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

async fn authenticate(
    options: &HysteriaOptions,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> meow_common::Result<()> {
    send.write_all(&[PROTOCOL_VERSION])
        .await
        .map_err(|err| MeowError::Proxy(format!("hysteria write protocol version: {err}")))?;
    send.write_all(&encode_client_hello(
        options.up_bps,
        options.down_bps,
        &options.auth,
    )?)
    .await
    .map_err(|err| MeowError::Proxy(format!("hysteria write client hello: {err}")))?;
    let response = read_server_hello(recv).await?;
    if !response.ok {
        return Err(MeowError::Proxy(format!(
            "hysteria auth rejected: {}",
            response.message
        )));
    }
    Ok(())
}

fn target_from_metadata(metadata: &Metadata) -> meow_common::Result<String> {
    if metadata.dst_port == 0 {
        return Err(MeowError::Proxy(
            "hysteria: metadata has no destination port".into(),
        ));
    }
    if !metadata.host.is_empty() {
        if let Ok(ip) = metadata.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, metadata.dst_port).to_string());
        }
        return Ok(format!("{}:{}", metadata.host, metadata.dst_port));
    }
    if let Some(ip) = metadata.dst_ip {
        return Ok(SocketAddr::new(ip, metadata.dst_port).to_string());
    }
    Err(MeowError::Proxy(
        "hysteria: metadata has no destination".into(),
    ))
}

fn encode_client_hello(send_bps: u64, recv_bps: u64, auth: &[u8]) -> meow_common::Result<Vec<u8>> {
    let auth_len: u16 = auth
        .len()
        .try_into()
        .map_err(|_| MeowError::Proxy("hysteria auth is too long".to_owned()))?;
    let mut out = Vec::with_capacity(18 + auth.len());
    out.extend_from_slice(&send_bps.to_be_bytes());
    out.extend_from_slice(&recv_bps.to_be_bytes());
    out.extend_from_slice(&auth_len.to_be_bytes());
    out.extend_from_slice(auth);
    Ok(out)
}

fn encode_client_request(target: &str) -> meow_common::Result<Vec<u8>> {
    let (host, port) = split_host_port(target)?;
    let host_len: u16 = host
        .len()
        .try_into()
        .map_err(|_| MeowError::Proxy("hysteria request host is too long".to_owned()))?;
    let mut out = Vec::with_capacity(1 + 2 + host.len() + 2);
    out.push(0);
    out.extend_from_slice(&host_len.to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

fn split_host_port(target: &str) -> meow_common::Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| MeowError::Proxy(format!("hysteria target lacks port: {target}")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port
        .parse::<u16>()
        .map_err(|err| MeowError::Proxy(format!("hysteria target port is invalid: {err}")))?;
    Ok((host.to_owned(), port))
}

struct ServerHello {
    ok: bool,
    message: String,
}

async fn read_server_hello(recv: &mut RecvStream) -> meow_common::Result<ServerHello> {
    let ok = recv.read_u8().await.map_err(MeowError::Io)? != 0;
    let _send_bps = recv.read_u64().await.map_err(MeowError::Io)?;
    let _recv_bps = recv.read_u64().await.map_err(MeowError::Io)?;
    let message_len = recv.read_u16().await.map_err(MeowError::Io)? as usize;
    let mut message = vec![0_u8; message_len];
    if message_len > 0 {
        recv.read_exact(&mut message)
            .await
            .map_err(|err| MeowError::Proxy(format!("hysteria read server hello: {err}")))?;
    }
    Ok(ServerHello {
        ok,
        message: String::from_utf8_lossy(&message).into_owned(),
    })
}

async fn read_server_response(recv: &mut RecvStream) -> meow_common::Result<()> {
    let ok = recv.read_u8().await.map_err(MeowError::Io)? != 0;
    let _udp_session_id = recv.read_u32().await.map_err(MeowError::Io)?;
    let message_len = recv.read_u16().await.map_err(MeowError::Io)? as usize;
    let mut message = vec![0_u8; message_len];
    if message_len > 0 {
        recv.read_exact(&mut message)
            .await
            .map_err(|err| MeowError::Proxy(format!("hysteria read server response: {err}")))?;
    }
    if ok {
        Ok(())
    } else {
        Err(MeowError::Proxy(format!(
            "hysteria connection rejected: {}",
            String::from_utf8_lossy(&message)
        )))
    }
}

struct HysteriaConn {
    target: String,
    send: SendStream,
    recv: RecvStream,
}

impl HysteriaConn {
    fn new(send: SendStream, recv: RecvStream, target: String) -> Self {
        Self { target, send, recv }
    }
}

impl AsyncRead for HysteriaConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().send).poll_write(cx, buf) {
            Poll::Ready(Ok(size)) => Poll::Ready(Ok(size)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().send.finish().map_err(io::Error::from))
    }
}

impl ProxyConn for HysteriaConn {
    fn remote_destination(&self) -> String {
        self.target.clone()
    }
}

#[derive(Debug)]
struct XPlusUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Vec<u8>,
}

impl XPlusUdpSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, key: Vec<u8>) -> Self {
        Self { inner, key }
    }

    fn deobfuscate_packet(&self, bytes: &mut [u8]) -> Option<usize> {
        if bytes.len() <= XPLUS_SALT_LEN {
            return None;
        }
        let key = Sha256::digest([self.key.as_slice(), &bytes[..XPLUS_SALT_LEN]].concat());
        for index in XPLUS_SALT_LEN..bytes.len() {
            bytes[index - XPLUS_SALT_LEN] = bytes[index] ^ key[(index - XPLUS_SALT_LEN) % 32];
        }
        Some(bytes.len() - XPLUS_SALT_LEN)
    }

    fn obfuscate_payload(&self, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.resize(XPLUS_SALT_LEN + payload.len(), 0);
        for byte in &mut out[..XPLUS_SALT_LEN] {
            *byte = rand::random::<u8>();
        }
        let key = Sha256::digest([self.key.as_slice(), &out[..XPLUS_SALT_LEN]].concat());
        for (index, byte) in payload.iter().enumerate() {
            out[XPLUS_SALT_LEN + index] = *byte ^ key[index % 32];
        }
    }
}

impl quinn::AsyncUdpSocket for XPlusUdpSocket {
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            };
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut accepted = 0;
            for index in 0..count {
                let len = meta[index].len;
                if let Some(new_len) = self.deobfuscate_packet(&mut bufs[index][..len]) {
                    meta[accepted] = meta[index];
                    meta[accepted].len = new_len;
                    accepted += 1;
                }
            }
            if accepted > 0 {
                return Poll::Ready(Ok(accepted));
            }
        }
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let mut payload = Vec::with_capacity(XPLUS_SALT_LEN + transmit.contents.len());
        self.obfuscate_payload(transmit.contents, &mut payload);
        let obfuscated = quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &payload,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obfuscated)
    }

    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
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
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_client_hello_like_hysteria_v1() {
        let encoded = encode_client_hello(11, 55, b"pass").unwrap();
        assert_eq!(&encoded[..8], &11_u64.to_be_bytes());
        assert_eq!(&encoded[8..16], &55_u64.to_be_bytes());
        assert_eq!(&encoded[16..18], &4_u16.to_be_bytes());
        assert_eq!(&encoded[18..], b"pass");
    }

    #[test]
    fn encodes_tcp_request_like_hysteria_v1() {
        let encoded = encode_client_request("example.com:443").unwrap();
        assert_eq!(encoded[0], 0);
        assert_eq!(&encoded[1..3], &11_u16.to_be_bytes());
        assert_eq!(&encoded[3..14], b"example.com");
        assert_eq!(&encoded[14..16], &443_u16.to_be_bytes());
    }

    #[tokio::test]
    async fn xplus_obfuscation_round_trips() {
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let inner = XPlusUdpSocket {
            inner: socket,
            key: b"secret".to_vec(),
        };
        let mut obfuscated = Vec::new();
        inner.obfuscate_payload(b"hello", &mut obfuscated);
        let len = inner.deobfuscate_packet(&mut obfuscated).unwrap();
        assert_eq!(&obfuscated[..len], b"hello");
    }
}
