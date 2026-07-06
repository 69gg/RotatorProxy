use std::{fs, io, net::SocketAddr, sync::Arc, time::Duration};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rotator_proxy::{
    AppConfig, HostPort, MihomoManager, ProxyNode, ProxyPool, health::refresh_proxy_pool,
    outbound::Connector, server::run_listener,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;

fn direct_connector() -> Connector {
    Connector::new(ProxyPool::new(Vec::new(), 10), Duration::from_secs(2))
}

async fn spawn_rotator(
    connector: Connector,
) -> io::Result<(SocketAddr, JoinHandle<io::Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(run_listener(listener, connector));
    Ok((addr, handle))
}

async fn spawn_echo_server() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    Ok((addr, handle))
}

async fn spawn_http_target() -> io::Result<(SocketAddr, oneshot::Receiver<String>, JoinHandle<()>)>
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(header) = read_header(&mut stream).await else {
            return;
        };
        let first_line = String::from_utf8_lossy(&header)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        let _ = tx.send(first_line);
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    });
    Ok((addr, rx, handle))
}

async fn spawn_http_connect_proxy() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(header) = read_header(&mut inbound).await else {
                    return;
                };
                let header = String::from_utf8_lossy(&header);
                let Some(target) = header
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                else {
                    return;
                };
                let Ok(mut outbound) = TcpStream::connect(target).await else {
                    let _ = inbound
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                };
                if inbound
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((addr, handle))
}

async fn spawn_https_connect_proxy() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], private_key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut inbound) = acceptor.accept(inbound).await else {
                    return;
                };
                let Ok(header) = read_header(&mut inbound).await else {
                    return;
                };
                let header = String::from_utf8_lossy(&header);
                let Some(target) = header
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                else {
                    return;
                };
                let Ok(mut outbound) = TcpStream::connect(target).await else {
                    let _ = inbound
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                };
                if inbound
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    let _ = copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((addr, handle))
}

async fn spawn_stalling_http_connect_proxy() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                if read_header(&mut inbound).await.is_err() {
                    return;
                }
                if inbound
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_ok()
                {
                    sleep(Duration::from_secs(5)).await;
                }
            });
        }
    });
    Ok((addr, handle))
}

async fn spawn_https_target() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], private_key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                if read_header(&mut stream).await.is_ok() {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                }
            });
        }
    });
    Ok((addr, handle))
}

async fn read_header<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(buffer);
        }
        if buffer.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
}

async fn unused_local_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn labels_from_pool(pool: &ProxyPool) -> Vec<String> {
    pool.candidates()
        .into_iter()
        .map(|choice| choice.label())
        .collect()
}

#[tokio::test]
async fn forwards_absolute_form_http_request_directly() -> io::Result<()> {
    let (target_addr, first_line_rx, _target_handle) = spawn_http_target().await?;
    let (proxy_addr, proxy_handle) = spawn_rotator(direct_connector()).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    let request = format!(
        "GET http://{target_addr}/hello?x=1 HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert_eq!(first_line_rx.await.unwrap(), "GET /hello?x=1 HTTP/1.1");

    proxy_handle.abort();
    Ok(())
}

#[tokio::test]
async fn forwards_http_connect_directly() -> io::Result<()> {
    let (target_addr, _target_handle) = spawn_echo_server().await?;
    let (proxy_addr, proxy_handle) = spawn_rotator(direct_connector()).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    let request = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await?;
    let response = read_header(&mut client).await?;
    assert!(String::from_utf8_lossy(&response).contains("200 Connection Established"));

    client.write_all(b"ping").await?;
    let mut echoed = [0_u8; 4];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping");

    proxy_handle.abort();
    Ok(())
}

#[tokio::test]
async fn forwards_socks5_connect_directly() -> io::Result<()> {
    let (target_addr, _target_handle) = spawn_echo_server().await?;
    let (proxy_addr, proxy_handle) = spawn_rotator(direct_connector()).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth = [0_u8; 2];
    client.read_exact(&mut auth).await?;
    assert_eq!(auth, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(
        &target_addr
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    client.write_all(&request).await?;

    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0x00);

    client.write_all(b"pong").await?;
    let mut echoed = [0_u8; 4];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"pong");

    proxy_handle.abort();
    Ok(())
}

#[tokio::test]
async fn retries_next_proxy_when_first_proxy_fails() -> io::Result<()> {
    let bad_port = unused_local_port().await?;
    let (target_addr, _target_handle) = spawn_echo_server().await?;
    let (good_proxy_addr, _good_proxy_handle) = spawn_http_connect_proxy().await?;

    let proxies = vec![
        ProxyNode::Http {
            addr: HostPort::new("127.0.0.1", bad_port).unwrap(),
            auth: None,
        },
        ProxyNode::Http {
            addr: HostPort::new("127.0.0.1", good_proxy_addr.port()).unwrap(),
            auth: None,
        },
    ];
    let connector = Connector::new(ProxyPool::new(proxies, 2), Duration::from_millis(500));
    let (proxy_addr, proxy_handle) = spawn_rotator(connector).await?;

    let mut client = TcpStream::connect(proxy_addr).await?;
    let request = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await?;
    let response = read_header(&mut client).await?;
    assert!(String::from_utf8_lossy(&response).contains("200 Connection Established"));

    client.write_all(b"next").await?;
    let mut echoed = [0_u8; 4];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"next");

    proxy_handle.abort();
    Ok(())
}

#[tokio::test]
async fn health_refresh_filters_failed_proxy_and_swaps_pool() -> io::Result<()> {
    let bad_port = unused_local_port().await?;
    let (target_addr, _first_line_rx, _target_handle) = spawn_http_target().await?;
    let (good_proxy_addr, _good_proxy_handle) = spawn_http_connect_proxy().await?;

    let dir = tempfile::tempdir().unwrap();
    let proxy_file = dir.path().join("proxies.txt");
    fs::write(
        &proxy_file,
        format!(
            "http://127.0.0.1:{bad_port}\nhttp://127.0.0.1:{}\n",
            good_proxy_addr.port()
        ),
    )
    .unwrap();

    let config = AppConfig {
        proxy_dirs: vec![dir.path().to_path_buf()],
        health_check_url: format!("http://{target_addr}/health"),
        health_check_expected_status: "200-399".to_owned(),
        health_check_attempts: 1,
        health_check_timeout_ms: 500,
        health_check_concurrency: 2,
        mihomo_enabled: false,
        ..AppConfig::default()
    };
    let pool = ProxyPool::with_runtime_options(Vec::new(), 2, 3, Duration::from_secs(60));
    let mihomo = MihomoManager::new();
    let summary = refresh_proxy_pool(&config, &pool, &mihomo, "test")
        .await
        .unwrap();

    assert_eq!(summary.loaded, 2);
    assert_eq!(summary.active, 1);
    assert_eq!(
        labels_from_pool(&pool),
        vec![format!("http://127.0.0.1:{}", good_proxy_addr.port())]
    );
    Ok(())
}

#[tokio::test]
async fn health_check_timeout_covers_stalled_response() -> io::Result<()> {
    let (target_addr, _first_line_rx, _target_handle) = spawn_http_target().await?;
    let (proxy_addr, _proxy_handle) = spawn_stalling_http_connect_proxy().await?;

    let dir = tempfile::tempdir().unwrap();
    let proxy_file = dir.path().join("proxies.txt");
    fs::write(
        &proxy_file,
        format!("http://127.0.0.1:{}\n", proxy_addr.port()),
    )
    .unwrap();

    let config = AppConfig {
        proxy_dirs: vec![dir.path().to_path_buf()],
        health_check_url: format!("http://{target_addr}/health"),
        health_check_expected_status: "200-399".to_owned(),
        health_check_attempts: 1,
        health_check_timeout_ms: 100,
        health_check_concurrency: 1,
        mihomo_enabled: false,
        ..AppConfig::default()
    };
    let pool = ProxyPool::with_runtime_options(Vec::new(), 2, 3, Duration::from_secs(60));
    let mihomo = MihomoManager::new();

    let summary = timeout(
        Duration::from_secs(2),
        refresh_proxy_pool(&config, &pool, &mihomo, "test"),
    )
    .await
    .expect("health refresh should not hang on stalled response")
    .unwrap();

    assert_eq!(summary.loaded, 1);
    assert_eq!(summary.active, 0);
    Ok(())
}

#[tokio::test]
async fn scheduled_refresh_keeps_previous_pool_when_all_new_nodes_fail() -> io::Result<()> {
    let bad_port = unused_local_port().await?;

    let dir = tempfile::tempdir().unwrap();
    let proxy_file = dir.path().join("proxies.txt");
    fs::write(&proxy_file, format!("http://127.0.0.1:{bad_port}\n")).unwrap();

    let previous = ProxyNode::Http {
        addr: HostPort::new("127.0.0.1", 19090).unwrap(),
        auth: None,
    };
    let config = AppConfig {
        proxy_dirs: vec![dir.path().to_path_buf()],
        health_check_url: "http://127.0.0.1:9/health".to_owned(),
        health_check_attempts: 1,
        health_check_timeout_ms: 100,
        health_check_concurrency: 1,
        mihomo_enabled: false,
        ..AppConfig::default()
    };
    let pool = ProxyPool::with_runtime_options(vec![previous], 2, 3, Duration::from_secs(60));
    let mihomo = MihomoManager::new();

    let summary = refresh_proxy_pool(&config, &pool, &mihomo, "scheduled")
        .await
        .unwrap();

    assert_eq!(summary.loaded, 1);
    assert_eq!(summary.active, 1);
    assert_eq!(labels_from_pool(&pool), vec!["http://127.0.0.1:19090"]);
    Ok(())
}

#[tokio::test]
async fn health_refresh_accepts_https_proxy() -> io::Result<()> {
    let (target_addr, _first_line_rx, _target_handle) = spawn_http_target().await?;
    let (proxy_addr, _proxy_handle) = spawn_https_connect_proxy().await?;

    let dir = tempfile::tempdir().unwrap();
    let proxy_file = dir.path().join("proxies.txt");
    fs::write(
        &proxy_file,
        format!(
            "https://127.0.0.1:{}?allowInsecure=1#local\n",
            proxy_addr.port()
        ),
    )
    .unwrap();

    let config = AppConfig {
        proxy_dirs: vec![dir.path().to_path_buf()],
        health_check_url: format!("http://{target_addr}/health"),
        health_check_expected_status: "200-399".to_owned(),
        health_check_attempts: 1,
        health_check_timeout_ms: 1000,
        health_check_concurrency: 1,
        mihomo_enabled: false,
        ..AppConfig::default()
    };
    let pool = ProxyPool::with_runtime_options(Vec::new(), 2, 3, Duration::from_secs(60));
    let mihomo = MihomoManager::new();

    let summary = refresh_proxy_pool(&config, &pool, &mihomo, "test")
        .await
        .unwrap();

    assert_eq!(summary.loaded, 1);
    assert_eq!(summary.active, 1);
    assert_eq!(
        labels_from_pool(&pool),
        vec![format!("https://127.0.0.1:{}", proxy_addr.port())]
    );
    Ok(())
}

#[tokio::test]
async fn https_health_check_can_skip_certificate_verification() -> io::Result<()> {
    let (target_addr, _target_handle) = spawn_https_target().await?;
    let (proxy_addr, _proxy_handle) = spawn_http_connect_proxy().await?;

    let dir = tempfile::tempdir().unwrap();
    let proxy_file = dir.path().join("proxies.txt");
    fs::write(
        &proxy_file,
        format!("http://127.0.0.1:{}\n", proxy_addr.port()),
    )
    .unwrap();

    let strict_config = AppConfig {
        proxy_dirs: vec![dir.path().to_path_buf()],
        health_check_url: format!("https://localhost:{}/health", target_addr.port()),
        health_check_attempts: 1,
        health_check_timeout_ms: 1000,
        health_check_concurrency: 1,
        mihomo_enabled: false,
        ..AppConfig::default()
    };
    let pool = ProxyPool::with_runtime_options(Vec::new(), 2, 3, Duration::from_secs(60));
    let mihomo = MihomoManager::new();
    let strict_summary = refresh_proxy_pool(&strict_config, &pool, &mihomo, "test")
        .await
        .unwrap();
    assert_eq!(strict_summary.active, 0);

    let skip_config = AppConfig {
        health_check_tls_skip_verify: true,
        ..strict_config
    };
    let skip_summary = refresh_proxy_pool(&skip_config, &pool, &mihomo, "test")
        .await
        .unwrap();
    assert_eq!(skip_summary.active, 1);
    assert_eq!(
        labels_from_pool(&pool),
        vec![format!("http://127.0.0.1:{}", proxy_addr.port())]
    );
    Ok(())
}
