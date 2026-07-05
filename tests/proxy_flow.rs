use std::{io, net::SocketAddr, time::Duration};

use rotator_proxy::{HostPort, ProxyNode, ProxyPool, outbound::Connector, server::run_listener};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

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

async fn read_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
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
