use std::{io, str, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::sleep,
};
use tracing::{debug, info, warn};
use url::Url;

use crate::{outbound::Connector, proxy::TargetAddr, resource::is_file_descriptor_exhaustion};

const HTTP_REQUEST_HEADER_LIMIT: usize = 64 * 1024;
const ACCEPT_ERROR_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(100);
const ACCEPT_ERROR_MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

pub async fn run(listen: &str, connector: Connector) -> io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    run_listener(listener, connector).await
}

pub async fn run_listener(listener: TcpListener, connector: Connector) -> io::Result<()> {
    run_listener_with_limit(listener, connector, Semaphore::MAX_PERMITS).await
}

pub async fn run_listener_with_limit(
    listener: TcpListener,
    connector: Connector,
    max_concurrent_connections: usize,
) -> io::Result<()> {
    if max_concurrent_connections == 0 || max_concurrent_connections > Semaphore::MAX_PERMITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("入站连接并发上限必须在 1..={} 之间", Semaphore::MAX_PERMITS),
        ));
    }
    let local_addr = listener.local_addr()?;
    let connector = Arc::new(connector);
    let connection_limit = Arc::new(Semaphore::new(max_concurrent_connections));
    info!(
        loaded_nodes = connector.proxy_count(),
        max_concurrent_connections, "RotatorProxy 正在监听 {local_addr}"
    );

    let mut retry_delay = ACCEPT_ERROR_INITIAL_RETRY_DELAY;
    loop {
        let permit = Arc::clone(&connection_limit)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("入站连接并发限制器已关闭"))?;
        let (socket, peer) = match listener.accept().await {
            Ok(accepted) => {
                retry_delay = ACCEPT_ERROR_INITIAL_RETRY_DELAY;
                accepted
            }
            Err(err) => {
                warn!(
                    error_kind = ?err.kind(),
                    error = %err,
                    resource_exhausted = is_file_descriptor_exhaustion(&err),
                    retry_ms = retry_delay.as_millis(),
                    "接受客户端连接失败，将在退避后继续监听"
                );
                drop(permit);
                sleep(retry_delay).await;
                retry_delay = next_accept_retry_delay(retry_delay);
                continue;
            }
        };
        let connector = Arc::clone(&connector);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_client(socket, connector).await {
                debug!("客户端 {peer} 处理结束并返回错误：{err}");
            }
        });
    }
}

fn next_accept_retry_delay(current: Duration) -> Duration {
    current.saturating_mul(2).min(ACCEPT_ERROR_MAX_RETRY_DELAY)
}

async fn handle_client(socket: TcpStream, connector: Arc<Connector>) -> io::Result<()> {
    let mut first = [0_u8; 1];
    let n = socket.peek(&mut first).await?;
    if n == 0 {
        return Ok(());
    }

    if first[0] == 0x05 {
        handle_socks5(socket, connector).await
    } else {
        handle_http(socket, connector).await
    }
}

async fn handle_http(mut client: TcpStream, connector: Arc<Connector>) -> io::Result<()> {
    let request = read_http_request(&mut client).await?;
    let parsed = match parse_http_request(&request) {
        Ok(parsed) => parsed,
        Err(err) => {
            write_http_error(&mut client, 400, "Bad Request").await?;
            return Err(err);
        }
    };

    let mut remote = match connector.connect(&parsed.target).await {
        Ok(remote) => remote,
        Err(err) => {
            write_http_error(&mut client, 502, "Bad Gateway").await?;
            return Err(err);
        }
    };

    if parsed.is_connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        remote.as_mut().write_all(&parsed.forward_bytes).await?;
    }

    let (client_to_remote, remote_to_client) =
        copy_bidirectional(&mut client, remote.as_mut()).await?;
    debug!(
        "HTTP 隧道 {} 已关闭：client_to_remote={} remote_to_client={}",
        parsed.target, client_to_remote, remote_to_client
    );
    Ok(())
}

async fn read_http_request(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 1024];

    loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "连接在 HTTP 请求头读取完成前关闭",
            ));
        }
        buffer.extend_from_slice(&chunk[..n]);
        if find_header_end(&buffer).is_some() {
            return Ok(buffer);
        }
        if buffer.len() > HTTP_REQUEST_HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP 请求头超过大小限制",
            ));
        }
    }
}

fn parse_http_request(buffer: &[u8]) -> io::Result<ParsedHttpRequest> {
    let header_end = find_header_end(buffer)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 HTTP 头结束标记"))?;
    let header_bytes = &buffer[..header_end];
    let extra = &buffer[header_end..];
    let header_text = str::from_utf8(header_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP 头不是 UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 HTTP 请求行"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 HTTP method"))?;
    let request_target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 HTTP request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 HTTP version"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let target = TargetAddr::parse(request_target, None)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        return Ok(ParsedHttpRequest {
            target,
            is_connect: true,
            forward_bytes: Vec::new(),
        });
    }

    let headers: Vec<&str> = lines.filter(|line| !line.is_empty()).collect();
    let (target, origin_target) = target_from_http_request_target(request_target, &headers)?;
    let mut forward = Vec::with_capacity(buffer.len());
    forward.extend_from_slice(format!("{method} {origin_target} {version}\r\n").as_bytes());
    for header in headers {
        let lower = header.to_ascii_lowercase();
        if lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authorization:") {
            continue;
        }
        forward.extend_from_slice(header.as_bytes());
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"\r\n");
    forward.extend_from_slice(extra);

    Ok(ParsedHttpRequest {
        target,
        is_connect: false,
        forward_bytes: forward,
    })
}

fn target_from_http_request_target(
    request_target: &str,
    headers: &[&str],
) -> io::Result<(TargetAddr, String)> {
    if request_target.starts_with("http://") || request_target.starts_with("https://") {
        let url = Url::parse(request_target)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "absolute URI 缺少 host"))?;
        let port = url.port_or_known_default().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "absolute URI 协议没有已知默认端口",
            )
        })?;
        let mut origin = url.path().to_owned();
        if origin.is_empty() {
            origin.push('/');
        }
        if let Some(query) = url.query() {
            origin.push('?');
            origin.push_str(query);
        }
        return Ok((
            TargetAddr::new(host, port)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            origin,
        ));
    }

    let host = find_header(headers, "host").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "origin-form 请求缺少 Host 头")
    })?;
    let target = TargetAddr::parse(host, Some(80))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok((target, request_target.to_owned()))
}

fn find_header<'a>(headers: &'a [&'a str], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

async fn write_http_error(client: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    let body = format!("{status} {reason}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await
}

struct ParsedHttpRequest {
    target: TargetAddr,
    is_connect: bool,
    forward_bytes: Vec<u8>,
}

async fn handle_socks5(mut client: TcpStream, connector: Arc<Connector>) -> io::Result<()> {
    let mut head = [0_u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 版本无效",
        ));
    }

    let mut methods = vec![0_u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xff]).await?;
        return Err(io::Error::other("SOCKS5 客户端未提供免认证方法"));
    }
    client.write_all(&[0x05, 0x00]).await?;

    let request = match read_socks5_request(&mut client).await {
        Ok(request) => request,
        Err(err) => {
            write_socks5_reply(&mut client, 0x01).await?;
            return Err(err);
        }
    };

    if request.command != 0x01 {
        write_socks5_reply(&mut client, 0x07).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SOCKS5 命令不是 CONNECT",
        ));
    }

    let mut remote = match connector.connect(&request.target).await {
        Ok(remote) => remote,
        Err(err) => {
            write_socks5_reply(&mut client, 0x05).await?;
            return Err(err);
        }
    };

    write_socks5_reply(&mut client, 0x00).await?;
    let (client_to_remote, remote_to_client) =
        copy_bidirectional(&mut client, remote.as_mut()).await?;
    debug!(
        "SOCKS5 隧道 {} 已关闭：client_to_remote={} remote_to_client={}",
        request.target, client_to_remote, remote_to_client
    );
    Ok(())
}

async fn read_socks5_request(client: &mut TcpStream) -> io::Result<Socks5Request> {
    let mut head = [0_u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 请求版本无效",
        ));
    }
    let command = head[1];
    let target = match head[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            client.read_exact(&mut rest).await?;
            let host = format!("{}.{}.{}.{}", rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            TargetAddr::new(host, port)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        }
        0x03 => {
            let mut len = [0_u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0_u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port = [0_u8; 2];
            client.read_exact(&mut port).await?;
            let host = String::from_utf8(domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SOCKS5 域名不是 UTF-8"))?;
            TargetAddr::new(host, u16::from_be_bytes(port))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            client.read_exact(&mut rest).await?;
            let mut ip = [0_u8; 16];
            ip.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            TargetAddr::new(std::net::Ipv6Addr::from(ip).to_string(), port)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("不支持的 SOCKS5 地址类型 {atyp:#x}"),
            ));
        }
    };

    Ok(Socks5Request { command, target })
}

async fn write_socks5_reply(client: &mut TcpStream, reply: u8) -> io::Result<()> {
    client
        .write_all(&[0x05, reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await
}

struct Socks5Request {
    command: u8,
    target: TargetAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_request() {
        let parsed = parse_http_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap();
        assert!(parsed.is_connect);
        assert_eq!(parsed.target.host, "example.com");
        assert_eq!(parsed.target.port, 443);
    }

    #[test]
    fn rewrites_absolute_form_request() {
        let parsed = parse_http_request(
            b"GET http://example.com:8080/a?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .unwrap();
        assert!(!parsed.is_connect);
        assert_eq!(parsed.target.host, "example.com");
        assert_eq!(parsed.target.port, 8080);
        let forwarded = String::from_utf8(parsed.forward_bytes).unwrap();
        assert!(forwarded.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
        assert!(!forwarded.to_ascii_lowercase().contains("proxy-connection:"));
    }

    #[test]
    fn parses_origin_form_request() {
        let parsed = parse_http_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(parsed.target.host, "example.com");
        assert_eq!(parsed.target.port, 80);
    }

    #[test]
    fn finds_header_case_insensitively() {
        let headers = ["hOsT: example.com"];
        assert_eq!(find_header(&headers, "host"), Some("example.com"));
    }

    #[test]
    fn accept_retry_delay_is_capped() {
        let mut delay = ACCEPT_ERROR_INITIAL_RETRY_DELAY;
        for _ in 0..16 {
            delay = next_accept_retry_delay(delay);
        }
        assert_eq!(delay, ACCEPT_ERROR_MAX_RETRY_DELAY);
    }

    #[tokio::test]
    async fn rejects_invalid_connection_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector = Connector::new(
            crate::proxy::ProxyPool::new(Vec::new(), 1),
            Duration::from_secs(1),
        );
        let err = run_listener_with_limit(listener, connector, 0)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
