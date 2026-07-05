# RotatorProxy

RotatorProxy is a single-port proxy rotator. It accepts HTTP proxy requests, HTTPS `CONNECT`, and SOCKS5/SOCKS5h-style clients on one local port, then chooses one outbound proxy from the configured pool for each new request. If no outbound proxies are loaded, traffic is sent directly.

## Features

- Single listening port with automatic HTTP/SOCKS5 detection.
- Round-robin outbound selection with low-contention atomic indexing.
- Connection-setup retry across the next proxies in the pool; default is 10 attempts.
- Direct mode when the proxy pool is empty.
- Outbound support for:
  - HTTP `CONNECT` proxies via `http://host:port`
  - SOCKS5 and SOCKS5h via `socks5://host:port` and `socks5h://host:port`
  - SOCKS4 and SOCKS4a via `socks4://host:port` and `socks4a://host:port`
  - Shadowsocks SIP002 `ss://` URLs
- Source loading from local files/directories, subscription URLs, Clash YAML, and common Base64 subscriptions.

## Quick Start

```bash
cp config.toml.example config.toml
cargo run --release -- --config config.toml
```

Point an HTTP or SOCKS5 client at the configured `listen` address, for example `127.0.0.1:7890`.

## Configuration

See [config.toml.example](config.toml.example). The important fields are:

- `listen`: local address for the single inbound proxy port.
- `proxy_dirs`: files or directories to scan. Directories are scanned non-recursively.
- `max_retries`: maximum outbound connection attempts per inbound request.
- `connect_timeout_ms`: timeout for connecting to the target or selected outbound proxy.
- `subscription_timeout_ms`: timeout when fetching subscription URLs.
- `subscription_user_agent`: User-Agent used for subscription HTTP requests.
- `log_level`: default tracing level. `RUST_LOG` overrides it.

`config.toml` is intentionally ignored by Git.

## Proxy Sources

Each file in `proxy_dirs` can be one of these forms:

Plain proxy list:

```text
http://user:pass@127.0.0.1:8080
socks5://127.0.0.1:1080
socks5h://127.0.0.1:1080
ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo4Mzg4#example
```

Subscription URL list:

```text
https://example.com/subscription/base64
https://example.com/clash.yaml
```

Clash YAML:

```yaml
proxies:
  - name: http-a
    type: http
    server: 127.0.0.1
    port: 8080
  - name: socks-a
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: ss-a
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: password
```

Base64 subscriptions are supported when the entire fetched body or file content is a Base64-encoded text document. After decoding, RotatorProxy parses the decoded content as the same line-based or Clash YAML formats.

## Current Scope

RotatorProxy is a TCP proxy rotator. It does not implement UDP associate, a Clash rules engine, VMess/Trojan/SSR/Hysteria transports, or HTTPS transport to an HTTP proxy. Unknown Clash proxy types are skipped with a warning.

For plain HTTP proxy requests, RotatorProxy rewrites the first absolute-form request line to origin-form and then tunnels the connection. `CONNECT` is the preferred mode for HTTPS traffic.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The integration tests cover:

- HTTP absolute-form forwarding.
- HTTP `CONNECT` forwarding.
- SOCKS5 inbound forwarding.
- Retry from a failed outbound proxy to the next proxy.
