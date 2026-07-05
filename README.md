# RotatorProxy

RotatorProxy is a single-port proxy rotator. It accepts HTTP proxy requests, HTTPS `CONNECT`, and SOCKS5/SOCKS5h-style clients on one local port, then chooses one outbound proxy from the configured pool for each new request. If no outbound proxies are loaded, traffic is sent directly.

## Features

- Single listening port with automatic HTTP/SOCKS5 detection.
- Round-robin outbound selection with low-contention atomic indexing.
- Connection-setup retry across the next proxies in the pool; default is 10 attempts.
- Startup full reload + batch health check before the service starts accepting traffic.
- Daily scheduled full reload + batch health check with seamless active-pool swap.
- Runtime cooldown: an active node is skipped temporarily after repeated connection failures.
- Direct mode when the proxy pool is empty.
- Outbound support for:
  - HTTP `CONNECT` proxies via `http://host:port`
  - SOCKS5 and SOCKS5h via `socks5://host:port` and `socks5h://host:port`
  - SOCKS4 and SOCKS4a via `socks4://host:port` and `socks4a://host:port`
  - Shadowsocks SIP002 `ss://` URLs
  - Complex Clash-compatible nodes through a Mihomo sidecar, including VMess, VLESS, Trojan, SSR, Hysteria/Hysteria2, TUIC, WireGuard, AnyTLS, Mieru, Snell, SSH, and other node mappings Mihomo understands
- Source loading from local files/directories, subscription URLs, Clash YAML, and common Base64 subscriptions.

## Quick Start

```bash
cp config.toml.example config.toml
cargo run --release -- --config config.toml
```

On startup, RotatorProxy first loads all configured sources and health-checks every parsed node. It starts listening only after that initial refresh finishes. Point an HTTP or SOCKS5 client at the configured `listen` address, for example `127.0.0.1:7890`.

## Configuration

See [config.toml.example](config.toml.example). The important fields are:

- `listen`: local address for the single inbound proxy port.
- `proxy_dirs`: files or directories to scan. Directories are scanned non-recursively.
- `max_retries`: maximum outbound connection attempts per inbound request.
- `connect_timeout_ms`: timeout for connecting to the target or selected outbound proxy.
- `subscription_timeout_ms`: timeout when fetching subscription URLs.
- `subscription_user_agent`: User-Agent used for subscription HTTP requests.
- `log_level`: default tracing level. `RUST_LOG` overrides it.
- `health_check_url`: HTTP URL used for node liveness checks. Any 2xx/3xx response passes.
- `health_check_attempts`: failed attempts before a node is excluded from the active pool.
- `health_check_concurrency`: maximum concurrent health checks during a batch.
- `runtime_failure_threshold`: runtime connection failures before an active node enters cooldown.
- `cooldown_seconds`: duration for skipping a runtime-failing active node.
- `daily_refresh_time`: local `HH:MM` time for the daily full source reload and health check.
- `mihomo_enabled`: enables Mihomo sidecar support for complex Clash node types.
- `mihomo_binary`: optional explicit Mihomo binary path. If unset, `mihomo`, `clash-meta`, then `clash` are searched in `PATH`.
- `mihomo_auto_download`: when enabled, Linux amd64/arm64 hosts can download the latest Mihomo release automatically.
- `mihomo_work_dir`: runtime directory for downloaded binaries and generated sidecar configs.
- `mihomo_startup_timeout_ms`: maximum wait for a new Mihomo generation to open its local listeners.
- `mihomo_retire_grace_seconds`: delay before an old Mihomo generation is killed after a pool swap.

`config.toml` and `.rotator-proxy/` are intentionally ignored by Git.

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
  - name: vless-a
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    network: ws
    ws-opts:
      path: /ws
```

Base64 subscriptions are supported when the entire fetched body or file content is a Base64-encoded text document. After decoding, RotatorProxy parses the decoded content as the same line-based or Clash YAML formats.

Common URI-style complex links such as `vmess://`, `vless://`, `trojan://`, `ssr://`, `hysteria2://`, `hy2://`, and `tuic://` are converted into Clash-style Mihomo node objects. Full Clash YAML remains the most complete format because unknown or protocol-specific fields are preserved and passed directly to Mihomo.

## Clash And Mihomo Nodes

RotatorProxy handles simple outbound protocols natively when the implementation is complete and predictable: HTTP, SOCKS4/5, and plain Shadowsocks. Other Clash node types are not reimplemented in this project. They are kept as Clash/Mihomo node YAML and handed to a Mihomo sidecar.

For each complex node in a refresh generation, RotatorProxy generates one local Mihomo `mixed` listener bound to `127.0.0.1` and sets that listener's `proxy` field to exactly one internal proxy name. The rotator then treats that listener as a normal outbound candidate. This avoids global selector switching and keeps concurrent requests pinned to the node selected by the rotator.

On Linux `x86_64` and `aarch64`, RotatorProxy can automatically download the latest Mihomo gzip release asset for `amd64` or `arm64`. On other platforms, or if you want fixed binary provenance, install Mihomo yourself and set `mihomo_binary` or put it in `PATH`.

## Refresh And Health Checks

RotatorProxy does not watch input directories. It reloads files and subscription URLs only at startup and at the configured daily refresh time. Startup does not provide service until all sources are loaded, Mihomo listeners are prepared, and batch health checks finish. Scheduled refreshes do not stop the service: the current active pool keeps serving while the new pool is downloaded, parsed, prepared, and health-checked, then the active pool is swapped in one step.

During batch health checks, RotatorProxy sends an HTTP request to `health_check_url` through each candidate node, similar to Clash-style URL delay testing rather than ICMP ping. A node that fails all configured attempts is not admitted to the active rotation pool. During normal traffic, if an admitted node fails connection setup repeatedly, it enters cooldown and is skipped until the cooldown expires.

For Mihomo-backed nodes, a new sidecar generation is started before health checks. If at least one of its nodes passes, that generation is activated and the old generation is retired after `mihomo_retire_grace_seconds`. If none pass, the new generation is discarded and no failed nodes enter rotation.

Logs include source reloads, subscription fetch failures, health-check admission/rejection, pool swaps, runtime failures, and cooldown transitions.

## Current Scope

RotatorProxy is a TCP proxy rotator. It does not implement UDP associate or a Clash rules engine in its own process. Complex Clash protocols are delegated to Mihomo, so their availability follows the Mihomo binary you run. Unknown non-Clash line formats are skipped with a warning.

Health checks currently use an `http://` URL so they can run through every supported TCP proxy without adding a TLS client into the check path.

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
- Batch health refresh filtering and active-pool swap.
- Parser coverage for native Clash nodes, complex Clash nodes, and common complex URI links.
- Mihomo generation config rendering without starting a real Mihomo process.
