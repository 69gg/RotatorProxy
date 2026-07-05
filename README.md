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
  - In-process complex nodes through `meow-proxy`: VMess, VLESS, Trojan, Hysteria2/Hy2, Snell, AnyTLS, and Shadowsocks with supported built-in plugins
  - Optional Mihomo sidecar fallback for complex nodes that are not supported by the in-process backend
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
- `mihomo_enabled`: enables the optional Mihomo sidecar fallback for complex Clash node types that the embedded backend cannot dial. Disabled by default.
- `mihomo_binary`: optional explicit Mihomo binary path. If unset, `mihomo`, `clash-meta`, then `clash` are searched in `PATH`.
- `mihomo_auto_download`: when enabled together with `mihomo_enabled`, Linux amd64/arm64 hosts can download the latest Mihomo release automatically.
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

Common URI-style complex links such as `vmess://`, `vless://`, `trojan://`, `hysteria2://`, `hy2://`, `anytls://`, `ssr://`, and `tuic://` are converted into Clash-style node objects. Full Clash YAML remains the most complete format because unknown or protocol-specific fields are preserved for the native builder or optional Mihomo fallback.

## Clash-Compatible Nodes

RotatorProxy handles common TCP proxy protocols in-process. Simple protocols use local implementations: HTTP, SOCKS4/5, and plain Shadowsocks. Complex Clash-compatible nodes are first built with the embedded `meow-proxy` backend. That path currently covers VMess, VLESS, Trojan, Hysteria2/Hy2, Snell, AnyTLS, and Shadowsocks with supported built-in plugins.

When a node uses fields that the embedded backend cannot safely reproduce, such as TUIC, WireGuard/WG, Mieru, SSH, SSR, Reality options, or client fingerprint/uTLS settings, it is sent to the optional Mihomo fallback queue. Mihomo fallback is disabled by default. With the default config, unsupported fallback-only nodes are logged and skipped instead of starting or downloading an external executable.

If `mihomo_enabled = true`, RotatorProxy generates one local Mihomo `mixed` listener per fallback node, bound to `127.0.0.1`, and sets that listener's `proxy` field to exactly one internal proxy name. The rotator then treats that listener as a normal outbound candidate. This avoids global selector switching and keeps concurrent requests pinned to the node selected by the rotator.

On Linux `x86_64` and `aarch64`, RotatorProxy can automatically download the latest Mihomo gzip release asset for `amd64` or `arm64` when both `mihomo_enabled` and `mihomo_auto_download` are true. On other platforms, or if you want fixed binary provenance, install Mihomo yourself and set `mihomo_binary` or put it in `PATH`.

## Refresh And Health Checks

RotatorProxy does not watch input directories. It reloads files and subscription URLs only at startup and at the configured daily refresh time. Startup does not provide service until all sources are loaded, native complex nodes and optional Mihomo fallback listeners are prepared, and batch health checks finish. Scheduled refreshes do not stop the service: the current active pool keeps serving while the new pool is downloaded, parsed, prepared, and health-checked, then the active pool is swapped in one step.

During batch health checks, RotatorProxy sends an HTTP request to `health_check_url` through each candidate node, similar to Clash-style URL delay testing rather than ICMP ping. A node that fails all configured attempts is not admitted to the active rotation pool. During normal traffic, if an admitted node fails connection setup repeatedly, it enters cooldown and is skipped until the cooldown expires.

For Mihomo-backed fallback nodes, a new sidecar generation is started before health checks. If at least one of its nodes passes, that generation is activated and the old generation is retired after `mihomo_retire_grace_seconds`. If none pass, the new generation is discarded and no failed nodes enter rotation.

Logs include source reloads, subscription fetch failures, health-check admission/rejection, pool swaps, runtime failures, and cooldown transitions.

## Current Scope

RotatorProxy is a TCP proxy rotator. It does not implement UDP associate or a Clash rules engine in its own process. Complex TCP protocols are handled by the embedded backend where supported; fallback-only Clash protocols require explicit Mihomo enablement. Unknown non-Clash line formats are skipped with a warning.

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

## License

RotatorProxy is licensed as GPL-3.0-only. Copyright (C) 2026 Null <pylindex@qq.com>.
