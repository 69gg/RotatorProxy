# RotatorProxy

RotatorProxy 是一个单端口代理轮换器。它在一个本地端口同时接受 HTTP 代理请求、HTTPS `CONNECT` 和 SOCKS5/SOCKS5h 客户端连接，并为每个新请求从活动代理池中选择一个出站代理。如果没有加载到可用出站代理，请求会直接连接目标地址。

## 功能

- 单监听端口，自动识别 HTTP 和 SOCKS5 入站协议。
- 出站代理按轮询选择，使用低竞争的原子索引。
- 出站连接建立失败时自动尝试代理池中的后续节点，默认最多 10 次。
- 启动时先完整加载来源并批量测活，测活完成后才开始提供服务。
- 每天按配置时间完整刷新来源并批量测活，完成后无缝切换活动代理池。
- 运行时故障冷却：活动节点连续连接失败后会临时跳过。
- 代理池为空时自动使用直连模式。
- 出站代理支持：
  - HTTP `CONNECT` 代理：`http://host:port`
  - SOCKS5 和 SOCKS5h：`socks5://host:port`、`socks5h://host:port`
  - SOCKS4 和 SOCKS4a：`socks4://host:port`、`socks4a://host:port`
  - Shadowsocks SIP002 `ss://` 链接
  - 基于 `meow-proxy` 的进程内复杂节点：VMess、VLESS、Trojan、Hysteria2/Hy2、Snell、AnyTLS、Reality TLS、uTLS/client-fingerprint，以及带受支持内置插件的 Shadowsocks
  - 对进程内后端暂不支持的复杂节点，可选使用 Mihomo sidecar fallback
- 支持从本地文件/目录、订阅 URL、Clash YAML 和常见 Base64 订阅中加载代理源。

## 快速开始

```bash
cp config.toml.example config.toml
cargo run --release -- --config config.toml
```

启动时，RotatorProxy 会先加载所有配置的代理源，并对解析出的每个节点执行健康检查。初始刷新完成后才会开始监听端口。然后把 HTTP 或 SOCKS5 客户端指向配置里的 `listen` 地址，例如 `127.0.0.1:7890`。

## 配置

参见 [config.toml.example](config.toml.example)。主要配置项如下：

- `listen`：本地入站代理端口地址。
- `proxy_dirs`：需要扫描的文件或目录。目录只会进行非递归扫描。
- `max_retries`：单个入站请求最多尝试多少个出站代理。
- `connect_timeout_ms`：连接目标地址或所选出站代理的超时时间。
- `subscription_timeout_ms`：获取订阅 URL 的超时时间。
- `subscription_user_agent`：获取订阅时使用的 User-Agent。
- `subscription_proxy`：可选代理 URL，只用于获取订阅/Clash 配置 URL 和自动下载 Mihomo。支持 `http`、`https`、`socks4`、`socks4a`、`socks5`、`socks5h`。
- `log_level`：默认日志级别。`RUST_LOG` 会覆盖该值。
- `health_check_url`：用于节点测活的 HTTP 或 HTTPS URL，默认 `http://cp.cloudflare.com/generate_204`。
- `health_check_expected_status`：测活成功期望状态码，默认 `200-399`。支持精确值和逗号分隔范围；如果想严格检测 `generate_204`，可以设为 `204`。
- `health_check_attempts`：节点被排除出活动代理池前的测活尝试次数。
- `health_check_concurrency`：批量测活时的最大并发数。节点很多时建议设置为 `128` 到 `512`。
- `health_check_tls_skip_verify`：显式设为 `true` 时跳过 HTTPS 测活证书校验，默认 `false`。
- `runtime_failure_threshold`：活动节点运行时连接失败多少次后进入冷却。
- `cooldown_seconds`：运行时故障节点被跳过的冷却时长。
- `daily_refresh_time`：每天完整重新加载和测活的本地时间，格式为 `HH:MM`。
- `mihomo_enabled`：启用可选 Mihomo sidecar fallback，用于进程内后端无法拨号的复杂 Clash 节点。默认关闭。
- `mihomo_binary`：可选的 Mihomo 可执行文件路径。未设置时会依次在 `PATH` 中查找 `mihomo`、`clash-meta`、`clash`。
- `mihomo_auto_download`：与 `mihomo_enabled` 同时启用时，Linux amd64/arm64 主机可自动下载最新 Mihomo release。
- `mihomo_work_dir`：下载的二进制和生成的 sidecar 配置所在运行目录。
- `mihomo_startup_timeout_ms`：等待新 Mihomo generation 打开本地监听端口的最长时间。
- `mihomo_retire_grace_seconds`：代理池切换后，旧 Mihomo generation 延迟退出的时间。

`config.toml` 和 `.rotator-proxy/` 会被 Git 忽略。

## 代理源

`proxy_dirs` 中的每个文件可以是以下几种形式之一。

普通代理列表：

```text
# 以 # 开头的行会被忽略
http://user:pass@127.0.0.1:8080
socks5://127.0.0.1:1080
socks5h://127.0.0.1:1080
ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo4Mzg4#example
http://127.0.0.1:8080 # 空白后的 # 会被视为行尾注释
```

订阅 URL 列表：

```text
https://example.com/subscription/base64
https://example.com/clash.yaml
```

如果设置了 `subscription_proxy`，这些 HTTP/HTTPS 来源会通过该代理获取。需要让订阅域名也通过代理解析时，使用 `socks5h://...`。该设置只用于下载配置输入，不参与运行时出站轮换。

只有本地代理源文件中的 HTTP/HTTPS 行会被当作订阅 URL 展开。下载回来的行式代理内容会按“一行一个代理”处理，不会把其中的 HTTP/HTTPS 行继续递归抓取；这样可以避免把带 `#节点名`、账号或端口的代理链接误判成订阅。

Clash YAML：

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

当整个文件内容或订阅响应体是 Base64 编码的文本时，RotatorProxy 会自动解码，并按同样的行格式或 Clash YAML 格式继续解析。

常见 URI 风格复杂链接，例如 `vmess://`、`vless://`、`trojan://`、`hysteria2://`、`hy2://`、`anytls://`、`ssr://`、`tuic://`，会被转换成 Clash 风格节点对象。完整 Clash YAML 仍然是最完整的输入格式，因为未知字段和协议特定字段会被保留下来，供原生构建器或可选 Mihomo fallback 使用。

## Clash 兼容节点

RotatorProxy 在进程内处理常见 TCP 代理协议。简单协议使用本地实现：HTTP、HTTPS、SOCKS4/5 和普通 Shadowsocks。复杂 Clash 兼容节点会优先交给内嵌 `meow-proxy` 后端构建。目前该路径覆盖 VMess、VLESS、Trojan、Hysteria2/Hy2、Snell、AnyTLS、Reality TLS、uTLS/client-fingerprint 配置，以及带受支持内置插件的 Shadowsocks。

Reality 和真实 uTLS/client-fingerprint 支持使用 `meow-transport` 的 BoringSSL TLS 路径，仍在 Rust 进程内完成。此类节点不需要外部 Mihomo 二进制，但 Linux 构建需要 `boring-sys` 所需的常规原生工具链。

当节点使用内嵌后端无法可靠复现的字段或协议时，例如 TUIC、WireGuard/WG、Mieru、SSH 或 SSR，该节点会进入可选 Mihomo fallback 队列。Mihomo fallback 默认关闭。在默认配置下，只有 fallback 才能支持的节点会被记录日志并跳过，不会启动或下载外部可执行文件。

如果设置 `mihomo_enabled = true`，RotatorProxy 会为每个 fallback 节点生成一个本地 Mihomo `mixed` 监听器，绑定到 `127.0.0.1`，并把该监听器的 `proxy` 字段固定到一个内部代理名。轮换器随后把这个监听器当作普通出站候选节点处理。这样可以避免全局 selector 切换，并让并发请求稳定绑定到轮换器选择的节点。

在 Linux `x86_64` 和 `aarch64` 上，当同时启用 `mihomo_enabled` 和 `mihomo_auto_download` 时，RotatorProxy 可以自动下载最新 Mihomo gzip release 中的 `amd64` 或 `arm64` 资源。其他平台，或需要固定二进制来源时，请自行安装 Mihomo，并设置 `mihomo_binary` 或放入 `PATH`。

## 刷新和健康检查

RotatorProxy 不会监控输入目录变化。它只会在启动时和配置的每日刷新时间重新加载文件与订阅 URL。启动阶段不会先提供服务，而是等待所有来源加载、原生复杂节点构建、可选 Mihomo fallback 监听器准备，以及批量健康检查全部完成。定时刷新不会停止服务：当前活动代理池会继续处理请求，新的代理池会在下载、解析、准备和测活完成后一次性切换。

批量测活时，RotatorProxy 会通过每个候选节点向 `health_check_url` 发起 HTTP/HTTPS 请求，类似 Clash/Mihomo 的 URL delay 测试，而不是 ICMP ping。响应状态码必须匹配 `health_check_expected_status`。通过测活的节点会记录本次延迟，活动池按延迟从低到高排序后再进入轮询。HTTPS 测活默认校验证书；只有私有或自签测活端点才建议设置 `health_check_tls_skip_verify = true`。节点如果在配置次数内全部测活失败，就不会进入活动轮换池。正常转发流量时，已入池节点如果连续连接失败，会进入冷却并在冷却结束前被跳过。

启动阶段如果没有任何健康节点，会按空活动池启动。定时刷新阶段如果新一轮测活没有任何健康节点，RotatorProxy 会保留上一版活动池继续服务，避免公开源短时波动把可用池清空。

对于 Mihomo-backed fallback 节点，新 sidecar generation 会在测活前启动。如果其中至少一个节点测活通过，该 generation 会被激活，旧 generation 会在 `mihomo_retire_grace_seconds` 后退出。如果没有节点通过，新 generation 会被丢弃，失败节点不会进入轮换。

日志会覆盖来源加载、订阅获取失败、解析异常汇总、健康检查开始/完成总结、代理池切换、运行时失败和冷却状态变化。RotatorProxy 自身日志使用中文；依赖库或可选 Mihomo sidecar 的日志会按其原始内容输出。逐行解析失败明细默认在 debug 日志中输出，避免大型公开源刷屏。

## 当前范围

RotatorProxy 是 TCP 代理轮换器。它不在自身进程中实现 UDP associate，也不实现 Clash 规则引擎。复杂 TCP 协议会在受支持时由内嵌后端处理；只有 fallback 才能支持的 Clash 协议需要显式启用 Mihomo。未知的非 Clash 行格式会计入来源解析汇总并跳过，打开 debug 日志可以查看具体行号。

健康检查支持 `http://` 和 `https://` URL。

对于普通 HTTP 代理请求，RotatorProxy 会把第一行 absolute-form 请求改写为 origin-form，然后继续转发连接。HTTPS 流量建议使用 `CONNECT` 模式。

## 开发

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

集成测试覆盖：

- HTTP absolute-form 转发。
- HTTP `CONNECT` 转发。
- SOCKS5 入站转发。
- 第一个出站代理失败时重试下一个代理。
- 批量健康刷新过滤失败代理并切换活动代理池。
- 定时刷新全失败时保留上一版活动代理池。
- HTTPS 健康检查显式跳过证书校验。
- 原生 Clash 节点、复杂 Clash 节点、HTTPS 代理和常见复杂 URI 链接的解析覆盖。
- HTTPS 出站代理可参与批量健康检查。
- 不启动真实 Mihomo 进程的 generation 配置渲染。

## 许可证

RotatorProxy 使用 GPL-3.0-only 许可证。Copyright (C) 2026 Null <pylindex@qq.com>.
