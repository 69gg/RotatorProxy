# RotatorProxy

RotatorProxy 是一个单端口代理轮换器。它在一个本地端口同时接受 HTTP 代理请求、HTTPS `CONNECT` 和 SOCKS5/SOCKS5h 客户端连接，并为每次出站尝试从活动代理池中伪随机选择一个代理。如果没有加载到可用出站代理，请求会直接连接目标地址。

## 功能

- 单监听端口，自动识别 HTTP 和 SOCKS5 入站协议。
- 出站代理按全局伪随机不放回方式选择：一轮内节点被取出后不会复用，耗尽后重新洗牌。
- 出站连接建立失败时自动随机尝试代理池中的后续节点，默认最多 10 次，可设为 `0` 表示试完整个可用池。
- 启动时先完整加载来源；默认会批量测活，也可以关闭健康预检查直接启用所有候选节点。
- 支持按固定间隔或每天固定时间增量刷新来源，完成后把新节点加入活动代理池，不删除旧节点。
- 运行时故障冷却：活动节点连接失败后会临时跳过，多次冷却后进入失效名单，后续刷新会静默测活恢复或淘汰。
- 失效名单和淘汰名单默认持久化到本地状态文件，重启后继续生效。
- 代理池为空时自动使用直连模式。
- 出站代理支持：
  - HTTP `CONNECT` 代理：`http://host:port`
  - SOCKS5 和 SOCKS5h：`socks5://host:port`、`socks5h://host:port`
  - SOCKS4 和 SOCKS4a：`socks4://host:port`、`socks4a://host:port`
  - Shadowsocks SIP002 `ss://` 链接
  - 基于 `meow-proxy` 的进程内复杂节点：VMess、VLESS、Trojan、Hysteria2/Hy2、Snell、AnyTLS、Reality TLS、uTLS/client-fingerprint，以及带受支持内置插件的 Shadowsocks
  - 进程内后端暂不支持的复杂节点会被跳过；Mihomo fallback 当前已停用
- 支持从本地文件/目录、订阅 URL、Clash YAML 和常见 Base64 订阅中加载代理源。

## 快速开始

```bash
cp config.toml.example config.toml
cargo run --release -- --config config.toml
```

启动时，RotatorProxy 会先加载所有配置的代理源。默认会对解析出的每个节点执行健康检查；如果设置 `health_check_enabled = false`，则跳过预检查并直接启用所有候选节点。初始刷新完成后才会开始监听端口。然后把 HTTP 或 SOCKS5 客户端指向配置里的 `listen` 地址，例如 `127.0.0.1:7890`。

## 配置

参见 [config.toml.example](config.toml.example)。主要配置项如下：

- `listen`：本地入站代理端口地址。
- `proxy_dirs`：需要扫描的文件或目录。目录只会进行非递归扫描。
- `max_retries`：单个入站请求最多尝试多少个出站代理。设为 `0` 时表示最多尝试当前可用池内每个节点一次。
- `connect_timeout_ms`：连接目标地址或所选出站代理的超时时间。
- `subscription_timeout_ms`：获取订阅 URL 的超时时间。
- `subscription_user_agent`：获取订阅时使用的 User-Agent。
- `subscription_proxy`：可选代理 URL，只用于获取订阅/Clash 配置 URL。支持 `http`、`https`、`socks4`、`socks4a`、`socks5`、`socks5h`。
- `log_level`：默认日志级别。`RUST_LOG` 会覆盖该值。
- `health_check_enabled`：是否启用启动/刷新阶段的健康预检查。默认 `true`；设为 `false` 时，所有候选节点直接进入活动池。
- `health_check_url`：用于节点测活的 HTTP 或 HTTPS URL，默认 `http://cp.cloudflare.com/generate_204`。
- `health_check_expected_status`：测活成功期望状态码，默认 `200-399`。支持精确值和逗号分隔范围；如果想严格检测 `generate_204`，可以设为 `204`。
- `health_check_attempts`：节点被排除出活动代理池前的测活尝试次数。
- `health_check_concurrency`：批量测活时的最大并发数。节点很多时建议设置为 `128` 到 `512`。
- `disabled_recheck_concurrency`：失效名单静默测活的最大并发数，默认 `128`。这条路径在启动和刷新时都会运行，即使 `health_check_enabled = false` 也会运行；如果系统文件描述符限制较低或失效复杂节点很多，建议调低到 `32` 到 `128`。
- `health_check_tls_skip_verify`：显式设为 `true` 时跳过 HTTPS 测活证书校验，默认 `false`。
- `runtime_failure_threshold`：活动节点运行时连接失败多少次后进入冷却。
- `runtime_disable_after_cooldowns`：节点进入冷却多少次后加入失效名单，默认 `2`。如果关闭健康预检查并希望请求失败后立刻冷却，建议把 `runtime_failure_threshold` 设为 `1`。
- `cooldown_seconds`：运行时故障节点被跳过的冷却时长。
- `pool_state_enabled`：是否把可用池、失效名单和淘汰名单持久化到本地状态文件，默认 `true`。
- `pool_state_path`：代理池状态文件路径，默认 `.rotator-proxy/pool-state.json`。可用池会保存完整代理配置，可能包含代理地址、账号和密码；失效名单和淘汰名单使用代理 key 的 SHA-256 哈希记录。
- `daily_refresh_time`：每天完整重新加载和测活的本地时间，格式为 `HH:MM`。未设置 `refresh_interval_seconds` 时生效。
- `refresh_interval_seconds`：可选固定刷新间隔，单位秒。设置后优先于 `daily_refresh_time`，用于更频繁地更新订阅 URL 和本地来源。
- `mihomo_enabled`：历史兼容配置项。Mihomo fallback 当前已停用，进程内后端无法拨号的复杂 Clash 节点会被跳过。
- `mihomo_binary`、`mihomo_auto_download`、`mihomo_work_dir`、`mihomo_generation_batch_size`、`mihomo_startup_timeout_ms`、`mihomo_retire_grace_seconds`：历史兼容配置项。当前刷新流程不会使用这些配置。

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

常见 URI 风格复杂链接，例如 `vmess://`、`vless://`、`trojan://`、`hysteria://`、`hysteria2://`、`hy2://`、`anytls://`、`ssr://`、`tuic://`，会被转换成 Clash 风格节点对象。`http://host:80` 和 `https://user:pass@host:443?sni=...#name` 这类简单代理 URI 会按 HTTP/HTTPS CONNECT 代理解析，即使端口是协议默认端口也会保留。完整 Clash YAML 仍然是最完整的输入格式，因为未知字段和协议特定字段会被保留下来，供原生构建器判断是否支持。

## Clash 兼容节点

RotatorProxy 在进程内处理常见 TCP 代理协议。简单协议使用本地实现：HTTP、HTTPS CONNECT、SOCKS4/5 和普通 Shadowsocks。Clash 中 `type: http` 且 `tls: true` 的节点会作为 HTTPS CONNECT 代理处理。复杂 Clash 兼容节点会优先交给内嵌 `meow-proxy` 后端或内置原生适配器构建。目前该路径覆盖 VMess、VLESS、Trojan、Trojan over WebSocket/HTTPUpgrade/gRPC/H2、Hysteria v1、Hysteria2/Hy2、Snell、AnyTLS、Reality TLS、uTLS/client-fingerprint 配置，以及带受支持内置插件的 Shadowsocks。Hysteria v1 支持 `hysteria://` 和 Clash `type: hysteria` 的 TCP 转发、默认 UDP 承载、`auth`、`alpn`、`sni`、`skip-cert-verify`、`upmbps`/`downmbps` 和 XPlus UDP 混淆密码；暂不支持 v1 的 `wechat`/`faketcp` 承载和 UDP associate。Hysteria2/Hy2 会兼容常见 `mport`/`ports`、`obfs`、`obfs-password`/`obfs_password`、`upmbps`/`downmbps` 字段；链接没有显式端口时会优先使用 `mport`/`ports` 的首个端口，否则默认使用 `443`；空 `obfs` 会按未启用混淆处理；缺少 password/auth 的 Hy2 链接会被解析进复杂节点队列，但当前内嵌 Hy2 adapter 仍会明确跳过空密码节点。VLESS 的 `xtls-rprx-vision-*` 后缀会按 TCP 场景归一化为 `xtls-rprx-vision`。空的 TLS SNI 或 WebSocket Host 会回退到节点 server，避免订阅里的空字段导致节点被整批跳过。

Reality 和真实 uTLS/client-fingerprint 支持使用 `meow-transport` 的 BoringSSL TLS 路径，仍在 Rust 进程内完成。此类节点不需要外部 Mihomo 二进制，但 Linux 构建需要 `boring-sys` 所需的常规原生工具链。

当节点使用内嵌后端无法可靠复现的字段或协议时，例如 Mieru、TUIC、WireGuard/WG、SSH、SSR、旧版 VMess `alterId`、VLESS XHTTP 或 VLESS ML-KEM encryption 扩展，该节点会被记录日志并跳过。Mieru/TUIC 当前只会被解析进复杂节点队列，原生拨号仍需要专门的协议实现或可复用客户端库；Mihomo fallback 当前已停用，不会启动、下载或管理外部 Mihomo 进程。

历史 Mihomo 配置项暂时保留以兼容已有配置文件，但当前刷新流程不会使用这些配置项。

## 刷新和健康检查

RotatorProxy 不会监控输入目录变化。它只会在启动时和配置的刷新时间重新加载文件与订阅 URL。默认按 `daily_refresh_time` 每天刷新一次；设置 `refresh_interval_seconds` 后改为按固定间隔刷新。启动阶段不会先提供服务，而是等待所有来源加载、原生复杂节点构建以及可选批量健康检查全部完成。定时刷新不会停止服务：当前活动代理池会继续处理请求，新的来源会在下载、解析和可选测活完成后增量合并到活动池。刷新不会删除旧活动节点；同 key 节点会去重，只追加新 key 节点。

批量测活时，RotatorProxy 会通过每个候选节点向 `health_check_url` 发起 HTTP/HTTPS 请求，类似 Clash/Mihomo 的 URL delay 测试，而不是 ICMP ping。响应状态码必须匹配 `health_check_expected_status`。通过测活的节点会记录本次延迟，活动池按延迟从低到高排序后进入随机袋。HTTPS 测活默认校验证书；只有私有或自签测活端点才建议设置 `health_check_tls_skip_verify = true`。节点如果在配置次数内全部测活失败，就不会进入活动轮换池。

设置 `health_check_enabled = false` 后，启动和刷新阶段不对新候选执行 URL delay 预检查，所有新候选节点都会直接进入活动轮换池。正常转发流量时，已入池节点连接失败会按 `runtime_failure_threshold` 计数，达到阈值后进入 `cooldown_seconds` 冷却期并临时跳过。若代理连接已经建立，但在收到代理侧首个响应前发生协议读写错误或提前关闭，也会计入运行时失败；这可以覆盖 VLESS/VMess 等延迟读取服务端响应头的节点。若同一节点达到 `runtime_disable_after_cooldowns` 次冷却阈值，该节点会进入失效名单，并从普通轮询中跳过。

每次来源刷新都会对失效名单里的节点执行后台静默健康检查，即使 `health_check_enabled = false` 也会执行。静默测活使用 `disabled_recheck_concurrency` 控制并发，并在每个节点测完后立即回写恢复、保留或淘汰结果，避免大量失效节点在启动/刷新期间长期持有连接资源。静默测活成功的失效节点会清空失败计数并恢复轮询；静默测活连续失败 3 次的节点会从活动池删除，并在当前进程内记为淘汰，后续刷新即使订阅源仍然包含同 key 节点也不会重新加入。启动阶段如果没有任何健康节点，会按空活动池启动。定时刷新阶段如果新一轮测活没有任何健康节点，现有活动池继续服务。

默认启用 `pool_state_enabled` 后，可用池、失效名单、失效静默测活失败次数和淘汰名单会写入 `pool_state_path`。重启后，RotatorProxy 会先从状态文件恢复上次可用池，再从代理来源增量加入新节点；因此某个仍可用节点即使已经从订阅源消失，也能在重启后继续参与轮询。命中失效名单的节点继续等待静默测活恢复，命中淘汰名单的节点继续跳过。普通冷却状态、随机轮询袋顺序和单次失败计数不会持久化。状态文件中的可用池会保存完整代理配置，可能包含账号密码；如果不希望凭据落盘，请设置 `pool_state_enabled = false`。状态文件损坏或版本不支持时，只会记录警告并按空状态启动。

日志会覆盖来源加载、订阅获取失败、解析异常汇总、健康检查开始/完成总结、代理池更新、运行时失败、冷却和失效状态变化。RotatorProxy 自身日志使用中文；依赖库日志会按其原始内容输出。逐行解析失败明细默认在 debug 日志中输出，避免大型公开源刷屏。

排查运行时出站问题时，可以设置 `RUST_LOG=rotator_proxy=debug`。debug 日志会打印每次出站连接尝试的 attempt 序号、节点类型、节点名、第一跳上游地址、最终目标、超时时间、耗时和错误类型。这里的第一跳上游地址是 RotatorProxy 实际直连的代理节点地址；最终目标是客户端请求通过该节点访问的目标地址。

## 当前范围

RotatorProxy 是 TCP 代理轮换器。它不在自身进程中实现 UDP associate，也不实现 Clash 规则引擎。复杂 TCP 协议会在受支持时由内嵌后端处理；内嵌后端暂不支持的 Clash 协议会被跳过。未知的非 Clash 行格式会计入来源解析汇总并跳过，打开 debug 日志可以查看具体行号。

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
- 出站节点伪随机不放回选择，`max_retries = 0` 时可试完整个可用池。
- 批量健康刷新过滤失败代理并增量更新活动代理池。
- 关闭健康预检查时直接加载所有候选代理。
- 定时刷新不删除旧活动节点，只追加新节点。
- 运行时重复冷却后加入失效名单，并在刷新时静默测活恢复或连续失败后淘汰。
- HTTPS 健康检查显式跳过证书校验。
- 原生 Clash 节点、复杂 Clash 节点、HTTPS 代理和常见复杂 URI 链接的解析覆盖。
- HTTPS 出站代理可参与批量健康检查。
- Mihomo fallback 停用后不会启动真实 Mihomo 进程。

## 许可证

RotatorProxy 使用 GPL-3.0-only 许可证。Copyright (C) 2026 Null <pylindex@qq.com>.
