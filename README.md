# dsh-mobile-access

DeepSeek Harness 移动访问插件：**同一局域网内，手机扫码后用自己的浏览器访问电脑上的 DSH**。

这是参考 [dsh-mobile](https://github.com/saya-ch/dsh-mobile) 安全网关思路的自研版本，功能聚焦在「局域网 + 手机浏览器访问」，去掉了远程通道（Tailscale/cpolar/FRP）与 Android App 部分，代码完全可见、可控。

## 它做了什么、为什么安全

DSH 官方禁止 `--host 0.0.0.0`（会把远程代码执行暴露到网络）。因此本插件**不修改 DSH 的 web server**，DSH Web 始终留在 `127.0.0.1` 上。插件在 DSH 进程内另起一个：

- **独立的 HTTPS 网关**（自签名证书），监听 `0.0.0.0:<port>`；
- 把请求**反向代理**到 `127.0.0.1:<DSH webServer 端口>`；
- 网关做 **PIN 认证**：手机浏览器首次打开网关地址需输入 PIN，通过后种下 httpOnly session cookie，之后的请求（含 WebSocket）只放行已认证的；
- 转发时把 `Host` / `Origin` / `sec-fetch-site` 重写为 DSH 后端（loopback 同源），使 DSH 的浏览器信任围栏放行 `/api` 与 SSE/WebSocket 传输；
- **桥接 DSH ≥ 0.1.5 的浏览器会话认证**：DSH 现在要求浏览器先完成「进程启动 token → 签名 cookie」握手，否则 `/` 与 `/api` 一律 401（正文 `dsh web authentication required`）。启动 token 只存在于 DSH 进程内，手机无从获得，因此网关在服务端代做这一步：用 `connection.authenticatedUrl()` 取本进程 token，`GET /?token=…` 换取 `dsh-auth-<authority>` cookie 并缓存，之后所有转发（含 WebSocket 升级）注入该 cookie。手机侧零感知，token 也不会落到手机上；会话失效（DSH 重启换端口 / cookie 过期）时网关收到 401 会清缓存、重新换取并重放一次。

**默认不开启**，需要你在设置里手动「开启局域网访问」；上次开启过的话，DSH 重启后会自动恢复。

**0.2.0 变更**：新增上述 DSH 会话认证桥接（修复升级到 0.1.5-rc.1 后手机端「需要重新进行 DSH web 认证」）；网关 PIN 会话 token 改成持久化，DSH 重启后手机不必重新输 PIN；未认证的并发请求只换取一次会话 cookie。

> ⚠️ 安全边界：开启后网关对外监听，仅靠 PIN 认证防护。请只在受信任的家庭 / 办公局域网使用，并设置足够强的 PIN。这不是公网安全的替代。

## 依赖

| 依赖 | 用途 |
| --- | --- |
| `selfsigned` | 生成本地 HTTPS 自签名证书 |
| `qrcode` | 生成访问地址二维码 |
| `http-proxy` | 反向代理（HTTP / SSE / WebSocket 透传） |

## 安装

```powershell
# 从 GitHub 安装（推荐）
dsh plugin --profile <profile> add github:MacilyDots/dsh-mobile-access

# 或从本地克隆的目录安装
dsh plugin --profile <profile> add file:<本仓库的绝对路径>

dsh --profile <profile>
```

`dsh plugin add` 会执行 `pnpm add` 并把声明了 `dsh.bundle` 的插件自动加入 profile 的 bundles 层；**安装后需重启 DSH** 才会加载插件。

## 使用

1. 重启 DSH 后，打开 DSH 设置页 → **移动访问**。
2. 输入一个至少 4 位的**访问 PIN**，点**开启局域网访问**（端口默认 3443，可改）。
3. 面板会显示**访问地址**（`https://<电脑局域网IP>:<端口>`）和**二维码**。
4. 让手机连**同一个局域网**，用手机浏览器**扫码**（或手动输入地址）。
5. 首次打开：手机浏览器会提示**信任自签名证书**（确认即可），然后输入刚才的 **PIN** 进入，即可在手机上操作 DSH。
6. 用完点**关闭移动访问**。

> 升级到 DSH ≥ 0.1.5 后，手机端若显示「需要重新进行 DSH web 认证」（HTTP 401 正文 `dsh web authentication required`），说明网关缺少 DSH 会话 cookie 桥接——0.2.0 起已在网关内解决，无需在手机上做任何额外认证。

> 手机浏览器的「证书未信任」提示是正常的（自签名证书）；不同浏览器“继续访问”的入口位置略有不同（如 iOS 需「显示详细信息 → 访问此网站」）。

## 自签证书的说明

首次开启时插件会生成自签名证书并缓存在 `$DSH_HOME/mobile-access/cert.pem` 与 `key.pem`。之后手机浏览器会记住你的信任。证书是 2048 位 RSA、400 天有效期。

## 文件

- `index.js` — 服务端：cordis 插件 + HTTPS 网关 + PIN 认证 + 反向代理 + 控制路由、二维码。
- `client.js` — 设置面板「移动访问」卡片。
- `cordis.patch.yml` — bundle 注入。
- `test/` — 离线回归测试：自己起假 DSH 后端，状态目录指向系统临时目录，不碰真实的 PIN 与证书。
- 运行态状态与证书：`$DSH_HOME/mobile-access/`。

## 测试

三个测试都是自包含的，不需要 DSH 在运行、不需要真实网关：

```powershell
node test/bridge.test.mjs        # 会话认证桥接：换取 cookie / 401 自愈 / 并发 single-flight
node test/integration.test.mjs   # 端到端：设 PIN → 开启 → 手机用 PIN 登录 → 反向代理
node test/websocket.test.mjs     # WebSocket 升级透传（sec-websocket-key 保留）
```

`bridge.test.mjs` 是 0.2.0 会话认证桥接的回归测试（12 个断言），改动网关逻辑后先跑它。

## 控制路由

挂在 DSH 自己的 web server 上（loopback，仅本机浏览器可访问）：

- `GET  /dsh-mobile-access/status` — 状态（含二维码 dataURL）
- `POST /dsh-mobile-access/enable` — `{ pin, port? }`
- `POST /dsh-mobile-access/disable`
- `POST /dsh-mobile-access/pin` — `{ pin }`

## 限制

- 仅支持 IPv4 局域网地址。
- 换网络后需重新开启（或重启 DSH 后再次开启）。
- 未实现 dsh-mobile 的设备配对、公网/远程通道与 App 端。
