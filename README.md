# dsh-mobile-access

[English](README.md) | [简体中文](README.zh-CN.md)

DeepSeek Harness mobile access plugin: **on the same LAN, scan a QR code with your phone and reach the DSH running on your computer from the phone's own browser**.

This is an in-house implementation of the secure-gateway idea from [dsh-mobile](https://github.com/saya-ch/dsh-mobile). Its scope is LAN + phone browser access: the remote tunnels (Tailscale/cpolar/FRP) and the Android app are dropped, and the code stays fully visible and under your control.

## What it does and why it is safe

DSH upstream forbids `--host 0.0.0.0` (it would expose remote code execution to the network). This plugin therefore **does not modify the DSH web server**; DSH Web always stays on `127.0.0.1`. Instead, the plugin starts the following inside the DSH process:

- **A separate HTTPS gateway** (self-signed certificate) listening on `0.0.0.0:<port>`;
- it **reverse-proxies** requests to `127.0.0.1:<DSH webServer port>`;
- the gateway enforces **PIN authentication**: the first time a phone browser opens the gateway address it must enter the PIN, after which the gateway sets an httpOnly session cookie, and later requests (including WebSocket) are allowed through only if already authenticated;
- on every forward it rewrites `Host` / `Origin` / `sec-fetch-site` to the DSH backend (loopback, same origin), so DSH's browser trust fence lets `/api` and SSE/WebSocket traffic through;
- **it bridges the browser session authentication of DSH ≥ 0.1.5**: DSH now requires the browser to complete a "process startup token → signed cookie" handshake first, otherwise `/` and `/api` always return 401 (body `dsh web authentication required`). The startup token exists only inside the DSH process, and the phone has no way to obtain it, so the gateway performs this step server-side: it calls `connection.authenticatedUrl()` for this process's token, exchanges it with `GET /?token=…` for a `dsh-auth-<authority>` cookie, caches that cookie, and injects it into every subsequent forward (including WebSocket upgrades). The phone notices nothing, and the token never reaches the phone; when the session goes stale (DSH restarted on a different port / cookie expired) the gateway gets a 401, clears the cache, exchanges a fresh cookie and replays the request once.

It is **off by default**; you enable LAN access manually in the settings. If it was enabled last time, it is restored automatically after a DSH restart.

**Changes in 0.2.0**: added the DSH session authentication bridge described above (fixes the "DSH web authentication required" prompt on the phone after upgrading to 0.1.5-rc.1); the gateway PIN session token is now persisted, so the phone does not have to re-enter the PIN after a DSH restart; concurrent unauthenticated requests exchange the session cookie only once.

> ⚠️ Security boundary: once enabled, the gateway listens on the network and is protected by PIN authentication alone. Use it only on a trusted home / office LAN, and set a PIN that is strong enough. It is not a substitute for public-network security.

## Dependencies

| Dependency | Purpose |
| --- | --- |
| `selfsigned` | Generates the local HTTPS self-signed certificate |
| `qrcode` | Generates the QR code for the access address |
| `http-proxy` | Reverse proxy (HTTP / SSE / WebSocket passthrough) |

## Installation

```powershell
# Install from GitHub (recommended)
dsh plugin --profile <profile> add github:MacilyDots/dsh-mobile-access

# Or install from a local clone
dsh plugin --profile <profile> add file:<absolute path to this repository>

dsh --profile <profile>
```

`dsh plugin add` runs `pnpm add` and automatically adds plugins that declare `dsh.bundle` to the profile's bundles layer; **DSH must be restarted after installation** before the plugin is loaded.

## Usage

1. After restarting DSH, open the DSH settings page → **Mobile access**.
2. Enter an **access PIN** of at least 4 characters, then click **Enable LAN access** (the port defaults to 3443 and can be changed).
3. The panel shows the **access address** (`https://<LAN IP of this computer>:<port>`) and a **QR code**.
4. Put the phone on the **same LAN** and **scan the QR code** with the phone browser (or type the address manually).
5. First open: the phone browser asks you to **trust the self-signed certificate** (confirm it), then you enter the **PIN** and are in, and DSH is operable from the phone.
6. When you are done, click **Disable mobile access**.

> After upgrading to DSH ≥ 0.1.5, if the phone shows "DSH web authentication required" (HTTP 401 with body `dsh web authentication required`), the gateway is missing the DSH session cookie bridge — that is solved inside the gateway as of 0.2.0, with no extra authentication needed on the phone.

> The "certificate not trusted" warning in the phone browser is expected (self-signed certificate); the location of the "continue" entry differs slightly between browsers (on iOS it is "Show Details → Visit this Website").

## About the self-signed certificate

On first enable, the plugin generates a self-signed certificate and caches it at `$DSH_HOME/mobile-access/cert.pem` and `key.pem`. The phone browser remembers your trust from then on. The certificate is 2048-bit RSA with a 400-day validity.

## Files

- `index.js` — server side: cordis plugin + HTTPS gateway + PIN authentication + reverse proxy + control routes and QR code.
- `client.js` — the "Mobile access" card in the settings panel.
- `cordis.patch.yml` — bundle injection.
- `test/` — offline regression tests: they start a fake DSH backend themselves and point the state directory at the system temp directory, so they never touch the real PIN or certificate.
- Runtime state and certificates: `$DSH_HOME/mobile-access/`.

## Tests

All three tests are self-contained; they need neither a running DSH nor a real gateway:

```powershell
node test/bridge.test.mjs        # Session auth bridge: cookie exchange / 401 self-heal / concurrent single-flight
node test/integration.test.mjs   # End-to-end: set PIN → enable → phone signs in with PIN → reverse proxy
node test/websocket.test.mjs     # WebSocket upgrade passthrough (sec-websocket-key preserved)
```

`bridge.test.mjs` is the regression test for the 0.2.0 session authentication bridge (12 assertions); run it first after changing gateway logic.

## Control routes

Mounted on DSH's own web server (loopback, reachable only from the local browser):

- `GET  /dsh-mobile-access/status` — status (includes the QR code dataURL)
- `POST /dsh-mobile-access/enable` — `{ pin, port? }`
- `POST /dsh-mobile-access/disable`
- `POST /dsh-mobile-access/pin` — `{ pin }`

## Limitations

- IPv4 LAN addresses only.
- After switching networks you have to enable it again (or enable it again after restarting DSH).
- The device pairing, public/remote tunnels and app client of dsh-mobile are not implemented.
