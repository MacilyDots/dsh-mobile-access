/**
 * dsh-mobile-access — DeepSeek Harness 移动访问插件（服务端半体）。
 *
 * 目标：同一局域网内，手机扫码后用自己的浏览器访问电脑上的 DSH Web。
 *
 * 设计（参考 dsh-mobile 的安全网关思路，但显著简化）：
 *  - DSH 官方禁止 `--host 0.0.0.0`（会把远程代码执行暴露到网络）。因此本插件
 *    不修改 DSH 的 web server，DSH Web 始终留在 127.0.0.1 上。
 *  - 插件另起一个**独立的 HTTPS 网关**（自签名证书），监听 0.0.0.0:<port>，
 *    把请求反向代理到 127.0.0.1:<DSH webServer 端口>。
 *  - 网关做 **PIN 认证**：手机浏览器首次打开网关地址先输入 PIN，校验通过后种下
 *    httpOnly session cookie，后续请求（含 WebSocket）仅放行已认证的。
 *  - 转发时把 Host / Origin / sec-fetch-site 重写为 DSH 后端（loopback 同源），
 *    这样 DSH 的浏览器信任围栏把网关来的请求视为可信，`/api` 与 SSE/WS 都能用。
 *  - 用 qrcode 生成访问地址二维码，显示在 DSH 设置面板的「移动访问」卡片里。
 *
 * DSH ≥ 0.1.5 的浏览器会话认证（client-connection）桥接：
 *  - DSH 现在要求每个浏览器先经过「进程启动 token 换签名 cookie」的握手：无有效
 *    cookie 时，`/` 与 `/api` 分别返回 401（正文 `dsh web authentication required`）。
 *    启动 token 只存在于 DSH 进程内，手机不可能拿到。
 *  - 因此网关自己做这件事：通过 `connection.authenticatedUrl()` 取本进程 token，
 *    在服务端用 `GET /?token=…` 向 DSH 换取 `dsh-auth-<authority>` 签名 cookie 并缓存，
 *    之后所有转发（HTTP + WebSocket 升级）都注入这个 cookie。手机侧零感知，
 *    token 也从不落到手机上。
 *  - 缓存的 cookie 失效（DSH 重启换端口、cookie 过期）时 DSH 回 401，网关清缓存并
 *    重新换取一次再重试；API 请求的 401 只清缓存，下次请求自动恢复。
 *  - 网关自身的 PIN 会话 token 持久化在 state.json，DSH 重启后手机不必重新输 PIN；
 *    上次的开启状态也会在插件加载时自动恢复。
 *
 * 安全边界：默认不开启（enabled=false）。开启后网关对外监听，仅靠 PIN 认证；
 * 请只在受信任的家庭/办公局域网使用，并使用足够强的 PIN。
 */

import { createServer as createHttpsServer } from "node:https";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir, networkInterfaces } from "node:os";
import { request as httpRequest } from "node:http";
import selfsigned from "selfsigned";
import QRCode from "qrcode";

const PLUGIN = "dsh-mobile-access";

// ---------- 状态目录（$DSH_HOME/mobile-access，兼容性兜底） ----------

function defaultStateDir() {
  if (process.env.DSH_MOBILE_STATE_DIR) return process.env.DSH_MOBILE_STATE_DIR;
  return process.env.DSH_HOME
    ? join(process.env.DSH_HOME, "mobile-access")
    : join(homedir(), ".dsh", "mobile-access");
}
function certPath() {
  return resolve(defaultStateDir(), "cert.pem");
}
function keyPath() {
  return resolve(defaultStateDir(), "key.pem");
}

// ---------- 局域网检测 + CIDR ----------

function ipv4ToInt(ip) {
  const p = String(ip).split(".");
  return ((Number(p[0]) << 24) >>> 0) + ((Number(p[1]) << 16) >>> 0) + ((Number(p[2]) << 8) >>> 0) + Number(p[3]);
}
function intToIpv4(n) {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}
function netmaskToPrefix(mask) {
  let prefix = 0;
  for (const part of String(mask).split(".")) {
    let byte = Number(part);
    for (let bit = 7; bit >= 0; bit -= 1) {
      if ((byte & (1 << bit)) !== 0) prefix += 1;
      else return prefix;
    }
  }
  return prefix;
}
function cidrFor(address, netmask) {
  const ip = ipv4ToInt(address);
  const prefix = netmaskToPrefix(netmask);
  const network = (ip & (~0 << (32 - prefix))) >>> 0;
  return `${intToIpv4(network)}/${prefix}`;
}
function pickLan() {
  const table = networkInterfaces();
  for (const entries of Object.values(table)) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) {
        return { address: entry.address, netmask: entry.netmask, cidr: cidrFor(entry.address, entry.netmask) };
      }
    }
  }
  return null;
}

// ---------- 状态持久化 ----------

function statePath() {
  return join(defaultStateDir(), "state.json");
}
function readState() {
  try {
    return JSON.parse(readFileSync(statePath(), "utf8"));
  } catch {
    return {};
  }
}
function writeState(state) {
  mkdirSync(defaultStateDir(), { recursive: true });
  writeFileSync(statePath(), JSON.stringify(state, null, 2));
}

function hashPin(pin, salt) {
  return createHash("sha256").update(`${salt}:${pin}`).digest("hex");
}
function verifyPin(pin, salt, expected) {
  if (typeof pin !== "string" || pin.length < 4 || pin.length > 64) return false;
  const actual = Buffer.from(hashPin(pin, salt), "hex");
  const want = Buffer.from(expected, "hex");
  if (actual.length !== want.length) return false;
  return timingSafeEqual(actual, want);
}

/** 诊断：把一次失败的登录尝试写入状态目录，便于确认手机端实际发送的 PIN。 */
function tryWriteLoginDebug(pin, salt) {
  try {
    const dir = defaultStateDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "login_debug.json"),
      JSON.stringify({
        at: new Date().toISOString(),
        pinLen: typeof pin === "string" ? pin.length : -1,
        pinSha256: createHash("sha256").update(String(pin)).digest("hex"),
        salt,
      }, null, 2),
    );
  } catch { /* ignore */ }
}

// ---------- HTTP 辅助 ----------

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}
function readJsonBody(req) {
  return new Promise((resolveBody, rejectBody) => {
    let data = "";
    req.on("data", (chunk) => { data += chunk; });
    req.on("end", () => {
      try { resolveBody(data ? JSON.parse(data) : {}); } catch { rejectBody(new Error("invalid JSON body")); }
    });
    req.on("error", rejectBody);
  });
}
/** 读取原始请求体文本（限长，避免内存滥用）。 */
function readTextBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolveBody, rejectBody) => {
    let data = "";
    let size = 0;
    req.on("data", (chunk) => {
      size += Buffer.byteLength(chunk);
      if (size > maxBytes) { rejectBody(new Error("body too large")); req.destroy(); return; }
      data += chunk;
    });
    req.on("end", () => resolveBody(data));
    req.on("error", rejectBody);
  });
}
/** 解析登录请求的 PIN：兼容 JSON 与标准 HTML 表单的 urlencoded 提交。 */
async function readLoginPin(req) {
  const ct = (req.headers["content-type"] ?? "").toLowerCase();
  const raw = await readTextBody(req);
  if (ct.includes("application/json")) {
    try { return String(JSON.parse(raw)?.pin ?? ""); } catch { return ""; }
  }
  try { return String(new URLSearchParams(raw).get("pin") ?? ""); } catch { return ""; }
}
function isSameOrigin(req) {
  const origin = req.headers?.origin;
  const host = req.headers?.host;
  if (!origin || !host) return true;
  try { return new URL(origin).host === host; } catch { return false; }
}
function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
function parseCookies(header) {
  const map = new Map();
  if (header === undefined) return map;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (!name || map.has(name)) continue;
    map.set(name, value);
  }
  return map;
}

// ---------- 证书 ----------

/** 读取或生成自签名证书（持久化到状态目录）。返回 { cert, key }。 */
async function ensureCert() {
  if (existsSync(certPath()) && existsSync(keyPath())) {
    return { cert: readFileSync(certPath(), "utf8"), key: readFileSync(keyPath(), "utf8") };
  }
  const pems = await selfsigned.generate(
    [{ name: "commonName", value: "dsh-mobile-access" }],
    { days: 400, keySize: 2048, algorithm: "sha256", keyUsage: ["digitalSignature", "keyEncipherment"], extKeyUsage: ["serverAuth"] },
  );
  mkdirSync(defaultStateDir(), { recursive: true });
  writeFileSync(certPath(), pems.cert);
  writeFileSync(keyPath(), pems.private);
  return { cert: pems.cert, key: pems.private };
}

// ---------- 网关：独立 HTTPS server + PIN 认证 + http-proxy ----------

const LOGIN_PATH = "/__mobile_login__";
const COOKIE_NAME = "dshmo";
const SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 天

class MobileGateway {
  constructor() {
    this.server = null;
    this.token = null;
    this.proxy = null;
    this.key = null;
    this.cert = null;
    this.port = null;
    this.dshPort = null;
    this.url = null;
    this.lanIp = null;
    this.cidr = null;
    this.enabled = false;
    this.error = null;
    /** 取 DSH 本进程启动 token 的回调（`() => string | undefined`）。 */
    this.resolveToken = null;
    /** 缓存的 DSH 浏览器会话 cookie（`dsh-auth-…=…`），null 表示尚未换取。 */
    this.dshCookie = null;
    /** 换取 cookie 的在途 Promise（single-flight，避免并发重复换取）。 */
    this.dshMint = null;
  }

  get running() {
    return this.server !== null;
  }

  async start({ pin, port, dshPort, resolveToken }) {
    const lan = pickLan();
    if (lan === null) throw new Error("未检测到局域网 IPv4 地址，请确认电脑已连接网络");

    // 访问 PIN：显式提供了则（重新）设置；未提供则复用已存的；两者皆无则报错。
    let state = readState();
    if (pin !== undefined && pin !== "") {
      if (typeof pin !== "string" || pin.length < 4) throw new Error("访问 PIN 至少 4 位");
      const salt = randomBytes(16).toString("hex");
      state = { ...state, salt, pinHash: hashPin(pin, salt) };
      writeState(state);
    } else if (typeof state.pinHash !== "string" || state.pinHash === "" || typeof state.salt !== "string" || state.salt === "") {
      throw new Error("请先在电脑上设置访问 PIN");
    }

    const { cert, key } = await ensureCert();
    this.cert = cert;
    this.key = key;
    this.port = port;
    this.dshPort = dshPort;
    this.lanIp = lan.address;
    this.cidr = lan.cidr;
    // PIN 会话 token 持久化：DSH 重启后手机上的网关 cookie 依然有效，不必重新输 PIN。
    let gwToken = typeof state.gatewayToken === "string" && state.gatewayToken.length >= 32 ? state.gatewayToken : null;
    if (gwToken === null) {
      gwToken = randomBytes(32).toString("hex");
      writeState({ ...readState(), gatewayToken: gwToken });
    }
    this.token = gwToken;
    this.resolveToken = typeof resolveToken === "function" ? resolveToken : null;
    this.dshCookie = null;
    this.dshMint = null;
    this.upstream = `http://127.0.0.1:${String(dshPort)}`;

    const server = createHttpsServer({ key: this.key, cert: this.cert }, (req, res) => {
      this.#handleHttp(req, res);
    });
    server.on("upgrade", (req, socket, head) => {
      this.#handleUpgrade(req, socket, head).catch(() => { try { socket.destroy(); } catch { /* ignore */ } });
    });

    await new Promise((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(this.port, "0.0.0.0", () => {
        server.off("error", rejectListen);
        server.on("error", (err) => { this.error = String(err?.message ?? err); });
        resolveListen();
      });
    });

    this.server = server;
    this.enabled = true;
    this.url = `https://${this.lanIp}:${String(this.port)}`;

    writeState({
      ...readState(),
      enabled: true,
      port: this.port,
      lanIp: this.lanIp,
      cidr: this.cidr,
    });

    return this.status();
  }

  stop() {
    if (this.server !== null) {
      try { this.server.close(); } catch { /* ignore */ }
      try { this.server.closeAllConnections(); } catch { /* ignore */ }
      this.server = null;
    }
    this.enabled = false;
    this.token = null;
    this.url = null;
    const state = readState();
    state.enabled = false;
    writeState(state);
  }

  setPin(pin) {
    if (typeof pin !== "string" || pin.length < 4) throw new Error("PIN 至少 4 位");
    const state = readState();
    const salt = randomBytes(16).toString("hex");
    state.salt = salt;
    state.pinHash = hashPin(pin, salt);
    writeState(state);
    return { ok: true };
  }

  /** 公开的状态快照（供控制路由返回，含二维码）。 */
  async status() {
    const state = readState();
    const qr = this.url ? await QRCode.toDataURL(this.url, { width: 240, margin: 1, errorCorrectionLevel: "M" }) : null;
    return {
      enabled: this.enabled,
      running: this.running,
      url: this.url,
      lanIp: this.lanIp,
      cidr: this.cidr,
      port: this.port,
      pinSet: typeof state.pinHash === "string" && state.pinHash.length > 0,
      dshSession: this.dshCookie !== null,
      error: this.error,
      qrDataUrl: qr,
    };
  }

  #isAuthenticated(req) {
    if (this.token === null) return false;
    const value = parseCookies(req.headers.cookie).get(COOKIE_NAME);
    if (value === undefined) return false;
    const a = Buffer.from(value);
    const b = Buffer.from(this.token);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  async #handleHttp(req, res) {
    let pathname;
    try { pathname = new URL(req.url ?? "/", "http://x").pathname; } catch { pathname = "/"; }
    if (pathname === LOGIN_PATH) return this.#handleLogin(req, res);
    if (!this.#isAuthenticated(req)) return this.#serveLogin(res, null);
    await this.#forward(req, res, false);
  }

  /** 改写为 DSH 后端（loopback 同源），白名单透传，并注入 DSH 会话 cookie。 */
  #requestHeaders(req, dshCookie) {
    const upstream = `http://127.0.0.1:${this.dshPort}`;
    const headers = { host: `127.0.0.1:${this.dshPort}` };
    if (req.headers.origin !== undefined) headers.origin = upstream;
    if (req.headers["sec-fetch-site"] !== undefined) headers["sec-fetch-site"] = "same-origin";
    for (const name of ["accept","accept-encoding","accept-language","content-type","content-length","if-match","if-modified-since","if-none-match","if-unmodified-since","range","user-agent"]) {
      const value = req.headers[name];
      if (value !== undefined) headers[name] = value;
    }
    // 手机侧的 cookie 不透传：DSH 只认网关服务端换取到的签名会话 cookie。
    if (typeof dshCookie === "string" && dshCookie !== "") headers.cookie = dshCookie;
    return headers;
  }

  /** DSH 浏览器会话 cookie；无缓存时用进程启动 token 换取（并发合并为一次）。 */
  async #dshSessionCookie(force = false) {
    if (force) { this.dshCookie = null; this.dshMint = null; }
    if (this.dshCookie !== null) return this.dshCookie;
    if (this.dshMint !== null) return this.dshMint;
    const task = this.#mintDshSession()
      .catch((err) => { this.error = String(err?.message ?? err); return null; })
      .finally(() => { this.dshMint = null; });
    this.dshMint = task;
    return task;
  }

  /**
   * 用本进程启动 token 向 DSH 换取签名 cookie。
   * DSH 只在 `GET /?token=<进程 token>` 时下发 `dsh-auth-<authority>` cookie，本函数只取
   * 该 Set-Cookie，不跟随重定向，也不把 token 暴露给手机。
   */
  async #mintDshSession() {
    const token = this.resolveToken?.() ?? "";
    if (token === "") {
      this.error = "无法获取 DSH 启动 token（connection 服务不可用）";
      return null;
    }
    const cookie = await new Promise((resolveMint, rejectMint) => {
      const upReq = httpRequest({
        host: "127.0.0.1",
        port: this.dshPort,
        method: "GET",
        path: `/?token=${encodeURIComponent(token)}`,
        headers: { host: `127.0.0.1:${this.dshPort}` },
      }, (upRes) => {
        const raw = upRes.headers["set-cookie"];
        upRes.resume();
        const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
        for (const line of list) {
          const at = line.indexOf("=");
          if (at <= 0) continue;
          const name = line.slice(0, at).trim();
          if (!name.startsWith("dsh-auth-")) continue;
          const semi = line.indexOf(";");
          const value = (semi === -1 ? line.slice(at + 1) : line.slice(at + 1, semi)).trim();
          if (value !== "") { resolveMint(`${name}=${value}`); return; }
        }
        resolveMint(null);
      });
      upReq.on("error", rejectMint);
      upReq.end();
    });
    this.dshCookie = cookie;
    this.error = cookie === null ? "DSH 未接受启动 token，未能建立浏览器会话" : null;
    return cookie;
  }

  /**
   * HTTP 流式转发：立即管道，绝不缓冲（消除「整段延迟」）。
   * DSH 回 401 说明缓存的服务端会话已失效（重启换端口 / cookie 过期）：清缓存后
   * 重新换取一次并重放（仅 GET/HEAD 无请求体可安全重放）；其它方法的 401 只清缓存，
   * 由客户端下一次请求触发自动恢复。
   */
  async #forward(req, res, retried) {
    const dshCookie = await this.#dshSessionCookie();
    const upReq = httpRequest({
      host: "127.0.0.1",
      port: this.dshPort,
      method: req.method,
      path: req.url,
      headers: this.#requestHeaders(req, dshCookie),
    });
    upReq.on("response", (upRes) => {
      const status = upRes.statusCode ?? 502;
      const replayable = req.method === "GET" || req.method === "HEAD";
      if (status === 401 && !retried) {
        upRes.resume();
        if (!replayable) this.#dshSessionCookie(true).catch(() => undefined);
        else this.#dshSessionCookie(true).then(() => this.#forward(req, res, true)).catch(() => {
          try { res.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" }); res.end("DSH 会话桥接失败"); } catch { /* ignore */ }
        });
        return;
      }
      const headers = { ...upRes.headers };
      delete headers["connection"];
      delete headers["transfer-encoding"];
      delete headers["content-length"];
      res.writeHead(status, headers);
      if (req.method === "HEAD") { res.end(); return; }
      upRes.pipe(res); // 流式、即时
    });
    upReq.on("error", (err) => {
      this.error = String(err?.message ?? err);
      try { res.writeHead(502, { "Content-Type": "text/plain" }); res.end("网关错误"); } catch { /* ignore */ }
    });
    if (req.method === "GET" || req.method === "HEAD") upReq.end();
    else req.pipe(upReq);
  }

  /** WebSocket 双向流式转发（即时，不缓冲）。 */
  async #handleUpgrade(req, socket, head) {
    if (!this.#isAuthenticated(req)) { socket.destroy(); return; }
    const dshCookie = await this.#dshSessionCookie();
    const headers = {
      ...this.#requestHeaders(req, dshCookie),
      connection: "upgrade",
      upgrade: req.headers.upgrade ?? "websocket",
    };
    for (const name of ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"]) {
      const value = req.headers[name];
      if (value !== undefined) headers[name] = value;
    }
    const upReq = httpRequest({
      host: "127.0.0.1",
      port: this.dshPort,
      method: "GET",
      path: req.url,
      headers,
    });
    upReq.on("upgrade", (upRes, upSocket, upHead) => {
      // 后端返回 101 时，node 已消费响应头；须把状态行+头回写给客户端，客户端才识别升级成功。
      const statusLine = `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage || "Switching Protocols"}\r\n`;
      const headerLines = Object.entries(upRes.headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}\r\n`).join("");
      socket.write(statusLine + headerLines + "\r\n");
      if (head !== undefined && head.length) upSocket.write(head);
      if (upHead !== undefined && upHead.length) socket.write(upHead);
      socket.pipe(upSocket);
      upSocket.pipe(socket);
      const cleanup = () => { try { socket.destroy(); } catch {} try { upSocket.destroy(); } catch {} };
      socket.on("error", cleanup);
      upSocket.on("error", cleanup);
      socket.on("close", () => { try { upSocket.end(); } catch {} });
      upSocket.on("close", () => { try { socket.end(); } catch {} });
    });
    upReq.on("response", (res) => {
      if (res.statusCode === 401) this.#dshSessionCookie(true).catch(() => undefined);
      res.destroy();
      socket.destroy();
    });
    upReq.on("error", () => { socket.destroy(); });
    upReq.end();
  }

  async #handleLogin(req, res) {
    if (req.method !== "POST") { res.writeHead(405, { allow: "POST" }); res.end(); return; }
    const state = readState();
    const pin = await readLoginPin(req);
    const salt = state.salt ?? "";
    const expected = state.pinHash ?? "";
    if (salt === "" || expected === "") {
      return this.#serveLogin(res, "尚未设置访问 PIN，请先在电脑上设置");
    }
    if (!verifyPin(pin, salt, expected)) {
      tryWriteLoginDebug(pin, salt);
      return this.#serveLogin(res, `PIN 不正确，请重试（电脑收到 ${pin.length} 位）`);
    }
    if (this.token === null) return this.#serveLogin(res, "网关未运行");
    const cookie = `${COOKIE_NAME}=${this.token}; Path=/; Max-Age=${SESSION_COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`;
    res.writeHead(302, {
      "Location": "/",
      "Set-Cookie": cookie,
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none';",
    });
    res.end();
  }

  #serveLogin(res, error) {
    const errorHtml = error ? `<p class="err">${escapeHtml(error)}</p>` : "";
    const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>DSH 移动访问</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  background:#0f172a;color:#e2e8f0;padding:24px}
.card{width:100%;max-width:380px;background:#1e293b;border:1px solid rgba(148,163,184,.25);
  border-radius:14px;padding:28px 26px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
h1{font-size:20px;margin:0 0 6px}
p.sub{color:#94a3b8;font-size:13px;line-height:1.5;margin:0 0 22px}
label{display:block;font-size:13px;color:#cbd5e1;margin-bottom:6px}
input[type=password]{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:8px;
  border:1px solid rgba(148,163,184,.4);background:#0f172a;color:#f1f5f9;font-size:16px}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:8px;background:#3b82f6;
  color:#fff;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#2563eb}
.err{color:#f87171;font-size:13px;margin:0 0 14px}
.foot{margin-top:18px;color:#64748b;font-size:12px;line-height:1.5}
</style>
</head>
<body>
  <form class="card" id="loginForm" method="POST" action="${LOGIN_PATH}">
    <h1>DSH 移动访问</h1>
    <p class="sub">此网关受 PIN 保护。请输入访问 PIN 以继续使用电脑上的 DSH。</p>
    ${errorHtml}
    <label for="pin">访问 PIN</label>
    <input id="pin" name="pin" type="password" inputmode="numeric" autocomplete="off" autofocus required>
    <button type="submit">进入</button>
    <p class="foot">请在受信任的网络中访问。</p>
  </form>
  <script>
    (function () {
      var form = document.getElementById("loginForm");
      var input = document.getElementById("pin");
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        var pin = input ? input.value : "";
        fetch(form.getAttribute("action"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pin: pin }),
          credentials: "same-origin",
        }).then(function (r) {
          if (r.redirected) { window.location.assign(r.url); return; }
          r.text().then(function (t) { document.open(); document.write(t); document.close(); });
        }).catch(function () { alert("提交失败：请确认已信任此站点证书后再试"); });
      });
    })();
  </script>
</body>
</html>`;
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self';",
    });
    res.end(html);
  }
}

// ---------- cordis 插件 ----------

export const name = PLUGIN;
export const inject = ["webServer"];

/**
 * 取本进程的 DSH 启动 token：client-connection 的 `authenticatedUrl()` 会把进程
 * token 作为唯一参数写进根 URL。惰性求值，宿主未提供 connection 服务时返回空串。
 */
function launchTokenResolver(ctx) {
  return () => {
    try {
      const connection = ctx.get("connection");
      if (connection === undefined || typeof connection.authenticatedUrl !== "function") return "";
      const url = new URL(connection.authenticatedUrl("http://127.0.0.1/"));
      return url.searchParams.get("token") ?? "";
    } catch {
      return "";
    }
  };
}

export function apply(ctx) {
  const gateway = new MobileGateway();
  const resolveToken = launchTokenResolver(ctx);

  ctx.inject(["webServer"], (host) => {
    host.effect(() => {
      const disposers = [];
      const dshPort = () => Number(host.webServer.port) || 3080;

      const statusHandler = async (req, res) => {
        if (req.method !== "GET") { res.writeHead(405); res.end(); return; }
        sendJson(res, 200, await gateway.status());
      };

      const enableHandler = async (req, res) => {
        if (req.method !== "POST") { res.writeHead(405); res.end(); return; }
        if (!isSameOrigin(req)) { sendJson(res, 403, { ok: false, error: "forbidden" }); return; }
        try {
          const body = await readJsonBody(req);
          const port = Number(body.port ?? 3443);
          if (!Number.isInteger(port) || port < 1 || port > 65535) {
            sendJson(res, 400, { ok: false, error: "端口无效" }); return;
          }
          const result = await gateway.start({ pin: body.pin, port, dshPort: dshPort(), resolveToken });
          sendJson(res, 200, result);
        } catch (err) {
          sendJson(res, 400, { ok: false, error: String(err?.message ?? err) });
        }
      };

      const disableHandler = async (req, res) => {
        if (req.method !== "POST") { res.writeHead(405); res.end(); return; }
        if (!isSameOrigin(req)) { sendJson(res, 403, { ok: false, error: "forbidden" }); return; }
        gateway.stop();
        sendJson(res, 200, { ok: true, enabled: false });
      };

      const pinHandler = async (req, res) => {
        if (req.method !== "POST") { res.writeHead(405); res.end(); return; }
        if (!isSameOrigin(req)) { sendJson(res, 403, { ok: false, error: "forbidden" }); return; }
        try {
          const body = await readJsonBody(req);
          sendJson(res, 200, gateway.setPin(body.pin));
        } catch (err) {
          sendJson(res, 400, { ok: false, error: String(err?.message ?? err) });
        }
      };

      disposers.push(host.webServer.register({ kind: "exact", path: "/dsh-mobile-access/status", handler: statusHandler }));
      disposers.push(host.webServer.register({ kind: "exact", path: "/dsh-mobile-access/enable", handler: enableHandler }));
      disposers.push(host.webServer.register({ kind: "exact", path: "/dsh-mobile-access/disable", handler: disableHandler }));
      disposers.push(host.webServer.register({ kind: "exact", path: "/dsh-mobile-access/pin", handler: pinHandler }));

      // 自动恢复上次的开启状态：DSH 升级/重启后手机端无需重新扫码开启。
      const saved = readState();
      if (saved.enabled === true && !gateway.running) {
        const port = Number(saved.port ?? 3443);
        if (Number.isInteger(port) && port > 0 && port <= 65535) {
          gateway.start({ port, dshPort: dshPort(), resolveToken }).catch((err) => {
            gateway.error = String(err?.message ?? err);
          });
        }
      }

      return () => { for (const dispose of disposers) if (typeof dispose === "function") dispose(); };
    }, "dsh-mobile-access: control routes");
  });

  ctx.effect(() => () => gateway.stop(), "dsh-mobile-access: teardown");
}

// 供测试/复用导出（不影响 cordis 加载）。
export { MobileGateway, ensureCert, LOGIN_PATH, COOKIE_NAME, verifyPin };
