/**
 * dsh-mobile-access 0.2.0 回归测试：DSH ≥0.1.5 浏览器会话认证的网关桥接。
 *
 * 用一个假的 DSH 后端复现 client-connection 的行为：
 *  - `GET /?token=<进程token>` → 303 + Set-Cookie: dsh-auth-…=<当前密钥>
 *  - 其它请求无有效 cookie → 401 `dsh web authentication required`
 * 然后验证网关：自动换取 cookie 并注入转发；密钥轮换后能 401 自愈。
 *
 * 状态目录走 DSH_MOBILE_STATE_DIR 临时目录，不触碰用户真实 PIN/网关状态。
 */
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "dshmo-"));
process.env.DSH_MOBILE_STATE_DIR = TMP;
const { MobileGateway } = await import("../index.js");

const TOKEN = "PROCESS_LAUNCH_TOKEN";
let cookieValue = "cookie-a";
let mintCalls = 0;
let unauthorized = 0;

// ---------- 假 DSH 后端 ----------
const backend = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/" && url.searchParams.get("token") === TOKEN) {
    mintCalls += 1;
    res.writeHead(303, {
      location: "/",
      "set-cookie": `dsh-auth-abc=${cookieValue}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict`,
    });
    res.end();
    return;
  }
  const cookie = req.headers.cookie ?? "";
  const ok = cookie.includes(`dsh-auth-abc=${cookieValue}`);
  if (!ok) {
    unauthorized += 1;
    res.writeHead(401, { "content-type": "text/plain; charset=utf-8" });
    res.end("dsh web authentication required; reopen the URL printed by dsh web.\n");
    return;
  }
  if (url.pathname.startsWith("/api")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, host: req.headers.host, path: url.pathname }));
    return;
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end("INDEX-OK");
});
await new Promise((r) => backend.listen(0, "127.0.0.1", r));
const backendPort = backend.address().port;

// ---------- 起网关 ----------
const gateway = new MobileGateway();
await gateway.start({ pin: "2468", port: 0, dshPort: backendPort, resolveToken: () => TOKEN });
const gwPort = gateway.server.address().port;

/** 发一个 HTTPS 请求（自签名证书 → 不校验），返回 { status, body, setCookie }。 */
function call({ method = "GET", path = "/", headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest({ host: "127.0.0.1", port: gwPort, method, path, headers, rejectUnauthorized: false }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, body: data, setCookie: res.headers["set-cookie"] ?? [], location: res.headers.location }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

const results = [];
function check(label, cond, detail = "") {
  results.push({ label, pass: Boolean(cond), detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? "  — " + detail : ""}`);
}

// 1) PIN 登录拿到网关会话 cookie
const login = await call({
  method: "POST",
  path: "/__mobile_login__",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ pin: "2468" }),
});
const gwCookie = (login.setCookie[0] ?? "").split(";")[0];
check("PIN 登录成功并下发网关 cookie", login.status === 302 && gwCookie.startsWith("dshmo="), `status=${login.status}`);

// 2) 未登录手机访问 → 输出 PIN 登录页
const anon = await call({ path: "/" });
check("未认证访问显示 PIN 登录页", anon.status === 200 && anon.body.includes("DSH 移动访问"), `status=${anon.status}`);

// 3) 已登录手机访问首页：网关应自动换取 DSH cookie 并拿到 200（修复的主路径）
const home = await call({ path: "/", headers: { cookie: gwCookie } });
check("已登录访问首页返回 DSH 内容（自动桥接会话）", home.status === 200 && home.body === "INDEX-OK", `status=${home.status} body=${home.body.slice(0, 40)}`);
check("网关确实向 DSH 换取过会话 cookie", mintCalls >= 1, `mintCalls=${mintCalls}`);
check("网关缓存了 DSH 会话 cookie", home.status === 200 && gateway.dshCookie !== null, `dshCookie=${gateway.dshCookie}`);

// 4) /api 请求同样被桥接（DSH 侧看到 loopback authority + 有效 cookie）
const api = await call({ method: "POST", path: "/api/test", headers: { cookie: gwCookie, "content-type": "application/json" }, body: "{}" });
let apiJson = null;
try { apiJson = JSON.parse(api.body); } catch { /* ignore */ }
check("POST /api 被桥接并返回 200", api.status === 200 && apiJson?.ok === true, `status=${api.status} body=${api.body.slice(0, 60)}`);
check("转发时 Host 改写为 loopback（DSH 信任围栏通过）", apiJson?.host === `127.0.0.1:${backendPort}`, `host=${apiJson?.host}`);

// 5) 缓存会话失效（DSH 轮换/换端口）→ 网关 401 自愈并重放
cookieValue = "cookie-b";
const before = mintCalls;
const healed = await call({ path: "/", headers: { cookie: gwCookie } });
check("DSH 会话失效后自动重新换取并恢复正常", healed.status === 200 && healed.body === "INDEX-OK", `status=${healed.status} body=${healed.body.slice(0, 40)}`);
check("重新换取确实发生过", mintCalls > before, `mintCalls ${before} → ${mintCalls}`);
check("过程中手机侧未收到 401", unauthorized >= 1, `DSH 401 次数=${unauthorized}（网关内部消化）`);

// 6) 并发首页请求只换取一次（single-flight）
cookieValue = "cookie-c";
gateway.dshCookie = null;
const burstBefore = mintCalls;
await Promise.all([0, 1, 2, 3, 4].map(() => call({ path: "/", headers: { cookie: gwCookie } })));
check("并发请求只换取一次会话 cookie", mintCalls - burstBefore === 1, `mint 次数=${mintCalls - burstBefore}`);

// 7) 未提供 token 时优雅降级（不得抛异常）
gateway.resolveToken = () => "";
gateway.dshCookie = null;
const degraded = await call({ path: "/", headers: { cookie: gwCookie } });
check("拿不到启动 token 时返回 401 而非崩溃", degraded.status === 401, `status=${degraded.status}`);

gateway.stop();
backend.close();

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} 通过`);
process.exit(failed.length === 0 ? 0 : 1);
