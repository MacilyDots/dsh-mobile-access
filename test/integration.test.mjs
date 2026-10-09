// 端到端集成测试（模拟真实用户流程）：先设 PIN，再开启（复用已存 PIN），手机用该 PIN 登录。
//
// 状态目录指向系统临时目录：既不读写 $DSH_HOME，也不会改掉真实网关的 PIN。
import { createServer as httpServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "dshmo-itest-"));
process.env.DSH_MOBILE_STATE_DIR = TMP;
const { MobileGateway, LOGIN_PATH } = await import("../index.js");

const BACKEND_PORT = 3098;
const GW_PORT = 3450;

const results = [];
function check(label, cond, detail = "") {
  results.push({ label, pass: Boolean(cond) });
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? "  — " + detail : ""}`);
}

// --- 模拟 DSH web server：仅需一个可被代理的响应 ---
const backend = httpServer((req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ trusted: true, path: req.url }));
});
await new Promise((r) => backend.listen(BACKEND_PORT, "127.0.0.1", r));

function req(method, path, { body, cookie, origin, form } = {}) {
  return new Promise((resolve, reject) => {
    const r = httpsRequest({ hostname: "127.0.0.1", port: GW_PORT, path, method, rejectUnauthorized: false }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on("error", reject);
    if (cookie) r.setHeader("Cookie", cookie);
    if (origin) r.setHeader("Origin", origin);
    if (form) {
      r.setHeader("Content-Type", "application/x-www-form-urlencoded");
      r.write(new URLSearchParams(body).toString());
    } else if (body !== undefined) {
      r.setHeader("Content-Type", "application/json");
      r.write(JSON.stringify(body));
    }
    r.end();
  });
}

const gw = new MobileGateway();

// A) 先设置 PIN
gw.setPin("1234");
check("setPin('1234') 成功", true);

// B) 开启（不传 pin，复用已存）
await gw.start({ port: GW_PORT, dshPort: BACKEND_PORT });
check("start() 复用已存 PIN 并给出访问地址", typeof gw.url === "string" && gw.url.startsWith("https://"), gw.url);

// C) 手机用同一 PIN（HTML form）登录 → 应 302 成功
const okLogin = await req("POST", LOGIN_PATH, { form: true, body: { pin: "1234" } });
check("正确 PIN 登录 → 302", okLogin.status === 302, `status=${okLogin.status}`);
const sc = okLogin.headers["set-cookie"];
const cookie = (Array.isArray(sc) ? sc[0] : String(sc || "")).split(";")[0];

// F) 带 cookie 反向代理到后端
const prox = await req("GET", "/api/x", { cookie });
check("带 cookie 反向代理到后端", prox.status === 200 && prox.body.includes('"trusted":true'), `status=${prox.status} body=${prox.body.slice(0, 60)}`);

// D) 手机用错误 PIN → 应拒绝（登录页）
const badLogin = await req("POST", LOGIN_PATH, { form: true, body: { pin: "9999" } });
check("错误 PIN 被拒绝", badLogin.status === 200 && badLogin.body.includes("PIN 不正确"), `status=${badLogin.status}`);

gw.stop();

// E) 未设置 PIN 就开启 → 应明确报错（先清空状态目录，确保真的没有已存 PIN）
rmSync(TMP, { recursive: true, force: true });
const gw2 = new MobileGateway();
let threw = null;
try {
  await gw2.start({ port: GW_PORT + 1, dshPort: BACKEND_PORT });
} catch (e) { threw = e; }
check("未设 PIN 就开启 → 明确抛错", threw !== null, threw ? threw.message : "UNEXPECTED (no throw)");
try { gw2.stop(); } catch { /* 未启动成功，忽略 */ }

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} 通过`);
process.exit(failed.length === 0 ? 0 : 1);
