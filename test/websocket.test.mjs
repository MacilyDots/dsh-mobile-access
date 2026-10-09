// 验证网关 WebSocket 升级：后端要求 upgrade 请求必须带 sec-websocket-key。
//
// 状态目录指向系统临时目录：不读写 $DSH_HOME，也不会动真实网关状态。
import { createServer as httpServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "dshmo-ws-"));
process.env.DSH_MOBILE_STATE_DIR = TMP;
const { MobileGateway } = await import("../index.js");

const BACKEND = 3098;
const GW = 3451;
let backendSawKey = false;

const backend = httpServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
backend.on("upgrade", (req, socket, head) => {
  const key = req.headers["sec-websocket-key"];
  backendSawKey = Boolean(key);
  console.log("[backend] upgrade 收到, sec-websocket-key 存在:", backendSawKey);
  if (!key) { socket.destroy(); return; }
  const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  socket.on("data", (c) => socket.write(c)); // echo
});
await new Promise((r) => backend.listen(BACKEND, "127.0.0.1", r));

const gw = new MobileGateway();
await gw.start({ pin: "1234", port: GW, dshPort: BACKEND });

const key = createHash("sha1").update(String(Math.random())).digest("base64");
const cookie = "dshmo=" + gw.token;

const result = await new Promise((resolve) => {
  const timer = setTimeout(() => resolve({ ok: false, timeout: true, gwError: gw.error }), 5000);
  const upReq = httpsRequest({
    host: "127.0.0.1", port: GW, path: "/api/events.mux", method: "GET", rejectUnauthorized: false,
    headers: { connection: "upgrade", upgrade: "websocket", "sec-websocket-key": key, "sec-websocket-version": "13", Cookie: cookie },
  });
  upReq.on("upgrade", (res, socket, head) => {
    console.log("[client] upgrade 事件 status=", res.statusCode);
    socket.write("hello");
    socket.once("data", (c) => { clearTimeout(timer); console.log("[client] echo=", c.toString()); socket.destroy(); resolve({ ok: true, status: res.statusCode, echo: c.toString() }); });
  });
  upReq.on("response", (res) => { console.log("[client] response(未升级) status=", res.statusCode); res.on("data", () => {}); res.on("end", () => { clearTimeout(timer); resolve({ ok: false, status: res.statusCode }); }); });
  upReq.on("error", (e) => { clearTimeout(timer); console.log("[client] error=", e.message); resolve({ ok: false, err: e.message, gwError: gw.error }); });
  upReq.end();
});

const results = [];
function check(label, cond, detail = "") {
  results.push({ label, pass: Boolean(cond) });
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${detail ? "  — " + detail : ""}`);
}

check("网关接受 WebSocket 升级并透传 echo", result.ok === true && result.echo === "hello", JSON.stringify(result));
check("后端收到 sec-websocket-key（未被网关吞掉）", backendSawKey === true, `sawKey=${backendSawKey}`);

gw.stop();

const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} 通过`);
process.exit(failed.length === 0 ? 0 : 1);
