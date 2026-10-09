/* dsh-mobile-access client half.
 * 设置栏「移动访问」分区：手机扫码、局域网访问网关的开启/关闭、PIN 设置。
 */
window.__ModuleLoader__.load({
  id: "dsh-mobile-access",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    var react = require("react");
    var inject = ["slots"];

    function apiUrl(path) {
      var rel = String(path).replace(/^\/+/, "");
      if (typeof document === "undefined") return "/" + rel;
      return new URL(rel, document.baseURI).pathname;
    }

    var S = {
      root: { display: "flex", flexDirection: "column", gap: "10px", padding: "2px 0 8px" },
      row: { display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" },
      label: { fontSize: "12px", color: "inherit", fontWeight: 600, minWidth: "72px" },
      muted: { fontSize: "11px", color: "var(--dsw-alias-label-secondary,#64748b)" },
      ok: { fontSize: "11px", color: "#16a34a" },
      warn: { fontSize: "11px", color: "#e5a142" },
      err: { fontSize: "11px", color: "#e5534b" },
      input: { padding: "4px 8px", borderRadius: "6px", border: "1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.25))", background: "var(--dsw-alias-bg-layer-2,rgba(127,127,127,.06))", color: "inherit", fontSize: "12px" },
      btn: { padding: "4px 12px", borderRadius: "6px", border: "1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.25))", background: "var(--dsw-alias-bg-layer-2,rgba(127,127,127,.06))", color: "inherit", fontSize: "12px", cursor: "pointer" },
      btnPrimary: { padding: "4px 12px", borderRadius: "6px", border: "1px solid var(--dsw-alias-brand-primary,#4aa3ff)", background: "var(--dsw-alias-brand-soft,rgba(74,163,255,.12))", color: "var(--dsw-alias-brand-primary,#4aa3ff)", fontSize: "12px", cursor: "pointer" },
      qr: { width: "180px", height: "180px", imageRendering: "pixelated", border: "1px solid var(--dsw-alias-border-l1,rgba(127,127,127,.25))", borderRadius: "8px" },
      url: { fontSize: "12px", color: "var(--dsw-alias-label-secondary,#64748b)", wordBreak: "break-all" },
    };
    var h = react.createElement;

    function MobileAccessSection() {
      var st = react.useState({ loading: true, data: null, error: null });
      var status = st[0]; var setStatus = st[1];
      var pin = react.useState(""); var pinState = pin[0]; var setPin = pin[1];
      var port = react.useState("3443"); var portState = port[0]; var setPort = port[1];
      var busy = react.useState(false); var busyState = busy[0]; var setBusy = busy[1];
      var msg = react.useState(null); var msgState = msg[0]; var setMsg = msg[1];

      var load = react.useCallback(function () {
        setStatus(function (prev) { return { loading: true, data: prev.data, error: null }; });
        return fetch(apiUrl("/dsh-mobile-access/status"))
          .then(function (r) { return r.json(); })
          .then(function (d) { setStatus({ loading: false, data: d, error: null }); })
          .catch(function (e) { setStatus({ loading: false, data: null, error: String(e) }); });
      }, []);

      react.useEffect(function () { load(); }, [load]);

      var post = react.useCallback(function (path, body) {
        return fetch(apiUrl(path), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body || {}),
        }).then(function (r) { return r.json(); });
      }, []);

      var doEnable = react.useCallback(function () {
        if (busyState) return;
        setBusy(true); setMsg(null);
        post("/dsh-mobile-access/enable", { port: Number(portState) })
          .then(function (d) {
            if (d && d.ok === false) { setMsg("启用失败：" + (d.error || "未知")); }
            else { setMsg(d && d.enabled ? "已开启，手机扫码访问下方地址" : "已开启"); }
            return load();
          })
          .catch(function (e) { setMsg("启用失败：" + String(e)); })
          .finally(function () { setBusy(false); });
      }, [busyState, portState, post, load]);

      var doDisable = react.useCallback(function () {
        if (busyState) return;
        setBusy(true); setMsg(null);
        post("/dsh-mobile-access/disable")
          .then(function () { setMsg("已关闭移动访问"); return load(); })
          .catch(function (e) { setMsg("关闭失败：" + String(e)); })
          .finally(function () { setBusy(false); });
      }, [busyState, post, load]);

      var doSetPin = react.useCallback(function () {
        if (!pinState) { setMsg("请输入新的 PIN"); return; }
        post("/dsh-mobile-access/pin", { pin: pinState })
          .then(function (d) { setMsg(d && d.ok === false ? "设置失败：" + (d.error || "") : "PIN 已保存，请点击『开启局域网访问』"); })
          .catch(function (e) { setMsg("设置失败：" + String(e)); });
      }, [pinState, post]);

      var data = status.data;
      var enabled = !!(data && data.enabled);

      return h("div", { style: S.root },
        h("div", { style: S.row }, h("span", { style: S.label }, "状态"),
          status.loading ? h("span", { style: S.muted }, "读取中…")
            : (status.error
              ? h("span", { style: S.err }, "读取失败：" + status.error)
              : h("span", { style: enabled ? S.ok : S.muted }, enabled ? "已开启" : "未开启"))),
        data && data.lanIp
          ? h("div", { style: S.row }, h("span", { style: S.label }, "局域网"), h("span", { style: S.url }, data.lanIp + (data.cidr ? "（" + data.cidr + "）" : "")))
          : null,
        data && data.enabled && data.url
          ? h("div", { style: S.row }, h("span", { style: S.label }, "访问地址"), h("span", { style: S.url }, data.url))
          : null,
        data && data.enabled && data.qrDataUrl
          ? h("div", { style: S.row }, h("span", { style: S.label }, "扫码"), h("img", { style: S.qr, src: data.qrDataUrl, alt: "手机扫码访问 DSH" }))
          : null,

        h("div", { style: S.row },
          h("span", { style: S.label }, "访问 PIN"),
          h("input", { style: S.input, type: "password", value: pinState, placeholder: "至少 4 位", onChange: function (e) { setPin(e.target.value); } })),
        h("div", { style: S.row },
          h("span", { style: S.label }, "端口"),
          h("input", { style: { ...S.input, width: "72px" }, value: portState, onChange: function (e) { setPort(e.target.value); } })),
        h("div", { style: S.row },
          enabled
            ? h("button", { style: S.btn, onClick: doDisable, disabled: busyState }, busyState ? "处理中…" : "关闭移动访问")
            : h("button", { style: S.btnPrimary, onClick: doEnable, disabled: busyState }, busyState ? "开启中…" : "开启局域网访问")),
        h("div", { style: S.row }, h("span", { style: S.label }, "PIN 管理"), h("button", { style: S.btn, onClick: doSetPin }, "更新 PIN")),
        msgState ? h("div", { style: S.muted }, msgState) : null,
        h("div", { style: S.muted }, "说明：开启后手机与电脑需在同一局域网；手机用浏览器打开上方地址，首次输入访问 PIN 并信任自签名证书后即可使用。请仅在信任的网络中开启。"));
    }

    function apply(ctx) {
      ctx.slots.inject("settings.section", function () {
        return ctx.slots.register({
          name: "settings.section",
          id: "dsh-mobile-access",
          order: 50,
          label: function () { return "移动访问"; },
        }, function () { return h(MobileAccessSection); });
      });
    }

    exports.name = "dsh-mobile-access";
    exports.inject = inject;
    exports.apply = apply;
    return module.exports;
  },
});
