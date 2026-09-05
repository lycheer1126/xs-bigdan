/* ============ xs-bigdan console 框架 ============
 * 模块契约: 每个模块在 /static/modules/<key>.js 中注册
 *   window.XSModules[key] = { mount(el), unmount() }
 * 导航由 /api/modules 驱动，前端动态加载模块脚本 —— 加模块零框架改动。
 */
"use strict";

const XS = (() => {
  const ICONS = {
    target: "◎", archive: "▤", sliders: "☰", shield: "◈",
    info: "ℹ", alert: "⚠", bug: "⌬", web: "↗", doc: "▤", folder: "▣",
  };
  const state = { modules: [], cur: null, timers: [], scripts: {} };

  async function api(path, opts = {}) {
    const resp = await fetch(path, {
      method: opts.method || "GET",
      headers: opts.json ? { "Content-Type": "application/json" } : {},
      body: opts.json ? JSON.stringify(opts.json) : undefined,
    });
    const data = await resp.json().catch(() => ({ detail: resp.statusText }));
    if (!resp.ok) {
      let msg = data.detail || `HTTP ${resp.status}`;
      if (Array.isArray(data.detail)) {
        msg = data.detail.map(d =>
          (d.loc ? d.loc.slice(1).join(".") + ": " : "") + (d.msg || JSON.stringify(d))).join("; ");
      }
      throw new Error(msg);
    }
    return data;
  }

  function toast(msg, type = "info", ms = 3200) {
    const wrap = document.getElementById("toasts");
    const el = document.createElement("div");
    el.className = "toast" + (type === "error" ? " err" : type === "ok" ? " ok" : "");
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => el.remove(), ms);
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function md(text) {
    if (window.marked) {
      try { return marked.parse(String(text ?? "")); } catch { /* fallthrough */ }
    }
    return esc(text).replace(/\n/g, "<br>");
  }

  function fmtBytes(n) {
    if (n == null) return "-";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }

  function fmtDur(sec) {
    if (sec == null) return "-";
    const m = Math.floor(sec / 60), s = Math.round(sec % 60);
    return m > 0 ? `${m}m${s}s` : `${s}s`;
  }

  function stateBadge(st) {
    const map = {
      running: "运行中", done: "已完成", timed_out: "超时", interrupted: "中断", created: "已创建",
      blocked: "待人工", queued: "排队中",
    };
    return `<span class="badge ${st}">${map[st] || st}</span>`;
  }

  function modal(html) {
    const mask = document.getElementById("modal-mask");
    mask.hidden = false;
    mask.innerHTML = `<div class="modal">${html}</div>`;
    mask.querySelector(".modal-head .x")?.addEventListener("click", () => mask.hidden = true);
    mask.addEventListener("click", e => { if (e.target === mask) mask.hidden = true; });
    return mask;
  }

  // 报告阅读弹窗：宽屏 + 全屏切换，任务页与历史页共用
  function reportModal(name, content) {
    const mask = modal(`
      <div class="modal wide report-modal">
      <div class="modal-head">
        <span style="font-weight:700;font-size:14px">${esc(name)}</span>
        <span class="spacer" style="flex:1"></span>
        <button class="btn sm" id="rpt-fs" title="全屏/退出全屏">⛶ 全屏</button>
        <span class="x" style="cursor:pointer;margin-left:12px;font-size:17px" id="rpt-close">✕</span>
      </div>
      <div class="modal-body" style="max-height:calc(92vh - 110px);overflow:auto"><div class="md-body">${md(content)}</div></div>
      <div class="modal-foot">
        <button class="btn" id="md-copy">复制原文</button>
        <button class="btn primary" id="md-close">关闭</button>
      </div>`);
    mask.querySelector("#rpt-close").addEventListener("click", () => mask.hidden = true);
    mask.querySelector("#md-close").addEventListener("click", () => mask.hidden = true);
    const modalEl = mask.querySelector(".modal");
    mask.querySelector("#rpt-fs").addEventListener("click", () => {
      const isFs = modalEl.style.position === "fixed";
      modalEl.style.cssText = isFs ? "" :
        "position:fixed;inset:0;width:100vw;height:100vh;max-height:100vh;border-radius:0;z-index:9999;overflow:auto";
      mask.querySelector("#rpt-fs").textContent = isFs ? "⛶ 全屏" : "✕ 退出全屏";
    });
    mask.querySelector("#md-copy").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(content); toast("报告原文已复制", "ok"); }
      catch { toast("复制失败", "error"); }
    });
    return mask;
  }

  function poll(fn, ms) {
    const id = setInterval(fn, ms);
    state.timers.push(id);
    return id;
  }

  function clearTimers() {
    state.timers.forEach(clearInterval);
    state.timers = [];
  }

  async function loadModule(key) {
    if (!state.scripts[key]) {
      const src = `/static/modules/${key}.js?v=${Date.now()}`;
      await new Promise((res, rej) => {
        const s = document.createElement("script");
        s.src = src;
        s.onload = res;
        s.onerror = () => rej(new Error(`模块脚本加载失败: ${src}`));
        document.head.appendChild(s);
        state.scripts[key] = true;
      });
    }
  }

  async function renderNav() {
    const nav = document.getElementById("nav");
    nav.innerHTML = state.modules.map(m => `
      <div class="nav-item" data-key="${esc(m.key)}" title="${esc(m.desc || "")}">
        <span class="nav-ico">${ICONS[m.icon] || "▪"}</span>${esc(m.title)}
      </div>`).join("");
    nav.querySelectorAll(".nav-item").forEach(el => {
      el.addEventListener("click", () => { location.hash = "#/" + el.dataset.key; });
    });
  }

  async function route() {
    const parts = (location.hash || "#/tasks").replace(/^#\//, "").split("/");
    const key = parts[0] || "tasks";
    const mod = state.modules.find(m => m.key === key);
    if (!mod) { location.hash = "#/tasks"; return; }
    const view = document.getElementById("view");
    document.querySelectorAll(".nav-item").forEach(el =>
      el.classList.toggle("active", el.dataset.key === key));
    clearTimers();
    // 先卸载旧模块（清理原生 setInterval 等，避免其轮询重写新页面内容）
    if (state.cur && window.XSModules[state.cur]?.unmount) {
      try { window.XSModules[state.cur].unmount(); } catch { /* ignore */ }
    }
    state.cur = key;
    view.innerHTML = "";
    try {
      await loadModule(key);
      const inst = window.XSModules[key];
      if (!inst) throw new Error(`前端模块未注册: ${key}`);
      view.innerHTML = `<div class="view-loading">模块加载中…</div>`;
      inst.mount(view);
    } catch (e) {
      view.innerHTML = `<div class="empty">模块加载失败: ${esc(e.message)}</div>`;
    }
  }

  async function boot() {
    try {
      const h = await api("/api/health");
      document.getElementById("foot-run").classList.add("ok");
    } catch {
      document.getElementById("foot-run").classList.add("err");
    }
    const data = await api("/api/modules");
    state.modules = data.modules;
    document.getElementById("foot-ver").textContent = "v" + data.version;
    await renderNav();
    window.addEventListener("hashchange", route);
    route();
  }

  return { api, toast, esc, md, fmtBytes, fmtDur, stateBadge, modal, reportModal, poll, clearTimers, boot, ICONS };
})();

document.addEventListener("DOMContentLoaded", () => XS.boot().catch(e => {
  document.getElementById("view").innerHTML =
    `<div class="empty">控制台启动失败: ${XS.esc(e.message)}<br>请确认 webui 服务已启动</div>`;
}));
