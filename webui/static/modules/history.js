/* ============ 模块: 历史报告 ============ */
"use strict";

window.XSModules = window.XSModules || {};

XSModules.history = (() => {
  let el = null;

  async function render() {
    if (!el) return;
    const data = await XS.api("/api/history/reports");
    el.innerHTML = `
      <div class="page-head">
        <h1>历史报告</h1>
        <span class="sub">runtime/outputs · 序号-站点.md 归档</span>
        <div class="head-actions">
          <button class="btn" id="h-refresh">刷新</button>
          <button class="btn" id="h-open">打开 outputs 目录</button>
        </div>
      </div>
      <div id="h-list">
        ${data.reports.length ? data.reports.map(r => `
          <div class="list-item">
            <span class="name" data-name="${XS.esc(r.name)}">${XS.esc(r.name)}</span>
            <span class="meta">${r.mtime} · ${XS.fmtBytes(r.size)}</span>
            <span class="spacer"></span>
            <button class="btn sm view-report" data-name="${XS.esc(r.name)}">查看</button>
          </div>`).join("") : `<div class="empty">暂无报告 — 任务运行结束后自动生成</div>`}
      </div>`;
    el.querySelector("#h-refresh").addEventListener("click", render);
    el.querySelector("#h-open").addEventListener("click", async () => {
      await XS.api("/api/history/open-outputs", { method: "POST" });
    });
    el.querySelectorAll(".view-report").forEach(b =>
      b.addEventListener("click", async () => {
        const r = await XS.api(`/api/history/reports/${encodeURIComponent(b.dataset.name)}`);
        const mask = XS.modal(`
          <div class="modal-head">${XS.esc(r.name)} <span class="x">✕</span></div>
          <div class="modal-body" style="max-height:72vh;overflow:auto"><div class="md-body">${XS.md(r.content)}</div></div>
          <div class="modal-foot">
            <button class="btn" id="md-copy">复制原文</button>
            <button class="btn" id="md-close">关闭</button>
          </div>`);
        mask.querySelector("#md-close").addEventListener("click", () => mask.hidden = true);
        mask.querySelector("#md-copy").addEventListener("click", async () => {
          try { await navigator.clipboard.writeText(r.content); XS.toast("报告原文已复制", "ok"); }
          catch { XS.toast("复制失败", "error"); }
        });
      }));
  }

  return {
    mount(container) { el = container; render().catch(e => { el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e.message)}</div>`; }); },
    unmount() { el = null; },
  };
})();
