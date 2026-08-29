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
        <span class="sub">runtime/outputs · report-*.md 归档</span>
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
      </div>
      <div class="panel" id="h-content" hidden>
        <div class="panel-head"><span id="h-title"></span><span class="spacer"></span>
          <button class="btn sm" id="h-close">收起</button></div>
        <div class="panel-body"><pre class="code" id="h-body"></pre></div>
      </div>`;
    el.querySelector("#h-refresh").addEventListener("click", render);
    el.querySelector("#h-open").addEventListener("click", async () => {
      await XS.api("/api/history/open-outputs", { method: "POST" });
    });
    el.querySelectorAll(".view-report").forEach(b =>
      b.addEventListener("click", async () => {
        const r = await XS.api(`/api/history/reports/${encodeURIComponent(b.dataset.name)}`);
        const panel = el.querySelector("#h-content");
        el.querySelector("#h-title").textContent = b.dataset.name;
        el.querySelector("#h-body").textContent = r.content;
        panel.hidden = false;
      }));
    el.querySelector("#h-close").addEventListener("click", () => {
      el.querySelector("#h-content").hidden = true;
    });
  }

  return {
    mount(container) { el = container; render().catch(e => { el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e.message)}</div>`; }); },
    unmount() { el = null; },
  };
})();
