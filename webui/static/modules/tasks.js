/* ============ 模块: 任务管理 ============ */
"use strict";

window.XSModules = window.XSModules || {};

XSModules.tasks = (() => {
  let el = null;
  let listTimer = null;
  let detailTimer = null;
  let detailId = null;
  let detailTab = "summary";
  let logAuto = true;
  let logFile = "";
  let groupFilter = "";  // 看板分组筛选: ""=全部, "__none__"=未分组, 组名=只看该组
  let searchFilter = ""; // 搜索筛选: 匹配任务 ID/URL/备注

  /* 漏洞类型英文 → 中文（看板/详情展示；已是中文的原样透传） */
  const VULN_CN = {
    "open redirect": "开放重定向", "info disclosure": "信息泄露", "information disclosure": "信息泄露",
    "user enumeration": "用户枚举", "sensitiveinfodisclosure": "敏感信息泄露",
    "ssrf": "SSRF", "sqli": "SQL注入", "sql injection": "SQL注入", "xss": "XSS",
    "idor": "越权", "csrf": "CSRF", "rce": "命令执行", "arbitrary file read": "任意文件读取",
    "unauthorized": "未授权访问", "weak password": "弱口令", "credential leak": "凭据泄露",
    "cleartext": "明文传输", "missing rate limit": "缺少速率限制",
  };

  function vulnCN(t) {
    const k = String(t || "").trim();
    if (!k) return "未知";
    return VULN_CN[k.toLowerCase()] || k;
  }

  function shortDomain(id) { return String(id).replace(/^ui-/, "").replace(/-\d{8}-\d{6}$/, ""); }
  function taskDate(id) {
    const m = String(id).match(/-(\d{4})(\d{2})(\d{2})-\d{6}$/);
    return m ? `${+m[2]}月${+m[3]}日` : "";
  }

  /* ---------- 列表页 ---------- */

  function statCard(label, num, cls) {
    return `<div class="stat ${cls}"><div class="num">${num}</div><div class="lbl">${label}</div></div>`;
  }

  function cardHTML(j, groups, marks) {
    const mk = (marks && marks[j.id]) || { task: false, vulns: {} };
    const vulns = Object.entries(j.findings_by_type || {})
      .map(([t, n]) => `<span class="tag vuln mark-vuln ${mk.vulns[t] ? "on" : ""}"
        data-id="${XS.esc(j.id)}" data-type="${XS.esc(t)}"
        title="点击标记该漏洞类型已被 SRC 确认有效(再次点击取消)">${XS.esc(vulnCN(t))}×${n}</span>`).join("");
    const pct = j.segments_planned
      ? Math.round((j.segments_ran / j.segments_planned) * 100) : 0;
    const grpOpts = `<option value="">未分组</option>` +
      groups.map(g => `<option value="${XS.esc(g.name)}" ${j.group === g.name ? "selected" : ""}>${XS.esc(g.name)}</option>`).join("");
    const buttons = `
      <button class="btn sm report-btn" data-id="${XS.esc(j.id)}" title="查看/生成漏洞报告">报告</button>
      <button class="btn sm detail-btn" data-id="${XS.esc(j.id)}">详情</button>
      ${j.state === "running" ? `
        <button class="btn sm danger stop-btn" data-id="${XS.esc(j.id)}">停止</button>` : `
        ${j.state !== "queued" ? `<button class="btn sm hint-btn" data-id="${XS.esc(j.id)}"
          title="续跑前提供线索/测试重点/账号——点「续跑」后注入 BRIEF">提供线索</button>` : ""}
        ${j.state === "queued" ? "" : `<button class="btn sm resume-btn" data-id="${XS.esc(j.id)}">续跑</button>`}
        <button class="btn sm danger del-btn" data-id="${XS.esc(j.id)}">${j.state === "queued" ? "取消" : "删除"}</button>`}`;
    return `
      <div class="card" data-id="${XS.esc(j.id)}">
        <div class="card-top">
          ${taskDate(j.id) ? `<span class="chip-date">${XS.esc(taskDate(j.id))}</span>` : ""}
          ${j.group ? `<span class="chip-grp">📁 ${XS.esc(j.group)}</span>` : ""}
          ${XS.stateBadge(j.state)}
          ${j.state === "blocked" && j.blocked_hours != null ? `
            <span class="chip-date" style="color:${j.blocked_hours >= 48 ? "var(--danger)" : "var(--warn)"};
              border:1px solid ${j.blocked_hours >= 48 ? "rgba(220,38,38,.5)" : "rgba(217,119,6,.5)"}"
              title="BLOCKED 挂起时长(等人工提供线索/账号)">⏱ 已挂 ${j.blocked_hours >= 48 ? "超48h" : j.blocked_hours + "h"}</span>` : ""}
          <span class="spacer" style="flex:1"></span>
          <button class="mark-btn ${mk.task ? "on" : ""}" data-id="${XS.esc(j.id)}" data-scope="task"
            title="标记该任务挖到的漏洞已被 SRC 确认有效(点击切换)">✓</button>
          <span class="card-meta">${j.findings_count} 个发现</span>
        </div>
        <div class="card-domain">${XS.esc(shortDomain(j.id))}</div>
        <div class="card-url">${XS.esc(j.url)}</div>
        ${j.note ? `<div class="card-note">${XS.esc(j.note)}</div>` : ""}
        <div class="card-vulns">${vulns || `<span class="muted" style="font-size:11.5px;color:var(--txt-faint)">暂无漏洞发现</span>`}</div>
        ${j.segments_planned ? `
        <div class="progress"><i style="width:${pct}%"></i></div>
        <div class="card-meta">段 ${j.segments_ran}/${j.segments_planned} · ${XS.fmtDur(j.elapsed_sec)}
          ${j.early_stop ? "· Agent 建议结束" : ""}</div>` : `
        <div class="card-meta">${j.started_at || "未开始"} ${j.ended_at ? "· " + j.ended_at : ""}</div>`}
        <div class="card-tags">
          ${j.errors ? `<span class="tag" style="color:var(--danger);border-color:var(--danger)"
            title="${XS.esc(j.last_error || "存在异常退出的段，详情页 SUMMARY 可见根因")}">⚠️ 失败×${j.errors}</span>` : ""}
        </div>
        <div class="card-actions">
          <select class="grp-sel" data-id="${XS.esc(j.id)}" title="把任务移入分组">
            ${grpOpts}
          </select>
          ${buttons}
        </div>
      </div>`;
  }

  function applySearchFilter() {
    if (!el) return;
    const q = searchFilter.toLowerCase();
    el.querySelectorAll(".card").forEach(card => {
      card.style.display = (!q || card.textContent.toLowerCase().includes(q)) ? "" : "none";
    });
  }

  async function renderList() {
    if (!el || detailId) return;
    try {
      const [data, grp, mk] = await Promise.all([
        XS.api("/api/tasks"), XS.api("/api/groups"),
        XS.api("/api/marks").catch(() => ({ jobs: {} })),
      ]);
      const marks = mk.jobs || {};
      const s = data.stats;
      const groups = grp.groups || [];
      let jobs = data.jobs;
      if (groupFilter === "__none__") jobs = jobs.filter(j => !j.group);
      else if (groupFilter) jobs = jobs.filter(j => j.group === groupFilter);
      if (searchFilter) {
        const q = searchFilter.toLowerCase();
        jobs = jobs.filter(j =>
          (j.note || "").toLowerCase().includes(q) ||
          (j.url || "").toLowerCase().includes(q) ||
          (j.id || "").toLowerCase().includes(q));
      }
      const searchBar = `
        <div style="margin-bottom:10px">
          <input id="task-search" spellcheck="false" placeholder="搜索：备注 / URL / 任务ID…"
            value="${XS.esc(searchFilter)}" autocomplete="off"
            style="width:100%;padding:6px 10px;font-size:13px;border:1px solid var(--border,#333);border-radius:6px;background:var(--bg,#1a1a2e);color:var(--fg,#eee)">
        </div>`;
      const grpBar = `
        <div class="grp-bar">
          <span class="grp-title">分组</span>
          <span class="grp-chip ${!groupFilter ? "on" : ""}" data-grp="">全部(${data.jobs.length})</span>
          <span class="grp-chip ${groupFilter === "__none__" ? "on" : ""}" data-grp="__none__">未分组</span>
          ${groups.map(g => `<span class="grp-chip ${groupFilter === g.name ? "on" : ""}"
            data-grp="${XS.esc(g.name)}" title="点击只看该组">${XS.esc(g.name)}(${g.count})</span>`).join("")}
          <button class="btn sm" id="btn-newgrp" title="新建分组，把同厂商/同批目标归到一起">＋ 新建组</button>
          ${groupFilter ? `<span class="grp-tip">当前只看「${XS.esc(groupFilter === "__none__" ? "未分组" : groupFilter)}」</span>` : ""}
        </div>`;
      el.innerHTML = `
        <div class="page-head">
          <h1>任务</h1>
          <span class="sub">runtime/jobs 实时状态 · 5s 自动刷新</span>
          <div class="head-actions">
            <button class="btn" id="btn-refresh">刷新</button>
            ${s.queued ? `<button class="btn" id="btn-clearq" title="取消所有排队中的任务（运行中的不受影响）">清空排队(${s.queued})</button>` : ""}
            <button class="btn primary" id="btn-new">＋ 新建任务</button>
          </div>
        </div>
        <div class="stats">
          ${statCard("总任务", s.total, "blu")}
          ${statCard("运行中", s.running, "acc")}
          ${statCard("排队中", s.queued || 0, s.queued ? "blu" : "")}
          ${statCard("已完成", s.done, "grn")}
          ${statCard("超时", s.timed_out, "orn")}
          ${statCard("中断", s.interrupted, "red")}
          ${statCard("待人工", s.blocked || 0, "orn")}
          ${statCard("异常退出", s.errors || 0, s.errors ? "red" : "")}
          ${statCard("发现数", s.findings, "")}
        </div>
        ${grpBar}
        ${searchBar}
        <div class="cards">
          ${jobs.length ? jobs.map(j => cardHTML(j, groups, marks)).join("") :
            `<div class="empty" style="grid-column:1/-1">${searchFilter ? "无匹配任务" : groupFilter ? "该分组暂无任务 — 点「全部」查看其它" : "暂无任务 — 点击右上角「新建任务」开始"}</div>`}
        </div>`;
      bindList();
      // 搜索框:恢复输入值 + 实时过滤卡片(自动刷新不丢状态)
      const searchEl = el.querySelector("#task-search");
      if (searchEl) {
        searchEl.value = searchFilter;
        searchEl.addEventListener("input", () => {
          searchFilter = searchEl.value.trim().toLowerCase();
          applySearchFilter();
        });
        applySearchFilter();
      }
    } catch (e) { XS.toast("列表刷新失败: " + e.message, "error"); }
  }

  async function openReportModal(jobId) {
    let r;
    try {
      r = await XS.api(`/api/tasks/${jobId}/report`);
    } catch {
      try {
        await XS.api("/api/tasks/report", { method: "POST", json: { job_id: jobId } });
        r = await XS.api(`/api/tasks/${jobId}/report`);
      } catch (e) { XS.toast("报告读取/生成失败: " + e.message, "error"); return; }
    }
    const mask = XS.modal(`
      <div class="modal wide">
      <div class="modal-head">${XS.esc(r.name)} <span class="x">✕</span></div>
      <div class="modal-body" style="max-height:80vh;overflow:auto"><div class="md-body">${XS.md(r.content)}</div></div>
      <div class="modal-foot">
        <button class="btn" id="md-copy">复制原文</button>
        <button class="btn" id="md-close">关闭</button>
      </div>`);
    mask.querySelector("#md-close").addEventListener("click", () => mask.hidden = true);
    mask.querySelector("#md-copy").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(r.content); XS.toast("报告原文已复制", "ok"); }
      catch { XS.toast("复制失败", "error"); }
    });
  }

  function openInputModal(jobId) {
    const mask = XS.modal(`
      <div class="modal-head">提供线索 <span class="x">✕</span></div>
      <div class="modal-body">
        <p class="muted" style="font-size:12.5px;margin-bottom:8px">
          提供测试账号 / 授权确认 / 下一步测试重点，点「续跑」后线索会注入任务简报，
          Agent 优先处理。待人工任务=Agent 卡住等你；中断/超时/已完成任务=续跑前补充方向。</p>
        <textarea id="hint-text" spellcheck="false" placeholder="如：测试账号 user01 / pass123（仅用于越权验证）；该资产在授权范围内；验证码需要真实手机号…"
          style="width:100%;min-height:110px;font-family:var(--mono);font-size:12.5px"></textarea>
      </div>
      <div class="modal-foot">
        <button class="btn" id="hint-cancel">取消</button>
        <button class="btn primary" id="hint-ok">提交线索</button>
      </div>`);
    mask.querySelector("#hint-cancel").addEventListener("click", () => mask.hidden = true);
    mask.querySelector("#hint-ok").addEventListener("click", async () => {
      const text = mask.querySelector("#hint-text").value.trim();
      if (!text) { XS.toast("线索不能为空", "error"); return; }
      try {
        await XS.api(`/api/tasks/${jobId}/input`, { method: "POST", json: { text } });
        XS.toast("线索已保存，点「续跑」生效", "ok");
        mask.hidden = true;
      } catch (e) { XS.toast("提交失败: " + e.message, "error"); }
    });
  }

  async function openGroupModal() {
    let groups = [], jobs = [];
    try {
      [groups, jobs] = await Promise.all([
        XS.api("/api/groups").then(r => r.groups || []).catch(() => []),
        XS.api("/api/tasks").then(r => r.jobs || []).catch(() => []),
      ]);
    } catch { /* 列表加载失败不阻塞 */ }
    const checked = new Set();
    const taskRows = jobs.map(j => `
      <label style="display:flex;align-items:center;gap:8px;padding:5px 8px;border-radius:8px;
        border:1px solid var(--line);margin-bottom:4px;font-size:12.5px;cursor:pointer">
        <input type="checkbox" class="grp-pick" value="${XS.esc(j.id)}">
        <span class="muted" style="font-family:var(--mono);font-size:11px">${XS.esc(shortDomain(j.id))}</span>
        <span class="muted" style="font-size:11px">${j.group ? `📁 ${XS.esc(j.group)}` : "未分组"}</span>
      </label>`).join("") || `<div class="muted" style="font-size:12px">暂无任务</div>`;
    const mask = XS.modal(`
      <div class="modal-head">管理分组 <span class="x">✕</span></div>
      <div class="modal-body">
        <p class="muted" style="font-size:12.5px;margin-bottom:8px">
          把同一厂商 / 同一批次的目标归到一组，看板按组过滤查看。创建时可直接勾选任务加入，
          之后也能用任务卡片上的分组下拉随时调整。</p>
        <div id="grp-list" style="margin-bottom:10px">
          ${groups.map(g => `
            <div style="display:flex;align-items:center;gap:8px;padding:6px 8px;border:1px solid var(--line);
              border-radius:8px;margin-bottom:6px;font-size:13px">
              <span class="chip-grp">📁 ${XS.esc(g.name)}</span>
              <span class="muted" style="font-size:11.5px">${g.count} 个任务</span>
              <span class="spacer" style="flex:1"></span>
              <button class="btn sm danger del-grp" data-grp="${XS.esc(g.name)}">删除</button>
            </div>`).join("") || `<div class="muted" style="font-size:12px;margin-bottom:6px">还没有分组</div>`}
        </div>
        <div style="display:flex;gap:8px;margin-bottom:10px">
          <input id="grp-name" placeholder="新组名，如: 货拉拉、58、银联SRC" maxlength="30" autocomplete="off"
            style="flex:1;padding:8px 10px;border-radius:8px;border:1px solid var(--line);font-size:13px">
          <button class="btn primary" id="grp-ok" style="flex:0 0 auto">新建</button>
        </div>
        <div class="muted" style="font-size:12px;margin-bottom:6px">选择要加入新组的任务（${jobs.length} 个）</div>
        <div id="grp-pick-list" style="max-height:200px;overflow-y:auto">${taskRows}</div>
      </div>
      <div class="modal-foot">
        <button class="btn" id="grp-cancel">关闭</button>
      </div>`);
    mask.querySelectorAll(".grp-pick").forEach(cb =>
      cb.addEventListener("change", () => {
        if (cb.checked) checked.add(cb.value); else checked.delete(cb.value);
      }));
    mask.querySelector("#grp-cancel").addEventListener("click", () => mask.hidden = true);
    mask.querySelector("#grp-ok").addEventListener("click", async () => {
      const name = mask.querySelector("#grp-name").value.trim();
      if (!name) { XS.toast("请输入组名", "error"); return; }
      const btn = mask.querySelector("#grp-ok");
      btn.disabled = true; btn.textContent = "创建中…";
      try {
        await XS.api("/api/groups", { method: "POST", json: { name } });
        for (const jobId of checked) {  // 勾选的任务批量入组
          await XS.api("/api/groups/assign", { method: "POST", json: { job_id: jobId, group: name } });
        }
        XS.toast(`已创建分组「${name}」并加入 ${checked.size} 个任务`, "ok");
        mask.hidden = true;
        renderList();
      } catch (e) { XS.toast("创建失败: " + e.message, "error"); btn.disabled = false; btn.textContent = "新建"; }
    });
    mask.querySelectorAll(".del-grp").forEach(b =>
      b.addEventListener("click", async () => {
        const name = b.dataset.grp;
        if (!confirm(`删除分组「${name}」？组内任务不会删除，只是变回未分组。`)) return;
        try {
          await XS.api(`/api/groups/${encodeURIComponent(name)}`, { method: "DELETE" });
          XS.toast(`已删除分组「${name}」`, "ok");
          if (groupFilter === name) groupFilter = "";
          mask.hidden = true;
          renderList();
        } catch (e) { XS.toast("删除失败: " + e.message, "error"); }
      }));
  }

  function bindList() {
    el.querySelector("#btn-refresh")?.addEventListener("click", renderList);
    el.querySelector("#btn-new")?.addEventListener("click", openNewModal);
    el.querySelector("#btn-newgrp")?.addEventListener("click", openGroupModal);
    el.querySelectorAll(".grp-chip").forEach(c =>
      c.addEventListener("click", () => {
        groupFilter = c.dataset.grp || "";
        renderList();
      }));
    el.querySelectorAll(".grp-sel").forEach(s => {
      s.addEventListener("click", e => e.stopPropagation());  // 防冒泡触发卡片跳详情(分组下拉曾因此无法操作)
      s.addEventListener("change", async () => {
        const jobId = s.dataset.id, grp = s.value;
        try {
          await XS.api("/api/groups/assign", { method: "POST", json: { job_id: jobId, group: grp } });
          XS.toast(grp ? `已移入「${grp}」` : "已移出分组", "ok");
          renderList();
        } catch (e) { XS.toast("分组失败: " + e.message, "error"); renderList(); }
      });
    });
    el.querySelector("#btn-clearq")?.addEventListener("click", async () => {
      if (!confirm(`取消全部排队中的任务？（正在运行的不受影响）`)) return;
      try {
        const r = await XS.api("/api/tasks/queue/clear", { method: "POST" });
        XS.toast(`已取消 ${r.cancelled} 个排队任务`, "ok");
        renderList();
      } catch (err) { XS.toast(err.message, "error"); }
    });
    el.querySelectorAll(".report-btn").forEach(b =>
      b.addEventListener("click", e => { e.stopPropagation(); openReportModal(b.dataset.id); }));
    el.querySelectorAll(".mark-btn").forEach(b =>
      b.addEventListener("click", async e => {
        e.stopPropagation();
        try {
          const r = await XS.api("/api/marks/toggle", { method: "POST", json: { job_id: b.dataset.id, scope: "task" } });
          XS.toast(r.state ? "已标记该任务漏洞有效 ✓" : "已取消标记", "ok");
          renderList();
        } catch (err) { XS.toast("标记失败: " + err.message, "error"); }
      }));
    el.querySelectorAll(".mark-vuln").forEach(t =>
      t.addEventListener("click", async e => {
        e.stopPropagation();
        try {
          const r = await XS.api("/api/marks/toggle", { method: "POST", json: { job_id: t.dataset.id, scope: "vuln", key: t.dataset.type } });
          XS.toast(r.state ? `「${vulnCN(t.dataset.type)}」已点亮 ✓` : "已取消点亮", "ok");
          renderList();
        } catch (err) { XS.toast("标记失败: " + err.message, "error"); }
      }));
    el.querySelectorAll(".detail-btn").forEach(b =>
      b.addEventListener("click", e => { e.stopPropagation(); location.hash = `#/tasks/${b.dataset.id}`; }));
    el.querySelectorAll(".card").forEach(c =>
      c.addEventListener("click", () => location.hash = `#/tasks/${c.dataset.id}`));
    el.querySelectorAll(".hint-btn").forEach(b =>
      b.addEventListener("click", e => { e.stopPropagation(); openInputModal(b.dataset.id); }));
    el.querySelectorAll(".resume-btn").forEach(b =>
      b.addEventListener("click", async e => {
        e.stopPropagation();
        if (!confirm(`确认续跑任务 ${b.dataset.id}？（断点续打，需 jobs/ 断点仍在）`)) return;
        try {
          const r = await XS.api(`/api/tasks/${b.dataset.id}/resume`, { method: "POST", json: {} });
          if (r.queued) XS.toast(`已加入队列排队，按顺序执行（${b.dataset.id}）`, "ok");
          else XS.toast(`已开始续跑 ${b.dataset.id}`, "ok");
          renderList();
        } catch (err) { XS.toast(err.message, "error"); }
      }));
    el.querySelectorAll(".stop-btn").forEach(b =>
      b.addEventListener("click", async e => {
        e.stopPropagation();
        if (!confirm(`确认停止任务 ${b.dataset.id}？`)) return;
        try {
          await XS.api(`/api/tasks/${b.dataset.id}/stop`, { method: "POST" });
          XS.toast(`已停止 ${b.dataset.id}`, "ok");
          renderList();
        } catch (err) { XS.toast(err.message, "error"); }
      }));
    el.querySelectorAll(".del-btn").forEach(b =>
      b.addEventListener("click", async e => {
        e.stopPropagation();
        if (!confirm(`确认删除任务 ${b.dataset.id}？\n将停止进程、jobs 目录移入回收站、并从 targets.txt 移除该行。`)) return;
        try {
          const r = await XS.api(`/api/tasks/${b.dataset.id}`, { method: "DELETE" });
          if (r.trashed) XS.toast(`已删除 ${b.dataset.id}（回收站）`, "ok");
          else XS.toast(`已移除 targets.txt 登记，但 jobs 目录删除失败（可能被占用），请手动清理`, "error");
          renderList();
        } catch (err) { XS.toast(err.message, "error"); }
      }));
  }

  function openNewModal() {
    XS.modal(`
      <div class="modal-head">新建任务（支持批量） <span class="x">✕</span></div>
      <div class="modal-body">
        <div class="field">
          <label>目标 URL —— 每行一个，可整批粘贴（自动生成任务ID，按粘贴顺序串行执行，绝不并行）</label>
          <textarea id="nf-url" spellcheck="false" autocomplete="off"
            style="width:100%;min-height:110px;font-family:var(--mono);font-size:12.5px"
            placeholder="https://target-a.com/login&#10;https://api.target-b.com&#10;card.target-c.net:18030"></textarea>
        </div>
        <div class="field">
          <label>备注（可选，应用于本批所有目标）</label>
          <input id="nf-note" placeholder="如: 某SRC已授权资产" autocomplete="off">
        </div>
        <div class="field">
          <label>分组（可选，把本批任务归入同一组；填新名字即自动建组）</label>
          <input id="nf-group" placeholder="如: 货拉拉" maxlength="30" autocomplete="off">
        </div>
        <div class="field">
          <label>Cookie（可选，每个框一个账号的登录态，应用于本批所有目标并自动按站点隔离）
            <button type="button" id="nf-cookie-add" class="btn" title="再加一个账号"
              style="margin-left:8px;padding:0 10px;font-size:14px;line-height:1.4">＋</button>
          </label>
          <div id="nf-cookie-list"></div>
          <div class="muted" style="font-size:11.5px;margin-top:4px">从浏览器 F12 → 网络 → 请求标头复制整串 Cookie 粘贴。
            多账号 = agent 自动做两账号差分越权(IDOR)测试；SSO/扫码登录站点只能走此通道。</div>
        </div>
        <div class="field">
          <label>我的想法（可选，自由填写：为什么测它 / 哪里薄弱 / 想先看什么 —— 原文注入 BRIEF，agent 优先验证）</label>
          <textarea id="nf-intent" spellcheck="false" autocomplete="off"
            style="width:100%;min-height:44px"
            placeholder="如: 这个 AI 聊天页登录即可用，怀疑会话对象越权与提示词注入；重点测会话归属和存储型 XSS 落点"></textarea>
        </div>
        <div class="field-row">
          <div class="field">
            <label>每目标总预算（秒，默认 3600=60min）</label>
            <input id="nf-timeout" type="number" value="3600" min="90" max="14400">
          </div>
          <div class="field">
            <label>最多段数（上下文保鲜切片，默认 3；阶段由产物门控自动判定）</label>
            <input id="nf-segs" type="number" value="3" min="1" max="10">
          </div>
        </div>
        <div class="muted" style="font-size:12px">任务按粘贴顺序进入队列串行执行：有任务在跑时自动排队，前一个结束自动开始下一个。
          credentials.txt 中命中的测试账号会自动注入各任务 BRIEF。</div>
      </div>
      <div class="modal-foot">
        <button class="btn" id="nf-cancel">取消</button>
        <button class="btn primary" id="nf-ok">创建任务</button>
      </div>`);
    const mask = document.getElementById("modal-mask");
    mask.querySelector("#nf-cancel").addEventListener("click", () => mask.hidden = true);
    // Cookie 多账号框：＋ 加框 / ✕ 删框；提交时把所有框拼回"每行一个账号"（后端格式不变）
    const cookieList = mask.querySelector("#nf-cookie-list");
    const addCookieRow = () => {
      const rows = cookieList.querySelectorAll(".nf-cookie-row");
      if (rows.length >= 5) { XS.toast("最多 5 个账号框", "error"); return; }
      const row = document.createElement("div");
      row.className = "nf-cookie-row";
      row.style.cssText = "display:flex;gap:6px;margin-top:6px;align-items:flex-start";
      const ta = document.createElement("textarea");
      ta.className = "nf-cookie-input";
      ta.spellcheck = false; ta.autocomplete = "off";
      ta.placeholder = `账号 ${rows.length + 1} 的 Cookie，如 __Secure-next-auth.session-token=xxx; SUB=xxx`;
      ta.style.cssText = "width:100%;min-height:38px;font-family:var(--mono);font-size:12px";
      const del = document.createElement("button");
      del.type = "button"; del.textContent = "✕"; del.className = "btn";
      del.title = "删除此账号";
      del.style.cssText = "flex:0 0 auto;padding:0 9px;";
      del.addEventListener("click", () => { row.remove(); refreshPlaceholders(); });
      row.append(ta, del);
      cookieList.appendChild(row);
    };
    const refreshPlaceholders = () => {
      cookieList.querySelectorAll(".nf-cookie-input").forEach((ta, i) => {
        ta.placeholder = `账号 ${i + 1} 的 Cookie，如 __Secure-next-auth.session-token=xxx; SUB=xxx`;
      });
    };
    mask.querySelector("#nf-cookie-add").addEventListener("click", addCookieRow);
    addCookieRow();
    mask.querySelector("#nf-ok").addEventListener("click", async () => {
      const text = mask.querySelector("#nf-url").value.trim();
      if (!text) { XS.toast("请输入目标 URL（每行一个）", "error"); return; }
      const btn = mask.querySelector("#nf-ok");
      btn.disabled = true; btn.textContent = "创建中…";
      try {
        const r = await XS.api("/api/tasks/batch", {
          method: "POST",
          json: {
            urls_text: text,
            note: mask.querySelector("#nf-note").value.trim(),
            group: mask.querySelector("#nf-group")?.value.trim() || "",
            cookie: [...cookieList.querySelectorAll(".nf-cookie-input")]
              .map(t => t.value.trim()).filter(Boolean).join("\n"),
            intent: mask.querySelector("#nf-intent").value.trim(),
            job_timeout: +mask.querySelector("#nf-timeout").value || 3600,
            segments: +mask.querySelector("#nf-segs").value || 3,
          },
        });
        mask.hidden = true;
        XS.toast(`已创建 ${r.created} 个任务${r.first_started ? "，首个已开始运行" : "，进入队列串行执行"}`, "ok");
        if (r.created === 1) location.hash = `#/tasks/${r.ids[0]}`;
        else { detailId = null; renderList(); }
      } catch (e) { XS.toast("创建失败: " + e.message, "error"); btn.disabled = false; btn.textContent = "创建任务"; }
    });
  }

  /* ---------- 详情页 ---------- */

  async function renderDetail() {
    if (!el) return;
    const data = await XS.api(`/api/tasks/${detailId}`);
    const s = data.summary || {};
    const state = await stateOf(detailId);
    const tabs = [
      ["summary", "概览", ""],
      ["digest", "Digest", data.digests.length],
      ["runlog", "事件流", data.runlog.length],
      ["session", "实时日志", data.sessions.length],
      ["stdout", "调度器", ""],
      ["evidence", "证据", data.evidence.length],
    ];
    const tabBar = tabs.map(([k, t, n]) =>
      `<span class="tab ${k === detailTab ? "active" : ""}" data-tab="${k}">${t}${n ? `<span class="cnt">${n}</span>` : ""}</span>`).join("");
    el.innerHTML = `
      <div class="page-head">
        <button class="btn ghost" id="d-back">← 返回</button>
        <h1 style="font-family:var(--mono);font-size:15px">${XS.esc(detailId)}</h1>
        ${XS.stateBadge(state)}
        <span class="sub" style="font-family:var(--mono)">${XS.esc(s.url || "")}</span>
        <div class="head-actions">
          ${state === "running" ?
            `<button class="btn danger" id="d-stop">停止</button>` :
            `<button class="btn primary" id="d-resume">续跑</button>`}
          ${state !== "running" && state !== "queued" ? `<button class="btn" id="d-hint" style="color:var(--warn);border-color:var(--warn)" title="续跑前提供线索/测试重点/账号">提供线索</button>` : ""}
          <button class="btn" id="d-report" title="查看漏洞报告(无则先生成,中断/半成品任务也出)">报告</button>
          <button class="btn" id="d-open">打开目录</button>
          <button class="btn danger" id="d-del">删除</button>
        </div>
      </div>
      ${state === "blocked" ? `
      <div style="background:var(--warn-bg, #fef3c7);border:1px solid var(--warn);color:#92400e;
        padding:8px 14px;border-radius:8px;font-size:13px;margin:10px 0 4px">
        Agent 请求人工输入（BLOCKED）：已停止后续段。查看 Digest 了解卡点，
        提供线索后点「续跑」——线索会注入下一段简报，Agent 优先处理。
      </div>` : ""}
      <div class="tabs">${tabBar}</div>
      <div id="tab-body" style="padding:16px 2px"></div>`;
    el.querySelector("#d-back").addEventListener("click", () => { location.hash = "#/tasks"; });
    el.querySelectorAll(".tab").forEach(t =>
      t.addEventListener("click", () => { detailTab = t.dataset.tab; renderTab(data); }));
    el.querySelector("#d-stop")?.addEventListener("click", async () => {
      if (!confirm(`停止 ${detailId}？`)) return;
      await XS.api(`/api/tasks/${detailId}/stop`, { method: "POST" });
      XS.toast("已停止", "ok"); renderDetail();
    });
    el.querySelector("#d-resume")?.addEventListener("click", async () => {
      if (!confirm(`断点续跑 ${detailId}？`)) return;
      try {
        await XS.api(`/api/tasks/${detailId}/resume`, { method: "POST", json: {} });
        XS.toast("已开始续跑", "ok"); renderDetail();
      } catch (e) { XS.toast(e.message, "error"); }
    });
    el.querySelector("#d-hint")?.addEventListener("click", () => openInputModal(detailId));
    el.querySelector("#d-report")?.addEventListener("click", () => openReportModal(detailId));
    el.querySelector("#d-open")?.addEventListener("click", async () => {
      await XS.api(`/api/tasks/${detailId}/open-dir`, { method: "POST" });
    });
    el.querySelector("#d-del")?.addEventListener("click", async () => {
      if (!confirm(`删除 ${detailId}？（jobs 移回收站，targets.txt 移除该行）`)) return;
      await XS.api(`/api/tasks/${detailId}`, { method: "DELETE" });
      location.hash = "#/tasks";
    });
    renderTab(data);
    startDetailPoll(state);
  }

  async function stateOf(id) {
    const data = await XS.api("/api/tasks");
    return data.jobs.find(j => j.id === id)?.state || "created";
  }

  function renderTab(data) {
    const body = el.querySelector("#tab-body");
    el.querySelectorAll(".tab").forEach(t =>
      t.classList.toggle("active", t.dataset.tab === detailTab));
    const s = data.summary || {};
    const lastPhase = (data.runlog || []).filter(r => r.type === "segment_start" && r.phase).pop()?.phase;
    if (detailTab === "summary") {
      const rows = [
        ["id", s.id], ["url", s.url], ["note", s.note],
        ["started_at", s.started_at], ["ended_at", s.ended_at || "-"],
        ["elapsed_sec", s.elapsed_sec], ["segments_ran", s.segments_ran],
        ["segments_planned", s.segments_planned], ["early_stop", s.early_stop],
        ["blocked", s.blocked], ["timed_out", s.timed_out], ["job_timeout_sec", s.job_timeout_sec],
        ["seg_timeout_sec", s.seg_timeout_sec],
        ["当前阶段", lastPhase ? `${lastPhase}（产物门控推断，详见 BRIEF/digest）` : "-"],
      ];
      body.innerHTML = `
        ${data.user_input ? `
        <div class="panel"><div class="panel-head">人工线索（已提供，续跑时注入简报）</div>
          <div class="panel-body"><pre class="code">${XS.esc(data.user_input)}</pre></div></div>` : ""}
        ${(s.findings || []).length ? `
        <div class="panel"><div class="panel-head">漏洞发现（${(s.findings || []).length}）</div>
          <div class="panel-body"><table class="kv">
            ${(s.findings || []).map((f, i) =>
              `<tr><td>#${i + 1}</td>
                <td><b>${XS.esc(vulnCN(f.type || ""))}</b> · ${XS.esc(f.title || "")}</td>
                <td class="mono">${XS.esc(f.status || "CONFIRMED")}</td>
                <td class="mono">${XS.esc(f.file || "")}</td></tr>`).join("")}
          </table></div></div>` : ""}
        <div class="panel"><div class="panel-head">基本信息</div><div class="panel-body">
          <table class="kv">${rows.map(([k, v]) =>
            `<tr><td>${k}</td><td class="mono">${XS.esc(String(v ?? "-"))}</td></tr>`).join("")}
          </table></div></div>
        <div class="panel"><div class="panel-head">SUMMARY JSON <span class="spacer"></span>
          <span class="muted" style="font-weight:400">${(s.findings || []).length} findings</span></div>
          <div class="panel-body"><pre class="code">${XS.esc(JSON.stringify(s, null, 2))}</pre></div></div>`;
    } else if (detailTab === "digest") {
      body.innerHTML = data.digests.length ? data.digests.map((name, i) => `
        <div class="panel"><div class="panel-head" style="cursor:pointer" data-fold="${i}">
          ${name} <span class="spacer"></span><span class="muted" style="font-weight:400">点击折叠</span></div>
          <div class="panel-body" id="digest-body-${i}"><pre class="code">加载中…</pre></div></div>`).join("")
        : `<div class="empty">尚无 digest</div>`;
      data.digests.forEach((name, i) => {
        XS.api(`/api/tasks/${detailId}/file?path=${encodeURIComponent(name)}`).then(r => {
          const box = el.querySelector(`#digest-body-${i} pre`);
          if (box) box.innerHTML = highlightBlocked(XS.esc(r.content));
        }).catch(() => {});
        el.querySelector(`[data-fold="${i}"]`).addEventListener("click", e => {
          const b = el.querySelector(`#digest-body-${i}`);
          b.style.display = b.style.display === "none" ? "" : "none";
        });
      });
    } else if (detailTab === "runlog") {
      body.innerHTML = `<div class="log-box">${
        data.runlog.length ? data.runlog.map(runlogLine).join("") : "（无事件）"}</div>`;
    } else if (detailTab === "session") {
      if (!data.sessions.length) { body.innerHTML = `<div class="empty">尚无 session 日志</div>`; return; }
      if (!logFile || !data.sessions.includes(logFile)) logFile = data.sessions[data.sessions.length - 1];
      body.innerHTML = `
        <div class="log-toolbar">
          <select id="log-sel">${data.sessions.map(n =>
            `<option value="${XS.esc(n)}" ${n === logFile ? "selected" : ""}>${XS.esc(n)}</option>`).join("")}</select>
          <label class="auto"><input type="checkbox" id="log-auto" ${logAuto ? "checked" : ""}>自动刷新(3s)</label>
          <span class="spacer" style="flex:1"></span>
          <span class="muted">pi agent 会话日志（末 300 行）</span>
        </div>
        <div class="log-box" id="log-box"></div>`;
      el.querySelector("#log-sel").addEventListener("change", e => { logFile = e.target.value; loadSession(); });
      el.querySelector("#log-auto").addEventListener("change", e => {
        logAuto = e.target.checked;
        if (logAuto) startDetailPoll(awaitCurrentState());
      });
      loadSession();
    } else if (detailTab === "stdout") {
      body.innerHTML = `<div class="log-toolbar"><span class="muted">bigdan.py 调度器 stdout（runtime/.webui/bigdan-${XS.esc(detailId)}.out.log，末 150 行）</span></div>
        <div class="log-box" id="stdout-box">加载中…</div>`;
      loadStdout();
    } else if (detailTab === "evidence") {
      body.innerHTML = data.evidence.length ? data.evidence.map((f, i) => `
        <div class="list-item">
          <span class="name" data-file="${XS.esc(f.name)}">${XS.esc(f.name)}</span>
          <span class="meta">${XS.fmtBytes(f.size)} · ${f.mtime}</span>
          <span class="spacer"></span>
          <button class="btn sm view-ev" data-file="${XS.esc(f.name)}">查看</button>
        </div>`).join("") : `<div class="empty">尚无证据文件</div>`;
      el.querySelectorAll(".view-ev").forEach(b =>
        b.addEventListener("click", async () => {
          const r = await XS.api(`/api/tasks/${detailId}/file?path=evidence/${encodeURIComponent(b.dataset.file)}`);
          XS.modal(`
            <div class="modal-head">${XS.esc(b.dataset.file)} <span class="x">✕</span></div>
            <div class="modal-body"><pre class="code">${XS.esc(r.content)}</pre></div>`);
        }));
    }
  }

  function runlogLine(r) {
    const ts = (r.ts || "").slice(11, 19);
    const isErrNote = r.type === "note" && /失败原因|exit=1/.test(r.msg || "");
    const clsMap = {
      finding: "ln-hit", early_stop: "ln-warn", retry: "ln-warn", segment_start: "ln-acc",
      blocked: "ln-warn",
    };
    let cls = isErrNote ? "ln-err" : (clsMap[r.type] || "ln-dim");
    const extra = r.vuln_type ? ` ${r.vuln_type} | ${r.title}` :
      r.categories ? ` ${r.categories.join(",")}` :
      r.msg ? ` ${r.msg}` :
      r.seg != null ? ` seg=${r.seg}${r.phase ? " · " + r.phase : ""}` : "";
    return `<span class="ln-dim">${ts}</span> <span class="${cls}">[${r.type}]</span>${XS.esc(extra || "")}\n`;
  }

  async function loadSession() {
    const box = el.querySelector("#log-box");
    if (!box) return;
    try {
      const r = await XS.api(`/api/tasks/${detailId}/file?path=${encodeURIComponent(logFile)}&tail=300`);
      box.innerHTML = colorize(r.content);
      box.scrollTop = box.scrollHeight;
    } catch { /* 文件可能尚未生成 */ }
  }

  async function loadStdout() {
    const box = el.querySelector("#stdout-box");
    if (!box) return;
    try {
      const r = await XS.api(`/api/tasks/${detailId}/stdout?tail=150`);
      box.innerHTML = r.content ? colorize(r.content) : "（无输出）";
    } catch { /* ignore */ }
  }

  function highlightBlocked(esc) {
    return esc.replace(/(### BLOCKED[\s\S]*?)(?=\n### |\n--- |$)/g,
      `<span style="display:block;background:#fef3c7;border-left:3px solid var(--warn);padding:4px 10px;margin:4px 0;border-radius:4px">$1</span>`);
  }

  function colorize(text) {
    return XS.esc(text)
      .split("\n").map(line => {
        const clean = line.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/, "");
        let cls = "ln-dim";
        if (/FINDING/i.test(clean)) cls = "ln-hit";
        else if (/exception|traceback|fail(?:ed|ure)?\b|error:|exit=1/i.test(clean)) cls = "ln-err";
        else if (/warn|warning|投降|重试|放弃/i.test(clean)) cls = "ln-warn";
        else if (/\[\+\]|ok|success|done|complete/i.test(clean)) cls = "ln-ok";
        else if (/assistant: think|^\[|===|-->/i.test(clean)) cls = "ln-acc";
        return `<span class="${cls}">${line}</span>`;
      }).join("\n");
  }

  async function startDetailPoll(state) {
    clearInterval(detailTimer);
    detailTimer = null;
    if (!logAuto || detailTab !== "session" || state !== "running") return;
    detailTimer = setInterval(async () => {
      try {
        const st = await stateOf(detailId);
        if (st !== "running") { clearInterval(detailTimer); detailTimer = null; renderDetail(); return; }
        loadSession();
      } catch { /* ignore */ }
    }, 3000);
  }

  function awaitCurrentState() { return "running"; }

  /* ---------- 生命周期 ---------- */

  function mount(container) {
    el = container;
    detailId = location.hash.includes("/tasks/")
      ? decodeURIComponent(location.hash.split("/").pop()) : null;
    if (detailId) {
      renderDetail().catch(e => {
        el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e.message)}<br><br>` +
          `<button class="btn" id="d-retry">重试</button></div>`;
        el.querySelector("#d-retry")?.addEventListener("click", () => {
          el.innerHTML = `<div class="view-loading">加载中…</div>`;
          renderDetail().catch(e2 => {
            el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e2.message)}<br><br>` +
              `<button class="btn" id="d-retry">重试</button></div>`;
          });
        });
      });
    } else {
      renderList().catch(e => { el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e.message)}</div>`; });
      listTimer = setInterval(() => renderList().catch(() => {}), 5000);
    }
  }

  function unmount() {
    clearInterval(listTimer); clearInterval(detailTimer);
    listTimer = detailTimer = null;
    el = null;
  }

  return { mount, unmount };
})();
