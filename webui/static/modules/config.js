/* ============ 模块: 配置 ============ */
"use strict";

window.XSModules = window.XSModules || {};

XSModules.config = (() => {
  let el = null;
  let cfg = null;
  let llmState = { active: "", profiles: [], cur: "" };

  const llmCur = () => llmState.profiles.find(p => p.name === llmState.cur) || llmState.profiles[0];
  const THINKING = ["low", "medium", "high"];

  function llmPanelHtml() {
    const chips = llmState.profiles.map(p => {
      const isAct = p.name === llmState.active;
      const isCur = p.name === llmState.cur;
      return `<span class="llm-chip${isCur ? " cur" : ""}" data-name="${XS.esc(p.name)}"
        title="${isAct ? "当前生效档位" : "点击编辑此档位"}">${XS.esc(p.name)}${isAct ? " ✓" : ""}</span>`;
    }).join("") + `<span class="llm-chip add" id="llm-add" title="新建档位">+ 新建</span>`;
    const p = llmCur() || { key: "", base: "", provider: "", model: "", thinking: "medium" };
    const thinkingOpts = THINKING.map(v =>
      `<option value="${v}" ${p.thinking === v ? "selected" : ""}>${v}</option>`).join("");
    return `
      <div class="panel">
        <div class="panel-head">LLM 模型配置 <span class="spacer"></span>
          <span class="muted" style="font-weight:400">多档位切换 · 保存后对新任务生效</span></div>
        <div class="panel-body">
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">${chips}</div>
          <div class="field"><label>API Key（仅存本地 .env 的 <code>LLM_KEY_&lt;档位名&gt;</code>，llm-profiles.json 不落明文）</label>
            <input type="text" id="llm-key" spellcheck="false" autocomplete="off"
              placeholder="sk-...（DeepSeek 直连 sk-35位 / Token Rhythm sk_tr_*）" value="${XS.esc(p.key || "")}"></div>
          <div class="field-row">
            <div class="field"><label>Base URL</label>
              <input type="text" id="llm-base" spellcheck="false"
                placeholder="https://api.deepseek.com/v1" value="${XS.esc(p.base || "")}"></div>
            <div class="field"><label>Provider</label>
              <input type="text" id="llm-provider" spellcheck="false"
                placeholder="deepseek / tokenrhythm" value="${XS.esc(p.provider || "")}"></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Model</label>
              <input type="text" id="llm-model" spellcheck="false"
                placeholder="deepseek-v4-flash" value="${XS.esc(p.model || "")}"></div>
            <div class="field"><label>Thinking</label>
              <select id="llm-thinking">${thinkingOpts}</select></div>
          </div>
          <div class="muted" style="font-size:12px;margin-bottom:10px">
            点档位名切换编辑；点「保存 LLM 配置」= 保存全部档位并激活当前档位（新任务生效）。</div>
          <div style="display:flex;gap:10px">
            <button class="btn primary" id="llm-save">保存 LLM 配置</button>
            <button class="btn" id="llm-del" style="color:var(--danger)">删除当前档位</button>
          </div>
        </div>
      </div>`;
  }

  function syncFieldsToState() {
    const p = llmCur();
    if (!p) return;
    p.key = el.querySelector("#llm-key").value.trim();
    p.base = el.querySelector("#llm-base").value.trim();
    p.provider = el.querySelector("#llm-provider").value.trim();
    p.model = el.querySelector("#llm-model").value.trim();
    p.thinking = el.querySelector("#llm-thinking").value;
  }

  function rerenderLlmPanel() {
    const panel = el.querySelector(".llm-wrap");
    if (panel) {
      panel.innerHTML = llmPanelHtml();
      bindLlmEvents();
    }
  }

  function bindLlmEvents() {
    el.querySelectorAll(".llm-chip[data-name]").forEach(chip => {
      chip.addEventListener("click", () => {
        llmState.cur = chip.dataset.name;
        rerenderLlmPanel();
      });
    });
    const add = el.querySelector("#llm-add");
    if (add) add.addEventListener("click", () => {
      const name = (window.prompt("新档位名称（如 deepseek）：") || "").trim();
      if (!name) return;
      if (llmState.profiles.some(p => p.name === name)) { XS.toast("档位已存在", "error"); return; }
      llmState.profiles.push({ name, key: "", base: "https://api.deepseek.com/v1",
        provider: "deepseek", model: "deepseek-v4-flash", thinking: "medium" });
      llmState.cur = name;
      rerenderLlmPanel();
    });
    const del = el.querySelector("#llm-del");
    if (del) del.addEventListener("click", () => {
      if (llmState.profiles.length <= 1) { XS.toast("至少保留一个档位", "error"); return; }
      const p = llmCur();
      if (!p) return;
      llmState.profiles = llmState.profiles.filter(x => x.name !== p.name);
      if (llmState.active === p.name) llmState.active = llmState.profiles[0].name;
      llmState.cur = llmState.active;
      rerenderLlmPanel();
    });
    const save = el.querySelector("#llm-save");
    if (save) save.addEventListener("click", async () => {
      try {
        syncFieldsToState();
        llmState.active = llmState.cur || llmState.active;
        const r = await XS.api("/api/config/llm", {
          method: "PUT",
          json: { active: llmState.active, profiles: llmState.profiles },
        });
        llmState.active = r.active;
        XS.toast(`已保存并激活「${llmState.active}」（key ${r.key_set ? "已配置" : "为空，任务会警告"}），新任务生效`, "ok");
      } catch (e) { XS.toast("保存失败: " + e.message, "error"); }
    });
  }

  async function render() {
    if (!el) return;
    cfg = await XS.api("/api/config");
    const llm = await XS.api("/api/config/llm");
    llmState = { active: llm.active, profiles: llm.profiles, cur: llm.active };
    const envRows = Object.entries(cfg.env).length
      ? Object.entries(cfg.env)
          .map(([k, v]) => `<tr><td>${XS.esc(k)}</td><td class="mono">${XS.esc(v)}</td></tr>`).join("")
      : (cfg.dotenv_keys || []).length
        ? cfg.dotenv_keys.map(k =>
            `<tr><td>${XS.esc(k)}</td><td class="mono">来自 .env 文件</td></tr>`).join("")
        : `<tr><td>（无）</td></tr>`;
    const toolRows = cfg.tools.map(t =>
      `<tr><td>${XS.esc(t.name)}</td><td class="mono">${XS.fmtBytes(t.size)}</td></tr>`).join("");
    const wlRows = Object.entries(cfg.wordlists)
      .map(([k, v]) => `<tr><td>${XS.esc(k)}</td><td class="mono">${XS.fmtBytes(v)}</td></tr>`).join("");
    el.innerHTML = `
      <div class="page-head">
        <h1>配置</h1>
        <span class="sub">LLM 模型 / 目标清单 / 环境 / 工具链状态（密钥仅本机可见）</span>
      </div>
      <div class="llm-wrap">${llmPanelHtml()}</div>
      <div class="panel">
        <div class="panel-head">targets.txt <span class="spacer"></span>
          <span class="muted" style="font-weight:400">${XS.esc(cfg.targets_file)}</span></div>
        <div class="panel-body">
          <div class="field">
            <textarea id="cfg-targets" spellcheck="false">${XS.esc(cfg.targets_text)}</textarea>
          </div>
          <div class="muted" style="font-size:12px;margin-bottom:10px">
            每行 <code>[id|]url[|备注]</code>，# 开头为注释。由控制台新建的任务会自动追加（ui- 前缀）。保存后立即生效。</div>
          <button class="btn primary" id="cfg-save">保存 targets.txt</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">credentials.txt 测试账号池 <span class="spacer"></span>
          <span class="muted" style="font-weight:400">${cfg.credentials_count || 0} 条账号 · ${XS.esc(cfg.credentials_file || "")}</span></div>
        <div class="panel-body">
          <div class="field">
            <textarea id="cfg-credentials" spellcheck="false" style="min-height:90px">${XS.esc(cfg.credentials_text || "")}</textarea>
          </div>
          <div class="muted" style="font-size:12px;margin-bottom:10px">
            每行 <code>[scope|]user|pass[|备注]</code>，scope 为 <code>*</code>（全部目标）/ 目标id / host。
            仅注入你自己注册的测试账号；登录速率红线（≤2次/秒）由 BRIEF 自动声明。文件已被 gitignore。</div>
          <button class="btn primary" id="cfg-cred-save">保存账号池</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">环境变量（.env + 进程环境）</div>
        <div class="panel-body"><table class="kv">${envRows || "<tr><td>（无）</td></tr>"}</table></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="panel">
          <div class="panel-head">工具链 tools/bin（${cfg.tools.length}）</div>
          <div class="panel-body"><table class="kv">${toolRows || "<tr><td>（空）</td></tr>"}</table></div>
        </div>
        <div class="panel">
          <div class="panel-head">字典 tools/wordlists</div>
          <div class="panel-body"><table class="kv">${wlRows || "<tr><td>（空）</td></tr>"}</table></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-head">路径</div>
        <div class="panel-body"><table class="kv">
          <tr><td>project_root</td><td class="mono">${XS.esc(cfg.project_root)}</td></tr>
          <tr><td>jobs_dir</td><td class="mono">${XS.esc(cfg.jobs_dir)}</td></tr>
          <tr><td>outputs_dir</td><td class="mono">${XS.esc(cfg.outputs_dir)}</td></tr>
          <tr><td>key_set</td><td class="mono">${cfg.key_set ? "✓ 已配置" : "✗ 未配置（任务会警告）"}</td></tr>
        </table></div>
      </div>`;
    bindLlmEvents();
    el.querySelector("#cfg-save").addEventListener("click", async () => {
      try {
        await XS.api("/api/config/targets", { method: "PUT", json: { text: el.querySelector("#cfg-targets").value } });
        XS.toast("targets.txt 已保存", "ok");
      } catch (e) { XS.toast("保存失败: " + e.message, "error"); }
    });
    el.querySelector("#cfg-cred-save").addEventListener("click", async () => {
      try {
        const r = await XS.api("/api/config/credentials", { method: "PUT", json: { text: el.querySelector("#cfg-credentials").value } });
        XS.toast(`账号池已保存（${r.count} 条），重跑任务自动注入 BRIEF`, "ok");
      } catch (e) { XS.toast("保存失败: " + e.message, "error"); }
    });
  }

  return {
    mount(container) { el = container; render().catch(e => { el.innerHTML = `<div class="empty">加载失败: ${XS.esc(e.message)}</div>`; }); },
    unmount() { el = null; },
  };
})();
