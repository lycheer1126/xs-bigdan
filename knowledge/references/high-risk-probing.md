# 高危探测详细步骤 (Phase 3.8)

> 从 SKILL.md Phase 3.8 迁出。进入 Phase 3.8 时加载。
> WARNING: 这些操作会触发 WAF 规则。仅在 Phase 0-3 安全测试完成且确认目标价值后执行。

---

## 核心模式：遍历+记录，互不阻塞

```
Phase 3.8 执行模式（非"首次403=整体停止"）:
  每个项目独立测试 → WAF 拦截=记入 blocked 清单 → 继续测下一项
  → blocked 清单写入 findings/_interim-phase3.8-blocked.md
  → 全部测完后再统一决定是否对 blocked 项做 WAF 绕过
```

---

## Step 1 — Swagger/API Docs（指纹为 Java/Spring Boot）

SAFE MODE，1 次探测:

```
→ 只测 /api-docs（Swagger 统一入口，WAF 拦全拦不拦全不拦，3 次无意义）
   200=提取全部端点 → 记录发现
   403=记入 blocked: "/api-docs WAF blocked"
   404=无 Swagger → 跳过
```

---

## Step 2 — Stack-Specific Admin 敏感路径（单请求, 3-5s 间隔）

```
每个 stack 只测 1 个代表性路径（WAF 对同类型路径行为一致，无需逐个探测）:
  Java:   /actuator
  PHP:    /.env
  Python: /admin/
  .NET:   /web.config

→ 200/302=记录发现 → 继续
→ 403=记入 blocked → 继续
→ 404=跳过 → 继续
```

---

## Step 3 — SQL Injection（手工单点，不批量）

```
→ 仅在 Phase 3 中已识别为 "可能的数据库输入" 的参数上测试
→ 测试: id=3-1 (数字型), keyword=test' (字符型), SLEEP(2)
→ 403=记入 blocked: "SQLi WAF blocked on param={param_name}"
→ 异常响应=记录发现
→ 正常返回=未发现 → 继续下一个参数
→ 绝不在 WAF 保护目标上使用 SQLmap
```

---

## Step 4 — Command Injection

```
→ 仅在名为 cmd/command/exec/shell/ping/host 的参数上测试
→ 测试: ; sleep 2 (盲打), ; ping -c 2 dnslog.cn (OOB)
→ 403=记入 blocked: "CMD注入 WAF blocked on param={param_name}"
→ OOB回调成功=记录发现
→ 正常返回=未发现
```

---

## Step 5 — SSTI / SSRF / XXE Payload Tests

```
→ SSTI: ${7*7}（预检，不触发 WAF）→ 计算=发现 | 原文=未发现
→ SSRF: http://127.0.0.1:80 → 被拦截=记入 blocked | 返回数据=发现
        被拦截后换 collaborator OOB 回调
→ XXE: <!DOCTYPE> OOB → 回调=发现 | 被拦截=记入 blocked
→ 403=记入 blocked → 继续下一个测试
```

---

## Step 6 — §26 垂直越权探测（通常不触发 WAF）

```
→ 用已获得的 Token 逐条测试管理端点
→ 按 §26 的优先级顺序: export/list → email/user → personnel/attendance → config
→ 200=记录发现（垂直越权确认）
→ 403=记录（有权限控制，正常）
→ 此步骤不触发 WAF（正常业务请求格式），可全量测试
```

---

## Step 7 — 导出接口权限测试（通常不触发 WAF）

```
→ 对 Phase 1 标记的 export/download/excel/csv/report 接口测试权限
→ 无Token直接访问=数据导出发现（严重）
→ 普通Token访问管理导出=垂直越权发现（严重）
→ 此步骤不触发 WAF（正常业务请求格式），可全量测试
```

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
