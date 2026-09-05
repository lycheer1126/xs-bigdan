# Admin 面与垂直越权（deep 阶段后半）

> 从 high-risk-probing（原 Step 1/2/6）迁入：这三类属**低 WAF 触发**的正常业务请求形态，
> 不必等到 highrisk 才测——deep 阶段（联动有产出即进）后半常规执行。
> 导出接口越权已移至 breakthrough-shortlist（linkage 阶段）。
> 纪律不变：SAFE MODE 下单请求、间隔 3-5s；blocked 记账不阻塞。

---

## §1 — Swagger/API Docs（指纹为 Java/Spring Boot）

SAFE MODE，1 次探测:

```
→ 只测 /api-docs（Swagger 统一入口，WAF 拦全拦不拦全不拦，3 次无意义）
   200=提取全部端点 → 记录发现 → 端点并入契约表参与联动
   403=记入 blocked: "/api-docs WAF blocked"
   404=无 Swagger → 跳过
```

---

## §2 — Stack-Specific Admin 敏感路径（单请求, 3-5s 间隔）

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

## §3 — 垂直越权探测（普通 Cookie 打 admin 面，通常不触发 WAF）

```
→ 用已获得的 Token 逐条测试管理端点
→ 按优先级顺序: export/list → email/user → personnel/attendance → config
→ 200=记录发现（垂直越权确认）
→ 403=记录（有权限控制，正常）
→ 此步骤不触发 WAF（正常业务请求格式），可全量测试
→ 无登录态时: 以未认证身份打同一批端点=未授权访问（升级为 08-unauth 记账）
```

---

## 执行时机

deep 阶段后半：JWT/加密材料不存在或榨干后，本文件三节是 deep 的常规收尾动作。
测完写 runlog 记账（含 blocked 清单），与端点覆盖账本联动。
