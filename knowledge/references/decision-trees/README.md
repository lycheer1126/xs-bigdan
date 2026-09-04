# 漏洞决策树索引（按需精读，勿整目录通读）

> 原 decision-trees.md 单文件 2100+ 行，一次 cat 会吃掉大量上下文——已按漏洞类拆分。
> 用法：**参数/响应特征命中 → 先查本索引 → 只 cat 对应小文件**（每棵 ≤400 行）。
> 格式约定不变：识别信号 → 决策流程 → Payload。
>
> **双轨分工（2026-09 约定）**：本目录 = **速查层**（识别信号→决策流程→Payload，命中特征后 1 分钟内出打法）；
> `skills/` = **手法层**（完整步骤、绕过变体、验证标准、案例引用，打深入时读）。
> 同类洞两处都有时：先读本目录出第一枪，深入/绕过/收尾再看对应 skill；
> **有 skill 的类型（如 ssrf→hunt_ssrf/race→race_condition）以 skill 为唯一权威**，本目录该类条目仅保留索引指向。

| § | 文件 | 漏洞类 |
|---|---|---|
| §1 | `01-idor.md` | IDOR（越权） |
| §2 | `02-payment-logic.md` | 支付逻辑 |
| §2+ | `02b-payment-edge-cases.md` | Payment Logic — Edge Cases |
| §3 | `03-file-upload-download.md` | 文件上传 & 文件下载（目录穿越） |
| §4 | `04-sqli.md` | SQL注入 |
| §5 | `05-xss.md` | XSS |
| §6 | `06-ssrf.md` | SSRF |
| §7 | `07-xxe.md` | XXE |
| §8 | `08-unauth-access.md` | 未授权访问 |
| §9 | `09-auth-bypass.md` | 认证绕过 |
| §10 | `10-logic-flaws.md` | 逻辑缺陷 |
| §11 | `11-rce-cmdi.md` | RCE/命令注入 |
| §12 | `12-race-condition.md` | 并发竞争 |
| §13 | `13-param-fuzz.md` | 通用参数Fuzz |
| §14 | `14-ssti.md` | SSTI |
| §15 | `15-nosql.md` | NoSQL注入 |
| §16 | `16-prototype-pollution.md` | Prototype Pollution |
| §17 | `17-deserialization.md` | 反序列化 |
| §18 | `18-api-linkage.md` | API数据联动 |
| §19 | `19-oss-bucket.md` | OSS/Bucket Analysis — Full Attack Chain |
| §20 | `20-cors.md` | CORS Misconfiguration |
| §21 | `21-jsonp.md` | JSONP Hijacking |
| §22 | `22-oauth-sso.md` | OAuth/SSO Authorization Attacks |
| §23 | `23-filter-bypass.md` | 泛查询 / Filter Bypass（筛选条件绕过） |
| §24 | `24-open-redirect.md` | Open Redirect |
| §25 | `25-csrf.md` | CSRF |
| §26 | `26-vertical-privesc.md` | VertPrivEsc（垂直越权 — 专用决策树） |
| §27 | `27-frontend-auth-bypass.md` | 前端鉴权绕过（响应包修改 + JS校验绕过） |
| §28 | `28-host-injection.md` | Host注入与Host碰撞 |
| §29 | `29-key-exploitation.md` | 密钥利用决策树（找到Key后能干什么） |

**阅读纪律**：一次只读命中的 1-2 棵，测完即弃；同类参数命中多棵时按优先级串行，不要并读。
