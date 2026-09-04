# §6 SSRF（索引页——权威内容已收敛至 hunt_ssrf）

> **本文件不再承载 SSRF 打法细节。唯一权威：`knowledge/skills/hunt_ssrf/SKILL.md`**
> （OOB 判定门/SRC 官方靶标表/VPS OOB/云元数据表/绕过变体/云开发代打三招/盲打三连/验证标准）。
> 2026-09 收敛：此前本文件与 hunt_ssrf/cloud-attack-surface 三处内容重复且有出入，已归一。

快速路由：
- 判定门（什么算确认/什么算误报）→ hunt_ssrf §1
- 回调源选择（SRC 官方靶标/VPS/dnslog）→ hunt_ssrf §2
- 云元数据 + 路径差 → hunt_ssrf §3/§5b
- 绕过变体（黑名单/白名单/短链/rebinding）→ hunt_ssrf §4
- 盲打三连（业务 oracle/store-and-read/DNS 外带）→ hunt_ssrf §6
- 合规边界 → 本节保留如下（唯一在此保留的内容：决策速记）

### 场景速记
```
目标属于主流 SRC? → 用其官方靶标(hunt_ssrf §2a) —— 授权证明+平台认可
有 VPS?          → VPS OOB(§2b, 可承载 302 跳转/HEAD 分流)
都没有?          → 公共 dnslog(§2c)
确认后第一优先:   → 云元数据表(§3), 凭证到手即停(TIER 3)
```

### SRC 合规边界（执行前必读）
```
[SRC ALLOWED] OOB 回调确认、file://读自己账号文件、官方靶标打标、cloud metadata(scope内)
[SRC FORBIDDEN] 写 webshell/cron/SSH key、无靶场时内网扫描、Redis 命令执行、gopher 攻击
```
