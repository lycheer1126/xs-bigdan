# 待办与观察项（BACKLOG）

> 来源：2026-08-30 VPS 首跑日 + 前序评审。按优先级排序；做完就删行。
> 触发式条目（达到观察条件才做）标注在文末。

## P1 — 尽快

- [ ] **连续秒败熔断**：同一任务连续 N 段（建议 2）`exit=1 且 elapsed<10s 且 findings=0` 时提前终止整个 job 并在卡片标注根因。起因：pi 版本漂移那次 3 段秒败只浪费 5 秒，但若换成 API key 失效类故障会连烧 3 段真金白银。（bigdan.py run_target 循环内）
- [ ] **opencode Go 套餐接入验证**：用户订阅后，webui 配置页新增 LLM 档位（base=opencode 网关 / 模型选 DeepSeek 系），拿已知目标对比 BRIEF 执行度与限速表现；限速严重则做混合调度（Go 跑 recon、直连跑主力段）。

## P2 — 本周内

- [ ] **联动引擎语义组扩展**：biz-mutations.md 中 `[引擎]` 标记的扰动族（状态翻转/数量边界/类型替换/置空）接入 PairingEngine 自动配对；`身份替换族` 保持人工/agent 判断区。
- [ ] **响应 id 回注规则**：联动引擎新增"响应 JSON 中 id 类字段 → 同请求参数回放"配对规则（引擎值池目前来自 JS 静态分析，不覆盖实时响应）。
- [ ] **system prompt 瘦身**：16.8k → ~5k。证据已足：知识按需读已实证可行（grep 命中 Nday 仅 5 秒）+ 外部 SOTA 极短提示词登顶。瘦身内容下沉到按相位读取索引。

## P3 — 排队

- [ ] **facts.jsonl 结构化事实账本**：digest（叙事）之外增加 agent 主动追加的结构化事实流，`infer_phase` 改为读事实，根治 digest 缺失/幻觉（今日 digest_saved=false 兜底属"补救"非"根治"）。
- [ ] **知识命中率计数器**：记录 reference/skill 读取与后续 FINDING 的关联，给"知识层去留"一个数据裁决。
- [ ] **webui 计划任务**：cron 式定时入队 UI（当前靠服务器 crontab + curl）。

## 观察项（达到条件才启动）

| 条件 | 动作 |
|---|---|
| 夜跑出现误报率显著上升 | 上对抗验证 agent（复测 CONFIRMED） |
| 真实 jsonl 增长数据显示上下文劣化 | 动态切片（按 token 阈值切段） |
| 离线统计 >30% 段无 digest 即死 | 循环检测器升级为 LLM 复盘 |
| 同类"Linux 首跑"类 bug 再现 ≥3 个 | 增加 CI：GitHub Actions 跑 py_compile + 回归脚本（ubuntu 环境） |

## 已完成存档（2026-08-30）

- ✅ VPS 全链路部署（Ubuntu 20.04 / 4C4G / systemd / Node22 隔离 / pi@0.84.1）
- ✅ 停止信号通道修复（GBK 根因 + jsonl 兜底 + 陈旧镜像门槛）
- ✅ Cookie/用户意图注入（多框 UI + host 隔离 + 多账号差分指引）
- ✅ business_flow skill + biz-mutations 七族扰动字典 + 相位接线
- ✅ ffuf 打法（fuzzDicts 字典库 + 范式入方法论 + PATH 修正）
- ✅ pid_alive POSIX 分支（队列串行性根基修复）
- ✅ config.py py3.8 兼容 + 入口聚焦 + 卡片信息回退 + 停止信号回归脚本
