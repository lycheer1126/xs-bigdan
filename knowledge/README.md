# knowledge/ — 知识层

xs-bigdan 的方法论知识库,全量融入自 mastermind-bug-bounty 2.0.0(知识层保值,执行层工程)。

## 目录规范(新知识入库位置)

| 目录 | 内容 | 回答的问题 | 新知识入库时机 |
|------|------|-----------|----------------|
| `skills/` | 18 个操作技能(js_analysis / data_linkage / jwt_attack / api_fuzz / race_condition ...) | 某类操作**怎么做**(步骤/命令/判定) | 攻克了新攻击手法、沉淀了新操作流程 |
| `agents/` | 7 个阶段视角(recon / api_fuzz / crypto_attack / bypass / exploit / report / ai_security) | 某个阶段**该决策什么**(产出标准/执行顺序/角色定义) | 新增测试阶段、调整阶段产出契约 |
| `references/` | 26 个参考文档(decision-trees / fingerprint-mapping / compliance-rules / cve-chains ...) | 遇到特征时**查什么**(决策树/指纹表/合规速查) | 新增攻击面类型、补充查证资料 |
| `scripts/` | 7 个 harness 钩子(worklog / retry_detector / triage_gate / handoff / context / guard / snow_eyes) | **治理逻辑**如何落地 | 新增治理机制;注意:思想进 `bigdan/`,原脚本留此作参考 |

## 读取机制(为什么这样设计)

pi agent **每段会话都是全新上下文**,文件读取是唯一知识通道。因此:

1. `prompts/methodology.md` 内置**完整读取表**(每段都会注入,作为兜底索引)。
2. 每段 BRIEF 注入**当前阶段索引**(3-5 条:该阶段必须/建议读的文件路径 + 一句话何时读)。
3. agent 自主 `cat` 对应文件,按需加载,不注入全文(防上下文泛滥)。

## 更新流程

```
实战发现新知识
  → 判断归属(skills 操作 / agents 视角 / references 资料)
  → 写入对应子目录(纯 md,无格式要求)
  → 更新 prompts/methodology.md 的读取表(如需要)
  → 下一段/下一轮自动生效(文件读取是动态的)
```

## 来源与版本

- 源: `E:\XS\mastermind-bug-bounty-2.0.0`(mastermind-bug-bounty v3.1.0,融合 vulnforge v0.4.0)
- 本目录为**独立副本**:以后在 xs-bigdan 内直接修改,不反向同步到 mastermind 源(除非有意回馈)。
- 与 xs-bigdan 不适配处的裁剪记录:

| 条目 | 处理 |
|------|------|
| skills 中依赖雪瞳/Shodan/Burp/MCP 的章节 | 保留原文作参考,实际执行以 methodology.md 的替代方案为准(curl+wayback / crt.sh / python socket) |
| scripts/ 的 Obsidian / caido / 多 agent 专属逻辑 | 思想移植进 bigdan/,原文件仅作参考 |
| agents/coordinator 视角 | 不存在(协调者即 bigdan.py 本身) |
| prompts/methodology.md 常驻 13 节(约 199 行) | **保持现状(2026-08-28 决策)**:先跑真实目标实测 token 消耗;若前缀成本高,再按 Heimdall 薄前缀原则瘦身到契约层(产出格式/值池公式/Quick-Filter/FINDING·DIGEST 格式),通用方法论只留指针指向本目录 |
