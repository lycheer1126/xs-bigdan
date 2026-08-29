# xs-bigdan

**本地 SRC 授权渗透测试流水线**：你提供授权目标，AI Agent 按阶段方法论自动完成黑盒测试并产出带证据的 Markdown 报告；确定性调度器负责时间控制、质量闸门和状态管理，人只做三件事——**给授权、给测试账号、复核报告**。

> 📖 操作规范见 [docs/USAGE.md](docs/USAGE.md) · 架构与全目录详解见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
>
> ⚠️ **仅限明确授权的目标**（SRC 收录 / 书面委托）。未授权渗透测试违法，后果自负。

---

## 它是怎么工作的

一次任务分五个阶段顺序推进，**进入下一阶段的条件是"产出物落盘并通过检查"，而不是时间到了**：

```
🟢 recon      指纹 + WAF 被动识别 + JS 全量落盘 + 接口契约
     │ 门: 契约文件存在且完整度 ≥0.8、端点 ≥3
     ▼
🟡 linkage    全接口覆盖 + 值池联动（A 接口的响应值自动注入 B 接口）+ 无认证探测
     │       （BRIEF 注入了测试账号时，先登录再打认证后攻击面：越权/IDOR）
🟡 deep       JWT 分析 / 前端加密破解 / 端点榨干（无 JWT 且无加密体则跳过）
     │ 门: 已确认 ≥1 个漏洞
     ▼
🔴 highrisk   高危探测（SQLi/CMD/SSTI/越权/导出），全程限速
     ▼
📋 report     汇总证据 → 报告（triage 硬门自动过滤不实发现）
```

每个阶段是一个**全新会话**执行（避免长上下文导致模型劣化），阶段之间靠结构化交接文档续命——所以可以跑到很晚、断了能续、状态不丢。

## 核心特性

| 特性 | 说明 |
|---|---|
| **阶段状态机** | 进度 = 已通过的门（落盘产物可验证），而非已消耗的时间；卡住自动停在原地等人，不硬闯 |
| **批量任务队列** | 控制台整批粘贴 URL 自动建任务；全局串行绝不并行（保护目标和你的 IP），一个结束自动开始下一个 |
| **测试账号池** | `credentials.txt` 写好账号，按目标自动注入任务简报——大部分高价值漏洞在登录之后 |
| **误报硬门** | 报告生成时对每条 CONFIRMED 做机械检查（有 URL/有类型/有证据/有影响描述），不过自动降级并标注原因 |
| **知识可积累** | 方法论/决策树/敏感信息模式库全部是 Markdown，实战学到什么就往里加什么，下个目标自动生效 |
| **无人值守韧性** | LLM 限流自动重试（带预算）、超时强杀、失败原因写进报告、断点续打不丢发现、误操作中断不留孤儿进程 |

## 快速开始

**依赖**：Python 3.10+、Node.js + [pi-coding-agent](https://github.com/badlogic/pi-mono)（`npm i -g @earendil-works/pi-coding-agent@0.84.1`）、DeepSeek API Key。

```bash
# 1. 配置密钥
copy .env.example .env          # 填 BIGDAN_LLM_KEY（DeepSeek key）

# 2. 填目标
copy targets.example.txt targets.txt   # 每行一个 URL

# 3. （推荐）准备测试账号 —— 认证后才有高价值漏洞
copy credentials.example.txt credentials.txt

# 4. 先看计划，再正式运行
python bigdan.py --dry-run
python bigdan.py
```

**控制台方式（推荐日常使用）**：

```bash
python -X utf8 -m webui.server        # 浏览器打开 http://127.0.0.1:8865
```

任务页可**整批粘贴 URL** 创建任务（自动生成任务 ID，按粘贴顺序串行执行）；配置页可在线维护目标清单、测试账号池和 LLM 档位；历史页浏览报告。

## 日常操作

| 操作 | 方式 |
|---|---|
| 跑全部目标 | `python bigdan.py` |
| 只跑/续跑某目标 | `python bigdan.py --only <id>`（断点自动合并历史发现） |
| 实时观察 Agent | `python dev/watch_run_logs.py` |
| 调整时间预算 | `--job-timeout 5400`（默认每目标 60 分钟，每段 30 分钟） |
| 停止/取消队列 | 控制台任务卡片「停止」/「取消」/「清空排队」 |
| 查看报告 | `runtime/outputs/report-*.md` 或控制台历史页 |

## 项目结构

```
bigdan.py            主调度器：目标解析 → 阶段判定 → 写任务简报 → 分段执行 → 汇总报告
core/                核心模块
  agent_exec.py        pi 会话执行器（限流重试/超时强杀/日志镜像/失败归档）
  linkage.py           值池联动引擎（A 接口响应值 → B 接口输入，自动生成测试矩阵）
  retry_detector.py    投降检测（Agent 过早放弃时强制注入换角度指令）
  report.py            报告生成 + triage 硬门（CONFIRMED 不过检查自动降级）
prompts/             常驻提示词：system.md（铁律/纪律/协议）+ methodology.md（阶段门控+操作手册）
knowledge/           知识层（全部 Markdown，改文件即改行为）
  agents/              阶段角色卡 ×7（该阶段你是谁、交付什么）
  skills/              操作手册 ×21（xs_auth 登录审计 / ai_chat_xss / js_analysis …）
  references/          字典速查 ×27（决策树 / WAF 签名 / 敏感信息模式库 / 合规 TIER …）
webui/               FastAPI 控制台（任务队列 / 配置 / 历史报告）
tools/               Agent 可调用工具（xsreq / xsenum / browser_probe / 字典分级 / 外部二进制）
dev/                 本地靶场 + 实时日志观察
docs/                USAGE.md（操作规范）+ ARCHITECTURE.md（架构与全目录详解）
runtime/             运行产物（自动生成，gitignore；jobs/ 是断点，续打前勿删）
```

完整版（每个文件的职责注释、机制与代码位置对照）见 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**。

## 知识层：让能力随实战增长

Agent 的判断力来自 `knowledge/` 的 Markdown 文件，全部**按需加载**（每段只读命中的 2-3 个，防止上下文膨胀）：

- **遇到新攻击手法** → 在 `skills/` 加操作手册（参考 `skills/xs_auth/SKILL.md` 的结构：识别信号 → 阶段步骤 → 测试清单 → 合规红线）
- **发现漏抓的敏感信息格式** → 在 `references/js-extraction-regexes.md` 加一行 grep 模式
- **某类参数怎么测** → `references/decision-trees/` 加一棵决策树
- 最后在 `prompts/methodology.md` §13 的读取表登记触发条件——下个目标自动生效

## 安全边界与免责声明

**本工具仅限在获得明确授权的目标上使用。**

- 只测试 `targets.txt` 白名单内的目标；禁止 DoS / 批量爆破 / 破坏性操作
- 内置合规约束：越权验证 ≤5 条数据、弱口令仅固定组合且限速、危险工具不默认启用、操作分级（TIER 1/2/3）
- 敏感文件（`.env` 密钥、`credentials.txt` 账号、`targets.txt` 在测目标）均不入库，模板见对应 `.example` 文件
- 使用者须确保对目标拥有合法授权；因使用本项目产生的任何后果由使用者自行承担
