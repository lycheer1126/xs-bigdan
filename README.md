# xs-bigdan

本地 SRC 授权渗透测试 Agent：你提供已收集的 URL 清单，它自动完成黑盒测试并输出 Markdown 报告。

> **规范使用文档见 [docs/USAGE.md](docs/USAGE.md)**：目录规范 / 首次使用 / 日常操作 / 时间模型 / 工具管理 / 清理维护 / 常见问题。

核心理念（源自 pi-recon / 百度 Agent 攻防赛前 15 经验）：

- **Harness 做减法**：只负责读目标、写简报、分段执行、硬超时、digest 交接、汇总报告。
- **模型决定怎么想，工具决定能看见什么**：pi agent 在同一段上下文里连续调用 curl/python 完成侦察→测试→验证。
- **共享证据，不共享判决**：会话日志、evidence 证据文件全量保留；段间只传 RECON_DIGEST 交接，不压缩原始痕迹。
- **不固化失败**：「枚举 miss ≠ 端点不存在」，「401 是门存在，不是此路失败」。

## 架构

```
bigdan.py            主调度（入口，留根）：目标读取 → BRIEF → 分段执行 → digest 交接 → 汇总报告
core/                核心模块包（升级主要改动区）
  agent_exec.py      pi 会话执行：tee 日志 + 心跳 + .pi-sessions jsonl 镜像 + 超时 kill
  linkage.py         值池联动引擎：别名归一化 + 语义组 + 配对生成 + 消费闭环（_linkage_results.jsonl）
  retry_detector.py  投降检测：中英文模式，命中即写 retry-prompt 强制换角度（最多 2 次）
  report.py          汇总 findings + evidence → Markdown 报告（CONFIRMED/PENDING/INFO 三态分组）
prompts/             system.md（纪律契约）+ methodology.md（13 节方法论速查 + 完整读取表）
knowledge/           知识层（skills 18 / agents 7 / references 26 / scripts 7 参考），升级靠加文件
dev/                 开发辅助：smoke_lab / blackhole_lab 本地靶场 + watch_run_logs 实时观察
docs/                USAGE.md 操作规范（README 在根）
tools/               bin（xsreq/xsenum/probe + ffuf 等二进制）+ wordlists + downloads + 工具本体
runtime/             运行产物（自动生成）：jobs/<目标id>/（断点）+ outputs/（报告）
```

> 目录规范细节（各目录放什么、新知识入库时机）见 `knowledge/README.md`。

## 快速开始

```bash
# 1. 安装 pi agent（首次）
npm i -g @earendil-works/pi-coding-agent@0.84.1

# 2. 配置
cp .env.example .env      # 填 BIGDAN_LLM_KEY（DeepSeek 直连 key）
cp targets.txt.example targets.txt   # 填你收集的目标 URL

# 3. 运行
python bigdan.py                     # 跑全部目标
python bigdan.py --only www-01       # 只跑某个目标
python bigdan.py --dry-run           # 先看计划
```

## 输入约定

`targets.txt` 每行一个目标：`[id|]url[|备注]`。例如：

```
www-01|https://example.com|主站，重点测登录与API
api-01|https://api.example.com|API网关
```

不填 id 时自动取 host 作为 id。测试范围严格限定在这些 host 内。

## 输出

- `runtime/outputs/report-<时间>.md`：报告（总体结论 + 每目标发现/未闭环线索/证据清单 + 通用修复建议）。
- `runtime/jobs/<id>/`：完整原始数据——会话日志（含每次工具调用与响应）、每段 digest、evidence 证据文件、summary.json。

## 工具矩阵（决定"能看见什么"）

`tools/bin/` 下的工具由 `bigdan.py` 在生成 BRIEF.md 时自动写入「工具」段（绝对路径），prompt 里要求用 `python <绝对路径> ...` 调用（不依赖 PATH——Windows 下 bash 会解析到 WSL、PATH 注入不可靠）：

- **`xsreq.py`** — AI 友好单请求工具：第一行 `[状态码] 耗时s | 长度B | Content-Type`，关键头一行并列，`--save` 存原始请求+响应做证据。设计目的：让模型一眼看到"某个 payload 多耗时 3 秒 / 某 Header 让长度突变"这类差异。
- **`xsenum.py`** — 轻量目录枚举（ffuf 思想）：自动取 404 基线，输出对比表并标出 `[!] 异常` 项——异常项就是新节点，优先深挖。
- **`tools/wordlists/`** — 内置字典：`paths.txt`（敏感路径 90+）、`params.txt`（参数名 60+）。

**仓库自带二进制（`tools/bin/`，Windows amd64，2026-08-27 补齐）**：

- **`ffuf.exe`** v2.1.0 — 目录/参数模糊测试（快速大字典场景替代 xsenum.py）
- **`feroxbuster.exe`** v2.13.1 — 递归目录枚举（深层目录发现）
- **`jadx.bat`** v1.5.1（wrapper → `tools/jadx/`，需本机 Java）— APK 反编译
- **`cast.exe`** v1.7.1（→ `tools/foundry/`，同包含 forge/anvil/chisel）— 链上合约交互
- **`sqlmap.bat`**（wrapper → `tools/sqlmap/`，纯 Python）— SQL 注入自动化
- **`strings.exe`** v2.54（Sysinternals）— 二进制字符串提取

`tools/jadx/`、`tools/foundry/`、`tools/sqlmap/` 为工具本体目录；原始 zip 存档在 `tools/downloads/`。

**动态工具探测**：每次生成 BRIEF.md 时 `tools/bin/probe_tools.py` 扫描本机 PATH（nmap/ncat/httpx/arjun 等）与 `tools/bin/`、`tools/foundry/` 本地二进制（ffuf/feroxbuster/jadx/cast/sqlmap/strings），以及 Python 库（requests/Crypto/web3/bs4/ldap3/pyasn1），把实际可用清单写进 BRIEF「工具」段——模型只"看见"真实存在的工具；缺失的工具由 agent 在 RECON_DIGEST 里标 TOOL_MISSING（源自 pi-recon：harness 决定工具可见性）。

## 模型选择

默认 `deepseek-v4-flash`（快、便宜，适合大范围覆盖）。文章经验：**模型决定能力上限**，深挖单目标、面对复杂利用链时换更强模型：

```bash
python bigdan.py --model deepseek-v4-pro
```

## 断点续打（endgame 心态）

每段收工都会写 `digest-*.md`（目标状态/已试路径/疑似点/下一步建议/TOOL_MISSING）。跑完一轮看报告后，想继续深挖某目标：

```bash
python bigdan.py --only <id>     # 保留 runtime/jobs/ 目录再跑，自动带上已有 digest 续打
```

不要删 `runtime/jobs/<id>/`——那是断点。Agent 也会在 digest 里写"建议结束"来提前收工（已测完时），你可以在报告里看到。

## Agent 与人的协作约定

- 发现漏洞 → Agent 写 `evidence/` 证据文件（完整请求 + 关键响应 + 影响）并打印 `FINDING: 类型|标题|文件名`。
- 判定标准：完整请求 + 可复现响应差异 + 明确安全影响；宁可漏报不可误报。
- 段间交接用 `### RECON_DIGEST` 结构化块：目标状态/技术栈/攻击面/已确认发现/疑似点/已试路径/下一步建议。
- 敏感数据只用于证明漏洞，报告中打码。

## 安全边界

只测 `targets.txt` 白名单内的目标；禁止 DoS / 爆破 / 破坏性操作。使用者须确保对目标拥有明确授权。
