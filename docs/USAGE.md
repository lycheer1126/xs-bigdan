# xs-bigdan 规范使用文档

本地 SRC 授权渗透测试 Agent：以 pi-coding-agent 为大脑、薄 harness 做调度与证据管理。
本文件是项目唯一的操作规范；结构与使用问题先查这里。

## 1. 目录规范

```
xs-bigdan/
├── bigdan.py              主调度器（入口，只运行这一个文件）
├── core/                  核心模块包（升级主要改动区，勿在根目录新增 py）
│   ├── agent_exec.py      pi 会话执行器（Windows 下自动 node+cli.js 直调）
│   ├── linkage.py         值池联动引擎（配对生成/消费闭环，bigdan.py 自动调用）
│   ├── retry_detector.py  投降检测（中英文模式，命中写 retry-prompt）
│   └── report.py          报告生成器（bigdan.py 自动调用，勿手动跑）
├── prompts/               提示词（system.md / methodology.md，改这里即改 Agent 行为）
├── knowledge/             知识层（skills/agents/references/scripts，升级靠加文件，规范见其 README）
├── dev/                   开发辅助（smoke_lab / blackhole_lab 本地靶场 + watch_run_logs 观察）
├── docs/                  文档（USAGE.md 操作规范；README.md 在根）
├── tools/
│   ├── bin/               可执行入口（probe 自动扫描区；新增工具解压 .exe 丢这里）
│   ├── foundry/           cast 等链上工具本体
│   ├── jadx/              jadx 本体（bin/jadx.bat 为 wrapper）
│   ├── sqlmap/            sqlmap 本体（bin/sqlmap.bat 为 wrapper）
│   ├── wordlists/         字典（paths.txt / params.txt）
│   └── downloads/         原始 zip 存档 + fetch_all.py（重下工具脚本）
├── runtime/               运行产物（自动生成，勿手改）
│   ├── jobs/<目标id>/    断点（BRIEF/日志/digest/evidence/summary，续打依赖）
│   └── outputs/           报告输出
├── targets.txt            目标清单（每行 [id|]url[|备注]，# 注释）
├── .env                   本地密钥（LLM key；已被 .gitignore 排除）
└── README.md              项目简介
```

**规则**：`.env`、`runtime/jobs/`、`runtime/outputs/` 永不提交 git；`tools/` 下二进制不入库（体积大，
缺失时用 `tools/downloads/fetch_all.py` 重新下载，需 Clash 代理）。

## 2. 首次使用

前置依赖（均已装好）：Python 3.10+、pi-coding-agent 0.84.1（npm 全局）、Clash 代理
（下载工具时才需要）。

```bash
cd E:\Agent\xs-bigdan
copy .env.example .env        # 填 BIGDAN_LLM_KEY（DeepSeek，sk-35位）
# 编辑 targets.txt 填入真实目标（格式见文件内注释）
python bigdan.py --dry-run    # 只打印计划，不执行
python bigdan.py              # 正式运行
```

## 3. 日常操作

| 操作 | 命令 |
|---|---|
| 跑全部目标 | `python bigdan.py` |
| 只跑指定目标（逗号分隔多值） | `python bigdan.py --only www-01,api-01` |
| 断点续打（保留 runtime/jobs/ 再跑） | `python bigdan.py --only www-01` |
| 每目标总预算（默认 1200s=20min） | `python bigdan.py --job-timeout 1800` |
| 并发目标数（默认 1=串行） | `python bigdan.py --concurrency 2` |
| 只看计划 | `python bigdan.py --dry-run` |

结果查看：`runtime/outputs/report-<时间>.md`（结论+证据）；原始数据在 `runtime/jobs/<id>/`
（session 日志 / digest / evidence）。实时观察 Agent 进度：`python dev/watch_run_logs.py`。

## 4. 时间模型（每个目标的硬预算）

- 每目标墙钟预算默认 1200s，超时强杀（exit=124 → 报告标"超时终止"），释放给下一目标。
- 段预算 = min(段上限, 剩余-25s)；剩余 <45s 停止后续段，保证收尾写 digest。
- Agent 测完可提前收工（RECON_DIGEST 标注"建议结束"），不浪费预算。

## 5. 工具管理

- **新增工具**：下载 Windows 版 → 解压 .exe 丢进 `tools/bin/` → 下次运行自动被
  probe_tools.py 探测并注入 BRIEF（无需改代码）。wrapper 类工具参考 bin/jadx.bat 写法。
- **重下工具**：`python tools/downloads/fetch_all.py`（需 Clash 代理；大文件用 python
  requests 流式+zip 完整性校验，curl 会断）。
- **已知坑**：本机 `python3` 是商店空壳，一律用 `python`；GitHub 资产名以 API 查询为准
  （ferox=windows-feroxbuster.exe.zip，foundry=win32_amd64）；火绒可能删 sqlmap.py，
  重 clone 后立即验证。

## 6. 清理维护

```bash
# 清空一轮运行产物（谨慎：runtime/jobs/ 是断点，续打前别删）
python -c "import shutil,pathlib; [shutil.rmtree(p) for p in pathlib.Path('jobs').iterdir() if p.is_dir()]"
# runtime/outputs/ 报告定期归档或删除
```

建议每轮正式测试前：确认 targets.txt 无残留靶场目标、runtime/jobs/ 为上一轮无关数据时清空。

## 7. 常见问题

| 现象 | 处理 |
|---|---|
| 报告标"目标总预算耗尽，超时终止" | 正常；该目标超时，换更强模型或加预算续打 |
| 全部目标秒收工 | runtime/jobs/ 有历史 digest，Agent 复用断点；清空 runtime/jobs/ 重来 |
| pi 无输出 | Windows shim 问题，agent_exec.py 已自动 node 直调，确认 node 在 PATH |
| 下载工具失败 | 确认 Clash 已开（127.0.0.1:7897），用 fetch_all.py 而非 curl |
| 火绒拦截 sqlmap.py | 加白 E:\Agent\xs-bigdan\tools\sqlmap\ 或重 clone 后立即验证 |
