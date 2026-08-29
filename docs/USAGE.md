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
├── webui/                 Web 控制台（FastAPI 本地界面，任务管理/历史/配置，模块开发见其 README）
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
├── credentials.txt        测试账号池（可选，[scope|]user|pass[|备注]，模板 credentials.example.txt，gitignore）
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
| 批量建任务（推荐） | 控制台「＋ 新建任务」弹窗：每行一个 URL 整批粘贴，自动生成 id，按粘贴顺序**入队串行执行**（绝不并行），前一个结束自动开始下一个 |
| 排队管理 | 卡片「取消」= 移出队列；头部「清空排队」= 取消全部排队（运行中不受影响） |
| 跑全部目标 | `python bigdan.py`（CLI 自带串行循环；注意：命令行直跑不受控制台队列管制，混用时自行避免并行） |
| 只跑指定目标（逗号分隔多值） | `python bigdan.py --only www-01,api-01` |
| 断点续打（保留 runtime/jobs/ 再跑） | `python bigdan.py --only www-01` |
| 每目标总预算（默认 3600s=60min） | `python bigdan.py --job-timeout 5400` |
| 并发目标数（默认 1=串行） | `python bigdan.py --concurrency 2` |
| 只看计划 | `python bigdan.py --dry-run` |
| 提供测试账号（推荐） | 复制 `credentials.example.txt` 为 `credentials.txt` 填写；重跑自动注入命中目标的 BRIEF「测试账号」节 |

结果查看：`runtime/outputs/report-<站点>[-<备注>]-<时间>.md`（站点/备注可识别，时间戳区分同站点多轮；结论+证据）；原始数据在 `runtime/jobs/<id>/`
（session 日志 / digest / evidence）。实时观察 Agent 进度：`python dev/watch_run_logs.py`。

## 4. Web 控制台（推荐日常入口）

```bash
python -X utf8 -m webui.server        # http://127.0.0.1:8865（必须带 -X utf8）
```

| 模块 | 能力 |
|---|---|
| 任务 | 统计面板、任务卡片（状态/进度/发现标签）、新建（追加 targets.txt + 后台跑 bigdan.py）、续跑/停止/删除（回收站）、详情页（SUMMARY/Digest/事件流/实时日志/调度器输出/证据） |
| 历史 | runtime/outputs 报告归档浏览 |
| 配置 | targets.txt 在线编辑、环境变量状态（不显示密钥值）、工具链/字典清单 |

新模块开发（导航、API、前端面板三件套）见 `webui/README.md`——加一个目录即注册，零框架改动。

## 5. 时间模型与阶段状态机

- 每目标墙钟预算默认 3600s（1 小时，真实目标侦察+验证以小时计），超时强杀（exit=124 → 报告标"超时终止"），释放给下一目标。
- 段预算 = min(段上限 1800s, 剩余-25s)；剩余 <45s 停止后续段，保证收尾写 digest。
- **段与阶段解耦**：段只是上下文保鲜切片（`--segments` 是最多切几段）；测试阶段（recon/linkage/deep/highrisk/report）由 harness 按落盘产物推断（Safe-First 门控，权威定义见 methodology.md 开头「阶段与门控总览」），写入 BRIEF「阶段判定」并附推断依据，Agent 有据可推翻。
- 续打自动合并历史 findings（按 类型|标题|证据 去重），上一轮发现不会因覆盖 summary.json 而丢失。
- LLM 上游限流（429/5xx）时段内自动重试（最多 2 次，等待+重跑计入本段预算，不打穿目标总预算）；402 余额/鉴权类致命错误直接失败并把原因写进报告。
- Agent 测完可提前收工（RECON_DIGEST 标注"建议结束"→ 下一段阶段判定为 report），不浪费预算。

## 6. 工具管理

- **新增工具**：下载 Windows 版 → 解压 .exe 丢进 `tools/bin/` → 下次运行自动被
  probe_tools.py 探测并注入 BRIEF（无需改代码）。wrapper 类工具参考 bin/jadx.bat 写法。
- **重下工具**：`python tools/downloads/fetch_all.py`（需 Clash 代理；大文件用 python
  requests 流式+zip 完整性校验，curl 会断）。
- **已知坑**：本机 `python3` 是商店空壳，一律用 `python`；GitHub 资产名以 API 查询为准
  （ferox=windows-feroxbuster.exe.zip，foundry=win32_amd64）；火绒可能删 sqlmap.py，
  重 clone 后立即验证。

## 7. 清理维护

```bash
# 清空一轮运行产物（谨慎：runtime/jobs/ 是断点，续打前别删）
python -c "import shutil,pathlib; [shutil.rmtree(p) for p in pathlib.Path('jobs').iterdir() if p.is_dir()]"
# runtime/outputs/ 报告定期归档或删除
```

建议每轮正式测试前：确认 targets.txt 无残留靶场目标、runtime/jobs/ 为上一轮无关数据时清空。

## 8. 常见问题

| 现象 | 处理 |
|---|---|
| 报告标"目标总预算耗尽，超时终止" | 正常；该目标超时，换更强模型或加预算续打 |
| 全部目标秒收工 | runtime/jobs/ 有历史 digest，Agent 复用断点；清空 runtime/jobs/ 重来 |
| pi 无输出 | Windows shim 问题，agent_exec.py 已自动 node 直调，确认 node 在 PATH |
| 下载工具失败 | 确认 Clash 已开（127.0.0.1:7897），用 fetch_all.py 而非 curl |
| 火绒拦截 sqlmap.py | 加白 E:\Agent\xs-bigdan\tools\sqlmap\ 或重 clone 后立即验证 |
