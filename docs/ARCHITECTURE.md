# xs-bigdan 架构总览

> 本文件是项目的**权威架构文档**——目录大纲、数据流、关键机制、外部依赖、已知边界。
> 结构性改动后请同步更新本文件。最后更新: 2026-08-29。

## 一、一页总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          xs-bigdan 系统边界                                  │
│                                                                             │
│  ┌─ webui 控制台 (FastAPI, :8865) ──────────────────────────────┐           │
│  │ 任务卡片/批量队列/配置(账号池·LLM档位)/历史报告/实时日志        │           │
│  │ 队列线程(3s): 串行启动下一个,绝不并行                           │           │
│  └──────────────┬───────────────────────────────────────────────┘           │
│                 │ 子进程(孤儿启动,taskkill /T 可杀)                           │
│                 ▼                                                           │
│  ┌─ bigdan.py 薄 harness(确定性编排,全部闸门在此) ───────────────┐           │
│  │ 目标解析 → 阶段状态机 infer_phase → write_brief → 分段执行     │           │
│  │ 闸门: 段预算强杀/目标总预算/LLM限流重试(dealine感知)/投降检测   │           │
│  │       triage硬门(报告期)/credentials池/队列串行                │           │
│  └──────────────┬───────────────────────────────────────────────┘           │
│                 │ node 直调 pi-coding-agent(--system-prompt+BRIEF)           │
│                 ▼                                                           │
│  ┌─ pi agent (LLM 大脑: deepseek flash/pro) ────────────────────┐           │
│  │ 工具: bash+read+edit+write → 调用 tools/bin/*(probe 决定可见) │           │
│  │ 知识: system.md+methodology.md 常驻; knowledge/ 按需 cat      │           │
│  └──────────────────────────────────────────────────────────────┘           │
│                 │ 产出                                                      │
│                 ▼                                                           │
│  runtime/jobs/<id>/ : session日志(脏) + digest(交接) + evidence(证据/契约)   │
│  runtime/outputs/   : report-*.md(triage 硬门过滤后的交付物)                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

**设计三原则**: ①harness 只做确定的事,模型只做判断; ②工具决定 Agent 能看见什么(输出整形+合规护栏); ③知识按需加载,上下文是稀缺资源。

## 二、一次任务的完整生命周期

```
创建(webui 批量粘贴/CLI targets.txt)
  → 队列(串行,一个结束自动下一个)
  → write_brief(阶段状态机 infer_phase 依据落盘产物判定 recon/linkage/deep/highrisk/report)
  → spawn pi(新会话=保鲜切片; system prompt 常驻 + BRIEF 注入角色卡/手册/账号/联动配对)
  → Agent 干活(xsreq/browser_probe/字典分级…; 产出 evidence/ 契约+证据, FINDING 行)
  → 段结束: 提取 digest+findings(stdout 丢失时从 .pi-sessions jsonl 兜底恢复,防停止信号被吞) → runlog 事件 → 投降检测(可注入重试) / BLOCKED(停,等人)
  → 下一段: 重新 infer_phase(产物变化→阶段推进) → 新鲜上下文接棒
  → 段数或预算尽 → report.py(triage 硬门过滤) → runtime/outputs/report-*.md
```

## 三、全部目录文件大纲

```
xs-bigdan/
├── bigdan.py                      # 主调度器(唯一入口): 目标解析/账号池/阶段状态机 infer_phase/
│                                  #   PHASE_READ_INDEX/write_brief(BRIEF生成)/run_target(分段循环)/
│                                  #   队列并发(fill-slot)/报告触发/队尾统计。~800行
├── core/                          # 核心模块包(升级主要改动区)
│   ├── agent_exec.py              #   pi 会话执行器: Windows node直调/tee+心跳/jsonl镜像/
│   │                              #   429·5xx deadline感知重试/致命错误分类/extract_last_error/
│   │                              #   Ctrl+C 杀子进程(防孤儿打目标)
│   ├── linkage.py                 #   值池联动引擎: EndpointRegistry×ValuePool→PairingEngine 配对/
│   │                              #   语义组扩展/自配对排除/check_pair_completeness 门控/
│   │                              #   JS完整性检查(兼容 list+dict 契约)/方法回退矩阵
│   ├── retry_detector.py          #   投降检测: 中英文模式匹配 agent 输出,命中→下段强制换角度(≤2次)
│   ├── report.py                  #   报告生成: 汇总 findings+evidence→md; triage 硬门(4项机械检查,
│   │                              #   不过自动降 PENDING+标注); 证据路径 basename 加固
│   └── __init__.py
├── prompts/                       # 常驻 system prompt(每段固定成本,改这里=改性格与流程)
│   ├── system.md                  #   铁律(Safe-First/WAF SAFE MODE/等待即烧钱/上下文预算)/工具用法/
│   │                              #   BLOCKED 协议/证据落盘协议/RECON_DIGEST 八节格式/输出纪律
│   └── methodology.md             #   阶段与门控总览(权威)+Phase 0被动优先执行序+13节操作手册+
│                                  #   §13 知识完整读取表(全部 knowledge 文件的触发条件索引)
├── knowledge/                     # 知识层(纯 md,改文件即改行为;读表见 methodology §13)
│   ├── agents/                    #   阶段角色卡×7(段首第一读: 使命/产出标准/验收线)
│   │   ├── recon/                 #     侦察卡(契约产出使命;已适配 browser_probe/evidence 路径)
│   │   ├── api_fuzz/              #     接口测试卡
│   │   ├── exploit/               #     利用卡(FOUND≠CONFIRMED;已适配 md 报告协议)
│   │   ├── report/ bypass/ crypto_attack/ ai_security/   # 其余视角(§13 触发)
│   ├── skills/                    #   操作手册×21(某类操作怎么做,有步骤顺序)
│   │   ├── xs_auth/               #     登录口逻辑审计(用户实战沉淀:S/A~F/O/G 测试清单+思路库登记表)
│   │   ├── ai_chat_xss/           #     AI对话XSS升级链(self-XSS→存储型→IPC接管,同构通杀)
│   │   ├── js_analysis/ data_linkage/ jwt_attack/ crypto_attack/ auth_bypass/ …(18+2)
│   ├── references/                #   字典/速查×27(特征命中才翻)
│   │   ├── decision-trees/        #     29 棵漏洞决策树(每棵≤250行,按§跳读)+README索引
│   │   ├── js-extraction-regexes.md  # JS敏感信息grep模式库(FindSomething+雪瞳合集,漏抓就加行)
│   │   ├── fingerprint-mapping.md #     指纹→测试映射+WAF被动签名§7b+SAFE MODE量化规则
│   │   ├── compliance-rules.md    #     SRC合规TIER分级/≤5条红线/声明模板
│   │   ├── rating-standard.md impact-escalation.md high-risk-probing.md cve-chains.md …
│   └── README.md                  #   目录规范(写给人看,Agent 不读)
├── tools/                         # Agent 可调用物(可见性由 probe_tools 决定)
│   ├── bin/                       #   CLI 入口(probe 扫描区)
│   │   ├── xsreq.py               #     AI友好单请求: 首行[码]耗时|长度|CT;连接重试;--save证据
│   │   ├── xsenum.py              #     轻量目录枚举: 404基线差分;连接重试;net-err 单列不污染
│   │   ├── browser_probe.py       #     无头浏览器: open/js/chunks/login/snow(雪瞳26类提取)
│   │   ├── slider_captcha_solver.py #   滑块验证码程序化解题(xs_auth S9,AES/SM4)
│   │   ├── probe_tools.py         #     本机工具动态探测→BRIEF「工具」节(sqlmap/ysoserial 已隐藏)
│   │   └── ffuf.exe feroxbuster.exe nuclei.exe cloudfox.exe ehole(可选)…  # 外部二进制
│   ├── js/snow_eyes_inject.js     #   雪瞳注入 payload(snow 子命令加载,git 历史复活)
│   ├── wordlists/                 #   字典分级: paths(轻探103)→seclists/web/(quickhits/common/
│   │                              #   raft-small/api-endpoints 深扫族)+params.txt;BRIEF 已接线
│   ├── sqlmap/ jadx/ foundry/ jwt_tool/ # 靶场工具本体(sqlmap 对 SRC 已隐藏)
│   └── downloads/fetch_all.py     #   工具重下脚本(直连+镜像;EHole v3.1 已入清单)
├── webui/                         # FastAPI 控制台(:8865;模块插件式架构)
│   ├── server.py                  #   入口: CSRF防线/静态禁缓存/队列后台线程(3s tick)
│   ├── core.py                    #   交互层: 任务CRUD/队列(enqueue/tick/clear)/LLM档位(key_env化)/
│   │                              #   credentials池/失败统计/进程树管理(taskkill /T)
│   ├── routes/                    #   tasks(单建/批量/队列清空/续跑/停止/删除/日志) config targets/
│   │                              #   credentials/LLM 档位 history
│   ├── static/                    #   app.js(骨架)+modules/{tasks,config,history}.js
│   └── README.md
├── dev/                           # 开发辅助
│   ├── smoke_lab.py blackhole_lab.py  # 本地靶场(验证正常/超时路径)
│   ├── watch_run_logs.py          #   实时观察 Agent 输出
│   └── gen_demo.py                #   webui 演示数据生成(demo- 前缀,可删)
├── docs/                          # USAGE.md(操作规范) + ARCHITECTURE.md(本文件)
├── targets.txt                    # 目标清单([id|]url|备注;webui 批量自动生成行)
├── credentials.txt                # 测试账号池([scope|]user|pass|备注;gitignore)
├── credentials.example.txt        # 账号池模板(入库)
├── .env / .env.example            # LLM keys(BIGDAN_LLM_* + LLM_KEY_<档位>;gitignore)
├── llm-profiles.json              # LLM 档位(只存 key_env 变量名,不落明文;gitignore)
├── tools/downloads/*.zip          # 工具存档(fetch_all.py 重下)
└── runtime/                       # 运行产物(gitignore;断点在这,续打勿删)
    ├── jobs/<目标id>/             #   BRIEF/summary.json/runlog.jsonl/session-N.log/
    │                              #   digest-N.md/evidence/(证据+_endpoint_params.json契约)
    ├── outputs/report-*.md        #   交付报告(triage 硬门过滤后)
    └── .webui/                    #   procs.json/queue.json/webui日志
```

## 四、关键机制速查

| 机制 | 位置 | 一句话 |
|---|---|---|
| 阶段状态机 | bigdan.py `infer_phase` | 落盘产物判定 recon/linkage/deep/highrisk/report;digest声明优先,推断兜底,冲突透明 |
| 上下文保鲜切片 | `--segments`/seg预算 | 段=新会话(防上下文劣化);digest 只带走状态,垃圾留在 session 日志 |
| LLM 限流重试 | agent_exec `run_pi_session` | 429/5xx deadline 感知重试≤2;402/鉴权=致命直接失败;失败原因入报告 |
| 投降检测 | core/retry_detector | agent 说"放弃"→下段强制注入换角度指令(≤2次) |
| BLOCKED 协议 | system.md+bigdan | 凭证/验证码/授权不明→停;webui 提供线索→user_input.md 注入下段 |
| 会话 Cookie/用户意图 | webui 建任务+write_brief | 建任务时可填 cookie(每行一账号,自动按 host 隔离,多账号→差分指引)与想法→job 目录 cookies.txt/intent.md→每段 BRIEF;browser_probe --cookie 浏览器层注入 |
| triage 硬门 | core/report.py | CONFIRMED 4项机械检查(类型/URL/证据/影响),不过自动降 PENDING |
| 任务队列 | webui/core.py | 全局串行绝不并行;queue.json 持久化;webui 重启自动接力 |
| 账号池 | bigdan.py `parse_credentials` | scope 匹配注入 BRIEF;≤2/s 红线随行 |
| 阶段门控产物 | `_recon_gate` | recon门=契约文件完整性;指纹产物=_fingerprint.md;highrisk门=CONFIRMED≥1 |
| LLM 档位 | webui/core.py + llm-profiles.json | key 明文只进 .env(key_env 化);切换档位=切 provider/model |

## 五、外部依赖

- **pi-coding-agent 0.84.1**(npm 全局)——agent 大脑载体;`--system-prompt/-p/--resume/--mode rpc` 是关键接口
- **Python 3.10+**: core/bigdan 零第三方依赖;browser_probe 需 playwright(+chromium);slider 需 pycryptodome/numpy/Pillow
- **LLM**: DeepSeek 直连或兼容网关(llm-profiles 档位切换)
- **Clash 代理**(127.0.0.1:7897): 仅 tools/downloads/fetch_all.py 下载工具时需要

## 六、已知边界与待办(触发条件制)

| 事项 | 触发条件 |
|---|---|
| 验证代理(对抗误报的第二意见 agent) | 首轮实测误报率可观时 |
| 动态切片(会话字节阈值) | 实测 session jsonl 增长曲线后定阈值 |
| 循环检测器/收尾救援 | 离线日志统计显示"满段被杀无digest">30% 或高频循环 |
| pi 扩展限速(工具层强制) | 实测发现限速纪律被违反 |
| 小程序/App 取材工具链 | 决定补信息搜集层时 |
| knowledge 内容去重审计 | 知识命中率脚本产出数据后 |
| .env 的 BIGDAN_SEGMENTS 等运行时变量 | 已修:load_dotenv 提前到常量求值前 |
```
