# 黑盒 Web 渗透方法论(融合 mastermind 核心)

给 Agent 的浓缩操作手册:按序推进,验证优先,证据完整,判断力来自本文件,操作细节按需读 knowledge/。

## 阶段与门控总览（Safe-First，动手前先读这节）

> 本节是阶段推进的权威定义。**门的证据必须是落盘产物**（契约文件/jsonl/FINDING 行/digest），
> 不是你的记忆——harness 每段读取这些产物推断阶段并写进 BRIEF「阶段判定」，与本节互为校验。

**Safe-First 铁律**：🟢 安全侦察 → 🟡 普通测试 → 🔴 高危探测 → 报告。
先干完所有不会触发 WAF 的事，数据攒够了再碰高危——**被封之前攒够数据 = 策略成功**。
门没过，不进下一层；条件不满足的阶段，跳过原因写进 digest 的「已试路径」或「下一步建议」，禁止静默跳过。

| 阶段 | 层 | 类型 | 进入门（全部满足才许进） | 细节 |
|---|---|---|---|---|
| recon | 🟢 | 强制 | ——（起点） | §1-2 |
| linkage | 🟡 | 强制 | WAF 状态已确认；recon 门（下表）已过 | §3-4 |
| deep | 🟡 | 条件 | linkage 门已过。无 JWT 且无加密体 → 跳过并写明原因 | §5 |
| highrisk | 🔴 | 条件 | linkage 已开工；已有 ≥1 个 CONFIRMED；WAF 存在则全程 SAFE MODE | §6 |
| report | — | 强制 | 全部攻击面收尽或 digest 标注「建议结束」 | §7/§10 |

**门的清单（harness 用同一份产物判定阶段）**：

- **recon 门**：`evidence/_endpoint_params.json` 存在 + `_meta.analysis_completeness ≥ 0.8` + endpoints ≥ 3（§2 的强制产出，未达标=JS 分析没做完，不进 🟡）
- **指纹产物**：`evidence/_fingerprint.md`（WAF 状态/技术栈/CDN，§0 Step 0-1 强制落盘）——linkage 门"WAF 状态已确认"的证据载体
- **linkage 消费**：`evidence/_linkage_results.jsonl` 至少 1 条结果（§3 的测一条记一条）
- **highrisk 门**：会话打印过 FINDING 行（harness 记入 runlog 的 CONFIRMED 计数 ≥1）
- **report**：digest 写「建议结束」

**跨阶段反馈**（源自 mastermind Phase 3.5，非线性执行）：拿到新 Token/ID/Key → 立即回溯（decode/查同类端点）+ 前推（用新身份测越权）——留在本阶段的发现是半个发现。

## 0. 进入目标（Phase 0:先被动后主动,指纹与 WAF 识别）

**先被动后主动**:响应头能看出来的,不要用主动探测去换——WAF 状态未知前,每一次主动请求都可能触发封禁。

1. 读 `BRIEF.md`,确认目标、范围与当前段阶段判定。
2. **Step 0 — WAF/CDN 被动识别(先于一切路径探测)**:每个 URL 发 1 次 `xsreq.py <url>`,只看响应头与错误页,不做目录枚举:
   Cloudflare(`CF-RAY`/`__cfduid`) | Akamai(`X-Akamai-Request-BC`) | Imperva(`X-Iinfo`/`visid_incap_*`) |
   CloudFront(`X-Amz-Cf-Id`/`X-Cache: Hit from cloudfront`) | 阿里云WAF(`X-WAF-*`/`aliws`) |
   腾讯云WAF(`stgw_*`/`TencentCloudWAF`) | 讯飞自研(`iflysec:Herald`) | Fastly(`X-Served-By`/`X-Cache-Hits`)。
   完整签名表 `fingerprint-mapping.md §7b`(命中即读)。
   **结论必须落盘**:WAF 状态(无/WAF类型/CDN类型)+技术栈 写进 `evidence/_fingerprint.md`——它是 linkage 门"WAF 状态已确认"的证据载体。
3. **Step 1 — 技术栈指纹(同一响应里免费拿,一并落盘 _fingerprint.md)**:
   响应头(Server/X-Powered-By) | Cookie 名(JSESSIONID→Java, PHPSESSID→PHP, ASP.NET_SessionId→.NET) |
   HTML(`<div id="app">`→Vue, `id="root"`→React, `ng-app`→Angular) | 错误页(Whitelabel→Spring Boot, Whoops→Laravel, Spring JSON 错误体) |
   JS 全局(`__vue_app__`/`__webpack_require__`)。
   **栈指纹决定后续测什么**:Java→Actuator/Swagger/Druid;PHP→.env;Python→SSTI;Node→原型污染/GraphQL(映射表 fingerprint-mapping.md §8)。
4. **WAF 处置**:WAF detected → 全程 SAFE MODE(敏感路径单请求、间隔 3-8s、每分钟 ≤3 条 admin/actuator 类);
   **未知栈 + WAF = 跳过全部 admin 路径主动探测**,直接进 §2 JS 分析(被动,不触发 WAF)。无 WAF → 可全量,限速 QPS≤3。
5. **Step 2 — 源码泄露搜索(GitHub/Gitee,不碰目标)**:厂商组织名/`{domain} password|api_key|config` 双通道
   (国内厂商 Gitee 优先),提取凭据 → 值池待联动。细节 `skills/source_leak/SKILL.md`。
6. **Step 3 — 被动侦察(秒级,不碰目标)**:crt.sh 子域 + wayback 历史 JS。细节 `skills/passive_recon/SKILL.md`。
7. 本段知识文件见 BRIEF「读取索引」;未列出的按第 13 节表自主选择。

## 1. 主动探测入口（WAF 状态确认之后才允许）

- **快速枚举泄露路径:`xsenum.py <base-url>`**(内置 90+ 条,自动 404 基线标异常)。**只测当前栈匹配的路径**;SAFE MODE 时加 `--concurrency 1 --limit 40`:
  Spring Boot→/actuator /env /heapdump | PHP→/.env /www.zip /index.php.bak | Python→/admin/ /api/docs | .NET→/web.config。
  WAF 存在 → SAFE MODE 限流,未知栈 + WAF 一律不探 admin。
- **字典分级**(BRIEF 工具节有完整路径):paths(轻探,默认) → quickhits(标准) → common(全量) → raft-small(深扫)。
  无 WAF 才允许逐级加深;深扫前先确认轻探档有异常信号,禁止一上来就 raft。
- **ffuf 范式(目录/接口爆破的执行器,补充面而非开局动作)**:**相位次序不变**——recon 仍以
  指纹/WAF 确认 → JS 分析(§2 优先产出契约)为先,ffuf 在 JS 分析落盘后或 linkage 阶段
  需要枚举特定命名空间时启用;先取 404 基线(状态码+长度),
  `ffuf -u <url>/FUZZ -w <字典> -mc all -fc 404 -fs <基线长度> -t 6 -r -timeout 8`;
  字典优先级: fuzzDicts 场景字典(BRIEF 工具节有路径,directoryDicts/apiDict/paramDict/routerDicts 按目标形态选)
  → seclists 分级;**特殊场景(业务名词/厂商词/前端路由名)自建临时字典**写入本段工作目录再 `-w` 喂入——
  JS 里提取到的端点是最高信噪比来源,ffuf 补的是 JS 没露出来的暗面;
  WAF/SAFE MODE 时 `-t 1` 并禁深扫档,发现限流立即降速或停手。
- 本机装了 EHole(`tools/bin/ehole.exe finger -u <url>`)时可用其指纹库辅助识别——**仅用指纹模式,
  禁用其漏洞扫描模块**(自动化漏扫违反 TIER 合规);未安装不等待,响应头指纹已够。
- 401/403 接口是"门":记录,后续配 token/绕过再试,不在此耗。
- 指纹→测试映射、WAF 签名表:`knowledge/references/fingerprint-mapping.md`(命中即读)。

## 2. JS 分析(优先做,产出契约)

- 框架:Vue/React 的 app.js 里常有 API baseURL、路由表;枚举 chunk 找业务接口。
- 提取:/api/ 路径、硬编码密钥(AK/SK/token/appSecret)、注释里的接口文档、调试开关。
- 小程序/APP:找导出 apiUrl+method 的模块,追踪调用方(`knowledge/references/miniprogram-analysis.md`)。
- **契约产出(联动引擎的输入,强制)**:分析完写入 `_endpoint_params.json`,格式:
  ```json
  {"_meta": {"domain": "...", "js_files_analyzed": 3, "analysis_completeness": 0.9},
   "endpoints": [{"path": "/api/user/list", "method": "GET", "content_type": "json",
                  "auth": "Bearer", "params_required": ["page"], "params_optional": ["userId"],
                  "source_files": ["app.abc.js"]}]}
  ```
  至少 3 个端点,每个有 method + source_files。0 端点 = 分析失败,禁止跳过。
- 完整步骤:`knowledge/skills/js_analysis/SKILL.md`(含 SPA 懒加载 chunk 触发、Sub-Path SPA 探测)。

## 3. 值池联动(核心引擎,收益最高)

**核心公式:JS 参数需求表 × 响应值池 = 自动构造的测试矩阵**

1. 每个 200 响应递归挖掘字段名+值,写入 `_leaked_values.json`:
  ```json
  {"values": [{"param": "userId", "value": "10086", "priority": "HIGH",
               "source_endpoint": "/api/user/list", "source_param": "id"}]}
  ```
  敏感字段(password/token/secret/apiKey/ak/sk)→ HIGH;普通 id/name → MEDIUM。
2. **联动注入**:A 返回的参数值 = B 请求的参数输入。拿新值 → 检查哪些接口需要它 → 注入 → 新响应 → 再挖。
   - 典型链:/user/list → userId → /user/info?userId → apiKey → /admin/config (X-API-Key)
   - 别名等价:userId/user_id/uid/memberId 同义;orgId/tenantId 同义;token/accessToken/apiKey 同义。
3. **泛查询**(SSRF 级高危):categoryId/tenantId/groupId 置空或 `%` → 绕过租户隔离批量拉数据。
4. **IDOR**:值池里的 userId/orderId 枚举相邻值,对比响应差异(两个 ID 有差异=证据)。
5. **饱和度**:同类参数 ≤5 值,3 轮无高价值增长 → 停;拿到新权限 token 后重启。
6. 机械循环由引擎接管:harness 每段把未消费配对注入 BRIEF『联动配对』节(linkage.py 生成,CRITICAL/HIGH 优先);测完一条,把结果追加到 `evidence/_linkage_results.jsonl`(`{"endpoint": "...", "param": "...", "value": "...", "hit": true/false, "note": "..."}`),下段自动标记已消费、不重复测。
7. 完整方法论:`knowledge/skills/data_linkage/SKILL.md` + `knowledge/references/response-chaining.md`。

## 4. 参数与接口测试

- 参数枚举:`tools/wordlists/params.txt` 候选参数(id/uid/url/file/redirect 优先),`xsreq.py` 验证。
- 未授权访问:去鉴权头直请求业务接口;改方法(GET/POST/PUT/DELETE);非 2xx 触发 method×content-type 组合重试(最多 12 种)。
- SQLi:数字参数 `1'`/`1 and 1=1`/`1 and 1=2` 差分;字符参数引号报错;观察长度/耗时。**禁止 SQLmap**(SRC 合规)。
- **SSRF(低成本高价值,发现 URL 类参数即测,不等 highrisk)**:url/redirect/callback/image_url 等参数先换 dnslog.cn 子域(按 sink 打标签)→ 有回调=确认,再打云元数据表(169.254.169.254 AWS / metadata.google.internal GCP / 100.100.100.200 阿里云 / metadata.tencentyun.com 腾讯云 / [::ffff:a9fe:a9fe] IPv6 绕过);被黑名单挡 → 十进制/hex/@/302/短链/DNS rebinding 绕过;凭证到手即停(TIER 3)。完整手册 `knowledge/skills/hunt_ssrf/SKILL.md`(OOB 判定门/绕过表/盲打三连)。
- 文件上传:扩展名黑名单绕过(大小写/双写/空格),验证=内容回显或可访问。
- 路径穿越:/static/../..//etc/passwd 或编码绕过。
- **XSS 预检两步法**:①`<s>XSS</s>` 看是否渲染删除线 ②`<img src=x onerror="console.log('xss')">` 看 console。未渲染即停,不深挖。
- **Host 头注入**:发现密码重置接口 → 改 Host/X-Forwarded-Host 看邮件链接域名。
- **低成本注入探针（linkage 即测,不等 highrisk 门——零确认目标也必须测完这层才许收工）**:
  单请求差分探针成本极低,**OOB 优先（参照 mastermind 12.2）**:盲打类一律走 dnslog.cn
  (最快)→ Burp Collaborator → interactsh。**每类参数只试 1-2 次、命中即停**:
  - SQLi 差分 `id=3-1`(数字)/`1'`(字符),盲注用 `SLEEP(5)` 计时+OOB 佐证
  - SSTI `${7*7}`;CMD `;ping dnslog子域`/`|id`(OOB 回连优先于回显)
  - **SSRF:url 参数换 dnslog 子域(有回调=确认)——禁止直打 127.0.0.1/169.254.x(一打就触发
    WAF 拦截,且打草惊蛇);OOB 确认后才做内网/元数据确认(云元数据表见 hunt_ssrf)**
  - XXE OOB(仅 XML 提交点,`<!DOCTYPE>` 外带 dnslog)
  全参数试完无差异 → 才允许在 digest 写"注入面无差异"并建议结束;禁止跳过该层直接收工。

## 5. JWT 与加密

- 全量扫描响应与 JS:grep `eyJ`(JWT)、token、accessToken、jwt;每个 JWT 解码看 alg/claims。
- JWT 攻击链:Bearer 移除 → alg:none → 密钥爆破(弱密钥字典)→ kid 注入 → 声明篡改 → RS256→HS256。
- **JWT↔泛查询闭环(单点→高危险链)**:泛查询拿到 userId/邮箱 → JWT 爆破伪造 → 伪造 token 测越权 → 扩大泛查询范围。
- 前端加密:JS 找 CryptoJS/WebCrypto 函数签名 → 密钥字典 → 批量解密 → 明文回注值池。
- 细节:`knowledge/skills/jwt_attack/SKILL.md` + `knowledge/skills/crypto_attack/SKILL.md`。

## 6. 高危探测(手工,条件触发)

前置:普通层(§3-4)完整 + 价值确认(已有中危+ 发现,或 指纹确认无 WAF——无 WAF 时敏感路径探测冒险成本低);全程 SAFE MODE。零发现+有 WAF → 不进本层,原因写 digest(显式跳过,禁止静默)。
- 注入探针已在 linkage(§4 低成本探针层)测完——本阶段只对**已命中**的注入点做利用链/深挖,不再广撒网。
- Admin 路径:Java→/actuator | PHP→/.env | Python→/admin/ | .NET→/web.config。
- 垂直越权:已获得 token 逐条测管理端点;导出接口(export/download/excel/csv)权限单独测。
- 全部测完:发现高价值被 WAF 挡 → 记 blocked 清单,不要当场死磕(WAF Bypass 是最终手段,留给人工)。

## 7. 验证与收尾(FOUND≠CONFIRMED)

- 每个发现闭环:请求 → 响应 → **影响**,三步都有记录。
- 三级分类(写进 FINDING 行):
  - **CONFIRMED** = 有 impact(能读到不该读的数据 / 能执行不该执行的操作 / 密钥可被利用)
  - **PENDING** = 有检测证据但 impact 未证明(如 401 可访问但无敏感数据)
  - **INFO** = 无利用路径(版本泄露/缺 header/目录列表)
- 确认三问:①能读到什么不该读的数据?②能执行什么不该执行的操作?③Key 能否利用?
- **SRC 提交价值自检**:明文传输无 MITM 实证 / 无链的 Cookie 属性 / .DS_Store 无内容 / 无法证明可行的无限流 / 设计内风险 → 禁止 CONFIRMED(加固项凑数=报告贬值);没真洞就写"未发现可提交漏洞"。完整清单见 system.md「SRC 提交价值自检」。
- 响应差异是客观信号:同样输入两次,长度/耗时/内容变化 = 值得深挖。
- 枚举 miss ≠ 端点不存在:换字典/方法/参数再试一次。
- 卡住 10 分钟无进展 → 停止该面换面。

## 8. 快速跳过清单(Quick-Filter,省时间的判断力)

- Map API key(Google/Baidu/Amap)→ SRC 不收
- 静态目录列表 → informational
- 无链的 Self-XSS → 无影响
- 非敏感操作的 CSRF → 无影响
- 无已知 CVE 的版本泄露 → INFO
- 单独缺失安全头 → 不算漏洞
- 仅内网 IP 泄露且无后续路径 → INFO
- 前端 UI 已展示的数据在 API 返回 → 正常业务
- 发现 admin 页面但 403 → recon finding,不是漏洞

## 9. 常见误判

- 401/403 不是漏洞(除非绕过后拿到数据)。
- 登录接口用户枚举 → 低危,记录即可。
- 弱口令:仅明确授权时测,≤2 req/s,命中即停。
- 硬编码凭据(apiKey/secretKey/JWT Secret)→ **可直接成洞**(P0),但大模型/地图类第三方 key 跳过。

## 10. 报告要点(triage 6 项检查)

- 报告前每个 finding 过 6 项:①有目标 URL ②有漏洞类型 ③证据可复现 ④**已证明实际危害(硬门)** ⑤置信度≥0.7 ⑥数据未在前端公开。
- 未过 ④/⑥ 的 → 标 PENDING,不写进最终报告正文。
- 复现步骤要能照着做出来(完整请求 + 关键响应)。
- 影响写"能做什么":如"可遍历全部用户订单数据"而非"存在越权"。
- 证据文件命名:`01-<漏洞英文名>.txt` 递增编号。

## 11. 工程纪律

- **验证纪律**:输出验证,完整且合理才交付;凭据/哈希是中间步骤不是结论;同一方法连续失败 3 次停下来分析根因;语义不确定用差分验证。
- **时间管理**:外部依赖不可用等 2-3 分钟确认,仍无则写 TRIED;预算优先给高匹配面。
- **多步攻击**:每步确认前提;凭据获取 ≠ 完成,要以该身份找目标数据;发现新服务先枚举标准接口。
- **复用侦察**:不重复已确认事实;从"差一步"断点续攻;缺工具路径补齐后重试;已试失败除非新思路否则跳过。
- **文件隔离**:临时文件加目标标识前缀,读前确认上下文。

## 12. 特殊场景

- APK → `jadx -d /tmp/<id>_src *.apk` 再分析。
- 智能合约 → `cast` 读 storage + trace revert。
- 协议/加密 → 先 `python -c "import xxx"` 检查现成库,用库不自实现。
- 回连 → ncat 监听(`ncat -lvnp <port>`),验证回连再继续。
- 多租户 → 拿凭据后以 victim 身份操作,越权需两个身份的响应差异。
- 502/网关错 → 等 2 分钟轮询,仍无写 TRIED。

## 13. 知识读取表(完整索引,按需 cat;BRIEF 的读取索引由 harness 按阶段状态机注入,本表为完整兜底)

**Skills(操作细节,阶段命中即读):**
| 文件 | 何时读 |
|---|---|
| knowledge/skills/js_analysis/SKILL.md | Phase 1 JS 分析(含 SPA chunk/雪瞳替代方案) |
| knowledge/skills/data_linkage/SKILL.md | Phase 2 值池联动 |
| knowledge/skills/api_fuzz/SKILL.md | Phase 2 全接口覆盖 |
| knowledge/skills/jwt_attack/SKILL.md | 发现 JWT 时 |
| knowledge/skills/crypto_attack/SKILL.md | 发现前端加密时 |
| knowledge/skills/auth_bypass/SKILL.md | 遇 401/403 屏障 |
| knowledge/skills/race_condition/SKILL.md | 优惠券/提现/库存类接口 |
| knowledge/skills/graphql_test/SKILL.md | 发现 /graphql |
| knowledge/skills/websocket_test/SKILL.md | 发现 WebSocket |
| knowledge/skills/cache_poisoning/SKILL.md | CDN/缓存特征 |
| knowledge/skills/http_smuggling/SKILL.md | 发现代理链/畸形请求特征 |
| knowledge/skills/prototype_pollution/SKILL.md | 前端合并深对象场景 |
| knowledge/skills/oauth_sso/SKILL.md | 发现 OAuth/SSO 登录 |
| knowledge/skills/source_leak/SKILL.md | Phase 0 源泄露搜索(参数名+@domain 查 GitHub) |
| knowledge/skills/passive_recon/SKILL.md | Phase 0 被动收集(crt.sh/wayback) |
| knowledge/skills/dependency_cve/SKILL.md | 组件版本指纹命中时 |
| knowledge/skills/vuln_classes/SKILL.md | Phase 5 漏洞百科 |
| knowledge/skills/ai_security/SKILL.md | 目标是 AI/LLM 应用 |
| knowledge/skills/ai_chat_xss/SKILL.md | AI 对话/聊天类目标(前端 XSS 升级链: self-XSS→存储型→IPC 接管,同构通杀) |
| knowledge/skills/xs_auth/SKILL.md | 存在登录口/认证逻辑审计需求(账号池注入后优先读:JS审计→定向验证→接管链,含 OAuth/找回密码白名单) |
| knowledge/skills/business_flow/SKILL.md | BRIEF 注入账号/Cookie 后的登录态业务面(四问框架/寻路四式/返回包地图/XSS冷门落点/钱权益状态机) |
| knowledge/skills/hunt_ssrf/SKILL.md | 发现 URL 类参数/上传审核转存/头像/低代码调试/Webhook/链接预览时(SSRF 低成本高价值,linkage 阶段优先测:OOB→云元数据→绕过) |

**References(查证资料,特征命中即读):**
| 文件 | 何时读 |
|---|---|
| knowledge/references/fingerprint-mapping.md | Phase 0 必读(指纹→测试映射+WAF 签名) |
| knowledge/references/js-extraction-regexes.md | Phase 1 JS 落盘后:敏感信息 grep 模式库(FindSomething+雪瞳合集,漏抓就往表里加) |
| knowledge/references/compliance-rules.md | Phase 0 + 报告前(SRC 合规 TIER 分级) |
| knowledge/references/decision-trees/README.md | Phase 2-3 参数特征命中:先读索引,再精读对应§决策树小文件(29棵) |
| knowledge/references/response-chaining.md | Phase 2-5 响应链方法论 |
| knowledge/references/discovery-amplification.md | Phase 2(端点→同类路径/参数榨干) |
| knowledge/references/high-risk-probing.md | Phase 6 高危探测细节 |
| knowledge/references/cve-chains.md | 组件命中已知 CVE(Solr/Druid/OFBiz/Spring) |
| knowledge/references/1day/README.md | 组件指纹命中时秒查该目录(人工偶发投喂的非完备库,VERIFIED直接用/PENDING先差分;未命中属正常,直接走模型记忆+检索) |
| knowledge/references/impact-escalation.md | Phase 5 影响升级框架 |
| knowledge/references/rating-standard.md | Phase 5 阿里 5 级评级 |
| knowledge/references/vue-spa-attacks.md | Vue 检测到(路由穷举/守卫绕过/Store) |
| knowledge/references/cloud-attack-surface.md | OSS/S3/COS URL 命中(AK/SK 利用链) |
| knowledge/references/miniprogram-analysis.md | 目标有小程序 |
| knowledge/references/report_templates.md | Phase 5 报告模板 |
| knowledge/references/bypass_techniques.md | LAST RESORT(仅高价值被 WAF 挡时) |
| knowledge/references/bug_classes.md | Phase 5 十大漏洞类 |
| knowledge/references/hunt_methodology.md | 完整方法论兜底 |
| knowledge/references/api-fuzz-payloads.md | Fuzz payload 模板 |
| knowledge/references/biz-mutations.md | 登录态业务参数扰动字典(七族:状态翻转/类型替换/数量边界/置空删除/结构注入/身份替换/编码探针,命中即停) |
| knowledge/references/api-testing-methodology.md | API 测试方法论 |
| knowledge/references/403-bypass-complete.md | 403 绕过全集 |
| knowledge/references/crypto-analysis.md / jwt-analysis.md | 加密/JWT 分析 |
| knowledge/references/js-analysis-source-leak.md / js-analysis-vulnforge.md | JS 分析补充 |
| knowledge/references/ai-security-testing.md 与 ai-security-vulnforge.md | 目标 AI/LLM 时 |
| knowledge/references/cloud-attack-surface.md | 云资产命中 |

**Agents(阶段视角,段首可选注入):**
| 文件 | 何时读 |
|---|---|
| knowledge/agents/recon/SKILL.md | 侦察/JS 收集段 |
| knowledge/agents/api_fuzz/SKILL.md | 接口测试段 |
| knowledge/agents/crypto_attack/SKILL.md | 加密/JWT 段 |
| knowledge/agents/bypass/SKILL.md | 绕过段 |
| knowledge/agents/exploit/SKILL.md | 利用/确认段 |
| knowledge/agents/report/SKILL.md | 报告段 |

**其余 references(bypass_techniques 等)** 按需全文检索(cat + grep 关键词),不再列举。
