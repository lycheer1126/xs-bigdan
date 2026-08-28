# 黑盒 Web 渗透方法论(融合 mastermind 核心)

给 Agent 的浓缩操作手册:按序推进,验证优先,证据完整,判断力来自本文件,操作细节按需读 knowledge/。

## 0. 进入目标

1. 读 `BRIEF.md`,记下全部目标 URL、授权边界与当前段任务。
2. 对每个 URL 用 `xsreq.py <url>` 看指纹:状态码/耗时/长度/关键头/首页。
3. 记录:Server / X-Powered-By / Set-Cookie / 跳转链 / 首页框架特征。
4. **WAF 探测**(先于一切测试):错误页特征、响应头、拦截响应。有 WAF → 全程 SAFE MODE(单请求间隔 3-8s);无 WAF → 可全量,限速 QPS≤3。
5. 当前段要读的知识文件见 BRIEF 的"读取索引"节;未列出的按本文件第 13 节表自主选择。

## 1. 指纹与入口

- 框架指纹:响应头、HTML 注释、generator meta、静态资源路径、报错页特征。
- Spring Boot:/actuator、/actuator/health、/env、/heapdump。PHP:/www.zip、/.env、/index.php.bak。Python:/admin/、/api/docs。.NET:/web.config。
- **快速枚举泄露路径:`xsenum.py <base-url>`**(内置 90+ 条,自动标出与 404 基线不同的异常项)。
- 401/403 接口是"门":记录,后续配 token/绕过再试(Phase 4 思路,不在此耗)。
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
- SSRF:url/redirect/callback 参数试 127.0.0.1、169.254.169.254;OOB 优先 dnslog.cn(最快)。
- 文件上传:扩展名黑名单绕过(大小写/双写/空格),验证=内容回显或可访问。
- 路径穿越:/static/../..//etc/passwd 或编码绕过。
- **XSS 预检两步法**:①`<s>XSS</s>` 看是否渲染删除线 ②`<img src=x onerror="console.log('xss')">` 看 console。未渲染即停,不深挖。
- **Host 头注入**:发现密码重置接口 → 改 Host/X-Forwarded-Host 看邮件链接域名。

## 5. JWT 与加密

- 全量扫描响应与 JS:grep `eyJ`(JWT)、token、accessToken、jwt;每个 JWT 解码看 alg/claims。
- JWT 攻击链:Bearer 移除 → alg:none → 密钥爆破(弱密钥字典)→ kid 注入 → 声明篡改 → RS256→HS256。
- **JWT↔泛查询闭环(单点→高危险链)**:泛查询拿到 userId/邮箱 → JWT 爆破伪造 → 伪造 token 测越权 → 扩大泛查询范围。
- 前端加密:JS 找 CryptoJS/WebCrypto 函数签名 → 密钥字典 → 批量解密 → 明文回注值池。
- 细节:`knowledge/skills/jwt_attack/SKILL.md` + `knowledge/skills/crypto_attack/SKILL.md`。

## 6. 高危探测(手工,条件触发)

前置:已确认 ≥1 个中危+(目标有价值)才做;全程 SAFE MODE。
- Admin 路径:Java→/actuator | PHP→/.env | Python→/admin/ | .NET→/web.config。
- 注入类(每项只试 1-2 次):SQLi `id=3-1` / CMD `; sleep 2` / SSTI `${7*7}` / SSRF `http://127.0.0.1:80` / XXE OOB。
- 垂直越权:已获得 token 逐条测管理端点;导出接口(export/download/excel/csv)权限单独测。
- 全部测完:发现高价值被 WAF 挡 → 记 blocked 清单,不要当场死磕(WAF Bypass 是最终手段,留给人工)。

## 7. 验证与收尾(FOUND≠CONFIRMED)

- 每个发现闭环:请求 → 响应 → **影响**,三步都有记录。
- 三级分类(写进 FINDING 行):
  - **CONFIRMED** = 有 impact(能读到不该读的数据 / 能执行不该执行的操作 / 密钥可被利用)
  - **PENDING** = 有检测证据但 impact 未证明(如 401 可访问但无敏感数据)
  - **INFO** = 无利用路径(版本泄露/缺 header/目录列表)
- 确认三问:①能读到什么不该读的数据?②能执行什么不该执行的操作?③Key 能否利用?
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

## 13. 知识读取表(完整索引,按需 cat)

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

**References(查证资料,特征命中即读):**
| 文件 | 何时读 |
|---|---|
| knowledge/references/fingerprint-mapping.md | Phase 0 必读(指纹→测试映射+WAF 签名) |
| knowledge/references/compliance-rules.md | Phase 0 + 报告前(SRC 合规 TIER 分级) |
| knowledge/references/decision-trees.md | Phase 2-3 参数匹配漏洞决策树 |
| knowledge/references/response-chaining.md | Phase 2-5 响应链方法论 |
| knowledge/references/discovery-amplification.md | Phase 2(端点→同类路径/参数榨干) |
| knowledge/references/high-risk-probing.md | Phase 6 高危探测细节 |
| knowledge/references/cve-chains.md | 组件命中已知 CVE(Solr/Druid/OFBiz/Spring) |
| knowledge/references/impact-escalation.md | Phase 5 影响升级框架 |
| knowledge/references/rating-standard.md | Phase 5 阿里 5 级评级 |
| knowledge/references/vue-spa-attacks.md | Vue 检测到(路由穷举/守卫绕过/Store) |
| knowledge/references/cloud-attack-surface.md | OSS/S3/COS URL 命中(AK/SK 利用链) |
| knowledge/references/miniprogram-analysis.md | 目标有小程序 |
| knowledge/references/report_templates.md | Phase 5 报告模板 |
| knowledge/references/bypass-techniques.md | LAST RESORT(仅高价值被 WAF 挡时) |
| knowledge/references/bug_classes.md | Phase 5 十大漏洞类 |
| knowledge/references/hunt_methodology.md | 完整方法论兜底 |
| knowledge/references/api-fuzz-payloads.md | Fuzz payload 模板 |
| knowledge/references/api-testing-methodology.md | API 测试方法论 |
| knowledge/references/403-bypass-complete.md | 403 绕过全集 |
| knowledge/references/crypto-analysis.md / jwt-analysis.md | 加密/JWT 分析 |
| knowledge/references/js-analysis-source-leak.md / js-analysis-vulnforge.md | JS 分析补充 |
| knowledge/references/ai-security-*.md | 目标 AI/LLM 时 |
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
