# 打穿短表（实战手法精选，吸收自实战 skill 知识库）

> 格式：认什么 → 打哪 → 出什么算成 → 假点。进站对得上就按此打，**假点列是防误报的命门**。
> 本表是"现场手法库"，不是扫描清单——对得上特征才打，对不上不硬套。
> **执行纪律：命中特征 → 打 → 结果写 `_linkage_results.jsonl`（hit 或 skipped）——与端点覆盖账本联动，
> 手法必须被执行并被记录，不能只是浏览。**

## 一、认证绕过现场手法（authbypass 精选）

| 认什么 | 打哪 | 算成 | 假点 |
|---|---|---|---|
| 改密口 body 吃旧密/验码字段+新密+身份 id | 旧密/验码**置空或省略**提交；报"与历史密码重复"=已写库证明 | 改掉别人的密(过了立刻改回) | 只回 0 没写库 |
| IDaaS 密保题未占用 id；匿名可提交 | 匿名签发 scope=`_` 的 JWT → 写未占用密保题 → verify 换 reset scope → set_password | 改别人密码 | Success 但登录走另一套 IdP |
| 验签失败时 GET/DELETE/OPTIONS/HEAD 的 **Location 或 msg 带 `calculateSign is:`** | 假签打签约/下单口，**GET 先看 Location**（有的网关 GET 自己就 302 漏签），换 METHOD 再试，抄服务端刚算的合法签 → 打查询 | 合法签过查询口 | 没有回显签 |
| 身份供应商代调（小程序码/OAuth 换票）；非法 pagepath/redirect_uri | 外域 redirect_uri 让下游 5xx 吐出 `client_secret=`；或未登录领票口直接 200 出票 | token/secret 能问出主体 | 报错只有 ErrCode；token 占位串 |
| 未登录发签口给 IM/RTC userSig；identifier 跟请求走 | 不登录拿签登 IM 拉他人会话/群成员 | 拉到**他人**会话/明文手机 | 只能登游客 null；换 UserID 失败 |
| 发签口回包 nonce 以 `MIIE`/`-----BEGIN` 开头 | **把 nonce 当 PKCS8 私钥 load** | 能 load 成 RSA 私钥 | nonce 只是短随机串 |
| 刷新票口空包/空参 | 空包发刷新请求，看是否发 admin/高权票 | 高权票 | 票登不进 |

## 二、IDOR「列表过滤详情不闸」别停表（精选）

| 现象 | 别停，改打 |
|---|---|
| 详情 403 | 跟预览/导出/下载口 |
| 列表有可见性参数 | `status=hidden`/`all`/`isDelete=1` 仍出全文 |
| 筛选项 null 报错 | 改 `[]`（空数组=不过滤） |
| pageNum=0 空 | 改 pageNum=1 |
| telephone 打码 | 看同包备注/自由文本字段 |
| 详情 200 但 canAnswer=false | 看同包 savedConfigDraft 草稿 |
| 换租户/换 id 401 | 附件 URL 只改租户字段（签名可能没罩住） |
| 列表 401/空包/缺参报错 | **都不等于没口**——换方法/换参/换头再试 |
| 作品/项目有 `period=edit|publish` 状态参 | 不登录打内容口 `period=edit`（publish 说已删除、edit 仍出正文才算） | 未发布正文 | 同 id publish 也出 |
| 对外搜索口有 materialType/素材类型参 | 改内部市场/营销规范类型（对照公开橱窗类型差分） | SSO 墙后的内部物料名单/文件直链 | 出的是公开规范 |

**换 id 不限字段名**：userId/uid/memberId/phone/回包抄的 id/0/-1/空都试；密文 id 从 JS 找公钥（modulus/exponent/JSEncrypt）自己加密相邻数字。

## 三、对象存储攻击矩阵（file-upload 精选）

| 认什么 | 打哪 | 算成 | 假点 |
|---|---|---|---|
| STS 凭证字段有 filename/key/prefix | 填 `*`/`**`/空/`/`（**一个 `*` 常落空桶、两个以上才命中业务桶**）；assumerole 场景后段 Policy 常盖前段；对象 key 是文件 md5 从 JS 搜 md5sum | 覆盖他人对象/列出并删别人 key | `*` 只到废桶；覆盖 403 |
| 落地页写死 supabase/nocode `role=anon` JWT；rest 表 403 | 带 apikey+Bearer 打 `POST /storage/v1/object/{桶}/{官方前缀/探测key}`；同对象名再 POST 加 **`x-upsert: true`** 改正文；官方图常在 use-cases/covers 前缀；打完 DELETE 探测文件 | 官方同前缀对象能被盖（同前缀能盖自己刚传的=官方同样能盖） | 只能盖自己的 key |
| STS List/Delete 403 | **别停**——对任意 key GET/PUT；领钥 XHR 不带登录头也打 | 通配钥能读写任意 key | 只有自己的前缀 |
| 带签 URL 的 SignedHeaders 没有 host | 域名换同账号另一桶 + `?uploads` 分片列举 | 列出别的桶 | 签名罩住 Host |
| 对象内容可控但 Content-Type 卡死；有临时钥 | 签一枪带 `response-content-type=text/html` | 浏览器当 HTML 执行=存储 XSS | 签名拒此参 |
| webpack/JS 里有永久 AK/SK | 自己算 POST policy（expiration 拉长）；假签对照 `SignatureDoesNotMatch` | 真钥能写桶 | 钥已吊销 |
| 桶策略对匿名全开 | 无密钥 LIST，再 PUT 盖官方对象 | 官方资源被盖 | 只能列不能写 |
| 业务网关代理存储 `?key=` | `key=/` 或 `key=.` 回 ListBucket XML → 读业务前缀 | 读到他人未公开对象 | 只有公开静态 |
| 分享详情 JSON 一边要提取码一边 auth 对象带明文 `pass_word` | 抄码打下文件 | 密码分享正文 | 是哈希登不进 |
| 云录制分享鉴权口有 download/sign 开关；POST JSON 报"录制 id 不能为空" | 打 download **和** sign 两口；**改 GET query**；无 Referer 403 带分享页 Referer | 鉴权 false 仍拉真媒体 | 真拦了 |

## 四、现场高价值手法（打穿短表精选）

| 认什么 | 打哪 | 算成 | 假点 |
|---|---|---|---|
| 二维码登录；回包有 token；登录页吃 `?token=` | 不登录拿 token；要会话的人打开带 token 的登录 URL | 未登录端变对方号 | token 过期；必须真机扫 |
| 管理后台 SPA 请求拦截器把自定义头当身份（User-Id/employeeId） | 名单抄数字号，把头换成该号打当前人信息口 | 出他人姓名+手机 | 头过了仍空 |
| 前端写死 appId+appKey 或 `role=anon` JWT | 不登录带写死钥打业务表；rest 403 改打存储 REST + `x-upsert:true` | 业务表 count 海量/他人稿 | 只能读自己刚建的 |
| BaaS 匿名 session；列表口不验管理员 | 不登录 `POST .../sessions/anonymous` 再 listRows | 匿名 total 涨且 rows 是**他人**手机/邮箱 | 无会话也是全表(那是另一条) |
| 云开发匿名登录；有低代码数据源 | 匿名签到拿 JWT 打用户集合；HTTP 网关禁用匿名别停，改文档库 `collection=users` | records 是他人手机/uin | 行权限拒匿名且文档库也空 |
| 分享图 generate；replacements 有 `%MARKDOWN%` | markdown 写 `![x](url)`；先对照公网图再打 metadata | 内网/元数据在图上出 500/正文 | 只出模板空图 |
| 助手/Agent 前端历史列表口；登录态只在可选头 | 不登录调列表打详情 | 列表/详情出现**他人**任务原文 | 只出广场/share_id |
| 客服/支持台知识列表+详情；或公告 JSON callname 代理知识库 | 不登录列表打详情；chatbot 检索口正文在 `behavior.value` | 内部话术/协查/短信正文 | 只有公开 FAQ；Info 只要标题 |
| 问卷/测验填表模型口；回包 schema 带答案 | 不登录打 getModel/schema；样图 preview 跟着打 | 内部测验正文+标准答案 | schema 没有 answer |
| 前端 JS 写死签名盐；写/检索口只要 timestamp/sign/nonce | 不登录抄盐自己算（常见 MD5(盐+参数)）；对照其它口要登录 | 平台状态真变(能改回) | 只过网关签名、业务仍 401 |
| 开放支付/进件网关 body 有 appId+sign；假签活应用回 MERCHANT_NOT_EXIST/SUCCESS、死应用回 SIGN_ERROR | 假签枚举 appId 看回码差分；活的打商户查询换 merchantId | 出他人商户证件/银行卡 | 假签一律 SIGN_ERROR |
| 未登录首页/运营 JSON 的跳转 URL（skipPath/jumpUrl）带能当会话用的 token | 抄出来当 Token 打 me/info；对照不带这串应登录过期 | me 是别人的手机/角色 | token 过期/占位串 |
| 详情 id 是长串密文；JS 有 JSEncrypt/security.js/演示 userid | 回包找明文序号，公钥加密相邻数字换进去 | 出别人地址/手机 | 钥匙是验签用的 |

## 五、云 IDE / Codex 编程台 RCE 链

认什么：`/tenant-api/login` + `/codex-api/rpc`（JSON-RPC）；dev/pre/fat 公网暴露优先。
链：裸默认口（admin/admin）→ 会话 → `command/exec`/`fs/*`/`env`/`meta/methods` → root → 集群 SA token + 模型 API Key。
同构变体：零认证 RPC / 注册口+固定邀请码（TENANT_INVITE_CODE）/ JWT 弱密钥 alg:none / 多租户垂直越权 RCE。
假点：通配符证书临时实例随时销毁不算；只登录没有 RPC=半条继续挖。

## 六、对话口工具真执行（AI 场景判定线）

认什么：身份口拦、对话口（/chat/createTask）不带 Cookie 仍接 + 工具列表有 bash/shell/code_interpreter/python；**没有 whoami 对照也打**。
打哪：让模型用工具跑 `id` 或 Python md5（本机对照）；SSE 只有 delta 没有 toolName 别停；列工作目录看提示里没出现过的文件。
算成：SRC 验证台 flag / 云密钥 / 他主体业务正文；**沙箱 `uid=` 只证明命令跑了，不算**。
假点：模型只口头说执行了、数字对不上本机；只 curl 到公网不算通内网；纯越狱没有工具执行不是这枪。

## 七、SSRF 云元数据补充（已收敛至 hunt_ssrf）

> 2026-09 起本节内容并入 `knowledge/skills/hunt_ssrf/SKILL.md` §5b（云开发/网关代打三招：
> 路径差/过滤对照法/匿名网关/固定 POST 代理 302 改写/GOPROXY）。打 SSRF 直接读该手册，
> 本节不再维护，防止两处内容漂移。
