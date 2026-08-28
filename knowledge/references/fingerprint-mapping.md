# Fingerprint Mapping: Tech Stack Detection → Test Plan

> Loaded at Phase 0. Determine stack first, then test ONLY what matches. No blind scanning.
> If no fingerprint matches → 403 bypass + directory traversal only. Do NOT spray paths from other stacks.

---

## 1. Swagger Detection (CRITICAL SHORTCUT)

Test these paths first:
```
/swagger-ui.html
/swagger-ui/index.html
/api-docs
/v2/api-docs
/v3/api-docs
/swagger.json
/openapi.json
```

**If ANY returns 200 with Swagger UI / JSON** → the entire API surface is exposed.
- Skip Phase 1 JS extraction entirely
- Skip Phase 1 endpoint discovery entirely
- Jump to: enumerate all endpoints → test unauthenticated access → search sensitive keywords → parameter injection per decision tree

**Sensitive endpoint keywords to search in Swagger**:
`admin`, `internal`, `export`, `download`, `delete`, `manage`, `config`, `backup`, `sys`, `secret`, `cron`, `execute`, `run`, `shell`, `upload`, `import`

---

## 2. HTTP Header Fingerprints

| Header | Stack | Test Priority |
|--------|-------|--------------|
| `Server: Apache-Coyote/1.1` | Tomcat | `/manager`, AJP, path traversal |
| `Server: nginx` | Nginx | Path parsing bypass, CRLF |
| `Server: Microsoft-IIS` | IIS/ASP.NET | WebDAV, short filename, ViewState |
| `X-Powered-By: PHP/*` | PHP | `.env`, LFI, file upload, SQLi |
| `X-Powered-By: Express` | Node.js | Prototype Pollution, SSRF |
| `X-Powered-By: Next.js` | Next.js | SSR injection, API routes |
| `CF-RAY` / `__cfduid` | Cloudflare CDN | Find origin IP first |
| `X-Cache: Hit` / `X-Served-By` | CDN/Cache layer | Cache poisoning, origin leak |
| `Set-Cookie: JSESSIONID=` | Java (Tomcat/Spring) | Actuator, Swagger, Druid |
| `Set-Cookie: PHPSESSID=` | PHP | PHPInfo, file include |
| `Set-Cookie: ASP.NET_SessionId=` | ASP.NET | ViewState, XXE |
| `Set-Cookie: laravel_session=` | Laravel | `.env`, debug mode |

---

## 3. HTML / Page Feature Fingerprints

| Feature | Stack | Next Step |
|---------|-------|-----------|
| `<div id="app">` + `app.*.js` | Vue.js | Extract router routes via `evaluate_script` |
| `<div id="root">` | React | Extract `__REACT_DEVTOOLS_GLOBAL_HOOK__` |
| `ng-app` / `ng-version` | Angular | Template injection (SSTI) |
| `data-v-*` attributes | Vue (scoped CSS) | Confirm Vue, extract routes |
| `__NEXT_DATA__` | Next.js | SSR props analysis |
| `__NUXT__` | Nuxt.js | SSR props analysis |
| `csrfmiddlewaretoken` | Django | `/admin/`, debug mode, SQLi |
| "Whitelabel Error Page" | Spring Boot | Actuator, Swagger, Druid |
| "Whoops, looks like" | Laravel | `.env`, debug mode |
| "Django Debug Page" | Django | Debug mode, SSTI |
| "Traceback (most recent call)" | Flask/Python | Debug mode, SSTI |

---

## 4. JS Global Variable Fingerprints

| Variable | Stack | What to Do |
|----------|-------|------------|
| `__vue_app__` | Vue 3 | Extract routes, clear guards |
| `__vue__` | Vue 2 | Extract routes |
| `__REACT_DEVTOOLS_GLOBAL_HOOK__` | React | Analyze fiber nodes |
| `__webpack_require__` | Webpack | Source map recovery |
| `webpackJsonp` | Webpack | Source map recovery |
| `CryptoJS` | CryptoJS | Find encryption logic |
| `JSEncrypt` | JSEncrypt (RSA) | Extract public key |
| `axios` | Axios | Extract baseURL |
| `jQuery` | jQuery | Check version for known CVEs |

---

## 5. Path Fingerprints (Quick Probe)

Send one request each, observe response code. 200/403/401 = endpoint exists. 404 = skip.

### Java / Spring Boot
```
/actuator/health  /swagger-ui.html  /druid/index.html
/swagger-ui/index.html  /v2/api-docs  /v3/api-docs
/solr/admin/cores  /jolokia/list  /nacos/
```

### PHP
```
/.env  /phpinfo.php  /wp-admin/  /admin.php
/index.php?s=/  /install.php  /composer.json
```

### Node.js / Express
```
/graphql  /graphiql  /api-docs  /.well-known/openapi
```

### .NET
```
/web.config  /trace.axd  /elmah.axd  /Views/
```

### Python / Django
```
/admin/  /graphql  /api/docs  /redoc  /openapi.json
```

---

## 6. File Extension Fingerprints

| Extension | Stack | Focus |
|-----------|-------|-------|
| `.php` | PHP (various frameworks) | LFI, file upload, SQLi |
| `.jsp` / `.do` / `.action` | Java (Spring/Struts) | SSTI, deserialization, RCE |
| `.aspx` / `.ashx` / `.asmx` | ASP.NET | ViewState, deserialization |
| `.asp` | Classic ASP | SQLi, file upload |
| `.py` | Python | SSTI, debug mode |
| `.go` | Go | Race conditions, API logic |

---

## 7. Cloud / CDN Fingerprints

| Feature | Provider | What to Do |
|---------|----------|------------|
| `*.aliyuncs.com` | Alibaba Cloud OSS | Bucket permissions, AK leak, NoSuchBucket takeover |
| `*.amazonaws.com` | AWS S3 | Bucket public access, AK/SK → SSM RCE |
| `*.myqcloud.com` | Tencent Cloud COS | Bucket permissions, AK/SK → CVM RCE |
| `*.obs.cn-*.myqcloud.com` | Huawei Cloud OBS | Bucket permissions |
| `*.blob.core.windows.net` | Azure Blob | Public access, SAS token leak |
| `*.storage.googleapis.com` | Google GCS | Public access |
| `*.qiniucdn.com` | Qiniu Kodo | Upload credential leak |
| Ping → `*.oss-cn-*.aliyuncs.com` | Alibaba OSS + domain binding | Test NoSuchBucket takeover |
| Ping → `*.s3.amazonaws.com` | AWS S3 + domain binding | Test NoSuchBucket takeover |
| `NoSuchBucket` XML response | Any cloud (bucket deleted) | Re-create bucket with same name+region → hijack |
| `AccessDenied` XML response | Any cloud (bucket exists, private) | Attempt public-read bypass, signed URL analysis |
| `*.qiniucdn.com` | Qiniu | Upload credential leak |
| CF-RAY header | Cloudflare | Find origin IP, test origin directly |
| `X-Akamai-Request-BC` | Akamai | Find origin IP |

---

## 8. Decision: What to Test

```
Fingerprint matched?
├── YES → Test ONLY that stack's paths + that stack's vuln classes
│   ├── Java/Spring Boot → Actuator, Swagger, Druid, Solr, Log4j, deserialization, SSTI
│   ├── PHP → .env, LFI, file upload, SQLi, phar deserialization
│   ├── Node.js → Prototype Pollution, SSRF, API logic, GraphQL
│   ├── .NET → ViewState, path traversal, XXE, deserialization
│   ├── Python → SSTI, debug mode, SQLi, Jinja2 RCE
│   └── Go → Race conditions, concurrency bugs, API logic
│
└── NO match → Conservative testing only:
    ├── 403 bypass (try path variants)
    ├── Directory traversal
    ├── Common config files (.git/HEAD, .env, robots.txt)
    └── Do NOT spray all-stack paths (don't waste requests)
```

---

## 9. CDN / WAF Detected → Origin IP Discovery

If WAF/CDN detected, find origin IP BEFORE testing:
1. DNS history: SecurityTrails, ViewDNS
2. Certificate transparency: crt.sh → search by domain
3. Shodan/Censys: search by SSL cert fingerprint
4. Mail headers: check SPF/DMARC records for origin
5. Subdomain brute force: dev/staging/test subdomains may bypass CDN

**Once origin IP found → test directly, bypassing CDN entirely.**

---

## 10. Mini-Program / APP Detection

**Signals that target has a mini-program or mobile APP**:
- WeChat mini-program → search WeChat for company name/products
- Alipay mini-program → search Alipay app for company services
- Mobile APP → check app stores (App Store, Google Play, 华为应用市场)
- JS references: `wx.miniProgram`, `wx.request`, `my.request` (Alipay)
- HTML comments: `<!-- built for mp -->` or mini-program specific meta tags
- API responses: `platform: "miniprogram"`, `clientType: "mp"`, `source: "wxapp"`

**Decision**:
```
Mini-program/APP detected?
├── YES → Priority SHIFT: mini-program analysis BEFORE web JS analysis
│   1. Obtain .wxapkg → decompile → full source audit
│   2. Source contains ALL APIs + secrets + auth logic (more complete than web JS)
│   3. Packet capture → map mini-program API calls
│   4. Test mini-program APIs for IDOR/auth bypass/hidden endpoints
│   5. Pivot: use mini-program findings (tokens, APIs, secrets) → test web side
│   Reference → references/miniprogram-analysis.md
│
└── NO → Standard web JS analysis
```

**Why mini-program first**: Mini-program source is the FULL frontend codebase — more APIs, more secrets, more parameters than what web JS exposes. One decompilation can reveal the entire backend API surface.

---

## 11. Framework Recognition (Trigger CVE Chain)

| Fingerprint | Framework | Attack Priority |
|-------------|-----------|----------------|
| Set-Cookie: `rememberMe=deleteMe` | Apache Shiro | Key brute force → Shiro-550 RCE / Shiro-721 / permission bypass |
| Cookie: `JSESSIONID` + `/prod-api/` + captcha endpoint | RuoYi (若依) | Default admin/admin123 → Shiro RCE → Swagger → Druid → SQLi |
| FOFA: `icon_hash="1167011145"` or `"290668793"` | RuoYi | Same as above + SnakeYaml/SQL injection/arbitrary file download |
| `/index.php?s=/` or FOFA `icon_hash="-1256084458"` | ThinkPHP | Multi-version RCE (5.x/6.x), log leak, cache leak |
| `/console/login/LoginForm.jsp` | WebLogic | SSRF, deserialization RCE, weak password, path traversal |
| `/seeyon/` | Seeyon (致远OA) | XXE, Fastjson RCE, arbitrary file upload |
| `/js/hrm/getdata.jsp` | Landray (蓝凌OA) | SSRF → file read → RCE |
| `.do` or `.action` extension + `Server: Apache-Coyote` | Struts 2 | S2-* series: OGNL RCE, file upload, redirect |
| FOFA: `icon_hash="-1930827139"` | Weblogic | T3/RMI deserialization, weak password at /console |

**Decision**:
```
Framework recognized?
├── YES → Load cve-chains.md for CVE exploitation steps
│   ├── Has known default password? → Test first (highest success rate)
│   ├── Has known RCE vulnerability in current version? → Exploit via BP MCP
│   └── Has Swagger/Druid/Nacos exposed? → Enumerate → find hidden endpoints
└── NO → Standard decision-tree testing (Phase 3)
```

### RuoYi Full Attack Chain (Framework Attack Pattern Template)

```
1. Default password: admin/admin123 or ry/admin123 → full system access
2. Druid monitor: /druid/index.html → default ruoyi/123456 → SQL monitoring
3. Swagger: /swagger-ui.html → full API enumeration → unauthenticated endpoints
4. Shiro key: fCq+/xW488hMTCD+cmJ3aQ== → Shiro-550 RCE via JRMP
5. Scheduled tasks: /monitor/job → SnakeYaml RCE (<= 4.6.2)
6. SQL injection: /system/dept/list → extract data (v4.2-v4.5)
7. Arbitrary file download: /common/download/resource → read config files
```

**Core insight**: This is NOT just about RuoYi. ANY recognized framework follows the same pattern:
`Default credentials → Exposed monitoring panels → Version-specific CVE → RCE → Data exfiltration`

---

---

# 附录：Sub-Path SPA 探测路径列表

> 独立部署的 SPA 通常隐藏管理后台。主站 `/` 用一套 API，`/order-system/` 的管理后台用完全不同的 API。

## Common Sub-Paths（通用）

```
/admin/ /manage/ /system/ /order/ /dashboard/ /console/ /backstage/
/backend/ /boss/ /ops/ /monitor/ /api-admin/ /internal/
```

## Stack-Specific Admin Paths（按技术栈）

```
Java/Spring: /order-system/ /manage/ /boss/ /backend/ /admin-web/ /platform/
PHP:         /admin/ /adminer/ /phpMyAdmin/ /wp-admin/ /backend/
.NET:        /admin/ /manage/ /backoffice/ /controlpanel/
Python:      /admin/ /dashboard/ /xadmin/ /flower/
Node.js:     /admin/ /manage/ /dashboard/
```

## Detection Method

```
GET each path → 如果返回 HTML（不是 404/redirect/403）→ 是独立 SPA
对每个发现的 SPA:
  1. 提取其 JS bundles（不同的构建，不同的 API 表面）
  2. 提取其 router routes（可能暴露仅管理员的端点）
  3. 作为独立攻击面处理 — 运行完整 Phase 1-3
```

*End of fingerprint-mapping.md*
