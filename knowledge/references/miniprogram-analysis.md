# Mini-Program Reverse Engineering & Multi-End Attack Chain

> Loaded when target has a WeChat/Alipay mini-program or mobile APP companion.
> Core insight: Mini-programs often share backend APIs with the web app but have weaker auth, hidden endpoints, and more exposed parameters. Decompile → audit source → test mini-program → pivot to web.

---

## Step 0: The Attack Chain (Big Picture)

```
Decompile .wxapkg → Audit source code
    ↓
Find API endpoints / Secrets / Hidden params / Auth logic
    ↓
Packet capture → Map all API calls + Auth headers
    ↓
Test mini-program APIs (IDOR / Auth bypass / Hidden endpoints)
    ↓
Pivot to Web → Same APIs? Same tokens? Weaker auth on web?
```

**Why this works**: Mini-programs often have:
- APIs not exposed on the web frontend (hidden endpoints)
- Weaker auth (rely on client-type fields instead of real auth)
- Old API versions still accessible
- Secrets/configs hardcoded in the mini-program package
- Same backend, different auth enforcement per platform

---

## Step 1: Decompile Mini-Program Source

### 1.1 Obtain the .wxapkg Package

```
WeChat mini-programs store .wxapkg files locally:
- PC WeChat: FileStorage/Applet/{appid}/{version}/
- Android (root): /data/data/com.tencent.mm/MicroMsg/{user}/appbrand/pkg/
- iOS (jailbroken): similar structure under WeChat app data

Alternative: Capture via proxy during mini-program launch
- The .wxapkg is downloaded on first open
- Filter for .wxapkg in proxy history
```

### 1.2 Decompile .wxapkg

```
Tools:
- wxappUnpacker: unpack .wxapkg → extracted JS/JSON/WXML/WXSS files
- unveilr: next-gen unpacker with better encryption support

After decompilation, you get:
├── app-config.json    # App config, permissions, navigation
├── app-service.js     # Core logic, API calls, business logic
├── page-frame.html    # UI templates (WXML compiled)
├── pages/             # Per-page JS files
└── utils/             # Helper functions, crypto, auth
```

### 1.3 Audit the Decompiled Source (Priority Order)

```
1. API endpoints (highest priority):
   grep: "https://" "http://" "baseUrl" "request(" "wx.request("
   → Map ALL API paths, methods, parameter names

2. Auth & tokens:
   grep: "token" "access_token" "Authorization" "session" "openid" "unionid"
   → How is auth implemented? What headers? Where is token stored?

3. Secrets & keys:
   grep: "appId" "appSecret" "secret" "key" "apiKey" "sign" "signature"
   → Hardcoded secrets, signing algorithms, API keys

4. Hidden parameters:
   grep: "userId" "tenantId" "role" "clientType" "version" "platform"
   → Parameters the client sends that should be server-controlled

5. Encryption logic:
   grep: "encrypt" "decrypt" "AES" "RSA" "md5" "sha" "sign"
   → Custom encryption/signing, MD5-based signatures with hardcoded salt

6. Version management:
   grep: "version" "buildVersion" "minVersion" "upgrade"
   → Multiple API versions? Old versions still accessible?

7. Platform flags:
   grep: "platform" "clientType" "device" "from" "source"
   → Does the backend trust client-sent platform identifiers?
```

---

## Step 2: Packet Capture & API Mapping

### 2.1 Capture Flow

```
1. Configure proxy (Burp/Charles) → set phone proxy to capture
2. Complete a full business flow:
   Launch → Login → Browse → Key action (order/upload/pay) → Logout
3. Run with TWO accounts (A and B) for IDOR comparison later
```

### 2.2 Archive Template (Per API Endpoint)

```
For each captured API request, document:
- Method + Path (e.g., POST /api/v2/order/create)
- Auth: token/cookie/none; where is it placed (header/query/body)
- Key params: userId/tenantId/role/clientType/version/orderId/fileId
- Response value: IDs returned? Sensitive fields leaked? Usable for chaining?
```

### 2.3 Group APIs by Module

```
Login/Auth → User/Profile → File/Upload → Order/Payment → Admin/Config → Other
```

---

## Step 3: Mini-Program-Specific Vulnerability Testing

### 3.1 Multi-End Auth Inconsistency (Highest ROI)

```
Same API, different platform → different auth enforcement?
├── Mini-program: no auth → 200 OK
├── Web app: auth required → 401
└── Result: auth bypass via mini-program endpoint

Test for each API:
  1. Send request from mini-program (with mini-program token)
  2. Send same request from web (with web token or no token)
  3. Compare responses → auth inconsistency?
```

### 3.2 Client-Type Trust Abuse

```
If the server trusts client-sent platform identifiers:
  Original: POST /api/data  Body: {platform: "miniprogram", version: "2.1.0"}
  Test:     POST /api/data  Body: {platform: "admin", version: "internal"}
  
Common client-type params:
  platform, clientType, device, from, source, channel
  version, buildVersion, apiVersion
```

### 3.3 Version Downgrade Attack

```
New version has auth → old version doesn't?
├── Current: POST /api/v2/user/info (auth required)
├── Try:     POST /api/v1/user/info (no auth?)
├── Try:     POST /api/user/info (legacy, no version)
└── Try:     Header: X-API-Version: 1.0.0

Old API versions are often left running without updates.
```

### 3.4 Hidden API Discovery

```
From decompiled source: /api/internal/admin/listUsers
├── Not visible on web frontend
├── Not in web JS files
└── Directly callable → auth check missing?
```

### 3.5 IDOR (Same Logic as Web, Different Entry)

```
Mini-program A account + resource ID from B account → cross-account access?
The methodology is identical to web IDOR but tested via mini-program auth tokens.
```

---

## Step 4: Pivot to Web (Cross-End Exploitation)

### 4.1 Token Reuse

```
Mini-program token → works on web?
├── Take mini-program auth token
├── Set it as web Authorization header / Cookie
└── Access web endpoints → same permissions? More permissions?
```

### 4.2 API Mirroring

```
Found hidden API on mini-program → exists on web?
├── /api/miniprogram/internal/config (mini-program endpoint)
├── Mirror to web: /api/web/internal/config
├── Mirror to web: /api/internal/config
└── Same backend, different frontend prefix → same vulnerability
```

### 4.3 Pattern: Mini-Program → Web Escalation

```
Common escalation chains:
1. Mini-program source → hardcoded admin API key → web admin takeover
2. Mini-program API → response leaks userId/token → web IDOR
3. Mini-program auth bypass → same token → web auth bypass
4. Mini-program old API version → web old API version → same vuln on web
5. Mini-program file upload → file accessible via web domain → stored XSS/RCE
```

### 4.4 Check: Does Web Have What Mini-Program Has?

```
For each mini-program finding:
□ Same API on web? →
    Test with web credentials
□ Same parameter on web? →
    Exploit same vulnerability
□ Same auth mechanism? →
    Does mini-program token work on web?
□ Same backend? →
    Does mini-program vuln affect web data?
```

---

## Step 5: Common Mini-Program Pitfalls

| Pitfall | Detection | Impact |
|---------|-----------|--------|
| API key in source | grep for appSecret/secret/key in decompiled JS | Full API impersonation |
| Signing salt in source | grep for md5/hmac near "sign" params | Forge any request signature |
| No auth on internal APIs | /internal/, /admin/ paths in source → curl directly | Unauthenticated data access |
| Client-type as auth | platform=admin accepted without verification | Vertical priv esc |
| Old API versions live | Decompiled source references v1 paths, test them | Weaker auth, more vulns |
| UnionID/OpenID leakage | User identifiers exposed in API responses | Cross-user tracking |
| Payment logic in client | Amount/price calculated in JS, sent to server | Price manipulation |

---

## Step 6: Quick Decision Tree

```
Target has mini-program or APP?
├── YES → Can you get the .wxapkg?
│   ├── YES → Decompile → audit source → extract APIs/secrets
│   │   ├── Found secrets → test directly on web
│   │   ├── Found hidden APIs → test auth on each
│   │   └── Found version/param trust → exploit
│   └── NO → Packet capture only
│       ├── Two-account traffic comparison → IDOR
│       ├── Extract all APIs → test on web side
│       └── Check platform/version headers → auth bypass
└── NO → Standard web testing only
```

---

## Reference: Tools

| Tool | Purpose |
|------|---------|
| wxappUnpacker | Decompile .wxapkg → full source |
| unveilr | Next-gen .wxapkg unpacker (supports encryption) |
| Burp Suite / Charles | Packet capture, proxy |
| chrome-devtools | Web side testing after mini-program pivot |

---

*End of miniprogram-analysis.md*
