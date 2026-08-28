# Encrypted Parameter Analysis Thinking Chain

> Loaded at Phase 2 when request body or key parameters appear encrypted/encoded.
> Goal: Find the cipher, find the key, forge encrypted payloads to exploit the API.

---

## Step 0: Detection — Is It Encrypted?

**Signals that a parameter is encrypted**:
- Base64-like string with no readable structure: `aGVsbG8...` or `U2FsdGVkX18...`
- Hex string in params: `?data=7b22757365...`
- POST body is a single opaque blob: `{"payload": "kVjF3..."}`
- Parameter names like: `encData`, `ciphertext`, `encrypted`, `sign`, `signature`, `signedData`
- Content-Type mismatch: body claims JSON but content is a single string

**Decode first, then classify**:
1. Base64 decode → if result has readable JSON/XML → it's encoding, not encryption. Proceed to manipulate decoded content directly.
2. Base64 decode → if result is binary garbage → real encryption. Continue to Step 1.

---

## Step 1: Find the Cipher

**From JS files** (primary source):
```
Search for in downloaded JS:
  CryptoJS.AES.encrypt / CryptoJS.AES.decrypt
  JSEncrypt.prototype.encrypt
  window.btoa / window.atob
  SubtleCrypto.encrypt / SubtleCrypto.decrypt
  forge.cipher / forge.md
  sm2 / sm3 / sm4  (Chinese national crypto)
  encryptData / decryptData
  signRequest / verifyResponse
```

**From source leak** (if Phase 5 found code):
```
Search for in backend source:
  Cipher.getInstance("AES/CBC/PKCS5Padding")
  openssl_encrypt / mcrypt_encrypt
  crypto.createCipher / crypto.createCipheriv
  hashlib.md5 / hmac.new
```

**Runtime hook to capture pre-encryption data** (most reliable):
```javascript
// Inject via chrome-devtools evaluate_script BEFORE triggering the action:
// Hook CryptoJS
CryptoJS.AES.encrypt = function(msg, key, opt) {
  console.log('[HOOK] AES encrypt plaintext:', msg.toString());
  console.log('[HOOK] AES key:', key.toString());
  return orig.call(this, msg, key, opt);
};
```
- Navigate to the page, inject hooks, THEN trigger the action (login, submit, etc.)
- Watch console for plaintext, key, and encryption parameters

---

## Step 2: Find the Key

**Key sources (priority order)**:

1. **Hardcoded in JS**: Search for `secretKey`, `encryptKey`, `aesKey`, `privateKey`, hex/long base64 strings near CryptoJS calls
2. **In source leak**: Search `application.yml`, `.env`, `config.js` for `encrypt.key`, `cipher.secret`, `aes.password`
3. **Derived from known values**: `MD5(password)`, `SHA256(timestamp)`, fixed prefix + timestamp
4. **Reused from JWT key**: If JWT uses HS256 with known key → same key for body encryption
5. **Weak derivation**: timestamp-based, `deviceId`-based, or simple XOR

**Mode discovery**:
- CryptoJS default: CBC mode with PKCS7 padding
- JSEncrypt: RSA-OAEP or RSA-PKCS1-v1_5
- Check `mode: CryptoJS.mode.CBC` or `padding: CryptoJS.pad.Pkcs7` in JS

---

## Step 3: Forge Encrypted Payloads

**If key found + cipher known** → you can now encrypt arbitrary payloads:

```
For each parameter in the unencrypted inner data:
  1. Decode the current encrypted blob to understand structure
  2. Identify which field to manipulate (userId, role, amount, etc.)
  3. Modify the field
  4. Re-encrypt with the captured cipher + mode + key
  5. Submit the forged encrypted request
```

**Common inner structures to exploit**:
```json
// User identity
{"userId": 10086, "timestamp": 1234567890}
→ {"userId": 10001, "timestamp": 1234567890}   // IDOR via encrypted body

// Payment
{"orderId": "ORD-123", "amount": 100, "sign": "md5hash"}
→ {"orderId": "ORD-123", "amount": 0.01, "sign": "md5hash"}  // Price manipulation

// Auth
{"username": "test", "password": "encrypted_pwd", "deviceId": "xxx"}
→ {"username": "admin", "password": "encrypted_pwd", "deviceId": "xxx"}  // User impersonation
```

---

## Step 4: What If Key Is NOT Found?

| Approach | How | When Useful |
|----------|-----|-------------|
| **Replay attack** | Same encrypted blob → different endpoint | Different endpoint accepts same token/auth payload |
| **Parameter exclusion** | Remove encryption entirely, try plain JSON | Backend falls back to unencrypted parser |
| **Content-Type switch** | Change `Content-Type` from encrypted format to `application/json` | Backend may have both encrypted and plaintext handlers |
| **Encryption oracle** | Observe how encrypted output changes when you change one input field | Build mapping of input→ciphertext for chosen-plaintext attack |
| **Downgrade** | Remove `encryption: true` or `version: 2.0` flags | Backend may fall back to legacy (unencrypted) API version |

---

## Step 5: Special Cases

### MD5/SHA "Signing" (Actually Hashing)
- `sign=md5(params+salt)` → if salt is in JS, you can forge any signature
- `sign=md5(body+timestamp+secret)` → brute force secret if it's short
- Many apps use MD5 for "signing" — MD5 is NOT encryption, it's trivial to forge if you have the salt

### RSA Encrypted Credentials (JSEncrypt)
- Login password encrypted with RSA public key → this is expected, not a vulnerability
- BUT: check if the public key is actually the server's → or is it a test key? → MITM possible
- BUT: if `encrypt` is client-side only → the server must decrypt → if backend error reveals plaintext, you have an encryption oracle

### AES with ECB Mode
- ECB mode encrypts each block independently → patterns visible in ciphertext
- Two identical plaintext blocks produce identical ciphertext blocks
- Can be exploited for chosen-plaintext attacks even without the key

---

## Step 6: Quick Decision

```
Parameter appears encrypted?
├── Base64 only → decode → modify → re-encode → test
├── Real encryption (AES/RSA/SM4)
│   ├── Key found in JS/source leak → decrypt → modify → re-encrypt → exploit
│   ├── Key NOT found
│   │   ├── Try replay (same blob, different endpoint/context)
│   │   ├── Try removal (send plain JSON instead)
│   │   ├── Try downgrade (old API version without encryption)
│   │   └── Inject runtime hooks → capture pre-encryption plaintext
│   └── Key not found + all approaches fail → mark as blocker, move on
└── MD5/SHA "signing" → find salt in JS → forge signatures
```

---

## Step 7: Locating the Encryption Function in JS

> Before you can forge encrypted payloads, you MUST find the encryption function in the frontend JS. 
> Three methods, in priority order.

### Method 1: Keyword Search (Fastest)

```
In downloaded JS files, search for:
  encrypt  Encrypt  decrypt  Decrypt
  CryptoJS  JSEncrypt  RSAKeyPair
  AES.encrypt  DES.encrypt  sign  signature
  setPublicKey  encryptData  encodeData
  cipher  ciphertext  hmac  md5  sha256

Also search for unique values from the request body:
  If request body is {"data": "U2FsdGVkX19..."} → search for "U2Fsd" in JS (CryptoJS AES OpenSSL format prefix)
  If body has "encryptedData" field → search for "encryptedData" in JS
  If body has "signature" field → search for "signature" / "HmacSHA" in JS
```

### Method 2: Call Stack Tracing (When Keyword Search Fails)

```
1. Open chrome-devtools → Sources tab
2. Find the XHR/Fetch that sends the encrypted request:
   - chrome-devtools_list_network_requests → find the request
   - Check which JS file initiated it
3. Set XHR breakpoint:
   - chrome-devtools_evaluate_script: hook XMLHttpRequest.prototype.send
   - Trigger the action → breakpoint hits → inspect call stack
4. Walk UP the call stack to find where encryption() was called before send()
5. The function 2-3 levels up from send() is usually the encryption function
```

### Method 3: XHR Event Monitoring

```javascript
// Inject via chrome-devtools_evaluate_script:
// Monitor ALL XHR/fetch that match the encrypted endpoint URL
const origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(body) {
  if (this._url && this._url.includes('login') || this._url.includes('encrypt')) {
    console.log('[HOOK] XHR body before encryption:', body);
    // This shows you what the body was BEFORE it was encrypted
  }
  return origSend.call(this, body);
};
```

**When all three fail**: The encryption may happen in a WASM module or native code → the app is using Rust/Go/C++ compiled encryption. Skip JS-based analysis, focus on source leak or server-side audit.

---

## Step 8: Common Encryption Patterns (Quick Match)

> Once you find the encrypt function, match its pattern to determine the attack path.

### Pattern A: AES Fixed Key
```
JS code: CryptoJS.AES.encrypt(data, key, {iv: iv, ...})
key & iv are HARDCODED strings → "1234567890123456", etc.

Attack path:
  1. Extract key + iv + mode + padding from JS
  2. Decrypt current encrypted payload → see plaintext structure
  3. Modify plaintext → re-encrypt with same key/iv/mode
  4. Submit forged encrypted payload → IDOR, PrivEsc, Payment bypass
```

### Pattern B: AES Random Key + RSA
```
JS code: 
  key = CryptoJS.lib.WordArray.random(16)   // random AES key
  encrypted = AES.encrypt(data, key)
  encryptedKey = RSA.encrypt(key, publicKey)  // key sent to server

Attack path:
  → Cannot forge (key is random each time)
  → BUT: can hook JS → capture plaintext before encryption
  → OR: override WordArray.random to return fixed key → then forge
```

### Pattern C: AES Key from Server
```
JS code: 
  fetch('/api/getKey') → {key: "...", iv: "..."}
  encrypted = AES.encrypt(data, serverKey)

Attack path:
  → Extract key from the /api/getKey response
  → Decrypt & re-encrypt arbitrary payloads
  → No brute force needed — server gives you the key
```

### Pattern D: DES with Derived Key
```
JS code:
  key = username.slice(0,8).padEnd(8,'6')   // key derived from username
  encrypted = DES.encrypt(password, key)

Attack path:
  → Key is predictable! Any user "admin" → key = "admin666"
  → Encrypt any password for any known username
  → Brute force: try common usernames → derive key → decrypt
```

### Pattern E: HMAC/SHA Signing with Hardcoded Secret
```
JS code:
  signature = HmacSHA256(username+password+nonce+timestamp, "be56e057f20f883e")

Attack path:
  → Secret is hardcoded → can forge any signature
  → BUT: nonce/timestamp may be validated → need to generate fresh values
  → Solution: call the JS function remotely (JSRPC) to auto-generate correct nonce/timestamp
```

### Pattern F: Anti-Replay (Timestamp + RSA)
```
JS code:
  encryptedTimestamp = RSA.encrypt(Date.now(), publicKey)
  // Server checks: is timestamp within 5s window? If replayed → reject

Attack path:
  → Cannot replay old requests (timestamp expired)
  → BUT: can hook JS → call RSA.encrypt(fresh timestamp, publicKey) on-demand
  → Generate new encrypted timestamp each time → bypass replay protection
```

### Pattern G: MD5 "Signing" (Actually Hashing)
```
JS code:
  sign = md5(params + "&key=" + secretKey)

Attack path:
  → If secretKey hardcoded → forge any MD5 signature
  → If secretKey unknown → check if md5(params) is accepted (no salt)
  → If sign is only client-side validated → remove sign entirely → server may accept
```

---

*End of crypto-analysis.md*
