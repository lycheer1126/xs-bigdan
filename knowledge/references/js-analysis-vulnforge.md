# JS Analysis & Source Leak: Process Flow

> Loaded at Phase 1 (endpoint discovery) and Phase 0 (concurrent source leak search).
> Core logic: JS files contain the app's entire API surface + secrets. Source leaks contain configs + keys + full source for audit.

---

## Part A: JS Endpoint Extraction (Phase 1)

### Step 1: Collect All JS Files

```
1. Navigate to target → chrome-devtools_navigate_page
2. Capture network history → chrome-devtools_list_network_requests
3. Filter: resourceType = "script" → collect ALL JS file URLs
4. DOWNLOAD JS files to: downloaded/{domain}/js/
   - Create directory if not exists
   - Save each JS file with its original filename
   - Example: downloaded/www.baidu.com/js/app.abc123.js
5. Alternative: analyze JS directly from chrome-devtools network history
   (no download needed — read response body of each JS request)
6. For SPA apps (Vue/React):
   - Click through every route/menu → trigger lazy-loaded JS chunks
   - Re-run list_network_requests after each navigation
   - Check waybackurls for historical JS files (may contain removed endpoints)
```

**Directory convention**: ALL downloaded content goes to `downloaded/{domain}/`:
```
downloaded/{domain}/
├── js/            # All JS files from the target
├── screens/       # Screenshots of findings
├── reports/       # Generated reports
└── findings/      # Request/response evidence
```

### Step 2: Extract API Endpoints from JS

**What to grep for** (in priority order):
```
1. Full API paths:
   "/api/"  "/v1/"  "/v2/"  "/v3/"  "/rest/"  "/graphql"
   "baseURL:"  "API_HOST:"  "apiBaseUrl"  "serverUrl"

2. HTTP client calls:
   "fetch("  "axios.get("  "axios.post("  "axios.put("  "axios.delete("
   "$.ajax("  "$.get("  "$.post("  "XMLHttpRequest"
   "request("

3. Route definitions:
   Vue: "$router"  "routes:"  "path:"
   React: "Route path="  "createBrowserRouter"
   Angular: "RouterModule.forRoot"

4. Cloud/service config:
   "bucket:"  "region:"  "endpoint:"
   "accessKey"  "secretKey"  "apiKey"  "token"
```

**Filter out noise**:
```
Skip: .jpg .png .gif .svg .ico .ttf .woff .woff2 .css
Skip: node_modules/  static/js/  static/css/
Skip: multipart/form-data references
Skip: element-ui / ant-design / bootstrap vendor paths
```

### Step 2.5: From Extracted Path → Complete Request

> Extracting `/api/user/info` is useless without knowing the request parameters.
> Find the JS code that CALLS this endpoint → extract its parameters → construct a valid test request.

```
For each extracted API path, search the JS file for the CALL site:

1. Search for the path in JS: "user/info" → find the fetch/axios call
   Example JS call:
     axios.post('/api/user/info', {
       userId: this.$store.state.userId,
       includeDetail: true,
       token: getAuthToken()
     })

2. From the call site, extract:
   - HTTP method (GET/POST/PUT/DELETE)
   - Content-Type (JSON/form-data/query-string)
   - All parameter names + their inferred types (from variable names)
   - Whether auth headers/tokens are attached
   - Base URL prefix (may be defined elsewhere: baseURL = "https://api.target.com")

3. Construct a complete test request:
   POST https://api.target.com/api/user/info
   Content-Type: application/json
   Authorization: Bearer {test_account_token}
   
   {"userId": 10086, "includeDetail": true, "token": "..."}

4. If the JS uses encrypted request bodies:
   → Locate the encryption function (see crypto-analysis.md Step 7)
   → Don't try to decrypt/re-encrypt yet — first test with the unencrypted equivalent
   → Sometimes removing encryption entirely → backend falls back to plain JSON parser
```

### Step 3: Extract Secrets & Credentials from JS

**Priority patterns to search**:
```
1. Cloud AK/SK (HIGHEST PRIORITY — full cloud takeover):
   AKIA... (AWS, 20-char AKID + 40-char SK)
   AKID... (Tencent, 36-char AKID + 32-char SK)
   LTAI... (Alibaba, 24-char AKID + 30-char SK)
   VM...   (Huawei, 20-char AKID + 40-char SK)
   AIza... (Google API)
   APID... (Apple Developer)

   Also search for:
   accessKeyId  access_key_id  secretAccessKey  secret_access_key
   accessKeySecret  secretId  secretKey
   oss.file.key-id  oss.file.key-secret
   aws_access_key_id  aws_secret_access_key

2. API tokens / keys:
   sk- (OpenAI)  ghp_/gho_/ghu_ (GitHub)  glpat- (GitLab)
   apiKey:  secretKey:  accessKey:  token:

3. Internal endpoints:
   /admin/  /internal/  /manage/  /debug/
   /actuator  /swagger  /druid  /graphql  /nacos/

4. Config patterns:
   ".env" references  "application.yml"  "config.js"
   REACT_APP_  VITE_  VUE_APP_  NEXT_PUBLIC_
   JWT secret  encryptKey  privateKey  salt

5. Database connection strings:
   jdbc:mysql://  mongodb://  redis://  postgresql://
   DB_HOST  DB_PASSWORD  DATABASE_URL
```

**AK/SK Leak Sources Beyond JS**:
```
3. Heapdump files (.hprof):
   - Access /actuator/heapdump → download → extract with heapdump_tool
   - Search for: accessKey, secretKey, LTAI, AKIA, AKID

4. Nacos config centers:
   - /nacos/v1/cs/configs?dataId=application&group=DEFAULT_GROUP
   - Configuration lists often contain plaintext AK/SK, DB passwords, JWT secrets

5. Mini-program response bodies:
   - Image upload / file upload / avatar upload APIs → response may contain AK/SK
   - Profile/detail API responses → may leak access keys in hidden fields

6. API error messages:
   - Invalid parameters may trigger stack traces containing credentials
   - Debug mode responses may include full config with keys

7. Source map files (.js.map):
   - Original variable names reveal credential fields
```

### Step 4: SPA Route Extraction

**Vue Router (hash mode)**:
```javascript
// evaluate_script to extract routes:
// Access: app.__vue_app__.config.globalProperties.$router.getRoutes()
// Access (Vue2): app.__vue__.$root.$options.router.options.routes
// Clear route guards: router.beforeHooks.length = 0 (to navigate freely)
```

**React Router**:
```javascript
// Look for: __REACT_DEVTOOLS_GLOBAL_HOOK__
// Extract fiber nodes → find all <Route> component paths
```

**After extracting routes**:
1. Navigate to each route → may trigger new API calls
2. Each new route may load additional JS chunks
3. Re-run list_network_requests after each navigation

### Step 5: Runtime Hooks (When Crypto/Encryption Detected)

Inject hooks BEFORE triggering actions (login, submit, etc.):
```
1. Hook fetch/XHR → capture all API calls + request bodies
2. Hook CryptoJS → capture encrypt() plaintext + key
3. Hook JSEncrypt → capture RSA encrypt() plaintext
4. Hook localStorage/sessionStorage → capture token storage
5. Hook JSON.parse/stringify → capture encrypted serialization
```

**Purpose**: See the data BEFORE encryption. Reveals API structure, parameters, and encryption keys without needing to reverse the cipher.

---

## Part B: Source Code Leak Search (Phase 0 — Concurrent Background Task)

### Step 1: Collect Target Fingerprint

Before searching, identify unique characteristics:
```
- Domain + all subdomains
- Company name (Chinese + English + abbreviation)
- JS baseURL patterns (e.g., https://api.xxx.com/v1)
- Unique API paths (e.g., /api/user/getUserInfoByToken)
- Error messages containing package/class names
- Cookie names (custom session IDs)
- HTML meta generator/version tags
- ICP备案号
```

### Step 2: Search GitHub/Gitee

**By domain**:
```
github_search_code: "target.com" language:java
github_search_code: "target.com" filename:.env
github_search_code: "target.com" filename:application.yml
github_search_repositories: "target company name"
```

**By unique code fingerprints**:
```
# Most reliable: unique error messages
github_search_code: "com.targetcorp.controller" language:java
github_search_code: "XX管理系统" in:readme

# Build files
github_search_code: "target_group" filename:pom.xml
github_search_code: "\"target_package\"" filename:package.json
github_search_code: "target_domain" filename:nginx.conf

# Config files
github_search_code: "spring.datasource.url" "target_internal_host"
github_search_code: "DB_PASSWORD" "target_name"
```

**Gitee focus** (higher leak probability for Chinese companies):
```
gitee_search: "<company_name>" + "spring" + "vue"
gitee_search: "<target_domain>" + "application"
gitee_search: "<Chinese_company_name>" + "管理系统"
```

### Step 2.5: Code Repository → Sensitive Data Extraction → Chain Exploitation (HIGH ROI)

**Principle**: Companies host open-source repos under GitHub/Gitee organizations. Employees expose sensitive data through commits (emails, PII), config files (passwords, keys), and issue discussions (screenshots, test accounts). ANY real data found in repos must NOT stop at "information leak" — it must enter the target's API testing branch and attempt linkage exploitation.

**Step 2.5a: Enumerate Target Repositories**
```
GitHub MCP: list_org_repos("{company_name}")  → enumerate all public repos
Gitee MCP: 同步执行 (domestic companies → Gitee first, higher leak probability)
Fallback:  github_search_code: "{company_domain}"  /  "{company_name}"  by keyword
```

**Step 2.5b: Three-Dimensional Sensitive Data Extraction** (per repo)

```
[维度1] Commit Record Dimension:
  list_commits → pull ALL commit history
  → Extract Author field: corporate email (@{company_domain}.com), real name
  → Append .patch to commit URL → raw diff exposes full email addresses
  → Visit committer GitHub profile → correlate real identity, department, role
  → Extract from commit messages: ticket IDs, internal URLs, test credentials

[维度2] Code Content Dimension:
  Search for config files: .env / config.yml / application.properties /
    application-dev.yml / application-prod.yml / settings.py / database.yml /
    applicationContext.xml / web.xml / pom.xml / package.json
  Extract hardcoded strings matching patterns:
    → Phone numbers (1[3-9]\d{9} for CN), ID card numbers (\d{17}[\dXx])
    → Real names, employee IDs, internal API URLs (10.x, 192.168.x, *.internal)
    → Cloud AK/SK (LTAI..., AKIA..., AKID...), DB passwords, JWT secrets
    → Any string that looks like real data → collect it for interface testing

[维度3] Issue / PR Comment Dimension:
  Search issue bodies and PR comments for:
    → Screenshots showing real data (developers post debug screenshots)
    → Test accounts / test phone numbers used in bug reports
    → API keys / tokens accidentally pasted in issue threads
    → Internal URLs / staging environment addresses discussed in comments
```

**Step 2.5c: MANDATORY Data Linkage Testing** (DO NOT stop at "info leak")

```
Any identifier extracted from repos → immediately queue for Phase 3 interface testing:

  Branch 1: Email → login + password-reset endpoints
    → Obtain JWT/Session Token → test horizontal/vertical privilege escalation
  Branch 2: Phone → address book API + org-chart API + SMS verification API
    → Bulk pull all employee data / access others' phone numbers
  Branch 3: Name / Employee ID → employee info query API
    → Test: /api/user/info?name={name} or /api/employee?empId={id}
    → Check if unauthenticated request returns ID card / bank card / salary
  Branch 4: ID Card Number → identity verification / real-name auth APIs
    → Test if queryable for associated full personal information
  Branch 5: JWT Secret / AK/SK → self-sign token / direct cloud API calls
    → Forge arbitrary user identity → vertical privilege escalation to admin

Severity escalation:
  Single branch confirmed → 中危
  Two branches linked (Email → JWT → Vertical PrivEsc) → 高危
  Three+ branches linked → 严重
```

**SRC compliance**:
```
- Searching public repos = passive reconnaissance, always OK
- Extracted data from public commits = public data, OK to collect
- DO NOT brute-force login (single attempt per account max)
- DO NOT save extracted PII locally after confirming exploitability
- Report: "代码仓库敏感信息泄露 → 数据联动 → [具体漏洞类型]"
```

### Step 3: Confirm Match

Once a potential source repo is found:
1. Compare directory structure with known target endpoints
2. Compare API route patterns → do paths match?
3. Compare JS variable names / comments / error messages
4. Check if config files reference target domains/IPs

**If confirmed matching → source is now readable → full white-box audit**:
- Read auth implementation → find bypass patterns
- Read SQL mappers → find injection points
- Read config → get database/Redis/AK credentials
- Read hidden endpoints → test them directly
- Read encryption logic → get keys and algorithms

### Step 4: What to Prioritize in Leaked Source

```
Priority order for auditing:
1. Config files (.env, application.yml, settings.py, config.js)
   → DB passwords, cloud AK/SK, JWT secret, encryption keys
2. Auth/security code (AuthController, SecurityConfig, JwtUtil)
   → Hardcoded backdoor accounts, weak JWT key, bypass logic
3. API Controllers
   → Cross-reference with JS-extracted endpoints
   → Check parameter validation, auth annotations
   → Find hidden/unexposed endpoints
4. SQL/Mapper XML
   → Dynamic SQL concatenation → SQL injection
5. Configuration (CORS, Swagger, logging)
   → Allowed origins, exposed endpoints, debug config
```

---

## Part C: JS Runtime Hooks via chrome-devtools MCP (Phase 2+)

> Inject hooks via `chrome-devtools_evaluate_script` BEFORE triggering target actions (login, submit, navigation).
> Purpose: Capture pre-encryption plaintext, API call parameters, token storage without reversing the cipher.

### Hook Pattern 1: Intercept Fetch/XHR

```javascript
// Inject BEFORE triggering page actions:
const origFetch = window.fetch;
window.fetch = function(...args) {
  console.log('[HOOK] fetch:', args[0]);
  return origFetch.apply(this, args);
};

// XHR hook:
const origOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  console.log('[HOOK] XHR:', method, url);
  return origOpen.apply(this, arguments);
};
```

**When**: Always inject at Phase 1 start. Captures every API call, including those triggered by user interaction or SPA route navigation.

### Hook Pattern 2: Intercept CryptoJS (AES/DES)

```javascript
// Structure-match — no variable name dependency
const origApply = Function.prototype.apply;
Function.prototype.apply = function(thisArg, args) {
  if (args && args[0] && args[0].ciphertext && args[0].key) {
    console.log('[HOOK] CryptoJS key:', args[0].key);
    console.log('[HOOK] CryptoJS iv:', args[0].iv);
    console.log('[HOOK] CryptoJS mode:', args[0].mode);
  }
  return origApply.call(this, thisArg, args);
};
```

**When**: Opaque request body detected + JS references CryptoJS. Captures key, IV, mode before encryption — enables payload forgery.

### Hook Pattern 3: Intercept JSEncrypt (RSA)

```javascript
const origCall = Function.prototype.call;
Function.prototype.call = function(thisArg, ...args) {
  if (thisArg && thisArg.__proto__ &&
      thisArg.__proto__.getPublicKey && thisArg.__proto__.parseKey) {
    console.log('[HOOK] JSEncrypt public key:', thisArg.getPublicKey());
  }
  return origCall.apply(this, args);
};
```

**When**: Login sends RSA-encrypted password. Captures public key for offline analysis.

### Hook Pattern 4: Intercept localStorage/sessionStorage

```javascript
const origSet = Storage.prototype.setItem;
Storage.prototype.setItem = function(key, val) {
  console.log('[HOOK] Storage.set:', key, val);
  return origSet.call(this, key, val);
};
```

**When**: App stores tokens/user data in localStorage. Reveals token format and credential reuse patterns.

### Hook Pattern 5: Intercept Cookie Writes

```javascript
const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
Object.defineProperty(document, 'cookie', {
  set: function(val) { console.log('[HOOK] Cookie set:', val); desc.set.call(this, val); },
  get: function() { return desc.get.call(this); }
});
```

**When**: App sets auth cookies via JS. Reveals cookie structure and token leakage.

### Hook Pattern 6: Intercept JSON.parse/stringify

```javascript
const origParse = JSON.parse;
JSON.parse = function(text) {
  console.log('[HOOK] JSON.parse:', text?.substring(0, 200));
  return origParse.call(this, text);
};
```

**When**: App decrypts then JSON-parses internally. Reveals decrypted response structure.

### Hook Pattern 7: Clear Vue Router Navigation Guards

```javascript
// Hook Array.push to silently drop beforeEach/beforeResolve guards
const origPush = Array.prototype.push;
Array.prototype.push = function(...items) {
  const stack = new Error().stack || '';
  if (stack.includes('beforeEach') || stack.includes('beforeResolve')) {
    return origPush.call(this); // Drop the guard function
  }
  return origPush.apply(this, items);
};
```

**When**: Vue SPA routes protected by navigation guards. Clears guards to freely navigate all routes and trigger lazy-loaded API calls.

### Hook Pattern 8: Extract Vue Router Routes

```javascript
// BFS scan DOM → find __vue_app__ → extract all routes
() => {
  const bfs = (el, d) => {
    if (d > 10 || !el) return null;
    if (el.__vue_app__ || el.__vue__) return el;
    if (el.children) for (const c of el.children) { const r = bfs(c, d+1); if (r) return r; }
    return null;
  };
  const app = bfs(document.body, 0);
  const router = app?.__vue_app__?.config?.globalProperties?.$router;
  return router ? router.getRoutes().map(r => r.path) : [];
}
```

**When**: Phase 0/1, Vue detected. Maps full SPA route tree, revealing hidden pages + their API calls.

### Hook Pattern 9: Fixed Timing Values (Anti-Debug Bypass)

```javascript
Date.now = () => 1234567890000;
Math.random = () => 0.5;
performance.now = () => 1000;
```

**When**: Page has anti-debug timing detection. Prevents DevTools detection.

---

## Part D: Source Map Analysis

> `.js.map` files map minified JS back to original source. They contain comments, variable names, internal paths, and hardcoded credentials stripped from the minified build.

### Step 1: Discover Source Maps

```
1. Append .map to any JS file URL: app.abc123.js → app.abc123.js.map
2. Check JS file last line for: //# sourceMappingURL=app.abc123.js.map
3. In chrome-devtools Sources panel, if loaded, original sources appear under webpack://
```

### Step 2: What to Extract

```
1. Internal paths (not in production JS):
   - webpack:///src/api/ — internal API route definitions
   - webpack:///src/config/ — configuration files with keys/secrets
   - webpack:///src/router/ — full route tree
   - webpack:///src/utils/auth.js — auth logic with embedded secrets
   - webpack:///src/store/ — Vuex/Pinia/Redux state structure

2. Original variable names:
   - "configService.getApiKey()" — reveals internal service names
   - "internalApiBaseUrl" — reveals hidden endpoints
   - "DEBUG_MODE", "isProduction" — reveals environment flags

3. Developer comments (stripped from minified):
   - TODO comments describe known bugs or incomplete features
   - API documentation in JSDoc format
   - Internal hostnames, IPs, dev server URLs
   - "// temporary key: xxx" — hardcoded credentials

4. Hardcoded credentials:
   - Test credentials in config files
   - Default passwords in component comments
   - Stripped API keys still present in source comments
```

### Step 3: Tool Reference
- `scripts/analyze_map.py` — rapid extraction of API keys, secrets, tokens, baseURL from .js.map
- `scripts/analyze_map_deep.py` — deep line-level scan for endpoints, auth functions, crypto references
- Manual: grep source map JSON for `apiKey secret token password baseURL internal dev staging admin`

### Step 4: Quick Decision

```
Source map found?
├── YES → Extract internal paths + secrets + comments → add to endpoint inventory
└── NO  → Try .map extension on each JS file → check for sourceMappingURL comment
```

---

---

## Part E: Source Map 深度利用（webpack打包站点）

### 识别信号
- JS文件末尾注释：`/*# sourceMappingURL=app.abc123.js.map*/`
- 浏览器F12 Sources面板可看到完整项目目录结构（而非单个压缩JS文件）
- webpack/vite打包特征：JS文件体积大 + 文件名含 hash（如 app.a1b2c3.js）

### 原理
```
前端项目打包(webpack/vite)时,默认生成 .js.map (Source Map) 文件。
.map 文件记录了编译前(源码)到编译后(打包)的映射关系。
如果 .map 文件可访问,可用工具还原出近乎完整的项目源码。
源码中包含: 所有API路由/Secret Key/业务逻辑/注释/内部域名/开发环境配置
```

### 决策流程
```
发现Source Map?

├── Step1: 定位.map文件
│   ├── 直接从请求中找: /js/app.abc123.js → /js/app.abc123.js.map
│   ├── 从F12 Sources面板看: 有展开的项目目录? → Source Map存在
│   └── 从HTML注释中找: <!--# sourceMappingURL=...--> 
│
├── Step2: 下载.map文件
│   ├── 直接请求 .map URL (通常在相同目录下)
│   └── 或: 从Chrome DevTools Network面板找.map请求
│
├── Step3: 还原源码(使用reverse-sourcemap)
│   npm install reverse-sourcemap -g
│   reverse-sourcemap -o output_dir app.abc123.js.map
│   → 还原出 webpack:// 目录结构 → 包含所有 .vue/.jsx/.ts 源文件
│
├── Step4: 从还原的源码中挖掘
│   ├── 找API接口: grep "/api/" 或 "axios.get" "fetch("
│   ├── 找Secret: grep "AKIA" "LTAI" "secret" "apiKey" "password"
│   ├── 找开发注释: grep "TODO" "FIXME" "HACK" "临时" "测试"
│   ├── 找内部域名: grep ".internal" ".dev" "staging" "localhost"
│   └── 找路由表: Vue Router / React Router 配置 → 全部入口一览
│
└── Step5 (发现内网/开发接口后):
    全部导入 Burp → 批量测试未授权/越权
```

### 相关工具
```
reverse-sourcemap (Node.js) — 还原Source Map到源码
Packer-Fuzzer (Python) — 自动化检测webpack站点并探测敏感路径
FindSomething (浏览器插件) — 一键提取当前页面JS中的Path/URL/敏感信息
```

### 四类JS信息提取方式对比
```
传统JS grep:    在打包后的代码中硬搜 → 噪音大,容易遗漏
Source Map还原: 还原出完整源码 → 最全面,但要有.map文件
运行时Hook:     Hook fetch/XHR捕获实际请求 → 准确但只能看到触发过的
FindSomething:  浏览器自动遍历提取 → 一键出结果,适合快速扫描
```

## Quick Checklist

```
□ Collect all JS files (network history + wayback)
□ Extract API paths (grep for /api/ /v1/ baseURL: fetch( axios.)
□ Extract secrets (grep for AKIA AKID LTAI apiKey secretKey token)
□ Extract SPA routes (Vue $router / React __REACT_DEVTOOLS_GLOBAL_HOOK__)
□ Check for anti-debug (timing/clear/close) → apply hook patterns
□ If encryption detected → inject runtime hooks (Patterns 2,3,6) → capture plaintext
□ Clear Vue router guards → navigate all SPA routes → capture lazy-loaded APIs
□ Check for source maps (.js.map) → extract internal paths, secrets, comments
□ Fingerprint target for source search (unique paths/errors/messages)
□ Search GitHub/Gitee for source leaks
□ If source found → white-box audit (configs first, auth code second)
```

---

*End of js-analysis.md*
