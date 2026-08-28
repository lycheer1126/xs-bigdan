---
name: js-analysis
description: >
  JS 文件全量采集与深度分析。双通道（雪瞳+自主探测）下载 JS，本地按域名组织，
  逐文件深度读取提取完整请求签名（URL + Method + Content-Type + 参数名 +
  是否必填 + Auth要求），构建接口-参数需求映射表，作为后续所有阶段的输入基础。
metadata:
  tags: "js-analysis,endpoint-extraction,credentials,spa,request-signature,parameter-mapping"
  category: "offensive-security"
---

# JS Analysis — 全量采集 + 深度分析 + 请求签名提取

> 核心原则：JS 文件是最大的接口信息来源。不走完这一步，绝不去 Fuzz。
>
> **你的优势**：可以同时加载并深度阅读所有 JS 文件，这是人类做不到的规模化分析。

---

## ⛔ 强制规则（不可跳过）

```
规则 1: 禁止只看前 N 行 —— 必须读取每个 JS 文件的完整内容
规则 2: 禁止只搜索关键词 —— 搜索完成后必须完整阅读有命中的文件
规则 3: 禁止跳过"看起来不重要"的 JS 文件 —— 每个 .js 文件都可能含 API 调用
规则 4: 提取粒度必须到参数级别 —— 不只是 URL，要完整的请求签名
规则 5: 必须保存到本地 —— 每个域名一个目录，文件用原始路径命名
```

---

## 1. 双通道 JS 采集

### 通道 A：雪瞳爬虫（自动化采集）

```
雪瞳负责:
  □ 爬取目标所有页面，自动拦截 .js 请求
  □ 触发懒加载路由（SPA 的每个 hash 页面点一遍）
  □ 多角色场景：登录不同角色后分别采集
  □ 输出：所有的 .js URL 清单 + 请求/响应记录

雪瞳的输出保存到:
  downloaded/{domain}/
  ├── _js_urls.txt           # 所有 JS URL 清单（去重后）
  ├── _response_log.jsonl    # 每个请求的 HTTP 日志
  └── js/                    # 按原始路径组织的 JS 文件
```

### 通道 B：自主探测（补充采集）

```bash
# 1. waybackurls 拿历史 JS（可能包含旧版本/未删除的测试端点）
curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey" \
  | grep '\.js$' | sort -u > wayback_js_urls.txt

# 2. 浏览器 DevTools → Sources → 全部保存
#    按 Ctrl+Shift+S 另存每个 JS 文件

# 3. 从页面 HTML 中提取 <script src=""> 
curl -s https://${TARGET} | grep -oP 'src="([^"]+\.js[^"]*)"' | sort -u

# 4. 合并去重
cat _js_urls.txt wayback_js_urls.txt page_js_urls.txt | sort -u > all_js_urls.txt
```

### 本地存储规范

```
downloaded/{domain}/
├── _js_urls.txt              # 全量 JS URL 清单
├── _analysis_summary.md      # JS 分析总结
├── _endpoint_params.json     # ★ 核心产出：接口→参数需求映射表
├── _secrets_found.json       # 硬编码凭据/密钥
├── _hash_routes.txt          # SPA Hash 路由清单
└── js/
    ├── static_js_app.js
    ├── static_js_chunk-vendors.js
    ├── static_js_api.js
    └── ...
```

---

## 2. 逐文件深度读取流程

### Step 1: 获取全量 JS URL 清单

```
从雪瞳输出 + wayback + 页面提取 → all_js_urls.txt（去重排序）
```

### Step 2: 逐个下载到本地

```bash
mkdir -p downloaded/${TARGET_HOST}/js/
while IFS= read -r url; do
  # 用 URL 路径作为文件名
  fname=$(echo "$url" | tr '/:.?=&' '_' | sed 's/_\+/_/g')
  curl -s "$url" -o "downloaded/${TARGET_HOST}/js/${fname}.js"
done < all_js_urls.txt
```

### Step 3: 逐个文件深度读取（核心步骤）

**对每个 .js 文件执行以下操作（不可跳过）：**

```
□ 完整读取文件内容（不是只看前几行）
□ 提取所有 API 调用及其完整请求签名
□ 提取所有硬编码字符串（重点：密钥、token、URL）
□ 提取 SPA 路由定义（Vue Router / React Router）
□ 提取加密函数签名（CryptoJS / Web Crypto）
□ 提取请求拦截器/中间件逻辑（axios interceptor / fetch wrapper）
□ 记录文件大小和大致功能分类
```

---

## 3. 完整请求签名提取（最重要）

### 不只是搜 URL，要还原完整的 HTTP 请求

每发现一个 API 调用，提取以下完整信息：

```
必提字段:
  □ HTTP 方法: GET / POST / PUT / DELETE / PATCH
  □ 完整 URL: （含路径参数占位符，如 /api/users/:id）
  □ Content-Type: application/json / multipart/form-data / etc.
  □ 需要的参数名: 从请求体构造逻辑中提取
  □ 参数是否必填: 判断是否有默认值或条件判断
  □ 认证方式: Authorization: Bearer / X-API-Key / Cookie / 无
  
可选提取:
  □ 响应处理逻辑: 从 .then() / await 后提取预期返回字段
  □ 错误处理: 错误回调中暴露的错误信息格式
  □ 请求拦截器逻辑: 公共参数注入（timestamp/sign/token）
```

### 3a. fetch() 调用 → 完整签名提取

```javascript
// 源码示例:
fetch('/api/user/info', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify({
    userId: userId,
    orgId: orgId
  })
})

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ POST /api/user/info
// │ Content-Type: application/json
// │ Authorization: Bearer <token>
// │ 参数: userId (必填), orgId (必填)
// │ 来源文件: static_js_app.js: 行号
// └─────────────────────────────────────────────────────────┘
```

### 3b. axios() 调用 → 完整签名提取

```javascript
// 源码示例:
axios.post('/api/order/list', 
  { buyerId, startTime, endTime, page: 1, pageSize: 20 },
  { headers: { 'X-Requested-With': 'XMLHttpRequest' } }
)

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ POST /api/order/list
// │ Content-Type: application/json (axios 默认)
// │ 参数: buyerId (必填), startTime (必填), endTime (必填),
// │       page (可选, 默认1), pageSize (可选, 默认20)
// │ Headers: X-Requested-With: XMLHttpRequest (自动)
// └─────────────────────────────────────────────────────────┘
```

### 3c. $.ajax / XMLHttpRequest → 完整签名提取

```javascript
// jQuery:
$.ajax({
  url: '/api/export/user',
  type: 'POST',
  contentType: 'application/json',
  data: JSON.stringify({ userIds: userIds, fields: ['name', 'email'] }),
  beforeSend: function(xhr) { xhr.setRequestHeader('X-CSRF-Token', csrf); }
})

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ POST /api/export/user
// │ Content-Type: application/json
// │ 参数: userIds (必填, 数组), fields (必填, 数组)
// │ Auth: X-CSRF-Token header (来自 CSRF token)
// └─────────────────────────────────────────────────────────┘
```

### 3d. API 封装函数 → 提取基础配置

```javascript
// 很多项目会封装统一的请求函数:
const apiClient = axios.create({
  baseURL: 'https://api.target.com/v2',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey
  }
});

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ Base URL: https://api.target.com/v2
// │ 全局 Headers: Content-Type: application/json
// │               X-API-Key: <从变量 apiKey>
// │ 超时: 10000ms
// │ → apiKey 的来源需要继续追踪
// └─────────────────────────────────────────────────────────┘
```

### 3e. GraphQL 调用 → 提取

```javascript
// 源码:
const { data } = await client.query({
  query: gql`
    query GetUser($id: ID!) {
      user(id: $id) { id name email role }
    }
  `,
  variables: { id: userId }
})

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ POST /graphql (推断)
// │ Content-Type: application/json
// │ Query: GetUser($id: ID!)
// │ 参数: id (必填, ID类型)
// │ 返回字段: id, name, email, role
// └─────────────────────────────────────────────────────────┘
```

---

## 4. 构建 _endpoint_params.json（核心产物）

将从所有 JS 文件中提取的请求签名汇总为结构化映射表：

```json
{
  "/api/user/list": {
    "method": "POST",
    "content_type": "application/json",
    "auth": "Bearer",
    "params_required": ["page", "pageSize"],
    "params_optional": [],
    "source_files": ["static_js_app.js"],
    "notes": "返回用户列表，含 userId, name"
  },
  "/api/user/info": {
    "method": "POST",
    "content_type": "application/json",
    "auth": "Bearer",
    "params_required": ["userId"],
    "params_optional": [],
    "source_files": ["static_js_app.js"],
    "notes": "返回用户详情，含 phone, email, orgId"
  },
  "/api/user/{id}/detail": {
    "method": "GET",
    "content_type": null,
    "auth": "Bearer",
    "params_required": ["id (路径参数)"],
    "params_optional": [],
    "source_files": ["static_js_chunk-vendors.js"],
    "notes": "路径 REST 风格"
  },
  "/api/order/list": {
    "method": "POST",
    "content_type": "application/json",
    "auth": "Bearer",
    "params_required": [],
    "params_optional": ["buyerId", "startTime", "endTime", "page", "pageSize"],
    "source_files": ["static_js_app.js"],
    "notes": "全部参数可选，不传返回全部订单"
  },
  "/api/export/user": {
    "method": "POST",
    "content_type": "application/json",
    "auth": "Bearer + X-CSRF-Token",
    "params_required": ["userIds", "fields"],
    "params_optional": [],
    "source_files": ["static_js_admin.js"],
    "notes": "管理功能，需 admin 权限"
  },
  "/api/admin/config": {
    "method": "GET",
    "content_type": null,
    "auth": "X-API-Key",
    "params_required": [],
    "params_optional": [],
    "source_files": ["static_js_admin.js"],
    "notes": "API Key 在响应中泄露，来源 /api/user/info"
  }
}
```

---

## 5. 搜索关键词增强版

**先全量搜索定位，再逐文件深度阅读。**

```
第一轮 — 定位 API 调用的所有变体:
  fetch(          axios(      axios.get(   axios.post(   axios.put(
  axios.delete(   $.ajax(     $.get(       $.post(       $.getJSON(
  XMLHttpRequest  request(    .get(         .post(        .put(
  createApi(      useQuery(   useMutation(  useLazyQuery(
  graphql(        gql`        client.query( client.mutate(
  apolloClient    createHttpLink

第二轮 — 定位 URL/路径:
  /api/           /v1/        /v2/         /v3/          /rest/
  /graphql        /query      /mutation    /internal/    /admin/
  /manage/        /debug/     /actuator    /swagger      /druid
  baseURL:        API_HOST    API_BASE     serverUrl     endpoint:
  path:           url:        prefix:      proxyUrl

第三轮 — 定位参数（确认哪些参数被传递）:
  body:           data:       params:      query:        variables:
  JSON.stringify( formData    new URLSearchParams
  ?               &           =            

第四轮 — 定位认证信息:
  Authorization   Bearer      X-API-Key    X-Auth-Token  token
  apiKey          secretKey   access_token refresh_token csrf
  Cookie          session     withCredentials: true

第五轮 — 定位加密/签名:
  CryptoJS.AES    CryptoJS.DES  CryptoJS.enc CryptoJS.mode
  crypto.subtle   createHmac    md5(         sha256(
  sign(           signature     timestamp + secret
```

---

## 6. 硬编码凭据提取增强

```javascript
// 搜索以下模式 — 不只是搜索变量名，要读赋值语句的完整内容:

// API 密钥 (云服务)
// 特征: 以 AKID/LTAI/AKIA/APID/AIza 开头
const accessKeyId = 'AKIDxxxxxxxxxxxxxxx';

// JWT Secret / 签名密钥
const JWT_SECRET = 'my_super_secret_key_12345';
const SIGN_KEY = 'abcdefghijklmnop';

// AES 密钥 + IV
var key = CryptoJS.enc.Utf8.parse("1234567890123456");
var iv = CryptoJS.enc.Utf8.parse("6543210987654321");

// 第三方服务密钥
const SMTP_PASS = 'email_password_here';
const MAPS_API_KEY = 'AIzaSyxxxxxxxxxxxxx';

// 数据库连接（罕见但致命）
const dbUrl = 'mongodb://admin:password@internal-db:27017/prod';

// OAuth 客户端密钥
const clientSecret = 'oauth_client_secret_here';
```

---

## 7. SPA Hash 路由提取增强

```javascript
// Vue Router:
const routes = [
  { path: '/dashboard', component: Dashboard },
  { path: '/admin/users', component: AdminUsers, meta: { requiresAuth: true, roles: ['admin'] } },
  { path: '/admin/config', component: AdminConfig, meta: { requiresAuth: true } },
  { path: '/debug/logs', component: DebugLogs },
];

// React Router:
<Route path="/dashboard" element={<Dashboard />} />
<Route path="/admin/users" element={<AdminUsers />} />
<Route path="/internal/status" element={<InternalStatus />} />

// 提取输出到 _hash_routes.txt:
// /#/dashboard          → 基础页面
// /#/admin/users        → 需 admin 角色
// /#/admin/config       → 需认证
// /#/debug/logs         → 无认证！(高危)
// /#/internal/status    → 无认证！(高危)
```

**SPA 路由价值判断：**
```
优先级:
  P0: /admin/ /manage/ /debug/ /internal/ 路由（无认证约束时立即测试）
  P1: 需要特定角色但无后端校验的 admin 路由
  P2: 普通用户路由（可能触发新的 API 调用）
```

---

## 8. 请求拦截器分析（关键）

很多项目用 axios/fetch 拦截器自动注入公共参数。这部分逻辑会告诉你"每个请求自动带了什么"。

```javascript
// axios 请求拦截器 → 全局注入的参数
axios.interceptors.request.use(config => {
  config.headers['Authorization'] = 'Bearer ' + store.getters.token;
  config.headers['X-Request-Timestamp'] = Date.now();
  config.headers['X-Request-Sign'] = md5(config.url + Date.now() + SECRET);
  config.params = { ...config.params, _t: Date.now() };
  return config;
});

// 提取结果:
// ┌─────────────────────────────────────────────────────────┐
// │ 全局请求拦截器自动注入:
// │   Authorization: Bearer <token>         (认证)
// │   X-Request-Timestamp: <unix_ms>        (防重放)
// │   X-Request-Sign: md5(url+ts+SECRET)    (签名)
// │   _t: <unix_ms> (查询参数, 防缓存)
// │
// │ → SECRET 需要从其他变量找到
// │ → 签名算法: md5(url + timestamp + SECRET)
// └─────────────────────────────────────────────────────────┘
```

---

## 9. JS 文件分类分析

```
对每个 JS 文件，分析完成后标记：

□ 类型: vendor/lib / app / chunk / config / admin / login
□ 大小: ____ KB
□ 是否包含 API 调用: 是/否 (数量)
□ 是否包含硬编码凭据: 是/否
□ 是否包含加密逻辑: 是/否
□ 是否包含路由定义: 是/否
□ 是否包含请求拦截器: 是/否
□ 优先级: P0(包含管理API) / P1(包含用户API) / P2(工具库) / P3(静态资源)

聚焦优先级:
  P0 文件: 逐行阅读，完整提取
  P1 文件: 搜索+上下文阅读
  P2 文件: 仅提取版本号（用于依赖扫描）
  P3 文件: 跳过（如 moment.js, lodash.min.js 等已知第三方）
```

---

## 10. JS 分析检查清单 + 完整性追踪

### ⛔ 完成判定（Phase 0→1 Gate 的前置条件）

```
在宣称"Phase 0 完成"之前，_endpoint_params.json 的 _meta 节必须满足:

  □ js_files_collected > 0  （下载了 JS 文件）
  □ js_files_analyzed > 0   （逐个完整读取了文件）
  □ analysis_completeness ≥ 0.8  （至少 80% 的非第三方文件已分析）
  □ total_endpoints_extracted ≥ 3  （至少提取了 3 个 API 端点）
  □ 每个端点标注了 method 和 source_files  ← ★ 必填

如果 _meta 不满足 → 不能进入 Phase 1
```

### 10a. _endpoint_params.json v2.4 完整格式

```json
{
  "_meta": {
    "js_files_collected": 8,
    "js_files_analyzed": 7,
    "js_files_skipped": ["moment.min.js"],
    "skipped_reason": "confirmed 3rd-party: moment.js datetime lib",
    "analysis_completeness": 1.0,
    "files_detail": {
      "app.js": {
        "analyzed": true,
        "size_kb": 234,
        "api_calls_found": 12,
        "classification": "app",
        "priority": "P1",
        "notes": "主应用逻辑，含用户 API"
      },
      "chunk-vendors.js": {
        "analyzed": true,
        "size_kb": 1200,
        "api_calls_found": 5,
        "classification": "chunk",
        "priority": "P0",
        "notes": "含 axios 拦截器 + admin API 配置"
      },
      "admin.js": {
        "analyzed": true,
        "size_kb": 89,
        "api_calls_found": 15,
        "classification": "admin",
        "priority": "P0",
        "notes": "管理后台独立构建，含 /admin/* 接口"
      },
      "moment.min.js": {
        "analyzed": false,
        "size_kb": 72,
        "api_calls_found": 0,
        "classification": "vendor",
        "priority": "P3",
        "notes": "第三方日期库，确认跳过"
      }
    },
    "total_endpoints_extracted": 32,
    "total_secrets_found": 2,
    "total_routes_found": 8,
    "warnings": [],
    "generated_at": "2026-05-19T12:00:00Z"
  },
  "endpoints": {
    "/api/user/list": {
      "method": "POST",
      "content_type": "application/json",
      "auth": "Bearer",
      "params_required": ["page", "pageSize"],
      "params_optional": [],
      "source_files": ["app.js"],
      "notes": "返回 {userId, name, phone}"
    }
  }
}
```

### 10b. JS 文件分析追踪清单

```
逐文件追踪（对 每个 JS 文件 必须如实标记）:

  □ 文件: _________.js  |  大小: ____ KB
    □ analyzed: true / false  ← 是否已完整读取？（不只是搜索关键词）
    □ api_calls_found: ___    ← 提取到几个 API 调用？
    □ classification: app / chunk / admin / vendor / config / login / unknown
    □ priority: P0 / P1 / P2 / P3
    □ notes: _________

对 priority 分为 P0/P1 的文件:
  □ 必须 analyzed: true
  □ 必须提取所有 API 调用的完整请求签名
  □ 禁止 search-only（只搜索关键词不读完整内容）

对 priority 分为 P3 的文件（已知第三方库）:
  □ 可以 analyzed: false
  □ 但必须在 skipped_reason 中说明理由
  □ 文件名必须在 js_files_skipped 列表中

聚焦优先级:
  P0 文件: 逐行阅读，完整提取（admin.js, 含 /admin/* 的 chunk）
  P1 文件: 搜索+上下文阅读（app.js, 业务逻辑 chunk）
  P2 文件: 仅提取版本号（vendor.js with axios config）
  P3 文件: 可跳过（moment.js, lodash.min.js 等已知第三方）
```

### 10c. ⛔ 禁止提交"未分析的空白清单"

```
以下情况视为 Phase 0 未完成:

❌ _meta 节缺失（无追踪数据）
❌ js_files_analyzed = 0（下载了但没读）
❌ analysis_completeness < 0.5（大部分文件没读）
❌ files_detail 为空（没有逐文件追踪）
❌ 所有文件都是 analyzed: false（虚假的"分析完成"）
❌ P0 文件标记为 analyzed: false（管理接口文件被跳过）
❌ 端点 source_files = []（不知道从哪个 JS 文件来的）
❌ 端点 method = ""（不知道 HTTP 方法）
```

---

## 11. 与后续阶段的接口

```
_endpoint_params.json  →  api_fuzz agent:     作为参数需求表
_secrets_found.json    →  crypto_attack agent: 作为密钥字典输入
_hash_routes.txt       →  api_fuzz agent:      测试隐藏页面
JS 文件中的加密调用      →  crypto_attack agent: 提取密钥+IV+算法
JS 中的 baseURL         →  api_fuzz agent:      确定 API 根路径
```

---

## 12. 禁止的行为

```
❌ 只看搜索结果不读文件内容
❌ 只读 app.js 不读 chunk-*.js（懒加载文件经常藏管理接口）
❌ 只提取 URL 不提取请求体参数名
❌ 跳过 vendor.js（可能包含 axios 配置和拦截器）
❌ 提取 3 个接口就停止（目标: 全量提取）
❌ JS 文件在线上，不下载到本地
```

