# JS Analysis, Endpoint Extraction & Source Code Leak Detection

> **用户实战方法论**: JS 文件是最大的接口信息来源。结合技术栈指纹在 GitHub/Gitee 搜索源码泄露。

---

## Part A: JS Analysis & Endpoint Extraction

### 1. JS File Collection Strategy

```
Step 1: 下载当前页面的所有 JS 文件
├── 工具: waybackurls + grep '.js$'
├── 浏览器 DevTools → Sources → 全部保存
├── playwright/puppeteer → 拦截所有 .js 请求
└── 目录: downloaded/{domain}/ （按域名组织）

Step 2: 爬取所有页面，收集增量 JS
├── SPA: 点击所有路由/菜单，触发懒加载 JS
├── 多级页面: 登录后/不同角色下 JS 可能不同
└── 历史版本: wayback machine 可能缓存旧版 JS

Step 3: 批量下载
├── waybackurls {domain} | grep '\.js$' | sort -u > js_urls.txt
├── cat js_urls.txt | xargs -I {} curl -s {} -o downloaded/{domain}/{}
└── 或: getJS, subjs, xnLinkFinder 等专用工具
```

### 2. JS File Analysis — Endpoint Extraction

#### 2.1 工具自动化

```bash
# LinkFinder — 最常用的 JS 端点提取工具
python3 linkfinder.py -i downloaded/{domain}/ -o results.html

# xnLinkFinder — 增强版
python3 xnLinkFinder.py -i downloaded/{domain}/ -o links.txt

# jsluice — Go 编写的新工具
jsluice urls downloaded/{domain}/*.js

# 正则 grep 快速提取
grep -rhoP '["\x27](\/api\/[^"'\''\s]+)["\x27]' downloaded/{domain}/*.js | sort -u
grep -rhoP '["\x27](\/v\d\/[^"'\''\s]+)["\x27]' downloaded/{domain}/*.js | sort -u
```

#### 2.2 Manual Pattern Search

**Extract API paths:**
```
关键词搜索:
  - /api/  /v1/  /v2/  /graphql  /rest/
  - fetch(  axios(  $.ajax(  XMLHttpRequest
  - url:  path:  endpoint:  baseURL:
  - createApi(  useQuery(  useMutation(

正则提取:
  - ["'](\/api\/[^"'\s]+)["']
  - ["'](\/v\d\/[^"'\s]+)["']
  - fetch\(["']([^"']+)["']
  - url:\s*["']([^"']+)["']
```

#### 2.3 Sensitive Information Extraction

```
硬编码凭证:
  - apiKey  secretKey  token  password  Authorization
  - Bearer  Basic  access_key  private_key
  - AKID (AWS/Tencent Cloud keys)
  - sk- (OpenAI/API keys)
  - glpat- (GitLab tokens)
  - ghp_ (GitHub tokens)

内部路径:
  - /admin/  /internal/  /manage/  /debug/
  - /actuator  /swagger  /druid  /graphql
  - /phpmyadmin  /jenkins  /kibana

配置信息:
  - baseURL  API_HOST  API_BASE  serverUrl
  - bucket  region  endpoint (云服务配置)
  - REACT_APP_  VITE_  VUE_APP_

端点文件泄露:
  - routes.js  router.js  api.js  config.js
  - environment.ts  environments.ts
```

#### 2.4 Regular Expression Patterns

```bash
# API endpoints
grep -rhoP '["\x27](\/(?:api|v[0-9]+|rest|graphql|internal)\/[^"'\''\s#?]+)' *.js | sort -u

# Hardcoded keys
grep -rhoP '(?:api[_-]?key|secret|token|password|auth)["\x27]?\s*[:=]\s*["\x27]([^"'\''\s]{8,})' *.js

# Cloud credentials
grep -rhoP '(AKIA|AKID|sk-[a-zA-Z0-9]{20,})' *.js

# Internal endpoints
grep -rhoP '["\x27](\/(?:admin|internal|manage|debug|actuator)\/[^"'\''\s]*)' *.js

# URLs with parameters
grep -rhoP '(?:https?:\/\/[^\/]+\/[\w\/-]*\?[\w=&-]+)' *.js
```

### 3. SPA / Vue Hash Routing

```
Vue Router (Hash 模式):
  # 后面的路径不会发到服务器
  /#/login/  /#/admin/dashboard  /#/user/profile

→ 手动拼接 hash 路由测试隐藏页面
→ 新页面 → 新 JS → 新 API 端点
→ urlfind/panda 等工具扫描时关注字节变化
```

### 4. From JS to API: Endpoint Construction

```
JS 中找到: "getUserList"
推断路由: GET /api/user/list (常见 RESTful 规范)
需要补全: 
├── API 前缀 (/api/, /api/v1/, /api/gw/)
├── Content-Type (application/json)
├── 认证方式 (Bearer token / Cookie / API-Key)
└── 请求参数 (从 JS 中的参数声明推断)
```

---

## Part B: Source Code Leak Detection

### 5. Technology Stack Fingerprinting

在进行源码搜索之前，先做技术栈指纹：

```
□ 响应头分析 (Server, X-Powered-By, Set-Cookie, X-Generator)
□ 错误页面特征 (404/500 错误页面模式，错误信息中的包名/类名)
□ HTML meta 标签 (generator, author, version)
□ 路径特征 (/actuator→Spring, /wp-content→WordPress, /skin→ThinkPHP)
□ JS 变量名 (angular→Angular, __react→React, Vue.prototype→Vue)
□ Cookie 格式 (JSESSIONID→Java, PHPSESSID→PHP, laravel_session→Laravel)
□ 静态资源路径 (/static/js/app.xxx.js→Vue CLI, /_next/→Next.js)
```

### 6. Source Code Search Strategy

```
Step 1: 技术栈指纹 → 确定搜索关键词
├── 前端框架特征 (Vue/React 特定代码片段)
├── 后端框架路径 (/actuator, /api/xxx 特征)
├── 页面标题/版权信息/错误信息特征字符串
└── Cookie 名称/Session ID 格式

Step 2: GitHub/Gitee 搜索
├── github_search_code: unique code snippets from target's JS
├── github_search_repositories: product/company name
├── gitee_search_open_source_repositories: product name
└── Google dork: site:github.com "target-unique-string"

Step 3: 二次确认
├── 对比目录结构是否一致
├── 对比接口路由是否匹配
├── 对比前端 JS 变量名/注释
└── 确认后链接保存，不要下载
```

### 7. Search Query Construction

```
# From tech fingerprint → search queries:

1. Unique error messages:
   "com.example.controller" "Internal Server Error"
   
2. Cookie/Header patterns:
   "JSESSIONID" "companyname"
   
3. Frontend code snippets:
   "apiBaseUrl" "https://target.com"
   
4. Page titles:
   "XX管理系统" in:readme
   
5. File patterns (GitHub code search):
   path:pom.xml "groupId" "artifact"
   path:composer.json "name"
   path:package.json "target-corp"
   
6. Config file patterns:
   "application.yml" "spring.datasource.url"
   ".env" "DB_PASSWORD"
   "config.js" "API_URL"
   
7. Framework-specific:
   "Django" "SECRET_KEY" path:settings.py
   "Laravel" "APP_KEY" path:.env
   "Spring Boot" "application.properties"
```

### 8. High-Value Leak Targets

```
优先级排序:
1. 配置文件: 
   - application.yml, .env, settings.py, config.js
   - application.properties, web.config, app.config
   
2. 数据库配置:
   - JDBC URL, DB credentials, connection strings
   - MySQL/PostgreSQL/MongoDB/Redis connection strings
   
3. API 密钥:
   - Cloud service keys (AWS AKIA, Tencent AKID, etc.)
   - Third-party API keys (Stripe, SendGrid, Twilio, etc.)
   - JWT secrets, encryption keys
   
4. 内部文档:
   - README with architecture overview
   - Deployment guide with IPs/hosts
   - API documentation with sensitive endpoints
   
5. 测试代码:
   - Test data with real credentials
   - Test fixtures with production-like data
   
6. CI/CD 配置:
   - .gitlab-ci.yml, Jenkinsfile, GitHub Actions
   - Dockerfile, docker-compose.yml
   - Kubernetes manifests with secrets

7. 版本控制:
   - .git/config (remote URLs)
   - .gitignore (exposed sensitive paths)
   - Commit history with credential changes
```

### 9. Tools for Credential Detection

```bash
# truffleHog — find secrets in git repos
trufflehog git https://github.com/target/repo.git

# GitLeaks — detect hardcoded secrets
gitleaks detect --source ./repo/ --verbose

# Gitleaks GitHub Action
gitleaks --repo-url=https://github.com/target/repo.git

# Manual grep for common patterns
grep -r "AKIA" ./repo/
grep -r "sk-" ./repo/
grep -r "ghp_" ./repo/
grep -r "password" ./repo/ | grep -v "password_hash"
```

### 10. Example Workflow

```bash
# 1. Tech fingerprint
curl -s https://target.com | grep -iE '(generator|meta name|react|vue|angular)'
curl -s https://target.com/api/error-test | grep -iE '(exception|error|trace)'

# 2. Extract unique identifiers
TITLE="XX后台管理系统"
API_PATTERN="/api/gw/rent/"  
ERROR_MSG="com.targetcorp.controller"

# 3. GitHub search
# Use github_search_code tool:
# q: "com.targetcorp.controller" language:java
# q: "XX后台管理系统" in:readme

# 4. Gitee search
# Use gitee_search_open_source_repositories:
# q: "targetcorp"

# 5. Google dork
# site:github.com "targetcorp" "application.yml"
# site:gitee.com "XX后台管理系统"

# 6. Confirm match
# Compare directory structure, route patterns, JS variable names
```

---

*JS Analysis & Source Leak Detection v1.0 — User's Practical Methodology*
