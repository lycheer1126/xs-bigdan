---
name: data-linkage
description: >
  全接口覆盖测试 + 响应驱动参数注入方法论。强制规则：测试所有API端点，
  从每个响应挖掘所有字段名和字段值，结合 JS 提取的参数需求表构建
  双向映射（接口→参数名 ← 参数名→值），自动构造测试请求。
  核心信条：A 接口返回的参数值 = B 接口的输入武器。永不停止。
metadata:
  tags: "data-linkage,parameter-injection,response-chaining,credential-stuffing,full-coverage"
  category: "offensive-security"
---

# Data Linkage — JS参数需求表 × 响应值池 → 联动注入

> 核心信条：A 接口返回的参数值 = B 接口的输入武器。
>
> **你的优势**：可以同时持有 JS 参数需求表和所有接口响应，做人类做不到的跨接口模式匹配。

---

## ⛔ 铁律（不可跳过）

```
铁律 1: 所有接口必须测试 —— 无论看起来多无聊
铁律 2: 每个 200 响应必须挖掘 —— 递归提取每一个字段名和字段值
铁律 3: 双向映射必须构建:
        JS 提供: 接口→需要的参数名（_endpoint_params.json）
        响应提供: 参数名→真实值池（_leaked_values.json）
        合体:   (接口, 参数名, 真实值) → 直接可测试
铁律 4: 闭环永不停止: 新拿到的数据 → 回注到所有已知接口 → 新响应 → 新数据 → ...
铁律 5: A 返回的参数在 B 中使用 —— 这是最重要的测试方向
```

---

## 0. 完整工作流（三阶段联动）

```
┌──────────────────────────────────────────────────────────────────────┐
│                     DATA LINKAGE WORKFLOW                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 1: JS 分析 (js_analysis)                                      │
│  ├── 提取所有 API 端点                                               │
│  ├── 提取每个端点需要的参数名（从 fetch/axios 调用）                 │
│  └── 输出: _endpoint_params.json                                    │
│                                                                      │
│  Phase 2: 全接口测试 + 响应挖掘 (本阶段)                             │
│  ├── GET/POST 每个端点（逐个，不可跳过）                             │
│  ├── 每个 200 响应 → 递归提取所有字段名和字段值                      │
│  ├── 特别标记: JWT / AK/SK / 密码 / 邮箱 / 手机 / ID / URL           │
│  └── 输出: _leaked_values.json, _response_dump/                     │
│                                                                      │
│  Phase 3: 联动注入 (本阶段核心)                                      │
│  ├── _endpoint_params.json × _leaked_values.json = 测试矩阵          │
│  ├── 逐个发请求，记录 200 响应                                       │
│  ├── 新响应 → 新泄露值 → 回加到值池 → 继续测试                      │
│  │   （循环直到无新数据或所有组合穷尽）                               │
│  └── 发现越权/泄露 → 提交 finding                                    │
│                                                                      │
│         ┌──────────┐                                                 │
│         │ 值池更新  │ ← 每次新响应都回写                              │
│         └────┬─────┘                                                 │
│              │                                                       │
│    ┌─────────▼──────────┐                                            │
│    │ 检查是否有新的匹配: │                                            │
│    │ 参数名 在值池中？   │── YES ──► 发请求 ──► 新响应 ──┐           │
│    │ 参数名 有真实值？   │                            │   │           │
│    └────────────────────┘                            │   │           │
│                                                      ◄───┘           │
│                                                     循环             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 1. Step 1: 从 JS 拿到接口-参数需求表

**这一步在 js_analysis 阶段完成。Data Linkage 阶段以此为基础。**

```json
// _endpoint_params.json（来自 JS 分析）
{
  "/api/user/list":       { "method": "POST", "params_required": ["page", "pageSize"] },
  "/api/user/info":       { "method": "POST", "params_required": ["userId"] },
  "/api/user/detail":     { "method": "POST", "params_required": ["userId", "orgId"] },
  "/api/order/list":      { "method": "POST", "params_required": [], 
                            "params_optional": ["buyerId", "startTime", "endTime"] },
  "/api/org/{id}/members":{ "method": "GET",  "params_required": ["id (路径参数)"] },
  "/api/export/user":     { "method": "POST", "params_required": ["userIds", "fields"] },
  "/api/admin/config":    { "method": "GET",  "params_required": [], "auth": "X-API-Key" }
}
```

---

## 2. Step 2: 全接口覆盖测试（逐个请求 + 保存响应）

**对 _endpoint_params.json 中的每一个接口，逐个发请求。**

```
规则：
  □ 每个接口至少 GET + POST 各一次
  □ 如果 JS 指定了 method，用指定的 method
  □ 如果 JS 提供了参数名但没有值 → 先用空值或占位值尝试
  □ 如果 JS 提供了 auth 方式 → 带上对应的 token/header
  □ 如果接口返回 405 → 换 HTTP 方法
  □ 如果接口返回 401/403 → 标记，留给 bypass 阶段
  □ 如果接口返回 200 → 保存完整响应体
```

```bash
# 逐个请求并保存完整响应
mkdir -p findings/_response_dump/

for endpoint in $(jq -r 'keys[]' _endpoint_params.json); do
  method=$(jq -r ".\"$endpoint\".method" _endpoint_params.json)
  
  echo "=== $method $endpoint ==="
  
  resp=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE$endpoint" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}')
  
  http_code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -n -1)
  
  # 记录日志
  echo "$endpoint | $method | $http_code | ${#body} bytes" >> response_log.txt
  
  # 保存 200 响应
  if [ "$http_code" = "200" ]; then
    fname=$(echo "$endpoint" | tr '/' '_')
    echo "$body" > "findings/_response_dump/${fname}.json"
  fi
done
```

**禁止的行为：**
- ❌ 跳过"看起来不重要的接口"（每个接口都是潜在信息源）
- ❌ 只看 HTTP 状态码不看响应体
- ❌ 请求一次就不管了（没返回数据也可能需要换参数）

---

## 3. Step 3: 响应挖掘 — 提取所有字段名和值

对**每一个 200 响应**，递归提取所有字段：

### 3a. 字段名提取（递归展开嵌套 JSON）

```python
def extract_all_fields(obj, prefix=""):
    """从 JSON 响应中递归提取所有字段名"""
    fields = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            fields[full_key] = v
            fields.update(extract_all_fields(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            fields.update(extract_all_fields(item, f"{prefix}[{i}]"))
    return fields
```

### 3b. 值类型识别 + 自动归类到值池

```python
def classify_value(field_name, value):
    """根据字段名+值特征，自动分类到值池"""
    
    # P0: 凭据类（最高优先级）
    if isinstance(value, str):
        if value.startswith("eyJ") and value.count('.') == 2:
            return "jwt_token", "CRITICAL"
        if value.startswith(("AKID", "AKIA", "LTAI", "APID", "AIza")):
            return "cloud_key", "CRITICAL"
        if value.startswith(("sk-", "pk-")):
            return "api_key", "CRITICAL"
    
    # P1: 身份标识类
    field_lower = field_name.lower()
    if any(kw in field_lower for kw in ['password', 'pwd', 'secret', 'privatekey']):
        return "credential", "CRITICAL"
    if any(kw in field_lower for kw in ['token', 'accesstoken', 'refreshtoken']):
        return "auth_token", "CRITICAL"
    if any(kw in field_lower for kw in ['userid', 'user_id', 'uid']):
        return "user_id", "HIGH"
    if any(kw in field_lower for kw in ['orgid', 'org_id', 'tenantid', 'tenant_id']):
        return "org_id", "HIGH"
    if any(kw in field_lower for kw in ['orderid', 'order_id']):
        return "order_id", "HIGH"
    
    # P2: 联系信息类
    if isinstance(value, str) and "@" in value and "." in value.split("@")[-1]:
        return "email", "MEDIUM"
    if isinstance(value, str) and len(value) == 11 and value.startswith("1"):
        return "phone", "MEDIUM"
    
    # P3: URL/路径
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return "url", "MEDIUM"
    
    # P4: 纯数字ID（1-99999999）
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "numeric_id", "MEDIUM"
    
    return "unknown", "LOW"
```

### 3c. 构建泄露值池（v2.4 — 带消费状态追踪）

```python
# 值池结构已升级: 参数名 → ValueEntry列表（每个值带消费状态）
# 
# 旧结构（v2.3 静态存储）:
# LEAKED_VALUES_POOL = {
#     "userId": set(),    # {10086, 10087, ...}
# }
#
# 新结构（v2.4 消费队列）:
# {
#   "param_name": {
#     "values": [
#       {
#         "value": "admin",
#         "status": "pending",        # pending → consuming → consumed
#         "discovered_at": "2026-05-19T...",
#         "source_endpoint": "/user/list",
#         "source_param": "uid",
#         "priority": "HIGH",
#         "consumed_endpoints": [],
#         "unconsumed_endpoints": ["/user/detail", "/user/edit"]
#       }
#     ]
#   }
# }

# 核心原则: 值池中的每个值，在 consumed 之前，
#           必须标记"还有哪些接口需要我去测"。
#           未测完所有目标接口 → 不能标记 consumed。
```

### 3d. 消费状态机

```
值状态流转:
  
  pending ──(发现)──► consuming ──(某接口测完)──► consuming（仍有待测接口）
      │                    │                           │
      │                    └──(所有接口测完)──────────► consumed
      │                                                │
      └──(手动跳过/限流)──────────────────────────────► skipped

关键规则:
  □ 每个值入池时 → status = pending
  □ 设置 unconsumed_endpoints 后 → status = consuming
  □ unconsumed_endpoints 为空后 → status = consumed
  □ 新 token/新角色 拿到后 → 所有 consumed 值 → 重置为 pending（重新消费）
```

---

## 4. Step 4: 联动注入 — JS需求表 × 值池 = 测试矩阵

**这是整个方法论的核心。A 返回的参数值 → B 请求的参数输入。**

### 4a. PairingEngine 自动配对（v2.4）

> 见 `shared/linkage.py` — 完整的 Python 实现。

```
配对引擎工作流程:

① 加载 _endpoint_params.json → EndpointRegistry
   加载 _leaked_values.json   → ValuePool (带消费状态)

② 对每个端点，检查其 params_required + params_optional
   对每个参数名，在值池中精确匹配 + 语义组匹配

③ 生成 UnconsumedPair 列表:
   (endpoint, param_name, value, primary_method, fallback_methods)

④ 按优先级排序: CRITICAL > HIGH > MEDIUM > LOW

⑤ 每测试完一个 pair → mark_consumed()
   新响应产生新值 → add_value() + sync_consumption_state()
```

### 4b. 语义参数匹配规则（不仅是精确匹配）

```
参数名的语义匹配:

  JS 说接口需要: userId
  值池中有:      userId → ✅ 精确匹配
  值池中有:      user_id → ✅ 下划线变体 (canonical: userId)
  值池中有:      uid → ✅ 语义同义 (canonical: uid)
  
  JS 说接口需要: id (通用 ID 参数)
  值池中有语义组 id_like 的任何值 → ✅ 自动注入:
    uid, userId, orgId, orderId, memberId, tenantId, buyerId

  JS 说接口需要: accountName
  值池中有语义组 string_like 的任何值 → ✅ 自动注入:
    username, email, phone, nickname, name
```

### 4c. Method Fallback 自动矩阵（v2.4 新增）

```
当端点返回 500/405/415/400/501 时:

① 自动枚举 fallback methods:
   GET → POST → PUT → PATCH → DELETE → OPTIONS

② 对 POST/PUT/PATCH，自动枚举 Content-Type:
   application/json → application/x-www-form-urlencoded → multipart/form-data

③ 最多 12 种组合:
   GET×1 + DELETE×1 + OPTIONS×1 + POST×3 + PUT×3 + PATCH×3

④ 任一组合返回 200 → 保存响应 → 回注值池
   全部组合返回 4xx/5xx → 标记 _unresolved_method.txt
```

### 4d. 联动注入主循环（伪代码）

```python
from shared.linkage import PairingEngine, check_pair_completeness

# 加载状态
registry, pool = load_linkage_state(hunt_dir)
engine = PairingEngine(registry, pool)

while True:
    new_values_found = False
    
    # 同步消费状态（计算每个值还需要测哪些端点）
    engine.sync_consumption_state()
    
    # 生成待消费对
    pairs = engine.match(semantic_expand=True)
    
    if not pairs:
        break
    
    for pair in pairs:
        # ① 先试 primary method
        response = send_request(
            endpoint=pair.endpoint,
            method=pair.method,
            params={pair.param_name: pair.value_entry.value}
        )
        
        if response.status == 200:
            engine.pool.mark_consumed(
                pair.param_name, pair.value_entry.value, pair.endpoint
            )
            # 新响应 → 回写值池
            new_fields = extract_all_fields(response.json())
            for fn, fv in new_fields.items():
                engine.pool.add_value(fn, str(fv),
                    source_endpoint=pair.endpoint,
                    source_param=fn)
            new_values_found = True
            continue  # 成功，跳过 fallback
        
        # ② Method fallback 触发？
        fallback_matrix = build_method_fallback_matrix(
            pair.endpoint, pair.method, response.status
        )
        
        for fb in fallback_matrix:
            response = send_request(
                endpoint=pair.endpoint,
                method=fb["method"],
                content_type=fb.get("content_type"),
                params={pair.param_name: pair.value_entry.value}
            )
            if response.status == 200:
                engine.pool.mark_consumed(
                    pair.param_name, pair.value_entry.value, pair.endpoint
                )
                new_fields = extract_all_fields(response.json())
                for fn, fv in new_fields.items():
                    engine.pool.add_value(fn, str(fv),
                        source_endpoint=pair.endpoint,
                        source_param=fn)
                new_values_found = True
                break  # fallback 命中
    
    # 饱和度检查
    if not new_values_found:
        break  # 值池不再增长，联动穷尽

# 保存状态
save_linkage_state(hunt_dir, engine.pool)
```

```
链式联动完整过程:

Step 1: JS 分析产出 _endpoint_params.json
  POST /api/user/list        需要: {page, pageSize}

Step 2: 测试 /api/user/list
  curl -X POST /api/user/list -d '{"page":1,"pageSize":10}'
  → [{"userId":10086,"name":"张三"}, {"userId":10087,"name":"李四"}, ...]
  → 值池注入: userId ∈ {10086, 10087, 10088, ...}

Step 3: 检查联动 — JS 说 /api/user/info 需要 userId!
  curl -X POST /api/user/info -d '{"userId":10086}'
  → {"userId":10086,"name":"张三","phone":"13800138000","email":"zhangsan@company.com",
     "orgId":42,"apiKey":"sk-xxx-prod-key","role":"user"}
  
  → 值池注入:
      phone ∈ {13800138000, ...}
      email ∈ {zhangsan@company.com, ...}
      orgId ∈ {42, ...}
      apiKey ∈ {sk-xxx-prod-key, ...}
      role ∈ {user, ...}

Step 4: 新值入池后立即检查联动
  - JS 说 /api/org/{id}/members 需要 id → orgId=42 是数字 → 注入!
    curl /api/org/42/members → 拿到更多 userId...
    
  - JS 说 /api/admin/config 需要 X-API-Key → apiKey 在值池中!
    curl /api/admin/config -H "X-API-Key: sk-xxx-prod-key" → 管理配置!

  - JS 说 /api/user/detail 需要 {userId, orgId} → 两者都在值池中!
    curl -X POST /api/user/detail -d '{"userId":10086,"orgId":42}' → 更多数据...

Step 5: 循环 — 新响应继续产生新值 → 继续匹配 → 直到穷尽
```

---

## 5. 重点测试：A返回的参数值在B中使用

**这是你必须反复执行的操作，也是人类的盲区。**

```
检查清单（每拿到一个新响应就执行）：

□ 新响应中有新的参数名吗？
  → 去 JS 的 _endpoint_params.json 查：哪个接口需要这个参数名？
  → 找到 → 立即构造请求测试

□ 新响应中有新的数字ID吗？
  → 所有需要 id/userId/orderId/orgId 的接口 → 逐个注入

□ 新响应中有新的 token/凭据吗？
  → 所有需要认证的接口 → 换这个凭据重测
  → 之前 401/403 的接口 → 用新凭据重测

□ 新响应中有新的 URL/地址吗？
  → 加入子域名扫描清单
  → 加入 SSRF 目标清单

□ 新响应中有新的邮箱/用户名吗？
  → 登录接口爆破
  → 密码重置接口
  → 注册接口（批量注册检查）
```

---

## 6. 值池的跨阶段流转

```
┌─────────────────────────────────────────────────────────────────┐
│                    值池的跨阶段生命周期                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1 (JS分析):                                              │
│  └── 提取硬编码值（baseURL, apiKey, token）→ 初始值池           │
│                                                                 │
│  Phase 2 (API Fuzz):                                            │
│  ├── 逐个端点请求 → 每个200响应 → 提取字段 → 值池膨胀           │
│  └── JS需求表 × 值池 → 联动注入                                 │
│                                                                 │
│  Phase 3 (Crypto Attack):                                       │
│  └── 解密出的明文 → 新的参数名+值 → 注入值池                     │
│                                                                 │
│  Phase 4 (Bypass):                                              │
│  └── 绕过 401/403 后的响应 → 新的数据 → 注入值池                │
│                                                                 │
│  Phase 5 (Exploit):                                             │
│  ├── JWT 爆破成功 → admin token → 注入值池                      │
│  ├── admin token 重打所有端点 → 大量新数据 → 值池爆炸           │
│  └── 新的 admin token → 回注 JS需求表所有管理接口               │
│                                                                 │
│  永不停止: 值池每增加一个值 → 检查是否开启新的攻击面             │
│  但注意 §6 饱和度检测 — 同一类型的值无需无穷枚举                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. 值池饱和度检测（何时停止循环）

**"永不停止"是原则，"穷尽到有意义的边界"是实战。**

```
停止注入的信号:

□ 同类 ID 饱和度:
  → 测了 5 个不同的 userId，每个返回结构相同 → 第 6 个大概率一样
  → 规则: 同类参数最多注入 5 个不同的值（compliance safe ≤5）
  → 例外: 如果某个 userId 返回了不同的 role/apiKey → 继续

□ 同类端点饱和度:
  → /api/user/1 到 /api/user/5 全部 200 → 无需测试 /api/user/6..100
  → 规则: 单端点类型最多遍历 5 个相邻值
  → 例外: 如果 ID 有规律（递增/递减/跳跃）→ 尝试边界值 (0, -1, 999999)

□ 值池增长停止:
  → 连续 3 轮联动注入，值池没有新增 HIGH/CRITICAL 类别值 → 停止
  → 新增 LOW 值（纯数字 ID 递增）不计入"增长"

□ 时间边界:
  → 单阶段联动注入 ≤ 30 分钟
  → 超过 30 分钟仍未穷尽 → 记录当前状态到 _linkage_queue.json，进入下一阶段
  → 在 EXPLOIT 阶段拿到更多特权 token 后回来继续

□ Token 引发的重启:
  → 如果后续阶段（Bypass/Exploit/JWT Attack）拿到了新角色的 token
  → 立即回到联动注入 → 用新 token 重新遍历值池
  → 这不算"重复劳动"，新角色能看到不同的数据
```

---

## 7. 输出文件

```
findings/
├── _endpoint_params.json     # 端点→所需参数 映射（来自JS分析）
├── _leaked_values.json       # 参数名→[值列表]（来自响应，持续更新）
├── _linkage_results.json     # 已测试的 (endpoint × param × value) 组合 + 结果
├── _new_endpoints.json       # 联动过程中新发现的端点
├── _linkage_queue.json       # 待测试的联动组合（按优先级排序）
├── response_log.txt          # 全量接口请求日志
└── _response_dump/           # 每个 200 响应的完整保存
    ├── api_user_list.json
    ├── api_user_info.json
    ├── api_order_list.json
    └── ...
```

---

## 8. 禁止的行为

```
❌ 测了一个接口就停了（必须全量覆盖）
❌ 看了状态码不看响应体（数据在响应体中）
❌ 提取了 userId 不去测其他需要 userId 的接口（联动是核心）
❌ 拿到 token 不去重测之前 401/403 的接口
❌ 发现一个洞就停（数据联动永不停）
❌ 值池更新后不检查新的匹配可能性
```

