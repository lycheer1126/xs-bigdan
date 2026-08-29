# §23 泛查询 / Filter Bypass（筛选条件绕过）
### 核心成因
查询接口后端未对筛选/限定参数做严格判空和鉴权兜底，导致参数边界失控，特殊值绕过 WHERE 条件后返回超出当前用户权限的全量数据。本质：**后端查询条件未做严格校验 → 参数边界失控 → 返回越权数据**。

### 挖掘入口
优先定位以下三类接口（天然依赖查询条件）：
- **列表/搜索接口**: `/api/order/list` `/api/ticket/search` `/api/knowledge/query` `/api/resource/page`
- **导出接口**: `/api/export/users` `/api/report/export` `/api/download/csv`
- **带限定参数接口**: 任何含 `categoryId` `tenantId` `groupId` `ownerId` `caseAccountId` `knowledge_lib_id` `buyerId` `creatorId` `projectId` `deptId` `orgId` `memberId` 等过滤字段的请求

### 13 种变异手法（从轻到重：改值 → 清空 → 删结构）

```
第一轮 P0 — 参数值变异（最轻量，不改参数结构，只改值）：
┌──────────────────────────────────────────────────────────────┐
│ ① 置0 (Set to 0)                                            │
│   id=0  /  userId=0  /  categoryId=0                         │
│   部分 ORM 对 id=0 匹配所有记录或跳过校验                      │
│   示例: /api/resource/list?ownerId=0 → 返回非当前用户的资源     │
│                                                              │
│ ② 置1扩散 (Set to 1 spread)                                  │
│   type=1  /  status=1  /  category=1                         │
│   命中最大范围的分类或状态，超出当前用户的限定范围               │
│   示例: 用户只能查type=2(自己的) → 改type=1 → 管理员级别的全量   │
│                                                              │
│ ③ 通配符模糊匹配 (Wildcard LIKE bypass)                       │
│   keyword=%  /  keyword=*  /  keyword=_                      │
│   后端直接拼成 WHERE name LIKE '%keyword%' → %命中所有记录     │
│   * 和 _ 作为 SQL 通配符直接绕过匹配逻辑                       │
│   Multi-byte: keyword=％ (全角百分号, 可能未被转义)            │
│                                                              │
│ ④ 负数 (Negative value)                                      │
│   id=-1  /  userId=-1  /  categoryId=-1                      │
│   绕过正整数校验逻辑，触发异常查询路径或返回特殊数据集           │
│   示例: WHERE id > 0 → id=-1 绕过 → 全表                       │
├──────────────────────────────────────────────────────────────┤
│ 第二轮 — 参数清空（参数仍存在但值为空）：                       │
│                                                              │
│ ⑤ 置空 (Empty value)                                         │
│   keyword=  /  name=  /  categoryId=                         │
│   后端可能拼成 WHERE name='' 或直接忽略该条件 → 全表返回       │
│   示例: /api/order/list?keyword= → WHERE keyword LIKE '%%'    │
├──────────────────────────────────────────────────────────────┤
│ 第三轮 — 参数结构删除（最重，改变请求结构）：                   │
│                                                              │
│ ⑥ 删参数 (Delete parameter)                                  │
│   直接不传该过滤字段 → 后端无此条件 → 查全量                    │
│   GET: 从 URL 删掉 &categoryId=xxx                            │
│   JSON: 从 body 删掉 "categoryId":"xxx" 整个键值对            │
├──────────────────────────────────────────────────────────────┤
│ 第四轮 P1 — 场景化扩展（针对特定参数类型的深度变异）：          │
│                                                              │
│ ⑦ 超大分页 (Large pagination)                                │
│   pageSize=9999  /  limit=99999  /  size=999999              │
│   服务端未限制单页最大条数，一次性拉取全量数据                   │
│   配合 page=1 → 直接导出全表                                   │
│                                                              │
│ ⑧ page 置0或负数 (page=0 / page=-1)                          │
│   page=0  /  page=-1  /  offset=-1                           │
│   部分框架 page=0 返回全部，page=-1 返回第一页之前的数据        │
│   ORM 分页计算: LIMIT offset, size → offset=-1 可能绕过        │
│                                                              │
│ ⑨ 数组注入 (Array injection)                                 │
│   id[]=1&id[]=2&id[]=3  /  ids=1,2,3,4,5...999              │
│   批量查询接口未限制 ID 数量 → 枚举他人 ID 拉到他人数据         │
│   JSON: {"ids": [1,2,3,...,1000]} → 批量越权拉取              │
│                                                              │
│ ⑩ 类型混淆 (Type confusion)                                  │
│   id=a  /  id=null  /  id=undefined  /  id=true              │
│   整型字段传字符串/布尔/null → 类型转换 → 查询条件失效          │
│   示例: WHERE id='a' → 隐式转换为0 → 返回 id=0 的数据或全表    │
│   JSON: 整型字段传 true/false/null → 反序列化异常 → 跳过条件   │
│                                                              │
│ ⑪ 时间范围扩大 (Time range expansion)                         │
│   startTime=2000-01-01&endTime=2099-12-31                    │
│   startTime=1970-01-01&endTime=9999-12-31                    │
│   拉取全量历史数据，突破默认时间窗口限制（如仅本月/本季度）      │
│   也可: 删除 startTime/endTime 参数 → 后端不加时间条件         │
│                                                              │
│ ⑫ 排序字段注入 (Order-by field injection)                     │
│   orderBy=id → orderBy=salary / orderBy=password / ...       │
│   排序字段名可控 → 间接泄露敏感字段值的排序规律和分布           │
│   延伸: orderBy=CASE WHEN ... THEN ... END → SQL注入          │
│                                                              │
│ ⑬ 响应字段扩展 (Response field expansion)                     │
│   fields=*  /  select=all  /  fields=id,name,phone,password  │
│   部分接口支持自定义返回字段 → 拉取未授权的敏感字段             │
│   GraphQL: { users { id name phone ssn } } → 越权字段         │
└──────────────────────────────────────────────────────────────┘
```

### 决策流程
```
发现列表/搜索/导出接口
  ↓
Step 1: 记录基线
  正常请求 → 记录 response_length + total/count + 数据内容特征
  ↓
Step 2: 逐个参数变异 + 每轮变异后立即对比基线（不批量，一步一观察）：
  For each 限定条件参数:
    按顺序: 置0 → 置1 → % → -1 → 置空 → 删参数
      ↓ (每次变异后立即发请求对比基线)
      观察: 响应体长度变大? total/count跳变? 出现他人数据?
        → YES: 该参数+该变异值触发泛查询 ✅ → 记录 → 继续测下一个参数
        → NO:  继续下一个变异值
  ↓
Step 3: P1 深度覆盖（P0 轮如已命中，P1 用于扩大战果）
  超大分页 → page=0/-1 → 数组注入 → 类型混淆 → 时间范围 → 排序字段 → 响应字段
  （同样每变异一次立即对比基线，非批量）
  ↓
Step 4: 人工确认
  对比响应内容 → 确认是否确实返回了越权数据 → 记录触发参数+变异值
```

### 测试位置全覆盖
```
URL Query:     GET /api/order/list?keyword=xxx&categoryId=xxx → 逐个变异
POST Form:     Content-Type: application/x-www-form-urlencoded → body参数变异
POST JSON:     {"query":{"filters":{"categoryId":"xxx"}}} → 逐层JSON key变异
Path Param:    /api/user/{userId}/orders → userId=0 / userId=-1 / userId=
Request Header: X-Tenant-Id / X-Group-Id / X-User-Id / X-Filter-* → 置空/删除
Cookie:        tenant=xxx; group=xxx → 拆分后逐个Cookie键值变异
GraphQL:       查询参数/筛选字段 → 删除where条件/扩大limit
```

### 参数变异速查字典
```
第一轮（改值，最轻量）:
  置0:     param=0
  置1:     param=1
  通配符:  param=% | param=* | param=_
  负数:    param=-1
第二轮（清空）:
  置空:    param=
第三轮（删结构，最重）:
  删参:    [REMOVE_KEY]

第四轮（场景化扩展）:
  大数:    pageSize=9999 | limit=99999 | size=999999
  page:    page=0 | page=-1 | offset=-1
  数组:    param[]=1&param[]=2 | ids=1,2,3
  混淆:    param=a | param=null | param=undefined | param=true
  时间:    startTime=2000-01-01&endTime=2099-12-31
  排序:    orderBy=salary | orderBy=password | sort=*
  字段:    fields=* | select=all | fields=id,name,phone
```

### 漏洞本质一句话总结
> 泛查询不是注入，是**授权边界在查询层面的塌陷**——后端用前端参数拼WHERE条件但未校验参数的有效性和归属，攻击者控制参数边界后查询范围越过了当前用户的权限边界。

### JWT ↔ 泛查询 闭环链路（MANDATORY）
```
泛查询泄露他人数据(userId/邮箱/手机号)
    ↓
提取的 userId → JWT爆破分支(§JWT Step 2) → 辅助字典
提取的 Secret/Key → JWT 自签 Token → 伪造任意用户身份
    ↓
用伪造的高权限 Token 回到泛查询接口
    ↓
更大范围的批量数据泄露 → 高危/严重

核心: 单点泛查询=中危, 泛查询→JWT→泛查询闭环=高危
```

### 关联漏洞
- 通用参数变异基线测试 → §13 通用参数Fuzz
- 若IDOR端点带筛选条件(ownerId/categoryId) → §1 IDOR
- 若接口本身无认证就返回全量 → §8 未授权访问
- JWT爆破/伪造 → `references/jwt-analysis.md` Step 2-3
- 源码泄露 → 数据联动链路 → SKILL.md Phase 0 Source Leak Search

### SRC合规
```
严重度:
  返回全站用户PII（手机/身份证/地址≥3敏感字段） → 高危/严重
  返回全站工单/订单（含他人业务数据） → 中危起步，涉及隐私=高危
  返回全站公开资源/列表（无敏感信息） → 低危/忽略
数据限制: 截图响应结构变化 + 前 ≤5 条数据样例即可，严禁批量导出
报告关键: 证明 "参数 X 从正常值变为 Y 后，数据范围突破当前用户权限"
```

---
