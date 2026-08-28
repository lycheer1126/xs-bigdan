# Discovery Amplification — 发现放大规则

> 从 SKILL.md Phase 3 迁出。在 Phase 3 和 Phase 3.5 时加载。
> 核心哲学：找到一个端点 = 找到一扇门。找到一个参数 = 找到一把钥匙。目标是找到这把钥匙能开的所有门，和这扇门接受的所有钥匙。

---

## Rule 1 — Path Pattern Inference (拼路径)

发现一个感兴趣端点后，立即枚举相关路径：

```
发现: POST /{PREFIX}/{MODULE}/get{Entity}By{Field}
  例: /app/getUserByAccountName, /api/queryStaffByEmail, /v1/findMemberById
  → 枚举前缀: /{PREFIX}/{MODULE}/
    get*  list*  query*  search*  find*  export*  delete*  update*  insert*  create*  add*
  → 枚举后缀模式: *By{Field}
    get*ByAccountName  get*ByEmail  get*ByPhone  query*ByName  find*ById
  → 枚举参数驱动的同类:
    get{Entity}By*  (ByEmail / ByPhone / ById / ByEmpCode / ByMobile / ByToken)
  → 测试所有推测路径 — 即使 90% 返回 404，剩下的 10% 是金矿

发现: /api/user/info?userId=xxx
  → 枚举: /api/user/getInfo  /api/user/info  /api/user/detail  /api/user/profile
          /api/user/query   /api/user/search  /api/user/list   /api/user/export
```

---

## Rule 2 — Parameter Pattern Inference (拼参数)

在一个端点发现参数后，在所有相关端点上测试：

```
发现: {param_name} 参数在某查询接口上有效
  → 在所有已收集端点中搜索变体:
    {param}  {param}_name  {param}Name  {param}Id  {param}_id
    同时搜索语义相关的参数: userId, user_id, account, username, memberId
  → 如果参数在端点 A 上有效 → 在端点 B, C, D, E... 上测试

发现: userId=1001 在 /api/user/info 上有效
  → 在以下端点测试 userId=1001: /api/order/list  /api/attendance/query
     /api/salary/info  /api/contract/list  /api/leave/balance
  → 一个 userId 在一个端点上有效，常常在多个端点上有效
```

---

## Rule 3 — Response Field Chaining (响应字段联动)

每次响应有新的数据字段后，立即交叉引用：

```
响应字段 → 可能的目标端点:
  emplCode  → /api/user/info?emplCode=xxx   (员工详情)
  orgId     → /api/org/{orgId}/members      (组织成员列表)
  deptId    → /api/dept/{deptId}/staff      (部门员工)
  orderId   → /api/order/{orderId}/detail   (订单详情)
  fileId    → /api/file/{fileId}/download   (文件下载)
  supplierId→ /api/supplier/{id}/contacts   (供应商联系人)
  token     → 所有端点（作为 Authorization header）
  jwt       → decode → forge → 所有端点（以提升的权限）

每次响应后的黄金问题:
"What field in this response can I feed into what other endpoint?"
```

---

## Rule 4 — Administrative Surface Escalation (管理面扩展)

标准用户端点配合 token 有效时：

```
1. 在 JS 中搜索: admin/manage/backstage/system/boss/console 路径
2. 在所有管理端点上尝试同样的 token（垂直越权）
3. 即使 GET /admin/user/list 返回 403:
   → 尝试 POST/PUT/PATCH/DELETE 方法
   → 尝试去掉 Content-Type header
   → 尝试不同的 Accept headers（部分网关按路由分发）
4. 发现管理员端点接受 token？
   → 立即枚举所有共享同一路径前缀的端点
   → 优先提取 export/download 端点（数据泄露风险最高）
```

---

## Rule 5 — Numeric Pattern Fuzzing (数字规律枚举)

ID/数字遵循某种模式时，枚举邻居：

```
{param} 模式示例: user_001, user_002, admin_01...
  → 提取命名规则: [前缀]+[数字编号]
  → 递减/递增数字: user_000, user_003, user_004...
  → 通过 GitHub/社交媒体/公开信息收集更多用户名 → 按规则构造参数值
  → 中文企业常见模式: 拼音缩写+数字 (如姓全拼+名首字母+编号)

emplCode 模式: 2021003112, 2025002543...
  → 格式: YYYY + 序列号? → 2021003000-2021003200 范围
  → 测试每第 100 个数字 → 如果命中率 >10%，整个范围可得
```

---

## Rule 6 — Export Endpoint Detection (导出接口检测)

> 导出接口是数据泄露的最高风险点——一次请求=全量数据导出。
> 任何系统的 export/download/report 端点都可能存在权限缺失。

```
发现导出端点的方法:
  1. JS中搜索: export, download, excel, csv, report, pdf, zip, dump, backup
  2. 管理API中筛选含 export/download 关键字的端点
  3. 对所有已发现端点做路径模式枚举: */export*, */download*, */report*

对每个发现的导出端点:
  → 用当前Token/无Token直接访问
  → 如果返回二进制/文件流 → 导出成功 = 严重（全量数据泄露）
  → 如果返回JSON含 total/count → 记录数据条数
  → 重点检查: 无需认证的导出 + 普通token能调用的管理导出

数据量级判定:
  total/rows ≥ 1000 → 严重
  total/rows ≥ 100 → 高危
  total/rows ≥ 10 → 中危
  无法确定数据量 → 标注"数据量未确认"
```

---

## Rule 7 — Batch Verification (批量验证/命中率统计)

> 实战案例: 某系统域账号枚举60个组合命中15个（25%命中率）。
> SRC报告中"批量验证结果"是提升报告可信度的关键。

```
当发现域账号/ID有规律时:
  1. 生成邻居值列表（递增/递减/命名规则推演）
  2. 批量探测（每100个抽1个，先验证规律存在性）
  3. 记录: 测试数量 / 命中数量 / 命中率
  4. 如果命中率 ≥ 25% → 标注"可批量枚举，高危泄露"
  5. 将命中结果格式化为表格: 测试值 | 命中 | 命中率

报告输出格式（用 {FIELD_NAMES} 替换为实际响应字段名）:
  | 测试值 | {FIELD1} | {FIELD2} | {FIELD3} | {FIELD4} | {FIELD5} |
  |--------|----------|----------|----------|----------|----------|
  | {value_1} | {data_1_1} | {data_1_2} | ... | ... | ... |
  ...
  | 共测试 {TEST_COUNT} 个组合 | 命中 {HIT_COUNT} 个 | 命中率 {HIT_RATE}% |
