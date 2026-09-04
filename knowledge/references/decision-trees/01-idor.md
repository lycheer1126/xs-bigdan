# §1 IDOR（越权）

> **IDOR 类权威**：本树是 IDOR 的唯一权威（无独立 skill）。框架层见 business_flow §问3，
> 纪律见 src-discipline §2（先加后清），现场别停表见 breakthrough-shortlist §二。
### 识别信号
- 请求含资源 ID：`userId id uid orderId fileId docId accountId`
- **列表类端点**（一请求返回全量数据）：`getuserlist /user/list /getAllUser /api/user/info(无参) /admin/user/list`
- 路径/Query/Body 中出现的归属标识
### 决策流程
```
发现资源ID/列表端点?
├── ⚠️ UI 可见性预检（MANDATORY — 防止把正常业务当漏洞报）:
│   ├── API 返回的字段是否在目标网站页面上已展示?
│   │   例: getAgentList 返回 uid/userName → 打开目标站对应页面
│   │   → /moreAssistant 页面已展示创作者名 → 这些字段是公开业务数据
│   │   → 非信息泄露，标记 "DATA_PUBLIC_IN_UI" → 跳过本§
│   ├── 判断标准: 打开目标网站的对应前端页面
│   │   → 截图对比 API 响应字段 vs UI 展示内容
│   │   → API 有的字段=UI 有的字段 → 正常业务功能
│   │   → API 有的字段≠UI 没有的字段 → 信息泄露（继续本§）
│   └── 常见 UI 公开字段: 用户名/头像/简介/公开ID/创建时间（这些不是漏洞）
│       常见非公开字段: 手机号/邮箱/身份证/密码/Token/内部ID（这些才是漏洞）
│
├── 列表类端点 (getuserlist / getAllUser 等)?
│   ├── 无Cookie/Token直接访问 → 200返回全站用户数据 → 直接【高危/严重】✅
│   │   → SRC proof: 截图返回结构 + 用户数量级，不超5条详情
│   │   → 京东: "越权获取大量用户信息"=高危，"核心DB敏感信息"=严重
│   │   → 讯飞: "核心业务系统敏感越权操作"=高危
│   └── 有低权限Token → 同样返回全量 → 垂直越权【高危】
│
├── 单资源端点 (getUserInfo?userId=X)?
│   ├── 可枚举?(Y→继续 N→从列表收集合法ID)
│   ├── A账号请求自己资源(记录响应)
│   ├── B账号请求A资源ID
│   │   → 返回A数据=IDOR ✅ | 403→进绕过 | 200但空→部分泄露
│   └── 严重度: 单条敏感信息(≤5条proof)→中危, 可批量枚举(≥高危)
│
└── SRC数据限制:
    ├── 京东: 越权读取≤5组真实数据, 严禁批量读取
    ├── 讯飞: 越权读取≤5组真实数据
    └── 仅用自己注册的2个账号验证，勿涉及线上正常用户
```
### 绕过技巧（如果B账号直访问返回403，不走常规ID置换）
```
确定不是IDOR? 不一定——鉴权可能只覆盖了"标准情况"，绕过方式很多:

a) 参数位置变换:
   鉴权只在Query检查userId,但移到Body/Path就放过
   ?userId=1003   → 403
   /api/user/1003  → 200 (Path参数)
   Body:{"userId":1003} → 200

b) 方法替换:
   鉴权只覆盖了GET,但PUT/POST/PATCH/DELETE没覆盖
   GET /api/user/1003  → 403
   POST /api/user/1003 → 200 (换方法)
   PUT /api/user/1003  → 200

c) 大小写/编码绕过:
   参数名/ID值的大小写不一致时鉴权失效
   ?userId=1003 → 403
   ?userid=1003 → 200
   ?USERID=1003 → 200
   ?user_id=1003 → 200

d) 版本降级:
   老版本API没有鉴权,新版有,降级回去绕过
   /api/v2/user/1003 → 403
   /api/v1/user/1003 → 200 (降级)
   /api/user/1003?version=1 → 200

e) Cookie二分法找鉴权参数:
   逐步删除Cookie键值对,找出哪个参数决定当前身份
   Cookie: session=xxx; token=yyy; user_id=zzz
   删session→结果变  |  删token→结果变  |  删user_id→结果变
   → 找到鉴权参数后,替换成他人的值再测

f) 响应包修改绕过前端鉴权:
   如果前端做了校验(401时前端弹窗),但后端实际返回了数据
   在Burp中将响应状态码401改200,或false改true,看前端是否展示他人数据
   本质:后端没鉴权,前端自己做了一层校验,Burp改响应即可绕过

g) 跨类型越权:
    不是同类型账户间越权,而是不同类型间
    如: 团队版账号帮个人版账号支付,管理员账号覆盖普通用户数据
    核心: 在一个请求中同时携带两个身份参数

h) 两步验证中篡改目标ID（多步流程常见）:
    第一步验证自己手机号(短信发给自己)→第二步改目标ID为别人的
    核心: 第二步只校验了"验证码正确",没校验"当前操作人是否对该ID有权限"
    例: 变更店铺负责人→第一步验自己手机→第二步改shopId=别人的店铺ID+新负责人填自己
        → 自己成为别人店铺的负责人

i) 导出/导入越权:
    导出: 导出参数中带shop_id/teamId→改成别人的→导别人全量数据
    导入: 先上传文件拿fileURL→第二步导入时改target_id为别人的
          → 文件内容写入别人空间

j) 筛选/查询接口越权:
    不要只看详情接口——筛选/列表/搜索类接口也常带ownerId/shopId参数
    替换成别人的 → 能查到别人名下的全量数据
    而且这类接口容易被人忽略,鉴权往往更弱

k) 越权改导致所有权转移（编辑变删除）:
    修改别人数据时,如果ID改成了数据属于别人的ID
    修改后的数据归属权可能变成自己的→原始数据从原用户那消失
    核心: 表面是"编辑",实际是"删除别人的数据"

l) Cookie统一认证绕过:
    Cookie里有多个参数时,逐个删除主要的鉴权Token(如bduss/token/session)
    看删除后是否还能正常访问接口
    如果能→说明有另一个参数(如uid)在做鉴权→改uid=别人的值→越权

m) 同源功能点参数推测隐藏接口:
    已知可用接口(如countByCondition)→猜同类接口也存在(如saveByCondition)
    方法: 在JS中搜动词(count→save/delete/update)组合同一路径段
```
### Payload
```
参数名: id uid user_id userId memberId accountId orderId fileId docId
位置: ?userId=1002 | Body:{"userId":1002} | Path:/api/users/1002
测试值: 0 -1 null undefined 其他用户已知ID
列表端点: GET /api/getuserlist (no params) / GET /api/user/info (no params)

注：如果IDOR端点是带筛选条件的查询接口（如 ?ownerId=xxx 限定当前用户），
先测完本§的ID置换 → 再进 §23 泛查询测筛选绕过（置空/删除/置0/%）。
```
### 关联漏洞
- 筛选绕过/泛查询 → §23


## 常见绕过技巧（clown idor-test 提炼）

### ID 猜测
```
数字 ID: ±1, ±10, 0, -1, 999999
租户/应用字段被拦后: 0 / -1 / 空 / 不传（哨兵租户，短表有指针）
UUID: 从响应或 JS 中收集其他用户 UUID
手机号: 某些接口直接以手机号为标识
```

### 参数污染（同名多值）
```
POST /api/user/info?userId=A&userId=B
URL 带 ?userId=B + body 再带 userId=A（双层不同值）
```

### 路径遍历式换资源
```
/api/user/A/orders → /api/user/B/orders
/api/order/123 → /api/order/124,125,...
```

### 编码变体
```
12345 → 0x3039(hex) → %31%32%33%34%35(URL编码)
```

### 证据收集规范
1. 请求完整内容（含 token/headers）2. 响应完整内容（含越权数据）3. 自己 vs 越权的对照。
越权数据 ≤5 条（合规红线），超出部分打码不落盘。
