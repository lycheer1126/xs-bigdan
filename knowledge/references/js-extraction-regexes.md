# JS 敏感信息提取模式库（FindSomething + 雪瞳 能力合集）

> 用途: JS 落盘到 `evidence/js/` 后逐条 grep;命中 → 敏感的进 `evidence/_secrets_found.json` 与值池,
> 普通的记 INFO。**每发现一个漏抓 pattern → 往本表加一行并注明日期**,捕获率只增不减。
> 命中 ≠ 漏洞:按 compliance-rules.md TIER 表确认可用性(能解密/能登录/能调用才算 CONFIRMED)。

## 用法

```bash
cd evidence/js
grep -oEn "<表中pattern>" *.js --no-filename | sort -u
# 或对单个文件
grep -oEn "<pattern>" app.xxx.js | head -20
```

## 1. 凭据与令牌（最高价值,命中即 PENDING 起）

| 目标 | grep -oE 模式 |
|------|---------------|
| JWT | `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}` |
| AWS AccessKey | `AKIA[0-9A-Z]{16}` |
| 阿里云 AccessKey | `LTAI[0-9A-Za-z]{12,28}` |
| 腾讯云 SecretId | `AKID[A-Za-z0-9]{13,40}` |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` |
| 私钥块 | `-----BEGIN (RSA \|EC \|OPENSSH \|PGP )?PRIVATE KEY-----` |
| 数据库/队列连接串 | `(jdbc\|mongodb(\+srv)?\|mysql\|postgres\|redis\|amqp\|mqtt)://[^\s"'<>]{5,}` |
| 通用密钥赋值 | `(secret\|secretKey\|secret_key\|apiKey\|api_key\|accessKey\|accessKeySecret\|appSecret)["']?\s*[:=]\s*["'][A-Za-z0-9+/=_-]{8,}["']` |
| 鉴权头硬编码 | `(Authorization\|X-API-Key\|X-Auth-Token)["']?\s*[:=]\s*["'](Basic\|Bearer\|)?\s*[A-Za-z0-9+/=]{10,}["']` |
| 加密密钥常量 | `(AES\|DES\|SM2\|SM4\|CryptoJS\.enc\.Utf8\.parse)\s*\(\s*["'][A-Za-z0-9+/=_!@#$%^&*]{8,}["']` |

## 2. 内部信息与 PII

| 目标 | grep -oE 模式 |
|------|---------------|
| 内网 IP | `\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}\|172\.(1[6-9]\|2\d\|3[01])\.\d{1,3}\.\d{1,3}\|192\.168\.\d{1,3}\.\d{1,3})\b` |
| 内网/环境域名 | `(dev\|test\|uat\|staging\|internal\|intranet\|jenkins\|gitlab\|nacos\|consul\|harbor)[\w.-]*\.(com\|cn\|net\|org\|local\|internal)` |
| 手机号（中国） | `\b1[3-9]\d{9}\b` |
| 身份证 | `\b[1-9]\d{5}(19\|20)\d{2}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])\d{3}[\dXx]\b` |
| 邮箱 | `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` |
| 内网路径泄漏 | `(\/home\/\w+\|\/Users\/\w+\|C:\\\\Users\\\\\w+\|\/data\/\w+)` |

## 3. API 路径与端点

| 目标 | grep -oE 模式 |
|------|---------------|
| 引号内路径 | `["'\x60](\/[a-zA-Z0-9_\-./]{3,})["'\x60]` → 结果再 `\| grep -Ei "api\|user\|admin\|upload\|export\|query\|list\|info\|login\|token\|sms\|code\|order\|pay"` |
| REST 前缀 | `\/(api\|v1\|v2\|v3\|rest\|gateway\|openapi\|inner\|internal)\//` |
| 完整 URL（含内网/异常域） | `https?://[A-Za-z0-9._-]+(:\d+)?(/[^\s"'<>]*)?` → 过滤掉静态资源域名后逐域归类 |
| sourcemap 泄漏 | `[A-Za-z0-9_./-]+\.js\.map` |
| 接口文档路径 | `(swagger\|api-docs\|openapi\|doc.html\|graphiql)` |

## 4. 风险变量名（值可能为空,但变量名暴露后端结构）

```
(password|passwd|pwd|token|jwt|secret|privateKey|private_key|apiKey|api_key|
accessKey|access_key|sessionKey|smsCode|verifyCode|payPassword|admin_password|
db_pass|db_password|smtp_pass|mail_pass|encrypt_key|iv|signKey|app_id|appid|
corpid|corpsecret|unionid|openid)
```
用法: `grep -oEn "<上面换行去掉>" *.js | sort -u | head -40` — 变量名清单本身写进 digest「技术栈/攻击面」。

## 5. 误报过滤（命中后过一遍再入库）

- **公开示例值**: `AKIAIOSFODNN7EXAMPLE`（AWS 文档示例）、`your-api-key`、`xxxx`、`test123` 类占位符
- **第三方库噪音**: axios/jquery/vue 内部字符串——按文件名排除 vendor/chunk-vendors
- **打包哈希**: webpack chunk hash 不是路径
- **UI 已公开的数据**: 前端已展示的手机号/邮箱不算泄露（decision-trees §1 UI 可见性预检）
- **地图类 Key**: Google/Baidu/Amap Key → SRC 不收（Quick-Filter）

## 登记（新 pattern 追加处）

| 日期 | 目标 | pattern | 备注 |
|------|------|---------|------|
| 2026-08-29 | 初始建表 | 上表全部 | FindSomething+雪瞳合集,源自 API-Agent 文章对照 |
