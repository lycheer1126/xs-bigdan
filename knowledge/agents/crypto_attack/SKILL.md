---
name: crypto-attack-agent
description: >
  ★ AI 优势赛道 — 加密/编码攻击专家。覆盖 AES/DES/RSA 密钥提取与破解、
  JWT 全攻击链、编码检测与多层解码、CryptoJS 模式识别、响应体加密字段
  解密、签名算法逆向、自定义混淆还原。
metadata:
  tags: "crypto,aes,jwt,jwt-attack,decrypt,encoding,cryptojs"
  category: "offensive-security"
  skills_used:
    - crypto_attack
    - jwt_attack
---

# Crypto Attack Agent — 加密/编码攻击专家

> 这是 AI 自动化渗透测试的核心优势阶段。
> 人的瓶颈：编码识别慢、密钥空间构建不全、多层解码容易漏。
> AI 的优势：全量扫描、模式匹配、字典自动构建、批量尝试。

## 测试流程

```
Step 0: 收集所有加密相关数据
  ├── 从 Phase 1 Recon: JS 文件中的 CryptoJS/WebCrypto/forge 调用
  ├── 从 Phase 4 API Fuzz: 所有请求/响应体中疑似加密的字段
  └── 从 data_linkage: 泄露的 key/secret/token 值

Step 1: JS 加密函数签名提取
  ├── CryptoJS.AES.encrypt → 提取 key, iv, mode, padding
  ├── CryptoJS.DES/TripleDES → 同上
  ├── JSEncrypt/RSA → 提取 publicKey
  ├── 自定义 encode/decode → 提取完整函数体
  └── 签名函数: md5/sha/hmac → 提取 secret

Step 2: 密钥字典构建
  ├── 层级 1: JS 提取的所有字符串字面量 (最高优先级)
  ├── 层级 2: 响应体泄露的敏感字段值
  ├── 层级 3: 公共密钥字典 (AES/JWT 常见弱密钥)
  └── 层级 4: 目标特征组合 (公司名+年份+特殊字符)

Step 3: 逐体解密尝试
  ├── 对每个疑似加密体 → 用字典批量解密
  ├── 成功标志: 解密结果可读 (JSON/XML/明文)
  ├── ECB 模式检测: 相同 16 字节块 → 无需密钥即可判断
  └── 解密出的新数据 → 回写 data_linkage 的值池

Step 4: JWT 攻击 (完整流程)
  ├── Bearer 移除 / alg:none / 空签名
  ├── Secret 爆破: jwt.secrets.list + JS 关键字
  ├── kid/jku/jwk 注入
  ├── 声明篡改 (改 role/isAdmin)
  └── → 见 skills/jwt_attack/SKILL.md

Step 5: 签名算法逆向
  ├── 从 JS 提取签名函数: md5(params + timestamp + secret)
  ├── 已知 secret → 可构造任意合法请求
  └── 结合 IDOR → 批量越权

Step 6: 数据回注 (闭环)
  ├── 解密出的 JSON → 递归提取字段名+值
  ├── 新的参数名 → 回注到 API Fuzz
  ├── 新的凭据 → 回注到 JWT Attack
  └── 新的 ID → 回注到 IDOR 测试
```

## 加密体发现指令

对 API Fuzz 阶段收集的**所有响应体**执行:

```python
# 伪代码: 全量扫描
for response in all_api_responses:
    for key, value in walk_json(response):
        if looks_encrypted(value):
            record({
                "endpoint": response.endpoint,
                "field": key,
                "value": value,
                "encoding_guess": identify_encoding(value),
                "length": len(value)
            })
```

## 联动规则

```
JS 分析 → 提取 CryptoJS 调用 + 密钥字面量
    ↓
API Fuzz → 发现加密的请求/响应字段
    ↓
Crypto Attack → 解密 → 拿到明文数据
    ↓
明文中的参数名/ID/凭据 → 回注到:
    ├── API Fuzz: 新参数名 → 测试其他端点
    ├── JWT Attack: 新 token → 爆破/篡改
    ├── Exploit: 新 ID → IDOR 测试
    └── Data Linkage: 新字段值 → 值池更新 → 继续联动

永不停止: 每次解密出的新数据 → 自动回注 → 检查能否打开新攻击面
```

---

## ★ 密钥利用决策树 (Key Found → What Next?)

> 找到一个 Key 时不要只问"能不能直接登录"。
> 要问"这个 Key 是用来做什么的"——不同用途对应不同利用路径。

### 类型判断 + 利用路径

```
找到一个密钥(Key/Secret/Token)?

├── 签名Key (用于计算请求签名 x-help-sign / sign / _signature)
│   → 能做什么: 参数防篡改绕过
│   → 以前改参数后端报"签名错误"→ 现在有了Key,改参数后重新算签名就行
│   → 直接后果: SQL注入/越权/其他参数篡改不会再被签名拦住
│
├── 加密Key (AES/SM4/DES, 用于加解密请求体/响应体)
│   → 能做什么:
│     1. 解密密文: 前端发的加密请求→解开→看到明文参数
│     2. 加密Payload: 把恶意Payload(如SQL注入)加密后发出去
│        → WAF只看密文看不懂→绕过WAF
│
├── JWT Secret (HS256签名密钥)
│   → 能做什么:
│     1. 伪造任意用户JWT: 改payload里 sub/role/name 再重新签名
│     2. 用伪造JWT访问所有接口→账户接管/垂直越权
│
├── 云AK/SK (LTAI/AKIA/AKID + 对应的Secret)
│   → 能做什么: (见 §OSS/Bucket)
│     1. 验证: 调用云API get-caller-identity 确认权限
│     2. 列存储桶/下载文件/上传文件
│     3. 如果有ECS权限→命令执行 | 有RAM权限→创建后门
│
└── Session Key / Cookie加密Key
    → 能做什么:
      1. 解密Cookie→看里面存了什么(用户ID/角色/权限)
      2. 伪造Cookie→替换用户ID/角色→身份冒充
```

### 验证 Key 有效性

```
签名Key: 抓正常请求→改参数值→用Key重新算签名→发出去看是否成功
加密Key: 抓加密请求→用Key解密→看到明文=有效
JWT Secret: 拿真实JWT→换payload→重新签名→调接口看是否成功
云AK/SK: 调云API→能调通=有效
```

### 定级速查

```
签名Key + 能绕过签名校验改参数 → 高危(配合其他漏洞)
加密Key + 能解密/加密Payload → 高危(WAF绕过)
JWT Secret + 能伪造任意用户 → 严重(全量账户接管)
云AK/SK + 能访问云资源 → 高危/严重(云环境控制)
Session Key + 能伪造Cookie → 高危(身份冒充)
Key但无法验证/已过期 → INFO(报告附录A,不入正文)
```

### 实战示例

```
场景: 找到128位AES Key,用在 x-help-sign 签名上,不能伪造Session
→ 不要下结论"没用了"
→ 判断: 这是签名Key,不是加密Key
→ 操作: 抓一个正常请求→改参数(加SQL注入)→用Key重算sign
→ 后果: 签名校验不再是障碍

场景: 找到JWT Secret,但发现Session是服务器随机生成的
→ 不要下结论"不能伪造Session"
→ 判断: JWT用来做接口鉴权,Session用来保持登录态(两回事)
→ 操作: 用JWT Secret伪造admin角色的JWT→直接调管理接口
→ 后果: 垂直越权(不需要管Session)
```

## Output

- 发现的所有加密体 (端点 + 字段名 + 加密类型)
- 成功解密的字段 (明文内容 + 使用的密钥)
- 提取的密钥和 IV 清单
- 识别的加密算法和模式
- 解密出的新参数名/凭据 → 自动加入 data_linkage 值池
- JWT 攻击结果
- **密钥利用判定结果（类型 + 可行攻击路径）**
