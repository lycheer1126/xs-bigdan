# §19 OSS/Bucket Analysis — Full Attack Chain
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
