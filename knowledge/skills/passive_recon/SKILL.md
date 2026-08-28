---
name: passive-recon
description: >
  Passive reconnaissance: subdomain enumeration via crt.sh/DNS history,
  Shodan/Censys IP intelligence, favicon hash matching for tech stack,
  Wayback Machine URL history, WHOIS data. All free, no target contact.
metadata:
  tags: "passive,recon,crt.sh,shodan,favicon,wayback,subdomain"
  category: "offensive-security"
---

# Passive Recon — 被动信息收集

## Core Principle

不向目标发任何请求，纯被动收集。速度快（秒级），无痕迹。

## 1. Subdomain Discovery

### crt.sh (Certificate Transparency)
```bash
# 查询证书透明度日志
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | \
  jq -r '.[].name_value' | sort -u | tee subdomains_crtsh.txt

# 也支持组织名搜索
curl -s "https://crt.sh/?q=${ORG_NAME}&output=json"
```

### DNS Dumpster / SecurityTrails (可选)
```bash
# SecurityTrails API (免费 tier 可用)
curl -s "https://api.securitytrails.com/v1/domain/${TARGET}/subdomains" \
  -H "apikey: $ST_API_KEY"
```

### 快速价值判断
```bash
# 挑选高价值子域名
grep -E 'admin|api|dev|test|staging|internal|vpn|jenkins|git|wiki' subdomains.txt
grep -E 'oss|s3|bucket|cdn|static' subdomains.txt  # 云资产
```

## 2. Favicon Hash Matching

相同的 favicon → 相同的技术栈。即使改了 Server header 也能识别。

```python
import mmh3, requests, codecs

def favicon_hash(url):
    resp = requests.get(f"{url}/favicon.ico")
    favicon_b64 = codecs.encode(resp.content, 'base64')
    return mmh3.hash(favicon_b64)

# 与已知指纹库比对
# shodan.io 的 favicon hash 数据库
# 例: -1273094408 → Apache Tomcat
#      -306746971  → Spring Boot
```

## 3. Wayback Machine URL History

```bash
# 获取目标历史上所有 URL
curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey" | \
  tee wayback_urls.txt

# 提取 JS 文件 (可能包含旧版本、未删除的测试端点)
grep '\.js$' wayback_urls.txt > wayback_js.txt

# 提取 API 路径
grep -E '/api/|/v[0-9]/|/graphql' wayback_urls.txt > wayback_apis.txt

# 提取敏感路径
grep -E 'admin|config|backup|test|debug|\.env|\.yml|\.json' wayback_urls.txt
```

## 4. Shodan / Censys (IP Intelligence)

```bash
# Shodan CLI
shodan domain $TARGET            # → IPs + 开放端口
shodan host $IP                  # → 服务版本、SSL 证书

# 无需认证的基础搜索
# 直接在浏览器搜: shodan.io → "org:Company Name"
```

## 5. Google Dork Quick Hits

```
site:target.com inurl:admin
site:target.com ext:json
site:target.com ext:log
site:target.com intitle:"index of"
site:target.com "password" filetype:txt
site:target.com "BEGIN RSA PRIVATE KEY"
site:github.com "target.com" "password"
```

## 6. 输出整合

把被动收集的结果注入 Recon agent:
```
subdomains_crtsh.txt  → 加入子域名扫列表
wayback_apis.txt      → 加入 API 端点清单
wayback_js.txt        → 下载历史 JS 版本
favicon hash          → 确认技术栈指纹
Shodan IP/端口        → 加入端口扫描清单
Google dork hits      → 加入源码泄露搜索
```
