# Response Chaining: The Highest-ROI Bug Bounty Technique

> Activated at Phase 3-6. After EVERY API response, extract fields and inject them into subsequent requests.
> Most IDOR/priv-esc findings come from chaining, not from blind single-request testing.

---

## Core Principle

```
API Response → Extract {IDs, tokens, keys, hashes, status fields}
                ↓
              Match to known endpoints
                ↓
              Inject into requests → IDOR / Priv Esc / Cross-tenant access
```

**Why this works**: Most APIs are designed as a graph, not isolated endpoints. `GET /api/user/info` returns `userId` which is then used by `GET /api/user/{userId}/orders`. The developer assumes only the rightful user reaches step 2 — but if `userId` is user-controllable, chaining breaks the assumption.

---

## Step 1: Automatic Extraction (After EVERY Response)

From JSON response, extract all fields that match:
```
ID patterns:    *id, *Id, *ID, *uuid, *UUID
Token patterns: *token, *Token, *access_token, *refresh_token
Key patterns:   *key, *Key, *secret, *Secret, *apiKey
Hash patterns:  *hash, *md5, *sha, *sign, *signature
User patterns:  userId, username, email, phone, accountId
Org patterns:   orgId, tenantId, companyId, teamId
Resource:       orderId, fileId, docId, projectId
```

**Extract from ALL locations**:
- Response body (JSON fields at any nesting level)
- Response headers (Authorization, X-Auth-Token, Session-Id)
- Set-Cookie headers (new session or auth cookies)
- Redirect URL query params (tokens/IDs in 302 Location header)

---

## Step 2: Match to Known Endpoints

Cross-reference extracted fields with your endpoint inventory:

| Extracted Value | Match to Endpoint | Test |
|-----------------|------------------|-------|
| `userId: 10086` | `GET /api/user/{id}` | Change to 10087 → IDOR |
| `orderId: 99887` | `GET /api/order/{id}` | Change to 99888 → IDOR |
| `token: eyJ...` | Any `Authorization` header | Use for all requests → vertical priv esc |
| `orgId: 42` | `GET /api/org/{id}/members` | Change to 43 → cross-org access |
| `fileId: abc123` | `GET /api/file/{id}/download` | Change to abc124 → file leak |
| `projectId: x9` | `POST /api/project/{id}/delete` | Delete other's project |
| `accessToken: ...` | Any API call | Higher-privilege token than current session? |
| `role: "user"` | `POST /api/user/update` | Mass-assignment: change role to "admin" |

---

## Step 3: Chain Examples

### Chain 1: Profile → Org → Cross-Tenant
```
GET /api/user/profile (as User A)
  → {userId: 1001, orgId: 42, token: "eyJ..."}

1. GET /api/user/1002 → can User A see User B? (IDOR)
2. GET /api/org/42/members → returns all org members (info leak)
3. GET /api/org/99/members → cross-org access? (tenant isolation)
4. Use token from response → is it higher-privilege than login token?
```

### Chain 2: Order List → Order Detail → Delete (TEST DATA ONLY)
```
GET /api/order/list → [{orderId: 1001, ...}, {orderId: 1002, ...}]

SRC SAFETY: Create your OWN test orders first (Account A & Account B)
1. GET /api/order/{B's test order ID} → IDOR: see order not in User A's list
2. OPTIONS /api/order/{B's test order ID} → Allow: DELETE → confirmed
3. DELETE /api/order/{A's OWN test order} → verify deletion works
4. Screenshot OPTIONS response → proves DELETE capability without deleting real data

NEVER: DELETE /api/order/{real user's order} / POST refund on real orders
```

### Chain 3: JWT Decode → Forge → Full Access
```
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIifQ...

1. Decode payload: {sub: "1001", role: "user"}
2. Brute force key → hashcat -m 16500 → key found: "secret1"
3. Forge: {sub: "1", role: "admin"} signed with "secret1"
4. GET /api/admin/users → full user list as admin
```

### Chain 4: File Upload → Path Leak → SSRF
```
POST /api/upload → {fileId: "abc", fileUrl: "https://cdn.target.com/files/abc.pdf"}

1. Upload YOUR OWN harmless test file → get fileId
2. GET /api/file/{your fileId} → verify access → IDOR check with other fileIds
3. POST /api/proxy?url={collaborator-url} → SSRF via file URL → DNS hit → confirmed
4. SRC: Cloud metadata (169.254.169.254) → authorized pentest only → use collaborator instead
```

---

## Step 4: Automated Response Mining Checklist

After every response, check:
- [ ] Any numeric ID that increments → test N+1, N-1, 0, -1
- [ ] Any UUID/GUID → collect for cross-referencing with other endpoints
- [ ] Any token/key → test if it works for other endpoints/other users
- [ ] Any role/status field → test if you can escalate/change via mass assignment
- [ ] Any URL/file path → test SSRF / path traversal / IDOR
- [ ] Any email/phone → test if exposed and searchable
- [ ] Response contains more fields than the UI displays → hidden data leakage

---

## Step 5: Common Chaining Pitfalls

| Mistake | Fix |
|---------|-----|
| Only testing the first response | Mine EVERY response, even error responses (they may still contain useful IDs) |
| Forgetting about response headers | Check Authorization, Set-Cookie, X-Request-Id, X-Session-Id |
| Not re-testing after role change | If you escalate to admin, re-run ALL previous tests as admin |
| Ignoring same-endpoint different methods | GET returns data, POST/PUT/DELETE on same endpoint may modify it |

---

*End of response-chaining.md*
