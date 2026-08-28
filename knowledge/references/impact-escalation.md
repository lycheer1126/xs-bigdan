# Impact Escalation: 5 Dimensions

> Loaded at Phase 6. Purpose: Maximize demonstrated impact without increasing test destructiveness.
> Rule: Prove with minimal data, describe the maximum possible consequence.

---

## Red Lines (DO NOT)

- Do NOT upload illegal content, harass with verification codes, or batch-download real private data
- Do NOT overwrite/destroy other users' resources for proof
- Prove impact with "minimal data, minimal impact" principle

---

## The 5 Dimensions (From Technical Finding → Business Impact)

### 1) Affected Object
- **Who**: Single user / Multiple users / All users / Cross-tenant
- **What**: Funds / Privileges / Rights / Files / Privacy / Operations data

```
Ask: "If exploited against ALL users, how many records/accounts are affected?"
```

### 2) Scalability
- **Automation potential**: API-based / Stable reproduction / No human interaction required
- **Batch potential**: Enumerable IDs / Listable resources / No rate limiting

```
Ask: "Can a script run this unattended against every user? Would rate limiting stop it?"
```

### 3) Sustainability
- **Reusability**: Token reusable / Link permanent / No revocation mechanism
- **Stealth**: No logging / No alerting / Appears as normal business request

```
Ask: "Once found, does this backdoor stay open? Does the victim know they're compromised?"
```

### 4) Combination Path
- **Not imaginary**: Use "confirmed chain evidence" to show what subsequent compromise is possible
- **State preconditions**: What additional access/information is needed for the next step

```
Ask: "With this vuln as stepping stone, what's the NEXT thing an attacker can reach?"
```

### 5) Business Context
- **Monetary impact**: Direct financial loss / Fraud / Inventory manipulation
- **Compliance impact**: GDPR / data breach notification / regulatory fines
- **Reputation impact**: Brand damage / User trust / Partner relationships

```
Ask: "If this gets exploited and makes news, what's the headline?"
```

---

## Per-Vuln-Type Escalation Templates

### A) IDOR / Unauthorized Access
- **Escalation**: From "I can see one field" → "I can traverse ALL resource IDs → multi-user impact"
- **Evidence**: Compare 2 accounts, same endpoint, different resource IDs → different owners' data returned
- **Keywords**: Cross-user data access, cross-tenant, sensitive info aggregation, automatable at scale
- **List endpoint rule**: If ONE request returns ALL users without traversal (e.g., GET /api/getuserlist → all users) → start at 高危, upgrade to 严重 if data includes PII (phone/ID card/address)
- **Distinction**: List endpoint (full dump in 1 request) >> single-resource traversal (need iteration). List endpoints are high-severity by nature, regardless of enumability.

### B) Payment / Pricing
- **Escalation**: From "price is modifiable" → "direct financial loss + automatable"
- **Evidence**: Show order amount vs. actual payment/settlement mismatch
- **Keywords**: Financial loss, fraud, reconciliation anomaly, rule bypass, unauthorized benefit

### C) SMS / Account Recovery
- **Escalation**: From "verification code issue" → "account security chain failure"
- **Evidence**: Emphasize 4-element binding missing (account/receiver/credential/step) → exploitable cross-account
- **Keywords**: Account takeover risk, brute force cost reduction, risk control bypass, batchable

### D) File Upload / Overwrite
- **Escalation**: From "can upload a file" → "content hosting + phishing + resource abuse"
- **Evidence**: Upload harmless proof file, demonstrate it's publicly accessible / downloadable by others
- **Keywords**: Brand risk, phishing hosting, malware distribution risk, storage abuse, content audit pressure

### E) Information Leak
- **Escalation**: From "extra fields returned" → "precondition for follow-on attacks"
- **Evidence**: Show only redacted samples and field types, NOT complete private data
- **Keywords**: Social engineering, account takeover prerequisite, IDOR prerequisite, internal asset exposure

### F) Race Condition
- **Escalation**: From "can trigger once" → "quota/inventory/count control failure"
- **Evidence**: Prove "duplicate effect" within controllable/reversible range; do NOT pursue maximum iteration count
- **Keywords**: Duplicate issuance, overselling, risk control failure, operational data pollution

### G) OAuth / SSO / Third-Party Login
- **Escalation**: From "callback issue" → "zero-interaction login / passive session leak → account risk"
- **Evidence**: Reproduce with own account → prove "visit link → logged in without confirmation/alert"
- **Keywords**: Account takeover risk, session leakage, external spread risk, no intent verification, hard to detect

---

## Report Sentence Templates (Reusable)

- "The vulnerability is stably reproducible via API request, does not require user interaction, and is automatable at scale."
- "This breaks the server-side consistency check (ownership/amount/state machine), allowing business rules to be bypassed with direct losses."
- "During reproduction, only minimal samples and redacted data were used to prove the vulnerability. No batch extraction or destructive operations were performed."

---

*End of impact-escalation.md*
