# SRC 合规规则与操作边界

> 从 SKILL.md §0.2 迁出。每次 Phase 0 加载，任何操作前检查。

---

## 一、三种场景

| Scenario | Allowed | Forbidden |
|----------|---------|-----------|
| **SRC/Bug Bounty** | 无害化漏洞验证：≤5条越权数据证明 / dnslog / collaborator / whoami / ping / sleep / test file。**越权查看他人数据=漏洞证明（不是违规）** | Webshell、批量数据导出（>5条）、删改真实数据、内网扫描、破坏性操作、SQLmap |
| **Authorized Pentest** | Full exploitation (with written consent) | Anything outside scope document |
| **CTF/Target Range** | No restrictions | — |

---

## 二、操作分级（任何操作前对照）

```
TIER 1 — ALWAYS OK (no question needed, SRC standard operations):
  • whoami / id / hostname / ping collaborator / dnslog callback / sleep 3
  • Write harmless test.txt / test.jsp (text-only content, prove extension bypass)
  • Read /etc/passwd (on own test account)
  • curl http://collaborator-url (SSRF verification via OOB callback)
  • SSRF: use SRC-provided test target first (e.g., 京东: ssrf.jd.local)
  • Payment testing: 0.01/0.1 test orders with own 2 accounts ONLY → cancel/refund after verification
  • IDOR cross-account: Account A reads Account B (both self-registered accounts)
  • Unauthenticated endpoint probe: GET /api/getuserlist with no token → check if data returned
  • IDOR proof with real data: ≤5 real user records (京东/讯飞规则) — viewing others' data IS the finding
  • SQL injection: prove read capability (1-2 rows), NEVER dump tables or read in bulk

TIER 2 — ASK USER FIRST:
  • Read files from unauthorized locations (/etc/shadow, app config)
  • Single internal IP probe via SSRF (127.0.0.1:80)
  • SSRF: if SRC has no test target → ask user before probing internal network
  • Upload .jsp/.php with "SRC test" text → verify accessible → DELETE
  • Modify own test account data (mark with "安全测试" in fields)
  • Extract 5-15 real records if needed for impact demonstration (beyond initial 5-record proof)

TIER 3 — REQUIRES WRITTEN AUTHORIZATION:
  • Write webshell with executable code / reverse shell / bind shell / C2
  • Mass data extraction / batch user data traversal (beyond 5-record proof)
  • Internal network scanning / lateral movement / cloud metadata (169.254.169.254)
  • Password changes / data deletion / service disruption on production
  • SQLmap or any automated injection scanner on production
```

---

## 三、SRC 禁止 vs 合规替代

**核心区分**: "越权查看他人数据" = 漏洞证明 ✅ / "批量拉取全量数据" = 违规 ❌

| Forbidden Action | SRC-Compliant Alternative |
|-----------------|--------------------------|
| 批量拉取全量用户数据（>5条） | IDOR: ≤5 real records for proof (京东/讯飞规则) |
| 删/改其他用户的真实数据 | 仅用自己注册的 2 个测试账号互相操作验证 |
| SQLmap 或自动化扫描器在生产环境 | 手工注入测试: `id=3-1`, `id=1'`, `SLEEP(2)` — 证明注入点即可 |
| SQL注入爆表（dump table） | 证明可读数据库（1-2行输出），不dump全表 |
| SSRF 扫描内网 | SRC提供靶场地址优先（京东: ssrf.jd.local）；无靶场→问用户 |
| Upload `.jsp/.php` with executable code | Upload `.jsp/.php` with "SRC test — YYYY-MM-DD" text → verify accessible → DELETE |
| Reverse shell / C2 / bind shell | `ping -c 3 collaborator.dnslog.cn` → DNS hit → RCE confirmed → STOP |
| Write webshell / executable to production | Write harmless test.jsp → verify write capability → DELETE immediately |
| Payment fraud / real money manipulation | 0.01 test orders with own 2 accounts → verify price tampering → cancel orders |
| DoS / DDoS / service disruption | Prove theory only (e.g., large param causes slow response → note, don't sustain) |
| Test beyond scope / unassigned assets | Contact SRC admin to confirm asset ownership before testing |
| **声明 "未访问真实用户数据"** | ❌ **这是错误声明** — 越权查看他人数据本身就是漏洞证明。正确的声明是 "已控制数据获取量 ≤5条" |

---

## 四、SRC 合规声明模板（报告第七节用）

```
☑ 1. 本次测试严格遵守[平台名称]安全响应中心(SRC)测试规范。
☑ 2. 所有漏洞验证均使用无害化测试方法（curl/Burp/浏览器手动测试），
     未使用SQLmap、Webshell、批量扫描器等自动化攻击工具。
☑ 3. 越权/IDOR测试已严格控制数据获取量：≤5条记录作为漏洞证明，
     未批量拉取全量数据（京东/讯飞规则）。
☑ 4. SQL注入测试仅通过手工payload证明注入点存在（如 SLEEP(2) / dnslog回调），
     未使用SQLmap，未dump数据表。
☑ 5. SSRF测试仅使用{SRC靶场地址 / dnslog / collaborator}验证OOB回调，
     未探测内网。
☑ 6. 未执行删除、修改、支付等破坏性操作。
☑ 7. 文件上传测试：仅上传含"SRC安全测试"文本的测试文件，
     验证后已立即删除。
☑ 8. CSRF/XSS测试仅通过dnslog/console.log验证行为存在性，
     未对线上用户造成实际影响。
☑ 9. 测试过程中未使用DDoS、批量扫描等影响服务可用性的手段。
☑ 10. 测试账号: [仅写账号名/ID，不写密码]
```

**注意**: 第3条是 SRC 测试的核心 — 越权查看其他用户数据=漏洞证明，不是违规。
        违规的是"批量拉取"（>5条）和"删改数据"。"未访问真实用户数据"是错误声明。
