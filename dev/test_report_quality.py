# -*- coding: utf-8 -*-
"""xs-bigdan 报告质量回归测试（正式版，随仓库维护）。

运行:  python -X utf8 dev/test_report_quality.py
覆盖:  FINDING 解析(粘行拆分/格式异常降级/截断标题)、归一化去重、评级映射、
       修复建议映射、报告渲染(降级区/附录)、早停机械门槛、infer_phase 被拒豁免。

样本说明: 以下文本来自 2026-08/09 实战日志(auth.58.com / ipgpms.lenovo.com)
          的关键行原文——保留真实形态才能测出当年踩过的坑。
"""
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from bigdan import (extract_findings, _finding_key, _finding_rank,  # noqa: E402
                    _early_stop_gate, infer_phase)
from core.report import _risk_of, _fix_for, build_report  # noqa: E402

fail = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        fail.append(name)


# ============ 样本:真实日志关键行 ============

# 1) 同一物理行粘 3 条 FINDING(agent 输出未换行)——旧正则只抓第一条且 status 被污染
GLUED_LINE = ("FINDING: 开放重定向|登录成功后任意跳转(protocol/domain/req 无白名单,潜在 javascript: 执行)|"
              "04-postlogin-open-redirect.txt|PENDING "
              "FINDING: 缺少速率限制|/dun_check_otp 动态码校验6连发无限流/锁定|05-otp-no-ratelimit.txt|PENDING "
              "FINDING: 信息泄露|SSO cookie 非HttpOnly+硬编码xxzlsid+内嵌开发网关|06-client-side-cookies-info.txt|INFO")

# 2) lenovo 实战脏行:标题被截断(带…) + 叙述句混进 file 字段——曾致 RCE 静默丢洞
LENOVO_DIRTY_LINE = ("FINDING: 明文传输|登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截… | "
                     "现在打印 FINDING 行并做最后收尾检查。 | call bash: cd /home/ubuntu/xs-bigdan/runtime/jobs && echo")

# 3) 正常 FINDING 行(合法形态)
CLEAN_LINES = (
    "FINDING: 明文传输|登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截获)|07-http-cleartext-login.txt|CONFIRMED\n"
    "FINDING: 凭据泄露|旧登录页/goto GET提交的58盾动态码明文反射进302 Location|08-legacy-goto-credential-reflection.txt|PENDING\n"
    "FINDING: 信息泄露|部署遗留.DS_Store暴露于/log58shield/目录树|09-dsstore-exposure.txt|INFO"
)

# ============ 1. FINDING 解析 ============

fs = extract_findings(GLUE_LINE if False else GLUED_LINE + "\n" + LENOVO_DIRTY_LINE + "\n" + CLEAN_LINES)
by_type = {}
for f in fs:
    by_type.setdefault(f["type"], []).append(f)

check("粘行拆出 3 条(开放重定向/缺少速率限制/信息泄露)",
      all(t in by_type for t in ("开放重定向", "缺少速率限制", "信息泄露")))
or_f = by_type["开放重定向"][0]
check("粘行拆出的开放重定向状态 PENDING(不被污染成 CONFIRMED)", or_f["status"] == "PENDING",
      f"状态: {or_f['status']}")
check("粘行拆出条目无 format_error(合法拆行)", "format_error" not in or_f)

dirty = [f for f in fs if f.get("format_error")]
check("lenovo 脏行降级为 PENDING+format_error(不静默丢弃)", len(dirty) >= 1,
      f"降级 {len(dirty)} 条")
if dirty:
    d = dirty[0]
    check("降级条目 file 置空 + status=PENDING", d["status"] == "PENDING" and not d["file"])
    check("降级条目含截断标题(可截)", "可截" in d.get("title", ""))

clean_07 = by_type.get("明文传输", [])
check("正常行 CONFIRMED 保留(file 合法)", any(f["status"] == "CONFIRMED" and f["file"] == "07-http-cleartext-login.txt" for f in clean_07))

# wms 案例修复:status 污染降级保留 file(仅状态粘行,证据文件名完好)
STATUS_POLLUTED = ("FINDING: 未授权信息泄露|未授权获取低代码应用完整配置页面schema与69个内部API端点|"
                   "02-unauth-app-config-disclosure.txt|CONFIRMED 继续探测：发码接口存在手机号枚举")
sp = extract_findings(STATUS_POLLUTED)
check("status污染:降级且保留 file(可关联证据文件)", len(sp) == 1 and sp[0]["status"] == "PENDING"
      and sp[0]["file"] == "02-unauth-app-config-disclosure.txt"
      and "状态字段异常" in sp[0].get("format_error", ""), str(sp))

# ============ 2. 归一化去重 ============

seg1 = [f for f in fs if f["file"] == "07-http-cleartext-login.txt"]
dup = {"type": "明文传输",
       "title": "登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截获)",
       "file": "99-dupe.txt", "status": "CONFIRMED"}
merged = []
for f in seg1 + [dup]:
    key = _finding_key(f)
    existing = next((x for x in merged if _finding_key(x) == key), None)
    if existing is None:
        merged.append(f)
    elif _finding_rank(f) > _finding_rank(existing):
        merged.remove(existing)
        merged.append(f)
check("截断/污染副本去重命中同一条(不新增)", len(merged) == 1, f"合并后 {len(merged)} 条")

# ============ 3. 评级/修复建议 ============

cases = [
    ("明文传输", "登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截获)", "低危"),
    ("开放重定向", "登录成功后任意跳转(protocol/domain/req 无白名单,潜在 javascript: 执行)", "中危"),
    ("缺少速率限制", "/dun_check_otp 动态码校验6连发无限流/锁定", "低危"),
    ("信息泄露", "SSO cookie 非HttpOnly+硬编码xxzlsid+内嵌开发网关", "低危"),
    ("信息泄露", "部署遗留.DS_Store暴露于/log58shield/目录树", "低危"),
    ("信息泄露", "TaskManager 参数问题导致信息泄露", "低危"),   # ak 无边界误匹配回归
    ("信息泄露", "接口泄露用户手机号与身份证", "中危"),
    ("凭据泄露", "旧登录页/goto GET提交的58盾动态码明文反射进302 Location", "低危"),
]
for typ, title, expect in cases:
    lvl, _ = _risk_of({"type": typ, "title": title})
    check(f"评级: {title[:18]}… → {expect}", lvl == expect, f"got {lvl}")

check("明文传输专属修复建议", "HSTS" in _fix_for({"type": "明文传输", "title": "无HSTS"}))
check("开放重定向专属修复建议", "白名单" in _fix_for({"type": "开放重定向", "title": "任意跳转"}))
check("无限流专属修复建议", "限流" in _fix_for({"type": "缺少速率限制", "title": "无限流"}))

# ============ 4. 报告渲染(降级区/附录/证据) ============

jobs = Path(tempfile.mkdtemp(prefix="xsbigdan-test-"))
try:
    jd = jobs / "ui-test-0001"
    ev = jd / "evidence"
    ev.mkdir(parents=True)
    (ev / "01-cleartext.txt").write_text(
        "标题: 明文传输无HSTS\nURL: http://auth.58.com/dun_check_otp\nURL2: http://auth.58.com/58shieldlogin.html\n"
        "漏洞类型: 明文传输\n## 复现\nPOST /dun_check_otp HTTP/1.1\nHost: auth.58.com\n"
        "Content-Type: application/x-www-form-urlencoded\n\nusername=admin&otp=123456\n"
        "关键响应 (无 Cookie):\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"code\":-1}\n"
        "影响: 动态码可明文截获,攻击者可在无认证下持续尝试\n",
        encoding="utf-8")
    summary = {
        "id": "ui-test-0001", "url": "https://auth.58.com/login_58dun.html",
        "started_at": "2026-09-01 02:24:04", "ended_at": "2026-09-01 02:51:02",
        "elapsed_sec": 1617, "job_timeout_sec": 3600, "seg_timeout_sec": 1800,
        "segments": [{"seg": 1, "exit_code": 0, "findings": ["明文传输"], "digest_saved": True, "log": "s1.log"}],
        "findings": [
            {"type": "明文传输", "title": "登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截获)",
             "file": "01-cleartext.txt", "status": "CONFIRMED"},
            {"type": "信息泄露", "title": "部署遗留.DS_Store暴露于/log58shield/目录树",
             "file": "03-dsstore.txt", "status": "INFO"},
            {"type": "明文传输", "title": "登录全流程可经明文HTTP完成且无HSTS(动态码/SSO cookie可截…",
             "file": "", "status": "PENDING",
             "format_error": "标题截断/超长——agent 输出格式异常,需人工复核"},
        ],
    }
    (jd / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    (jd / "digest-2.md").write_text("### RECON_DIGEST\n**疑似点**\n- 开放重定向待闭环\n", encoding="utf-8")
    out = jobs / "report-test.md"
    build_report([summary], out, jobs)
    rep = out.read_text(encoding="utf-8")
    check("降级项不进漏洞详情(无'漏洞3'章节)", "### 漏洞3" not in rep)
    check("格式异常项在总结表标⚠️降级", "⚠️ 降级" in rep)
    check("格式异常项进降级/待复核区", "### 降级/待复核" in rep and "格式异常" in rep)
    check("降级区提示证据可能已落盘", "请人工核对 evidence/ 目录" in rep)
    check("DS_Store 评级低危", "| 🟢 低危 |" in rep)
    check("证据全文内联", "01-cleartext" in rep)
    check("SRC格式:危害描述", "**危害描述**" in rep and "动态码可明文截获" in rep)
    check("SRC格式:接口地址Target", "【接口地址(Target)】" in rep and "auth.58.com/dun_check_otp" in rep)
    check("SRC格式:Payload数据包Raw", "【Payload数据包(Raw)】" in rep and "POST /dun_check_otp HTTP/1.1" in rep and "Host: auth.58.com" in rep)
    check("SRC格式:修复建议", "【修复建议】" in rep and "HSTS" in rep)
    check("SRC格式:危害描述无双重标签(影响:影响:)", "**危害描述**: 影响" not in rep)
    check("SRC格式:关键响应为响应提取(HTTP状态行,非全文)", "**关键响应**" in rep and "HTTP/1.1 200 OK" in rep
          and "明文传输无HSTS\nURL:" not in rep.replace("**关键响应**", "").split("```")[2] if "```" in rep else True)
    check("SRC格式:Target 多 URL(URL2 行也被列出)", rep.count("auth.58.com") >= 2)
    check("附录:Agent原始交接存在且位于修复建议后",
          "## 附录：Agent 原始交接" in rep and
          rep.index("## 修复建议（通用）") < rep.index("## 附录：Agent 原始交接"))
finally:
    shutil.rmtree(jobs, ignore_errors=True)

# ============ 5. 早停机械门槛 + infer_phase 豁免 ============

tmp2 = Path(tempfile.mkdtemp(prefix="xsbigdan-gate-"))
try:
    jd2 = tmp2 / "ui-test-0002"
    ev2 = jd2 / "evidence"
    ev2.mkdir(parents=True)
    ok, why = _early_stop_gate(jd2)
    check("早停门槛:无契约文件拒绝", (not ok) and "recon" in why, why)
    (ev2 / "_endpoint_params.json").write_text(json.dumps(
        {"_meta": {"analysis_completeness": 0.9},
         "endpoints": [{"path": "/a"}, {"path": "/b"}, {"path": "/c"}]}), encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("早停门槛:契约过但无指纹 拒绝", (not ok) and "指纹" in why, why)
    (ev2 / "_fingerprint.md").write_text("WAF 状态: 未检测到 WAF 特征; 技术栈: Tengine\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("早停门槛:契约+指纹但联动0 拒绝", (not ok) and "联动" in why, why)
    (ev2 / "_linkage_results.jsonl").write_text("\n".join([
        json.dumps({"endpoint": "/a", "param": "id", "value": "1", "hit": False}),
        json.dumps({"endpoint": "/b", "hit": False}),
        json.dumps({"endpoint": "/c", "hit": True}),
    ]) + "\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("早停门槛:契约+指纹+联动全达标放行", ok, why)
    (jd2 / "digest-1.md").write_text("### RECON_DIGEST\n建议结束\n", encoding="utf-8")
    (jd2 / "earlystop-deny-1.txt").write_text("deny\n", encoding="utf-8")
    phase, _ = infer_phase(jd2)
    check("infer_phase:被拒 digest 不判 report(防死循环)", phase != "report", f"phase={phase}")
    (jd2 / "earlystop-deny-1.txt").unlink()
    phase, _ = infer_phase(jd2)
    check("infer_phase:无 deny 时建议结束判 report", phase == "report", f"phase={phase}")

    # highrisk 门（mastermind 式价值确认）：零确认 + 无 WAF → 允许进 highrisk 补测敏感路径
    jd3 = tmp2 / "ui-test-0003"
    ev3 = jd3 / "evidence"
    ev3.mkdir(parents=True)
    (ev3 / "_endpoint_params.json").write_text(json.dumps(
        {"_meta": {"analysis_completeness": 0.9},
         "endpoints": [{"path": "/a"}, {"path": "/b"}, {"path": "/c"}]}), encoding="utf-8")
    (ev3 / "_linkage_results.jsonl").write_text(
        json.dumps({"endpoint": "/a", "param": "id", "value": "1", "hit": False}) + "\n", encoding="utf-8")
    (ev3 / "_fingerprint.md").write_text("WAF 状态: 未检测到 WAF 特征; 技术栈: Tengine\n", encoding="utf-8")
    phase, basis = infer_phase(jd3)
    check("highrisk门:零确认+无WAF 放行补测", phase == "highrisk", f"phase={phase} ({basis})")
    (ev3 / "_fingerprint.md").write_text("WAF 状态: 阿里云 WAF(aliws)\n", encoding="utf-8")
    phase, basis = infer_phase(jd3)
    check("highrisk门:零确认+有WAF 谨慎进deep", phase == "deep", f"phase={phase} ({basis})")
    (ev3 / "_fingerprint.md").unlink()
    phase, basis = infer_phase(jd3)
    check("指纹门:指纹缺失 回 recon 补门(不进普通测试)", phase == "recon", f"phase={phase} ({basis})")

    # bypass 正式化 + data_not_public 机械检查
    from bigdan import PHASE_READ_INDEX, PHASE_READ_INDEX_COND, write_brief  # noqa: E402
    check("Phase4正式化:linkage 读取索引注入 403-bypass",
          any("403-bypass-complete" in p for p, _ in PHASE_READ_INDEX["linkage"]))
    check("手法库注入:linkage 含 breakthrough-shortlist(防知识存在但agent不会读)",
          any("breakthrough-shortlist" in p for p, _ in PHASE_READ_INDEX["linkage"]))
    check("手法库注入:highrisk 含 advanced-techniques",
          any("advanced-techniques" in p for p, _ in PHASE_READ_INDEX["highrisk"]))
    check("读取索引不膨胀:无条件层不含 xs_auth/business_flow(已移入条件层)",
          not any("xs_auth" in p or "business_flow" in p for p, _ in PHASE_READ_INDEX["linkage"]))
    check("条件层登记:has_account 条目仍在(xs_auth/business_flow)",
          any(c == "has_account" and "xs_auth" in p_ for p_, _, c in PHASE_READ_INDEX_COND["linkage"])
          and any(c == "has_account" and "business_flow" in p_ for p_, _, c in PHASE_READ_INDEX_COND["linkage"]))
    import bigdan as bigdan_mod  # noqa: E402
    check("条件层登记:特征触发条目判定函数已实现(php_stack/subdomains)",
          {"has_account", "php_stack", "subdomains"} >= {c for _, _, c in PHASE_READ_INDEX_COND["linkage"]}
          and hasattr(bigdan_mod, "_php_stack_signal") and hasattr(bigdan_mod, "_subdomains_signal"))
    from core.report import _triage_check  # noqa: E402
    t_ok = _triage_check({"type": "信息泄露"},
                         "URL: http://x.com/api\n影响: 可读取用户手机号(前端已展示该数据)\n")
    check("triage data_not_public:证据自述前端已展示→降级原因",
          any("data_not_public" in r for r in t_ok), str(t_ok))

    # 条件注入真实联动:write_brief 无账号时不注入 xs_auth,有 cookies.txt 时注入
    jd4 = tmp2 / "ui-test-0004"
    ev4 = jd4 / "evidence"
    ev4.mkdir(parents=True)
    (ev4 / "_endpoint_params.json").write_text(json.dumps(
        {"_meta": {"analysis_completeness": 0.9},
         "endpoints": [{"path": "/a"}, {"path": "/b"}, {"path": "/c"}]}), encoding="utf-8")
    (ev4 / "_fingerprint.md").write_text("WAF 状态: 未检测到 WAF 特征\n", encoding="utf-8")
    target4 = {"id": "ui-test-0004", "url": "https://test.example.com", "note": ""}

    def brief_read_index(text):
        """截取 BRIEF 读取索引段落(工具清单里的 xs_auth 字样不算)。"""
        m = re.search(r"## 读取索引(.*?)(?=\n## |\Z)", text, re.S)
        return m.group(1) if m else ""

    write_brief(jd4, target4, ["test.example.com"], segs=3, seg_idx=1)
    brief4 = brief_read_index((jd4 / "BRIEF.md").read_text(encoding="utf-8"))
    check("条件注入:无账号时读取索引不含 xs_auth/business_flow",
          "xs_auth" not in brief4 and "business_flow" not in brief4)
    (jd4 / "cookies.txt").write_text("session=abc\n", encoding="utf-8")
    write_brief(jd4, target4, ["test.example.com"], segs=3, seg_idx=1)
    brief4b = brief_read_index((jd4 / "BRIEF.md").read_text(encoding="utf-8"))
    check("条件注入:有 cookies.txt 时读取索引注入 xs_auth+business_flow",
          "xs_auth" in brief4b and "business_flow" in brief4b)

    # 登录口末位测试（无账号场景结束前必测——早停门槛机械检查）
    from bigdan import _has_login_surface, _login_probe_done  # noqa: E402
    check("登录口判定:无登录类端点=False", not _has_login_surface(jd2))
    ep2 = json.loads((ev2 / "_endpoint_params.json").read_text(encoding="utf-8"))
    ep2["endpoints"].append({"path": "/login", "method": "POST"})
    (ev2 / "_endpoint_params.json").write_text(json.dumps(ep2), encoding="utf-8")
    check("登录口判定:含 /login 端点=True", _has_login_surface(jd2))
    check("登录口判定:未测=False", not _login_probe_done(jd2))
    # /login 端点写 skipped 不可达记录 → 端点覆盖全过,由登录口末位测试检查拦截
    with open(ev2 / "_linkage_results.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"endpoint": "/login", "skipped": "弱口令已测,需真实账号"}) + "\n")
    (jd2 / "digest-2.md").write_text("### RECON_DIGEST\n建议结束\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("末位测试门:无账号+有登录口+未测 拒绝早停", (not ok) and "登录口" in why, why)
    (ev2 / "_login_probe.txt").write_text("弱口令|无命中|false\n轰炸|限流正常|false\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("末位测试门:落盘 _login_probe.txt 后放行", ok, why)
    (ev2 / "_login_probe.txt").unlink()
    (jd2 / "cookies.txt").write_text("session=x\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd2)
    check("末位测试门:有 cookies.txt 时不要求末位测试", ok, why)

    # 凭证门机械门槛（过早 BLOCKED 打回——无认证面未测完不许要账号）
    from bigdan import _credential_gate_ok, BLOCKED_RE  # noqa: E402
    jd5 = tmp2 / "ui-test-0005"
    (jd5 / "evidence").mkdir(parents=True)
    check("凭证门:无契约产物 False(不许 BLOCKED 要账号)", not _credential_gate_ok(jd5))
    (ev3 / "_fingerprint.md").write_text("WAF 状态: 未检测到 WAF 特征\n", encoding="utf-8")  # 前序测试删过,重建
    check("凭证门:契约+指纹+联动达标 True(可 BLOCKED)",
          _credential_gate_ok(jd3), "jd3 产物齐全")
    check("BLOCKED_RE 识别 AUTH_CREDENTIALS",
          bool(BLOCKED_RE.search("### BLOCKED\ntype: AUTH_CREDENTIALS\n卡点: 需账号")))

    # 门控质量抽查（存在性→内容/结构完整性,防刷产物骗过门）
    from bigdan import _fingerprint_ok, _linkage_consumed  # noqa: E402
    jd6 = tmp2 / "ui-test-0006"
    ev6 = jd6 / "evidence"
    ev6.mkdir(parents=True)
    (ev6 / "_fingerprint.md").write_text("ok\n", encoding="utf-8")
    check("质量抽查:空壳指纹(仅'ok')不过门", not _fingerprint_ok(jd6))
    (ev6 / "_fingerprint.md").write_text("WAF 状态: 无; 技术栈: Tengine\n", encoding="utf-8")
    check("质量抽查:含指纹特征词过门", _fingerprint_ok(jd6))
    (ev6 / "_linkage_results.jsonl").write_text(json.dumps({"hit": False}) + "\n", encoding="utf-8")
    check("质量抽查:空壳联动记录(无endpoint)不计消费", _linkage_consumed(jd6) == 0)
    (ev6 / "_linkage_results.jsonl").write_text(
        json.dumps({"endpoint": "/api/x", "hit": False}) + "\n", encoding="utf-8")
    check("质量抽查:完整联动记录计消费", _linkage_consumed(jd6) == 1)
    (ev6 / "_login_probe.txt").write_text("测试\n", encoding="utf-8")
    check("质量抽查:空壳 _login_probe(无协议测试项)不过", not _login_probe_done(jd6))
    (ev6 / "_login_probe.txt").write_text("弱口令|无命中|false\n", encoding="utf-8")
    check("质量抽查:含协议测试项过门", _login_probe_done(jd6))

    # 登录口正则收窄:裸 auth 不算登录口(纯 API 认证端点误伤修复)
    ep6 = {"_meta": {"analysis_completeness": 0.9},
           "endpoints": [{"path": "/api/auth/token"}, {"path": "/authorize"},
                         {"path": "/b"}, {"path": "/c"}]}
    (ev6 / "_endpoint_params.json").write_text(json.dumps(ep6), encoding="utf-8")
    check("登录口收窄:/api/auth/token+authorize 不算登录口", not _has_login_surface(jd6))
    ep6["endpoints"].append({"path": "/login"})
    (ev6 / "_endpoint_params.json").write_text(json.dumps(ep6), encoding="utf-8")
    check("登录口收窄:含 /login 仍算登录口", _has_login_surface(jd6))

    # 认证墙场景:真全登录墙目标把 401 测试结果记进联动文件 → 凭证门放行(不浪费 2 段)
    (ev6 / "_linkage_results.jsonl").write_text("\n".join([
        json.dumps({"endpoint": "/api/a", "hit": False, "note": "401 需登录"}),
        json.dumps({"endpoint": "/api/b", "hit": False, "note": "403 认证"}),
    ]) + "\n", encoding="utf-8")
    check("认证墙场景:401 测试结果计入有效联动 → 凭证门放行", _credential_gate_ok(jd6))

    # 修复3:被拒原因醒目块(拼进 prompt 最前部,防 agent 忽略事件流再被拒白烧预算)
    from bigdan import compose_context  # noqa: E402
    ctx = compose_context(jd3)
    check("被拒醒目块:无 deny 文件时不出现", "上段被机械门槛拒绝" not in ctx)
    (jd3 / "earlystop-deny-2.txt").write_text("早停被拒(段2):联动消费=0(参数面疑似未测)\n", encoding="utf-8")
    ctx = compose_context(jd3)
    check("被拒醒目块:deny 存在时拼进 prompt 最前部且含原因",
          ctx.startswith("### ⚠️ 上段被机械门槛拒绝") and "联动消费=0" in ctx)

    # 端点覆盖完整性（lingan 案例修复:上传等功能面未测不许收工）
    from bigdan import _endpoint_coverage  # noqa: E402
    jd7 = tmp2 / "ui-test-0007"
    ev7 = jd7 / "evidence"
    ev7.mkdir(parents=True)
    ep7 = {"_meta": {"analysis_completeness": 0.9},
           "endpoints": [{"path": "/api/upload"}, {"path": "/api/avatar"},
                         {"path": "/api/list"}, {"path": "/api/export"}]}
    (ev7 / "_endpoint_params.json").write_text(json.dumps(ep7), encoding="utf-8")
    (ev7 / "_fingerprint.md").write_text("WAF 状态: 无; 技术栈: Tengine\n", encoding="utf-8")
    (ev7 / "_linkage_results.jsonl").write_text("\n".join([
        json.dumps({"endpoint": "/api/list", "hit": False}),
        json.dumps({"endpoint": "/api/export", "hit": True}),
    ]) + "\n", encoding="utf-8")
    cov, tot, unc = _endpoint_coverage(jd7)
    check("端点覆盖:2/4 且 upload 未覆盖", cov == 2 and tot == 4 and "/api/upload" in unc,
          f"覆盖 {cov}/{tot} 未覆盖={unc}")
    ok, why = _early_stop_gate(jd7)
    check("端点覆盖:未测 upload 拒绝早停(原因列出端点)",
          (not ok) and "端点覆盖不完整" in why and "/api/upload" in why, why)
    (ev7 / "_linkage_results.jsonl").write_text("\n".join([
        json.dumps({"endpoint": "/api/list", "hit": False}),
        json.dumps({"endpoint": "/api/export", "hit": True}),
        json.dumps({"endpoint": "/api/upload", "skipped": "需素材账号"}),
        json.dumps({"endpoint": "/api/avatar", "skipped": "编辑器不可达"}),
    ]) + "\n", encoding="utf-8")
    ok, why = _early_stop_gate(jd7)
    check("端点覆盖:写 skipped 不可达原因后放行", ok, why)
finally:
    shutil.rmtree(tmp2, ignore_errors=True)

print("\n" + ("=" * 24 + " 全部通过 " + "=" * 24) if not fail else f"\n失败 {len(fail)} 项: {fail}")
sys.exit(1 if fail else 0)
