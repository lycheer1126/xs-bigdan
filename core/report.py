#!/usr/bin/env python3
"""xs-bigdan 报告生成：汇总各目标 summary.json + evidence 文件 → 一份易读的 md 报告。

模板对齐人工渗透报告风格：目标信息 → 漏洞总结表 → 每个漏洞详情
（风险等级/类型/描述/复现/影响/修复建议）→ 未闭环线索 → 证据清单。

防误导兜底：findings 为空但 evidence/ 存在非 `_` 前缀证据文件时（agent 写了
证据却没按 FINDING 行登记），报告列出「证据线索」并要求人工复核，绝不写
「未确认到可利用漏洞」掩盖已落盘的证据。
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

# ---------------------------------------------------------------- 风险等级映射（type 关键词 → 等级）

# 注意顺序：具体规则在前，宽泛词（信息泄露/泄露）在后，避免 .DS_Store/cookie 属性被误升中危。
_RISK_RULES: List[Tuple[Tuple[str, ...], Tuple[str, str]]] = [
    (("rce", "命令执行", "代码执行", "getshell", "webshell", "反序列化", "s2-045", "s2-057", "cve-2017"), ("严重", "🔴")),
    (("sql", "注入", "ssrf", "任意文件", "文件上传", "文件读取", "文件写入", "ssti", "xxe", "命令"), ("高危", "🟠")),
    (("xss", "越权", "idor", "未授权", "csrf", "弱口令", "接管", "任意用户", "开放重定向", "open redirect"), ("中危", "🟡")),
    (("明文传输", "明文", "无hsts", "传输层", "hsts"), ("低危", "🟢")),
    (("ds_store", ".ds_store", "部署遗留", "上传痕迹", "部署痕迹"), ("低危", "🟢")),
    (("cookie", "httponly", "samesite", "会话属性"), ("低危", "🟢")),
    (("无限流", "限流", "速率限制", "缺少速率"), ("低危", "🟢")),
    (("重定向",), ("低危", "🟢")),
    (("信息泄露", "泄露", "枚举", "暴露", "缺失", "版本", "目录列表", "安全头", "用户名"), ("低危", "🟢")),
]
_DEFAULT_RISK = ("待评估", "⚪")

# 信息泄露类升级特例：标题含高价值敏感词才升中危（无实际泄露内容的加固项保持低危）
_HIGH_VALUE_LEAK_RE = re.compile(r"凭证|手机号|身份证|密钥|源码|口令|密码|token|订单|用户数据|\bak\b|\bsk\b|access[-_]?key|secret[-_]?key")


def _risk_of(finding: dict) -> Tuple[str, str]:
    """由漏洞 type/title 关键词映射风险等级（尽力而为，人工复核为准）。"""
    text = (f"{finding.get('type') or ''} {finding.get('title') or ''}").lower()
    for keywords, level in _RISK_RULES:
        for kw in keywords:
            if kw.lower() in text:
                if level[0] == "低危" and "信息泄露" in text and _HIGH_VALUE_LEAK_RE.search(text):
                    return ("中危", "🟡")
                return level
    return _DEFAULT_RISK


# ---------------------------------------------------------------- 修复建议（按类型通用，不绑定具体系统）

_FIX_BY_TYPE: List[Tuple[Tuple[str, ...], str]] = [
    (("rce", "命令执行", "代码执行", "反序列化", "s2-", "cve-2017", "ssti", "xxe"),
     "升级组件到已修复版本并移除调试入口；严格校验输入与 Content-Type/编码，禁用危险函数/反序列化入口；部署 RASP/WAF 并配置出网白名单。"),
    (("sql",), "输入校验 + 参数化查询/预编译语句，禁止拼接 SQL；最小化数据库账号权限，关闭错误详情回显。"),
    (("ssrf",), "服务端请求 URL 做协议/内网地址/IP 段白名单校验，禁止直连内网；响应做内容过滤并限时重定向。"),
    (("上传", "文件上传"), "上传目录禁止脚本执行权限；扩展名+Content-Type+内容三重校验；文件重命名并隔离存储。"),
    (("越权", "idor"), "所有资源操作强制校验数据归属（owner/租户维度），禁止仅依赖前端隐藏；越权验证用双账号差分。"),
    (("未授权",), "接口侧强制鉴权与登录态校验，敏感接口增加访问控制与审计日志。"),
    (("凭据泄露", "cwe-598", "动态码明文反射", "凭据进"), "敏感凭据（动态码/口令/token）禁止经 GET 参数/URL 传输，改用 POST body；网关中间件反射参数进 Location/重定向目标前做白名单过滤。"),
    (("明文传输", "明文", "无hsts", "传输层", "hsts"), "强制全站 HTTPS 并配置 HSTS（Strict-Transport-Security）；HTTP 请求 301/308 跳转 HTTPS；登录/动态码接口禁止明文回退；会话 cookie 加 Secure 属性。"),
    (("开放重定向", "open redirect"), "跳转目标做协议+域名白名单校验，禁止拼接用户可控的 protocol/domain/req；登录成功跳转改为服务端会话内下发固定目标。"),
    (("无限流", "限流", "速率限制", "缺少速率"), "认证/校验类接口增加服务端限流（按账号+IP）、失败锁定与图形验证码；动态码增加时间窗重放校验与尝试次数上限。"),
    (("ds_store", ".ds_store", "部署遗留", "上传痕迹", "部署痕迹"), "清理 Web 根目录部署元数据文件（.DS_Store 等），发布流程增加静态资产清理步骤；静态目录禁止目录列表。"),
    (("cookie", "httponly", "samesite", "会话属性"), "敏感会话 cookie 改由服务端 Set-Cookie 下发，并设置 HttpOnly/Secure/SameSite 属性；前端 js-cookie 写入改为仅存非敏感值。"),
    (("信息泄露", "泄露", "枚举", "暴露", "版本"), "移除调试信息/详细错误页/冗余响应头，敏感数据脱敏，收紧默认访问配置。"),
    (("xss",), "输出编码 + CSP 头，富文本场景白名单过滤；Cookie 加 HttpOnly/Secure/SameSite。"),
    (("弱口令", "爆破"), "强制强口令策略 + 失败锁定/延迟 + 验证码，禁止默认凭据。"),
]
_DEFAULT_FIX = "接口侧强制鉴权与数据归属校验；输入校验与输出编码；移除调试信息；按上述风险项针对性加固并复测回归。"


def _fix_for(finding: dict) -> str:
    text = f"{finding.get('type') or ''} {finding.get('title') or ''}".lower()
    for keywords, fix in _FIX_BY_TYPE:
        for kw in keywords:
            if kw in text:
                return fix
    return _DEFAULT_FIX


# ---------------------------------------------------------------- 证据读取

def _load_summary(job_dir: Path) -> dict:
    p = job_dir / "summary.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"id": job_dir.name, "url": "", "segments": [], "findings": []}
    return {"id": job_dir.name, "url": "", "segments": [], "findings": []}


def _evidence_files(job_dir: Path) -> List[Path]:
    ev = job_dir / "evidence"
    if not ev.is_dir():
        return []
    return sorted(ev.glob("*.txt"))


def _digest_text(job_dir: Path, tail: int = 8000) -> str:
    """最新 digest 全文（前缀已在 bigdan.extract_digest 剥离），仅极端超大才截断。"""
    digests = sorted(job_dir.glob("digest-*.md"))
    if not digests:
        return "（无）"
    text = digests[-1].read_text(encoding="utf-8", errors="replace").strip()
    if len(text) > tail:
        text = text[:tail] + "\n...(截断，全文见 digest 文件)"
    return text


def _extract_digest_section(job_dir: Path, keyword: str, tail: int = 4000) -> str:
    """从 digest 提取某小节(如「疑似点」)文本；找不到返回空串。"""
    digests = sorted(job_dir.glob("digest-*.md"))
    if not digests:
        return ""
    text = digests[-1].read_text(encoding="utf-8", errors="replace")
    m = re.search(rf"^\s*\*?\*?{keyword}[^\n]*\n(.*?)(?=\n\s*\*?\*?[^\n]+\n|\Z)", text, re.S | re.M)
    if not m:
        return ""
    sec = m.group(1).strip()
    return sec[:tail] + ("\n...(截断)" if len(sec) > tail else "")


def _evidence_clues(job_dir: Path) -> List[Path]:
    """非 `_` 开头的证据文件 = agent 按协议手写的漏洞证据（NN-名称.txt）。
    findings 为空时它们是唯一线索，报告必须列出而非掩盖。"""
    return [p for p in _evidence_files(job_dir) if not p.name.startswith("_")]


def _evidence_block(path: Path, limit: int = 50000) -> str:
    """证据全文内联（SRC 提交需要完整 Payload/响应,不可截断）：仅 >50KB 极端超大才截断。"""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if len(text) > limit:
        cut = text[:limit]
        nl = cut.rfind("\n")
        if nl > limit // 2:  # 优先在行边界截断（保持复现步骤完整）
            cut = cut[:nl]
        text = cut + "\n...(证据过长已截断，全文见原文件)"
    return f"```\n{text}\n```"


def _digest_full(job_dir: Path, limit: int = 20000) -> str:
    """最新 digest 全文（仅 >20KB 极端超大才截断）——报告附录用：Agent 原始交接即线索挖掘素材。"""
    digests = sorted(job_dir.glob("digest-*.md"))
    if not digests:
        return ""
    text = digests[-1].read_text(encoding="utf-8", errors="replace").strip()
    if len(text) > limit:
        cut = text[:limit]
        nl = cut.rfind("\n")
        if nl > limit // 2:
            cut = cut[:nl]
        text = cut + "\n...(digest 过长已截断，全文见 jobs/<id>/digest-*.md)"
    return text


def _impact_from_evidence(text: str) -> str:
    """从证据文本提取「影响」说明（尽力而为）。"""
    for pat in (r"影响[^\n]{2,200}", r"危害[^\n]{2,200}", r"后果[^\n]{2,200}"):
        m = re.search(pat, text)
        if m:
            return m.group(0).strip()
    return ""


def _check_evidence(job_dir: Path, f: dict) -> tuple:
    """triage 证据检查:文件存在且内容 >20 字符才算完整。"""
    if not f.get("file"):
        return False, "无证据文件名"
    evp = job_dir / "evidence" / Path(f["file"]).name
    if not evp.is_file():
        return False, f"证据文件缺失: {f['file']}"
    text = evp.read_text(encoding="utf-8", errors="replace").strip()
    if len(text) < 20:
        return False, f"证据文件过短({len(text)}字符),疑似空壳"
    return True, ""


_RAW_REQ_RE = re.compile(
    r"(?m)(?:^|\n)(?:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+ HTTP/\d(?:\.\d)?.*?(?=\n\s*\n|\n[A-Z][A-Za-z-]+:|\Z))"
    r"|(?:curl\s+-[^\n]+)"
)


def _evidence_urls(text: str) -> List[str]:
    """从证据文本提取接口地址（URL: 行或独立 URL）。"""
    urls: List[str] = []
    for m in re.finditer(r"(?m)^\s*(?:URL|url|接口地址|地址|Target)\s*[:：]\s*(https?://\S+)", text):
        u = m.group(1).rstrip(".,;)]}")
        if u not in urls:
            urls.append(u)
    if not urls:
        for m in re.finditer(r"https?://[^\s'\"<>)]+", text):
            u = m.group(0).rstrip(".,;)]}")
            if u not in urls:
                urls.append(u)
    return urls[:5]


def _evidence_raw_request(text: str) -> str:
    """从证据提取完整请求包（HTTP 原始包优先,curl 命令兜底）——SRC 提交 Payload 包。"""
    for m in re.finditer(
            r"(?m)((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?\n"
            r"(?:[A-Za-z0-9-]+:\s*[^\n]*\n)*)(?:\n|\Z)", text):
        block = m.group(1).strip()
        if len(block) > 40:
            return block
    for m in re.finditer(r"(?m)(curl\s+-[^\n]{20,})", text):
        return m.group(1).strip()
    return ""


def _finding_detail(i: int, f: dict, job_dir: Path) -> List[str]:
    """单个漏洞详情（SRC 提交标准格式:危害描述/接口地址/Payload 包/修复建议）。"""
    level, icon = _risk_of(f)
    lines = [f"### 漏洞{i}：{f.get('title') or '(未命名)'}", ""]
    lines.append(f"**风险等级**: {icon} {level}")
    lines.append("")
    lines.append(f"**漏洞类型**: {f.get('type') or '未标注'} | **状态**: {f.get('status') or 'CONFIRMED'}")
    lines.append("")

    evp = None
    if f.get("file"):
        evp = job_dir / "evidence" / Path(f["file"]).name
        ok, reason = _check_evidence(job_dir, f)
        if not ok:
            lines.append(f"> ⚠️ 证据检查未过: {reason}")
        if f.get("triage_reason"):
            lines.append(f"> ⚠️ triage 硬门: {f['triage_reason']}")
        lines.append("")

    ev_text = evp.read_text(encoding="utf-8", errors="replace") if evp and evp.is_file() else ""

    # 危害描述（影响,SRC 提交必需）
    impact = _impact_from_evidence(ev_text) or f.get("title") or ""
    lines.append(f"**危害描述**: {impact}")
    lines.append("")

    # 接口地址(Target)
    urls = _evidence_urls(ev_text)
    if urls:
        lines.append("**【接口地址(Target)】**")
        lines.append("")
        for u in urls:
            lines.append(f"- `{u}`")
        lines.append("")

    # Payload 数据包(Raw)
    raw = _evidence_raw_request(ev_text)
    if raw:
        lines.append("**【Payload数据包(Raw)】**")
        lines.append("")
        lines.append("```http")
        lines.append(raw)
        lines.append("```")
        lines.append("")

    # 关键响应（全文内联,SRC 提交需要完整响应）
    if evp and evp.is_file():
        resp = _evidence_block(evp, limit=50000)
        if raw:  # 有 Payload 时响应作为补充
            lines.append("**关键响应**:")
            lines.append("")
            lines.append(resp)
            lines.append("")

    lines.append(f"**【修复建议】**: {_fix_for(f)}")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


# ---------------------------------------------------------------- triage 硬门（源自 mastermind triage_gate 可机械化子集）

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_IMPACT_HINT_RE = re.compile(r"(能|可|导致|任意|越权|接管|泄露|泄漏|执行|删除|读取|修改|获取|绕过|冒充|遍历|导出)")
# data_not_public 机械近似（triage 6 项之⑥）:agent 证据自述数据前端已展示 → 提示人工复核
_FRONTEND_PUBLIC_RE = re.compile(r"前端.{0,8}(展示|可见|已显示|公开)|页面.{0,8}(展示|可见|已显示|公开)|UI.{0,4}(展示|可见|已显示)|已在(前端|页面).{0,6}(展示|显示|公开)")


def _triage_check(finding: dict, ev_text: str) -> List[str]:
    reasons: List[str] = []
    if not (finding.get("type") or "").strip():
        reasons.append("无漏洞类型")
    if not _URL_RE.search(ev_text or ""):
        reasons.append("证据中无目标 URL")
    m = re.search(r"(?:影响|危害)\s*[:：]?\s*(.{5,})", ev_text or "", re.S)
    impact_desc = (m.group(1)[:300] if m else "").strip()
    if not _IMPACT_HINT_RE.search(impact_desc):
        reasons.append("无影响描述或未写明具体后果")
    if _FRONTEND_PUBLIC_RE.search(ev_text or ""):
        reasons.append("证据自述数据前端/页面已展示(未过 data_not_public 检查)")
    return reasons


def _apply_triage_gate(summaries: List[dict], jobs_dir: Path) -> int:
    demoted = 0
    for s in summaries:
        job_dir = jobs_dir / s["id"]
        kept = []
        for f in s.get("findings", []):
            if (f.get("status") or "CONFIRMED") == "CONFIRMED":
                evp = job_dir / "evidence" / Path(f.get("file") or "_missing_").name
                ev_text = evp.read_text(encoding="utf-8", errors="replace") if evp.is_file() else ""
                reasons = _triage_check(f, ev_text)
                if reasons:
                    f = {**f, "status": "PENDING",
                         "triage_reason": "；".join(reasons) + "（原判 CONFIRMED，triage 硬门降级）"}
                    demoted += 1
            kept.append(f)
        s["findings"] = kept
    return demoted


# ---------------------------------------------------------------- 报告主函数

def build_report(summaries: List[dict], report_path: Path, jobs_dir: Path) -> None:
    demoted = _apply_triage_gate(summaries, jobs_dir)

    lines: List[str] = []
    lines.append("# 渗透测试报告")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 测试目标数: {len(summaries)}")
    lines.append("- 测试方式: 黑盒（仅凭输入 URL，无源码/凭据）")
    lines.append("- 授权范围: 仅测试清单内目标，禁止越界")
    lines.append("")

    def _count(status: str) -> int:
        return sum(1 for s in summaries for f in s.get("findings", []) if (f.get("status") or "CONFIRMED") == status)

    n_conf = _count("CONFIRMED")
    n_pend = _count("PENDING")
    n_info = _count("INFO")
    # 证据线索兜底：findings 空但 evidence 有 agent 手写证据文件 → 绝不是"未发现"
    clue_total = sum(len(_evidence_clues(jobs_dir / s["id"])) for s in summaries)

    lines.append("## 总体结论")
    lines.append("")
    lines.append("> 风险等级为机器按漏洞类型关键词推断（低危/中危/高危仅作参考），提交 SRC 前请按平台收录标准人工校准；"
                 "加固项类发现（明文传输无实证/无链 Cookie 属性/部署痕迹等）多数平台不收，建议先人工复核再提交。")
    lines.append("")
    if demoted:
        lines.append(f"> ⚠️ triage 硬门已将 {demoted} 项 CONFIRMED 降级为 PENDING"
                     f"（缺目标 URL / 缺影响描述等，详见各条目标注）——提交前请人工复核或补证据。")
        lines.append("")
    if n_conf:
        parts = [f"本次确认 **{n_conf}** 项漏洞"]
        extra = []
        if n_pend:
            extra.append(f"{n_pend} 项待确认")
        if n_info:
            extra.append(f"{n_info} 项信息类")
        if clue_total:
            extra.append(f"{clue_total} 条证据线索待复核")
        if extra:
            parts.append("另有 " + "、".join(extra))
        parts.append("详见各目标章节。")
        lines.append(" ".join(parts))
    elif n_pend or n_info:
        lines.append(f"本次确认 0 项漏洞，但有 {n_pend} 项待确认"
                     f"{f'、{n_info} 项信息类' if n_info else ''}，详见各目标章节。")
    elif clue_total:
        lines.append(f"⚠️ **未登记为漏洞，但存在 {clue_total} 条证据线索**（agent 已落盘证据文件但未按 FINDING 行登记，"
                     f"可能漏报）。详见各目标「证据线索」，建议人工复核后再定论。")
    else:
        lines.append("本次未发现可利用漏洞。")
    lines.append("")

    for s in summaries:
        job_dir = jobs_dir / s["id"]
        findings = s.get("findings", [])
        by_status = {
            "CONFIRMED": [f for f in findings if (f.get("status") or "CONFIRMED") == "CONFIRMED"],
            "PENDING": [f for f in findings if (f.get("status") or "") == "PENDING"],
            "INFO": [f for f in findings if (f.get("status") or "") == "INFO"],
        }
        clues = _evidence_clues(job_dir)

        lines.append(f"## 目标：{s['url'] or s['id']}")
        lines.append("")
        lines.append(f"- **目标ID**: `{s['id']}`")
        if s.get("note"):
            lines.append(f"- **备注**: {s['note']}")
        lines.append(f"- **执行时间**: {s.get('started_at', '?')} ~ {s.get('ended_at', '?')}")
        segs = s.get("segments", [])
        segs_note = "（Agent 建议提前结束）" if s.get("early_stop") else ""
        if s.get("timed_out"):
            segs_note += "（目标总预算耗尽，超时终止）"
        lines.append(f"- **段数**: {len(segs)}{segs_note}")
        if s.get("elapsed_sec") is not None:
            lines.append(f"- **耗时**: {s.get('elapsed_sec')}s / 预算 {s.get('job_timeout_sec', '?')}s"
                         f"（段上限 {s.get('seg_timeout_sec', '?')}s）")
        for seg in segs:
            err = (seg.get("last_error") or "").strip()
            seg_findings = seg.get("findings") or []
            if isinstance(seg_findings, int):  # 旧格式/演示数据:findings 是计数而非标题列表
                seg_findings = [str(seg_findings)]
            lines.append(f"  - 段{seg['seg']}: exit={seg['exit_code']}{'（超时被终止）' if seg.get('timed_out') else ''} "
                         f"发现={len(seg_findings)} digest={'有' if seg.get('digest_saved') else '无'} "
                         f"日志={seg.get('log', '')}"
                         + (f" ⚠️ 失败原因: {err}" if err else ""))
        lines.append("")

        all_findings = [f for f in by_status["CONFIRMED"] + by_status["PENDING"] + by_status["INFO"]]
        if all_findings or clues:
            lines.append("### 漏洞总结")
            lines.append("")
            lines.append("| 序号 | 漏洞名称 | 风险等级 | 状态 |")
            lines.append("|------|---------|---------|------|")
            i = 0
            for f in all_findings:
                i += 1
                level, icon = _risk_of(f)
                if f.get("triage_reason") or f.get("format_error"):
                    st = "⚠️ 降级"
                else:
                    st = {"CONFIRMED": "✅ 确认", "PENDING": "⏳ 待确认", "INFO": "ℹ️ 信息"}.get(
                        f.get("status") or "CONFIRMED", f.get("status") or "确认")
                lines.append(f"| {i} | **{f.get('title') or '(未命名)'}** | {icon} {level} | {st} |")
            for c in clues:
                i += 1
                lines.append(f"| {i} | `{c.name}`（证据线索，未登记 FINDING） | ⚪ 待评估 | ⚠️ 待复核 |")
            lines.append("")
        else:
            lines.append("### 漏洞总结")
            lines.append("")
            lines.append("无。")
            lines.append("")

        # 漏洞详情（triage 降级项 / 格式异常项不在此渲染，归入下方「降级/待复核」）
        active = [f for f in all_findings if not (f.get("triage_reason") or f.get("format_error"))]
        demoted = [f for f in all_findings if f.get("triage_reason") or f.get("format_error")]
        if active:
            lines.append("### 漏洞详情")
            lines.append("")
            i = 0
            for st_key in ("CONFIRMED", "PENDING", "INFO"):
                for f in by_status[st_key]:
                    if f.get("triage_reason") or f.get("format_error"):
                        continue
                    i += 1
                    lines.extend(_finding_detail(i, f, job_dir))
            lines.append("")

        # 降级/待复核：triage 未过 / FINDING 格式异常的条目单独列出（不占漏洞编号）
        if demoted:
            lines.append("### 降级/待复核（triage 硬门未过或 FINDING 格式异常，已从漏洞详情移除）")
            lines.append("")
            for f in demoted:
                reason = f.get("triage_reason") or f.get("format_error") or ""
                extra = ""
                if f.get("format_error") and not f.get("triage_reason"):
                    extra = "；证据文件可能已落盘（agent 打 FINDING 时格式坏了），请人工核对 evidence/ 目录"
                lines.append(f"- **{f.get('title') or '(未命名)'}**（类型: {f.get('type') or '未标注'}）"
                             f"—— {reason}{extra}"
                             + (f"；原证据文件: `{f['file']}`" if f.get("file") else ""))
            lines.append("")

        # 证据线索（findings 空时的兜底呈现 + digest 疑似点）
        if clues:
            lines.append("### 证据线索（agent 落盘了证据但未按 FINDING 行登记，请人工复核）")
            lines.append("")
            for c in clues:
                lines.append(f"- `evidence/{c.name}`（{c.stat().st_size} 字节）")
            lines.append("")

        suspect = _extract_digest_section(job_dir, "疑似点")
        lines.append("### 未闭环线索（SUSPECT / 下一步）")
        lines.append("")
        if suspect:
            lines.append(suspect)
            lines.append("")
        else:
            digest_tail = _digest_text(job_dir, tail=900)
            lines.append(digest_tail)
            lines.append("")

        evs = _evidence_files(job_dir)
        if evs:
            lines.append("### 证据文件清单")
            lines.append("")
            for p in evs:
                lines.append(f"- `evidence/{p.name}`")
            lines.append("")

        lines.append("### 原始数据")
        lines.append("")
        lines.append(f"- 会话日志: `jobs/{s['id']}/session-*.log`（含完整工具调用与响应）")
        lines.append(f"- 结构化摘要: `jobs/{s['id']}/digest-*.md`")
        lines.append("")

    lines.append("## 修复建议（通用）")
    lines.append("")
    lines.append("1. 接口侧强制鉴权与数据归属校验，禁止仅依赖前端隐藏。")
    lines.append("2. 输入校验 + 参数化查询 + 输出编码，敏感数据脱敏。")
    lines.append("3. 组件升级到已修复版本，移除调试信息与默认入口。")
    lines.append("4. 按「漏洞详情」各条针对性修复，修复后按原请求包回归复测。")
    lines.append("")

    # 附录：Agent 原始交接（与正文分开的线索挖掘素材——正文只收可提交漏洞，
    # digest 里的疑似点/已试路径/工具缺失/下一步建议可能对人工有价值）
    lines.append("## 附录：Agent 原始交接（digest 全文，正文之外的挖掘素材）")
    lines.append("")
    lines.append("> 本附录与报告正文分离：正文只收可提交漏洞；这里保留 Agent 观察到的原始线索")
    lines.append("> （疑似点差一步闭环 / 已试路径 / 工具缺失 / 下一步建议），部分线索对人工")
    lines.append("> 挖掘有价值——看到线索就知道怎么打的场景，请优先翻阅本附录。")
    lines.append("")
    for s in summaries:
        digest = _digest_full(jobs_dir / s["id"])
        lines.append(f"### {s['id']}")
        lines.append("")
        if digest:
            lines.append("```markdown")
            lines.append(digest)
            lines.append("```")
        else:
            lines.append("（无 digest）")
        lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
