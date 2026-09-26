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


def _digest_order(p):
    """digest 自然排序键:段号跨轮累积后 digest-10.md 需排在 digest-2 之后。"""
    m = re.search(r"digest-(\d+)", p.name)
    return int(m.group(1)) if m else 0


def _digest_text(job_dir: Path, tail: int = 8000) -> str:
    """最新 digest 全文（前缀已在 bigdan.extract_digest 剥离），仅极端超大才截断。"""
    digests = sorted(job_dir.glob("digest-*.md"), key=_digest_order)
    if not digests:
        return "（无）"
    text = digests[-1].read_text(encoding="utf-8", errors="replace").strip()
    if len(text) > tail:
        text = text[:tail] + "\n...(截断，全文见 digest 文件)"
    return text


def _extract_digest_section(job_dir: Path, keyword: str, tail: int = 4000) -> str:
    """从 digest 提取某小节(如「疑似点」)文本；找不到返回空串。"""
    digests = sorted(job_dir.glob("digest-*.md"), key=_digest_order)
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
    digests = sorted(job_dir.glob("digest-*.md"), key=_digest_order)
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


def _evidence_response(text: str, limit: int = 1500) -> str:
    """从证据提取关键响应（SRC 提交只需证明成功的响应,不要整个证据全文内联）。

    优先:"关键响应/响应:"标记后的内容(通常含状态码+JSON,到 验证/影响/上传后/HTTP 等下一标记前);
    其次:HTTP 状态行起的响应块(限 8 行,防带入后续段落);上限 limit。
    """
    m = re.search(
        r"(?:关键)?响应[ \t]*[:：]?[ \t]*[^\n]*\n(.*?)(?=\n[ \t]*(?:#{1,6}\s|验证|影响|危害|修复|curl|上传后|可直接访问|GET https|HTTP/|\Z))",
        text, re.S)
    if m:
        sec = m.group(1).strip()
        if sec and len(sec) > 10:
            return sec[:limit]
    for m in re.finditer(
            r"(?m)^\s*(HTTP/\d(?:\.\d)?\s+\d{3}[^\n]*\n(?:[^\n]*\n){0,8})", text):
        block = m.group(1).strip()
        if len(block) > 20:
            return block[:limit]
    return ""


def _impact_from_evidence(text: str) -> str:
    """从证据文本提取「影响」说明（去掉"影响:"前缀,支持跨行——修复双重标签+换行截断）。"""
    for pat in (r"影响\s*[:：]\s*(.{5,400})", r"危害\s*[:：]\s*(.{5,400})",
                r"后果\s*[:：]\s*(.{5,400})", r"影响等级\s*[:：]\s*(.{5,400})"):
        m = re.search(pat, text, re.S)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""


def _impact_block(text: str, limit: int = 1200) -> str:
    """证据中的「影响说明/危害」整块内容——保持多行列表结构（单行压缩会糊成一团）。"""
    lines = text.splitlines()
    out, on = [], False
    for ln in lines:
        if not on:
            if re.match(r"^\s*(?:影响说明|危害说明|危害描述|影响分析|影响|危害)\s*[:：]?\s*$", ln):
                on = True
                continue
            m = re.match(r"^\s*(?:影响说明|危害说明|危害描述|影响分析|影响|危害)\s*[:：]\s*(\S.*)$", ln)
            if m:
                out.append(m.group(1).rstrip())
                on = True
            continue
        # 已进入影响块：遇到下一小节标题（额外发现/修复/复现等，或"xxx:"形态的裸标题行）即止;
        # markdown 标题行(## 补充/### xxx)同样终止——防止"## 补充2"这类行漏进危害说明
        if re.match(r"^\s*#{1,6}\s", ln):
            break
        if re.match(r"^\s*[-*•]?\s*(?:额外发现|修复建议|修复方案|修复|备注|参考|复现请求|复现步骤|关键响应|验证方式|验证)\s*[:：]?", ln):
            break
        s = ln.strip()
        if s and not s.startswith(("-", "*", "•")) and s.endswith(("：", ":")):
            break
        if s:
            out.append(ln.rstrip())
    block = "\n".join(out).strip()
    if not block:
        return ""
    return block[:limit] + ("\n...(截断)" if len(block) > limit else "")


# 危害说明兜底话术（按类型给实质句子——报告里禁止出现"见证据文件"这类推诿）
_IMPACT_GENERIC: List[Tuple[Tuple[str, ...], str]] = [
    (("信息泄露", "泄露", "暴露", "枚举"),
     "该问题向未授权方暴露内部信息（网络拓扑/源码片段/接口结构/敏感标识等），可被攻击者用于绘制目标结构、定位高价值资产，显著提升后续攻击的成功率。"),
    (("敏感信息", "密钥", "硬编码", "凭据", "口令", "密码"),
     "敏感数据随公开渠道分发，任何获取方无需授权即可直接读取利用；若为加密密钥/凭据，可解密或冒充合法会话，机密性与真实性同时受损。"),
    (("越权", "idor"), "越权漏洞使攻击者可绕过归属校验，跨用户/跨租户直接读取或操作他人数据，权限边界整体失效，属高危。"),
    (("未授权",), "接口无需登录即可调用，未认证攻击者可直接获取受保护数据或执行业务操作，认证防线对该接口完全失效。"),
    (("上传",), "攻击者可上传任意内容获取 Web 访问路径，配合解析漏洞可升级为远程代码执行，服务器完整沦陷。"),
    (("sql",), "攻击者可通过构造输入操控数据库查询，读取/篡改/删除任意数据，必要时可进一步获取服务器权限。"),
    (("xss",), "攻击者可在受害者浏览器中执行任意脚本，窃取会话 Cookie、冒充用户操作，配合钓鱼几乎无法被察觉。"),
    (("ssrf",), "服务端被诱导向任意地址发起请求，可探测内网拓扑、访问内部系统，云环境下可直接获取云凭证接管基础设施。"),
    (("弱口令", "爆破", "无限流", "限流", "轰炸"),
     "认证/发送类接口缺少频控，攻击者可高速穷举或骚扰用户（短信轰炸），造成凭据失陷与业务骚扰。"),
    (("重定向", "redirect"), "跳转目标可被攻击者控制，被用于钓鱼跳转并窃取用户凭据，同时稀释主站域名信誉。"),
]
_IMPACT_DEFAULT = "结合下方复现数据包与关键响应可见：攻击者可在无需特定前提的情况下获取本不应暴露的数据或能力，直接损害系统机密性/完整性。"


def _impact_for(f: dict, ev_text: str) -> str:
    """危害说明三级兜底：证据影响块 → 影响单行 → 按类型话术。绝不输出"见证据文件"。"""
    block = _impact_block(ev_text)
    if block:
        return block
    line = _impact_from_evidence(ev_text)
    if line:
        return line
    text = f"{f.get('type') or ''} {f.get('title') or ''}".lower()
    for keywords, impact in _IMPACT_GENERIC:
        for kw in keywords:
            if kw.lower() in text:
                return impact
    return _IMPACT_DEFAULT


def _full_title(f: dict, job_dir: Path) -> str:
    """标题恢复：agent 打 FINDING 时标题被截断(以 .../… 结尾) → 从证据文件「标题:」行找回全文。"""
    t = (f.get("title") or "").strip()
    if t.endswith(("...", "…")) and f.get("file"):
        evp = job_dir / "evidence" / Path(f["file"]).name
        if evp.is_file():
            try:
                m = re.search(r"(?m)^\s*标题\s*[:：]\s*(.+)$",
                              evp.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                m = None
            if m:
                full = m.group(1).strip()
                if len(full) > len(t.rstrip(".…")):
                    return full
    return t or "(未命名)"


# 垃圾 FINDING 行判定(权威实现;bigdan.extract_findings 延迟 import 复用):
# agent 会把模板占位符/bash 命令片段/正则碎片当 FINDING 行打出来——这些是输出噪音不是洞,
# 直接丢弃(与"格式异常降级"区分:有真实标题的坏行降级给人工,无语义的噪音消失)
_GARBAGE_TOKENS = ("<标题>", "<漏洞类型>", "<证据文件名>", "<标题…", "<漏洞…",
                   "sort -u", "tail -", "/dev/null", "session-*", "2>/dev/null",
                   "grep ", "awk ", "xargs ", "baseURL:", "curl -", "| head")
_GARBAGE_TITLE_RE = re.compile(r"^[\s\W]+$")  # 纯符号/无字母数字中文(如 "]+\**")


def garbage_finding_reason(f: dict) -> str:
    """垃圾行判定:返回丢弃理由,正常条目返回空串。"""
    t_ = f.get("type") or ""
    ti = f.get("title") or ""
    blob = f"{t_} {ti}"
    if "<标题>" in blob or "<漏洞类型>" in blob or "<证据文件名>" in blob:
        return "模板占位符"
    if _GARBAGE_TITLE_RE.match(ti):
        return "无语义标题(正则碎片/符号)"
    for tok in _GARBAGE_TOKENS:
        if tok in blob:
            return f"shell 片段/命令噪音({tok!r})"
    return ""


# 粘行恢复:存量 summary.json 里 status 可能是"CONFIRMED Now let me..."(agent 行尾续写思考)
_ST_RE = re.compile(r"^(CONFIRMED|PENDING|INFO)(?![A-Za-z])")


def recover_status(f: dict) -> dict:
    """恢复粘行污染的 status(原地修改返回),两条路:
    ① status 本身粘了叙述("CONFIRMED Now let me...") → 取词首;
    ② 存量 summary:status 已被旧代码洗成 PENDING,污染原文只在 format_error 文案里
       ("状态字段异常('CONFIRMED ...')") → 从文案提取原判状态恢复。
    这能把'有真实证据但行尾粘了思考文字'的高价值发现从降级区救回主表(广交会案例)。"""
    st = f.get("status") or ""
    m = _ST_RE.match(st)
    if m and len(st) > len(m.group(1)):
        f["status"] = m.group(1)
        f.pop("format_error", None)  # 粘行已恢复,不再标记格式异常
        return f
    fe = f.get("format_error") or ""
    m2 = re.search(r"状态字段异常[(]'?(CONFIRMED|PENDING|INFO)(?![A-Za-z])", fe)
    if m2 and m2.group(1) != "PENDING":  # 被洗成 PENDING 的原判若为 CONFIRMED/INFO → 恢复原判
        f["status"] = m2.group(1)
        f.pop("format_error", None)
    return f


def _status_badge(f: dict) -> str:
    """状态徽标——降级必须写明"从什么状态降到什么状态"。
    降级语义澄清：降级 ≠ 误报判定。原 CONFIRMED 被 triage 机械检查打回 PENDING，
    意思是"证据链不完整、不能自动盖章为可提交"，需人工补证/复核后定性；洞本身可能真实存在。
    风险等级（高危/中危/低危）是另一维度（_risk_of 按类型推断），降级不改变它。"""
    if f.get("triage_reason"):
        r = str(f["triage_reason"]).strip()
        return (f"⚠️ **已降级**（状态: ✅CONFIRMED → ⏳PENDING待人工复核，风险推断不变；"
                f"非误报判定，机械检查未过: {r[:60]}{'…' if len(r) > 60 else ''}；补齐证据后可恢复可提交）")
    if f.get("format_error"):
        return ("⚠️ **已降级**（状态: ✅CONFIRMED → ⏳PENDING待人工复核，风险推断不变；"
                "FINDING 行格式异常，证据可能已正常落盘，核对 evidence/ 后可定性）")
    st = f.get("status") or "CONFIRMED"
    return {
        "CONFIRMED": "✅ **已确认**（CONFIRMED，证据链完整，可直接提交）",
        "PENDING": "⏳ **待确认**（PENDING，agent 自报未闭环，人工复核定性）",
        "INFO": "ℹ️ **信息**（INFO，记录性质，多数平台不收）",
    }.get(st, st)


# ---------------------------------------------------------------- 黄金攻击链素材提取

def _evidence_section(text: str, names: tuple, limit: int = 1500) -> str:
    """从证据提取约定小节（发现过程/防御证据/危害放大）——到下一小节标题或文件尾。"""
    pat = "|".join(names)
    lines = text.splitlines()
    out, on = [], False
    for ln in lines:
        if not on:
            if re.match(rf"^\s*\**\s*(?:{pat})\s*\**\s*[:：]", ln):
                m = re.match(rf"^\s*\**\s*(?:{pat})\s*\**\s*[:：]\s*(.*)$", ln)
                if m and m.group(1).strip():
                    out.append(m.group(1).rstrip())
                on = True
            continue
        # 已入节：下一小节标题（常见节名或"xxx:"裸标题行）即止
        if re.match(r"^\s*\**\s*(?:标题|URL|漏洞类型|发现过程|防御证据|防御|危害放大|影响说明|影响|危害|复现请求|复现步骤|关键响应|验证)\s*\**\s*[:：]", ln):
            break
        s = ln.strip()
        if s and not s.startswith(("-", "*", "•", "→")) and re.match(r"^.{1,12}[:：]$", s):
            break
        if s:
            out.append(ln.rstrip())
    block = "\n".join(out).strip()
    if not block:
        return ""
    return block[:limit] + ("\n...(截断)" if len(block) > limit else "")


_TRIAD_HINTS = [
    ("机密性", r"泄露|泄漏|读取|获取|导出|遍历|枚举|敏感|手机号|身份证|密钥|凭据|token|订单|用户数据"),
    ("完整性", r"写入|修改|篡改|删除|上传|伪造|覆盖|冒充|绑定|重置"),
    ("可用性", r"中断|瘫痪|拒绝服务|耗尽|轰炸|接管|钓鱼|跳转|劫持"),
]
# 类型 → 典型三性话术（影响文本未实证该性时给"典型影响"提示，不编造实证）
_TRIAD_BY_TYPE: List[Tuple[Tuple[str, ...], dict]] = [
    (("越权", "idor"), {"机密性": "越权读取他人/全量业务数据；若对象 ID 可遍历则影响随 ID 空间扩展。"}),
    (("未授权", "信息泄露", "泄露", "敏感信息"), {"机密性": "未授权方直接获取受保护数据；规模取决于接口分页/遍历能力。"}),
    (("上传",), {"完整性": "攻击者可向服务器存储写入任意内容，若落地域可达可进一步钓鱼/存储型 XSS。"}),
    (("sql", "rce", "命令执行", "ssti", "反序列化"), {
        "机密性": "可读取数据库/服务器内任意可达数据。",
        "完整性": "可写入/篡改数据甚至获得系统控制权。",
        "可用性": "极端情况可致服务瘫痪。"}),
    (("无限流", "限流", "轰炸", "弱口令", "爆破"), {"可用性": "可对用户/接口形成骚扰或耗尽资源；弱口令命中即账号接管。"}),
    (("重定向", "redirect"), {"可用性": "可构造恶意跳转实施钓鱼，稀释主站域名信誉。"}),
]


def _impact_triad(f: dict, ev_text: str, impact_text: str) -> List[str]:
    """三性影响评估：影响文本实证命中 → 引用原句；类型典型但未实证 → 标注'典型影响'；否则未实证。"""
    blob = f"{impact_text}\n{ev_text[:3000]}"
    text = f"{f.get('type') or ''} {f.get('title') or ''}".lower()
    defaults = {}
    for keywords, triad in _TRIAD_BY_TYPE:
        if any(kw.lower() in text for kw in keywords):
            defaults = triad
            break
    lines = []
    used_hits = set()
    for dim, kw_re in _TRIAD_HINTS:
        hit = ""
        for ln in impact_text.splitlines():
            s = ln.strip().lstrip("-*• ").strip()
            if len(s) > 8 and re.search(kw_re, s, re.I):
                hit = re.sub(r"\s+", " ", s)[:120]
                break
        if not hit and re.search(kw_re, blob[:2000], re.I):
            m = re.search(rf"[^\n。；;]*{kw_re}[^\n。；;]*[。；;]?", blob[:2000], re.I)
            if m and len(m.group(0).strip()) >= 12:  # 孤词级短匹配(如"伪造"两字)无信息量,弃用
                hit = re.sub(r"\s+", " ", m.group(0)).strip()[:120]
        if hit and hit in used_hits:
            lines.append(f"- **{dim}**：与上述维度同源，无独立实证。")
            continue
        if hit:
            used_hits.add(hit)
            lines.append(f"- **{dim}**：{hit}")
        elif dim in defaults:
            lines.append(f"- **{dim}**（典型影响，本次未单独实证）：{defaults[dim]}")
        else:
            lines.append(f"- **{dim}**：本次未观察到直接实证（如有请人工补充）。")
    return lines


def _fig(fig_no: List[int], desc: str) -> str:
    """图位占位：全局连续编号，写清该截什么图 + 怎么截（VPS 无头环境不自动截图，人工补图指引）。"""
    fig_no[0] += 1
    return f"〔图{fig_no[0]}〕此处放图：{desc}（获取：本地浏览器复现该步时截屏）"


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


def _split_target(url: str) -> tuple:
    """URL → (path?query, host)。把绝对 URL 请求行还原成原始报文形态。"""
    m = re.match(r"[a-zA-Z]+://([^/]+)(/?.*)$", url or "")
    if m:
        return (m.group(2) or "/"), m.group(1)
    return (url or "/"), ""


def _assemble_raw(method: str, url: str, headers, body: str = "") -> str:
    """(方法, URL, 头列表, body) → 标准原始 HTTP 请求报文（请求行含路径，Host 单独成头）。"""
    from urllib.parse import urlsplit
    u = urlsplit(url or "")
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    host = u.netloc
    lines = [f"{method.upper()} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    for k, v in headers or []:
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def _curl_to_raw(curl: str) -> str:
    """curl 命令 → 原始 HTTP 请求报文（方法/-H 头/--data body/URL 解析；SRC 提交格式）。"""
    method = "GET"
    headers = []
    body = ""
    url = ""
    toks = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', curl or "")
    i = 0
    while i < len(toks):
        tk = toks[i].strip("\"'")
        low = tk.lower()
        if low in ("-x", "--request") and i + 1 < len(toks):
            method = toks[i + 1].strip("\"'").upper()
            i += 2
            continue
        if low in ("-h", "--header") and i + 1 < len(toks):
            hv = toks[i + 1].strip("\"'")
            if ":" in hv:
                k, _, v = hv.partition(":")
                headers.append((k.strip(), v.strip()))
            i += 2
            continue
        if low in ("-d", "--data", "--data-raw", "--data-binary", "--json") and i + 1 < len(toks):
            body = toks[i + 1]
            i += 2
            continue
        if tk.lower().startswith(("http://", "https://")) and not url:
            url = tk
        i += 1
    return _assemble_raw(method, url, headers, body)


def _raw_http_from_evidence(ev_text: str):
    """从 xsreq --save 证据还原 (原始请求报文, 原始响应报文)——SRC 提交格式的数据包来源。

    证据格式（xsreq --save）:
      # status=200 ...
      === REQUEST ===
      GET https://host/path
      头: 值...
      === RESPONSE HEADERS === ...
      === RESPONSE BODY === ...
    REQUEST 段为 curl 命令形态时走 _curl_to_raw 兜底。
    """
    req_raw, resp_raw = "", ""
    m = re.search(r"=== REQUEST ===\n(.*?)(?=\n?=== RESPONSE|\Z)", ev_text, re.S)
    if m:
        block = m.group(1).strip()
        parts = block.split("\n", 1)
        head_line = parts[0] if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        mm = re.match(r"([A-Z]+)\s+(\S+)", head_line)
        if mm and "curl" not in head_line:
            url = mm.group(2)
            hdrs = []
            for hl in rest.splitlines():
                if ":" in hl:
                    k, _, v = hl.partition(":")
                    hdrs.append((k.strip(), v.strip()))
            path, host = _split_target(url)
            lines = [f"{mm.group(1)} {path} HTTP/1.1", f"Host: {host}"]
            lines += [f"{k}: {v}" for k, v in hdrs]
            req_raw = "\n".join(lines)
        elif block.startswith("curl"):
            req_raw = _curl_to_raw(block.splitlines()[0])
    m2 = re.search(r"#\s*status=(\d+)", ev_text)
    status = m2.group(1) if m2 else "200"
    mh = re.search(r"=== RESPONSE HEADERS ===\n(.*?)(?=\n?=== RESPONSE BODY|\Z)", ev_text, re.S)
    mb = re.search(r"=== RESPONSE BODY ===\n(.*)\Z", ev_text, re.S)
    if mh or mb:
        headers = mh.group(1).strip() if mh else ""
        body = mb.group(1).strip() if mb else ""
        resp_raw = f"HTTP/1.1 {status}\n{headers}"
        if body:
            resp_raw += "\n\n" + body
    return req_raw, resp_raw


def _split_cookie_line(cookie_header: str) -> str:
    """Cookie 头过长时按 '; ' 折行展示（报告可读性）。"""
    return (";\n" + " " * 7).join(cookie_header.split("; "))


def _evidence_urls(text: str) -> List[str]:
    """从证据文本提取接口地址（URL: 行优先,独立 https URL 补充——SRC 提交 Target 可多列）。"""
    urls: List[str] = []
    for m in re.finditer(r"(?m)^\s*(?:URL|url|接口地址|地址|Target)\s*[:：]\s*(https?://\S+)", text):
        u = m.group(1).rstrip(".,;)]}")
        if u not in urls:
            urls.append(u)
    for m in re.finditer(r"https?://[^\s'\"<>)]+", text):
        u = m.group(0).rstrip(".,;)]}")
        if u not in urls:
            urls.append(u)
    return urls[:5]


def _evidence_raw_request(text: str) -> str:
    """从证据提取完整请求包（xsreq 保存格式优先还原为标准原始包;半格式/curl 兜底）。"""
    text = text.rstrip("\n") + "\n"  # 归一化:确保尾行有换行,否则尾行头匹配不上
    req, _ = _raw_http_from_evidence(text)
    if req:
        return req
    for m in re.finditer(
            r"(?m)(?:^\s*(?:复现)?(?:请求|Request|Payload)\s*[:：][ \t]*)?"
            r"((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+(?:\s+HTTP/\d(?:\.\d)?)?\n"
            r"(?:(?!(?:关键响应|响应[:：]|发现过程|防御证据|危害放大|影响说明|标题))"
            r"[A-Za-z0-9-]+:\s*[^\n]*\n)*)", text):
        block = m.group(1).strip()
        if len(block) > 40:
            # 请求行尾部孤立右括号清理(agent 常写 "(POST ...)" 括号包裹形态)
            first_nl = block.find("\n")
            head_line = block if first_nl < 0 else block[:first_nl]
            if head_line.endswith(")") and head_line.count("(") < head_line.count(")"):
                fixed_head = head_line[:-1].rstrip()
                block = fixed_head + (block[first_nl:] if first_nl > 0 else "")
            head_parts = block.split("\n", 1)[0].split()
            host, path = _split_target_host(head_parts[1] if len(head_parts) > 1 else "")
            if host:  # 绝对 URL 形态 → 重建为 路径 + Host(标准原始包形态)
                lines = [f"{block.split()[0]} {path} HTTP/1.1", f"Host: {host}"]
                lines += block.splitlines()[1:]
                return "\n".join(lines)
            return block  # 路径形态(已含 Host 头)→ 原样保留
    for m in re.finditer(r"(?m)(curl\s+-[^\n]{20,})", text):
        return _curl_to_raw(m.group(1).strip())
    return ""


def _split_target_host(url_or_path: str) -> tuple:
    """从请求行第二段(绝对 URL 或路径)取 (host, path)。"""
    m = re.match(r"(?:[a-zA-Z]+://)?([^/]+)(/.*)?$", url_or_path or "")
    if m and ("." in m.group(1) or ":" in m.group(1)):
        return m.group(1), (m.group(2) or "/")
    return "", url_or_path or "/"


def _scope_expanded_hosts(job_dir: Path) -> dict:
    """scope=root 模式下 agent 记录的扩展域清单 {host: 来源说明}（_scope_expanded.json）。"""
    p = job_dir / "evidence" / "_scope_expanded.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict = {}
    recs = data if isinstance(data, list) else (data.get("hosts") if isinstance(data, dict) else None) or []
    for rec in recs:
        if isinstance(rec, dict) and str(rec.get("host") or "").strip():
            out[str(rec["host"]).strip().lower()] = str(rec.get("source") or "")
        elif isinstance(rec, str) and rec.strip():
            out[rec.strip().lower()] = ""
    return out


def _finding_detail(i: int, f: dict, job_dir: Path, note: str = "", fig_no: List[int] = None,
                     target_url: str = "", related_note: str = "") -> List[str]:
    """单个漏洞详情——SRC 五段式黄金攻击链（对齐 skills/vuln_report），每项信息只出现一次：

      标题（[资产]存在[漏洞类]，[最大危害]） + 元信息行
      一、漏洞摘要（五要素 1~2 句）
      二、受影响资产（具体端点 + scope 扩展域标注）
      三、复现手册（发现过程→防御证据→复现数据包→危害放大→合规说明，含〔图〕占位）
      四、风险影响评估（机密性/完整性/可用性 三性）
      五、修复建议（原理性）
    """
    if fig_no is None:
        fig_no = [0]
    level, icon = _risk_of(f)
    title = _full_title(f, job_dir)
    ftype = f.get("type") or "未标注"
    lines = [f"### 漏洞{i}：{title}", ""]
    meta = [f"**风险等级**: {icon} {level}（机器按类型关键词推断，提交前人工校准）",
            f"**漏洞类型**: {ftype}",
            f"**状态**: {_status_badge(f)}"]
    if note:
        meta.append(f"**涉及业务**: {note}")
    lines.append(" | ".join(meta))
    lines.append("")

    evp = None
    if f.get("file"):
        evp = job_dir / "evidence" / Path(f["file"]).name
    ev_text = evp.read_text(encoding="utf-8", errors="replace") if evp and evp.is_file() else ""

    urls = _evidence_urls(ev_text)
    impact_block = _impact_for(f, ev_text)
    impact_line = _impact_from_evidence(ev_text)

    # 一、漏洞摘要（五要素：系统+端点+漏洞类+能做什么+规模）
    lines.append("#### 一、漏洞摘要")
    lines.append("")
    from urllib.parse import urlsplit
    host = urlsplit(urls[0]).netloc if urls else ""
    endpoint = urls[0] if urls else (f.get("file") and "见复现数据包" or "见复现数据包")
    blk_first = impact_block.splitlines()[0].strip() if impact_block else ""
    imp_line_clean = impact_line.split("##")[0].strip() if impact_line else ""  # re.S 跨行抓取可能吞进"## 补充2"
    what = blk_first or imp_line_clean
    what = re.sub(r"\s+", " ", what)[:160]
    host_disp = host or (re.sub(r"^https?://", "", target_url or "").split("/")[0]) or "目标"
    if what and len(what) <= 50 and not what.startswith(("该问题", "攻击者", "可", "该")) and "攻击者" not in what:
        core_sentence = f"存在{ftype}漏洞，攻击者可 {what.rstrip('。')}。"
    else:
        # 话术整句(自带主语)或超长 → 冒号引出;句尾保证单句号
        core_sentence = f"存在{ftype}漏洞：{what.rstrip('。')}。" if what else f"存在{ftype}漏洞。"
    summary = (f"{host_disp} " if urls else f"{host_disp}") + (f"的 `{endpoint}` " if urls else "") + core_sentence
    if f.get("chain"):
        summary += f"发现链：{f['chain']}"
    lines.append(summary)
    lines.append("")

    # 二、受影响资产
    lines.append("#### 二、受影响资产")
    lines.append("")
    if urls:
        for u in urls:
            lines.append(f"- `{u}`")
    else:
        lines.append("- 见下方复现数据包请求行")
    expanded = _scope_expanded_hosts(job_dir)
    if expanded and urls:
        hosts_hit = sorted({urlsplit(u).netloc.lower().split(":")[0] for u in urls
                            if urlsplit(u).netloc.lower().split(":")[0] in expanded})
        if hosts_hit:
            lines.append("")
            lines.append(f"> ⚠️ 本条含 **scope 扩展域**（{', '.join(hosts_hit)}，来源: "
                         f"{'; '.join(filter(None, (expanded.get(h, '') for h in hosts_hit))[:2]) or '见 _scope_expanded.json'}）"
                         f"——提交前按平台收录范围人工核对归属（同根域≠一定在收录内，如 58 外包资产条款）。")
    if related_note:
        lines.append(related_note.rstrip())
    lines.append("")

    # 三、复现手册（黄金攻击链）
    lines.append("#### 三、复现手册")
    lines.append("")

    # 1. 发现过程：FINDING 链摘要 > 证据"发现过程"节 > 兜底叙述
    discovery = (f.get("chain") or "").strip() or _evidence_section(ev_text, ("发现过程", "发现链", "接口来源"))
    lines.append("**1. 发现过程**")
    lines.append("")
    if discovery:
        lines.append(discovery)
    else:
        lines.append("对该目标的 JS 全量采集与接口契约分析命中本端点；该任务未按新证据协议留档来源链"
                     "（页面/JS→接口），补图时可一并人工补充发现过程。")
    lines.append("")
    lines.append(f"- {_fig(fig_no, '目标站点页面/登录页（证明系统真实在跑）')}")
    lines.append("")

    # 2. 防御证据（如有）
    defense = _evidence_section(ev_text, ("防御证据", "防御", "绕过根因", "绕过原理"))
    if defense:
        lines.append("**2. 防御证据（先证明『本来有校验』）**")
        lines.append("")
        lines.append(defense)
        lines.append("")
        lines.append(f"- {_fig(fig_no, '未绕过前直接调接口被 401/403 拒绝的报错截图')}")
        lines.append("")

    # 3. 复现数据包（步骤号动态:有防御证据时顺延）
    step = 3 if defense else 2
    req_raw, resp_raw = _raw_http_from_evidence(ev_text)
    if not req_raw:
        req_raw = _evidence_raw_request(ev_text)
    lines.append(f"**{step}. 复现数据包（可直接重放）**")
    lines.append("")
    if req_raw:
        lines.append("```http")
        lines.append(req_raw)
        lines.append("```")
        lines.append("")
    if not resp_raw:
        resp_raw = _evidence_response(ev_text, limit=4000)
    if resp_raw:
        lines.append("**关键响应**:")
        lines.append("")
        lines.append("```")
        lines.append(resp_raw)
        lines.append("```")
        lines.append("")
        lines.append(f"- {_fig(fig_no, 'Burp/浏览器中该请求的响应，需能看到关键敏感字段')}")
        lines.append("")
    if not req_raw and not resp_raw:
        lines.append("> 该证据未提取到结构化请求/响应，请对照 evidence 目录原始文件复核。")
        lines.append("")

    # 4. 危害放大
    amplify = _evidence_section(ev_text, ("危害放大", "放大", "批量证明", "遍历证明"))
    lines.append(f"**{step+1}. 危害放大**")
    lines.append("")
    if amplify:
        lines.append(amplify)
    else:
        lines.append(impact_block or _impact_for(f, ev_text))
    lines.append("")
    lines.append(f"- {_fig(fig_no, '遍历/批量/全量数据的列表截图（证明非偶发一条）')}")
    lines.append("")

    # 5. 合规说明（固定措辞）
    lines.append(f"**{step+2}. 合规说明**")
    lines.append("")
    lines.append("本次为授权范围内测试，仅做可读/最小化证明（验证数据不超过 5 条），未实际执行写操作与批量导出；"
                 "涉及的个人敏感数据已做脱敏处理，测试账号与会话已还原。")
    lines.append("")

    # 四、风险影响评估（三性）
    lines.append("#### 四、风险影响评估")
    lines.append("")
    lines.extend(_impact_triad(f, ev_text, impact_block or impact_line))
    lines.append("")

    # 五、修复建议
    lines.append("#### 五、修复建议")
    lines.append("")
    lines.append(_fix_for(f))
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
    if not _URL_RE.search(ev_text or "") and not _evidence_raw_request(ev_text or ""):
        # 原始包形态证据("POST /path HTTP/1.1 + Host:")同样证明目标明确,不再误判"无 URL"
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
            if garbage_finding_reason(f):   # 存量 summary 的垃圾条目在此清退
                continue
            f = recover_status(f)            # 粘行 status 恢复(救回真实 CONFIRMED)
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
    fig_no = [0]  # 图位全局连续编号

    lines: List[str] = []
    lines.append("# 渗透测试报告")
    lines.append("")
    lines.append(f"**生成时间** {datetime.now().strftime('%Y-%m-%d %H:%M')} · **目标数** {len(summaries)} · "
                 f"**方式** 黑盒（仅凭输入 URL） · **范围** 仅测试清单内目标，禁止越界")
    lines.append("")
    lines.append("> 文中〔图n〕为人工补图指引（VPS 无头环境不自动截图）：按各占位说明在本地复现时截取并替换；"
                 "标注『可选』的图位可省略，不影响提交。")
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
        if all_findings:
            lines.append("### 漏洞总结")
            lines.append("")
            lines.append("| 序号 | 漏洞名称 | 风险等级 | 状态 |")
            lines.append("|------|---------|---------|------|")
            i = 0
            for f in all_findings:
                i += 1
                level, icon = _risk_of(f)
                lines.append(f"| {i} | **{_full_title(f, job_dir)}** | {icon} {level} | {_status_badge(f)} |")
            lines.append("")
        elif clues:
            lines.append("### 漏洞总结")
            lines.append("")
            lines.append(f"无登记漏洞；另有 {len(clues)} 条证据线索待人工复核（见下方「证据线索」）。")
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
            # 同族发现统计(两遍法):先编号,同证据文件的条目互相标注(提交时可合并)
            file_group: dict = {}
            for idx, f in enumerate(active, 1):
                if f.get("file"):
                    file_group.setdefault(f["file"], []).append(idx)
            for idx, f in enumerate(active, 1):
                related = ""
                if f.get("file") and len(file_group.get(f["file"], [])) > 1:
                    peers = [str(x) for x in file_group[f["file"]] if x != idx]
                    related = (f"> 🔗 **同族发现**：与漏洞{'、'.join(peers)}共用同一证据文件（同族越权面），"
                               f"提交时可按平台规则合并为一份报告。")
                lines.extend(_finding_detail(idx, f, job_dir, note=(s.get("note") or ""), fig_no=fig_no,
                                             target_url=(s.get("url") or ""), related_note=related))
            lines.append("")

        # 降级/待复核：triage 未过 / FINDING 格式异常的条目单独列出（不占漏洞编号）
        if demoted:
            lines.append("### 降级/待复核（triage 硬门未过或 FINDING 格式异常，已从漏洞详情移除）")
            lines.append("")
            lines.append("> **降级语义**：以下条目均从 ✅CONFIRMED 降为 ⏳PENDING（风险推断不变）。"
                         "降级 ≠ 误报——是证据链机械检查未过（缺 URL/缺影响描述/格式异常），"
                         "洞可能真实存在，人工补齐证据或核对 evidence/ 后即可恢复可提交。")
            lines.append("")
            for f in demoted:
                reason = f.get("triage_reason") or f.get("format_error") or ""
                extra = ""
                if f.get("format_error") and not f.get("triage_reason"):
                    extra = "；证据可能已落盘，请核对 evidence/ 目录"
                lines.append(f"- **{_full_title(f, job_dir)}**（类型: {f.get('type') or '未标注'}）"
                             f"—— {reason}{extra}"
                             + (f"；原证据文件: `{f['file']}`" if f.get("file") else ""))
                # 证据内容内联（复现步骤直接可看,不用翻 evidence 目录）
                if f.get("file") and not f.get("triage_reason"):
                    evp = job_dir / "evidence" / Path(f["file"]).name
                    if evp.is_file():
                        ev_text = evp.read_text(encoding="utf-8", errors="replace")
                        raw = _evidence_raw_request(ev_text)
                        if raw:
                            lines.append("")
                            lines.append("  复现请求:")
                            lines.append("  ```http")
                            lines.append("  " + raw.replace("\n", "\n  "))
                            lines.append("  ```")
                        else:
                            lines.append("")
                            lines.append(_evidence_block(evp, limit=2000))
            lines.append("")

        # 证据线索（findings 空时的兜底呈现 + digest 疑似点）
        if clues:
            lines.append("### 证据线索（agent 落盘了证据但未按 FINDING 行登记，请人工复核）")
            lines.append("")
            for c in clues:
                lines.append(f"- `evidence/{c.name}`（{c.stat().st_size} 字节）")
                # 内容内联:线索的复现请求/响应节选(证据可能存在价值的洞,直接可复现判断)
                text = c.read_text(encoding="utf-8", errors="replace")
                raw = _evidence_raw_request(text)
                if raw:
                    lines.append("")
                    lines.append("  复现请求:")
                    lines.append("  ```http")
                    lines.append("  " + raw.replace("\n", "\n  "))
                    lines.append("  ```")
                else:
                    lines.append("")
                    lines.append(_evidence_block(c, limit=2000))
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
