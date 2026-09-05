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


def _evidence_response(text: str, limit: int = 1500) -> str:
    """从证据提取关键响应（SRC 提交只需证明成功的响应,不要整个证据全文内联）。

    优先:"关键响应/响应:"标记后的内容(通常含状态码+JSON,到 验证/影响/上传后/HTTP 等下一标记前);
    其次:HTTP 状态行起的响应块(限 8 行,防带入后续段落);上限 limit。
    """
    m = re.search(
        r"(?:关键)?响应\s*[:：]?\s*[^\n]*\n(.*?)(?=\n\s*(?:验证|影响|危害|修复|curl|上传后|可直接访问|GET https|HTTP/|\Z))",
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
            r"(?m)(?:^\s*(?:请求|Request|Payload)\s*[:：]\s*)?"
            r"((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+(?:\s+HTTP/\d(?:\.\d)?)?\n"
            r"(?:[A-Za-z0-9-]+:\s*[^\n]*\n)*)(?:\n|\Z)", text):
        block = m.group(1).strip()
        if len(block) > 40:
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


def _finding_detail(i: int, f: dict, job_dir: Path, note: str = "") -> List[str]:
    """单个漏洞详情（对齐 SRC 提交模板:漏洞地址/漏洞等级/详细说明/漏洞证明/修复方案；
    Payload 与响应均为原始 HTTP 数据包——可直接重放复现，非 curl 命令）。"""
    level, icon = _risk_of(f)
    lines = [f"### 漏洞{i}：{f.get('title') or '(未命名)'}", ""]
    lines.append(f"**漏洞等级**: {icon} {level} | **漏洞类型**: {f.get('type') or '未标注'} | "
                 f"**状态**: {f.get('status') or 'CONFIRMED'}"
                 + (f" | **涉及业务**: {note}" if note else ""))
    lines.append("")

    evp = None
    if f.get("file"):
        evp = job_dir / "evidence" / Path(f["file"]).name
        ok, reason = _check_evidence(job_dir, f)
        if not ok:
            lines.append(f"> ⚠️ 证据检查未过: {reason}")
        if f.get("triage_reason"):
            lines.append(f"> ⚠️ triage 硬门: {f['triage_reason']}")
        if f.get("format_error"):
            lines.append(f"> ⚠️ 格式异常: {f['format_error']}")
        lines.append("")

    ev_text = evp.read_text(encoding="utf-8", errors="replace") if evp and evp.is_file() else ""

    # 一、漏洞地址
    lines.append("#### 一、漏洞地址")
    lines.append("")
    urls = _evidence_urls(ev_text)
    if urls:
        for u in urls:
            lines.append(f"- `{u}`")
    else:
        lines.append("- 见「四、漏洞证明」数据包中的请求行")
    lines.append("")

    # 二、漏洞等级
    lines.append("#### 二、漏洞等级")
    lines.append("")
    lines.append(f"{icon} **{level}**（机器按漏洞类型关键词推断，提交前按平台收录标准人工校准）")
    lines.append("")

    # 三、详细说明（涉及业务 / 危害描述 / 漏洞细节全文）
    lines.append("#### 三、详细说明")
    lines.append("")
    if note:
        lines.append(f"**涉及业务**: {note}")
        lines.append("")
    impact = _impact_from_evidence(ev_text)
    lines.append(f"**危害描述**: {impact or '见证据文件中的响应差异与影响说明'}")
    lines.append("")
    if evp and evp.is_file():
        lines.append("**漏洞细节（证据全文，含复现步骤与响应）**:")
        lines.append("")
        lines.append(_evidence_block(evp))
        lines.append("")

    # 四、漏洞证明（原始数据包——可直接重放）
    lines.append("#### 四、漏洞证明")
    lines.append("")
    urls = _evidence_urls(ev_text)
    if urls:
        lines.append("**【接口地址(Target)】**")
        lines.append("")
        for u in urls:
            lines.append(f"- `{u}`")
        lines.append("")
    req_raw, resp_raw = _raw_http_from_evidence(ev_text)
    if not req_raw:
        req_raw = _evidence_raw_request(ev_text)
    if req_raw:
        lines.append("**【Payload数据包(Raw)】**:")
        lines.append("")
        lines.append("```http")
        lines.append(req_raw)
        lines.append("```")
        lines.append("")
    if not resp_raw:
        resp_raw = _evidence_response(ev_text, limit=4000)
    if resp_raw:
        lines.append("**关键响应**:")
        lines.append("")
        lines.append(f"```\n{resp_raw}\n```")
        lines.append("")

    # 五、修复方案
    lines.append("#### 五、修复方案")
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
                    lines.extend(_finding_detail(i, f, job_dir, note=(s.get("note") or "")))
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
