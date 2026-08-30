#!/usr/bin/env python3
"""xs-bigdan — 本地 SRC 授权渗透测试 Agent 主调度器。

理念（源自 pi-recon / 百度 Agent 攻防赛前15经验）：
- Harness 只做确定的事：读目标、写 BRIEF、分段执行、硬超时、digest 交接、汇总报告。
- 模型负责想，工具负责看，Harness 负责让这两件事稳定发生。
- 不压缩证据：原始会话日志、evidence 文件全部保留，摘要可回指原文。

用法:
    python bigdan.py --targets targets.txt            # 跑全部目标
    python bigdan.py --targets targets.txt --only www-01   # 只跑某个目标
    python bigdan.py --targets targets.txt --dry-run       # 只打印计划
    python bigdan.py --target <url>                         # 直接给单个 URL
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

from core.agent_exec import run_pi_session, extract_last_error
from core.retry_detector import detect_surrender, build_retry_prompt

VERSION = "0.1.0"


def load_dotenv(path: Path) -> None:
    """必须在模块常量求值前调用——否则 .env 里的 BIGDAN_* 对常量不可见(历史陷阱)。"""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv(Path(__file__).resolve().parent / ".env")

JOBS_DIR = Path(os.environ.get("BIGDAN_JOBS_DIR", "runtime/jobs"))
OUTPUTS_DIR = Path(os.environ.get("BIGDAN_OUTPUTS_DIR", "runtime/outputs"))
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

DEFAULT_SEGMENTS = int(os.environ.get("BIGDAN_SEGMENTS", "3"))
DEFAULT_SEGMENT_TIMEOUT = int(os.environ.get("BIGDAN_SEGMENT_TIMEOUT_SEC", "1800"))
# 每目标总预算（墙钟），超时即停止该目标释放给下一个 —— 迁移自 pi-recon 的 PI_RECON_JOB_TIMEOUT_SEC
# 真实 SRC 目标侦察+验证以小时计（qdedu 实测：20 分钟连侦察都跑不完），默认 1 小时
DEFAULT_JOB_TIMEOUT = int(os.environ.get("BIGDAN_JOB_TIMEOUT_SEC", "3600"))
DEFAULT_CONCURRENCY = int(os.environ.get("BIGDAN_CONCURRENCY", "1"))
# 测试账号池（BRIEF 注入，推进认证后攻击面；模板见 credentials.example.txt）
CREDENTIALS_FILE = os.environ.get("BIGDAN_CREDENTIALS", "credentials.txt")


# ---------------------------------------------------------------- 基础工具

def _site_label(url: str) -> str:
    """从目标 URL 提取可识别的站点名（host，去协议/端口/路径/www.）。"""
    u = (url or "").strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split(":", 1)[0]
    if u.startswith("www."):
        u = u[4:]
    return u or "unknown"


def _safe_filename_part(s: str, max_len: int = 24) -> str:
    """清洗为 Windows 文件名安全片段（非法字符转 -，截断）。"""
    import re

    s = re.sub(r'[\\/:*?"<>|\s]+', "-", s or "").strip("-")
    return s[:max_len]


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)
    try:
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass


def env_int(*names: str, default: int) -> int:
    """按顺序取第一个可解析为 int 的环境变量（迁移自 pi-recon env_int）。"""
    for n in names:
        raw = os.environ.get(n)
        if raw is None or not str(raw).strip():
            continue
        try:
            return int(str(raw).strip())
        except ValueError:
            continue
    return default


def resolve_llm_key() -> str:
    """多别名回退找 LLM key（迁移自 pi-recon resolve_llm_key）。"""
    for name in (
        "BIGDAN_LLM_KEY",
        "PI_RECON_LLM_KEY",
        "DEEPSEEK_API_KEY",
        "API_KEY",
        "LLM_API_KEY",
    ):
        v = (os.environ.get(name) or "").strip()
        if v:
            return v
    return ""


# ---------------------------------------------------------------- 目标解析

def parse_targets(text: str) -> List[dict]:
    """每行: [id|]url[|备注]  ；# 开头为注释；空行跳过。

    id 缺省时自动生成：取 URL host 的主域名部分。
    """
    targets: List[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        # 无 id 的裸 URL 行(url 本身可能含 | 备注):parts[0] 以 http 开头即视为 URL 行
        if parts and parts[0].lower().startswith(("http://", "https://")):
            url = parts[0]
            tid, note = "", (parts[1] if len(parts) > 1 else "")
        elif len(parts) >= 2 and parts[0]:
            tid, url = parts[0], parts[1]
            note = parts[2] if len(parts) > 2 else ""
        else:
            url = parts[0]
            tid, note = "", ""
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
        if not tid:
            host = re.sub(r"^https?://", "", url).split("/")[0]
            tid = re.sub(r"[^0-9a-zA-Z.-]", "-", host)
        targets.append({"id": tid, "url": url, "note": note})
    return targets


def read_targets_file(path: Path) -> List[dict]:
    if not path.is_file():
        sys.exit(f"[!] targets 文件不存在: {path}")
    return parse_targets(path.read_text(encoding="utf-8", errors="ignore"))


def scope_hosts(targets: List[dict]) -> List[str]:
    hosts: List[str] = []
    for t in targets:
        h = re.sub(r"^https?://", "", t["url"]).split("/")[0].split(":")[0]
        if h not in hosts:
            hosts.append(h)
    return hosts


# ---------------------------------------------------------------- 测试账号池

def parse_credentials(text: str) -> List[dict]:
    """每行: [scope|]user|pass[|备注]  ；# 开头为注释。

    scope 缺省为 `*`（全部目标注入）；scope 匹配目标 id 或 host（精确，
    或 host 以 .scope 结尾的子域）。登录速率红线（≤2次/秒）由 BRIEF 文案兜底。
    """
    creds: List[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            scope, user, pwd = parts[0], parts[1], parts[2]
            note = parts[3] if len(parts) > 3 else ""
        elif len(parts) == 2:
            scope, user, pwd, note = "*", parts[0], parts[1], ""
        else:
            continue
        if not user or not pwd:
            continue
        creds.append({"scope": scope or "*", "user": user, "pass": pwd, "note": note})
    return creds


def credentials_for_target(target: dict, creds: List[dict]) -> List[dict]:
    tid = (target.get("id") or "").lower()
    host = re.sub(r"^https?://", "", target.get("url") or "").split("/")[0].split(":")[0].lower()
    out: List[dict] = []
    for c in creds:
        s = (c.get("scope") or "*").lower()
        if s in ("*", "") or s == tid or s == host or host.endswith("." + s):
            out.append(c)
    return out


# ---------------------------------------------------------------- BRIEF

# 阶段→读取索引（Safe-First 状态机：阶段由落盘产物门控，不由段号驱动。
# pi 每段全新上下文，文件读取是唯一知识通道；methodology.md 第 13 节是完整兜底表，
# methodology.md 开头「阶段与门控总览」是权威定义——与本表/harness 判定是同一份清单）
PHASE_READ_INDEX = {
    "recon": [  # 🟢 安全侦察: 指纹/WAF/JS 落盘/端点表
        ("agents/recon/SKILL.md", "侦察专家视角:本段产出标准(JS落盘/端点表)"),
        ("skills/js_analysis/SKILL.md", "JS 全量采集+深度分析(SPA chunk/Sub-Path SPA 探测)"),
        ("references/browser-probe-usage.md", "无头浏览器用法:open/js/chunks/login + JS驱动打法(Vue/__vue__/mock登录)"),
        ("references/fingerprint-mapping.md", "指纹→测试映射表+WAF 签名(先探测 WAF 再动手)"),
        ("references/compliance-rules.md", "SRC 合规 TIER 分级,动手前必读"),
    ],
    "linkage": [  # 🟡 普通测试: 值池联动/无认证扫/泛查询/IDOR
        ("agents/api_fuzz/SKILL.md", "接口测试专家视角:全接口覆盖+产出标准"),
        ("skills/data_linkage/SKILL.md", "值池联动:JS需求表×响应值池=测试矩阵"),
        ("references/response-chaining.md", "响应链方法论:A 返回值→B 输入"),
        ("references/decision-trees/README.md", "参数特征命中→先读索引再精读对应§决策树小文件(29棵,防上下文泛滥)"),
        ("skills/xs_auth/SKILL.md", "BRIEF 注入了测试账号时:登录口逻辑审计手册(JS审计→定向验证→接管链)"),
        ("skills/business_flow/SKILL.md", "BRIEF 注入了账号/Cookie 时:登录态功能点遍历(四问框架+寻路四式+返回包地图)"),
    ],
    "deep": [  # 🟡 条件阶段: JWT/加密/端点榨干（无 JWT 且无加密体→跳过并写 digest）
        ("skills/jwt_attack/SKILL.md", "发现 JWT 时:全攻击链(alg:none/弱密钥/kid/RS256→HS256)"),
        ("skills/crypto_attack/SKILL.md", "发现前端加密时:密钥提取→批量解密→明文回注值池"),
        ("references/discovery-amplification.md", "Discovery Amplification:端点→同类路径/参数榨干"),
        ("references/biz-mutations.md", "登录态业务参数扰动字典:七族扰动/命中即停(越权/状态机/载体探针)"),
    ],
    "highrisk": [  # 🔴 条件阶段: 已有 ≥1 CONFIRMED 才进；WAF 存在全程 SAFE MODE
        ("agents/exploit/SKILL.md", "利用专家视角:FOUND≠CONFIRMED 三级分类"),
        ("references/high-risk-probing.md", "高危探测细节(SQLi/CMD/SSTI/SSRF/XXE/越权)"),
        ("references/impact-escalation.md", "影响升级框架:证明实际危害"),
    ],
    "report": [  # 收尾: 评级/报告视角
        ("agents/report/SKILL.md", "报告视角:triage 6 项检查"),
        ("references/rating-standard.md", "SRC 评级标准(报告对齐)"),
        ("references/impact-escalation.md", "影响升级框架:影响写'能做什么'"),
    ],
}


# ---------------------------------------------------------------- 阶段状态机（Safe-First 门控）

def _recon_gate(job_dir: Path) -> tuple[bool, str]:
    """recon 门:契约文件存在 + completeness≥0.8 + 端点≥3（与 methodology 总览同一份清单）。"""
    ep = job_dir / "evidence" / "_endpoint_params.json"
    if not ep.is_file():
        return False, "契约文件 _endpoint_params.json 不存在(JS 分析未产出)"
    try:
        data = json.loads(ep.read_text(encoding="utf-8", errors="replace"))
        meta = data.get("_meta") or {}
        n_ep = len(data.get("endpoints") or [])
        comp = meta.get("analysis_completeness", 0)
    except (OSError, json.JSONDecodeError):
        return False, "契约文件存在但解析失败"
    if not isinstance(comp, (int, float)) or comp < 0.8:
        return False, f"契约 completeness={comp}(<0.8,JS 分析未达标)"
    if n_ep < 3:
        return False, f"契约端点数={n_ep}(<3)"
    return True, f"契约完整:{n_ep} 端点/completeness={comp}"


def _confirmed_count(job_dir: Path) -> int:
    """runlog 里 CONFIRMED finding 事件数(FINDING 行由 harness 提取落盘)。"""
    p = job_dir / "runlog.jsonl"
    if not p.is_file():
        return 0
    n = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("type") == "finding" and (rec.get("status") or "CONFIRMED") == "CONFIRMED":
            n += 1
    return n


def _linkage_consumed(job_dir: Path) -> int:
    """联动消费计数:hit 字段非 None 的结果行数。"""
    p = job_dir / "evidence" / "_linkage_results.jsonl"
    if not p.is_file():
        return 0
    n = 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            if json.loads(line).get("hit") is not None:
                n += 1
        except json.JSONDecodeError:
            continue
    return n


def infer_phase(job_dir: Path) -> tuple[str, str]:
    """阶段状态机:纯落盘产物推断（零 Agent 新增义务），返回 (阶段, 推断依据)。

    判定次序: report > highrisk > deep/linkage/recon（由门放行）。
    与 methodology.md「阶段与门控总览」是同一份清单的产物化实现；
    BRIEF 会写明阶段+依据，Agent 有据可推翻。
    """
    # report: agent 明确建议结束（存在人工新线索时不短路——线索重新开面）
    digests = sorted(job_dir.glob("digest-*.md"))
    fresh_clue = (job_dir / "user_input.md").is_file()
    if digests and not fresh_clue:
        try:
            if "建议结束" in digests[-1].read_text(encoding="utf-8", errors="replace"):
                return "report", "最新 digest 标注建议结束"
        except OSError:
            pass
    # highrisk: ≥1 CONFIRMED 且 recon 门已过（门没过→回 recon 补，写明原因）
    confirmed = _confirmed_count(job_dir)
    if confirmed >= 1:
        gate_ok, gate_why = _recon_gate(job_dir)
        if gate_ok:
            return "highrisk", f"已有 {confirmed} 条 CONFIRMED，{gate_why}"
        return "recon", f"已有发现但 {gate_why}，先补门"
    # deep / linkage / recon: 由 recon 门与联动消费进度放行
    gate_ok, gate_why = _recon_gate(job_dir)
    if not gate_ok:
        return "recon", gate_why
    consumed = _linkage_consumed(job_dir)
    if consumed > 0:
        return "deep", f"联动已消费 {consumed} 条配对且暂无 CONFIRMED，转入 JWT/加密/端点榨干"
    return "linkage", f"{gate_why}，值池联动尚未消费"


def write_brief(job_dir: Path, target: dict, scope: List[str], segs: int, seg_idx: int = 0,
                creds: Optional[List[dict]] = None) -> tuple[str, str]:
    """写目标简报。返回 (阶段, 推断依据) 供调度器日志展示。"""
    brief = job_dir / "BRIEF.md"
    tools_dir = Path(__file__).resolve().parent / "tools"
    knowledge_dir = Path(__file__).resolve().parent / "knowledge"
    req = (tools_dir / "bin" / "xsreq.py").as_posix()
    enum = (tools_dir / "bin" / "xsenum.py").as_posix()
    browser = (tools_dir / "bin" / "browser_probe.py").as_posix()
    wordlist_paths = (tools_dir / "wordlists" / "paths.txt").as_posix()
    wordlist_params = (tools_dir / "wordlists" / "params.txt").as_posix()

    # 动态探测本机工具并注入（pi-recon"工具决定可见性"；失败不影响 BRIEF）
    probe_extra = ""
    probe = tools_dir / "bin" / "probe_tools.py"
    if probe.is_file():
        try:
            probe_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            r = subprocess.run(
                [sys.executable, str(probe)],
                capture_output=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
                env=probe_env,
            )
            if r.returncode == 0 and r.stdout.strip():
                probe_extra = "\n" + r.stdout.strip() + "\n"
        except Exception:  # noqa: BLE001
            probe_extra = ""

    # 读取索引（按阶段注入;完整目录表在 prompts/methodology.md 第 13 节）
    phase, basis = infer_phase(job_dir)
    read_idx = PHASE_READ_INDEX.get(phase, PHASE_READ_INDEX["recon"])
    idx_lines = "\n".join(
        f"- `{knowledge_dir.as_posix()}/{path}` — {why}"
        for path, why in read_idx
    )

    # 联动配对（值池引擎注入:契约文件存在时才显示）
    linkage_section = build_linkage_section(job_dir)

    # 用户线索（人工协作通道:webui 提供线索 → user_input.md → 续跑时注入 BRIEF）
    user_input_section = ""
    ui = job_dir / "user_input.md"
    if ui.is_file():
        ui_text = ui.read_text(encoding="utf-8", errors="replace").strip()
        if ui_text:
            user_input_section = (
                f"\n## 用户线索（人工提供，优先处理）\n{ui_text}\n"
            )

    # 测试账号（人工提供的账号池:推进认证后攻击面——越权/IDOR 在认证后才是主战场）
    cred_section = ""
    matched_creds = credentials_for_target(target, creds) if creds else []
    if matched_creds:
        cred_lines = [
            f"- 用户名: `{c['user']}`  密码: `{c['pass']}`" + (f"（{c['note']}）" if c["note"] else "")
            for c in matched_creds
        ]
        cred_section = (
            "\n## 测试账号（人工提供，先登录再测认证后攻击面）\n"
            "登录速率≤2次/秒，禁止爆破，命中即停；登录成功后优先测越权/IDOR/垂直越权与业务逻辑，"
            "两账号差分是金标准。登录失败 2 次即停，写 BLOCKED:AUTH_CREDENTIALS。\n"
            + "\n".join(cred_lines) + "\n"
        )

    # 会话 Cookie（人工提供的登录态:SSO/扫码登录站点无法走密码登录，这是唯一通道。
    # 每行 `[host|]cookie`；带 host 前缀的按目标 host 过滤，防 cookie 发到别的站点）
    cookie_section = ""
    cookie_file = job_dir / "cookies.txt"
    if cookie_file.is_file():
        host = urlsplit(target["url"]).netloc.split(":")[0].lower()
        cookies: List[str] = []
        try:
            for raw in cookie_file.read_text(encoding="utf-8", errors="replace").splitlines():
                s = raw.strip()
                if not s or s.startswith("#"):
                    continue
                head, sep, rest = s.partition("|")
                scope = head.lower().split(":")[0]  # 容忍 host:port 前缀
                if (sep and "=" not in head
                        and re.fullmatch(r"[A-Za-z0-9.\-]+", head or "")
                        and ("." in scope or scope == "localhost")):
                    if scope != host and not host.endswith("." + scope):
                        continue  # 其他站点的 cookie，绝不下发（防串站泄露）
                    s = rest.strip()
                cookies.append(s)
        except OSError:
            cookies = []
        if cookies:
            ck_lines = [f"- 账号{i}: `{ck}`" for i, ck in enumerate(cookies, 1)]
            diff_hint = (
                "\n**多账号差分是金标准**：用账号A的 Cookie 访问/操作账号B的资源对象"
                "（遍历 ID/路由），能读能改即 IDOR。"
                if len(cookies) > 1 else ""
            )
            cookie_section = (
                "\n## 测试 Cookie（人工提供，登录态直接可用，无需再登录）\n"
                "用法: API 层 `xsreq --header 'Cookie: <串>'`；"
                "浏览器层 `browser_probe.py <子命令> <url> --cookie '<串>'`"
                "（登录态页面渲染/存储型 XSS 落点验证/功能点遍历）。\n"
                + "\n".join(ck_lines) + "\n" + diff_hint
            )

    # 用户意图（建任务时人工填写的原始想法:哪里薄弱/想先测什么——优先级最高的方向指引）
    intent_section = ""
    it_f = job_dir / "intent.md"
    if it_f.is_file():
        it = it_f.read_text(encoding="utf-8", errors="replace").strip()
        if it:
            intent_section = (
                "\n## 用户意图（建任务时人工填写，优先验证）\n"
                f"{it}\n"
            )

    # 入口聚焦（用户给带路径的 URL = 想先深测这个入口，而非整个 host 铺开；
    # 不缩白名单——host 级授权不变，只是探索优先级跟随用户意图）
    focus_section = ""
    url_path = urlsplit(target["url"]).path.strip("/")
    if url_path:
        app_prefix = "/" + url_path.split("/")[0]
        focus_section = (
            f"\n## 入口聚焦（用户意图，优先级高于 host 内自由探索）\n"
            f"用户指定入口 `{target['url']}`——往往是他判断的薄弱点。"
            f"**先集中深测此入口及其应用前缀 `{app_prefix}/*`**；"
            f"host 内其他应用/路径默认不要主动铺开（偏离用户意图且浪费预算），"
            f"仅当该入口已榨干且有明确线索指向别处时才扩大，并在 digest 里说明理由。\n"
        )

    brief.write_text(
        f"# 目标简报\n\n"
        f"- 目标 ID: `{target['id']}`\n"
        f"- 目标 URL: `{target['url']}`\n"
        f"- 备注: {target['note'] or '无'}\n"
        f"- 本次授权范围（白名单）: {', '.join(scope)}\n"
        f"- 总段数: {segs} | 本段: 第 {seg_idx + 1} 段（段=上下文保鲜切片，与阶段无关）\n"
        f"- 本段阶段判定: **{phase}**（harness 按落盘产物推断: {basis}；"
        f"你若依据 BRIEF/证据判断阶段不同，按你的判断推进并在 digest 里说明）\n"
        f"{focus_section}\n"
        f"## 读取索引（本段建议读,按需 cat;别一次全读,防上下文泛滥）\n"
        f"{idx_lines}\n"
        f"\n"
        f"{linkage_section}"
        f"{user_input_section}"
        f"{intent_section}"
        f"{cred_section}"
        f"{cookie_section}"
        f"\n"
        f"## 工具（绝对路径，直接 `python <路径> ...` 调用，不要 which/find 找）\n"
        f"- 请求: `python {req} <url> [--method POST] [--data '...'] [--json '{{...}}'] [--header 'K: V'] [--save 文件名]`\n"
        f"- 枚举: `python {enum} <base-url> [--wordlist 文件] [--limit N]`\n"
        f"- 浏览器分析(SPA必用): `python {browser} open|js|chunks|login|snow <url> ...` —— 渲染后DOM/console/XHR/执行JS/mock登录/雪瞳26类提取;高难站先走JS驱动(见读取索引)\n"
        f"- 路径字典: `{wordlist_paths}`(轻探档103条,xsenum默认)\n"
        f"- 参数字典: `{wordlist_params}`\n"
        f"- 深度字典(按级选用,勿跳级;WAF/SAFE MODE 时禁止深扫档): "
        f"`{(tools_dir / 'wordlists' / 'seclists' / 'web' / 'quickhits.txt').as_posix()}`(标准) → "
        f"`{(tools_dir / 'wordlists' / 'seclists' / 'web' / 'common.txt').as_posix()}`(全量) → "
        f"`{(tools_dir / 'wordlists' / 'seclists' / 'web' / 'raft-small-dirs.txt').as_posix()}`(深扫) → "
        f"`{(tools_dir / 'wordlists' / 'seclists' / 'web' / 'api-endpoints.txt').as_posix()}`(API专项)\n"
        f"{probe_extra}"
        f"\n"
        f"## 规则\n"
        f"- 只测以上白名单内的 host；禁止 DoS、禁止破坏性操作。\n"
        f"- 发现漏洞 → 按 system prompt 的『证据落盘协议』写 evidence/ 并打印 FINDING 行。\n",
        encoding="utf-8",
    )
    return phase, basis


# ---------------------------------------------------------------- worklog 事件日志

def runlog(job_dir: Path, entry_type: str, data: dict) -> None:
    """append-only JSONL 事件日志(mastermind worklog_recorder 精简版)。

    entry_type ∈ {segment_start, segment_end, finding, retry, early_stop, note}
    """
    try:
        rec = {
            "ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "run": job_dir.name,
            **data,
            "type": entry_type,  # 后置:防止 data 中的 "type" 键覆盖事件类型
        }
        with open(job_dir / "runlog.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — 日志失败不打断 run
        pass


def load_recent_runlog(job_dir: Path, limit: int = 30) -> List[dict]:
    """读 runlog 尾部 N 条(新→旧),供交接上下文注入。"""
    if not (job_dir / "runlog.jsonl").is_file():
        return []
    lines = (job_dir / "runlog.jsonl").read_text(encoding="utf-8", errors="replace").splitlines()
    out: List[dict] = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except Exception:  # noqa: BLE001
            continue
        if len(out) >= limit:
            break
    return out


def build_linkage_section(job_dir: Path, max_pairs: int = 10) -> str:
    """值池联动(mastermind linkage 引擎):契约文件 → 配对 → BRIEF 注入。

    消费闭环:agent 测完一条配对 → 结果追加 evidence/_linkage_results.jsonl
    ({"endpoint","param","value","hit","note"}) → 下段自动标记已消费,不重复测。
    """
    try:
        from core.linkage import load_linkage_state, PairingEngine, check_pair_completeness
    except Exception:  # noqa: BLE001
        return ""
    ep = job_dir / "evidence" / "_endpoint_params.json"
    vp = job_dir / "evidence" / "_leaked_values.json"
    if not ep.is_file() or not vp.is_file():
        return ""
    try:  # Agent 手写契约损坏时跳过联动,绝不炸整轮运行
        return _build_linkage_section_inner(job_dir, max_pairs)
    except Exception as e:  # noqa: BLE001
        log(f"[linkage] 引擎加载失败已跳过: {type(e).__name__}: {e}")
        return ""


def _build_linkage_section_inner(job_dir: Path, max_pairs: int = 10) -> str:
    from core.linkage import load_linkage_state, PairingEngine, check_pair_completeness

    reg, pool = load_linkage_state(job_dir)
    res_path = job_dir / "evidence" / "_linkage_results.jsonl"
    if res_path.is_file():
        for line in res_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rec = json.loads(line)
                if rec.get("hit") is not None:
                    pool.mark_consumed(rec.get("param", ""), rec.get("value", ""), rec.get("endpoint", ""))
            except Exception:  # noqa: BLE001
                continue
    eng = PairingEngine(reg, pool)
    pairs = eng.match()
    gate = check_pair_completeness(pairs)
    if not pairs:
        return ""
    lines = [
        "## 联动配对(值池引擎生成,按优先级逐个测;测完把结果追加到 evidence/_linkage_results.jsonl)",
        '  格式: {"endpoint": "...", "param": "...", "value": "...", "hit": true/false, "note": "..."}',
        "",
    ]
    for p in pairs[:max_pairs]:
        lines.append(f"- [{p.priority}] {p.reason} (method={p.method})")
    if gate.block_transition:
        lines.append("")
        lines.append(f"⚠️ 引擎门控: 仍有 {len(gate.critical_unconsumed)} 条 HIGH/CRITICAL 配对未消费,优先测完它们再开新面。")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- digest 提取

DIGEST_RE = re.compile(r"#{1,4}\s*RECON_DIGEST\s*\n(.*)$", re.S | re.I)
BLOCKED_RE = re.compile(r"#{1,4}\s*BLOCKED\s*(?:\n|:)|BLOCKED\s*type\s*:", re.I)


def extract_digest(log_text: str) -> Optional[str]:
    m = DIGEST_RE.search(log_text)
    if not m:
        return None
    body = m.group(1)
    # 剥离 harness 行前缀（`[tag] ` 与 `# [tag] ` 两种形态）
    body = re.sub(r"(?m)^(?:# )?\[[^\]]+\] ", "", body)
    # 过滤 heartbeat 与收尾控制行
    body = re.sub(r"(?m)^(?:# )?heartbeat .*$", "", body)
    body = re.sub(r"(?m)^# --- .*$", "", body)
    body = re.sub(r"(?m)^session_dir files=.*$", "", body)
    body = re.sub(r"(?m)^--- end .*$", "", body)
    body = re.sub(r"(?m)^pi pid=.*$", "", body)
    body = re.sub(r"(?m)^spawning pi at .*$", "", body)
    return body.strip() or None


def load_digests(job_dir: Path) -> List[str]:
    digests: List[str] = []
    for p in sorted(job_dir.glob("digest-*.md")):
        digests.append(p.read_text(encoding="utf-8", errors="replace"))
    return digests


def read_final_assistant_text(job_dir: Path, min_mtime: float = 0.0) -> str:
    """兜底通道：从最新 pi 会话镜像读最后一条非空 assistant 文本。

    stdout 捕获丢失（管道/编码故障，如 Windows GBK tee error）时，agent 的
    最终输出（FINDING/BLOCKED/RECON_DIGEST）会整段丢失，调度器错过停止信号
    就会多烧后续段预算。pi 自己落盘的 jsonl 始终是 UTF-8，用它兜底恢复。

    min_mtime: 只接受该时间点之后有写入的 jsonl——本段 pi 压根没启动时
    （exit 127 等），最新 jsonl 是上一段的陈旧镜像，不设门槛会把旧交接
    误记到本段。
    """
    sess = job_dir / ".pi-sessions"
    if not sess.is_dir():
        return ""
    jsonls = sorted(sess.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not jsonls or jsonls[-1].stat().st_mtime < min_mtime:
        return ""
    last = ""
    try:
        with jsonls[-1].open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"assistant"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = e.get("message") or e
                if not isinstance(msg, dict) or msg.get("role") != "assistant":
                    continue
                c = msg.get("content")
                if isinstance(c, list):
                    c = "\n".join(
                        b.get("text", "") for b in c if isinstance(b, dict)
                    )
                if isinstance(c, str) and c.strip():
                    last = c
    except OSError:
        return ""
    return last


# ---------------------------------------------------------------- FINDING 提取

FINDING_RE = re.compile(r"(?:^|\])\s*`{0,2}\s*FINDING:\s*(.+?)`{0,2}\s*$", re.M)


def extract_findings(log_text: str) -> List[dict]:
    """提取 FINDING: type|title|file|status 行；type/title 为空的脏行丢弃（宁缺勿滥）。

    反引号容错：agent 常把整行包进 `` ` ``（行内代码），老版正则因此漏提取。
    """
    out: List[dict] = []
    for m in FINDING_RE.finditer(log_text):
        parts = [p.strip().strip("`").strip() for p in m.group(1).split("|")]
        f = {
            "type": parts[0] if len(parts) > 0 else "",
            "title": parts[1] if len(parts) > 1 else "",
            "file": parts[2] if len(parts) > 2 else "",
            "status": parts[3] if len(parts) > 3 else "CONFIRMED",
        }
        if not f["type"] or not f["title"]:
            continue
        if f["status"] not in ("CONFIRMED", "PENDING", "INFO"):
            f["status"] = "CONFIRMED"
        if f not in out:
            out.append(f)
    return out


# ---------------------------------------------------------------- 用户 prompt 构造

def compose_context(job_dir: Path, max_findings: int = 10, tail_events: int = 15) -> str:
    """从 runlog + evidence 派生限长交接上下文(mastermind session_context/handoff 合并移植)。

    pi agent 每段全新上下文,靠此恢复连续性:事件流(谁在何时发现了什么)
    + 已有证据文件清单。注入每段 user prompt 头部,防上下文泛滥(限长)。
    """
    parts: List[str] = []
    events = load_recent_runlog(job_dir, limit=tail_events)
    if events:
        ev_lines: List[str] = []
        for e in reversed(events):  # 时间正序
            t = e.get("ts", "")[11:19]
            typ = e.get("type", "?")
            if typ == "segment_start":
                ev_lines.append(f"  {t} 段{e.get('seg')}开始(预算{e.get('budget_sec')}s)")
            elif typ == "segment_end":
                ev_lines.append(f"  {t} 段{e.get('seg')}结束 exit={e.get('exit_code')} findings={e.get('findings')}")
            elif typ == "finding":
                vt = e.get("vuln_type") or e.get("type") or "?"
                ev_lines.append(f"  {t} FINDING {vt} | {e.get('title')} ({e.get('status') or 'CONFIRMED'})")
            elif typ == "retry":
                ev_lines.append(f"  {t} 触发重试:{','.join(e.get('categories', []))}")
            elif typ == "early_stop":
                ev_lines.append(f"  {t} 早停(段{e.get('seg')})")
        parts.append("### 当前 run 状态(harness 记录)\n" + "\n".join(ev_lines))
    ev_dir = job_dir / "evidence"
    if ev_dir.is_dir():
        files = sorted(ev_dir.glob("*.txt"))
        if files:
            parts.append("### 已有证据文件\n" + "\n".join(f"- `{p.name}`" for p in files[:max_findings]))
    return "\n\n".join(parts)


def build_user_prompt(target: dict, seg_idx: int, segs: int, timeout_sec: int) -> str:
    seg = seg_idx + 1
    head = (
        f"开始对目标 `{target['url']}` 进行黑盒渗透测试。"
        f"这是第 {seg}/{segs} 段，本段预算约 {timeout_sec // 60} 分钟。\n\n"
        f"请先打开 BRIEF.md 确认范围，再按方法论推进。"
    )
    # run 状态注入(mastermind session_context):事件流+证据清单,防从头重来
    job_dir = Path(os.environ.get("BIGDAN_JOBS_DIR", "runtime/jobs")) / target["id"]
    if job_dir.is_dir():
        ctx = compose_context(job_dir)
        if ctx:
            head += f"\n\n{ctx}"
    prev = load_digests(Path(os.environ.get("BIGDAN_JOBS_DIR", "runtime/jobs")) / target["id"])
    if prev:
        digest_tail = prev[-1][-2500:]
        head += (
            f"\n\n## 上一段交接（RECON_DIGEST 末尾，全文在 digest-*.md）\n\n"
            f"{digest_tail}\n\n"
            f"不要从头重来：先看 evidence/ 里已有的证据文件（避免重复劳动），"
            f"重点处理上一段的『疑似点』和『下一步建议』。"
        )
    # 上段投降检测触发的重试指令(存在则强制注入)
    retry_files = sorted(job_dir.glob("retry-prompt-*.txt")) if job_dir.is_dir() else []
    if retry_files:
        retry_txt = retry_files[-1].read_text(encoding="utf-8", errors="replace").strip()
        if retry_txt:
            head += f"\n\n{retry_txt}"
    tail = (
        f"\n\n## 本段收工要求\n"
        f"- 有可确认漏洞 → 写证据文件 + 打印 FINDING 行。\n"
        f"- 无论有无发现，收工前输出 `### RECON_DIGEST` 结构化摘要（格式见 system prompt）。\n"
        f"- 若本段已把全部攻击面试完且无新线索，可在 digest 里说明『建议结束』，"
        f"调度器会提前停止后续段。"
    )
    return head + tail


# ---------------------------------------------------------------- 单目标运行

def _load_prev_findings(job_dir: Path) -> List[dict]:
    """续打保护:读上一轮 summary.json 的 findings（报告只读 summary.json，不合并会丢历史发现）。"""
    p = job_dir / "summary.json"
    if not p.is_file():
        return []
    try:
        prev = json.loads(p.read_text(encoding="utf-8"))
        return [f for f in (prev.get("findings") or []) if isinstance(f, dict)]
    except (OSError, json.JSONDecodeError):
        return []


def run_target(
    target: dict,
    scope: List[str],
    segs: int,
    job_timeout_sec: int,
    seg_timeout_sec: int,
    model: str,
    dry_run: bool = False,
    creds: Optional[List[dict]] = None,
) -> dict:
    job_dir = JOBS_DIR / target["id"]
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "evidence").mkdir(parents=True, exist_ok=True)
    write_brief(job_dir, target, scope, segs, 0, creds=creds)

    summary = {
        "id": target["id"],
        "url": target["url"],
        "note": target["note"],
        "segments": [],
        "findings": _load_prev_findings(job_dir),
        "early_stop": False,
        "blocked": False,
        "timed_out": False,
        "job_timeout_sec": job_timeout_sec,
        "seg_timeout_sec": seg_timeout_sec,
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    system_prompt = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    system_prompt += "\n\n## 方法论速查\n\n" + (PROMPTS_DIR / "methodology.md").read_text(encoding="utf-8")

    t0 = time.monotonic()
    segs_ran = 0
    for i in range(segs):
        seg_no = i + 1
        # 每段重写 BRIEF:阶段由产物状态机推断（Safe-First 门控），段只是保鲜切片
        phase, basis = write_brief(job_dir, target, scope, segs, i, creds=creds)
        # 目标级总预算：预留 ~25s 收尾（迁移自 pi-recon 的 budget = timeout - 25）
        left = job_timeout_sec - (time.monotonic() - t0)
        if left < 45:
            log(f"=== [{target['id']}] 目标总预算将尽 (left={left:.0f}s)，停止后续段 ===")
            break
        seg_to = min(seg_timeout_sec, int(left) - 25)
        if seg_to < 40:
            break

        user_prompt = build_user_prompt(target, i, segs, seg_to)
        log_path = job_dir / f"session-{seg_no}.log"
        tag = target["id"]
        seg_start_epoch = time.time()  # jsonl 兜底的陈旧镜像门槛基线

        runlog(job_dir, "segment_start", {"seg": seg_no, "budget_sec": seg_to, "phase": phase})
        log(f"=== [{tag}] 段 {seg_no}/{segs} 开始 {datetime.now().strftime('%H:%M:%S')} "
            f"phase={phase}（seg_budget={seg_to}s, job_left={left:.0f}s） ===")
        exit_code = run_pi_session(
            job_dir,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            log_path=log_path,
            provider=os.environ.get("BIGDAN_LLM_PROVIDER", "deepseek"),
            model=model,
            api_key=os.environ.get("BIGDAN_LLM_KEY") or resolve_llm_key() or None,
            thinking=os.environ.get("BIGDAN_LLM_THINKING", "medium"),
            timeout_sec=seg_to,
            session_name=f"{tag}-seg{seg_no}",
            job_tag=tag,
        )
        segs_ran += 1
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
        # 兜底：从 pi 会话镜像恢复最终 assistant 输出（stdout 捕获丢失时救回
        # FINDING/BLOCKED/RECON_DIGEST，否则调度器错过停止信号多烧整段预算）。
        # min_mtime 防陈旧镜像：本段 pi 没启动成功时不该用上一段的交接
        recover = read_final_assistant_text(job_dir, min_mtime=seg_start_epoch - 5)

        # 提取本段发现（按 类型|标题|证据 去重后合并，保留上一轮/前几段的历史发现）
        seg_findings = extract_findings(log_text)
        for f in extract_findings(recover):
            if f not in seg_findings:
                seg_findings.append(f)
        for f in seg_findings:
            key = (f["type"], f["title"], f["file"])
            if all((x["type"], x["title"], x["file"]) != key for x in summary["findings"]):
                summary["findings"].append(f)
            runlog(job_dir, "finding", {"seg": seg_no, "vuln_type": f["type"], "title": f["title"], "file": f["file"], "status": f.get("status", "CONFIRMED")})

        # 提取 digest（stdout 没截到时用 jsonl 兜底恢复）
        digest = extract_digest(log_text) or (extract_digest(recover) if recover else None)
        if digest:
            (job_dir / f"digest-{seg_no}.md").write_text(digest + "\n", encoding="utf-8")
            if "建议结束" in digest:
                summary["early_stop"] = True
                runlog(job_dir, "early_stop", {"seg": seg_no})
        # 人工求助检测（BLOCKED 协议）：agent 请求人工输入 → 停止后续段等待线索。
        # digest 只截 RECON_DIGEST 起的尾部，其前的 BLOCKED 块要看 recover / 原始日志尾
        if BLOCKED_RE.search((digest or "") + "\n" + recover + "\n" + log_text[-4000:]):
            summary["blocked"] = True
            runlog(job_dir, "blocked", {"seg": seg_no})

        # 投降检测(mastermind retry_detector):agent 过早收手 → 下一段强制重试
        if not summary["early_stop"] and not summary["blocked"]:
            detect_text = digest or log_text[-2500:]
            surr = detect_surrender(detect_text)
            if surr["should_retry"]:
                existing = sorted(job_dir.glob("retry-prompt-*.txt"))
                if len(existing) < 2:  # 最多 2 次强制重试,之后允许自然收工
                    retry_prompt = build_retry_prompt(surr["categories"], seg_no)
                    (job_dir / f"retry-prompt-{seg_no}.txt").write_text(retry_prompt, encoding="utf-8")
                    runlog(job_dir, "retry", {"seg": seg_no, "categories": [c["category"] for c in surr["categories"]]})
                    log(f"=== [{tag}] 段 {seg_no} 检测到放弃信号({surr['top_category']}),已注入重试指令到下一段 ===")

        seg_rec = {
            "seg": seg_no,
            "exit_code": exit_code,
            "timed_out": exit_code == 124,
            "findings": [f["title"] for f in seg_findings],
            "digest_saved": bool(digest),
            "log": log_path.name,
        }
        # exit=1 等异常退出：提取日志尾部失败原因归档（旧版只记 exit 码，失败根因无从排查）
        if exit_code not in (0, 124, 127):
            seg_rec["last_error"] = extract_last_error(log_path)
            runlog(job_dir, "note", {"seg": seg_no, "msg": f"exit={exit_code} 失败原因: {seg_rec['last_error']}"})
            log(f"=== [{tag}] 段 {seg_no} 失败原因: {seg_rec['last_error']} ===")
        summary["segments"].append(seg_rec)
        runlog(job_dir, "segment_end", {"seg": seg_no, "exit_code": exit_code, "findings": len(seg_findings), "digest_saved": bool(digest)})
        log(f"=== [{tag}] 段 {seg_no} 结束 exit={exit_code} findings={len(seg_findings)} digest={'Y' if digest else 'N'} ===")

        if exit_code == 124:
            summary["timed_out"] = True

        if summary["blocked"]:
            log(f"=== [{tag}] Agent 请求人工输入（BLOCKED），停止后续段；提供线索后点「续跑」===")
            break

        if summary["early_stop"]:
            log(f"=== [{tag}] Agent 建议结束，提前停止后续段 ===")
            break

    summary["ended_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary["elapsed_sec"] = round(time.monotonic() - t0, 1)
    summary["segments_planned"] = segs
    summary["segments_ran"] = segs_ran
    (job_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


# ---------------------------------------------------------------- 主入口

def main() -> int:
    ap = argparse.ArgumentParser(description="xs-bigdan 本地 SRC 授权渗透测试 Agent")
    ap.add_argument("--targets", default="targets.txt", help="目标清单文件（默认 targets.txt）")
    ap.add_argument("--target", help="直接给单个 URL（优先级高于 --targets）")
    ap.add_argument("--only", help="只运行指定 id（逗号/空格分隔多值）")
    ap.add_argument("--segments", type=int, default=DEFAULT_SEGMENTS, help=f"每目标最多段数（上下文保鲜切片，默认 {DEFAULT_SEGMENTS}；与阶段无关）")
    ap.add_argument("--segment-timeout", type=int, default=DEFAULT_SEGMENT_TIMEOUT, help=f"每段预算上限秒（默认 {DEFAULT_SEGMENT_TIMEOUT}，受目标总预算约束）")
    ap.add_argument("--job-timeout", type=int, default=DEFAULT_JOB_TIMEOUT, help=f"每目标总预算秒，超时停止该目标（默认 {DEFAULT_JOB_TIMEOUT}=60分钟）")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help=f"同时测试的目标数 fill-slot（默认 {DEFAULT_CONCURRENCY}=串行）")
    ap.add_argument("--credentials", default=CREDENTIALS_FILE, help=f"测试账号池文件（默认 {CREDENTIALS_FILE}，不存在则跳过）")
    ap.add_argument("--model", default=os.environ.get("BIGDAN_LLM_MODEL", "deepseek-v4-flash"), help="LLM 模型")
    ap.add_argument("--dry-run", action="store_true", help="只打印执行计划")
    args = ap.parse_args()

    if args.target:
        targets = parse_targets(args.target)
    else:
        targets = read_targets_file(Path(args.targets))
    if args.only:
        only_ids = {x.strip().lower() for x in re.split(r"[,\s]+", args.only) if x.strip()}
        targets = [t for t in targets if t["id"].lower() in only_ids]
        if not targets:
            sys.exit(f"[!] 没有找到 id 匹配 {args.only} 的目标")

    if not targets:
        sys.exit("[!] 目标清单为空")

    scope = scope_hosts(targets)
    job_timeout = max(90, int(args.job_timeout))
    seg_timeout = max(60, int(args.segment_timeout))
    workers = max(1, int(args.concurrency))

    creds: List[dict] = []
    cred_path = Path(args.credentials)
    if cred_path.is_file():
        creds = parse_credentials(cred_path.read_text(encoding="utf-8", errors="ignore"))
    if creds:
        log(f"测试账号: {len(creds)} 条（{cred_path}），将注入命中目标的 BRIEF")

    log(f"xs-bigdan v{VERSION} | 目标数={len(targets)} | 白名单={scope}")
    log(f"模型={args.model} provider={os.environ.get('BIGDAN_LLM_PROVIDER', 'deepseek')} "
        f"key_set={bool(os.environ.get('BIGDAN_LLM_KEY') or resolve_llm_key())}")
    log(f"时间模型: 每目标总预算 {job_timeout}s ({job_timeout // 60}min) | 每段上限 {seg_timeout}s | "
        f"段数 {args.segments} | 并发 {workers}")
    for t in targets:
        log(f"  - [{t['id']}] {t['url']} {t['note']}")

    if args.dry_run:
        log("\n[dry-run] 不执行，以上为计划。")
        return 0

    if not (os.environ.get("BIGDAN_LLM_KEY") or resolve_llm_key()):
        log("[!] 警告: BIGDAN_LLM_KEY 未设置，pi 可能无法调用模型。请在 .env 里配置。")

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    all_summaries = []

    if workers == 1:
        # 串行：一个目标跑完（或超时）再下一个 —— 每目标总预算保证不拖死队列
        for t in targets:
            all_summaries.append(
                run_target(t, scope, args.segments, job_timeout, seg_timeout, args.model,
                           creds=creds)
            )
    else:
        # fill-slot 并发：最多 workers 个目标同时在测，一个完成/超时立即补下一个
        import concurrent.futures

        q = list(targets)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures: dict = {}
            while q or futures:
                while len(futures) < workers and q:
                    t = q.pop(0)
                    log(f"=== [slot] 启动目标 {t['id']} in_flight={len(futures)+1}/{workers} queued={len(q)} ===")
                    fut = ex.submit(run_target, t, scope, args.segments, job_timeout, seg_timeout,
                                    args.model, False, creds)
                    futures[fut] = t["id"]
                if not futures:
                    break
                done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in done:
                    tid = futures.pop(fut)
                    try:
                        s = fut.result()
                        all_summaries.append(s)
                    except Exception as e:  # noqa: BLE001
                        log(f"=== [slot] 目标 {tid} 异常: {e} ===")
                        all_summaries.append({"id": tid, "error": str(e)})
                    log(f"=== [slot] 目标 {tid} 完成 in_flight={len(futures)} queued={len(q)} ===")

    # 汇总统计（语义对齐 pi-recon harvest_summary）
    has_findings = [s for s in all_summaries if s.get("findings")]
    expired = [s for s in all_summaries if s.get("timed_out")]
    log("\n" + "#" * 56)
    log(f"### BIGDAN_DONE 目标={len(all_summaries)} 有发现={len(has_findings)} 超时={len(expired)}")
    for s in all_summaries:
        log(f"  - [{s.get('id')}] findings={len(s.get('findings', []))} "
            f"segments={s.get('segments_ran', 0)}/{s.get('segments_planned', '?')} "
            f"elapsed={s.get('elapsed_sec', '?')}s timed_out={s.get('timed_out', False)}")

    # 汇总报告（文件名带站点/备注，方便历史归档里定位目标；时间戳防同站点多轮覆盖）
    from core.report import build_report
    sites, notes = [], []
    for s in all_summaries:
        h = _site_label(s.get("url", ""))
        if h not in sites:
            sites.append(h)
        n = (s.get("note") or "").strip()
        if n and n not in notes:
            notes.append(n)
    if len(sites) == 1:
        site_part = sites[0]
        note_part = _safe_filename_part("-".join(notes)) if notes else ""
    else:
        site_part = f"multi-{len(sites)}"
        note_part = ""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"report-{site_part}" + (f"-{note_part}" if note_part else "") + f"-{stamp}"
    report_path = OUTPUTS_DIR / f"{name}.md"
    build_report(all_summaries, report_path, JOBS_DIR)
    log(f"[+] 报告已生成: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
