#!/usr/bin/env python3
"""xs-bigdan 报告生成：汇总各目标 summary.json + evidence 文件 → 一份 md 报告。

报告风格（对齐渗透交付偏好）：
- 发现描述含核实数据（URL/参数/证据文件）+ 攻击链 + 具体证据。
- 修复建议简短通用，不绑定具体系统。
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import List


def _load_summary(job_dir: Path) -> dict:
    p = job_dir / "summary.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"id": job_dir.name, "url": "", "segments": [], "findings": []}


def _evidence_files(job_dir: Path) -> List[Path]:
    ev = job_dir / "evidence"
    if not ev.is_dir():
        return []
    return sorted(ev.glob("*.txt"))


def _digest_text(job_dir: Path, tail: int = 800) -> str:
    digests = sorted(job_dir.glob("digest-*.md"))
    if not digests:
        return "（无）"
    text = digests[-1].read_text(encoding="utf-8", errors="replace")
    if len(text) > tail:
        text = text[:tail] + "\n...(截断)"
    return text


def _evidence_block(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if len(text) > 4000:
        text = text[:4000] + "\n...(证据文件过长已截断，全文见原文件)"
    return f"```\n{text}\n```"


def _check_evidence(job_dir: Path, f: dict) -> tuple:
    """triage 证据检查:文件存在且内容 >20 字符才算完整。

    Returns: (ok: bool, reason: str)
    """
    if not f.get("file"):
        return False, "无证据文件名"
    evp = job_dir / "evidence" / f["file"]
    if not evp.is_file():
        return False, f"证据文件缺失: {f['file']}"
    text = evp.read_text(encoding="utf-8", errors="replace").strip()
    if len(text) < 20:
        return False, f"证据文件过短({len(text)}字符),疑似空壳"
    return True, ""


def _finding_entry(i: int, f: dict, job_dir: Path) -> List[str]:
    lines = [f"**{i}. {f.get('title') or '(未命名)'}**", ""]
    lines.append(f"- 类型: {f.get('type') or '未标注'}")
    lines.append(f"- 状态: {f.get('status') or 'CONFIRMED'}")
    if f.get("file"):
        lines.append(f"- 证据文件: `evidence/{f['file']}`")
        ok, reason = _check_evidence(job_dir, f)
        if not ok:
            lines.append(f"- ⚠️ 证据检查未过: {reason}")
        evp = job_dir / "evidence" / f["file"]
        if evp.is_file():
            lines.append("- 证据内容:")
            lines.append("")
            lines.append(_evidence_block(evp))
    lines.append("")
    return lines


def build_report(summaries: List[dict], report_path: Path, jobs_dir: Path) -> None:
    lines: List[str] = []
    lines.append(f"# xs-bigdan 渗透测试报告")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- 目标数: {len(summaries)}")
    lines.append("- 测试方式: 黑盒（仅凭输入 URL，无源码/凭据）")
    lines.append("- 授权范围: 仅测试清单内目标，禁止越界")
    lines.append("")

    def _count(status: str) -> int:
        return sum(1 for s in summaries for f in s.get("findings", []) if (f.get("status") or "CONFIRMED") == status)

    n_conf = _count("CONFIRMED")
    n_pend = _count("PENDING")
    n_info = _count("INFO")

    lines.append(f"## 总体结论")
    lines.append("")
    if n_conf:
        lines.append(f"本次共确认 **{n_conf}** 项可利用漏洞"
                     f"{f'，另有 {n_pend} 项待确认、{n_info} 项信息类' if n_pend or n_info else ''}，详见各目标章节。")
    else:
        tail = []
        if n_pend:
            tail.append(f"{n_pend} 项待确认")
        if n_info:
            tail.append(f"{n_info} 项信息类")
        if tail:
            lines.append(f"本次未确认到可利用漏洞（{'、'.join(tail)}见各目标章节）。疑似点见各目标『未闭环线索』。")
        else:
            lines.append("本次未确认到可利用漏洞（或证据不足未予记录）。疑似点见各目标『未闭环线索』。")
    lines.append("")

    for s in summaries:
        job_dir = jobs_dir / s["id"]
        lines.append(f"## 目标: {s['id']}")
        lines.append("")
        lines.append(f"- URL: `{s['url']}`")
        if s.get("note"):
            lines.append(f"- 备注: {s['note']}")
        lines.append(f"- 执行时间: {s.get('started_at', '?')} ~ {s.get('ended_at', '?')}")
        segs = s.get("segments", [])
        segs_note = "（Agent 建议提前结束）" if s.get("early_stop") else ""
        if s.get("timed_out"):
            segs_note += "（目标总预算耗尽，超时终止）"
        lines.append(f"- 段数: {len(segs)}" + segs_note)
        if s.get("elapsed_sec") is not None:
            lines.append(f"- 耗时: {s.get('elapsed_sec')}s / 预算 {s.get('job_timeout_sec', '?')}s"
                         f"（段上限 {s.get('seg_timeout_sec', '?')}s）")
        for seg in segs:
            lines.append(f"  - 段{seg['seg']}: exit={seg['exit_code']}{'（超时被终止）' if seg.get('timed_out') else ''} "
                         f"发现={len(seg.get('findings', []))} digest={'有' if seg.get('digest_saved') else '无'} "
                         f"日志={seg.get('log', '')}")
        lines.append("")

        findings = s.get("findings", [])
        by_status = {
            "CONFIRMED": [f for f in findings if (f.get("status") or "CONFIRMED") == "CONFIRMED"],
            "PENDING": [f for f in findings if (f.get("status") or "") == "PENDING"],
            "INFO": [f for f in findings if (f.get("status") or "") == "INFO"],
        }
        for st, title in (("CONFIRMED", "已确认发现"), ("PENDING", "待确认（PENDING，未进结论）"), ("INFO", "信息类（INFO）")):
            group = by_status[st]
            lines.append(f"### {title}（{len(group)}）")
            lines.append("")
            if group:
                for i, f in enumerate(group, 1):
                    lines.extend(_finding_entry(i, f, job_dir))
            else:
                lines.append("无。")
                lines.append("")

        lines.append("### 未闭环线索（SUSPECT / 下一步）")
        lines.append("")
        lines.append(_digest_text(job_dir))
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
    lines.append("1. 对越权/未授权访问类：接口侧强制鉴权与数据归属校验，禁止仅依赖前端隐藏。")
    lines.append("2. 对信息泄露类：移除调试信息与敏感文件，配置层收紧默认访问。")
    lines.append("3. 对注入类：输入校验 + 参数化查询 + 出网控制。")
    lines.append("4. 复测验证：修复后按原请求包回归，确认响应差异消除。")
    lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
