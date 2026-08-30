#!/usr/bin/env python3
"""回归：段收工停止信号（FINDING/BLOCKED/RECON_DIGEST）在 stdout 丢失时必须仍被检出。

背景（2026-08-29 mcd 实测）：agent 正确输出 FINDING+BLOCKED+RECON_DIGEST，
但 Windows 下 Popen(text=True) 未指定 encoding，GBK 解码中文抛异常吞掉整段
stdout → 调度器三项全漏检 → 误拉后续段空烧预算。

本脚本构造同形态现场（session log 无最终输出 + jsonl 有完整最终消息），
断言兜底通道恢复全部三项。退出码 0=通过。
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bigdan import BLOCKED_RE, extract_digest, extract_findings, read_final_assistant_text  # noqa: E402

FINAL_MSG = (
    "本段测试完成。\n\n"
    "`FINDING: SQL Injection|测试注入点|05-sqli-pending.txt|PENDING`\n\n"
    "### BLOCKED\n"
    "type: AUTH_CREDENTIALS\n"
    "卡点: 全部业务 API 需要登录，无测试账号，无法进入越权/IDOR 深测。\n\n"
    "### RECON_DIGEST\n"
    "**目标状态**\n"
    "- 目标存活；已测路径 20+，全部需登录\n"
    "**下一步建议**\n"
    "- 拿到测试账号后重跑"
)


def make_job(tmp: Path) -> None:
    """session log 不含最终输出（模拟 stdout 被吞）；jsonl 含完整最终消息。"""
    sess = tmp / ".pi-sessions"
    sess.mkdir(parents=True)
    event = {"message": {"role": "assistant", "content": [{"type": "text", "text": FINAL_MSG}]}}
    (sess / "seg1.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    (tmp / "session-1.log").write_text(
        "[20:00:01] [tag] [:01Z] toolResult bash: some output\n"
        "[20:00:02] # heartbeat n=1 elapsed=1s pi_alive=1\n",
        encoding="utf-8",
    )


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="xsbd-stop-signal-"))
    try:
        make_job(tmp)
        log_text = (tmp / "session-1.log").read_text(encoding="utf-8", errors="replace")
        recover = read_final_assistant_text(tmp)

        assert extract_findings(log_text) == [], "stdout 现场本就不该提取到"
        fs = extract_findings(recover)
        assert len(fs) == 1 and fs[0]["status"] == "PENDING", f"FINDING 兜底失败: {fs}"
        dg = extract_digest(log_text) or extract_digest(recover)
        assert dg and "下一步建议" in dg, "digest 兜底失败"
        assert BLOCKED_RE.search((dg or "") + "\n" + recover + "\n" + log_text[-4000:]), "BLOCKED 漏检"
        print("PASS: FINDING/digest/BLOCKED 三项均从 jsonl 兜底检出")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
