#!/usr/bin/env python3
"""test_min_product_gate.py — 段级最小产物门(静默早退根治)回归测试。

覆盖:
  1. _evidence_delta   — 空目录 / 陈旧文件 / 本段窗口内新写文件
  2. _segment_min_product — FINDING 增量放行 / 落盘增量放行 / 双零拦截(带原因)
  3. 拦截原因文案含"零产物"且 build_retry_prompt 能渲染 no_product 类别
  4. 豁免路径:digest 含"建议结束"时调用方不触发产物门(模拟段循环判定条件)

用法: python -X utf8 dev/test_min_product_gate.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bigdan  # noqa: E402
from core.retry_detector import build_retry_prompt  # noqa: E402

passed = 0
failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}  {detail}")


def make_job() -> Path:
    d = Path(tempfile.mkdtemp(prefix="mpg-"))
    (d / "evidence").mkdir()
    return d


def write_old(job: Path, name: str, age_sec: float = 600) -> None:
    p = job / "evidence" / name
    p.write_text("x", encoding="utf-8")
    old = time.time() - age_sec
    os.utime(p, (old, old))


def write_now(job: Path, name: str, content: str = "x") -> None:
    (job / "evidence" / name).write_text(content, encoding="utf-8")


print("== 1. _evidence_delta ==")
job = make_job()
check("空 evidence 目录 → []", bigdan._evidence_delta(job, time.time() - 5) == [])
write_old(job, "01-stale.txt")
check("陈旧文件(段窗口外)不计入", bigdan._evidence_delta(job, time.time() - 5) == [])
write_now(job, "_fingerprint.md")
d = bigdan._evidence_delta(job, time.time() - 5)
check("本段新写文件被计入", d == ["_fingerprint.md"], str(d))
job2 = make_job()
write_now(job2, "_linkage_results.jsonl")
write_now(job2, "01-xss.txt")
d2 = bigdan._evidence_delta(job2, time.time() - 5)
check("多文件均计入且排序", d2 == ["01-xss.txt", "_linkage_results.jsonl"], str(d2))
job3 = make_job()
write_old(job3, "_fingerprint.md", 1.0)
d3 = bigdan._evidence_delta(job3, time.time() - 0.1)
check("1s 前写入(2s 容忍窗内)仍计入", d3 == ["_fingerprint.md"], str(d3))

print("== 2. _segment_min_product ==")
job = make_job()
ok, why = bigdan._segment_min_product(job, time.time() - 5, 0, 0)
check("双零(无落盘无 FINDING)→ 拦截", not ok)
check("拦截原因含『零产物』", "零产物" in why, why)
ok, why = bigdan._segment_min_product(job, time.time() - 5, 0, 1)
check("FINDING 增量 → 放行", ok)
ok, why = bigdan._segment_min_product(job, time.time() - 5, 2, 2)
check("FINDING 零增量且无落盘 → 拦截", not ok, why)
write_now(job, "01-idor.txt")
ok, why = bigdan._segment_min_product(job, time.time() - 5, 2, 2)
check("有落盘增量(即使 FINDING 零增量)→ 放行", ok, why)
write_old(job, "02-ssrf.txt")  # 段窗口外旧文件
job4 = make_job()
write_old(job4, "01-old.txt")
write_old(job4, "_fingerprint.md")
ok, _ = bigdan._segment_min_product(job4, time.time() - 0.1, 2, 2)
check("仅陈旧文件不算本段产物 → 拦截", not ok)

print("== 3. 豁免与提示渲染 ==")
job = make_job()
# 模拟段循环:digest 含建议结束 → 调用方不查产物门(早停门接管) —— 复刻段循环判定条件
dig_suggest_end = True
exit_code, early_stop, blocked = 0, False, False
cond = (not early_stop and not blocked
        and exit_code in (0, 1) and not dig_suggest_end)
check("digest 建议结束 → 产物门条件不成立", not cond)
dig_suggest_end = False
cond = (not early_stop and not blocked
        and exit_code in (0, 1) and not dig_suggest_end)
check("exit=0 且无建议结束 → 产物门条件成立", cond)
check("exit=124 被 exit_code∈(0,1) 排除在产物门外", 124 not in (0, 1))
prompt = build_retry_prompt([{"category": "no_product", "severity": "critical", "matched": "零产物"}], 1)
check("no_product 提示含补产物指令", "零产物增量" in prompt and "_fingerprint" in prompt and "建议结束" in prompt)
check("no_product 提示不含未知类别残留", "BY_VULN_CLASS" not in prompt)

print(f"\n{'-' * 40}\npassed={passed} failed={failed}")
sys.exit(1 if failed else 0)
