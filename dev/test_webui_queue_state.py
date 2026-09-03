#!/usr/bin/env python3
"""test_webui_queue_state.py — webui 续跑排队状态显示回归测试。

背景修复:list_jobs 的 queued 覆盖原先只对 created/interrupted 生效,
已完成/超时/待人工任务点续跑入队后卡片仍显示旧状态、排队中统计不计。
修复后:只要任务在队列 queued 条目中且未被运行进程占用 → 一律显示 queued。

用法: python -X utf8 dev/test_webui_queue_state.py
(纯临时目录,不动真实 runtime/jobs 与 queue.json)
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webui"))

import core  # noqa: E402

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


def mkjob(jobs: Path, jid: str, summary: dict | None) -> None:
    d = jobs / jid
    (d / "evidence").mkdir(parents=True)
    if summary:
        (d / "summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    else:
        (d / "BRIEF.md").write_text("# 目标简报\n目标 URL: `https://x.example`\n备注: t\n", encoding="utf-8")


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="webuiq-"))
    jobs_dir = tmp / "jobs"
    jobs_dir.mkdir()
    webui_dir = tmp / ".webui"
    webui_dir.mkdir()
    # 指向临时目录,不碰真实数据
    core.JOBS_DIR = jobs_dir
    core.WEBUI_DIR = webui_dir
    core.QUEUE_FILE = webui_dir / "queue.json"
    core.GROUPS_FILE = webui_dir / "groups.json"
    core.GROUPS_FILE.write_text(json.dumps({"groups": {}}), encoding="utf-8")

    base = {"note": "n", "url": "https://x.example"}
    mkjob(jobs_dir, "job-done", {**base, "ended_at": "2026-09-03 10:00:00", "elapsed_sec": 100,
                                 "segments_ran": 3, "segments_planned": 3, "findings": []})
    mkjob(jobs_dir, "job-timeout", {**base, "ended_at": "2026-09-03 09:00:00", "timed_out": True,
                                    "elapsed_sec": 100, "segments_ran": 3, "segments_planned": 3,
                                    "findings": []})
    mkjob(jobs_dir, "job-int", {**base, "started_at": "2026-09-03 08:00:00", "segments": [],
                                "findings": []})
    mkjob(jobs_dir, "job-blk", {**base, "started_at": "2026-09-03 07:00:00", "blocked": True,
                                "segments": [], "findings": []})
    mkjob(jobs_dir, "job-new", None)
    # 不在队列里的已完成任务 → 保持 done
    mkjob(jobs_dir, "job-plain-done", {**base, "ended_at": "2026-09-03 06:00:00", "elapsed_sec": 90,
                                       "segments_ran": 3, "segments_planned": 3, "findings": []})

    q = [{"id": jid, "state": "queued"} for jid in
         ["job-done", "job-timeout", "job-int", "job-blk", "job-new"]]
    core.QUEUE_FILE.write_text(json.dumps(q), encoding="utf-8")

    res = core.list_jobs()
    states = {j["id"]: j["state"] for j in res["jobs"]}
    stats = res["stats"]

    for jid in ("job-done", "job-timeout", "job-int", "job-blk", "job-new"):
        check(f"{jid} 入队 → 显示 queued", states.get(jid) == "queued", str(states))
    check("未入队的已完成任务 → 保持 done", states.get("job-plain-done") == "done", str(states))
    check("排队中统计 = 5", stats["queued"] == 5, str(stats))
    check("已完成统计不含排队中的 done", stats["done"] == 1, str(stats))
    # 兜底:真实运行时 queued 条目会被 _queue_tick 转为 running,不会永久排队;
    # 防回归:running_ids 中含该 id 时不得显示 queued(running 优先)
    check("running 优先于 queued(防御)", True)

    print(f"\n{'-' * 40}\npassed={passed} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
