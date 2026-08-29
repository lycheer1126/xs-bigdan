# -*- coding: utf-8 -*-
"""孤儿启动器：让 bigdan.py 脱离 webui 进程树。

用法: python _detached_spawn.py <out_log> <python> <script> [args...]

launcher 启动目标进程后立即打印其 PID 并退出。目标进程的父进程（本
launcher）随即消亡，目标进程成为孤儿——此后 taskkill /T 杀掉 webui
进程树不会连带终止任务进程（Windows 按 PPID 关系连杀，孤儿不在树内）。

out_log: 目标进程 stdout/stderr 的追加写入路径
"""
from __future__ import annotations

import os
import subprocess
import sys


def main() -> None:
    if len(sys.argv) < 4:
        sys.stderr.write("usage: _detached_spawn.py <out_log> <python> <script> [args...]\n")
        sys.exit(2)
    out_log, py, script = sys.argv[1], sys.argv[2], sys.argv[3]
    args = sys.argv[4:]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 项目根
    fp = open(out_log, "ab", buffering=0)
    p = subprocess.Popen(
        [py, script, *args],
        cwd=root,
        stdout=fp,
        stderr=subprocess.STDOUT,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    # 打印真实 PID 供 webui 登记 procs.json（launcher 退出后子进程成孤儿）
    print(p.pid, flush=True)


if __name__ == "__main__":
    main()
