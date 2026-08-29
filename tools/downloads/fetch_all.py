#!/usr/bin/env python3
"""批量下载 xs-bigdan 缺失工具(Windows amd64)。直连多轮重试 + 镜像回退。"""
import subprocess, time
from pathlib import Path

DL = Path(__file__).parent

JOBS = [
    ("ferox.zip", "https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-pc-windows-msvc-feroxbuster.zip"),
    ("jadx.zip",  "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip"),
    ("foundry.zip","https://github.com/foundry-rs/foundry/releases/download/v1.7.1/foundry_v1.7.1_win_amd64.zip"),
    ("strings.zip","https://download.sysinternals.com/files/Strings.zip"),
    ("ehole.zip", "https://github.com/EdgeSecurityTeam/EHole/releases/download/v3.1/EHole_windows_amd64.zip"),
]

def fetch(url: str, out: Path) -> bool:
    for attempt in range(6):
        r = subprocess.run(
            ["curl", "-fsSL", "--connect-timeout", "20", "--max-time", "300",
             "-o", str(out), url],
            capture_output=True)
        if r.returncode == 0 and out.stat().st_size > 0:
            return True
        print(f"  direct attempt {attempt+1} fail (rc={r.returncode})", flush=True)
        time.sleep(3)
    for mirror in ["https://gh.ddlc.top", "https://ghps.cc"]:
        r = subprocess.run(
            ["curl", "-fsSL", "--connect-timeout", "20", "--max-time", "400",
             "-o", str(out), f"{mirror}/{url}"],
            capture_output=True)
        if r.returncode == 0 and out.stat().st_size > 0:
            return True
        print(f"  mirror {mirror} fail (rc={r.returncode})", flush=True)
    return False

for name, url in JOBS:
    out = DL / name
    if out.exists() and out.stat().st_size > 0:
        print(f"[skip] {name} exists", flush=True)
        continue
    print(f"[fetch] {name}", flush=True)
    ok = fetch(url, out)
    print(f"[{'OK' if ok else 'FAIL'}] {name} {out.stat().st_size if out.exists() else 0}B", flush=True)

print("ALL_DONE", flush=True)
