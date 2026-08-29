#!/usr/bin/env python3
"""enum.py — 轻量目录/参数枚举（AI 友好版，对齐 ffuf 思想）

自动请求一个不存在的路径取 404 基线，把每个候选路径的状态码/长度/耗时
排成对比表，并【标出所有与基线显著不同的项】——模型一眼看到"多出来的节点"。

用法:
  enum.py <base-url> [--wordlist tools/wordlists/paths.txt] [--method GET]
          [--concurrency 8] [--timeout 8] [--limit 300] [--insecure]

示例:
  enum.py http://127.0.0.1:18080
  enum.py http://example.com --wordlist paths.txt --limit 100

输出:
  CODE  LEN    TIME   PATH          FLAG
  200   1234   0.01s  /             base
  404   162    0.00s  /nonexistent  baseline(404)
  401   60     0.00s  /admin        [!] 非404
  500   0      0.02s  /boom         [!] 非404
  ...
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _fetch(url: str, method: str, ctx: ssl.SSLContext, timeout: float, retries: int = 2) -> tuple:
    """连接失败(重置/超时)自动重试——间歇性重置的目标(qdedu 类)否则整表被误标异常。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    t0 = time.monotonic()
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "xs-bigdan/0.1 (authorized pentest agent)"})
        try:
            r = opener.open(req, timeout=timeout)
            body = r.read()
            return r.status, len(body), time.monotonic() - t0
        except urllib.error.HTTPError as e:
            body = e.read()
            return e.code, len(body), time.monotonic() - t0
        except Exception:  # noqa: BLE001 — 连接重置/超时,退避后重试
            time.sleep(min(2.0, 0.5 * (attempt + 1)))
    return 0, 0, time.monotonic() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-friendly path/param enumerator")
    ap.add_argument("base_url")
    ap.add_argument("--wordlist", default=None, help="候选路径文件（每行一个，支持 # 注释）")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--limit", type=int, default=300, help="最大测试条数")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    wl = args.wordlist or str(Path(__file__).resolve().parents[1] / "wordlists" / "paths.txt")
    if not Path(wl).is_file():
        print(f"[ERR] wordlist not found: {wl}", file=sys.stderr)
        return 1
    words = [ln.strip() for ln in Path(wl).read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.strip().startswith("#")][: args.limit]

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # 404 基线
    probe = f"{base}/__xsbd404_{random.randint(100000, 999999)}__"
    base_code, base_len, _ = _fetch(probe, args.method, ctx, args.timeout)

    print(f"=== enum {base} ({len(words)} paths, 404-baseline={base_code}/{base_len}B) ===")
    print(f"CODE  LEN    TIME   PATH")

    rows: list[tuple] = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(_fetch, f"{base}/{w}", args.method, ctx, args.timeout): w for w in words}
        for fut in cf.as_completed(futs):
            w = futs[fut]
            code, length, elapsed = fut.result()
            flag = ""
            if code == 0:
                flag = "[net-err]"  # 连接失败(重试后仍不通): 单列,不计入异常
            elif w == "/":
                flag = "base"
            elif code != base_code and abs(length - base_len) > max(15, base_len * 0.15):
                flag = "[!] 异常"
            elif code != base_code:
                flag = "[!] 非404"
            elif abs(length - base_len) > max(15, base_len * 0.15):
                flag = "[!] 长度偏差"
            rows.append((code, length, elapsed, w, flag))

    # 异常优先，再按状态码；net-err 沉底(网络噪音不是发现)
    rows.sort(key=lambda r: (0 if (r[4] and r[4] != "[net-err]") else (2 if r[4] == "[net-err]" else 1), r[0]))
    n_abnormal = sum(1 for r in rows if r[4] and r[4] != "[net-err]")
    n_neterr = sum(1 for r in rows if r[4] == "[net-err]")
    for code, length, elapsed, w, flag in rows:
        print(f"{code:<5} {length:<6} {elapsed:.2f}s {w:<40} {flag}")

    print(f"--- {n_abnormal}/{len(rows)} 异常项（非404 或 长度偏离基线），优先看这些 ---"
          + (f" 另有 {n_neterr} 项连接失败(net-err,目标不稳/限速,建议 --concurrency 1 慢扫)" if n_neterr else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
