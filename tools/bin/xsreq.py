#!/usr/bin/env python3
"""req.py — AI-friendly HTTP 请求工具（xs-bigdan 工具矩阵）

设计目标（对齐"工具决定能看见什么"思想）：
- 把【状态码 | 耗时 | 响应长度 | Content-Type】放在第一行，模型一眼看到差异；
- 关键响应头 + body 摘录紧跟其后，同时支持 --save 保留原始请求与响应供证据用；
- 默认不走代理（--noproxy），避免本地代理干扰。

用法:
  req.py <url> [--method GET|POST|PUT|DELETE] [--data 'k=v&k2=v2'] [--json '{...}']
         [--header 'Name: value']... [--save out.txt] [--limit 1500] [--insecure]

示例:
  req.py http://example.com/api/user?id=1
  req.py http://example.com/api/login --method POST --json '{"user":"a","pass":"b"}'
  req.py http://example.com/admin --header 'X-Token: abc' --save ev.txt

输出示例:
  [200] 0.42s | 1234B | text/html
  Server: nginx/1.24 | Content-Type: text/html | X-Powered-By: PHP/7.4
  --- body (first 800 chars) ---
  ...
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-friendly HTTP request tool")
    ap.add_argument("url")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", help="表单数据 k=v&k2=v2")
    ap.add_argument("--json", help="JSON body")
    ap.add_argument("--header", action="append", default=[], help="请求头，可多次")
    ap.add_argument("--save", help="把原始请求+响应保存到文件")
    ap.add_argument("--limit", type=int, default=1500, help="body 摘录最大字符数")
    ap.add_argument("--insecure", action="store_true", help="跳过 SSL 验证")
    ap.add_argument("--follow", action="store_true", help="跟随重定向")
    args = ap.parse_args()

    url = args.url
    method = args.method.upper()
    headers = {"User-Agent": "xs-bigdan/0.1 (authorized pentest agent)"}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    body = None
    if args.json:
        body = args.json.encode()
        headers.setdefault("Content-Type", "application/json")
    elif args.data:
        body = args.data.encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    t0 = time.monotonic()
    status = 0
    resp_headers: dict = {}
    resp_body = b""
    final_url = url
    try:
        r = opener.open(req, timeout=15)
        status = r.status
        resp_headers = dict(r.headers.items())
        resp_body = r.read()
        final_url = r.geturl()
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers.items())
        resp_body = e.read()
    except Exception as e:  # noqa: BLE001
        print(f"[ERR] {type(e).__name__}: {e}")
        return 1
    elapsed = time.monotonic() - t0

    # 第一行：核心信号
    print(f"[{status}] {elapsed:.2f}s | {len(resp_body)}B | {resp_headers.get('Content-Type', '-')}")
    if final_url != url:
        print(f"redirect_to: {final_url}")

    # 关键响应头（一行内并列）
    key_headers = ["Server", "Content-Type", "X-Powered-By", "Set-Cookie", "Location",
                   "WWW-Authenticate", "Access-Control-Allow-Origin", "Content-Length",
                   "X-Frame-Options", "Strict-Transport-Security", "Via", "X-Forwarded-For"]
    shown = [f"{k}: {resp_headers[k]}" for k in key_headers if k.lower() in {x.lower() for x in resp_headers}]
    if shown:
        print(" | ".join(shown))

    # body 摘录
    try:
        text = resp_body.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        text = resp_body.hex()[:200]
    limit = args.limit
    if len(text) > limit:
        print(f"--- body (first {limit} chars of {len(text)}) ---")
        print(text[:limit])
        print("...(truncated)")
    else:
        print("--- body ---")
        print(text)

    # 保存原始请求+响应（证据用）
    if args.save:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        req_dump = f"{method} {url}\n" + "".join(f"{k}: {v}\n" for k, v in headers.items())
        if body:
            req_dump += "\n" + body.decode("utf-8", errors="replace")
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(f"# saved by req.py at {ts}\n# status={status} elapsed={elapsed:.2f}s len={len(resp_body)}\n\n")
            f.write("=== REQUEST ===\n" + req_dump + "\n\n")
            f.write("=== RESPONSE HEADERS ===\n" + "".join(f"{k}: {v}\n" for k, v in resp_headers.items()) + "\n")
            f.write("=== RESPONSE BODY ===\n" + text + "\n")
        print(f"[saved] {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
