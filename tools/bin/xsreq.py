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
import socket
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
    ap.add_argument("--timeout", type=int, default=15, help="单次请求超时秒")
    ap.add_argument("--retry", type=int, default=2, help="连接失败/超时自动重试次数（连接重置/限速场景；服务器有响应的 4xx/5xx 不重试）")
    ap.add_argument("--retry-wait", type=float, default=2.0, help="重试基础等待秒（指数退避 x2，封顶 15s）")
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

    t0 = time.monotonic()
    status = 0
    resp_headers: dict = {}
    resp_body = b""
    final_url = url
    attempts = 0
    last_err: Exception = None
    while attempts <= max(0, args.retry):
        attempts += 1
        # Request 不可复用（body 流已消费），每次尝试新建
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            r = opener.open(req, timeout=args.timeout)
            status = r.status
            resp_headers = dict(r.headers.items())
            resp_body = r.read()
            final_url = r.geturl()
            last_err = None
            break
        except urllib.error.HTTPError as e:
            # 服务器有响应：4xx/5xx 是目标的行为信号，直接返回，不重试
            status = e.code
            resp_headers = dict(e.headers.items())
            resp_body = e.read()
            last_err = None
            break
        except OSError as e:
            # 连接重置/拒绝/超时/解析失败（URLError/ConnectionResetError/timeout 均为 OSError 子类）
            last_err = e
            if attempts > args.retry:
                break
            wait = min(15.0, args.retry_wait * (2 ** (attempts - 1)))
            print(f"[retry {attempts}/{args.retry}] {type(e).__name__}: {e} -> {wait:.1f}s 后重试",
                  file=sys.stderr, flush=True)
            time.sleep(wait)
    elapsed = time.monotonic() - t0
    if last_err is not None:
        print(f"[ERR] {type(last_err).__name__}: {last_err} (已重试 {attempts - 1} 次)")
        return 1

    lower_headers = {k.lower(): v for k, v in resp_headers.items()}
    # 第一行：核心信号（发生过重试时追加标记，模型可感知"该路径不稳"）
    ct = lower_headers.get('content-type', '-')
    print(f"[{status}] {elapsed:.2f}s | {len(resp_body)}B | {ct}"
          + (f" | retried={attempts - 1}" if attempts > 1 else ""))
    if final_url != url:
        print(f"redirect_to: {final_url}")

    # 关键响应头（一行内并列）
    key_headers = ["Server", "Content-Type", "X-Powered-By", "Set-Cookie", "Location",
                   "WWW-Authenticate", "Access-Control-Allow-Origin", "Content-Length",
                   "X-Frame-Options", "Strict-Transport-Security", "Via", "X-Forwarded-For"]
    shown = [f"{k}: {lower_headers[k.lower()]}" for k in key_headers if k.lower() in lower_headers]
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
