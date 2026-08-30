#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""browser_probe.py — AI-friendly 无头浏览器工具（xs-bigdan 工具矩阵）

设计目标（补齐 HTTP 层看不见的前端面）：
- SPA 渲染后的真实 DOM、console 消息、XHR/fetch 请求（Vue chunk 枚举、
  __vue__.$parent、mock 登录、前端签名/加密分析全靠这三样）；
- 输出全部 JSON 化/结构化，模型一眼看到关键信号；
- 默认 headless chromium，无需额外二进制。

子命令:
  open <url>                打开页面：title / DOM 规模 / console / XHR / storage 键
  js <url> <expr>           打开页面后执行 JS 表达式，打印 JSON 结果
  chunks <url>              枚举页面加载的所有 JS 文件（含动态 chunk），可 --save 下载
  login <url> <user> <pass> mock 登录：填表提交，输出后续 XHR / storage / 跳转

示例:
  browser_probe.py open https://target.com/app --wait 3 --console 20 --xhr 30
  browser_probe.py js https://target.com/app "Object.keys(document.querySelector('#app').__vue__.$parent)"
  browser_probe.py chunks https://target.com/app --save js_dump/
  browser_probe.py login https://target.com/login user01 pass123 --wait 4

输出示例 (open):
  title: xxx | url: https://... | divs: 812 | scripts: 23
  console: [log] Vue Router 4.0 ...
  xhr: [200] GET https://target.com/api/user/info
  storage: localStorage: token, user_info | sessionStorage: (none)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


def _out(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=1))


def _pick_keys(d: dict) -> list:
    return sorted(str(k) for k in (d or {}).keys())


def _cookie_to_playwright(cookie: str, url: str) -> list:
    """'k=v; k2=v2' → playwright add_cookies 形参（按目标 url 定域）。"""
    from urllib.parse import urlparse
    u = urlparse(url)
    base = f"{u.scheme or 'https'}://{u.netloc}"
    out = []
    for part in (cookie or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k:
            out.append({"name": k, "value": v, "url": base})
    return out


def _run(sub: str, args) -> int:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-proxy-server", "--ignore-certificate-errors"])
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
            viewport={"width": 1440, "height": 900},
        )
        cookies = _cookie_to_playwright(getattr(args, "cookie", ""), args.url)
        if cookies:
            ctx.add_cookies(cookies)
        page = ctx.new_page()

        console_msgs: list = []
        xhrs: list = []
        page.on("console", lambda m: console_msgs.append(f"{m.type}: {m.text[:200]}"))

        def on_request(req):
            rtype = req.resource_type
            if rtype in ("xhr", "fetch"):
                xhrs.append({"method": req.method, "url": req.url})

        def on_response(resp):
            try:
                if resp.request.resource_type in ("xhr", "fetch"):
                    for x in xhrs:
                        if x["url"] == resp.url:
                            x["status"] = resp.status
                            break
            except Exception:  # noqa: BLE001
                pass

        page.on("request", on_request)
        page.on("response", on_response)

        try:
            page.goto(args.url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:  # noqa: BLE001
            print(f"[ERR] goto: {type(e).__name__}: {e}")
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except PWTimeout:
            pass
        if args.wait:
            page.wait_for_timeout(int(args.wait * 1000))

        if sub == "open":
            try:
                info = page.evaluate("""() => ({
                    title: document.title,
                    divs: document.querySelectorAll('div').length,
                    scripts: [...document.scripts].map(s => s.src).filter(Boolean),
                    forms: document.querySelectorAll('form').length,
                    inputs: [...document.querySelectorAll('input')].map(i => i.name || i.id || i.type),
                    links: [...document.querySelectorAll('a[href]')].slice(0, 50).map(a => a.href),
                    local_keys: Object.keys(localStorage || {}),
                    session_keys: Object.keys(sessionStorage || {}),
                })""")
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] evaluate: {e}")
                browser.close()
                return 1
            print(f"title: {info['title']} | url: {page.url} | divs: {info['divs']} | scripts: {len(info['scripts'])}")
            if info["forms"]:
                print(f"forms: {info['forms']} | inputs: {info['inputs'][:30]}")
            if info["links"]:
                print(f"links({len(info['links'])}): " + " ".join(info["links"][:15]))
            if info["local_keys"] or info["session_keys"]:
                print(f"storage: local={info['local_keys']} session={info['session_keys']}")
            if console_msgs:
                shown = console_msgs[: args.console or 20]
                print(f"console({len(console_msgs)} shown {len(shown)}):")
                for m in shown:
                    print("  " + m[:250])
            done = [x for x in xhrs if "status" in x]
            if done:
                shown = done[: args.xhr or 30]
                print(f"xhr({len(done)} shown {len(shown)}):")
                for x in shown:
                    print(f"  [{x.get('status', '?')}] {x['method']} {x['url'][:220]}")
            else:
                print("xhr: (none captured)")
            print(f"[scripts] {len(info['scripts'])} js loaded")

        elif sub == "js":
            try:
                result = page.evaluate(args.expr)
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] evaluate: {type(e).__name__}: {e}")
                browser.close()
                return 1
            print("=== result ===")
            if isinstance(result, (dict, list)):
                _out(result)
            else:
                print(result)

        elif sub == "chunks":
            try:
                info = page.evaluate("""() => [...document.scripts].map(s => s.src).filter(Boolean)""")
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] evaluate: {e}")
                browser.close()
                return 1
            print(f"js files: {len(info)}")
            for s in info:
                print("  " + s)
            if args.save:
                import urllib.request
                outdir = Path(args.save)
                outdir.mkdir(parents=True, exist_ok=True)
                saved = 0
                for i, s in enumerate(info):
                    try:
                        req = urllib.request.Request(s, headers={"User-Agent": "xs-bigdan/0.1"})
                        data = urllib.request.urlopen(req, timeout=15).read()
                        name = s.split("/")[-1].split("?")[0] or f"chunk{i}.js"
                        (outdir / name).write_bytes(data)
                        saved += 1
                    except Exception as e:  # noqa: BLE001
                        print(f"  [skip] {s}: {type(e).__name__}")
                print(f"[saved] {saved}/{len(info)} -> {outdir}")

        elif sub == "snow":
            payload_file = Path(__file__).resolve().parent.parent / "js" / "snow_eyes_inject.js"
            try:
                payload = payload_file.read_text(encoding="utf-8")
                raw = page.evaluate(payload)
                results = json.loads(raw) if isinstance(raw, str) else raw
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] snow: {type(e).__name__}: {e}")
                browser.close()
                return 1
            cats = {k: (len(v) if isinstance(v, list) else 1)
                    for k, v in results.items() if not k.startswith("_") and v}
            total = sum(cats.values())
            fw = (results.get("_meta") or {}).get("framework_version", "?")
            print(f"snow: {total} findings in {len(cats)} cats | framework: {fw} | "
                  + " ".join(f"{k}={n}" for k, n in sorted(cats.items(), key=lambda x: -x[1])[:8]))
            show = 0
            for k, v in results.items():
                if k.startswith("_") or not isinstance(v, list) or not v:
                    continue
                preview = [str(x)[:160] for x in v[:5]]
                print(f"  {k}({len(v)}): " + " | ".join(preview))
                show += 1
                if show >= 12:
                    print("  ...(其余类别见 --save 全量 JSON)")
                    break
            if args.save:
                out = Path(args.save)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(raw if isinstance(raw, str) else json.dumps(results, ensure_ascii=False, indent=2),
                               encoding="utf-8")
                print(f"[saved] {out}")

        elif sub == "login":
            try:
                info = page.evaluate("""() => ({
                    inputs: [...document.querySelectorAll('input')].map(i => ({
                        name: i.name, id: i.id, type: i.type, placeholder: i.placeholder || '' })),
                    forms: document.querySelectorAll('form').length,
                })""")
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] evaluate: {e}")
                browser.close()
                return 1
            print(f"inputs: {json.dumps(info['inputs'], ensure_ascii=False)[:500]}")
            filled = 0
            # 优先按 name/id 匹配；无 name/id 的 element-plus 输入框按位置填充
            text_inputs = [i for i in info["inputs"] if i["type"] in ("text", "email", "tel", "username", "number", "")]
            pwd_inputs = [i for i in info["inputs"] if i["type"] == "password"]
            filled = 0
            if text_inputs:
                sel = f"input[name='{text_inputs[0]['name']}']" if text_inputs[0]["name"] else "input[type='text']"
                try:
                    page.fill(sel, args.user, timeout=3000); filled += 1
                except Exception:
                    page.locator("input").first.fill(args.user, timeout=3000); filled += 1
            if pwd_inputs:
                sel = f"input[name='{pwd_inputs[0]['name']}']" if pwd_inputs[0]["name"] else "input[type='password']"
                try:
                    page.fill(sel, args.passwd, timeout=3000); filled += 1
                except Exception:
                    page.locator("input[type='password']").first.fill(args.passwd, timeout=3000); filled += 1
            print(f"filled: {filled} input(s)")
            # 找提交按钮
            try:
                clicked = page.evaluate("""() => {
                    const b = [...document.querySelectorAll('button, input[type=submit]')]
                        .find(x => /登录|login|submit|登 录/i.test(x.innerText || x.value || ''));
                    if (b) { b.click(); return b.outerHTML.slice(0, 120); }
                    return null;
                }""")
                print(f"submit clicked: {bool(clicked)}")
            except Exception as e:  # noqa: BLE001
                print(f"[ERR] submit: {e}")
            if args.wait:
                page.wait_for_timeout(int(args.wait * 1000))
            done = [x for x in xhrs if "status" in x and x["url"] != args.url]
            if done:
                print(f"post-login xhr({len(done)}):")
                for x in done[-args.xhr or 15:]:
                    print(f"  [{x.get('status', '?')}] {x['method']} {x['url'][:220]}")
            try:
                storage = page.evaluate("() => ({local: Object.keys(localStorage||{}), session: Object.keys(sessionStorage||{})})")
                if storage["local"] or storage["session"]:
                    print(f"storage: local={storage['local']} session={storage['session']}")
            except Exception:  # noqa: BLE001
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
                print(f"final url: {page.url}")
            except Exception:  # noqa: BLE001
                print(f"final url: {page.url}")

        browser.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AI-friendly headless browser tool")
    sub = ap.add_subparsers(dest="sub", required=True)

    for name, help_ in [
        ("open", "打开页面：title/DOM/console/XHR/storage"),
        ("js", "打开页面执行 JS 表达式"),
        ("chunks", "枚举页面全部 JS（含动态 chunk）"),
        ("login", "mock 登录流程"),
        ("snow", "雪瞳注入:26 类前端信息一次性提取(Vue路由/API/JWT/密钥/PII)"),
    ]:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("url")
        if name == "js":
            sp.add_argument("expr")
        if name == "login":
            sp.add_argument("user")
            sp.add_argument("passwd")
        sp.add_argument("--wait", type=float, default=2, help="加载后额外等待秒数")
        sp.add_argument("--cookie", default="", help="登录态 Cookie 'k=v; k2=v2'，注入后以该身份浏览")
        sp.add_argument("--console", type=int, default=20, help="console 显示条数")
        sp.add_argument("--xhr", type=int, default=30, help="xhr 显示条数")
        sp.add_argument("--save", help="chunks 保存目录")

    args = ap.parse_args()
    return _run(args.sub, args)


if __name__ == "__main__":
    sys.exit(main())
