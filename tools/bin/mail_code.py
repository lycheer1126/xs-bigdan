#!/usr/bin/env python3
r"""mail.tm 临时邮箱接码助手（无 API key，纯标准库）

用法:
  mail_code.py create                         # 建邮箱 → 输出 address/password/token
  mail_code.py list   --address A --password P   # 列收件箱
  mail_code.py poll   --address A --password P [--timeout 180] [--regex '\b\d{4,8}\b']
                                              # 轮询等验证码 → 输出 code
"""
import argparse, json, random, re, string, sys, time
import urllib.request, urllib.error

BASE = "https://api.mail.tm"

def _req(method, path, token=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}
    except Exception as e:
        return -1, {"error": str(e)}

def _members(d):
    if isinstance(d, list):
        return d
    return d.get("hydra:member") or d.get("member") or []

def get_domain():
    st, d = _req("GET", "/domains")
    ms = _members(d)
    if st != 200 or not ms:
        raise SystemExit(f"拉域名失败({st}): {json.dumps(d, ensure_ascii=False)[:200]}")
    return ms[0]["domain"]

def login(address, password):
    st, tok = _req("POST", "/token", body={"address": address, "password": password})
    if st != 200 or "token" not in tok:
        raise SystemExit(f"登录失败({st}): {json.dumps(tok, ensure_ascii=False)[:200]}")
    return tok["token"]

def extract_code(text, regex):
    m = re.search(r"\b\d{6}\b", text)          # 优先 6 位
    if m:
        return m.group(0)
    m = re.search(regex, text)
    if m:
        return m.group(0)
    return None

def cmd_create(_args):
    domain = get_domain()
    prefix = "user_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    address = f"{prefix}@{domain}"
    password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    st, d = _req("POST", "/accounts", body={"address": address, "password": password})
    if st not in (200, 201):
        raise SystemExit(f"建账号失败({st}): {json.dumps(d, ensure_ascii=False)[:200]}")
    token = login(address, password)
    print(json.dumps({"address": address, "password": password, "token": token, "domain": domain},
                     ensure_ascii=False, indent=2))

def cmd_list(args):
    token = login(args.address, args.password)
    st, msgs = _req("GET", "/messages", token=token)
    ms = _members(msgs)
    if not ms:
        print("收件箱为空")
        return
    for m in ms:
        frm = (m.get("from") or {}).get("address", "?")
        print(f"[{m.get('createdAt','')}] {frm} | {m.get('subject','')} | id={m.get('id')}")

def cmd_poll(args):
    token = login(args.address, args.password)
    deadline = time.time() + args.timeout
    wait = 3.0
    while time.time() < deadline:
        st, msgs = _req("GET", "/messages", token=token)
        ms = _members(msgs)
        if ms:
            subjects = []
            for m in ms:
                mid = m.get("id")
                st2, detail = _req("GET", f"/messages/{mid}", token=token)
                subjects.append(m.get("subject", ""))
                html = detail.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(html)
                text_all = "\n".join([
                    detail.get("text") or "", detail.get("intro") or "",
                    m.get("subject") or "", re.sub(r"<[^>]+>", " ", html),
                ])
                code = extract_code(text_all, args.regex)
                if code:
                    print(json.dumps({
                        "code": code,
                        "from": (m.get("from") or {}).get("address", ""),
                        "subject": m.get("subject", ""),
                        "message_id": mid,
                    }, ensure_ascii=False, indent=2))
                    return
            print(f"收到 {len(ms)} 封但未提取到验证码 subjects={subjects}", file=sys.stderr)
        time.sleep(wait)
        wait = min(wait * 1.5, 15.0)
    raise SystemExit(f"等待 {args.timeout}s 未收到验证码（目标站发信慢可加大 --timeout 重试，账号仍有效）")

def main():
    ap = argparse.ArgumentParser(description="mail.tm 接码助手")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create", help="创建临时邮箱")
    for name, fn in (("list", cmd_list), ("poll", cmd_poll)):
        p = sub.add_parser(name)
        p.add_argument("--address", required=True)
        p.add_argument("--password", required=True)
        if name == "poll":
            p.add_argument("--timeout", type=int, default=180)
            p.add_argument("--regex", default=r"\b\d{4,8}\b")
        p.set_defaults(fn=fn)
    sub.choices["create"].set_defaults(fn=cmd_create)
    args = ap.parse_args()
    args.fn(args)

if __name__ == "__main__":
    main()
