def _split_target(url: str) -> tuple:
    """URL → (path?query, host)。把绝对 URL 请求行还原成原始报文形态。"""
    m = re.match(r"[a-zA-Z]+://([^/]+)(/?.*)$", url or "")
    if m:
        return (m.group(2) or "/"), m.group(1)
    return (url or "/"), ""


def _assemble_raw(method: str, url: str, headers, body: str = "") -> str:
    """(方法, URL, 头列表, body) → 标准原始 HTTP 请求报文（请求行含路径，Host 单独成头）。"""
    from urllib.parse import urlsplit
    u = urlsplit(url or "")
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    host = u.netloc
    lines = [f"{method.upper()} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    for k, v in headers or []:
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def _curl_to_raw(curl: str) -> str:
    """curl 命令 → 原始 HTTP 请求报文（方法/-H 头/--data body/URL 解析；SRC 提交格式）。"""
    method = "GET"
    headers = []
    body = ""
    url = ""
    toks = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', curl or "")
    i = 0
    while i < len(toks):
        tk = toks[i].strip("\"'")
        low = tk.lower()
        if low in ("-x", "--request") and i + 1 < len(toks):
            method = toks[i + 1].strip("\"'").upper()
            i += 2
            continue
        if low in ("-h", "--header") and i + 1 < len(toks):
            hv = toks[i + 1].strip("\"'")
            if ":" in hv:
                k, _, v = hv.partition(":")
                headers.append((k.strip(), v.strip()))
            i += 2
            continue
        if low in ("-d", "--data", "--data-raw", "--data-binary", "--json") and i + 1 < len(toks):
            body = toks[i + 1]
            i += 2
            continue
        if tk.lower().startswith(("http://", "https://")) and not url:
            url = tk
        i += 1
    return _assemble_raw(method, url, headers, body)


def _raw_http_from_evidence(ev_text: str):
    """从 xsreq --save 证据还原 (原始请求报文, 原始响应报文)——SRC 提交格式的数据包来源。

    证据格式（xsreq --save）:
      # status=200 ...
      === REQUEST ===
      GET https://host/path
      头: 值...
      === RESPONSE HEADERS === ...
      === RESPONSE BODY === ...
    REQUEST 段为 curl 命令形态时走 _curl_to_raw 兜底。
    """
    req_raw, resp_raw = "", ""
    m = re.search(r"=== REQUEST ===\n(.*?)(?=\n?=== RESPONSE|\Z)", ev_text, re.S)
    if m:
        block = m.group(1).strip()
        parts = block.split("\n", 1)
        head_line = parts[0] if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        mm = re.match(r"([A-Z]+)\s+(\S+)", head_line)
        if mm and "curl" not in head_line:
            url = mm.group(2)
            hdrs = []
            for hl in rest.splitlines():
                if ":" in hl:
                    k, _, v = hl.partition(":")
                    hdrs.append((k.strip(), v.strip()))
            path, host = _split_target(url)
            lines = [f"{mm.group(1)} {path} HTTP/1.1", f"Host: {host}"]
            lines += [f"{k}: {v}" for k, v in hdrs]
            req_raw = "\n".join(lines)
        elif block.startswith("curl"):
            req_raw = _curl_to_raw(block.splitlines()[0])
    m2 = re.search(r"#\s*status=(\d+)", ev_text)
    status = m2.group(1) if m2 else "200"
    mh = re.search(r"=== RESPONSE HEADERS ===\n(.*?)(?=\n?=== RESPONSE BODY|\Z)", ev_text, re.S)
    mb = re.search(r"=== RESPONSE BODY ===\n(.*)\Z", ev_text, re.S)
    if mh or mb:
        headers = mh.group(1).strip() if mh else ""
        body = mb.group(1).strip() if mb else ""
        resp_raw = f"HTTP/1.1 {status}\n{headers}"
        if body:
            resp_raw += "\n\n" + body
    return req_raw, resp_raw


def _split_cookie_line(cookie_header: str) -> str:
    """Cookie 头过长时按 '; ' 折行展示（报告可读性）。"""
    return (";\n" + " " * 7).join(cookie_header.split("; "))
