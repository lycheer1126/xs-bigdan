#!/usr/bin/env python3
"""xs-bigdan 冒烟测试靶场：本地模拟站点，用于验证端到端闭环。

内置两个"漏洞"（都可被黑盒 agent 发现）：
1. 未授权访问: /admin 返回 401，但 401 页面 HTML 注释里泄露 token=letmein，带上即可进入管理页。
2. IDOR/未授权API: /api/user?id=N 无鉴权返回任意用户数据（含手机号/secret）。

用法: python scripts/smoke_lab.py [port]   （默认 18080）
"""

import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静默
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "Demo-Framework/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path == "/":
            self._send(200, b'<html><title>Demo App</title><body><h1>Demo App v1.0</h1><a href="/admin">Admin</a></body></html>', "text/html")
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        elif path == "/admin":
            if qs.get("token") == ["letmein"]:
                body = b'<html><h1>Admin Panel</h1><pre>user api: /api/user?id=N (no auth)</pre></html>'
                self._send(200, body, "text/html")
            else:
                body = b'<html><!-- token=letmein --><h1>401 Unauthorized</h1></html>'
                self._send(401, body, "text/html")
        elif path.startswith("/api/user"):
            uid = qs.get("id", ["1"])[0]
            data = {"id": uid, "name": "user-" + uid, "phone": "1380000" + uid.zfill(4), "secret": "demo-secret-" + uid}
            self._send(200, json.dumps(data).encode(), "application/json")
        else:
            self._send(404, b"<html>404 Not Found</html>", "text/html")


if __name__ == "__main__":
    print(f"[smoke_lab] listening on http://127.0.0.1:{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
