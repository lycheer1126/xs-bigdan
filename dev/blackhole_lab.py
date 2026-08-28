#!/usr/bin/env python3
"""xs-bigdan 黑洞靶场：监听但永不响应，用于验证"每目标超时停止"。

Agent 对它的任何请求都会挂起直到段预算耗尽被 harness 强杀（exit 124），
调度器随即把目标标记 timed_out 并释放给下一个目标。

用法: python scripts/blackhole_lab.py [port]   （默认 18082）
"""

import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18082

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT))
s.listen(8)
s.settimeout(1)
print(f"[blackhole] listening on 127.0.0.1:{PORT} (accept & hold forever)", flush=True)
while True:
    try:
        conn, _ = s.accept()
    except socket.timeout:
        continue
    except KeyboardInterrupt:
        break
    # 收下连接但不回任何字节，让客户端挂起
    try:
        conn.settimeout(0.2)
        while True:
            try:
                if not conn.recv(65536):
                    break
            except socket.timeout:
                continue
            except OSError:
                break
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass
