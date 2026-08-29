# -*- coding: utf-8 -*-
"""xs-bigdan Web 控制台入口。

用法:
    python -m webui.server                 # http://127.0.0.1:8865
    python -m webui.server --port 9000
    python -m webui.server --host 0.0.0.0  # 仅局域网内多机查看时（注意无鉴权）

设计: 薄控制面 —— 只读 runtime/ 产物 + 子进程触发 bigdan.py CLI，
不复制 agent 逻辑；新模块见 routes/README。
"""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, routes

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="xs-bigdan console",
    version=__version__,
    description="本地 SRC 授权渗透测试 Agent 控制台（薄控制面，只读产物 + 触发 CLI）",
)


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """无鉴权本地控制台的 CSRF 防线：跨站页面无法触发停止/删除/续跑等写操作。

    浏览器同源请求带 Origin=http://127.0.0.1:8865（hostname=127.0.0.1）放行；
    恶意网页跨站 POST 带 Origin=https://evil.com 拒绝；无 Origin/Referer（curl 等）放行。
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin:
            host = (urlparse(origin).hostname or "").lower()
            if host not in ("127.0.0.1", "localhost", "::1"):
                return JSONResponse(
                    {"detail": f"跨站请求被拒绝（origin={host}）"}, status_code=403)
    return await call_next(request)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def no_cache_static(request, call_next):
    """静态资源禁止缓存：改前端代码后刷新即生效，不依赖强刷。"""
    resp = await call_next(request)
    if request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

for r in routes.ROUTERS:
    app.include_router(r)


@app.get("/api/modules")
def modules():
    """导航元数据：前端据此渲染左侧菜单并动态加载模块 js。"""
    return {"modules": routes.MODULES, "version": __version__}


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


def _start_queue_runner() -> None:
    """任务队列后台线程：每 3s 推进一次（对账死亡进程 + 串行启动下一个排队任务）。"""
    import threading
    import time

    def loop() -> None:
        while True:
            try:
                from . import core
                core._queue_tick()
            except Exception:  # noqa: BLE001 — 队列线程永不中断服务
                pass
            time.sleep(3)

    threading.Thread(target=loop, daemon=True, name="queue-runner").start()


def main() -> None:
    ap = argparse.ArgumentParser(description="xs-bigdan Web 控制台")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1，勿外网暴露）")
    ap.add_argument("--port", type=int, default=8865, help="监听端口（默认 8865；8765 被本机其它工具占用）")
    ap.add_argument("--reload", action="store_true", help="开发模式热重载")
    args = ap.parse_args()
    print(f"[webui] xs-bigdan console v{__version__} → http://{args.host}:{args.port}")
    _start_queue_runner()
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload, log_level="warning")


if __name__ == "__main__":
    main()
