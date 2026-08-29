# -*- coding: utf-8 -*-
"""模块注册表：自动扫描本目录下所有非 _ 开头的 .py，收集 MODULE 元数据 + router。

新增模块 = 在 routes/ 下新建一个 .py，定义：
    MODULE = {"key": "xxx", "title": "模块名", "icon": "svg 路径或 emoji", "desc": "一句话说明"}
    router = APIRouter(prefix="/api/xxx")
    router 里注册该模块全部 API 路由
再在 static/modules/ 下加同名前端 js 即可，无需改任何框架代码。
"""

from __future__ import annotations

import importlib
import pkgutil

MODULES: list[dict] = []
ROUTERS = []

for _m in pkgutil.iter_modules(__path__):
    if _m.name.startswith("_"):
        continue
    try:
        mod = importlib.import_module(f"{__name__}.{_m.name}")
    except Exception as e:  # noqa: BLE001 — 单个模块坏不影响控制台启动
        print(f"[webui] 模块 {_m.name} 加载失败: {e}")
        continue
    if getattr(mod, "MODULE", None):
        MODULES.append(mod.MODULE)
    if getattr(mod, "router", None):
        ROUTERS.append(mod.router)

MODULES.sort(key=lambda m: m.get("order", 99))
