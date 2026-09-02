# -*- coding: utf-8 -*-
"""模块: 有效标记（标注哪些任务/漏洞类型被 SRC 确认有效，卡片点亮绿色）。

无 MODULE 元数据 → 不进入侧边栏导航，仅挂载 /api/marks 路由。
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import core

router = APIRouter(prefix="/api/marks", tags=["marks"])


class ToggleReq(BaseModel):
    job_id: str = Field(min_length=1, max_length=120)
    scope: str = Field(default="task", pattern="^(task|vuln)$")
    key: str = Field(default="", max_length=100)


@router.get("")
def list_all():
    """全部有效标记（任务级✓ + 漏洞类型点亮）。"""
    return core.list_marks()


@router.post("/toggle")
def toggle(req: ToggleReq):
    try:
        return core.toggle_mark(req.job_id, req.scope, req.key)
    except ValueError as e:
        raise HTTPException(400, str(e))
