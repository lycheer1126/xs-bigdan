# -*- coding: utf-8 -*-
"""模块: 历史（runtime/outputs 报告归档浏览）。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import core

MODULE = {
    "key": "history",
    "title": "历史",
    "icon": "archive",
    "desc": "历史报告归档：runtime/outputs 下 report-*.md 浏览",
    "order": 2,
}

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("/reports")
def reports():
    return {"reports": core.list_reports()}


@router.get("/reports/{name}")
def report_content(name: str):
    content = core.read_report(name)
    if content is None:
        raise HTTPException(404, f"报告不存在: {name}")
    return {"name": name, "content": content}


@router.post("/open-outputs")
def open_outputs():
    return {"opened": core.open_dir("outputs")}
