# -*- coding: utf-8 -*-
"""模块: 任务分组（手动把目标归类，看板按组过滤展示）。

无 MODULE 元数据 → 不进入侧边栏导航，仅挂载 /api/groups 路由供任务页调用。
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import core

router = APIRouter(prefix="/api/groups", tags=["groups"])


class CreateGroupReq(BaseModel):
    name: str = Field(min_length=1, max_length=30)


class AssignReq(BaseModel):
    job_id: str = Field(min_length=1, max_length=120)
    group: str = Field(default="", max_length=30)


@router.get("")
def list_groups():
    """全部组 + 成员任务ID（按成员数降序）。"""
    return core.list_groups()


@router.post("")
def create_group(req: CreateGroupReq):
    try:
        return core.create_group(req.name)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{name}")
def delete_group(name: str):
    """删除组（成员任务变为未分组，不删除任务本身）。"""
    core.delete_group(name)
    return {"deleted": name}


@router.post("/assign")
def assign(req: AssignReq):
    """任务分入指定组；group 为空串 = 取消分组。一个任务唯一属于一组。"""
    if not (core.JOBS_DIR / req.job_id).is_dir():
        raise HTTPException(404, f"任务 {req.job_id} 不存在")
    try:
        core.assign_job(req.job_id, req.group)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"job_id": req.job_id, "group": req.group}
