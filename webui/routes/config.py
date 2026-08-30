# -*- coding: utf-8 -*-
"""模块: 配置（targets.txt 编辑 + 环境/工具状态）。"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import core

MODULE = {
    "key": "config",
    "title": "配置",
    "icon": "sliders",
    "desc": "目标清单 / 环境变量 / 工具链状态",
    "order": 3,
}

router = APIRouter(prefix="/api/config", tags=["config"])


class TargetsReq(BaseModel):
    text: str


class LlmProfileItem(BaseModel):
    name: str = ""
    key: str = ""
    key_env: str = ""
    base: str = ""
    provider: str = ""
    model: str = ""
    thinking: str = "medium"


class LlmProfilesReq(BaseModel):
    active: str = ""
    # typing.List 而非 list[]：服务器 Python 3.8 下 pydantic 求值注解会炸
    profiles: List[LlmProfileItem] = []


@router.get("")
def config():
    return core.config_view()


@router.put("/targets")
def save_targets(req: TargetsReq):
    core.save_targets_text(req.text)
    return {"saved": True}


@router.put("/credentials")
def save_credentials(req: TargetsReq):
    """测试账号池（credentials.txt）：[scope|]user|pass[|备注]，重跑任务自动注入 BRIEF。"""
    core.save_credentials_text(req.text)
    return {"saved": True, "count": core.credentials_count()}


@router.get("/llm")
def llm_config():
    return core.llm_profiles_view()


@router.put("/llm")
def save_llm(req: LlmProfilesReq):
    try:
        r = core.save_llm_profiles(
            req.active,
            [p.model_dump() for p in req.profiles],
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"saved": True, **r}


@router.post("/open-project")
def open_project():
    return {"opened": core.open_dir("outputs")}
