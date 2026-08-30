# -*- coding: utf-8 -*-
"""模块: 任务管理（渗透测试任务卡片 + 实时日志 + 新建/续跑/停止/删除）。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import core

MODULE = {
    "key": "tasks",
    "title": "任务",
    "icon": "target",
    "desc": "渗透测试任务管理：新建 / 续跑 / 停止 / 删除，实时日志与证据浏览",
    "order": 1,
}

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


class NewTaskReq(BaseModel):
    url: str = Field(min_length=4, max_length=500)
    note: str = ""
    cookie: str = Field(default="", max_length=20000)
    intent: str = Field(default="", max_length=4000)
    job_timeout: int = Field(default=core.DEFAULT_JOB_TIMEOUT, ge=90, le=14400)
    segments: int = Field(default=core.DEFAULT_SEGMENTS, ge=1, le=10)


class ResumeReq(BaseModel):
    job_timeout: int = Field(default=core.DEFAULT_JOB_TIMEOUT, ge=90, le=14400)
    segments: int = Field(default=core.DEFAULT_SEGMENTS, ge=1, le=10)


class UserInputReq(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/{job_id}/input")
def submit_input(job_id: str, req: UserInputReq):
    """人工协作通道：提供线索（测试账号/授权确认/提示），续跑时注入 BRIEF。"""
    if not core.save_user_input(job_id, req.text):
        raise HTTPException(404, f"任务 {job_id} 不存在")
    return {"saved": True, "id": job_id}


@router.get("")
def list_all():
    """任务列表 + 统计面板数据。"""
    return core.list_jobs()


@router.post("")
def create_task(req: NewTaskReq):
    if not req.url.strip():
        raise HTTPException(400, "URL 不能为空")
    try:
        return core.start_task(req.url, req.note, req.job_timeout, req.segments,
                               req.cookie, req.intent)
    except ValueError as e:
        raise HTTPException(400, str(e))


class BatchTaskReq(BaseModel):
    urls_text: str = Field(min_length=1, max_length=50000)
    note: str = ""
    cookie: str = Field(default="", max_length=20000)
    intent: str = Field(default="", max_length=4000)
    job_timeout: int = Field(default=core.DEFAULT_JOB_TIMEOUT, ge=90, le=14400)
    segments: int = Field(default=core.DEFAULT_SEGMENTS, ge=1, le=10)


@router.post("/batch")
def batch_create(req: BatchTaskReq):
    """批量新建：每行一个 URL（可整批粘贴），自动生成 id，按粘贴顺序入队串行执行（绝不并行）。"""
    try:
        return core.enqueue_tasks(req.urls_text, req.note, req.job_timeout, req.segments,
                                  req.cookie, req.intent)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/queue/clear")
def queue_clear():
    """取消所有排队中任务（正在运行的不受影响）。"""
    return {"cancelled": core.clear_queue()}


@router.get("/{job_id}")
def detail(job_id: str):
    d = core.job_detail(job_id)
    if not d:
        raise HTTPException(404, f"任务 {job_id} 不存在")
    return d


@router.post("/{job_id}/resume")
def resume(job_id: str, req: ResumeReq):
    if not (core.JOBS_DIR / job_id).is_dir():
        raise HTTPException(404, f"任务 {job_id} 不存在断点")
    if job_id in core.running_pids():
        raise HTTPException(409, f"任务 {job_id} 已在运行")
    try:
        return core.resume_task(job_id, req.job_timeout, req.segments)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/{job_id}/stop")
def stop(job_id: str):
    ok = core.stop_job(job_id)
    if not ok:
        raise HTTPException(409, f"任务 {job_id} 未在运行")
    return {"id": job_id, "stopped": True}


@router.delete("/{job_id}")
def delete(job_id: str):
    """停止 + jobs/<id> 移回收站 + targets.txt 移除该行。"""
    return core.delete_task(job_id)


@router.get("/{job_id}/file")
def job_file(job_id: str, path: str = "BRIEF.md", tail: int = 0):
    """读 jobs/<id>/ 下任意文本文件（path 相对 job 目录）。"""
    if not (core.JOBS_DIR / job_id).is_dir():
        raise HTTPException(404, "任务不存在")
    if tail:
        p = (core.JOBS_DIR / job_id / path).resolve()
        try:
            p.relative_to((core.JOBS_DIR / job_id).resolve())
        except ValueError:
            raise HTTPException(400, "非法路径")
        return {"name": path, "content": core.tail_text(p, int(tail))}
    content = core.read_job_file(job_id, path)
    if content is None:
        raise HTTPException(404, f"文件不存在: {path}")
    return {"name": path, "content": content}


@router.get("/{job_id}/stdout")
def bigdan_stdout(job_id: str, tail: int = 150):
    """调度器(bigdan.py)自身 stdout 尾部。"""
    return {"name": "bigdan.out.log", "content": core.read_bigdan_stdout(job_id, int(tail))}


@router.post("/{job_id}/open-dir")
def open_job_dir(job_id: str):
    if not (core.JOBS_DIR / job_id).is_dir():
        raise HTTPException(404, "任务不存在")
    core.open_dir("jobs", job_id)
    return {"opened": job_id}
