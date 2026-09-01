# -*- coding: utf-8 -*-
"""webui 项目交互层：纯函数，不依赖 FastAPI，便于测试与复用。

职责边界（延续 xs-bigdan 薄 harness 理念）：
- 只读 runtime/jobs、runtime/outputs 的产物数据（summary / runlog / digest / evidence / 日志）
- 通过子进程触发 bigdan.py 既有 CLI（新建 / 续跑 / 停止），不复制任何 agent 逻辑
- 所有删除走回收站；所有文件访问做路径越界校验
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
JOBS_DIR = PROJECT_ROOT / "runtime" / "jobs"
OUTPUTS_DIR = PROJECT_ROOT / "runtime" / "outputs"
TARGETS_FILE = PROJECT_ROOT / "targets.txt"
WEBUI_DIR = PROJECT_ROOT / "runtime" / ".webui"
PROCS_FILE = WEBUI_DIR / "procs.json"
QUEUE_FILE = WEBUI_DIR / "queue.json"
GROUPS_FILE = WEBUI_DIR / "groups.json"
BIGDAN_ENTRY = PROJECT_ROOT / "bigdan.py"

DEFAULT_JOB_TIMEOUT = 3600  # 与 bigdan.py 默认一致(60 分钟，真实目标侦察+验证以小时计)
DEFAULT_SEGMENTS = 3

# 任务队列（批量粘贴 → 串行执行）：webui 全局任意时刻最多一个 bigdan 子进程
_queue_lock = threading.RLock()

ALLOWED_FILE_ROOTS = {
    "jobs": JOBS_DIR,
    "outputs": OUTPUTS_DIR,
}


# ---------------------------------------------------------------- 基础工具

def safe_resolve(root_name: str, rel: str) -> Path | None:
    """把 rel 解析到指定根目录内，越界返回 None。"""
    root = ALLOWED_FILE_ROOTS.get(root_name)
    if root is None:
        return None
    try:
        p = (root / rel).resolve()
        p.relative_to(root.resolve())
        return p
    except (ValueError, OSError):
        return None


def read_text(path: Path, limit_chars: int | None = None) -> str:
    if not path.is_file():
        return ""
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return txt[:limit_chars] if limit_chars else txt


def tail_text(path: Path, n_lines: int = 200) -> str:
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n_lines:])
    except OSError:
        return ""


def to_recycle_bin(path: Path) -> bool:
    """删除任务目录：Windows 进回收站；POSIX 无回收站语义直接 rmtree（调用方已二次确认）。"""
    try:
        if os.name != "nt":
            import shutil as _sh
            _sh.rmtree(path, ignore_errors=True)
            return not path.exists()
        p = str(path).replace("'", "''")
        cmd = (
            "Add-Type -AssemblyName Microsoft.VisualBasic; "
            f"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory('{p}',"
            "'OnlyErrorDialogs','SendToRecycleBin')"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", cmd],
            capture_output=True, timeout=60,
        )
        return not path.exists()
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- 进程管理

def load_procs() -> dict:
    if not PROCS_FILE.is_file():
        return {}
    try:
        return json.loads(PROCS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_procs(procs: dict) -> None:
    WEBUI_DIR.mkdir(parents=True, exist_ok=True)
    PROCS_FILE.write_text(
        json.dumps(procs, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def pid_alive(pid: int) -> bool:
    """进程存活探测。Windows 用 tasklist；POSIX 用 signal 0 存在性探测——
    此函数是队列串行性的根基,坏一个平台就会误判 running=中断/双跑任务。"""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, timeout=15,
            ).stdout.decode("gbk", errors="replace")
            return str(pid) in out
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(pid, 0)  # 信号 0 = 只探存在性,不投递
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 进程存在,只是属主不是当前用户
    except OSError:
        return False


def running_pids() -> dict:
    """返回 {job_id: {pid, started_at, cmd}}，过滤掉已不存活的进程。"""
    procs = load_procs()
    total = len(procs)
    alive = {}
    for job_id, rec in list(procs.items()):
        if pid_alive(rec.get("pid", -1)):
            alive[job_id] = rec
        else:
            procs.pop(job_id, None)
    if len(procs) != total:  # 有死进程被清理（含全部死亡时 0 != N 仍触发）
        save_procs(procs)
    return alive


def spawn_bigdan(args: list[str], job_id: str) -> dict:
    """后台启动 bigdan.py 子进程并登记 procs.json。

    经 _detached_spawn.py 孤儿启动：bigdan 脱离 webui 进程树，
    taskkill /T 重启 webui 不会连带终止任务进程（曾因连杀丢失任务）。
    """
    WEBUI_DIR.mkdir(parents=True, exist_ok=True)
    out_log = WEBUI_DIR / f"bigdan-{job_id}.out.log"
    launcher = Path(__file__).resolve().parent / "_detached_spawn.py"
    lp = subprocess.Popen(
        [sys.executable, str(launcher), str(out_log), sys.executable, str(BIGDAN_ENTRY), *args],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    line = lp.stdout.readline() if lp.stdout else b""
    try:
        pid = int(line.strip())
    except (TypeError, ValueError):
        pid = lp.pid  # 兜底：launcher 未回报时登记其 pid（随后会失效）
    try:
        lp.wait(timeout=30)
    except subprocess.TimeoutExpired:
        lp.kill()
    rec = {
        "pid": pid,
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cmd": " ".join([sys.executable, "bigdan.py", *args]),
    }
    procs = load_procs()
    procs[job_id] = rec
    save_procs(procs)
    return rec


def _kill_tree_windows(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        capture_output=True, timeout=30,
    )


def _kill_tree_posix(pid: int) -> None:
    """杀进程树：bigdan 是孤儿进程（launcher 已退出），/proc 走 PPID 收集整棵子树。

    先杀叶子（node pi 及其 chromium），最后杀根，避免根死后子进程被 init 收养漏杀。
    """
    import time as _t
    tree: dict[int, list[int]] = {}
    for ent in Path("/proc").iterdir():
        if not ent.name.isdigit():
            continue
        try:
            stat = (ent / "stat").read_text(encoding="utf-8", errors="replace")
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            tree.setdefault(ppid, []).append(int(ent.name))
        except (OSError, ValueError, IndexError):
            continue
    order: list[int] = []
    stack = [pid]
    seen = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        order.append(cur)
        stack.extend(tree.get(cur, []))
    import signal
    for p in reversed(order):  # 叶子→根
        try:
            os.kill(p, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    _t.sleep(0.3)


def stop_job(job_id: str) -> bool:
    """终止任务进程树（Windows taskkill /T；POSIX 走 /proc 子树 SIGKILL，
    连带 pi node 与其 chromium 子进程——打目标的进程绝不能留孤儿）。"""
    rec = running_pids().get(job_id)
    if not rec:
        return False
    try:
        if os.name == "nt":
            _kill_tree_windows(int(rec["pid"]))
        else:
            _kill_tree_posix(int(rec["pid"]))
    except Exception:  # noqa: BLE001
        pass
    procs = load_procs()
    procs.pop(job_id, None)
    save_procs(procs)
    return True


# ---------------------------------------------------------------- 任务数据

def _gen_job_id(url: str, seq: int = 0) -> str:
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    host = re.sub(r"[^0-9a-zA-Z.-]", "-", host)[:40]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"ui-{host}-{stamp}" + (f"-{seq}" if seq else "")


# ---------------------------------------------------------------- 任务队列（批量粘贴 → 串行执行）

def _load_queue() -> list[dict]:
    if QUEUE_FILE.is_file():
        try:
            data = json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return []


def _save_queue(q: list[dict]) -> None:
    WEBUI_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_FILE.write_text(json.dumps(q, ensure_ascii=False, indent=2), encoding="utf-8")


def _queue_busy() -> bool:
    """是否有任务在跑（存活子进程，或队列中标记 running 的条目）。"""
    if running_pids():
        return True
    return any(e.get("state") == "running" for e in _load_queue())


def parse_batch_lines(text: str) -> list[tuple[str, str]]:
    """批量粘贴解析：每行一个目标，返回 (url, note)。

    支持：裸 URL / [id|]url[|备注]（id 列被忽略，自动生成）/ 无协议补 https://。
    按 **host** 去重（本项目目标即 host 白名单，同 host 多 URL 只保留首次出现的行）；
    无有效 host 的行丢弃。
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split("|") if p.strip()]
        if not parts:
            continue
        url = next((p for p in parts if p.lower().startswith(("http://", "https://"))), "")
        if url:
            rest = [p for p in parts if p != url]
        else:
            url = parts[0]
            if not url.lower().startswith(("http://", "https://")):
                url = "https://" + url
            rest = parts[1:]
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
        if not host or ("." not in host and host != "localhost"
                        and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)):
            continue
        if host in seen:
            continue
        seen.add(host)
        out.append((url, rest[-1] if rest else ""))
    return out


def _spawn_queued(entry: dict) -> None:
    """启动一个队列条目对应的 bigdan 子进程并标记 running（调用方持有锁）。"""
    rec = spawn_bigdan(
        ["--targets", "targets.txt", "--only", entry["id"],
         "--job-timeout", str(entry.get("job_timeout") or DEFAULT_JOB_TIMEOUT),
         "--segments", str(entry.get("segments") or DEFAULT_SEGMENTS)],
        entry["id"],
    )
    entry["state"] = "running"
    entry["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry["pid"] = rec.get("pid")


def _queue_tick() -> dict:
    """队列推进（后台线程每 3s 调用）：对账死亡进程 + 串行启动下一个。

    串行保证：存在存活 bigdan 子进程或 running 队列条目时，绝不启动新任务。
    webui 重启后队列自动恢复（queue.json 持久化；进程消失的 running 条目对账为 done）。
    """
    started = None
    with _queue_lock:
        q = _load_queue()
        procs = running_pids()
        changed = False
        for e in q:
            if e.get("state") == "running" and e["id"] not in procs:
                e["state"] = "done"
                e["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                changed = True
        if not procs and not any(e.get("state") == "running" for e in q):
            nxt = next((e for e in q if e.get("state") == "queued"), None)
            if nxt:
                _spawn_queued(nxt)
                changed = True
                started = nxt["id"]
        if changed:
            _save_queue(q)
        # 防膨胀：done 条目超过 100 条时只保留最近 50 条
        done = [e for e in q if e.get("state") == "done"]
        if len(done) > 100:
            _save_queue([e for e in q if e.get("state") != "done"] + done[-50:])
    return {"started": started}


def _write_job_auth(job_dir: Path, host: str, cookie: str, intent: str, scope_by_host: bool) -> None:
    """建任务时落盘人工提供的登录态与意图。

    cookies.txt 每行 `[host|]cookie`：scope_by_host=True 时为无前缀行自动加 host
    （批量多目标防 cookie 串站泄露）；凭证只进 job 目录（gitignored），不进
    queue.json / targets.txt。
    """
    ck_lines = []
    for raw in (cookie or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        head, sep, rest = s.partition("|")
        scope = head.lower().split(":")[0]  # 容忍用户自带 host:port 前缀
        if (sep and "=" not in head
                and re.fullmatch(r"[A-Za-z0-9.\-]+", head or "")
                and ("." in scope or scope == "localhost")):
            ck_lines.append(s)  # 用户自带 host 前缀，原样保留（bigdan 端按 host 过滤）
        elif scope_by_host:
            ck_lines.append(f"{host}|{s}")
        else:
            ck_lines.append(s)
    if ck_lines:
        (job_dir / "cookies.txt").write_text("\n".join(ck_lines) + "\n", encoding="utf-8")
    if (intent or "").strip():
        (job_dir / "intent.md").write_text(intent.strip() + "\n", encoding="utf-8")


def enqueue_tasks(urls_text: str, note: str = "", job_timeout: int = DEFAULT_JOB_TIMEOUT,
                  segments: int = DEFAULT_SEGMENTS, cookie: str = "", intent: str = "") -> dict:
    """批量新建任务：每行一个 URL 自动生成 id，按粘贴顺序入队，串行执行（绝不并行）。"""
    lines = parse_batch_lines(urls_text)
    if not lines:
        raise ValueError("没有解析到有效 URL（每行一个，http(s):// 或域名）")
    created: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _queue_lock:
        q = _load_queue()
        for i, (url, n) in enumerate(lines):
            job_id = _gen_job_id(url, seq=i)
            upsert_target_line(job_id, url, (n or note).strip())
            jd = JOBS_DIR / job_id
            jd.mkdir(parents=True, exist_ok=True)
            (jd / "evidence").mkdir(parents=True, exist_ok=True)
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
            _write_job_auth(jd, host, cookie, intent, scope_by_host=True)
            q.append({"id": job_id, "url": url, "note": (n or note).strip(),
                      "state": "queued", "src": "batch",
                      "job_timeout": max(90, int(job_timeout)),
                      "segments": max(1, int(segments)),
                      "enqueued_at": now})
            created.append(job_id)
        _save_queue(q)
    tick = _queue_tick()  # 空闲时立即启动第一个
    return {"created": len(created), "ids": created, "first_started": tick.get("started")}


def clear_queue() -> int:
    """取消所有排队中的任务（运行中的不受影响），并清理其空目录与 targets 登记行。"""
    cancelled: list[dict] = []
    with _queue_lock:
        q = _load_queue()
        keep = []
        for e in q:
            (cancelled if e.get("state") == "queued" else keep).append(e)
        if cancelled:
            _save_queue(keep)
    for e in cancelled:
        remove_target_line(e["id"])
        d = JOBS_DIR / e["id"]
        if d.is_dir() and not (d / "summary.json").is_file():
            shutil.rmtree(d, ignore_errors=True)
    return len(cancelled)


def read_targets_text() -> str:
    if not TARGETS_FILE.is_file():
        return ""
    return read_text(TARGETS_FILE)


CREDENTIALS_FILE = PROJECT_ROOT / "credentials.txt"


def read_credentials_text() -> str:
    if not CREDENTIALS_FILE.is_file():
        return ""
    return read_text(CREDENTIALS_FILE)


def save_credentials_text(text: str) -> None:
    CREDENTIALS_FILE.write_text(text, encoding="utf-8")


def credentials_count() -> int:
    """有效账号行数（非注释、字段≥2）。"""
    n = 0
    for ln in read_credentials_text().splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if len([p for p in s.split("|") if p.strip()]) >= 2:
            n += 1
    return n


def upsert_target_line(job_id: str, url: str, note: str) -> None:
    """targets.txt 按 id 行覆盖/追加（保留注释与其他行）。"""
    text = read_targets_text()
    new_line = f"{job_id}|{url}|{note}"
    lines = text.splitlines() if text.strip() else []
    replaced = False
    out = []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and s.split("|", 1)[0].strip() == job_id:
            out.append(new_line)
            replaced = True
        else:
            out.append(ln)
    if not replaced:
        out.append(new_line)
    TARGETS_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")


def remove_target_line(job_id: str) -> None:
    text = read_targets_text()
    if not text.strip():
        return
    out = [
        ln for ln in text.splitlines()
        if not (ln.strip() and not ln.strip().startswith("#")
                and ln.strip().split("|", 1)[0].strip() == job_id)
    ]
    TARGETS_FILE.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")


def start_task(url: str, note: str = "", job_timeout: int = DEFAULT_JOB_TIMEOUT,
               segments: int = DEFAULT_SEGMENTS, cookie: str = "", intent: str = "") -> dict:
    """新建任务：登记 targets.txt；空闲立即启动，繁忙自动入队（串行，绝不并行）。"""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    if not host:
        raise ValueError("URL 缺少主机名（host），例如 https://example.com")
    job_id = _gen_job_id(url)
    upsert_target_line(job_id, url, note.strip())
    # 先建目录：详情接口依赖 jobs/<id> 存在，子进程 mkdir 有延迟，
    # 否则创建后立刻点详情会 404「任务不存在」（bigdan.py 的 mkdir 幂等）。
    (JOBS_DIR / job_id).mkdir(parents=True, exist_ok=True)
    (JOBS_DIR / job_id / "evidence").mkdir(parents=True, exist_ok=True)
    _write_job_auth(JOBS_DIR / job_id, host.lower(), cookie, intent, scope_by_host=False)
    entry = {"id": job_id, "url": url, "note": note.strip(), "src": "single",
             "job_timeout": max(90, int(job_timeout)), "segments": max(1, int(segments))}
    with _queue_lock:
        q = _load_queue()
        if _queue_busy():
            entry.update({"state": "queued", "enqueued_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            q.append(entry)
            _save_queue(q)
            return {"id": job_id, "url": url, "note": note.strip(), "queued": True,
                    "queue_len": sum(1 for e in q if e.get("state") == "queued")}
        rec = spawn_bigdan(
            ["--targets", "targets.txt", "--only", job_id,
             "--job-timeout", str(entry["job_timeout"]),
             "--segments", str(entry["segments"])],
            job_id,
        )
        entry.update({"state": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        q.append(entry)
        _save_queue(q)
    return {"id": job_id, "url": url, "note": note.strip(), "queued": False, "proc": rec}


def resume_task(job_id: str, job_timeout: int = DEFAULT_JOB_TIMEOUT,
                segments: int = DEFAULT_SEGMENTS) -> dict:
    """断点续跑；有任务在跑时自动入队串行执行。"""
    if not _target_registered(job_id):
        raise ValueError(
            f"任务 {job_id} 未在 targets.txt 中登记（可能已删除），"
            "请用「新建任务」重新提交或手动补一行")
    entry = {"id": job_id, "url": "", "note": "续跑", "src": "resume",
             "job_timeout": max(90, int(job_timeout)), "segments": max(1, int(segments))}
    with _queue_lock:
        q = _load_queue()
        if _queue_busy():
            entry.update({"state": "queued", "enqueued_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            q.append(entry)
            _save_queue(q)
            return {"id": job_id, "queued": True}
        rec = spawn_bigdan(
            ["--targets", "targets.txt", "--only", job_id,
             "--job-timeout", str(entry["job_timeout"]),
             "--segments", str(entry["segments"])],
            job_id,
        )
        entry.update({"state": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        q.append(entry)
        _save_queue(q)
    return {"id": job_id, "queued": False, "proc": rec}


def _target_registered(job_id: str) -> bool:
    for ln in read_targets_text().splitlines():
        s = ln.strip()
        if s and not s.startswith("#") and s.split("|", 1)[0].strip() == job_id:
            return True
    return False


def delete_task(job_id: str) -> dict:
    """停止进程 + 移出队列（若在排队）+ jobs/<id> 移回收站 + targets.txt 移除该行。"""
    stop_job(job_id)
    with _queue_lock:
        q = _load_queue()
        q2 = [e for e in q if e.get("id") != job_id]
        if len(q2) != len(q):
            _save_queue(q2)
    job_dir = JOBS_DIR / job_id
    trashed = False
    if job_dir.is_dir():
        trashed = to_recycle_bin(job_dir)
    remove_target_line(job_id)
    return {"id": job_id, "trashed": trashed}


def _classify(job_id: str, summary: dict | None, running_ids: set) -> str:
    if job_id in running_ids:
        return "running"
    if summary and summary.get("blocked"):
        return "blocked"
    if summary and summary.get("ended_at"):
        return "timed_out" if summary.get("timed_out") else "done"
    if summary and (summary.get("started_at") or summary.get("segments")):
        return "interrupted"
    return "created"


# ---------------------------------------------------------------- 任务分组（手动归类，看板按组过滤）

_groups_lock = threading.RLock()
_RESERVED_GROUP_NAMES = ("全部", "未分组")


def _load_groups_raw() -> dict:
    if GROUPS_FILE.is_file():
        try:
            return json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_groups_raw(data: dict) -> None:
    WEBUI_DIR.mkdir(parents=True, exist_ok=True)
    GROUPS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def list_groups() -> dict:
    """全部组 + 成员任务ID列表（按成员数降序，便于看板展示）。"""
    raw = _load_groups_raw().get("groups") or {}
    items = []
    for k, v in raw.items():
        if not isinstance(v, list):
            continue  # groups.json 被手工改坏时跳过，不崩看板
        alive = [i for i in v if (JOBS_DIR / i).is_dir()]
        items.append({"name": k, "jobs": alive, "count": len(alive)})
    items.sort(key=lambda g: -g["count"])
    return {"groups": items}


def create_group(name: str) -> dict:
    name = (name or "").strip()
    if not name or len(name) > 30:
        raise ValueError("组名需为 1-30 个字符")
    if name in _RESERVED_GROUP_NAMES:
        raise ValueError(f"「{name}」为保留词，不能用作组名")
    with _groups_lock:
        raw = _load_groups_raw()
        groups = raw.setdefault("groups", {})
        if name in groups:
            raise ValueError(f"组已存在: {name}")
        groups[name] = []
        _save_groups_raw(raw)
    return {"name": name, "count": 0}


def delete_group(name: str) -> None:
    with _groups_lock:
        raw = _load_groups_raw()
        groups = raw.setdefault("groups", {})
        if name in groups:
            del groups[name]
            _save_groups_raw(raw)


def assign_job(job_id: str, group: str) -> None:
    """任务放入指定组（一个任务唯一属于一组，重复分配自动换组）；group 为空 = 取消分组。"""
    if not valid_job_id(job_id):
        raise ValueError("非法任务 ID")
    group = (group or "").strip()
    if group and (len(group) > 30 or group in _RESERVED_GROUP_NAMES):
        raise ValueError("非法组名")
    with _groups_lock:
        raw = _load_groups_raw()
        groups = raw.setdefault("groups", {})
        for g, ids in groups.items():
            if job_id in ids:
                ids.remove(job_id)
        if group:
            groups.setdefault(group, []).append(job_id)
        _save_groups_raw(raw)


def group_of(job_id: str) -> str:
    """任务所属组名（未分组返回空串）。"""
    groups = _load_groups_raw().get("groups") or {}
    for g, ids in groups.items():
        if job_id in ids:
            return g
    return ""


def list_jobs() -> list[dict]:
    """扫描 runtime/jobs/，返回任务卡片数据（含统计分类计数）。"""
    running = set(running_pids().keys())
    with _queue_lock:
        queued_ids = {e["id"] for e in _load_queue() if e.get("state") == "queued"}
    jobs = []
    if JOBS_DIR.is_dir():
        for d in sorted(JOBS_DIR.iterdir(), reverse=True):
            if not d.is_dir() or d.name.startswith("."):
                continue
            summary = None
            sf = d / "summary.json"
            if sf.is_file():
                try:
                    summary = json.loads(sf.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    summary = None
            state = _classify(d.name, summary, running)
            if state in ("created", "interrupted") and d.name in queued_ids:
                state = "queued"  # 已入队待跑（排队中的新任务 / 排队等待续跑的断点）
            if state == "created" and summary is None:
                # 无 summary 但有运行痕迹 → 曾启动后被中断（段未写完 summary）
                has_trace = (d / "BRIEF.md").is_file() or (d / "runlog.jsonl").is_file()
                if has_trace:
                    state = "interrupted"
            findings = summary.get("findings", []) if summary else []
            by_status: dict[str, int] = {}
            by_type: dict[str, int] = {}
            for f in findings:
                st = f.get("status", "CONFIRMED")
                by_status[st] = by_status.get(st, 0) + 1
                t = f.get("type", "?")
                by_type[t] = by_type.get(t, 0) + 1
            # 异常退出段统计（exit=1 等，排除超时 124/正常 0/未启动 None）——LLM 限流/崩溃可见化
            err_segs = [s for s in ((summary or {}).get("segments") or [])
                        if s.get("exit_code") is not None and s.get("exit_code") not in (0, 124, 127)]
            last_error = next((s.get("last_error") for s in reversed(err_segs)
                               if s.get("last_error")), "")
            url = (summary or {}).get("url", "")
            note = (summary or {}).get("note", "")
            if not url or not note:  # 中断/排队任务无 summary → BRIEF.md 回退
                bu, bn = _brief_meta(d)
                url = url or bu
                note = note or bn
            jobs.append({
                "id": d.name,
                "state": state,
                "url": url,
                "note": note,
                "group": group_of(d.name),
                "started_at": (summary or {}).get("started_at", ""),
                "ended_at": (summary or {}).get("ended_at", ""),
                "elapsed_sec": (summary or {}).get("elapsed_sec"),
                "segments_ran": (summary or {}).get("segments_ran"),
                "segments_planned": (summary or {}).get("segments_planned"),
                "early_stop": bool(summary and summary.get("early_stop")),
                "blocked": bool(summary and summary.get("blocked")),
                "blocked_hours": _blocked_hours(d) if (summary or {}).get("blocked") else None,
                "has_user_input": (d / "user_input.md").is_file(),
                "findings_count": len(findings),
                "findings_by_status": by_status,
                "findings_by_type": by_type,
                "errors": len(err_segs),
                "last_error": last_error,
                "phase": _last_phase(d),
                "has_brief": (d / "BRIEF.md").is_file(),
                "has_digest": len(list(d.glob("digest-*.md"))) > 0,
                "evidence_count": len(list((d / "evidence").glob("*.txt")))
                if (d / "evidence").is_dir() else 0,
                "runlog_count": _runlog_count(d),
            })
    stats = {
        "total": len(jobs),
        "running": sum(1 for j in jobs if j["state"] == "running"),
        "blocked": sum(1 for j in jobs if j["state"] == "blocked"),
        "done": sum(1 for j in jobs if j["state"] == "done"),
        "timed_out": sum(1 for j in jobs if j["state"] == "timed_out"),
        "interrupted": sum(1 for j in jobs if j["state"] == "interrupted"),
        "findings": sum(j["findings_count"] for j in jobs),
        "errors": sum(j["errors"] for j in jobs),
        "queued": sum(1 for j in jobs if j["state"] == "queued"),
    }
    return {"stats": stats, "jobs": jobs}


def _brief_meta(job_dir: Path) -> tuple[str, str]:
    """从 BRIEF.md 回退读 目标URL/备注。

    summary.json 只在 run_target 跑完时才落盘，中断/排队任务没有——
    卡片上 url/note 会空白；而 BRIEF.md 在任务创建时就写入且每段重写
    时这两行不变，适合做回退源。
    """
    bf = job_dir / "BRIEF.md"
    if not bf.is_file():
        return "", ""
    try:
        text = bf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", ""
    mu = re.search(r"(?m)^-\s*目标\s*URL:\s*`?([^`\n]+?)`?\s*$", text)
    mn = re.search(r"(?m)^-\s*备注:\s*(.*)$", text)
    url = mu.group(1).strip() if mu else ""
    note = mn.group(1).strip() if mn else ""
    return url, note


def _blocked_hours(job_dir: Path):
    """BLOCKED 挂起小时数:runlog 最新 blocked 事件 ts 距现在(无事件返回 None)。"""
    f = job_dir / "runlog.jsonl"
    if not f.is_file():
        return None
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for ln in reversed(lines):
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if rec.get("type") == "blocked":
            ts = rec.get("ts") or ""
            try:
                dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return None
            return round((datetime.now() - dt).total_seconds() / 3600, 1)
    return None


def task_report(job_id: str) -> dict | None:
    """按任务域名找最新报告(outputs 序号化 00-站点.md),无则 None。"""
    host = ""
    sf = JOBS_DIR / job_id / "summary.json"
    if sf.is_file():
        try:
            s = json.loads(sf.read_text(encoding="utf-8"))
            host = re.sub(r"^https?://", "", (s.get("url") or "")).split("/")[0].split(":")[0]
        except (OSError, json.JSONDecodeError):
            host = ""
    if not host:
        host = job_id.split("-")[0] if "-" in job_id else job_id
    best = None
    for p in OUTPUTS_DIR.glob("*.md"):
        m = re.match(r"^(\d{2,})-", p.name)
        if not m:
            continue
        if host and host not in p.name:
            continue
        key = (int(m.group(1)), p.stat().st_mtime)
        if best is None or key > best[0]:
            best = (key, p)
    if best is None:
        return None
    p = best[1]
    try:
        return {"name": p.name, "content": p.read_text(encoding="utf-8", errors="replace")}
    except OSError:
        return None


def generate_report(job_id: str = "") -> dict:
    """手动生成报告（修复:webui 停止/进程被杀时 main 未跑到报告生成,任务无报告）。

    job_id 指定单个任务(需有 summary.json);空 = 全部有 summary 的任务。
    返回 {"path": 报告相对路径, "jobs": 覆盖任务数}。
    """
    from core import report as report_mod  # 延迟导入,避免模块环(webui 包内无 report,须从项目根)

    jobs_dir = JOBS_DIR
    ids: list[str] = []
    if job_id:
        sf = jobs_dir / job_id / "summary.json"
        if not sf.is_file():
            raise ValueError(f"任务 {job_id} 无 summary.json(未跑完或目录不存在)")
        ids = [job_id]
    else:
        if jobs_dir.is_dir():
            for d in sorted(jobs_dir.iterdir(), reverse=True):
                if d.is_dir() and (d / "summary.json").is_file():
                    ids.append(d.name)
    if not ids:
        raise ValueError("没有可生成报告的任务(summary.json 不存在)")
    summaries = []
    for i in ids:
        try:
            s = json.loads((jobs_dir / i / "summary.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        s.setdefault("id", i)
        s.setdefault("url", _brief_meta(jobs_dir / i)[0] or i)
        summaries.append(s)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    # 序号化命名（与 bigdan.py main 一致）: {序号:02d}-{站点}{-备注}.md,去时间戳与 report- 前缀
    seq = 0
    for p in OUTPUTS_DIR.glob("*.md"):
        m = re.match(r"^(\d{2,})-", p.name)
        if m:
            seq = max(seq, int(m.group(1)))
    if len(summaries) == 1:
        host = re.sub(r"^https?://", "", (summaries[0].get("url") or "")).split("/")[0].split(":")[0]
        name = f"{seq + 1:02d}-{host or job_id}.md"
    else:
        name = f"{seq + 1:02d}-multi-{len(summaries)}.md"
    report_path = OUTPUTS_DIR / name
    report_mod.build_report(summaries, report_path, jobs_dir)
    return {"path": f"runtime/outputs/{name}", "jobs": len(summaries)}


def _last_phase(job_dir: Path) -> str | None:
    """最近一次 segment_start 记录的测试阶段（阶段状态机由 bigdan.py 判定并写入 runlog）。"""
    f = job_dir / "runlog.jsonl"
    if not f.is_file():
        return None
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for ln in reversed(lines):
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if rec.get("type") == "segment_start":
            return rec.get("phase") or None
    return None


def _runlog_count(job_dir: Path) -> int:
    f = job_dir / "runlog.jsonl"
    if not f.is_file():
        return 0
    try:
        return sum(1 for _ in f.open(encoding="utf-8", errors="replace"))
    except OSError:
        return 0


_JOB_ID_RE = re.compile(r"^[0-9a-zA-Z._-]{1,100}$")


def valid_job_id(job_id: str) -> bool:
    """job_id 仅允许安全字符且不含 '..'（防目录穿越到 jobs/ 之外）。"""
    if not job_id or ".." in job_id:
        return False
    return bool(_JOB_ID_RE.fullmatch(job_id))


def job_detail(job_id: str) -> dict:
    """任务详情：summary + findings + segments + runlog + digest + evidence + 日志文件。"""
    if not valid_job_id(job_id):
        return {}
    job_dir = JOBS_DIR / job_id
    if not job_dir.is_dir():
        return {}
    summary = {}
    sf = job_dir / "summary.json"
    if sf.is_file():
        try:
            summary = json.loads(sf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    runlog = []
    rf = job_dir / "runlog.jsonl"
    if rf.is_file():
        for ln in rf.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                runlog.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    digests = sorted(
        [p.name for p in job_dir.glob("digest-*.md")],
        key=lambda n: int(re.sub(r"\D", "", n) or 0),
    )
    sessions = sorted(
        [p.name for p in job_dir.glob("session-*.log")],
        key=lambda n: int(re.sub(r"\D", "", n) or 0),
    )
    evidence = []
    ev_dir = job_dir / "evidence"
    if ev_dir.is_dir():
        for p in sorted(ev_dir.iterdir(), key=lambda x: x.name.lower()):
            if p.is_file():
                evidence.append({
                    "name": p.name,
                    "size": p.stat().st_size,
                    "mtime": datetime.fromtimestamp(p.stat().st_mtime)
                    .strftime("%Y-%m-%d %H:%M"),
                })
    return {
        "id": job_id,
        "summary": summary,
        "runlog": runlog[-100:],
        "digests": digests,
        "sessions": sessions,
        "evidence": evidence,
        "brief_exists": (job_dir / "BRIEF.md").is_file(),
        "user_input": (job_dir / "user_input.md").read_text(encoding="utf-8", errors="replace").strip()
        if (job_dir / "user_input.md").is_file() else "",
        "files": [p.name for p in sorted(job_dir.iterdir())
                  if p.is_file() and p.name not in ("summary.json", "runlog.jsonl")
                  and not p.name.startswith(("session-", "digest-"))],
    }


def save_user_input(job_id: str, text: str) -> bool:
    """人工协作通道：把用户提供的线索写入 jobs/<id>/user_input.md（追加，保留历史）。"""
    if not valid_job_id(job_id):
        return False
    job_dir = JOBS_DIR / job_id
    if not job_dir.is_dir():
        return False
    text = (text or "").strip()
    if not text:
        return False
    path = job_dir / "user_input.md"
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n--- 人工线索 {datetime.now().strftime('%Y-%m-%d %H:%M')} ---\n{text}\n")
    return True


def list_reports() -> list[dict]:
    if not OUTPUTS_DIR.is_dir():
        return []
    out = []
    for p in sorted(OUTPUTS_DIR.glob("report-*.md"), reverse=True):
        st = p.stat()
        out.append({
            "name": p.name,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return out


def read_report(name: str) -> str | None:
    p = safe_resolve("outputs", name)
    if p is None or not p.is_file() or not name.startswith("report-"):
        return None
    return read_text(p, limit_chars=200_000)


def read_job_file(job_id: str, rel: str) -> str | None:
    """读 jobs/<id>/ 下任意文件（BRIEF/digest/session/evidence/...）。"""
    if not valid_job_id(job_id):
        return None
    job_dir = JOBS_DIR / job_id
    if not job_dir.is_dir():
        return None
    try:
        p = (job_dir / rel).resolve()
        p.relative_to(job_dir.resolve())
    except (ValueError, OSError):
        return None
    if not p.is_file():
        return None
    return read_text(p, limit_chars=300_000)


def read_bigdan_stdout(job_id: str, n_lines: int = 150) -> str:
    """读取调度器 stdout 尾部。修复前旧日志为 GBK 写入，先试 UTF-8 失败回退 GBK。"""
    p = WEBUI_DIR / f"bigdan-{job_id}.out.log"
    if not p.is_file():
        return ""
    try:
        raw = p.read_bytes()
    except OSError:
        return ""
    for enc in ("utf-8", "gbk"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    return "\n".join(text.splitlines()[-n_lines:])


def open_dir(root_name: str, rel: str = "") -> bool:
    """os.startfile 打开本地目录（仅限 jobs/outputs 根内）。"""
    p = safe_resolve(root_name, rel)
    if p is None or not p.is_dir():
        return False
    try:
        os.startfile(str(p))  # type: ignore[attr-defined]
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- 配置

def tool_list() -> list[dict]:
    bin_dir = PROJECT_ROOT / "tools" / "bin"
    out = []
    if bin_dir.is_dir():
        for p in sorted(bin_dir.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                out.append({"name": p.name, "size": p.stat().st_size})
    return out


def _dotenv_key_set(key: str) -> bool:
    """webui 进程不加载 .env（bigdan.py 子进程才读），此处直查文件避免误报未设置。"""
    envf = PROJECT_ROOT / ".env"
    if not envf.is_file():
        return False
    for ln in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = ln.strip()
        if s.startswith(key) and "=" in s and s.split("=", 1)[1].strip():
            return True
    return False


def config_view() -> dict:
    env = {}
    for k in os.environ:
        if k.startswith("BIGDAN_") or k in ("DEEPSEEK_API_KEY", "API_KEY", "LLM_API_KEY"):
            env[k] = "<set>" if os.environ.get(k) else "<empty>"
    # 补充 .env 文件里的键（不读值）
    dotenv_keys = []
    envf = PROJECT_ROOT / ".env"
    if envf.is_file():
        for ln in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and "=" in s:
                dotenv_keys.append(s.split("=", 1)[0].strip())
    wordlists = {}
    wd = PROJECT_ROOT / "tools" / "wordlists"
    if wd.is_dir():
        for p in wd.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".txt", ".lst", ".dic"):
                wordlists[p.relative_to(wd).as_posix()] = p.stat().st_size
    return {
        "project_root": str(PROJECT_ROOT),
        "jobs_dir": str(JOBS_DIR),
        "outputs_dir": str(OUTPUTS_DIR),
        "targets_file": str(TARGETS_FILE),
        "targets_text": read_targets_text(),
        "credentials_file": str(CREDENTIALS_FILE),
        "credentials_text": read_credentials_text(),
        "credentials_count": credentials_count(),
        "env": env,
        "dotenv_keys": sorted(set(dotenv_keys)),
        "tools": tool_list(),
        "wordlists": wordlists,
        "key_set": bool(os.environ.get("BIGDAN_LLM_KEY")) or _dotenv_key_set("BIGDAN_LLM_KEY"),
    }


def save_targets_text(text: str) -> None:
    TARGETS_FILE.write_text(text, encoding="utf-8")


LLM_ENV_KEYS = ("BIGDAN_LLM_KEY", "BIGDAN_LLM_BASE", "BIGDAN_LLM_PROVIDER",
                "BIGDAN_LLM_MODEL", "BIGDAN_LLM_THINKING")


def _read_dotenv() -> dict:
    """读 .env 文件全部键值（注释行忽略）。"""
    envf = PROJECT_ROOT / ".env"
    out = {}
    if envf.is_file():
        for ln in envf.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and "=" in s:
                k, _, v = s.partition("=")
                out[k.strip()] = v.strip()
    return out


def llm_config_view() -> dict:
    """返回 .env 中的 LLM 配置（key 明文回显，供配置页编辑/切换模型）。"""
    cfg = _read_dotenv()
    return {k: cfg.get(k, "") for k in LLM_ENV_KEYS}


def _upsert_env_var(key: str, value: str) -> None:
    """向 .env 原位写一个变量（替换或追加末尾），注释/其余行原样保留。"""
    envf = PROJECT_ROOT / ".env"
    lines = envf.read_text(encoding="utf-8", errors="ignore").splitlines() if envf.is_file() else []
    out: list = []
    seen = False
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" in s and s.partition("=")[0].strip() == key:
            if not seen:
                out.append(f"{key}={value}")
                seen = True
            continue
        out.append(ln)
    if not seen:
        out.append(f"{key}={value}")
    envf.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")


def save_llm_config(updates: dict) -> None:
    """写回 .env 的 BIGDAN_LLM_* 键（原位替换/追加）。"""
    kv = {k: str(v).strip() for k, v in (updates or {}).items() if k in LLM_ENV_KEYS}
    for k, v in kv.items():
        _upsert_env_var(k, v)


LLM_PROFILES_FILE = PROJECT_ROOT / "llm-profiles.json"
_PROFILE_FIELDS = ("base", "provider", "model", "thinking")


def _profile_key_env(name: str) -> str:
    """档位名 → 存放其 key 的 .env 变量名。key 明文只进 .env，不进 llm-profiles.json。"""
    safe = re.sub(r"[^A-Za-z0-9]", "_", (name or "").strip()).upper()
    return f"LLM_KEY_{safe or 'DEFAULT'}"


def _write_llm_profiles(data: dict) -> None:
    LLM_PROFILES_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_llm_profiles() -> dict:
    """读档位文件；不存在或损坏时从 .env 迁移构造一个默认档位。

    旧版 json 带 `key` 明文的自动迁移：key 写入 .env 的 LLM_KEY_<档位名>，
    json 回写为 key_env 变量名——文件里从此没有明文密钥。
    """
    env = _read_dotenv()
    if LLM_PROFILES_FILE.is_file():
        try:
            data = json.loads(LLM_PROFILES_FILE.read_text(encoding="utf-8"))
            if (isinstance(data, dict) and isinstance(data.get("profiles"), list)
                    and data["profiles"] and data.get("active")):
                changed = False
                for p in data["profiles"]:
                    if p.get("key"):
                        ke = _profile_key_env(p.get("name"))
                        _upsert_env_var(ke, p.pop("key"))
                        p["key_env"] = ke
                        changed = True
                    elif not p.get("key_env"):
                        p["key_env"] = _profile_key_env(p.get("name"))
                        changed = True
                if changed:
                    _write_llm_profiles(data)
                return data
        except (OSError, json.JSONDecodeError):
            pass
    name = env.get("BIGDAN_LLM_PROVIDER") or "default"
    ke = _profile_key_env(name)
    _upsert_env_var(ke, env.get("BIGDAN_LLM_KEY", ""))
    data = {"active": name, "profiles": [{
        "name": name,
        "key_env": ke,
        "base": env.get("BIGDAN_LLM_BASE", ""),
        "provider": env.get("BIGDAN_LLM_PROVIDER", ""),
        "model": env.get("BIGDAN_LLM_MODEL", ""),
        "thinking": env.get("BIGDAN_LLM_THINKING", "medium"),
    }]}
    _write_llm_profiles(data)
    return data


def _resolved_profiles(data: dict) -> list:
    """key_env → 解析后的 key 明文回传前端（仅内存回显供编辑，不落 json 磁盘）。"""
    env = {**_read_dotenv(), **os.environ}
    out = []
    for p in data["profiles"]:
        q = dict(p)
        q["key"] = env.get(q.get("key_env") or "", "")
        out.append(q)
    return out


def llm_profiles_view() -> dict:
    data = _load_llm_profiles()
    return {
        "active": data["active"],
        "profiles": _resolved_profiles(data),
        "key_set": bool(os.environ.get("BIGDAN_LLM_KEY")) or _dotenv_key_set("BIGDAN_LLM_KEY"),
    }


def _register_provider_models(base: str, provider: str, model: str) -> None:
    """把档位 provider 注册进 pi 的 ~/.pi/agent/models.json(幂等合并)。

    pi 只认 models.json 里注册过的 provider;本函数在 webui 保存档位时自动调用,
    新环境无需再手动注册。只覆盖同名 provider 条目,不破坏其他 provider。
    """
    try:
        mp = Path.home() / ".pi" / "agent" / "models.json"
        data = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else {"providers": {}}
        data.setdefault("providers", {})
        data["providers"][provider] = {
            "baseUrl": base,
            "api": "openai-completions",
            "models": [{
                "id": model, "name": model, "reasoning": True, "input": ["text"],
                "contextWindow": 128000, "maxTokens": 8192,
                "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
            }],
        }
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001 — 注册失败不阻断档位保存
        pass


def save_llm_profiles(active: str, profiles: list) -> dict:
    """保存档位列表 + 激活档位。

    前端传来的明文 key 只写入 .env（LLM_KEY_<档位名>），json 只存 key_env；
    激活档位同步应用到 .env 的 BIGDAN_LLM_*（新任务生效）。
    """
    cleaned = []
    for p in profiles or []:
        name = str(p.get("name", "")).strip()
        if not name:
            continue
        item = {"name": name}
        for f in _PROFILE_FIELDS:
            item[f] = str(p.get(f, "")).strip()
        ke = str(p.get("key_env", "")).strip() or _profile_key_env(name)
        key_plain = str(p.get("key", "")).strip()
        if key_plain:
            _upsert_env_var(ke, key_plain)
        item["key_env"] = ke
        cleaned.append(item)
    if not cleaned:
        raise ValueError("至少需要一个档位")
    if active not in {p["name"] for p in cleaned}:
        active = cleaned[0]["name"]
    _write_llm_profiles({"active": active, "profiles": cleaned})
    act = next(p for p in cleaned if p["name"] == active)
    # 空 provider/model 会被同步成 .env 空值(BIGDAN_LLM_PROVIDER= / BIGDAN_LLM_MODEL=),
    # 新任务 spawn 的 bigdan 拿到空 model 不传 --model,pi 报模糊错误
    # "--api-key requires a model"。源头拒绝:保存失败比写坏配置好。
    missing = [f for f in ("provider", "model") if not act.get(f)]
    if missing:
        raise ValueError(f"激活档位「{active}」的 {', '.join(missing)} 为空,请填写完整后再保存")
    # 治本:把档位 provider 注册进 pi 的 models.json——pi 只认 models.json 里有的
    # provider(webui 只写 .env 的话,新环境的 pi 会报 Unknown provider)。幂等合并,
    # 不破坏已有条目;失败静默,不阻断保存。
    _register_provider_models(act.get("base", ""), act["provider"], act["model"])
    resolved = {**_read_dotenv(), **os.environ}.get(act["key_env"], "")
    sync = {f"BIGDAN_LLM_{k.upper()}": act[k] for k in _PROFILE_FIELDS}
    sync["BIGDAN_LLM_KEY"] = resolved
    save_llm_config(sync)
    return {"active": active, "key_set": bool(resolved) or _dotenv_key_set("BIGDAN_LLM_KEY")}
