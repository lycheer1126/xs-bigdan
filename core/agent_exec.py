"""Run one non-interactive `pi` session; tee + heartbeats + session jsonl mirror.

Why: pi often prints almost nothing to stdout while waiting on the LLM (or when
piped). The harness emits heartbeats and mirrors .pi-sessions/*.jsonl so
progress is visible.  (xs-bigdan: adapted from pi-recon agent_exec.py)
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
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, TextIO


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_now() -> str:
    """本地墙钟时间，用于日志行标注（UTC 头 + 本地时间双标，用户可区分中断重启批次）。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _prefix_tag(tag: str, line: str) -> str:
    """Prefix challenge id on every console/file line so parallel jobs are separable."""
    t = (tag or "").strip()
    if not t:
        return line
    # avoid double-prefix
    if line.startswith(f"[{t}]") or line.startswith(f"# [{t}]"):
        return line
    if line.startswith("#"):
        return f"# [{t}] {line[1:].lstrip()}"
    return f"[{t}] {line}"


def _write(
    lock: threading.Lock,
    logf: TextIO,
    line: str,
    console: bool,
    tag: str = "",
) -> None:
    line = _prefix_tag(tag, line)
    # 每行统一加本地时间戳（[HH:MM:SS]），区分中断重启批次；多行内容逐行加
    ts = f"[{local_now()[11:]}] "
    line = "\n".join(ts + ln if ln else "" for ln in line.rstrip("\n").split("\n")) + "\n"
    with lock:
        logf.write(line)
        logf.flush()
        if console:
            sys.stdout.write(line)
            sys.stdout.flush()


def _tee(
    stream,
    logf: TextIO,
    lock: threading.Lock,
    console: bool,
    tag: str = "",
) -> None:
    try:
        for raw in iter(stream.readline, ""):
            _write(lock, logf, raw.rstrip("\n"), console, tag=tag)
    except Exception as e:  # noqa: BLE001
        _write(lock, logf, f"# tee error: {e}", console, tag=tag)


def _clip(text: str, n: int = 240) -> str:
    text = " ".join(str(text).split())
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def _format_session_event(obj: dict) -> Optional[str]:
    if obj.get("type") != "message":
        return None
    msg = obj.get("message") or {}
    if not isinstance(msg, dict):
        return None
    role = msg.get("role") or "?"
    content = msg.get("content")
    ts = (obj.get("timestamp") or "")[-8:]
    head = f"[{ts}]"
    parts: List[str] = []

    if isinstance(content, str):
        parts.append(_clip(content))
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text" and block.get("text"):
                parts.append(_clip(str(block["text"])))
            elif btype == "thinking" and block.get("thinking"):
                parts.append("think:" + _clip(str(block["thinking"]), 160))
            elif btype in {"toolCall", "toolUse", "tool_use"}:
                name = block.get("name") or block.get("toolName") or "tool"
                args = block.get("arguments") or block.get("input") or {}
                if isinstance(args, dict):
                    summary = (
                        args.get("command")
                        or args.get("cmd")
                        or args.get("path")
                        or args.get("file_path")
                        or args.get("url")
                        or json.dumps(args, ensure_ascii=False)[:120]
                    )
                else:
                    summary = str(args)[:120]
                parts.append(f"call {name}: {_clip(str(summary), 200)}")
            elif btype in {"toolResult", "tool_result"}:
                text = block.get("text") or block.get("content") or ""
                if isinstance(text, list):
                    text = " ".join(
                        str(x.get("text", x)) if isinstance(x, dict) else str(x) for x in text
                    )
                parts.append("result:" + _clip(str(text), 200))

    if role == "toolResult":
        name = msg.get("toolName") or "tool"
        text = ""
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("text"):
                    text = str(block["text"])
                    break
        elif isinstance(content, str):
            text = content
        return f"{head} toolResult {name}: {_clip(text, 220)}"

    if not parts:
        return None
    if role == "assistant":
        return f"{head} assistant: " + " | ".join(parts)
    if role == "user":
        return f"{head} user: " + " | ".join(parts)
    return f"{head} {role}: " + " | ".join(parts)


def _mirror_session_jsonl(
    session_dir: Path,
    logf: TextIO,
    lock: threading.Lock,
    stop: threading.Event,
    console: bool,
    tag: str = "",
) -> None:
    offsets: dict[str, int] = {}
    _write(
        lock,
        logf,
        "# --- live session mirror (.pi-sessions/*.jsonl); stdout often empty while LLM waits ---",
        console,
        tag=tag,
    )
    while not stop.is_set():
        try:
            files = (
                sorted(p for p in session_dir.rglob("*.jsonl") if p.is_file())
                if session_dir.is_dir()
                else []
            )
            for path in files:
                key = str(path)
                pos = offsets.get(key, 0)
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size < pos:
                    pos = 0
                if size == pos:
                    continue
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as f:
                        f.seek(pos)
                        chunk = f.read()
                        new_pos = f.tell()
                except OSError:
                    continue
                offsets[key] = new_pos
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    pretty = _format_session_event(obj)
                    if pretty:
                        _write(lock, logf, pretty, console, tag=tag)
        except Exception as e:  # noqa: BLE001
            _write(lock, logf, f"# mirror error: {e}", console, tag=tag)
        stop.wait(0.4)


def _heartbeat(
    logf: TextIO,
    lock: threading.Lock,
    stop: threading.Event,
    console: bool,
    t0: float,
    session_dir: Path,
    tag: str = "",
    timeout_sec: int = 0,
) -> None:
    n = 0
    # first tick sooner so platform logs are not blank for 15s
    intervals = [5.0, 10.0]
    while True:
        wait = intervals[min(n, len(intervals) - 1)] if n < 3 else 10.0
        if stop.wait(wait):
            break
        n += 1
        elapsed = time.monotonic() - t0
        n_jsonl = 0
        n_bytes = 0
        if session_dir.is_dir():
            files = [p for p in session_dir.rglob("*.jsonl") if p.is_file()]
            n_jsonl = len(files)
            n_bytes = 0
            for p in files:
                try:
                    n_bytes += p.stat().st_size
                except OSError:
                    pass
        left = max(0, int(timeout_sec - elapsed)) if timeout_sec else 0
        _write(
            lock,
            logf,
            f"# heartbeat n={n} elapsed={elapsed:.0f}s timeout_left={left}s pi_alive=1 "
            f"session_jsonl={n_jsonl} bytes={n_bytes} "
            f"(stdout live; waiting on model/tools if no new agent lines)",
            console,
            tag=tag,
        )


def which_pi(pi_bin: str = "pi") -> str:
    return shutil.which(pi_bin) or pi_bin


def _models_base_hint() -> str:
    for path in (
        Path(os.environ.get("PI_CODING_AGENT_DIR") or "") / "models.json",
        Path("/root/.pi/agent/models.json"),
        Path.home() / ".pi" / "agent" / "models.json",
    ):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            bu = ((data.get("providers") or {}).get("deepseek") or {}).get("baseUrl")
            if bu:
                return str(bu)
        except (OSError, json.JSONDecodeError, TypeError):
            continue
    return os.environ.get("DEEPSEEK_BASE_URL") or os.environ.get("LLM_BASE_URL") or "<unknown>"


# Token Rhythm 等上游限流: pi 收到 429(UPSTREAM_RATE_LIMITED)/503(SERVICE_BUSY) 会直接退出(exit=1)，
# 且 provider 配置层无重试字段。这里在段内做进程级重试：等待后重启 pi 会话（受段预算约束）。
LLM_RATE_LIMIT_RETRIES = 2        # 最多重试次数
LLM_RATE_LIMIT_WAIT_SEC = 60      # 每次等待秒数（对齐上游 retryAfterSeconds=60）
_LLM_LIMITED_MARKS = (
    "429 status code",
    "UPSTREAM_RATE_LIMITED",
    "SERVICE_BUSY",
    "503 status code",
    # 网关类 5xx：上游抖动，等待后重试通常能恢复
    "500 status code",
    "502 status code",
    "504 status code",
    "ECONNRESET",
    "fetch failed",
)
# 致命错误：重试不可能成功（余额/鉴权/请求参数），立即失败并把原因归档
_LLM_FATAL_MARKS = (
    "402 status code",
    "Insufficient Balance",
    "invalid api key",
    "Invalid API key",
    "invalid_request_error",
)


def _looks_like_llm_limited(tail: str) -> bool:
    """从 pi 会话日志尾部判断是否因 LLM 上游限流/抖动失败（区别于目标侧 429）。"""
    return any(m in tail for m in _LLM_LIMITED_MARKS)


def _looks_like_llm_fatal(tail: str) -> bool:
    """致命错误（余额不足/鉴权失败/参数错）——重试只是空耗预算。"""
    return any(m in tail for m in _LLM_FATAL_MARKS)


# 日志尾部失败行提取：命中错误特征、跳过 harness 自身行（供 summary/report 归档 exit=1 根因）
_LLM_ERR_LINE_RE = re.compile(
    r"(?i)(status code|api error|error:|exception|insufficient|invalid api|rate.?limit|failed)")
_LLM_ERR_SKIP_RE = re.compile(
    r"(?i)(heartbeat|session_dir files|--- (begin|end|live|agent)|spawning pi|"
    r"mirror error|tee error|user_prompt_preview|retry)")


def extract_last_error(log_path: Path, clip: int = 220) -> str:
    """取会话日志尾部最后一行失败原因（pi 把上游错误打到 stdout，会话 jsonl 里没有）。"""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in reversed(text.splitlines()[-400:]):
        s = line.strip()
        if not s or _LLM_ERR_SKIP_RE.search(s):
            continue
        if _LLM_ERR_LINE_RE.search(s):
            return _clip(s, clip)
    return ""


def _append_log_note(log_path: Path, msg: str, console: bool = True, tag: str = "") -> None:
    """重试/放弃等 harness 决策追加到会话日志（与 tee 行同格式前缀，肉眼可追）。"""
    line = f"# --- {msg} ---"
    if console:
        print(f"[{tag or 'agent_exec'}] {line}", flush=True)
    try:
        with log_path.open("a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except OSError:
        pass


def run_pi_session(
    work_dir: Path,
    *,
    system_prompt: str,
    user_prompt: str,
    log_path: Path,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    thinking: Optional[str] = None,
    pi_bin: str = "pi",
    timeout_sec: int = 900,
    session_name: str = "session",
    tee_console: bool = True,
    extra_args: Optional[List[str]] = None,
    job_tag: str = "",
) -> int:
    """包一层 429/5xx 重试：LLM 上游限流时等待后重启 pi 会话。

    预算约束（deadline 感知）：重试等待与重跑全部计入 timeout_sec 总预算，
    段耗时不会像旧版那样放大到 (retries+1)*timeout 打穿目标总预算。
    致命错误（402 余额/鉴权/参数错）不重试；失败原因留在日志尾部，
    由 extract_last_error 提取进 summary/report。
    """
    t0 = time.monotonic()
    last_ec = 1
    for attempt in range(LLM_RATE_LIMIT_RETRIES + 1):
        remaining = int(timeout_sec - (time.monotonic() - t0))
        if attempt > 0 and remaining < 45:
            _append_log_note(log_path, f"段剩余预算不足45s，停止 LLM 重试 (已试 {attempt} 次)", tag=job_tag)
            break
        ec = _run_pi_session_once(
            work_dir,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            log_path=log_path,
            provider=provider,
            model=model,
            api_key=api_key,
            thinking=thinking,
            pi_bin=pi_bin,
            timeout_sec=timeout_sec if attempt == 0 else max(45, remaining),
            session_name=session_name,
            tee_console=tee_console,
            extra_args=extra_args,
            job_tag=job_tag,
            log_mode=("w" if attempt == 0 else "a"),
        )
        last_ec = ec
        if ec == 0 or ec == 124 or ec == 127:
            return ec
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-1600:]
        except OSError:
            tail = ""
        if _looks_like_llm_fatal(tail):
            _append_log_note(log_path, "LLM 致命错误(余额/鉴权/参数)，重试无意义，直接失败", tag=job_tag)
            return ec
        if not _looks_like_llm_limited(tail) or attempt >= LLM_RATE_LIMIT_RETRIES:
            return ec
        # 等待也受段预算约束：等待后至少还剩 45s 可跑一个最小重试段
        budget_left = int(timeout_sec - (time.monotonic() - t0))
        wait = min(LLM_RATE_LIMIT_WAIT_SEC, budget_left - 45)
        if wait < 1:
            _append_log_note(log_path, "段剩余预算不足以完成重试，放弃", tag=job_tag)
            return ec
        tag = job_tag or work_dir.name or ""
        _append_log_note(
            log_path,
            f"LLM 上游限流(429/5xx)，等待 {wait}s 后重试 (attempt {attempt + 1}/{LLM_RATE_LIMIT_RETRIES})",
            tag=tag)
        time.sleep(wait)
    return last_ec


def _run_pi_session_once(
    work_dir: Path,
    *,
    system_prompt: str,
    user_prompt: str,
    log_path: Path,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    thinking: Optional[str] = None,
    pi_bin: str = "pi",
    timeout_sec: int = 900,
    session_name: str = "session",
    tee_console: bool = True,
    extra_args: Optional[List[str]] = None,
    job_tag: str = "",
    log_mode: str = "w",
) -> int:
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # absolute path: pi resolves relative --session-dir against its own cwd,
    # which would nest the jsonl inside work_dir/jobs/<id>/ and break the mirror
    session_dir = work_dir.resolve() / ".pi-sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    # challenge id for parallel log separation (a-05 / c-07 / ...)
    tag = (job_tag or work_dir.name or "").strip()

    pi = which_pi(pi_bin)
    cmd = [
        pi,
        "-p",
        "--approve",
        "--verbose",
        "--mode",
        "text",
        "--session-dir",
        str(session_dir),
        "--name",
        session_name,
        "--system-prompt",
        system_prompt,
    ]
    if provider:
        cmd.extend(["--provider", provider])
    if model:
        cmd.extend(["--model", model])
    if api_key:
        cmd.extend(["--api-key", api_key])
    if thinking:
        cmd.extend(["--thinking", thinking])
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(user_prompt)

    # Windows: npm shims resolve to *.CMD which CreateProcess cannot run
    # directly, and `cmd.exe /c` would re-parse arguments containing shell
    # metachars (`|`, `<`, `>`, newlines in prompts) and truncate them.
    # Instead resolve the shim to node + cli.js and invoke node directly.
    if sys.platform == "win32" and pi.lower().endswith((".cmd", ".bat")):
        npm_root = Path(pi).resolve().parent
        cli_js = npm_root / "node_modules" / "@earendil-works" / "pi-coding-agent" / "dist" / "cli.js"
        node_bin = shutil.which("node") or "node"
        if cli_js.is_file():
            cmd = [node_bin, str(cli_js)] + cmd[1:]
        else:
            cmd = ["cmd.exe", "/c"] + cmd

    meta_cmd = list(cmd)
    try:
        i = meta_cmd.index("--system-prompt")
        meta_cmd[i + 1] = f"<system_prompt {len(system_prompt)} chars>"
    except (ValueError, IndexError):
        pass
    try:
        i = meta_cmd.index("--api-key")
        meta_cmd[i + 1] = "<redacted>"
    except (ValueError, IndexError):
        pass
    if meta_cmd:
        meta_cmd[-1] = f"<user_prompt {len(user_prompt)} chars>"

    env = os.environ.copy()
    env.setdefault("NO_PROXY", "*")
    env.setdefault("no_proxy", "*")
    env.setdefault("PYTHONUNBUFFERED", "1")
    # Prefer line-buffered node when piped
    env["NODE_OPTIONS"] = (env.get("NODE_OPTIONS") or "") + " --trace-uncaught"
    env.setdefault("FORCE_COLOR", "0")
    tools = Path("/app/tools/bin")
    if tools.is_dir():
        env["PATH"] = f"{tools}{os.pathsep}{env.get('PATH', '')}"
    try:
        local_tools = work_dir.resolve().parents[1] / "tools" / "bin"
        if local_tools.is_dir():
            env["PATH"] = f"{local_tools}{os.pathsep}{env.get('PATH', '')}"
    except IndexError:
        pass

    lock = threading.Lock()
    t0 = time.monotonic()
    exit_code = 1
    timed_out = False
    base_hint = _models_base_hint()

    with log_path.open(log_mode, encoding="utf-8", errors="replace") as logf:
        header = (
            f"# pi-recon agent transcript job={tag}\n"
            f"# started_at={utc_now()} (本地 {local_now()})\n"
            f"# cwd={work_dir}\n"
            f"# timeout_sec={timeout_sec}\n"
            f"# llm_base_hint={base_hint}\n"
            f"# provider={provider} model={model} api_key_set={bool(api_key)}\n"
            f"# cmd={json.dumps(meta_cmd, ensure_ascii=False)}\n"
            f"# parallel logs: every line prefixed with [{tag or '?'}]\n"
            f"# --- begin ---\n"
        )
        _write(lock, logf, header.rstrip("\n"), tee_console, tag=tag)
        _write(lock, logf, f"# user_prompt_preview=\n{user_prompt[:1500]}", tee_console, tag=tag)
        _write(lock, logf, "# --- agent output ---", tee_console, tag=tag)
        _write(lock, logf, f"# spawning pi at {utc_now()} (本地 {local_now()}) ...", tee_console, tag=tag)

        stop = threading.Event()
        mirror = threading.Thread(
            target=_mirror_session_jsonl,
            args=(session_dir, logf, lock, stop, tee_console, tag),
            daemon=True,
            name=f"jsonl-mirror-{tag or 'job'}",
        )
        heart = threading.Thread(
            target=_heartbeat,
            args=(logf, lock, stop, tee_console, t0, session_dir, tag, timeout_sec),
            daemon=True,
            name=f"heartbeat-{tag or 'job'}",
        )
        mirror.start()
        heart.start()

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(work_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            _write(lock, logf, f"# pi pid={proc.pid}", tee_console, tag=tag)
            reader = threading.Thread(
                target=_tee,
                args=(proc.stdout, logf, lock, tee_console, tag),
                daemon=True,
                name=f"tee-{tag or 'job'}",
            )
            reader.start()
            try:
                exit_code = proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                exit_code = 124
                _write(
                    lock,
                    logf,
                    f"# --- killed: timeout after {timeout_sec}s — slot free for next job ---",
                    tee_console,
                    tag=tag,
                )
            except BaseException:
                # KeyboardInterrupt 等中断：必须杀掉 pi 子进程，否则孤儿 pi
                # 会在后台继续对目标发请求（合规风险 + 空烧 token），再原样抛出
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                _write(lock, logf, f"# --- killed: interrupted, pi child reaped ---", tee_console, tag=tag)
                raise
            reader.join(timeout=5)
        except FileNotFoundError as e:
            _write(lock, logf, f"# --- failed to spawn pi: {e} ---", tee_console, tag=tag)
            exit_code = 127
        except Exception as e:  # noqa: BLE001
            _write(lock, logf, f"# --- runner error: {e} ---", tee_console, tag=tag)
            exit_code = 1
        finally:
            stop.set()
            mirror.join(timeout=2)
            heart.join(timeout=1)

        elapsed = time.monotonic() - t0
        # dump any leftover session jsonl names
        if session_dir.is_dir():
            files = list(session_dir.rglob("*"))
            _write(
                lock,
                logf,
                f"# session_dir files={[p.name for p in files[:20]]}",
                tee_console,
                tag=tag,
            )
        _write(
            lock,
            logf,
            f"# --- end exit={exit_code} elapsed_sec={elapsed:.2f} timed_out={timed_out} ---",
            tee_console,
            tag=tag,
        )

    meta = {
        "started_at": utc_now(),
        "cwd": str(work_dir),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_sec": timeout_sec,
        "provider": provider,
        "model": model,
        "llm_base_hint": base_hint,
        "cmd": meta_cmd,
        "log_file": str(log_path),
    }
    (log_path.parent / (log_path.stem + ".meta.json")).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return exit_code
