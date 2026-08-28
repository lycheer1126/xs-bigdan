#!/usr/bin/env python3
"""Poll TSecBench hosted run logs and optionally archive ALL lines to disk.

Why: the web UI only keeps ~1000 lines. This script keeps polling and appends
every new event to local files for later analysis.

Usage:
  export TSEC_BEARER='eyJ...'
  export TSEC_RUN_ID=9829
  python3 scripts/watch_run_logs.py --save-dir logs/run-9829

  # live tail only (no archive):
  python3 scripts/watch_run_logs.py --limit 1000
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

DEFAULT_BASE = "https://tsecbench.zc.tencent.com"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    raw = s.strip()
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def short_ts(s: str) -> str:
    dt = parse_iso(s)
    if not dt:
        return (s or "")[-8:]
    return dt.astimezone(timezone.utc).strftime("%H:%M:%S")


@dataclass
class Line:
    key: str
    ts: str
    text: str


@dataclass
class WatchState:
    lines: Deque[Line]
    seen: Set[str]
    seen_order: Deque[str]
    run_from: Optional[str] = None
    save_dir: Optional[Path] = None
    stream_path: Optional[Path] = None
    seen_path: Optional[Path] = None
    status_path: Optional[Path] = None
    saved_count: int = 0


class TsecClient:
    def __init__(self, base: str, token: str, cookie: str = "") -> None:
        self.base = base.rstrip("/")
        self.token = token.strip()
        self.cookie = cookie.strip()

    def get_json(self, path: str, timeout: float = 60.0) -> Any:
        url = self.base + path
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "pi-recon-logwatch/0.3",
        }
        if self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            # hard timeout so one hung page cannot stall the whole archiver forever
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise RuntimeError(f"HTTP {e.code} {path}: {body[:300]}") from e
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"{type(e).__name__} {path}: {e}") from e

    def status(self, run_id: int) -> dict:
        data = self.get_json(f"/api/v1/runs/{run_id}/status")
        if not isinstance(data, dict):
            raise RuntimeError("status payload not object")
        return data

    def list_sessions(
        self,
        run_id: int,
        *,
        frm: str,
        to: str,
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        q = urllib.parse.urlencode(
            {"from": frm, "to": to, "page": page, "page_size": page_size}
        )
        data = self.get_json(f"/api/v1/runs/{run_id}/llm/sessions?{q}")
        if not isinstance(data, dict):
            raise RuntimeError("sessions payload not object")
        return data

    def session_detail(
        self,
        run_id: int,
        session_id: int,
        *,
        frm: str,
        to: str,
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        q = urllib.parse.urlencode(
            {"from": frm, "to": to, "page": page, "page_size": page_size}
        )
        data = self.get_json(f"/api/v1/runs/{run_id}/llm/sessions/{session_id}?{q}")
        if not isinstance(data, dict):
            raise RuntimeError("session detail payload not object")
        return data


def clip(s: str, n: int = 500) -> str:
    s = " ".join((s or "").split())
    if len(s) <= n:
        return s
    return s[: n - 1] + "…"


def challenge_tag_from_title(title: str) -> str:
    m = re.search(r"[（(]([a-zA-Z0-9_-]+)[）)]", title or "")
    if m:
        return m.group(1)
    m = re.search(r"\b([a-z]+-\d+)\b", title or "", re.I)
    if m:
        return m.group(1)
    return ""


def format_step_items(step: dict, *, full: bool = False) -> List[str]:
    n = 2000 if full else 400
    out: List[str] = []
    et = step.get("event_type") or "?"
    err = (step.get("error") or "").strip()
    if err and et in {"session_note", "system_note"}:
        out.append(f"note/{et}: {clip(err, n)}")
    items = step.get("items") or []
    if not isinstance(items, list):
        return out
    for it in items:
        if not isinstance(it, dict):
            continue
        kind = it.get("kind") or it.get("role") or "item"
        name = it.get("name") or ""
        text = it.get("text")
        args = it.get("args")
        is_err = it.get("is_error")
        if kind == "thinking" and text:
            out.append(f"think: {clip(str(text), n)}")
        elif kind in {"user_text", "assistant_text", "text"} and text:
            role = it.get("role") or kind
            out.append(f"{role}: {clip(str(text), n)}")
        elif kind in {"tool_call", "toolCall", "function_call"} or (name and args is not None):
            if isinstance(args, dict):
                cmd = (
                    args.get("command")
                    or args.get("cmd")
                    or args.get("code")
                    or json.dumps(args, ensure_ascii=False)
                )
            else:
                cmd = str(args)
            out.append(f"call {name or 'tool'}: {clip(str(cmd), n)}")
        elif kind in {"tool_result", "toolResult"} and text:
            prefix = "toolERR" if is_err else "tool"
            out.append(f"{prefix} {name or ''}: {clip(str(text), n)}")
        elif text:
            out.append(f"{kind}: {clip(str(text), n)}")
        elif err:
            out.append(f"{et}: {clip(err, n)}")
    if not out and err:
        out.append(f"{et}: {clip(err, n)}")
    if not out:
        out.append(f"{et}")
    return out


def load_seen(path: Path) -> Set[str]:
    if not path.is_file():
        return set()
    out: Set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        k = line.strip()
        if k:
            out.add(k)
    return out


def append_seen(path: Path, key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(key + "\n")


def push_line(
    state: WatchState,
    key: str,
    ts: str,
    text: str,
    *,
    raw: Optional[dict] = None,
) -> bool:
    if key in state.seen:
        return False
    state.seen.add(key)
    state.seen_order.append(key)
    # bound in-memory seen if not archiving
    if state.save_dir is None and state.seen_order.maxlen:
        while len(state.seen) > int(state.seen_order.maxlen):
            old = state.seen_order.popleft()
            state.seen.discard(old)

    line = Line(key=key, ts=ts, text=text)
    state.lines.append(line)

    if state.stream_path is not None:
        state.stream_path.parent.mkdir(parents=True, exist_ok=True)
        with state.stream_path.open("a", encoding="utf-8") as f:
            f.write(f"{ts}\t{text}\n")
        if state.seen_path is not None:
            append_seen(state.seen_path, key)
        if raw is not None and state.save_dir is not None:
            raw_dir = state.save_dir / "raw_events"
            raw_dir.mkdir(parents=True, exist_ok=True)
            # one file per key-ish; use hash-safe name
            safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", key)[:180]
            (raw_dir / f"{safe}.json").write_text(
                json.dumps(raw, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        state.saved_count += 1
    return True


def collect_run_event_lines(status: dict) -> Iterable[Tuple[str, str, str, Optional[dict]]]:
    for ev in status.get("run_events") or []:
        if not isinstance(ev, dict):
            continue
        eid = ev.get("id")
        ts = str(ev.get("event_time") or "")
        code = ev.get("challenge_code") or "-"
        op = ev.get("operation_type") or ev.get("description") or "event"
        extra = ev.get("extra") or {}
        addr = ""
        if isinstance(extra, dict) and extra.get("container_addr"):
            addr = f" addr={extra.get('container_addr')}"
        name = ev.get("challenge_name") or ""
        text = f"[RUN] {op} {code} {name}{addr}".strip()
        yield (f"run_event:{eid}", ts, text, ev)

    for ev in (status.get("score_events") or []) + (status.get("new_score_events") or []):
        if not isinstance(ev, dict):
            continue
        eid = ev.get("id") or ev.get("event_id") or json.dumps(ev, sort_keys=True)[:80]
        ts = str(ev.get("event_time") or ev.get("created_at") or "")
        text = f"[SCORE] {json.dumps(ev, ensure_ascii=False)}"
        yield (f"score_event:{eid}", ts, text, ev)


def iter_all_session_steps(
    client: TsecClient,
    run_id: int,
    session_id: int,
    *,
    frm: str,
    to: str,
    archive: bool,
) -> Iterable[dict]:
    page_size = 50
    first = client.session_detail(
        run_id, session_id, frm=frm, to=to, page=1, page_size=page_size
    )
    pag = first.get("pagination") or {}
    total_pages = int(pag.get("total_pages") or 1)
    if archive:
        start_page = 1
    else:
        # live view: only last ~4 pages
        start_page = max(1, total_pages - 3)

    # if first page not in range, still yield when start==1
    for page in range(start_page, total_pages + 1):
        if page == 1:
            data = first
        else:
            data = client.session_detail(
                run_id, session_id, frm=frm, to=to, page=page, page_size=page_size
            )
        for st in data.get("steps") or []:
            if isinstance(st, dict):
                yield st

        # also dump raw page when archiving
        if archive:
            yield {"__raw_page__": True, "page": page, "data": data}


def _load_progress(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def collect_session_lines(
    client: TsecClient,
    run_id: int,
    sess: dict,
    *,
    frm: str,
    to: str,
    archive: bool,
    save_dir: Optional[Path],
) -> Iterable[Tuple[str, str, str, Optional[dict]]]:
    """Yield stream lines + dump raw pages.

    Completeness first: archive mode re-pulls any session whose platform
    event_count / last_active_at advanced, or that is not marked complete.
    """
    sid = sess.get("session_id") or sess.get("id")
    if not sid:
        return
    sid = int(sid)
    title = sess.get("title") or ""
    tag = challenge_tag_from_title(title) or f"s{sid}"
    status = sess.get("status") or ""
    model = sess.get("model") or ""
    event_count = sess.get("event_count")
    last_active = str(sess.get("last_active_at") or "")

    yield (
        f"session_meta:{sid}:{last_active}:{event_count}",
        last_active or str(sess.get("first_captured_at") or ""),
        f"[LLM {tag}] session={sid} status={status} model={model} events={event_count}",
        sess,
    )

    sess_dir: Optional[Path] = None
    progress_path: Optional[Path] = None
    progress: dict = {}
    if save_dir is not None:
        sess_dir = save_dir / "sessions" / f"{tag}_{sid}"
        sess_dir.mkdir(parents=True, exist_ok=True)
        (sess_dir / "meta.json").write_text(
            json.dumps(sess, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        progress_path = sess_dir / "progress.json"
        progress = _load_progress(progress_path)
        # Skip full re-download only when frozen closed session already fully paged
        if (
            progress.get("complete")
            and progress.get("event_count") == event_count
            and progress.get("last_active_at") == last_active
            and status not in {"active", "running"}
        ):
            return

    try:
        pages_seen = 0
        steps_seen = 0
        total_pages = None
        for st in iter_all_session_steps(
            client, run_id, sid, frm=frm, to=to, archive=archive
        ):
            if st.get("__raw_page__") and sess_dir is not None:
                page = int(st["page"])
                data = st["data"]
                pages_seen = max(pages_seen, page)
                pag = data.get("pagination") or {}
                total_pages = int(pag.get("total_pages") or total_pages or page)
                # always overwrite page file with latest full snapshot (safe for analysis)
                (sess_dir / f"page_{page:04d}.json").write_text(
                    json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                if page == 1 and isinstance(data.get("session"), dict):
                    (sess_dir / "session.json").write_text(
                        json.dumps(data["session"], ensure_ascii=False, indent=2)
                        + "\n",
                        encoding="utf-8",
                    )
                continue

            steps_seen += 1
            sid_step = st.get("id")
            seq = st.get("seq")
            ts = str(st.get("captured_at") or "")
            for j, piece in enumerate(format_step_items(st, full=archive)):
                key = f"step:{sid}:{sid_step}:{seq}:{j}"
                yield (key, ts, f"[LLM {tag}] {piece}", st if j == 0 else None)

        if progress_path is not None and sess_dir is not None:
            complete = (
                status not in {"active", "running"}
                and total_pages is not None
                and pages_seen >= total_pages
            )
            progress.update(
                {
                    "session_id": sid,
                    "tag": tag,
                    "status": status,
                    "event_count": event_count,
                    "last_active_at": last_active,
                    "pages_seen": pages_seen,
                    "total_pages": total_pages,
                    "steps_seen_this_pass": steps_seen,
                    "complete": complete,
                    "updated_at": fmt_iso(utc_now()),
                }
            )
            progress_path.write_text(
                json.dumps(progress, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    except Exception as e:  # noqa: BLE001
        # never drop the session forever — clear complete flag so next loop retries
        if progress_path is not None:
            progress = _load_progress(progress_path)
            progress["complete"] = False
            progress["last_error"] = str(e)
            progress["updated_at"] = fmt_iso(utc_now())
            progress_path.write_text(
                json.dumps(progress, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        yield (
            f"session_err:{sid}:{int(time.time())}",
            fmt_iso(utc_now()),
            f"[LLM {tag}] fetch steps failed (will retry): {e}",
            None,
        )


def redraw(state: WatchState, header: str) -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.write(header + "\n")
    sys.stdout.write("-" * 80 + "\n")
    for line in state.lines:
        sys.stdout.write(f"{short_ts(line.ts)} {line.text}\n")
    sys.stdout.write("-" * 80 + "\n")
    extra = ""
    if state.stream_path:
        extra = f" saved={state.saved_count} file={state.stream_path}"
    sys.stdout.write(
        f"buffer={len(state.lines)}/{state.lines.maxlen} seen={len(state.seen)}{extra}\n"
        f"Ctrl+C to stop (archive file keeps growing while running)\n"
    )
    sys.stdout.flush()


def watch(
    *,
    base: str,
    token: str,
    run_id: int,
    limit: int,
    interval: float,
    cookie: str,
    once: bool,
    save_dir: Optional[Path],
    no_tui: bool,
) -> int:
    client = TsecClient(base, token, cookie=cookie)
    archive = save_dir is not None
    # archive: keep huge seen set; live: bound
    if archive:
        seen_order: Deque[str] = deque()  # unbounded growth via set only
        lines: Deque[Line] = deque(maxlen=max(50, limit))  # tui still last N
        state = WatchState(lines=lines, seen=set(), seen_order=seen_order)
        save_dir.mkdir(parents=True, exist_ok=True)
        state.save_dir = save_dir
        state.stream_path = save_dir / "stream.log"
        state.seen_path = save_dir / "seen.keys"
        state.status_path = save_dir / "status_latest.json"
        state.seen = load_seen(state.seen_path)
        state.saved_count = 0
        # count existing lines roughly
        if state.stream_path.is_file():
            with state.stream_path.open("rb") as f:
                state.saved_count = sum(1 for _ in f)
    else:
        state = WatchState(
            lines=deque(maxlen=max(10, limit)),
            seen=set(),
            seen_order=deque(maxlen=max(1000, limit * 5)),
        )

    try:
        st0 = client.status(run_id)
    except Exception as e:  # noqa: BLE001
        print(f"[fatal] status: {e}", file=sys.stderr)
        return 2

    created = st0.get("created_at") or st0.get("started_at")
    if created:
        dt = parse_iso(str(created))
        if dt:
            state.run_from = fmt_iso(dt - timedelta(minutes=5))
    if not state.run_from:
        state.run_from = fmt_iso(utc_now() - timedelta(hours=6))

    if save_dir is not None:
        # do not clobber first meta — append restart note
        meta_path = save_dir / "run_meta.json"
        meta = {}
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                meta = {}
        restarts = meta.get("restarts") or []
        if not isinstance(restarts, list):
            restarts = []
        restarts.append(fmt_iso(utc_now()))
        meta.update(
            {
                "run_id": run_id,
                "base": base,
                "run_from": state.run_from,
                "last_watch_start": fmt_iso(utc_now()),
                "restarts": restarts[-50:],
                "goal": "full archive for offline analysis (not real-time)",
                "latest_status_snapshot": {
                    k: st0.get(k)
                    for k in (
                        "status",
                        "unique_code",
                        "set_name",
                        "current_score",
                        "max_score",
                        "elapsed_seconds",
                        "created_at",
                        "started_at",
                    )
                },
            }
        )
        if "started_watch_at" not in meta:
            meta["started_watch_at"] = fmt_iso(utc_now())
        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (save_dir / "README_ANALYSIS.md").write_text(
            """# Run log archive (for offline analysis)

Goal: **complete** capture for later analysis. Lag is OK; missing data is not.

## Files

| path | meaning |
|------|---------|
| `stream.log` | append-only human timeline (`[RUN]` / `[SCORE]` / `[LLM …]`) |
| `seen.keys` | dedupe keys so restarts **append only**, never wipe |
| `status_latest.json` | latest `/status` snapshot |
| `status_history/status_*.json` | full status dumps each poll (run_events included) |
| `score_timeline.jsonl` | score/elapsed crumbs |
| `sessions_index.json` | all LLM sessions list |
| `sessions/<tag>_<id>/` | per-session raw pages + `progress.json` |
| `raw_events/` | individual event JSON blobs |

## Completeness rules

- RUN/SCORE lines de-duped by event id, append forever.
- LLM sessions re-fetched until `progress.json` marks `complete` (closed + all pages).
- Active sessions always re-scanned when `event_count` / `last_active_at` changes.
- One session failure does not stop the rest; errors go to `stream.log` and retry next loop.

## Tips

```bash
grep '\\[SCORE\\]' stream.log
grep '\\[RUN\\] instance_' stream.log | tail -50
ls sessions | wc -l
```
""",
            encoding="utf-8",
        )

    print(
        f"[watch] run={run_id} archive={'yes' if archive else 'no'} "
        f"limit={limit} interval={interval}s from={state.run_from} "
        f"save_dir={save_dir}",
        flush=True,
    )

    while True:
        to = fmt_iso(utc_now() + timedelta(minutes=1))
        frm = state.run_from or fmt_iso(utc_now() - timedelta(hours=6))
        new_count = 0
        header = ""
        status: dict = {}

        try:
            status = client.status(run_id)
            if state.status_path is not None and state.save_dir is not None:
                blob = json.dumps(status, ensure_ascii=False, indent=2) + "\n"
                state.status_path.write_text(blob, encoding="utf-8")
                # full snapshot each poll — protects against run_events windowing
                hist = state.save_dir / "status_history"
                hist.mkdir(parents=True, exist_ok=True)
                stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
                (hist / f"status_{stamp}.json").write_text(blob, encoding="utf-8")
                snap = {
                    "t": fmt_iso(utc_now()),
                    "status": status.get("status"),
                    "score": status.get("current_score"),
                    "elapsed": status.get("elapsed_seconds"),
                    "run_events": len(status.get("run_events") or []),
                    "score_events": len(status.get("score_events") or []),
                }
                with (state.save_dir / "score_timeline.jsonl").open(
                    "a", encoding="utf-8"
                ) as f:
                    f.write(json.dumps(snap, ensure_ascii=False) + "\n")

            for key, ts, text, raw in collect_run_event_lines(status):
                if push_line(state, key, ts, text, raw=raw):
                    new_count += 1
                # also always append raw run_event once to jsonl for analysis
                if (
                    state.save_dir is not None
                    and raw is not None
                    and key.startswith("run_event:")
                ):
                    # push_line already de-dupes stream; raw_events dir holds json
                    pass

            sess_items: List[dict] = []
            page = 1
            while True:  # no hard page cap — completeness over speed
                data = client.list_sessions(
                    run_id, frm=frm, to=to, page=page, page_size=50
                )
                items = data.get("items") or []
                if not items:
                    break
                for it in items:
                    if isinstance(it, dict):
                        sess_items.append(it)
                pag = data.get("pagination") or {}
                if page >= int(pag.get("total_pages") or 1):
                    break
                page += 1

            if save_dir is not None:
                (save_dir / "sessions_index.json").write_text(
                    json.dumps(sess_items, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )

            def sess_sort(s: dict) -> Tuple[int, str]:
                # active first so current work is archived sooner; still do all
                active = 0 if (s.get("status") == "active") else 1
                return (active, s.get("last_active_at") or "")

            sess_items.sort(key=sess_sort)
            deep = sess_items if archive else sess_items[:12]
            for sess in deep:
                try:
                    for key, ts, text, raw in collect_session_lines(
                        client,
                        run_id,
                        sess,
                        frm=frm,
                        to=to,
                        archive=archive,
                        save_dir=save_dir,
                    ):
                        if push_line(state, key, ts, text, raw=raw):
                            new_count += 1
                except Exception as e:  # noqa: BLE001
                    # one bad session must not abort the whole archive loop
                    sid = sess.get("session_id") or sess.get("id")
                    push_line(
                        state,
                        f"session_loop_err:{sid}:{int(time.time())}",
                        fmt_iso(utc_now()),
                        f"[watch] session {sid} error (continue): {e}",
                    )
                    new_count += 1

            header = (
                f"run={run_id} status={status.get('status')} "
                f"score={status.get('current_score')}/{status.get('max_score')} "
                f"elapsed={status.get('elapsed_seconds')}s sessions={len(sess_items)} "
                f"new={new_count} saved_total={state.saved_count}"
            )
            print(f"[{short_ts(fmt_iso(utc_now()))}] {header}", flush=True)
        except Exception as e:  # noqa: BLE001
            header = f"run={run_id} ERROR {e}"
            push_line(
                state,
                f"err:{time.time()}",
                fmt_iso(utc_now()),
                f"[watch] {e}",
            )
            print(header, flush=True)

        if not no_tui and not archive:
            redraw(state, header)
        elif archive and new_count:
            # append-only mode: print a short progress line
            pass

        if once:
            return 0

        st_now = status.get("status") if status else None
        if st_now in {"finished", "failed", "stopped", "completed", "ended"}:
            print(f"[watch] run terminal status={st_now}", flush=True)
            if save_dir is not None:
                (save_dir / "FINISHED").write_text(
                    f"{st_now} at {fmt_iso(utc_now())}\n", encoding="utf-8"
                )
            return 0
        time.sleep(max(1.0, interval))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Watch/archive TSecBench run logs")
    p.add_argument("--base", default=os.environ.get("TSEC_BASE", DEFAULT_BASE))
    p.add_argument(
        "--run-id", type=int, default=int(os.environ.get("TSEC_RUN_ID") or "9829")
    )
    p.add_argument(
        "--token",
        default=os.environ.get("TSEC_BEARER")
        or os.environ.get("TSEC_TOKEN")
        or os.environ.get("AUTHORIZATION", "").removeprefix("Bearer ").strip(),
    )
    p.add_argument("--cookie", default=os.environ.get("TSEC_COOKIE", ""))
    p.add_argument(
        "--limit", type=int, default=int(os.environ.get("TSEC_LOG_LIMIT") or "1000")
    )
    p.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("TSEC_POLL_INTERVAL") or "5"),
    )
    p.add_argument("--once", action="store_true")
    p.add_argument(
        "--save-dir",
        default=os.environ.get("TSEC_SAVE_DIR") or "",
        help="directory to append all logs (stream.log + raw sessions)",
    )
    p.add_argument(
        "--no-tui",
        action="store_true",
        help="no full-screen redraw (recommended with --save-dir)",
    )
    args = p.parse_args(argv)

    if not args.token:
        print("missing TSEC_BEARER / --token", file=sys.stderr)
        return 2

    save_dir = Path(args.save_dir).expanduser() if args.save_dir else None
    no_tui = bool(args.no_tui or save_dir)

    try:
        return watch(
            base=args.base,
            token=args.token,
            run_id=args.run_id,
            limit=args.limit,
            interval=args.interval,
            cookie=args.cookie,
            once=args.once,
            save_dir=save_dir,
            no_tui=no_tui,
        )
    except KeyboardInterrupt:
        print("\n[watch] stopped", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
