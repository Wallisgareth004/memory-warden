"""C2, intent vs effect (PreToolUse + PostToolUse on every tool).

The write policy (C1) reads a command's text, so a write from inside a script
file (`python3 /tmp/s.py`) or through an MCP tool gets past it. This check
looks at the disk instead.

Pre, for a subagent call: fingerprint every file under the protected,
append-only and watched roots (size, mtime, inode; a content cache keeps one
copy per file for comparisons and before-copies), and store the intent: the
write targets the policy predicted.

Post: diff the fingerprints. For each change:
  * violation: a protected file changed, appeared or vanished;
  * append-only breach: an append-only file shrank or was rewritten (growth is fine);
  * unexpected effect: a watched (opt-in) file changed that nobody predicted;
  * a same-content touch is ignored.
A violation or breach makes the post hook return {"decision": "block"} so the
subagent is told to stop, sends one alert line (paths, time, agent type, never
content), and keeps the before-copy in the quarantine folder (owner-only, kept
30 days). An unexpected effect is alerted only. Nothing is ever restored: a
restore could wipe a real main-thread write made in the same second.

Main-thread calls leave markers (the path an Edit names; the time window of a
command that names a guarded area or git), so a change the main thread made
during a subagent's call is never blamed on the subagent.

Known limits: a write that lands after the call returns (a background job) is
outside the window; the next call's fingerprint catches it, but a subagent's
last call has no next one.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from . import alerts, retention, roots
from .config import Config, ensure_state_dir
from .resolver import Resolver

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
MARKER_TTL = 600  # seconds a main-thread marker stays useful
SLACK = 2.0  # seconds either side of a subagent's call window


def _dir(cfg: Config, *parts: str) -> Path:
    d = ensure_state_dir(cfg).joinpath(*parts)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _walk(root: str) -> list[str]:
    out = []
    for match in glob.glob(root) if re.search(r"[*?\[]", root) else [root]:
        if os.path.isfile(match):
            out.append(match)
        elif os.path.isdir(match):
            for dirpath, dirnames, filenames in os.walk(match):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                out.extend(
                    os.path.join(dirpath, f) for f in filenames if not f.startswith(".")
                )
    return out


def watched(cfg: Config) -> dict[str, str]:
    """{path: class} for every file now under a guarded or watched root."""
    out: dict[str, str] = {}
    for kind in ("watch", "protected", "append_only"):  # later classes win
        for root in getattr(cfg.roots, kind):
            for path in _walk(root):
                cls = roots.classify(path, cfg) or (
                    "watch" if kind == "watch" else None
                )
                if cls in ("protected", "append_only", "watch"):
                    out[path] = cls
                elif cls is None and kind == "watch":
                    out[path] = "watch"
    return out


def fingerprint(paths) -> dict[str, list[int]]:
    fp = {}
    for p in paths:
        try:
            st = os.stat(p)
            fp[p] = [st.st_size, st.st_mtime_ns, st.st_ino]
        except OSError:
            pass
    return fp


def _cache_file(cfg: Config, path: str, sig) -> Path:
    h = hashlib.sha1(path.encode()).hexdigest()[:16]
    return _dir(cfg, "effect", "cache") / f"{h}-{sig[0]}-{sig[1]}"


def _cache_now(cfg: Config, path: str, sig) -> None:
    """Keep a copy of this version of `path` (one version per path)."""
    dest = _cache_file(cfg, path, sig)
    if dest.exists():
        return
    prefix = dest.name.split("-")[0] + "-"
    tmp = dest.with_name(dest.name + f".{os.getpid()}.tmp")
    try:
        shutil.copyfile(path, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except OSError:
        return
    for old in dest.parent.glob(prefix + "*"):
        if old != dest and not old.name.endswith(".tmp"):
            try:
                old.unlink()  # an older cached version of the same file: the guard's own state
            except OSError:
                pass


def _read_cached(cfg: Config, path: str, sig) -> bytes | None:
    try:
        return _cache_file(cfg, path, sig).read_bytes()
    except OSError:
        return None


def call_key(payload: dict) -> str:
    tid = payload.get("tool_use_id")
    if tid:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", str(tid))
    raw = json.dumps(
        [
            payload.get("session_id"),
            payload.get("agent_id"),
            payload.get("tool_name"),
            payload.get("tool_input"),
        ],
        sort_keys=True,
        default=str,
    )
    return hashlib.sha1(raw.encode()).hexdigest()


def _append_line(path: Path, obj: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")


def _recent(path: Path, now: float) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if now - max(rec.get("ts", 0), rec.get("end") or 0) < MARKER_TTL:
                    out.append(rec)
    except OSError:
        pass
    return out


def _intent(payload: dict, cfg: Config) -> list[str]:
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd")
    if tool in EDIT_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path")
        if isinstance(raw, str) and raw:
            p = os.path.expanduser(raw)
            return [
                os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd or "/", p))
            ]
        return []
    if tool == "Bash":
        try:
            return Resolver(cfg).predicted_targets(ti.get("command") or "", cwd)
        except Exception:
            return []
    return []


def _mark_main(payload: dict, mode: str, cfg: Config) -> None:
    """The main thread's own writes, remembered so they aren't blamed on a
    subagent whose call window they fall in."""
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    now = time.time()
    d = _dir(cfg, "effect")
    if mode == "pre" and tool in EDIT_TOOLS:
        p = ti.get("file_path") or ti.get("notebook_path")
        if p:
            _append_line(
                d / "main-edits.jsonl",
                {"path": os.path.normpath(os.path.expanduser(p)).lower(), "ts": now},
            )
    elif mode == "pre" and tool.startswith("mcp__") and isinstance(ti.get("path"), str):
        _append_line(d / "main-edits.jsonl", {"path": "*mcp*", "ts": now})
    elif tool == "Bash":
        command = ti.get("command") or ""
        r = Resolver(cfg)
        names = (r.names_protected and r.names_protected.search(command)) or (
            r.names_area and r.names_area.search(command)
        )
        if names or re.search(r"\bgit\b", command):
            rec = {
                "key": call_key(payload),
                "ts": now,
                "end": now if mode == "post" else None,
            }
            _append_line(d / "main-bash.jsonl", rec)


def _excused(path: str, start: float, end: float, cfg: Config, now: float) -> bool:
    d = _dir(cfg, "effect")
    low = path.lower()
    for rec in _recent(d / "main-edits.jsonl", now):
        if (
            rec.get("path") in (low, "*mcp*")
            and start - SLACK <= rec.get("ts", 0) <= end + SLACK
        ):
            return True
    windows: dict = {}
    for rec in _recent(d / "main-bash.jsonl", now):
        w = windows.setdefault(rec["key"], [rec["ts"], None])
        if rec.get("end") is not None:
            w[1] = rec["end"]
        else:
            w[0] = min(w[0], rec["ts"])
    return any(
        s <= end + SLACK and (e is None or e >= start - SLACK)
        for s, e in windows.values()
    )


def pre(payload: dict, cfg: Config) -> None:
    if not payload.get("agent_id"):
        _mark_main(payload, "pre", cfg)
        return None
    files = watched(cfg)
    fp = fingerprint(files)
    for p, sig in fp.items():
        _cache_now(cfg, p, sig)
    snap = {
        "ts": time.time(),
        "fp": fp,
        "classes": files,
        "intent": _intent(payload, cfg),
    }
    path = _dir(cfg, "effect", "snapshots") / f"snap-{call_key(payload)}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(snap, fh)
    return None


def post(payload: dict, cfg: Config) -> dict | None:
    if not payload.get("agent_id"):
        _mark_main(payload, "post", cfg)
        return None
    path = _dir(cfg, "effect", "snapshots") / f"snap-{call_key(payload)}.json"
    try:
        snap = json.loads(path.read_text(encoding="utf-8"))
        path.unlink()  # the guard's own scratch state
    except (OSError, ValueError):
        return None
    start, now = snap["ts"], time.time()
    before = {p: tuple(v) for p, v in snap["fp"].items()}
    now_files = watched(cfg)
    after = {p: tuple(v) for p, v in fingerprint(now_files).items()}
    classes = {**snap.get("classes", {}), **now_files}
    intent = set(snap.get("intent") or [])
    breaches, unexpected = [], []
    for p in sorted(set(before) | set(after)):
        a, b = before.get(p), after.get(p)
        if a == b:
            continue
        old = _read_cached(cfg, p, a) if a else None
        cur = None
        if b:
            try:
                cur = Path(p).read_bytes()
            except OSError:
                pass
        if a and b and old is not None and cur == old:
            continue  # touched, same content
        cls = classes.get(p)
        if (
            cls == "append_only"
            and a
            and b
            and old is not None
            and cur is not None
            and cur.startswith(old)
        ):
            continue  # it grew: fine
        if cls == "watch":
            if p not in intent:
                unexpected.append(
                    (p, "changed" if a and b else ("new" if b else "deleted"))
                )
            continue
        if _excused(p, start, now, cfg, now):
            continue
        kind = "changed" if a and b else ("new" if b else "deleted")
        if cls == "append_only":
            kind = "append-only rewritten" if b else "append-only deleted"
        breaches.append((p, kind, old))

    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    who = payload.get("agent_type") or "subagent"
    tool = payload.get("tool_name")
    if unexpected:
        names = "; ".join(f"{k} {p}" for p, k in unexpected)
        alerts.send(
            f"{stamp} · {who} · {tool} · unexpected effect (nobody predicted it): {names}",
            cfg,
        )
    if not breaches:
        return None
    names = [f"{kind} {p}" for p, kind, _old in breaches]
    qroot = _dir(cfg, "quarantine")
    qdir = qroot / (time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}")
    qdir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(qdir, 0o700)
    for p, _kind, old in breaches:
        if old is not None:
            dest = qdir / (os.path.basename(p) + ".before")
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(old)
    retention.prune(qroot)
    alerts.send(f"{stamp} · {who} · {tool} · " + "; ".join(names), cfg)
    predicted = ", ".join(sorted(intent)) if intent else "no write at all"
    return {
        "decision": "block",
        "reason": (
            "Protected memory changed during this call (" + "; ".join(names) + "). "
            f"The policy predicted: {predicted}. Subagents may not write protected memory by any route: "
            f"stop and report to the main thread. Nothing was restored; the before-copy is in {qdir}."
        ),
    }
