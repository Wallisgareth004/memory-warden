"""C5, the doctor. Hooks fail open on a crash, a timeout or a missing script,
so the doctor proves the guard is installed, runnable, deciding and alive.

    guard doctor [--accept] [--expect-recent MINUTES]

Checks, each PASS or FAIL:
  * config: guard.toml loads and protects something;
  * present: every guard hook is in the merged Claude settings (user, project,
    local) for its event, with a matcher that covers the tools it must see;
  * runnable: each hook's interpreter exists and is Python 3.11+, its script
    exists, and its timeout isn't shorter than 5 s;
  * self-test: the installed policy hook, fed a canned subagent write to a
    scratch protected root, must answer deny;
  * firing (with --expect-recent, e.g. from inside a session): every hook's
    heartbeat is recent;
  * tripwire: its watcher's heartbeat is fresh and its process alive;
  * gate: each repo in [doctor] repos has core.hooksPath on the guard's githooks;
  * gitleaks: found;
  * drift: the guard's files, its hook entries and its config match the last
    accepted baseline (the first run records it; --accept re-records it).

The SessionStart hook runs the same checks ("doctor-fast") and, only when
something fails, adds a warning to the session's context and sends an alert.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import alerts, gate
from .config import Config, ensure_state_dir

GUARD_HOME = Path(__file__).resolve().parents[1]
EDIT = ["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"]
REQUIRED = [
    ("PreToolUse", "policy", EDIT),
    ("PreToolUse", "effect-pre", EDIT + ["mcp__any__tool"]),
    ("PostToolUse", "effect-post", EDIT + ["mcp__any__tool"]),
    (
        "ConfigChange",
        "config-change",
        ["user_settings", "project_settings", "local_settings", "skills"],
    ),
    ("SessionStart", "doctor-fast", []),
]
MIN_TIMEOUT = 5


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


def _settings_files() -> list[Path]:
    home = Path(os.path.expanduser("~"))
    files = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
    ]
    project = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    files += [
        Path(project) / ".claude" / n for n in ("settings.json", "settings.local.json")
    ]
    return [f for f in dict.fromkeys(files) if f.is_file()]


def hook_entries() -> list[dict]:
    """Every command hook in the merged settings: event, matcher, command, timeout."""
    out = []
    for f in _settings_files():
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for event, groups in (data.get("hooks") or {}).items():
            for group in groups or []:
                for h in group.get("hooks") or []:
                    if h.get("type", "command") == "command" and h.get("command"):
                        out.append(
                            {
                                "event": event,
                                "matcher": group.get("matcher", ""),
                                "command": h["command"],
                                "timeout": h.get("timeout"),
                                "file": str(f),
                            }
                        )
    return out


def _component_of(command: str) -> str | None:
    m = re.search(r"hook\.py['\"]?\s+([a-z-]+)", command)
    return m.group(1) if m else None


def _covers(matcher: str, tool: str) -> bool:
    if matcher in ("", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return tool in matcher.split("|")


def _runnable(entry: dict) -> str | None:
    """Why this hook can't run, or None."""
    try:
        argv = shlex.split(entry["command"])
    except ValueError:
        return f"its command can't be parsed: {entry['command']}"
    interp = argv[0]
    exe = interp if "/" in interp else shutil.which(interp)
    if not exe or not os.access(exe, os.X_OK):
        return f"interpreter not found: {interp}"
    if len(argv) < 2 or not os.path.isfile(argv[1]):
        return f"script not found: {argv[1] if len(argv) > 1 else '(none)'}"
    try:
        ok = subprocess.run(
            [
                exe,
                "-c",
                "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)",
            ],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return f"interpreter won't run: {e}"
    if ok.returncode != 0:
        return f"{interp} is older than Python 3.11"
    if entry.get("timeout") is not None and entry["timeout"] < MIN_TIMEOUT:
        return f"timeout {entry['timeout']} s is under {MIN_TIMEOUT} s"
    return None


def _self_test(entry: dict) -> str | None:
    """Feed the installed policy hook a canned subagent write to a scratch
    protected root. Why it failed, or None."""
    scratch = Path(tempfile.mkdtemp(prefix="guard-selftest-"))
    try:
        (scratch / "memory").mkdir()
        cfg = scratch / "guard.toml"
        cfg.write_text(
            f'[roots]\nprotected = ["{scratch / "memory"}"]\n[policy]\ncase_insensitive = false\n'
            f'[state]\ndir = "{scratch / "state"}"\n'
        )
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": f"echo x >> {scratch / 'memory' / 'probe.md'}"},
            "agent_id": "doctor-self-test",
            "agent_type": "doctor",
            "cwd": str(scratch),
        }
        run = subprocess.run(
            shlex.split(entry["command"]),
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "GUARD_CONFIG": str(cfg)},
        )
        try:
            decision = json.loads(run.stdout)["hookSpecificOutput"][
                "permissionDecision"
            ]
        except (ValueError, KeyError, TypeError):
            decision = "allow"
        return (
            None
            if decision == "deny"
            else f"a subagent write to a protected root came back {decision}"
        )
    except (OSError, subprocess.SubprocessError) as e:
        return f"it couldn't run: {e}"
    finally:
        shutil.rmtree(
            scratch, ignore_errors=True
        )  # a scratch folder under the temp dir


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(cfg: Config, entries: list[dict]) -> dict:
    files = sorted(
        [
            *GUARD_HOME.glob("guard/*.py"),
            GUARD_HOME / "hook.py",
            GUARD_HOME / "githooks" / "pre-commit",
        ]
    )
    out = {
        str(f.relative_to(GUARD_HOME)): _sha(f.read_bytes())
        for f in files
        if f.is_file()
    }
    mine = sorted(
        (e["event"], e["matcher"], e["command"], str(e["timeout"]))
        for e in entries
        if _component_of(e["command"])
    )
    out["hook entries"] = _sha(json.dumps(mine).encode())
    if cfg.source is not None and Path(cfg.source).is_file():
        out["guard.toml"] = _sha(Path(cfg.source).read_bytes())
    return out


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def tripwire_check(cfg: Config) -> Check:
    """Is the tripwire watcher alive? Its heartbeat must be fresh and its process running."""
    hb = cfg.state_dir / "tripwire" / "heartbeat"
    if not hb.exists():
        return Check(
            "tripwire: watching",
            False,
            "no heartbeat: start it with `guard tripwire watch`",
        )
    ts, _, pid = hb.read_text().strip().partition(" ")
    age = time.time() - float(ts)
    limit = max(10.0, 5 * cfg.poll_seconds)
    ok = age <= limit and pid.isdigit() and _alive(int(pid))
    detail = f"heartbeat {age:.0f} s old, pid {pid}" + (
        "" if ok else " (stale or not running)"
    )
    return Check("tripwire: watching", ok, detail)


def check(
    cfg: Config, accept: bool = False, expect_recent_minutes: float | None = None
) -> list[Check]:
    checks: list[Check] = []
    n = len(cfg.roots.protected)
    checks.append(
        Check(
            "config",
            n > 0,
            f"protects {n} root{'s' if n != 1 else ''}"
            if n
            else "guard.toml protects nothing",
        )
    )

    entries = hook_entries()
    policy_entry = None
    for event, component, tools in REQUIRED:
        mine = [
            e
            for e in entries
            if e["event"] == event and _component_of(e["command"]) == component
        ]
        name = f"present: {event} {component}"
        if not mine:
            checks.append(Check(name, False, "no hook entry runs it"))
            continue
        missed = [t for t in tools if not any(_covers(e["matcher"], t) for e in mine)]
        checks.append(
            Check(
                name,
                not missed,
                f"its matcher doesn't cover {', '.join(missed)}" if missed else "ok",
            )
        )
        for e in mine:
            why = _runnable(e)
            checks.append(
                Check(
                    f"runnable: {event} {component}", why is None, why or e["command"]
                )
            )
            if component == "policy" and why is None:
                policy_entry = e
    if policy_entry is not None:
        why = _self_test(policy_entry)
        checks.append(
            Check(
                "self-test: a subagent write is denied",
                why is None,
                why or "deny, as it should",
            )
        )
    else:
        checks.append(
            Check(
                "self-test: a subagent write is denied",
                False,
                "no runnable policy hook to test",
            )
        )

    beats = cfg.state_dir / "heartbeats"
    if expect_recent_minutes is not None:
        for _event, component, _tools in REQUIRED:
            f = beats / component
            if not f.exists():
                checks.append(
                    Check(f"firing: {component}", False, "it has never fired")
                )
                continue
            age = time.time() - float(f.read_text().split()[0])
            ok = age <= expect_recent_minutes * 60
            checks.append(
                Check(f"firing: {component}", ok, f"last fired {age / 60:.0f} min ago")
            )

    if cfg.roots.append_only:
        checks.append(tripwire_check(cfg))

    for repo in cfg.doctor_repos:
        run = subprocess.run(
            ["git", "-C", repo, "config", "core.hooksPath"],
            capture_output=True,
            text=True,
        )
        path = run.stdout.strip()
        want = GUARD_HOME / "githooks"
        ok = bool(path) and os.path.realpath(
            os.path.expanduser(path)
        ) == os.path.realpath(want)
        ok = ok and os.access(want / "pre-commit", os.X_OK)
        checks.append(
            Check(f"gate: installed in {repo}", ok, path or "core.hooksPath isn't set")
        )

    leaks = gate.find_gitleaks()
    checks.append(
        Check(
            "gitleaks: found",
            leaks is not None,
            leaks or "not found: the gate will block every commit",
        )
    )

    d = ensure_state_dir(cfg) / "doctor"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    base_f = d / "baseline.json"
    now_fp = _fingerprint(cfg, entries)
    if accept or not base_f.exists():
        fd = os.open(base_f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(now_fp, fh, indent=1, sort_keys=True)
        checks.append(
            Check("drift: matches the accepted baseline", True, "baseline recorded")
        )
    else:
        base = json.loads(base_f.read_text(encoding="utf-8"))
        changed = sorted(
            k for k in set(base) | set(now_fp) if base.get(k) != now_fp.get(k)
        )
        detail = (
            (
                "changed since the accepted baseline: "
                + ", ".join(changed)
                + " (guard doctor --accept)"
            )
            if changed
            else "ok"
        )
        checks.append(
            Check("drift: matches the accepted baseline", not changed, detail)
        )
    return checks


def table(checks: list[Check]) -> str:
    return "\n".join(
        f"{'PASS' if c.ok else 'FAIL'}  {c.name:<44}  {c.detail}" for c in checks
    )


def fast(payload: dict, cfg: Config) -> dict | None:
    """The SessionStart hook: quiet when all is well, a warning when not."""
    bad = [c for c in check(cfg) if not c.ok]
    if not bad:
        return None
    lines = "; ".join(f"{c.name} ({c.detail})" for c in bad)
    alerts.send(f"guard doctor: {len(bad)} problem(s): {lines}", cfg)
    return {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": f"Guard doctor found {len(bad)} problem(s), so protection may be off: {lines}",
        }
    }


def main(argv: list[str]) -> int:
    import argparse

    from .config import load

    ap = argparse.ArgumentParser(prog="guard doctor")
    ap.add_argument(
        "--accept", action="store_true", help="re-record the drift baseline"
    )
    ap.add_argument("--expect-recent", type=float, default=None, metavar="MINUTES")
    args = ap.parse_args(argv)
    checks = check(load(), accept=args.accept, expect_recent_minutes=args.expect_recent)
    print(table(checks))
    return 0 if all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
