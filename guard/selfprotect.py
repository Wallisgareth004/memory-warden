"""C4, self-protection. A guard an agent can switch off is no guard.

PreToolUse: no agent, the main thread included, may write the guard's own
files, its config, the Claude settings files that hold the hook entries
(user, project and local), or skills. Deny, not ask: "ask" doesn't hold in
every permission mode. There is no in-session unlock, because an agent could
trigger one itself: end the session, make the change, restart.

ConfigChange: a settings or skills change made mid-session is stopped from
taking effect (exit 2). Claude Code can't block policy_settings changes, so
those are alerted instead, and the doctor's drift check covers them.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from . import alerts, roots
from .config import Config, Roots
from .resolver import Resolver

GUARD_HOME = Path(__file__).resolve().parents[1]
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
REASON = (
    "Guard self-protection: no agent may change the guard's files, its config, the Claude settings that "
    "hold the hooks, or skills, mid-session ({what}). End the session, make the change, and restart."
)


def _project_dirs(cwd: str | None) -> list[Path]:
    """The project folders whose .claude/ settings count: the nearest folder up
    from the working folder that has a .claude/, and the working folder itself,
    where settings could be created from nothing (CVE-2026-25725's shape)."""
    out = []
    for start in filter(None, (cwd, os.environ.get("CLAUDE_PROJECT_DIR"))):
        d = Path(os.path.expanduser(start))
        out.append(d)
        for folder in (d, *d.parents):
            if (folder / ".claude").is_dir():
                out.append(folder)
                break
    return list(dict.fromkeys(out))


def user_paths(cfg: Config) -> list[str]:
    """The guard, its config, and the user's own settings and skills: strict,
    including any whole-tree write that holds them."""
    home = Path(os.path.expanduser("~"))
    paths = [
        GUARD_HOME,
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude" / "skills",
    ]
    if cfg.source is not None:
        paths.append(Path(cfg.source))
    paths += [Path(p) for p in cfg.selfprotect_paths]
    return [os.path.normpath(str(p)) for p in paths]


def project_paths(cwd: str | None) -> list[str]:
    """A project's settings and skills: a write inside its .claude/ counts; a
    whole-tree write on the project (a git pull, an extraction) doesn't, because
    the ConfigChange hook stops any settings change that arrives that way."""
    paths = []
    for project in _project_dirs(cwd):
        paths += [
            project / ".claude" / n
            for n in ("settings.json", "settings.local.json", "skills")
        ]
    return [os.path.normpath(str(p)) for p in paths]


def protected_paths(cfg: Config, cwd: str | None = None) -> list[str]:
    return user_paths(cfg) + project_paths(cwd)


def _inside_dot_claude(path: str, cwd: str | None) -> bool:
    for project in _project_dirs(cwd):
        dot = os.path.normpath(str(project / ".claude"))
        if path == dot or path.startswith(dot + os.sep):
            return True
    return False


def _as_config(cfg: Config, paths: list[str]) -> Config:
    return replace(
        cfg,
        roots=Roots(protected=tuple(paths)),
        subagents="deny",
        main="deny",
        mcp_scan=False,
    )


def deny(what: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": REASON.format(what=what),
        }
    }


def decide(payload: dict, cfg: Config) -> dict | None:
    if not cfg.selfprotect:
        return None
    cwd = payload.get("cwd")
    sp = _as_config(cfg, protected_paths(cfg, cwd))
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    if tool in EDIT_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path")
        if not isinstance(raw, str) or not raw:
            return None
        p = os.path.expanduser(raw)
        if not os.path.isabs(p):
            if not cwd:
                return None
            p = os.path.join(cwd, p)
        return (
            deny(os.path.normpath(p))
            if roots.classify(os.path.normpath(p), sp) == "protected"
            else None
        )
    if tool == "Bash":
        command = ti.get("command") or ""
        strict = _as_config(cfg, user_paths(cfg))
        project = _as_config(cfg, project_paths(cwd))
        passes = [Resolver(strict)]
        if project.roots.protected:
            passes.append(
                Resolver(
                    project,
                    tree_rule=lambda path: (
                        roots.classify(path, project) == "protected"
                        or (
                            roots.holds_protected(path, project)
                            and _inside_dot_claude(path, cwd)
                        )
                    ),
                )
            )
        for resolver in passes:
            try:
                why = resolver.write_reason(command, cwd)
            except Exception:
                why = resolver.text_check(command)
            if why:
                return deny(why)
        return None
    return None


def config_change(payload: dict, cfg: Config) -> dict | None:
    """Stop a mid-session settings or skills change (exit 2), or alert when it can't be stopped."""
    if not cfg.selfprotect:
        return None
    source = next(
        (
            payload.get(k)
            for k in ("source", "config_source", "matcher")
            if isinstance(payload.get(k), str)
        ),
        "settings",
    )
    if source == "policy_settings":
        alerts.send(
            f"a policy_settings change took effect mid-session (it can't be blocked): {source}",
            cfg,
        )
        return None
    alerts.send(f"blocked a mid-session configuration change ({source})", cfg)
    return {"__exit__": 2, "stderr": REASON.format(what=f"a {source} change")}
