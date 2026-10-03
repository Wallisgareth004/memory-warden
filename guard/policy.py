"""C1, the per-agent write policy (PreToolUse on Bash, Edit, Write, MultiEdit,
NotebookEdit, and optionally MCP tools).

A subagent's write that would land in a protected root is denied. Reads always
pass. An append-only file may grow (an append, a pure insertion) but not be
rewritten, truncated, replaced or removed. The main thread writes freely
unless the config says otherwise; the effect check still records what it does.

Deny, never ask: in bypass mode prompts are disabled, and before Claude Code
2.1.211 auto mode could approve some "ask" decisions without showing them, so
only "deny" holds in every mode and on every version.

Subagents are told apart by the payload's `agent_id`, which Claude Code sets
only inside a subagent (forked agents included, checked on 2.1.283).
"""

from __future__ import annotations

import os

from . import roots
from .config import Config
from .resolver import Resolver

EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}


def deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _absolute(raw: str, cwd: str | None) -> str | None:
    p = os.path.expanduser(raw)
    if os.path.isabs(p):
        return os.path.normpath(p)
    return os.path.normpath(os.path.join(cwd, p)) if cwd else None


def _insertion(old: str, new: str) -> bool:
    """An edit that only adds text: the old text survives whole at either end."""
    return bool(old) and (new.startswith(old) or new.endswith(old))


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _reason(who: str, what: str, cfg: Config) -> str:
    inbox = ", ".join(cfg.roots.allow) if cfg.roots.allow else "no inbox is configured"
    return (
        f"Protected memory: {who} may not write here ({what}). Reads are fine. "
        f"Report the finding to the main thread, or write it to an inbox the guard allows ({inbox})."
    )


def decide(payload: dict, cfg: Config) -> dict | None:
    sub = bool(payload.get("agent_id"))
    if sub and (
        cfg.subagents == "allow" or payload.get("agent_type") in cfg.agent_types_allowed
    ):
        return None
    if not sub and cfg.main == "allow":
        return None
    who = (
        f"a subagent ({payload.get('agent_type') or 'unknown type'})"
        if sub
        else "the main thread"
    )
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd")

    if tool in EDIT_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path")
        path = _absolute(raw, cwd) if isinstance(raw, str) and raw else None
        if path is None:
            return None
        cls = roots.classify(path, cfg)
        if cls == "protected":
            return deny(_reason(who, path, cfg))
        if cls == "append_only":
            if tool == "Edit" and _insertion(
                ti.get("old_string") or "", ti.get("new_string") or ""
            ):
                return None
            edits = ti.get("edits") or []
            if (
                tool == "MultiEdit"
                and edits
                and all(
                    _insertion(e.get("old_string") or "", e.get("new_string") or "")
                    for e in edits
                )
            ):
                return None
            return deny(
                _reason(
                    who, f"{path} is append-only: add lines, never rewrite them", cfg
                )
            )
        return None

    if tool == "Bash":
        command = ti.get("command") or ""
        resolver = Resolver(cfg)
        try:
            why = resolver.write_reason(command, cwd)
        except Exception:  # the parser couldn't read it: the old text check decides
            why = resolver.text_check(command)
        return deny(_reason(who, why, cfg)) if why else None

    if tool.startswith("mcp__") and cfg.mcp_scan:
        for value in _strings(ti):
            if "/" not in value and not value.startswith("~"):
                continue
            path = _absolute(value, cwd)
            if path and roots.classify(path, cfg) in ("protected", "append_only"):
                return deny(_reason(who, f"an MCP call names {path}", cfg))
    return None
