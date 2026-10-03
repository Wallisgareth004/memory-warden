"""Shared test helpers. Every test builds its own synthetic layout in a temp
folder: a fake vault with memory/, hubs/, inbox/ and an append-only
daily-log.md. Nothing here reads a real home folder, vault or log."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_real_trash(monkeypatch):
    """Retention never reaches the real Trash from a test: a no-op stands in."""
    monkeypatch.setenv("GUARD_TRASH", shutil.which("true") or "/usr/bin/true")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A made-up home folder, so `~` in a config never means the real one."""
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    return h


@pytest.fixture
def vault(home):
    """A synthetic second brain: memory/ (protected, with an append-only log),
    hubs/ (protected), inbox/ (subagents may write) and notes/ (unguarded)."""
    v = home / "vault"
    for d in ("memory", "hubs", "inbox", "notes"):
        (v / d).mkdir(parents=True)
    (v / "memory" / "state.md").write_text("state v1\n")
    (v / "memory" / "facts.md").write_text("canon v1\n")
    (v / "memory" / "daily-log.md").write_text("- line 1\n")
    (v / "hubs" / "trading.md").write_text("hub v1\n")
    (v / "notes" / "idea.md").write_text("an idea\n")
    return v


GUARD_TOML = """
[roots]
protected   = ["~/vault/memory", "~/vault/hubs", "~/.claude/projects/*/memory/MEMORY.md"]
append_only = ["~/vault/memory/daily-log.md"]
allow       = ["~/vault/inbox"]
watch       = []

[policy]
subagents = "deny"
main = "allow"
agent_types_allowed = []
case_insensitive = "auto"

[alerts]
sinks = ["log"]

[tripwire]
poll_seconds = 1
settle_seconds = 0.2
drop_line_patterns = []

[state]
dir = "~/.local/state/guard"
"""


@pytest.fixture
def config_file(home, vault):
    path = home / "guard.toml"
    path.write_text(textwrap.dedent(GUARD_TOML))
    return path


def run_hook(component: str, payload, env: dict | None = None, raw: str | None = None):
    """Run hook.py as Claude Code would: JSON on stdin, decision on stdout."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "hook.py"), component],
        input=raw if raw is not None else json.dumps(payload),
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {}), "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=30,
    )
    return proc
