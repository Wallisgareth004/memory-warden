"""Retention for the guard's evidence and quarantine folders (30 days).

Old entries go to the Trash: $GUARD_TRASH if set, else `trash` (macOS),
else `gio trash` (Linux desktops). Only where no trash exists are they
removed outright.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

KEEP_DAYS = 30


def _trash_command() -> list[str] | None:
    forced = os.environ.get("GUARD_TRASH")
    if forced:
        return [forced]
    found = shutil.which("trash") or (
        "/usr/bin/trash" if os.path.exists("/usr/bin/trash") else None
    )
    if found:
        return [found]
    if shutil.which("gio"):
        return ["gio", "trash"]
    return None


def dispose(paths: list[Path]) -> None:
    if not paths:
        return
    cmd = _trash_command()
    try:
        if cmd:
            subprocess.run([*cmd, *map(str, paths)], timeout=30, capture_output=True)
        else:
            for p in paths:
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(
                    missing_ok=True
                )
    except (OSError, subprocess.SubprocessError):
        pass


def prune(folder: Path, days: int = KEEP_DAYS) -> None:
    cutoff = time.time() - days * 86400
    try:
        old = [p for p in Path(folder).iterdir() if p.stat().st_mtime < cutoff]
    except OSError:
        return
    dispose(sorted(old))
