"""C3a, the pre-commit gate. Every check fails closed.

1. Secrets: gitleaks scans the staged changes. If gitleaks can't be found the
   commit is blocked: a missing scanner must never mean "no secrets". It is
   looked for on absolute paths too, because a hook run from launchd gets an
   empty PATH.
2. Append-only: a staged file inside an append-only root may not lose a single
   line. The count comes from `git diff --cached --numstat` (renames off), so a
   removed blank line, a deleted file and a renamed one all count.

Escape hatch, documented on every refusal: `git commit --no-verify`, with the
reason in the message. The tripwire and the doctor still see what happens.
Installed for a repo with `git config core.hooksPath /path/to/guard/githooks`,
so the gate is versioned and survives a fresh clone.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from . import config, roots

CANDIDATES = (
    "/opt/homebrew/bin/gitleaks",
    "/usr/local/bin/gitleaks",
    "/usr/bin/gitleaks",
)
HATCH = "A genuine exception: git commit --no-verify, with the reason in the message."


def find_gitleaks() -> str | None:
    forced = os.environ.get("GUARD_GITLEAKS")
    if forced:
        return forced if os.access(forced, os.X_OK) else None
    for c in (*CANDIDATES, shutil.which("gitleaks") or ""):
        if c and os.access(c, os.X_OK):
            return c
    return None


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )


def secrets_check(repo: Path) -> list[str]:
    exe = find_gitleaks()
    if exe is None:
        return [
            "gitleaks not found: commit blocked (fail-closed). The secret scan can't run, so this commit "
            "isn't safe to make. Install it (e.g. brew install gitleaks). " + HATCH
        ]
    run = subprocess.run(
        [
            exe,
            "git",
            "--pre-commit",
            "--staged",
            "--redact",
            "--no-banner",
            "--log-level",
            "error",
            str(repo),
        ],
        capture_output=True,
        text=True,
    )
    if run.returncode == 0:
        return []
    shown = "\n".join(
        line for line in (run.stdout + run.stderr).splitlines() if line.strip()
    )[:2000]
    return [
        "gitleaks found a possible secret in the staged changes: commit blocked (fail-closed). Remove it, "
        "or add its fingerprint to .gitleaksignore if it's a false positive.\n" + shown
    ]


def append_only_check(repo: Path, cfg: config.Config) -> list[str]:
    run = _git(repo, "diff", "--cached", "--numstat", "--no-renames", "-z")
    if run.returncode != 0:
        return [
            f"couldn't read the staged changes ({run.stderr.strip()}): commit blocked (fail-closed)"
        ]
    problems = []
    for record in run.stdout.split("\0"):
        if not record:
            continue
        added, removed, rel = record.split("\t", 2)
        if removed in ("-", "0"):
            continue  # binary, or nothing removed
        path = str(repo / rel)
        if roots.classify(path, cfg) == "append_only":
            n = int(removed)
            problems.append(
                f"append-only: {rel} lost {n} line{'s' if n != 1 else ''}. To correct an entry, add a "
                f"correction line; never edit or delete. {HATCH}"
            )
    return problems


def main(repo: Path | None = None) -> int:
    try:
        cfg = config.load()
    except config.ConfigError as e:
        print(
            f"guard gate: guard.toml can't be read ({e}): commit blocked (fail-closed). {HATCH}"
        )
        return 1
    if repo is None:
        top = _git(Path.cwd(), "rev-parse", "--show-toplevel")
        if top.returncode != 0:
            print("guard gate: not inside a git repo: commit blocked (fail-closed)")
            return 1
        repo = Path(top.stdout.strip())
    problems = secrets_check(repo) + append_only_check(repo, cfg)
    for p in problems:
        print(f"guard gate: {p}")
    return 1 if problems else 0
