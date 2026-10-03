"""The repo's leak check: no personal strings in any file git would publish.

Generic patterns catch a real user's home-folder path anywhere. Private
patterns (a name, a vault's folder names, a handle) come from a file kept
outside the repo's published files, so the list itself never leaks. A
licence's copyright line is the one place an author's name belongs, so that
line alone is skipped.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

GENERIC = [
    re.compile(r"/Users/(?!Shared\b)[A-Za-z][\w.-]*"),
    re.compile(r"[Cc]:\\Users\\[A-Za-z][\w.-]*"),
]
LICENCE_FILE = re.compile(r"(?i)(licen[cs]e|copying)(\.\w+)?")
COPYRIGHT_LINE = re.compile(r"\s*Copyright\b")


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    pattern: str


def patterns(private_file: Path | None) -> list[re.Pattern]:
    out = list(GENERIC)
    if private_file is not None and Path(private_file).is_file():
        for raw in Path(private_file).read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("#"):
                out.append(re.compile(raw))
    return out


def publishable_files(root: Path) -> list[str]:
    """Tracked files plus new ones git would add (ignored files excluded)."""
    run = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in run.stdout.splitlines() if line]


def scan(
    root: Path, pats: list[re.Pattern], files: list[str] | None = None
) -> list[Hit]:
    root = Path(root)
    hits = []
    for rel in files if files is not None else publishable_files(root):
        path = root / rel
        try:
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary files are checked by their own review
        licence = LICENCE_FILE.fullmatch(Path(rel).name) is not None
        for n, line in enumerate(text.splitlines(), start=1):
            if licence and COPYRIGHT_LINE.match(line):
                continue
            for pat in pats:
                if pat.search(line):
                    hits.append(Hit(rel, n, pat.pattern))
    return hits
