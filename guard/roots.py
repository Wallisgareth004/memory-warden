"""Which root a path falls in: "allow", "append_only", "protected", or None.

Roots are anchored absolute paths from guard.toml (globs allowed: `*` and `?`
never cross a `/`). A path matches a root when it is the root or lies under
it, in its normalised form or its resolved (symlink-followed) form, against
the root as written or the root resolved. Allow wins over append-only, which
wins over protected, so an inbox inside a protected folder stays writable and
an append-only log inside it keeps its own rule.

Case follows the filesystem: cfg.case_insensitive (probed at load) folds case.
"""

from __future__ import annotations

import glob
import os
import re

from .config import Config

ORDER = ("allow", "append_only", "protected")
_GLOB = re.compile(r"[*?\[]")


def _glob_regex(pattern: str, fold: bool) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j < 0:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j]
                out.append(
                    "[" + ("^" + body[1:] if body.startswith("!") else body) + "]"
                )
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE if fold else 0)


def _path_forms(path: str) -> set[str]:
    return {os.path.normpath(path), os.path.realpath(path)}


def _root_forms(root: str) -> set[str]:
    forms = {root}
    if _GLOB.search(root):
        forms.update(os.path.realpath(m) for m in glob.glob(root))
    else:
        forms.add(os.path.realpath(root))
    return forms


def _under(path: str, root: str, fold: bool) -> bool:
    """Is `path` the root, or inside it?"""
    if _GLOB.search(root):
        rx = _glob_regex(root, fold)
        candidate = path
        while True:
            if rx.match(candidate):
                return True
            parent = os.path.dirname(candidate)
            if parent == candidate:
                return False
            candidate = parent
    p, r = (path.lower(), root.lower()) if fold else (path, root)
    r = r.rstrip("/") or "/"
    return p == r or p.startswith(r + "/") or r == "/"


def _ancestor_of(folder: str, root: str, fold: bool) -> bool:
    """Is `folder` the root or a folder above it (component by component, globs allowed)?"""
    f_parts = [x for x in folder.split("/") if x]
    r_parts = [x for x in root.split("/") if x]
    if len(f_parts) > len(r_parts):
        return False
    for f, r in zip(f_parts, r_parts):
        if _GLOB.search(r):
            if not _glob_regex(r, fold).match(f):
                return False
        elif (f.lower() != r.lower()) if fold else (f != r):
            return False
    return True


def classify(path: str, cfg: Config) -> str | None:
    if not os.path.isabs(path):
        raise ValueError(f"classify needs an absolute path, got {path!r}")
    forms = _path_forms(path)
    for kind in ORDER:
        for root in getattr(cfg.roots, kind):
            for rf in _root_forms(root):
                if any(_under(f, rf, cfg.case_insensitive) for f in forms):
                    return kind
    return None


def holds_protected(folder: str, cfg: Config) -> bool:
    """Would removing, moving or overwriting this whole folder touch a protected
    or append-only root? True when the folder is inside one or contains one."""
    if not os.path.isabs(folder):
        raise ValueError(f"holds_protected needs an absolute path, got {folder!r}")
    if classify(folder, cfg) in ("protected", "append_only"):
        return True
    for kind in ("protected", "append_only"):
        for root in getattr(cfg.roots, kind):
            for rf in _root_forms(root):
                for f in _path_forms(folder):
                    if _ancestor_of(f, rf, cfg.case_insensitive) and not _allowed_whole(
                        rf, cfg
                    ):
                        return True
    return False


def _allowed_whole(root: str, cfg: Config) -> bool:
    """A protected root that sits inside an allowed root is the allowed root's business."""
    return any(_under(root, a, cfg.case_insensitive) for a in cfg.roots.allow)
