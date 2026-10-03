"""guard.toml: one config file for every component.

Roots are anchored when the file is read: `~` expands to the home folder and
every root must then be absolute, so a protected root can't accidentally match
a lookalike path somewhere else. Globs (`*`) stay as patterns and are matched
when a path is checked.

The file is found at $GUARD_CONFIG, else ~/.config/guard/guard.toml. With no
file the guard protects nothing (and the doctor says so).
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

SINKS = ("log", "stderr", "macos-notify", "linux-notify", "webhook")

SCHEMA = {
    "roots": {"protected", "append_only", "allow", "watch"},
    "policy": {
        "subagents",
        "main",
        "agent_types_allowed",
        "case_insensitive",
        "mcp_scan",
    },
    "alerts": {"sinks", "webhook_url"},
    "tripwire": {"poll_seconds", "settle_seconds", "drop_line_patterns"},
    "state": {"dir"},
    "selfprotect": {"enabled", "paths"},
    "doctor": {"repos"},
}


class ConfigError(ValueError):
    """guard.toml can't be used as written; the message names the key."""


@dataclass(frozen=True)
class Roots:
    protected: tuple = ()
    append_only: tuple = ()
    allow: tuple = ()
    watch: tuple = ()


@dataclass(frozen=True)
class Config:
    roots: Roots = field(default_factory=Roots)
    subagents: str = "deny"
    main: str = "allow"
    agent_types_allowed: tuple = ()
    case_insensitive: bool = False
    mcp_scan: bool = False
    sinks: tuple = ("log",)
    webhook_url: str | None = None
    poll_seconds: float = 1.0
    settle_seconds: float = 2.0
    drop_line_patterns: tuple = ()
    state_dir: Path = Path("~/.local/state/guard")
    selfprotect: bool = True
    selfprotect_paths: tuple = ()
    doctor_repos: tuple = ()
    source: Path | None = None


def default_path() -> Path:
    return Path(
        os.environ.get("GUARD_CONFIG")
        or Path.home() / ".config" / "guard" / "guard.toml"
    )


def anchor(raw, where: str) -> str:
    """An absolute, normalised path (globs kept), or ConfigError."""
    if not isinstance(raw, str) or not raw.strip():
        raise ConfigError(f"{where}: {raw!r} isn't a path")
    expanded = os.path.expanduser(raw.strip())
    if not os.path.isabs(expanded):
        raise ConfigError(
            f"{where}: {raw!r} isn't anchored: use an absolute path or one starting with ~/"
        )
    return os.path.normpath(expanded)


def probe_case_insensitive(directory: Path) -> bool:
    """Does this filesystem treat FOO and foo as one name? Read-only: it asks
    whether the case-swapped spelling of an existing folder names the same one."""
    d = Path(directory).resolve()
    for candidate in (d, *d.parents):
        name = candidate.name
        if name and name.swapcase() != name:
            swapped = candidate.parent / name.swapcase()
            try:
                return swapped.exists() and os.path.samefile(candidate, swapped)
            except OSError:
                return False
    return False


def _strings(table: dict, key: str, where: str) -> tuple:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}.{key} must be a list of strings")
    return tuple(value)


def _number(
    table: dict, key: str, default: float, where: str, minimum: float, open_low: bool
) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}.{key} must be a number")
    if value < minimum or (open_low and value == minimum):
        bound = f"above {minimum}" if open_low else f"at least {minimum}"
        raise ConfigError(f"{where}.{key} must be {bound} (got {value})")
    return float(value)


def from_dict(raw: dict, source: Path | None = None) -> Config:
    for section, value in raw.items():
        if section not in SCHEMA:
            raise ConfigError(
                f"unknown section [{section}] (known: {', '.join(SCHEMA)})"
            )
        if not isinstance(value, dict):
            raise ConfigError(f"[{section}] must be a table")
        unknown = sorted(set(value) - SCHEMA[section])
        if unknown:
            raise ConfigError(
                f"[{section}]: unknown key(s) {', '.join(unknown)} (known: {', '.join(sorted(SCHEMA[section]))})"
            )

    r = raw.get("roots", {})
    roots = Roots(
        **{
            k: tuple(anchor(p, f"roots.{k}") for p in _strings(r, k, "roots"))
            for k in SCHEMA["roots"]
        }
    )

    p = raw.get("policy", {})
    subagents = p.get("subagents", "deny")
    if subagents not in ("deny", "allow"):
        raise ConfigError(
            f"policy.subagents must be deny or allow (got {subagents!r}); ask doesn't hold in every mode"
        )
    main = p.get("main", "allow")
    if main not in ("deny", "allow"):
        raise ConfigError(f"policy.main must be deny or allow (got {main!r})")
    allowed_types = _strings(p, "agent_types_allowed", "policy")
    case = p.get("case_insensitive", "auto")
    if case == "auto":
        case_insensitive = probe_case_insensitive(Path.home())
    elif isinstance(case, bool):
        case_insensitive = case
    else:
        raise ConfigError(
            f"policy.case_insensitive must be auto, true or false (got {case!r})"
        )

    mcp_scan = p.get("mcp_scan", False)
    if not isinstance(mcp_scan, bool):
        raise ConfigError("policy.mcp_scan must be true or false")

    a = raw.get("alerts", {})
    sinks = _strings(a, "sinks", "alerts") if "sinks" in a else ("log",)
    strange = [s for s in sinks if s not in SINKS]
    if strange:
        raise ConfigError(
            f"alerts.sinks: unknown sink(s) {', '.join(strange)} (known: {', '.join(SINKS)})"
        )
    webhook = a.get("webhook_url")
    if "webhook" in sinks:
        if not isinstance(webhook, str) or not webhook:
            raise ConfigError(
                "alerts.sinks has webhook, so alerts.webhook_url must be set"
            )
        if not webhook.startswith("https://"):
            raise ConfigError(
                "alerts.webhook_url must be https:// (alerts name files and agents)"
            )

    t = raw.get("tripwire", {})
    patterns = []
    for pat in _strings(t, "drop_line_patterns", "tripwire"):
        try:
            patterns.append(re.compile(pat))
        except re.error as e:
            raise ConfigError(
                f"tripwire.drop_line_patterns: {pat!r} isn't a valid regex ({e})"
            ) from None

    sp = raw.get("selfprotect", {})
    sp_enabled = sp.get("enabled", True)
    if not isinstance(sp_enabled, bool):
        raise ConfigError("selfprotect.enabled must be true or false")
    sp_paths = tuple(
        anchor(p, "selfprotect.paths") for p in _strings(sp, "paths", "selfprotect")
    )

    dr = raw.get("doctor", {})
    doctor_repos = tuple(
        anchor(p, "doctor.repos") for p in _strings(dr, "repos", "doctor")
    )

    s = raw.get("state", {})
    state_dir = Path(anchor(s.get("dir", "~/.local/state/guard"), "state.dir"))

    return Config(
        roots=roots,
        subagents=subagents,
        main=main,
        agent_types_allowed=allowed_types,
        case_insensitive=case_insensitive,
        mcp_scan=mcp_scan,
        sinks=tuple(sinks),
        webhook_url=webhook,
        poll_seconds=_number(t, "poll_seconds", 1.0, "tripwire", 0, open_low=True),
        settle_seconds=_number(t, "settle_seconds", 2.0, "tripwire", 0, open_low=False),
        drop_line_patterns=tuple(patterns),
        state_dir=state_dir,
        selfprotect=sp_enabled,
        selfprotect_paths=sp_paths,
        doctor_repos=doctor_repos,
        source=source,
    )


def load(path: Path | str | None = None) -> Config:
    path = Path(path) if path is not None else default_path()
    if not path.exists():
        return Config(
            state_dir=Path(os.path.expanduser("~/.local/state/guard")), source=None
        )
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path.name} isn't valid TOML: {e}") from None
    return from_dict(raw, source=path)


def ensure_state_dir(cfg: Config) -> Path:
    """The state folder (owner-only), with any missing parents."""
    d = cfg.state_dir
    missing = [p for p in (d, *d.parents) if not p.exists()]
    d.mkdir(parents=True, exist_ok=True)
    for p in missing:
        os.chmod(p, 0o700)
    os.chmod(d, 0o700)
    return d
