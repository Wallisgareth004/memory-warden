"""C6, the attack suite runner.

    guard attacks [FOLDER] [--report PATH]

Each case in attacks/*.toml is handed to the guard as Claude Code would hand
it a tool call, inside a throwaway sandbox home (a synthetic vault, its own
guard.toml and state folder). Commands are NEVER run: the payload goes to
the hooks, and only the effect the case describes is simulated on disk.

Outcomes: prevented (C1 or C4 denied it, C3a blocked the commit), detected
(C2 blocked it after the call, C3b restored the file, C5 flagged the
watcher), or through. A case passes when its outcome is the one it expects;
the run fails if any case doesn't. "through" cases are the honest list of
what the guard can't see.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

EXPECT = {"deny": "prevented", "detect": "detected", "through": "through"}


@dataclass
class Case:
    id: str
    cls: str
    source: str
    expect: str
    component: str
    agent: str = "subagent"
    tool: str = "Bash"
    command: str = ""
    file: str = ""
    cwd: str = ""
    effect: str = ""
    setup: str = ""
    config: str = ""
    note: str = ""


@dataclass
class Result:
    case: Case
    outcome: str
    by: str = ""
    detail: str = ""

    @property
    def ok(self) -> bool:
        return EXPECT.get(self.case.expect) == self.outcome


def load_cases(folder: Path) -> list[Case]:
    cases = []
    for f in sorted(Path(folder).glob("*.toml")):
        for raw in tomllib.loads(f.read_text(encoding="utf-8")).get("case", []):
            raw = dict(raw)
            raw["cls"] = raw.pop("class")
            cases.append(Case(**raw))
    return cases


@dataclass
class Sandbox:
    root: Path
    home: Path
    vault: Path
    tmp: Path
    project: Path
    config_path: Path
    places: dict = field(default_factory=dict)

    def fill(self, text: str) -> str:
        for key, value in self.places.items():
            text = text.replace("{" + key + "}", value)
        return text


CONFIG = """
[roots]
protected   = ["~/vault/memory", "~/vault/hubs"]
append_only = ["~/vault/memory/daily-log.md"]
allow       = ["~/vault/inbox"]
[policy]
case_insensitive = true
mcp_scan = {mcp_scan}
[alerts]
sinks = ["log"]
[tripwire]
settle_seconds = 0.05
[state]
dir = "{state}"
"""


@contextlib.contextmanager
def sandbox(case: Case):
    saved = {k: os.environ.get(k) for k in ("HOME", "GUARD_CONFIG", "GUARD_TRASH")}
    root = Path(tempfile.mkdtemp(prefix="guard-attack-")).resolve()
    try:
        home, tmp, project = root / "home", root / "tmp", root / "project"
        vault = home / "vault"
        for d in (
            vault / "memory",
            vault / "hubs",
            vault / "inbox",
            vault / "notes",
            home / ".claude" / "skills" / "notes",
            tmp / "empty",
            project,
        ):
            d.mkdir(parents=True, exist_ok=True)
        (vault / "memory" / "state.md").write_text("state v1\n")
        (vault / "memory" / "facts.md").write_text("canon v1\n")
        (vault / "memory" / "daily-log.md").write_text(
            "".join(f"- entry {i}\n" for i in range(1, 9))
        )
        (vault / "hubs" / "trading.md").write_text("hub v1\n")
        for name in ("x", "x.md", "s.py", "evil"):
            (tmp / name).write_text("made up\n")
        config_path = home / "guard.toml"
        config_path.write_text(
            CONFIG.replace(
                "{mcp_scan}", "true" if case.config == "mcp_scan" else "false"
            ).replace("{state}", str(root / "state"))
        )
        os.environ.update(
            {
                "HOME": str(home),
                "GUARD_CONFIG": str(config_path),
                "GUARD_TRASH": shutil.which("true") or "/usr/bin/true",
            }
        )
        box = Sandbox(root, home, vault, tmp, project, config_path)
        box.places = {
            "home": str(home),
            "vault": str(vault),
            "tmp": str(tmp),
            "project": str(project),
        }
        if case.setup.startswith("symlink "):
            link, _, target = box.fill(case.setup[len("symlink ") :]).partition(" -> ")
            os.symlink(target.strip(), link.strip())
        yield box
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(root, ignore_errors=True)  # a scratch folder under the temp dir


def _apply(effect: str, box: Sandbox) -> None:
    """Make on disk the change the attack would have made. Never runs the command."""
    verb, _, rel = effect.partition(" ")
    path = box.vault / rel if rel else None
    if verb == "write":
        with open(path, "a") as fh:
            fh.write("tampered\n")
    elif verb == "create":
        path.write_text("injected\n")
    elif verb == "delete":
        path.unlink()
    elif verb == "stale-overwrite":
        lines = path.read_text().splitlines(keepends=True)
        path.write_text("".join(lines[: len(lines) // 2]))
    elif verb == "swap-symlink":
        path.unlink()
        os.symlink(box.tmp / "evil", path)
    elif verb == "delete-line":
        lines = path.read_text().splitlines(keepends=True)
        path.write_text("".join(lines[:2] + lines[3:]))
    elif verb == "stale-heartbeat":
        hb = box.root / "state" / "tripwire"
        hb.mkdir(parents=True, exist_ok=True)
        (hb / "heartbeat").write_text(f"{time.time() - 3600:.0f} {os.getpid()}\n")
    else:
        raise ValueError(f"unknown effect {effect!r}")


def _payload(case: Case, box: Sandbox) -> dict:
    tool = case.tool or "Bash"
    p: dict = {
        "session_id": "attack",
        "tool_use_id": f"attack-{case.id}",
        "tool_name": tool,
    }
    if tool == "Bash":
        p["tool_input"] = {"command": box.fill(case.command)}
    elif tool.startswith("mcp__"):
        p["tool_input"] = {"path": box.fill(case.file), "content": "x"}
    else:
        p["tool_input"] = {
            "file_path": box.fill(case.file),
            "old_string": "a",
            "new_string": "b",
            "content": "b",
        }
    p["cwd"] = box.fill(case.cwd) if case.cwd else str(box.tmp)
    if case.agent == "subagent":
        p.update(agent_id=f"attack-{case.id}", agent_type="general-purpose")
    return p


def run_case(case: Case) -> Result:
    from . import config, doctor, effect, gate, hooks, selfprotect, tripwire

    with sandbox(case) as box:
        cfg = config.load(box.config_path)
        log = box.vault / "memory" / "daily-log.md"
        touches_log = "daily-log.md" in case.effect

        if case.agent == "commit":
            subprocess.run(["git", "init", "-q", str(box.vault)], check=True)
            for args in (
                ["config", "user.email", "t@example.invalid"],
                ["config", "user.name", "T"],
                ["add", "-A"],
            ):
                subprocess.run(["git", "-C", str(box.vault), *args], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(box.vault),
                    "commit",
                    "-q",
                    "-m",
                    "seed",
                    "--no-verify",
                ],
                check=True,
            )
            _apply(case.effect, box)
            subprocess.run(["git", "-C", str(box.vault), "add", "-A"], check=True)
            problems = gate.append_only_check(box.vault, cfg)
            return (
                Result(case, "prevented", "C3a", problems[0])
                if problems
                else Result(case, "through")
            )

        if case.agent == "sync":
            if case.effect == "stale-heartbeat":
                _apply(case.effect, box)
                c = doctor.tripwire_check(cfg)
                return (
                    Result(case, "through")
                    if c.ok
                    else Result(case, "detected", "C5", c.detail)
                )
            if touches_log:
                tripwire.check_once(log, cfg)
            _apply(case.effect, box)
            if touches_log and tripwire.check_once(log, cfg) == "restored":
                return Result(case, "detected", "C3b", "restored")
            return Result(case, "through", detail="no tool call fired")

        if case.tool == "ConfigChange":
            out = selfprotect.config_change(
                {"hook_event_name": "ConfigChange", "source": "user_settings"}, cfg
            )
            ok = bool(out and out.get("__exit__") == 2)
            return (
                Result(case, "prevented", "C4", "exit 2")
                if ok
                else Result(case, "through")
            )

        payload = _payload(case, box)
        if selfprotect.decide(payload, cfg):
            return Result(case, "prevented", "C4", "denied")
        out = hooks.COMPONENTS["policy"](payload, cfg)
        if out:
            return Result(
                case,
                "prevented",
                "C1",
                out["hookSpecificOutput"]["permissionDecisionReason"][:120],
            )
        if not case.effect:
            return Result(case, "through", detail="the policy allowed it")
        if touches_log:
            tripwire.check_once(log, cfg)
        effect.pre(payload, cfg)
        if not case.effect.startswith("background-write"):
            _apply(case.effect, box)
        out = effect.post(payload, cfg)
        if case.effect.startswith("background-write"):
            _apply(
                "write " + case.effect.split(" ", 1)[1], box
            )  # lands after the call returned
        if out:
            return Result(case, "detected", "C2", out["reason"][:120])
        if touches_log and tripwire.check_once(log, cfg) == "restored":
            return Result(case, "detected", "C3b", "restored")
        return Result(case, "through", detail="nothing caught the effect")


def run_all(folder: Path) -> list[Result]:
    return [run_case(c) for c in load_cases(folder)]


def report(results: list[Result]) -> str:
    by_class: dict = defaultdict(Counter)
    for r in results:
        by_class[r.case.cls][r.outcome] += 1
    total = Counter(r.outcome for r in results)
    n = len(results)
    lines = [
        "| Class | Cases | Prevented | Detected | Through |",
        "|---|---|---|---|---|",
    ]
    for cls in sorted(by_class):
        c = by_class[cls]
        lines.append(
            f"| {cls} | {sum(c.values())} | {c['prevented']} | {c['detected']} | {c['through']} |"
        )
    lines.append(
        f"| **all** | **{n}** | **{total['prevented']}** | **{total['detected']}** | **{total['through']}** |"
    )
    caught = total["prevented"] + total["detected"]
    by_component = Counter(r.by for r in results if r.by)
    parts = ", ".join(f"{k} {v}" for k, v in sorted(by_component.items()))
    lines += [
        "",
        f"Caught {caught} of {n} ({100 * caught / n:.0f}%): prevented {total['prevented']}, detected {total['detected']} ({parts}).",
        "",
        "## What still gets through",
        "",
    ]
    through = [r for r in results if r.outcome == "through"]
    for r in through:
        flag = "" if r.ok else " (UNEXPECTED: it was meant to be caught)"
        note = f" {r.case.note[:1].upper()}{r.case.note[1:]}." if r.case.note else ""
        lines.append(f"- `{r.case.id}` ({r.case.cls}): {r.case.source}.{note}{flag}")
    if not through:
        lines.append("- nothing in this suite")
    wrong = [r for r in results if not r.ok and r.outcome != "through"]
    for r in wrong:
        lines.append(
            f"- `{r.case.id}`: expected {r.case.expect}, got {r.outcome} (UNEXPECTED)"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="guard attacks")
    ap.add_argument(
        "folder",
        nargs="?",
        default=str(Path(__file__).resolve().parents[1] / "attacks"),
    )
    ap.add_argument("--report", help="write the markdown report here")
    args = ap.parse_args(argv)
    results = run_all(Path(args.folder))
    text = report(results)
    if args.report:
        Path(args.report).write_text(text)
    print(text)
    bad = [r for r in results if not r.ok]
    for r in bad:
        print(
            f"MISMATCH {r.case.id}: expected {r.case.expect}, got {r.outcome} ({r.detail})"
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
