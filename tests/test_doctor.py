"""C5, the doctor. Hooks fail open on a crash, a timeout or a missing script,
so something has to prove they're installed, runnable and firing.

Each case builds a synthetic home with its own ~/.claude/settings.json whose
hook entries point at this repo's hook.py."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import textwrap
import time

import pytest

from conftest import GUARD_TOML, ROOT, run_hook
from guard import config, doctor

PY = shlex.quote(sys.executable)
HOOK = shlex.quote(str(ROOT / "hook.py"))  # the repo path may hold a space


def entries(
    policy_matcher="Bash|Edit|Write|MultiEdit|NotebookEdit", drop=None, command_for=None
):
    def cmd(component):
        return (command_for or {}).get(component, f"{PY} {HOOK} {component}")

    hooks = {
        "PreToolUse": [
            {
                "matcher": policy_matcher,
                "hooks": [{"type": "command", "command": cmd("policy"), "timeout": 10}],
            },
            {
                "matcher": "*",
                "hooks": [
                    {"type": "command", "command": cmd("effect-pre"), "timeout": 10}
                ],
            },
        ],
        "PostToolUse": [
            {
                "matcher": "*",
                "hooks": [
                    {"type": "command", "command": cmd("effect-post"), "timeout": 10}
                ],
            }
        ],
        "ConfigChange": [
            {
                "matcher": "user_settings|project_settings|local_settings|skills",
                "hooks": [
                    {"type": "command", "command": cmd("config-change"), "timeout": 10}
                ],
            }
        ],
        "SessionStart": [
            {
                "hooks": [
                    {"type": "command", "command": cmd("doctor-fast"), "timeout": 10}
                ]
            }
        ],
    }
    if drop:
        hooks.pop(drop)
    return {"hooks": hooks}


@pytest.fixture
def D(home, vault, tmp_path):
    (home / ".claude").mkdir()
    settings = home / ".claude" / "settings.json"
    settings.write_text(json.dumps(entries()))
    repo = home / "vault"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.hooksPath", str(ROOT / "githooks")],
        check=True,
    )
    fake_gitleaks = tmp_path / "gitleaks"
    fake_gitleaks.write_text("#!/bin/sh\nexit 0\n")
    fake_gitleaks.chmod(0o755)
    state = tmp_path / "state"
    text = (
        textwrap.dedent(GUARD_TOML).replace(
            'dir = "~/.local/state/guard"', f'dir = "{state}"'
        )
        + '\n[doctor]\nrepos = ["~/vault"]\n'
    )
    cfg_path = home / "guard.toml"
    cfg_path.write_text(text)
    cfg = config.load(cfg_path)
    beat = state / "tripwire"
    beat.mkdir(parents=True)
    (beat / "heartbeat").write_text(f"{time.time():.0f} {os.getpid()}\n")

    class X:
        pass

    x = X()
    x.home, x.settings, x.cfg_path, x.cfg, x.state = (
        home,
        settings,
        cfg_path,
        cfg,
        state,
    )
    x.env = {"GUARD_CONFIG": str(cfg_path), "GUARD_GITLEAKS": str(fake_gitleaks)}
    return x


def run(D, monkeypatch, **kw):
    for k, v in D.env.items():
        monkeypatch.setenv(k, v)
    return doctor.check(D.cfg, **kw)


def failures(checks):
    return [c for c in checks if not c.ok]


def test_a_healthy_install_passes_every_check(D, monkeypatch):
    checks = run(D, monkeypatch)
    assert failures(checks) == [], [f"{c.name}: {c.detail}" for c in failures(checks)]
    names = " ".join(c.name for c in checks)
    for part in (
        "present",
        "runnable",
        "self-test",
        "tripwire",
        "gate",
        "gitleaks",
        "drift",
    ):
        assert part in names


def test_a_missing_hook_entry_fails_by_name(D, monkeypatch):
    D.settings.write_text(json.dumps(entries(drop="ConfigChange")))
    bad = failures(run(D, monkeypatch))
    assert any("ConfigChange" in c.name and "config-change" in c.name for c in bad)


def test_a_matcher_that_misses_a_tool_fails(D, monkeypatch):
    D.settings.write_text(json.dumps(entries(policy_matcher="Bash")))
    bad = failures(run(D, monkeypatch))
    assert any("Edit" in c.detail for c in bad)


def test_a_missing_script_fails(D, monkeypatch):
    D.settings.write_text(
        json.dumps(
            entries(
                command_for={
                    "policy": f"{PY} {shlex.quote(str(ROOT / 'gone' / 'hook.py'))} policy"
                }
            )
        )
    )
    assert any(
        "runnable" in c.name and "script not found" in c.detail
        for c in failures(run(D, monkeypatch))
    )


def test_a_missing_interpreter_fails(D, monkeypatch):
    D.settings.write_text(
        json.dumps(
            entries(
                command_for={"effect-pre": f"/nonexistent/python3 {HOOK} effect-pre"}
            )
        )
    )
    assert any(
        "runnable" in c.name and "/nonexistent/python3" in c.detail
        for c in failures(run(D, monkeypatch))
    )


def test_a_hook_that_no_longer_decides_fails_the_self_test(D, monkeypatch, tmp_path):
    silent = tmp_path / "silent.py"
    silent.write_text("import sys; sys.stdin.read()\n")
    D.settings.write_text(
        json.dumps(
            entries(command_for={"policy": f"{PY} {shlex.quote(str(silent))} policy"})
        )
    )
    assert any("self-test" in c.name for c in failures(run(D, monkeypatch)))


def test_a_stale_heartbeat_fails_when_a_session_is_active(D, monkeypatch):
    beats = D.state / "heartbeats"
    beats.mkdir()
    for component in (
        "policy",
        "effect-pre",
        "effect-post",
        "config-change",
        "doctor-fast",
    ):
        (beats / component).write_text(f"{time.time() - 3600:.0f}\n")
    assert any(
        "firing" in c.name
        for c in failures(run(D, monkeypatch, expect_recent_minutes=10))
    )
    assert not any("firing" in c.name for c in failures(run(D, monkeypatch)))


def test_a_dead_or_silent_tripwire_fails(D, monkeypatch):
    (D.state / "tripwire" / "heartbeat").write_text(
        f"{time.time() - 600:.0f} {os.getpid()}\n"
    )
    assert any("tripwire" in c.name for c in failures(run(D, monkeypatch)))
    (D.state / "tripwire" / "heartbeat").write_text(f"{time.time():.0f} 999999\n")
    assert any("tripwire" in c.name for c in failures(run(D, monkeypatch)))


def test_a_repo_without_the_gate_fails(D, monkeypatch):
    subprocess.run(
        ["git", "-C", str(D.home / "vault"), "config", "--unset", "core.hooksPath"],
        check=True,
    )
    assert any("gate" in c.name for c in failures(run(D, monkeypatch)))


def test_a_missing_gitleaks_fails(D, monkeypatch):
    D.env["GUARD_GITLEAKS"] = "/nonexistent/gitleaks"
    assert any("gitleaks" in c.name for c in failures(run(D, monkeypatch)))


def test_drift_since_the_accepted_baseline_fails_until_accepted(D, monkeypatch):
    assert failures(run(D, monkeypatch)) == []  # the first run records the baseline
    changed = entries()
    changed["hooks"]["PostToolUse"][0]["hooks"][0]["timeout"] = 30
    D.settings.write_text(json.dumps(changed))
    assert any("drift" in c.name for c in failures(run(D, monkeypatch)))
    assert failures(run(D, monkeypatch, accept=True)) == []
    assert failures(run(D, monkeypatch)) == []


def test_a_config_that_protects_nothing_fails(D, monkeypatch):
    D.cfg_path.write_text(
        D.cfg_path.read_text().replace(
            'protected   = ["~/vault/memory", "~/vault/hubs", "~/.claude/projects/*/memory/MEMORY.md"]',
            "protected = []",
        )
    )
    D.cfg = config.load(D.cfg_path)
    assert any("protects" in c.detail for c in failures(run(D, monkeypatch)))


def test_the_command_line_prints_a_table_and_exits_non_zero_on_a_failure(D):
    D.settings.write_text(json.dumps(entries(drop="SessionStart")))
    env = {**os.environ, **D.env, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [PY, "-m", "guard", "doctor"], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 1
    assert "FAIL" in proc.stdout and "PASS" in proc.stdout


def test_fast_mode_warns_inside_the_session_only_when_something_is_wrong(D):
    proc = run_hook("doctor-fast", {"hook_event_name": "SessionStart"}, env=D.env)
    assert (proc.returncode, proc.stdout.strip()) == (0, "")
    D.settings.write_text(json.dumps(entries(drop="ConfigChange")))
    proc = run_hook("doctor-fast", {"hook_event_name": "SessionStart"}, env=D.env)
    ctx = json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "ConfigChange" in ctx
