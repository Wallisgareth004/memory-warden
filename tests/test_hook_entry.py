"""hook.py: one entry for every component. It reads Claude Code's JSON payload,
and on anything it can't use it exits 0 with no output, so it can never wedge
a session (the detective components cover what a failed hook misses)."""

from __future__ import annotations

import pytest

from conftest import run_hook


@pytest.mark.parametrize("component", ["policy", "effect-pre", "effect-post"])
def test_every_tool_component_answers_a_harmless_payload_quietly(
    component, config_file
):
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/x"},
        "session_id": "s",
    }
    proc = run_hook(component, payload, env={"GUARD_CONFIG": str(config_file)})
    assert (proc.returncode, proc.stdout.strip()) == (0, "")


def test_malformed_input_exits_zero_with_no_decision(config_file):
    proc = run_hook(
        "policy", None, env={"GUARD_CONFIG": str(config_file)}, raw="{not json"
    )
    assert (proc.returncode, proc.stdout.strip()) == (0, "")


def test_an_unknown_component_exits_zero_and_says_so_on_stderr(config_file):
    proc = run_hook("teleport", {}, env={"GUARD_CONFIG": str(config_file)})
    assert proc.returncode == 0 and proc.stdout.strip() == ""
    assert "unknown component" in proc.stderr


HEAVY = {"guard.doctor", "guard.gate", "urllib.request", "http.client", "ssl", "tempfile"}


def _imported(proc) -> set[str]:
    """Module names from Python's import-time profile (PYTHONPROFILEIMPORTTIME)."""
    return {
        line.rsplit("|", 1)[1].strip()
        for line in proc.stderr.splitlines()
        if line.startswith("import time:") and line.count("|") == 2
    }


@pytest.mark.parametrize(
    "component", ["policy", "effect-pre", "effect-post", "config-change"]
)
def test_a_call_loads_only_what_its_hook_needs(
    component, config_file, vault, tmp_path
):
    """Every tool call pays for what its hook imports, so imports are lazy: the
    doctor, the commit gate and the network stack stay out of the per-call path."""
    payload = {
        "hook_event_name": "ConfigChange",
        "source": "user_settings",
        "tool_name": "Bash",
        "tool_input": {"command": f"echo x >> {vault}/memory/state.md"},
        "agent_id": "a1",
        "agent_type": "general-purpose",
        "session_id": "s",
        "tool_use_id": "t1",
        "cwd": str(vault),
    }
    proc = run_hook(
        component,
        payload,
        env={
            "GUARD_CONFIG": str(config_file),
            "PYTHONPROFILEIMPORTTIME": "1",
            "TMPDIR": str(tmp_path),
        },
    )
    loaded = _imported(proc)
    assert "guard.config" in loaded, proc.stderr[-500:]
    if component == "policy":
        assert '"deny"' in proc.stdout
    if component == "config-change":
        assert proc.returncode == 2
    assert not loaded & HEAVY, sorted(loaded & HEAVY)


def test_a_broken_config_never_blocks_a_call(home, config_file):
    config_file.write_text("[roots]\nprotected = [")
    proc = run_hook(
        "policy",
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        env={"GUARD_CONFIG": str(config_file)},
    )
    assert (proc.returncode, proc.stdout.strip()) == (0, "")
    assert "guard.toml" in proc.stderr
