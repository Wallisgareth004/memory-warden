"""C4, self-protection: no agent (the main thread included) may change the
guard's own files, its config, the Claude settings that hold the hooks, or
skills, mid-session. Deny, not ask; the only way to change them is to end the
session, edit, and restart. A ConfigChange hook stops mid-session settings
changes from taking effect (exit 2)."""

from __future__ import annotations

import json
import textwrap

import pytest

from conftest import GUARD_TOML, ROOT, run_hook
from guard import config, selfprotect


@pytest.fixture
def S(home, vault, tmp_path):
    claude = home / ".claude"
    (claude / "skills" / "notes").mkdir(parents=True)
    (claude / "settings.json").write_text('{"hooks": {}}\n')
    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "settings.local.json").write_text("{}\n")
    text = (
        textwrap.dedent(GUARD_TOML)
        + '\n[selfprotect]\nenabled = true\npaths = ["~/secrets-of-the-guard"]\n'
    )
    path = home / "guard.toml"
    path.write_text(text)

    class X:
        pass

    x = X()
    x.home, x.claude, x.project, x.cfg_path = home, claude, project, path
    x.cfg = config.load(path)
    x.env = {"GUARD_CONFIG": str(path)}
    return x


def edit(path, sub=False, tool="Edit", cwd=None):
    p = {
        "tool_name": tool,
        "tool_input": {"file_path": str(path), "old_string": "a", "new_string": "b"},
    }
    if cwd:
        p["cwd"] = str(cwd)
    if sub:
        p.update(agent_id="a1", agent_type="general-purpose")
    return p


def bash(cmd, sub=False, cwd=None):
    p = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    if cwd:
        p["cwd"] = str(cwd)
    if sub:
        p.update(agent_id="a1", agent_type="general-purpose")
    return p


def outcome(payload, S):
    out = selfprotect.decide(payload, S.cfg)
    return "allow" if out is None else out["hookSpecificOutput"]["permissionDecision"]


def test_the_main_thread_may_not_edit_the_settings_that_hold_the_hooks(S):
    assert outcome(edit(S.claude / "settings.json"), S) == "deny"


def test_a_subagent_may_not_rewrite_the_guards_own_code(S):
    assert outcome(edit(ROOT / "hook.py", sub=True, tool="Write"), S) == "deny"
    assert outcome(edit(ROOT / "guard" / "policy.py", sub=True), S) == "deny"


def test_bash_writes_to_settings_or_skills_are_denied(S):
    assert outcome(bash(f"echo x >> {S.claude}/settings.local.json"), S) == "deny"
    assert (
        outcome(bash(f"cp /tmp/evil.md {S.claude}/skills/notes/SKILL.md"), S) == "deny"
    )


def test_the_projects_own_claude_settings_are_covered(S):
    payload = edit(S.project / ".claude" / "settings.local.json", cwd=S.project)
    assert outcome(payload, S) == "deny"


def test_the_guards_config_file_is_covered(S):
    assert outcome(edit(S.cfg_path), S) == "deny"


def test_an_extra_path_from_the_config_is_covered(S):
    assert outcome(edit(S.home / "secrets-of-the-guard" / "x.md"), S) == "deny"


def test_reading_them_is_fine(S):
    assert (
        outcome(bash(f"cat {S.claude}/settings.json && ls {S.claude}/skills"), S)
        == "allow"
    )


def test_ordinary_files_are_not_its_business(S):
    assert outcome(edit(S.home / "vault" / "notes" / "idea.md"), S) == "allow"


def test_it_can_be_switched_off(S):
    S.cfg_path.write_text(
        S.cfg_path.read_text().replace("enabled = true", "enabled = false")
    )
    S.cfg = config.load(S.cfg_path)
    assert outcome(edit(S.claude / "settings.json"), S) == "allow"


def test_the_policy_hook_applies_self_protection_first(S):
    proc = run_hook("policy", edit(S.claude / "settings.json"), env=S.env)
    out = json.loads(proc.stdout)["hookSpecificOutput"]
    assert (
        out["permissionDecision"] == "deny"
        and "restart" in out["permissionDecisionReason"]
    )


def test_a_mid_session_settings_change_is_blocked_with_exit_2(S):
    proc = run_hook(
        "config-change",
        {"hook_event_name": "ConfigChange", "source": "user_settings"},
        env=S.env,
    )
    assert proc.returncode == 2
    assert "restart" in proc.stderr


def test_policy_settings_cant_be_blocked_so_it_is_alerted(S):
    proc = run_hook(
        "config-change",
        {"hook_event_name": "ConfigChange", "source": "policy_settings"},
        env=S.env,
    )
    assert proc.returncode == 0
    log = (S.cfg.state_dir / "alerts.log").read_text()
    assert "policy_settings" in log


def test_with_self_protection_off_settings_changes_go_through(S):
    S.cfg_path.write_text(
        S.cfg_path.read_text().replace("enabled = true", "enabled = false")
    )
    proc = run_hook(
        "config-change",
        {"hook_event_name": "ConfigChange", "source": "user_settings"},
        env=S.env,
    )
    assert proc.returncode == 0


def test_a_settings_file_created_where_no_claude_folder_existed_is_denied(S, tmp_path):
    """CVE-2026-25725's shape: settings.json absent at start-up, then written."""
    fresh = tmp_path / "fresh-project"
    fresh.mkdir()
    cmd = "mkdir -p .claude && echo '{\"hooks\": {}}' > .claude/settings.json"
    assert outcome(bash(cmd, sub=True, cwd=fresh), S) == "deny"
    assert (
        outcome(
            edit(fresh / ".claude" / "settings.local.json", tool="Write", cwd=fresh), S
        )
        == "deny"
    )


DESTROY = (
    "r" + "m -rf"
)  # spelt in two pieces so no shell guard mistakes this file for a command


@pytest.mark.parametrize(
    "cmd, want",
    [
        (
            "git -C {project} pull",
            "allow",
        ),  # whole-tree git in a project: ConfigChange covers settings
        ("mv {home}/vault/notes/idea.md {project}/", "allow"),
        (DESTROY + " {project}/.claude", "deny"),
        ("tar -xf /tmp/a.tar -C {project}/.claude", "deny"),
        (DESTROY + " {home}/.claude", "deny"),  # the user's own .claude stays strict
    ],
)
def test_project_settings_count_only_for_writes_inside_dot_claude(S, cmd, want):
    command = cmd.replace("{project}", str(S.project)).replace("{home}", str(S.home))
    assert outcome(bash(command, cwd=S.project), S) == want
