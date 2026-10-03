"""C2, intent vs effect: the ported checks, on a synthetic vault.

Before each subagent call the guard fingerprints every file under the
protected, append-only and watched roots and stores what the policy predicted;
after the call it diffs. A protected file changed, created or deleted, or an
append-only file rewritten, is a violation: the subagent is told to stop, one
line goes to the alert sinks (never content), and the before-copy is kept.
Nothing is ever restored. The main thread's own writes leave markers, so they
are never blamed on a subagent.
"""

from __future__ import annotations

import json
import os
import textwrap
import time

import pytest

from conftest import GUARD_TOML, run_hook
from guard import config, effect


@pytest.fixture
def L(home, vault, tmp_path):
    index = home / ".claude" / "projects" / "p" / "memory" / "MEMORY.md"
    index.parent.mkdir(parents=True)
    index.write_text("index v1\n")
    watched = home / "vault" / "projects"
    watched.mkdir()
    (watched / "p.md").write_text("probe v1\n")
    text = (
        textwrap.dedent(GUARD_TOML)
        .replace("watch       = []", 'watch       = ["~/vault/projects"]')
        .replace('case_insensitive = "auto"', "case_insensitive = true")
        .replace(f'dir = "~/.local/state/guard"', f'dir = "{tmp_path / "state"}"')
    )
    path = home / "guard.toml"
    path.write_text(text)

    class X:
        pass

    x = X()
    x.cfg_path, x.cfg = path, config.load(path)
    x.vault, x.index, x.watched = vault, index, watched
    x.env = {"GUARD_CONFIG": str(path)}
    x.alerts = lambda: (
        (x.cfg.state_dir / "alerts.log").read_text()
        if (x.cfg.state_dir / "alerts.log").exists()
        else ""
    )
    return x


def sub(tid="t1", tool="Bash", **inp):
    return {
        "session_id": "s",
        "tool_name": tool,
        "tool_input": inp or {"command": "python3 /tmp/s.py"},
        "tool_use_id": tid,
        "agent_id": "a1",
        "agent_type": "general-purpose",
    }


def main_call(tid="m1", tool="Bash", **inp):
    return {"session_id": "s", "tool_name": tool, "tool_input": inp, "tool_use_id": tid}


def cycle(L, change, payload=None):
    p = payload or sub()
    assert effect.pre(p, L.cfg) is None
    change()
    return effect.post(p, L.cfg)


def assert_block(out, *names):
    assert out is not None and out["decision"] == "block", out
    for n in names:
        assert n in out["reason"]


# -- violations --------------------------------------------------------------


def test_a_write_from_a_script_file_is_caught_and_the_before_copy_kept(L):
    out = cycle(
        L, lambda: (L.vault / "memory" / "facts.md").write_text("canon TAMPERED\n")
    )
    assert_block(out, "facts.md")
    assert (L.vault / "memory" / "facts.md").read_text() == "canon TAMPERED\n", (
        "never restored"
    )
    q = L.cfg.state_dir / "quarantine"
    copies = [p for p in q.rglob("*") if p.is_file()]
    assert any(c.read_text() == "canon v1\n" for c in copies)
    assert q.stat().st_mode & 0o777 == 0o700
    log = L.alerts()
    assert "facts.md" in log and "canon" not in log, "alerts hold no content"
    assert (L.cfg.state_dir / "alerts.log").stat().st_mode & 0o777 == 0o600


def test_a_new_file_in_a_protected_folder_is_caught(L):
    assert_block(
        cycle(L, lambda: (L.vault / "hubs" / "new.md").write_text("x\n")), "new.md"
    )


def test_a_deleted_protected_file_is_caught(L):
    assert_block(
        cycle(L, lambda: (L.vault / "memory" / "state.md").unlink()), "state.md"
    )


def test_a_glob_root_is_watched(L):
    def change():
        with open(L.index, "a") as fh:
            fh.write("x\n")

    assert_block(cycle(L, change), "MEMORY.md")


def test_an_append_only_rewrite_is_caught(L):
    out = cycle(
        L, lambda: (L.vault / "memory" / "daily-log.md").write_text("- other\n")
    )
    assert_block(out, "daily-log.md", "append-only")


def test_an_mcp_write_is_caught(L):
    p = sub(
        tid="t9", tool="mcp__notes__write_note", path="memory/facts.md", content="x"
    )
    assert_block(
        cycle(L, lambda: (L.vault / "memory" / "facts.md").write_text("x\n"), p),
        "facts.md",
    )


def test_the_reason_says_what_the_policy_had_predicted(L):
    p = sub(tid="t10", command=f"echo x > {L.vault}/notes/ok.md && python3 tool.py")
    out = cycle(L, lambda: (L.vault / "memory" / "facts.md").write_text("x\n"), p)
    assert_block(out, "facts.md", "predicted")


# -- silence -----------------------------------------------------------------


def test_no_change_is_silent(L):
    assert cycle(L, lambda: None) is None


def test_an_append_to_the_append_only_file_is_silent(L):
    def change():
        with open(L.vault / "memory" / "daily-log.md", "a") as fh:
            fh.write("- line 2\n")

    assert cycle(L, change) is None


def test_a_touch_with_the_same_content_is_silent(L):
    def touch():
        t = time.time() + 5
        os.utime(L.vault / "memory" / "facts.md", (t, t))

    assert cycle(L, touch) is None


def test_a_main_thread_edit_during_the_call_is_not_blamed(L):
    def change():
        m = main_call(
            tid="m2", tool="Edit", file_path=str(L.vault / "memory" / "facts.md")
        )
        effect.pre(m, L.cfg)
        (L.vault / "memory" / "facts.md").write_text("canon v2 by main\n")
        effect.post(m, L.cfg)

    assert cycle(L, change) is None


def test_a_main_thread_vault_command_during_the_call_is_not_blamed(L):
    def change():
        m = main_call(tid="m3", command=f"printf x >> '{L.vault}/memory/state.md'")
        effect.pre(m, L.cfg)
        with open(L.vault / "memory" / "state.md", "a") as fh:
            fh.write("x")
        effect.post(m, L.cfg)

    assert cycle(L, change) is None


def test_an_unrelated_main_command_does_not_excuse_a_subagent(L):
    def change():
        m = main_call(tid="m4", command="pytest -q")
        effect.pre(m, L.cfg)
        (L.vault / "memory" / "facts.md").write_text("canon TAMPERED\n")
        effect.post(m, L.cfg)

    assert_block(cycle(L, change), "facts.md")


def test_the_main_thread_is_never_blocked(L):
    m = main_call(tid="m5", command="python3 /tmp/s.py")
    effect.pre(m, L.cfg)
    (L.vault / "memory" / "facts.md").write_text("x\n")
    assert effect.post(m, L.cfg) is None


def test_a_post_without_a_pre_is_silent(L):
    assert effect.post(sub(tid="never"), L.cfg) is None


# -- watched roots: an effect nobody predicted ---------------------------------


def test_an_unpredicted_change_in_a_watched_root_alerts_without_blocking(L):
    out = cycle(
        L, lambda: (L.watched / "p.md").write_text("probe v2\n"), sub(tid="t11")
    )
    assert out is None
    assert "unexpected effect" in L.alerts() and "p.md" in L.alerts()


def test_a_predicted_change_in_a_watched_root_is_fine(L):
    p = sub(
        tid="t12",
        tool="Edit",
        file_path=str(L.watched / "p.md"),
        old_string="v1",
        new_string="v2",
    )
    assert cycle(L, lambda: (L.watched / "p.md").write_text("probe v2\n"), p) is None
    assert "unexpected effect" not in L.alerts()


# -- through hook.py -------------------------------------------------------------


def test_malformed_input_exits_zero(L):
    proc = run_hook("effect-pre", None, env=L.env, raw="{not json")
    assert (proc.returncode, proc.stdout.strip()) == (0, "")


def test_end_to_end_the_post_hook_prints_the_block(L):
    p = sub(tid="t13")
    run_hook("effect-pre", p, env=L.env)
    (L.vault / "hubs" / "trading.md").write_text("tampered\n")
    proc = run_hook("effect-post", p, env=L.env)
    assert json.loads(proc.stdout)["decision"] == "block"


def test_every_run_leaves_a_heartbeat(L):
    run_hook("effect-pre", sub(tid="t14"), env=L.env)
    assert (L.cfg.state_dir / "heartbeats" / "effect-pre").exists()


def test_its_own_work_is_quick_when_nothing_changed(L):
    p = sub(tid="t15")
    effect.pre(p, L.cfg)
    effect.post(p, L.cfg)  # warm the content cache
    p = sub(tid="t16")
    t0 = time.perf_counter()
    effect.pre(p, L.cfg)
    effect.post(p, L.cfg)
    assert (time.perf_counter() - t0) * 1000 < 25
