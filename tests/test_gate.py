"""C3a, the pre-commit gate: no secrets (gitleaks, failing closed when it's
missing) and no removed lines in append-only files. Every case runs on a
throwaway git repo in a temp folder."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap

import pytest

from conftest import ROOT

GITLEAKS = next(
    (
        p
        for p in (
            "/opt/homebrew/bin/gitleaks",
            "/usr/local/bin/gitleaks",
            shutil.which("gitleaks") or "",
        )
        if p and os.path.exists(p)
    ),
    None,
)
needs_gitleaks = pytest.mark.skipif(GITLEAKS is None, reason="gitleaks isn't installed")


def git(repo, *args, env=None, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env,
        check=check,
    )


@pytest.fixture
def repo(home, tmp_path):
    r = home / "vault"
    r.mkdir(exist_ok=True)
    git(r, "init", "-q")
    git(r, "config", "user.email", "test@example.invalid")
    git(r, "config", "user.name", "Test")
    (r / "memory").mkdir(exist_ok=True)
    (r / "chats").mkdir(exist_ok=True)
    (r / "memory" / "daily-log.md").write_text("- one\n\n- two\n")
    (r / "chats" / "2026-10-01 - a.md").write_text("first\nsecond\n")
    (r / "notes.md").write_text("a\nb\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "seed", "--no-verify")
    cfg = home / "guard.toml"
    cfg.write_text(
        textwrap.dedent("""
        [roots]
        append_only = ["~/vault/memory/daily-log.md", "~/vault/chats"]
        [policy]
        case_insensitive = false
    """)
    )
    return r


def run_gate(repo, gitleaks=None):
    env = {
        **os.environ,
        "GUARD_CONFIG": str(repo.parent / "guard.toml"),
        "PYTHONPATH": str(ROOT),
    }
    env["GUARD_GITLEAKS"] = (
        gitleaks if gitleaks is not None else (GITLEAKS or "/nonexistent/gitleaks")
    )
    return subprocess.run(
        [sys.executable, "-m", "guard", "gate"],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
    )


def stage(repo):
    git(repo, "add", "-A")


@needs_gitleaks
def test_an_append_passes(repo):
    with open(repo / "memory" / "daily-log.md", "a") as fh:
        fh.write("- three\n")
    stage(repo)
    run = run_gate(repo)
    assert run.returncode == 0, run.stdout + run.stderr


@needs_gitleaks
def test_a_removed_line_is_blocked_and_named(repo):
    (repo / "memory" / "daily-log.md").write_text("- one\n\n- three\n")
    stage(repo)
    run = run_gate(repo)
    assert run.returncode == 1
    assert "daily-log.md" in run.stdout and "1 line" in run.stdout
    assert "--no-verify" in run.stdout


@needs_gitleaks
def test_a_removed_blank_line_is_blocked_too(repo):
    (repo / "memory" / "daily-log.md").write_text("- one\n- two\n")
    stage(repo)
    assert run_gate(repo).returncode == 1


@needs_gitleaks
def test_an_append_only_folder_takes_new_files_but_never_loses_lines(repo):
    (repo / "chats" / "2026-10-02 - b.md").write_text("new\n")
    stage(repo)
    assert run_gate(repo).returncode == 0
    (repo / "chats" / "2026-10-01 - a.md").write_text("first\n")
    stage(repo)
    assert run_gate(repo).returncode == 1


@needs_gitleaks
def test_deleting_or_renaming_an_append_only_file_is_blocked(repo):
    git(repo, "rm", "-q", "chats/2026-10-01 - a.md")
    assert run_gate(repo).returncode == 1
    git(repo, "reset", "-q", "--hard")
    git(repo, "mv", "chats/2026-10-01 - a.md", "chats/renamed.md")
    assert run_gate(repo).returncode == 1


@needs_gitleaks
def test_ordinary_files_may_change_freely(repo):
    (repo / "notes.md").write_text("b\n")
    stage(repo)
    assert run_gate(repo).returncode == 0


@needs_gitleaks
def test_a_binary_file_in_an_append_only_folder_is_not_a_false_alarm(repo):
    (repo / "chats" / "pic.bin").write_bytes(bytes(range(256)))
    stage(repo)
    git(repo, "commit", "-q", "-m", "bin", "--no-verify")
    (repo / "chats" / "pic.bin").write_bytes(bytes(range(255, -1, -1)))
    stage(repo)
    assert run_gate(repo).returncode == 0


def test_a_missing_gitleaks_blocks_the_commit(repo):
    (repo / "notes.md").write_text("a\nb\nc\n")
    stage(repo)
    run = run_gate(repo, gitleaks="/nonexistent/gitleaks")
    assert run.returncode == 1
    assert "gitleaks" in run.stdout and "fail-closed" in run.stdout


@needs_gitleaks
def test_a_staged_secret_is_blocked(repo):
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (repo / "notes.md").write_text(f"a\nb\ntoken = {token}\n")
    stage(repo)
    run = run_gate(repo)
    assert run.returncode == 1
    assert "secret" in run.stdout
    assert token not in run.stdout + run.stderr  # the finding is redacted


def test_a_broken_config_blocks_rather_than_waves_through(repo):
    (repo.parent / "guard.toml").write_text("[roots]\nappend_only = [")
    (repo / "notes.md").write_text("x\n")
    stage(repo)
    run = run_gate(repo, gitleaks=GITLEAKS or "/nonexistent/gitleaks")
    assert run.returncode == 1 and "guard.toml" in run.stdout


@needs_gitleaks
def test_the_git_hook_shim_runs_the_gate(repo):
    git(repo, "config", "core.hooksPath", str(ROOT / "githooks"))
    (repo / "memory" / "daily-log.md").write_text("- one\n")
    stage(repo)
    env = {
        **os.environ,
        "GUARD_CONFIG": str(repo.parent / "guard.toml"),
        "GUARD_GITLEAKS": GITLEAKS,
    }
    blocked = git(repo, "commit", "-q", "-m", "lose lines", env=env, check=False)
    assert blocked.returncode != 0
    assert "daily-log.md" in blocked.stdout + blocked.stderr
