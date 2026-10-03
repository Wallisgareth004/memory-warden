"""guard.toml: loaded, checked, and every root anchored to an absolute path."""

from __future__ import annotations

import textwrap

import pytest

from conftest import GUARD_TOML
from guard import config


def load_text(home, text):
    path = home / "guard.toml"
    path.write_text(textwrap.dedent(text))
    return config.load(path)


def test_roots_are_anchored_to_absolute_paths(home, config_file):
    cfg = config.load(config_file)
    assert cfg.roots.protected[0] == str(home / "vault" / "memory")
    assert cfg.roots.protected[2] == str(
        home / ".claude" / "projects" / "*" / "memory" / "MEMORY.md"
    )
    assert cfg.roots.append_only == (str(home / "vault" / "memory" / "daily-log.md"),)
    assert cfg.state_dir == home / ".local" / "state" / "guard"


def test_the_state_folder_is_created_owner_only(home, config_file):
    cfg = config.load(config_file)
    made = config.ensure_state_dir(cfg)
    assert made.is_dir() and made.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "change, words",
    [
        ('protected   = ["vault/memory"]', "anchored"),
        ('subagents = "ask"', "subagents"),
        ('case_insensitive = "sometimes"', "case_insensitive"),
        ('sinks = ["log", "carrier-pigeon"]', "carrier-pigeon"),
        ('sinks = ["webhook"]', "webhook_url"),
        ("poll_seconds = 0", "poll_seconds"),
        ('drop_line_patterns = ["(unclosed"]', "drop_line_patterns"),
        ('agent_types_allowed = "curator"', "agent_types_allowed"),
    ],
)
def test_a_bad_value_is_refused_by_name(home, change, words):
    key = change.split("=")[0].strip()
    text = "\n".join(
        change
        if line.strip().startswith(key + " ") or line.strip().startswith(key + "=")
        else line
        for line in GUARD_TOML.splitlines()
    )
    with pytest.raises(config.ConfigError, match=words):
        load_text(home, text)


def test_an_unknown_key_or_section_is_refused(home):
    with pytest.raises(config.ConfigError, match="protect "):
        load_text(home, GUARD_TOML.replace("protected   =", "protect ="))
    with pytest.raises(config.ConfigError, match="rootz"):
        load_text(home, GUARD_TOML.replace("[roots]", "[rootz]"))


def test_a_webhook_must_be_https(home):
    text = GUARD_TOML.replace(
        'sinks = ["log"]',
        'sinks = ["webhook"]\nwebhook_url = "http://example.test/hook"',
    )
    with pytest.raises(config.ConfigError, match="https"):
        load_text(home, text)


def test_with_no_file_the_guard_protects_nothing_and_says_so(home):
    cfg = config.load(home / "missing.toml")
    assert cfg.roots.protected == () and cfg.source is None


def test_the_case_probe_reads_the_filesystem(home, config_file, tmp_path):
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / "lower.txt").write_text("x")
    expected = (probe_dir / "LOWER.TXT").exists()  # what this filesystem actually does
    assert config.probe_case_insensitive(probe_dir) is expected


@pytest.mark.parametrize("setting, want", [("true", True), ("false", False)])
def test_the_case_setting_can_be_forced(home, setting, want):
    cfg = load_text(
        home,
        GUARD_TOML.replace(
            'case_insensitive = "auto"', f"case_insensitive = {setting}"
        ),
    )
    assert cfg.case_insensitive is want


def test_the_shipped_example_loads(home):
    from conftest import ROOT

    cfg = config.load(ROOT / "examples" / "guard.toml")
    assert cfg.subagents == "deny" and cfg.roots.allow == (
        str(home / "vault" / "inbox"),
    )
