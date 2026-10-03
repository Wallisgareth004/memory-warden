"""Which root a path falls in: protected, append-only, allowed, or none.

Matching uses anchored absolute roots (not path segments), so a lookalike
folder elsewhere is never caught, and both the normalised and the resolved
(symlink-followed) form of a path count.
"""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from guard import config, roots


@pytest.fixture
def cfg(config_file):
    return config.load(config_file)


def test_a_file_in_a_protected_folder_is_protected(cfg, vault):
    assert roots.classify(str(vault / "memory" / "state.md"), cfg) == "protected"
    assert roots.classify(str(vault / "hubs" / "new.md"), cfg) == "protected"


def test_the_append_only_file_and_the_allowed_folder_have_their_own_class(cfg, vault):
    assert roots.classify(str(vault / "memory" / "daily-log.md"), cfg) == "append_only"
    assert roots.classify(str(vault / "inbox" / "note.md"), cfg) == "allow"


def test_an_unguarded_path_is_none(cfg, vault, tmp_path):
    assert roots.classify(str(vault / "notes" / "idea.md"), cfg) is None
    assert roots.classify("/tmp/out.txt", cfg) is None


def test_a_lookalike_folder_outside_the_anchored_root_is_not_caught(cfg, tmp_path):
    look = tmp_path / "elsewhere" / "vault" / "memory" / "state.md"
    assert roots.classify(str(look), cfg) is None


def test_dot_dot_is_normalised(cfg, vault):
    assert (
        roots.classify(str(vault / "notes" / ".." / "memory" / "state.md"), cfg)
        == "protected"
    )


def test_a_glob_root_matches(cfg, home):
    index = home / ".claude" / "projects" / "any-project" / "memory" / "MEMORY.md"
    assert roots.classify(str(index), cfg) == "protected"
    assert roots.classify(str(index.with_name("other.md")), cfg) is None


def test_a_symlink_into_a_protected_folder_is_followed(cfg, vault, tmp_path):
    link = tmp_path / "m"
    link.symlink_to(vault / "memory")
    assert roots.classify(str(link / "state.md"), cfg) == "protected"


def test_a_protected_root_reached_through_its_own_symlink_still_counts(home, tmp_path):
    real = tmp_path / "real-memory"
    real.mkdir()
    (home / "vault").mkdir()
    (home / "vault" / "memory").symlink_to(real)
    cfg = config.from_dict(
        {
            "roots": {"protected": ["~/vault/memory"]},
            "policy": {"case_insensitive": False},
        }
    )
    assert roots.classify(str(real / "x.md"), cfg) == "protected"


def test_case_follows_the_filesystem_setting(cfg, vault):
    shouty = str(vault / "MEMORY" / "STATE.md")
    assert roots.classify(shouty, replace(cfg, case_insensitive=True)) == "protected"
    assert roots.classify(shouty, replace(cfg, case_insensitive=False)) is None


def test_a_folder_that_holds_a_protected_root_counts_for_a_whole_tree_write(
    cfg, vault, home
):
    assert roots.holds_protected(str(vault), cfg) is True  # rm -rf ~/vault
    assert roots.holds_protected(str(home), cfg) is True
    assert roots.holds_protected(str(vault / "notes"), cfg) is False
    assert roots.holds_protected(str(vault / "inbox"), cfg) is False


def test_relative_paths_are_never_classified(cfg):
    with pytest.raises(ValueError):
        roots.classify(os.path.join("vault", "memory", "state.md"), cfg)
