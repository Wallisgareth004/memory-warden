"""No personal data in the repo, from the first commit on.

Generic checks run everywhere (home-folder paths of real users). A machine's
private patterns (names, vault and folder names, handles) live in
local/scrub-patterns.txt, which git ignores, so the patterns themselves never
enter the repo."""

from __future__ import annotations

from guard import leakcheck

from conftest import ROOT


def test_the_repo_holds_no_personal_strings():
    hits = leakcheck.scan(
        ROOT, leakcheck.patterns(ROOT / "local" / "scrub-patterns.txt")
    )
    assert hits == [], "\n".join(f"{h.path}:{h.line}: {h.pattern}" for h in hits)


def test_a_planted_name_is_caught(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nowner = 'Jane Q Public'\n")
    (tmp_path / "pats.txt").write_text("# private\n(?i)jane q\n")
    hits = leakcheck.scan(
        tmp_path, leakcheck.patterns(tmp_path / "pats.txt"), files=["a.py"]
    )
    assert [(h.path, h.line) for h in hits] == [("a.py", 2)]


def test_a_licence_may_name_its_author_on_the_copyright_line_only(tmp_path):
    (tmp_path / "LICENSE").write_text(
        "MIT License\n\nCopyright (c) 2026 Jane Q Public\n\nThanks, Jane Q Public.\n"
    )
    (tmp_path / "c.md").write_text("Copyright (c) 2026 Jane Q Public\n")
    (tmp_path / "pats.txt").write_text("(?i)jane q\n")
    hits = leakcheck.scan(
        tmp_path, leakcheck.patterns(tmp_path / "pats.txt"), files=["LICENSE", "c.md"]
    )
    assert [(h.path, h.line) for h in hits] == [("LICENSE", 5), ("c.md", 1)]


def test_a_real_users_home_path_is_caught_without_any_private_list(tmp_path):
    (tmp_path / "b.md").write_text(
        "see /Us" + "ers/somebody/notes\nand ~/notes is fine\n"
    )
    hits = leakcheck.scan(tmp_path, leakcheck.patterns(None), files=["b.md"])
    assert [(h.path, h.line) for h in hits] == [("b.md", 1)]
