"""Evidence and quarantine are kept 30 days, then go to the Trash (or the
desktop's trash), never deleted outright where a trash exists."""

from __future__ import annotations

import os
import time

from guard import retention


def test_only_entries_older_than_the_limit_are_disposed(tmp_path, monkeypatch):
    folder = tmp_path / "evidence"
    old, new = (
        folder / "2026-08-01 - tripwire-000000",
        folder / "2026-10-01 - tripwire-000000",
    )
    old.mkdir(parents=True)
    new.mkdir()
    then = time.time() - 40 * 86400
    os.utime(old, (then, then))
    record = tmp_path / "trashed.txt"
    stub = tmp_path / "trash-stub"
    stub.write_text(f'#!/bin/sh\nfor p in "$@"; do echo "$p" >> "{record}"; done\n')
    stub.chmod(0o755)
    monkeypatch.setenv("GUARD_TRASH", str(stub))
    retention.prune(folder, days=30)
    assert record.read_text().splitlines() == [str(old)]


def test_an_empty_or_missing_folder_is_fine(tmp_path):
    retention.prune(tmp_path / "nothing-here", days=30)
