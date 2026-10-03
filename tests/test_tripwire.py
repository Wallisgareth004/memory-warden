"""C3b, the tripwire: the ported checks, on a synthetic append-only log.

It must catch a stale overwrite in the act, keep the evidence, and restore
last-good plus every new legitimate line, without ever clobbering a write
that lands meanwhile. Every case runs in a temp folder with a "log" alert sink.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import textwrap

import pytest

from guard import config, tripwire

MARKER = "unlogged session"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def L(home, tmp_path):
    mem = home / "vault" / "memory"
    mem.mkdir(parents=True)
    log = mem / "daily-log.md"
    log.write_text(
        "---\ntitle: log\n---\n\n"
        + "".join(f"- 2026-09-2{i} entry {i}\n" for i in range(1, 7))
    )
    path = home / "guard.toml"
    path.write_text(
        textwrap.dedent(f"""
        [roots]
        append_only = ["~/vault/memory/daily-log.md"]
        [policy]
        case_insensitive = false
        [alerts]
        sinks = ["log"]
        [tripwire]
        settle_seconds = 0.1
        drop_line_patterns = ["{MARKER}"]
        [state]
        dir = "{tmp_path / "state"}"
    """)
    )
    cfg = config.load(path)

    class Layout:
        pass

    x = Layout()
    x.cfg, x.mem, x.log, x.tmp = cfg, mem, log, tmp_path
    x.run = lambda **kw: tripwire.check_once(log, cfg, **kw)
    x.evidence = lambda: (
        sorted((cfg.state_dir / "evidence").glob("* - tripwire-*"))
        if (cfg.state_dir / "evidence").exists()
        else []
    )
    x.alerts = lambda: (
        (cfg.state_dir / "alerts.log").read_text().splitlines()
        if (cfg.state_dir / "alerts.log").exists()
        else []
    )
    x.good = lambda: tripwire.state_for(cfg, log) / "last-good"
    return x


def test_0_the_first_run_initialises_last_good_and_writes_no_evidence(L):
    assert L.run() == "initialised"
    assert sha(L.good()) == sha(L.log)
    assert L.evidence() == []


def test_1_an_append_is_left_alone_and_becomes_last_good(L):
    L.run()
    with open(L.log, "a") as fh:
        fh.write("- 2026-09-26 entry 7 (an append)\n")
    before = sha(L.log)
    assert L.run() == "ok"
    assert sha(L.log) == before
    assert L.evidence() == [] and L.alerts() == []
    assert sha(L.good()) == sha(L.log)


@pytest.fixture
def overwritten(L):
    """A stale overwrite: entries 4-7 lost, a junk marker added, then one new legit line."""
    L.run()
    with open(L.log, "a") as fh:
        fh.write("- 2026-09-26 entry 7 (an append)\n")
    L.run()
    good = L.log.read_text()
    bad = (
        "".join(good.splitlines(keepends=True)[:7])
        + f"- ⚠️ {MARKER} 2026-09-26 00:03\n"
        + "- 2026-09-26 entry 8 (after the overwrite)\n"
    )
    L.log.write_text(bad)  # a truncate-and-rewrite
    L.result = L.run()
    L.good_text, L.bad_text = good, bad
    return L


def test_2_a_stale_overwrite_is_restored_with_the_new_line_kept(overwritten):
    L = overwritten
    assert L.result == "restored"
    assert (
        L.log.read_text()
        == L.good_text + "- 2026-09-26 entry 8 (after the overwrite)\n"
    )


def test_2_the_junk_marker_is_dropped(overwritten):
    assert MARKER not in overwritten.log.read_text()


def test_2_one_evidence_folder_holds_the_bad_file_byte_for_byte(overwritten):
    (e,) = overwritten.evidence()
    assert (e / "daily-log.md.bad").read_text() == overwritten.bad_text
    assert (e / "daily-log.md.last-good").read_text() == overwritten.good_text


def test_2_the_diff_shows_the_lost_line(overwritten):
    (e,) = overwritten.evidence()
    assert "-- 2026-09-26 entry 7 (an append)" in (e / "diff.patch").read_text()


def test_2_the_time_is_kept_to_the_second(overwritten):
    import re

    (e,) = overwritten.evidence()
    assert re.search(
        r"^detected: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        (e / "time.txt").read_text(),
        re.M,
    )


def test_2_the_process_table_and_open_files_are_captured(overwritten):
    (e,) = overwritten.evidence()
    ps = (e / "ps.txt").read_text().splitlines()
    assert any("STARTED" in line for line in ps[:3]) and len(ps) > 5
    assert (e / "lsof.txt").exists()


def test_2_one_alert_names_the_count_and_never_the_content(overwritten):
    (line,) = overwritten.alerts()
    assert "daily-log.md lost 4 line" in line
    assert "entry" not in line and MARKER not in line


def test_2_last_good_is_the_restored_file_and_the_next_run_does_nothing(overwritten):
    L = overwritten
    assert sha(L.good()) == sha(L.log)
    assert L.run() == "ok"
    assert (len(L.evidence()), len(L.alerts())) == (1, 1)


def test_2_the_restored_file_keeps_its_permissions(L):
    L.run()
    os.chmod(L.log, 0o640)
    L.log.write_text("- 2026-09-21 entry 1\n")
    L.run()
    assert L.log.stat().st_mode & 0o777 == 0o640


def test_3_a_rotation_flag_pauses_it_and_it_rebaselines_after(L):
    L.run()
    flag = L.mem / ".rotation-in-progress"
    flag.write_text("")
    rotated = (
        "".join(L.log.read_text().splitlines(keepends=True)[:4]) + "- new period\n"
    )
    L.log.write_text(rotated)
    assert L.run() == "rotation"
    assert L.log.read_text() == rotated and L.evidence() == []
    flag.rename(L.tmp / "flag-done")
    assert L.run() == "rebaselined"
    assert L.log.read_text() == rotated and L.evidence() == [] and L.alerts() == []
    assert sha(L.good()) == sha(L.log)


def test_4a_two_overlapping_runs_after_two_appends_raise_nothing(L):
    L.run()
    results = []
    with open(L.log, "a") as fh:
        fh.write("- entry 9\n")
    t1 = threading.Thread(target=lambda: results.append(L.run()))
    t1.start()
    with open(L.log, "a") as fh:
        fh.write("- entry 10\n")
    t2 = threading.Thread(target=lambda: results.append(L.run()))
    t2.start()
    t1.join()
    t2.join()
    assert L.evidence() == []
    assert sha(L.good()) == sha(L.log)


def test_4b_an_append_just_before_an_overwrite_survives_the_restore(L):
    L.run()
    good = L.log.read_text()
    with open(L.log, "a") as fh:
        fh.write("- entry 11 (seconds before the overwrite)\n")
    done = []
    t = threading.Thread(target=lambda: done.append(L.run(settle=1.0)))
    t.start()
    time.sleep(0.4)
    L.log.write_text(
        "".join(good.splitlines(keepends=True)[:5]) + f"- ⚠️ {MARKER} 00:04\n"
    )
    t.join()
    assert done == ["restored"]
    assert L.log.read_text() == good + "- entry 11 (seconds before the overwrite)\n"
    assert MARKER not in L.log.read_text()


def test_5_a_deleted_file_is_restored(L):
    L.run()
    before = L.log.read_text()
    L.log.rename(L.tmp / "deleted.md")
    assert L.run() == "restored"
    assert L.log.read_text() == before and len(L.evidence()) == 1


def test_6_a_missing_folder_refuses_loudly_and_baselines_nothing(L, home):
    missing = home / "nowhere" / "daily-log.md"
    with pytest.raises(tripwire.Refused, match="folder not found"):
        tripwire.check_once(missing, L.cfg)
    assert not (tripwire.state_for(L.cfg, missing) / "last-good").exists()


def test_6b_no_file_yet_means_no_baseline(L):
    L.log.rename(L.tmp / "gone.md")
    assert L.run() == "nothing"
    assert not L.good().exists()


def test_a_trailing_line_still_being_written_never_becomes_last_good(L):
    L.run()
    with open(L.log, "a") as fh:
        fh.write("- half a li")
    L.run()
    assert not L.good().read_text().endswith("- half a li")


def test_the_watch_loop_heartbeats_and_runs_a_check_on_change(L):
    L.run()
    stop = threading.Event()
    t = threading.Thread(
        target=lambda: tripwire.watch(L.cfg, stop=stop, poll=0.05), daemon=True
    )
    t.start()
    time.sleep(0.2)
    L.log.write_text("- 2026-09-21 entry 1\n")  # an overwrite while it watches
    deadline = time.time() + 5
    while time.time() < deadline and not L.evidence():
        time.sleep(0.05)
    stop.set()
    t.join(timeout=5)
    assert len(L.evidence()) == 1
    assert (L.cfg.state_dir / "tripwire" / "heartbeat").exists()
