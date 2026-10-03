"""C6, the attack suite. Every case cites a CVE, an advisory or a research
note, is labelled by class, and says what should happen: prevented, detected,
or (a documented limit) through. Commands are never run: each one is handed
to the hooks as a payload, and only the effect the case describes is
simulated, inside a throwaway sandbox home."""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

from conftest import ROOT
from guard import attacks

SPEC_CLASSES = {
    "quoting",
    "wrappers",
    "variables",
    "subshells",
    "eval",
    "interpreters",
    "script files",
    "base64",
    "symlinks",
    "case",
    "zsh clobber",
    "cd then write",
    "config self-edit",
    "stale overwrite",
    "line deletion",
    "new file",
    "MCP write",
    "background write",
    "symlink swap",
}
CVES = {
    "CVE-2025-66032",
    "CVE-2025-54131",
    "CVE-2025-59829",
    "CVE-2026-25724",
    "CVE-2026-39861",
    "CVE-2025-59944",
    "CVE-2026-24053",
    "CVE-2026-25722",
    "CVE-2026-25725",
}


@pytest.fixture(scope="module")
def results():
    return attacks.run_all(ROOT / "attacks")


def test_every_case_behaves_as_its_file_expects(results):
    wrong = [
        f"{r.case.id}: expected {r.case.expect}, got {r.outcome} ({r.detail})"
        for r in results
        if not r.ok
    ]
    assert wrong == []


def test_every_class_from_the_spec_has_a_case(results):
    assert SPEC_CLASSES <= {r.case.cls for r in results}


def test_every_cve_from_the_spec_is_cited_with_a_link(results):
    cited = set()
    for r in results:
        assert r.case.source.strip(), r.case.id
        for cve in re.findall(r"CVE-\d{4}-\d+", r.case.source):
            assert "https://" in r.case.source, r.case.id
            cited.add(cve)
    assert cited == CVES


def test_the_report_gives_per_class_rates_and_what_still_gets_through(results):
    text = attacks.report(results)
    assert "| Class | Cases | Prevented | Detected | Through |" in text
    assert "## What still gets through" in text
    for r in results:
        if r.case.expect == "through":
            assert r.case.id in text


def test_no_command_is_ever_run(tmp_path):
    proof = tmp_path / "it-ran"
    case_file = tmp_path / "one.toml"
    case_file.write_text(
        f'[[case]]\nid = "would-touch"\nclass = "probe"\nsource = "test"\n'
        f'command = "touch {proof} && echo x >> {{vault}}/memory/state.md"\nexpect = "deny"\ncomponent = "C1"\n'
    )
    (r,) = attacks.run_all(tmp_path)
    assert r.ok and not proof.exists()


def test_a_case_that_slips_through_unexpectedly_fails_the_run(tmp_path):
    (tmp_path / "bad.toml").write_text(
        '[[case]]\nid = "harmless"\nclass = "probe"\nsource = "test"\ncommand = "echo hi"\nexpect = "deny"\ncomponent = "C1"\n'
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    run = subprocess.run(
        [sys.executable, "-m", "guard", "attacks", str(tmp_path)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert run.returncode == 1
    assert "harmless" in run.stdout


def test_the_sandbox_leaves_the_environment_as_it_found_it(tmp_path):
    before = {k: os.environ.get(k) for k in ("HOME", "GUARD_CONFIG", "GUARD_TRASH")}
    (tmp_path / "one.toml").write_text(
        '[[case]]\nid = "x"\nclass = "probe"\nsource = "test"\ncommand = "echo x >> {vault}/memory/state.md"\nexpect = "deny"\ncomponent = "C1"\n'
    )
    attacks.run_all(tmp_path)
    assert {k: os.environ.get(k) for k in before} == before
