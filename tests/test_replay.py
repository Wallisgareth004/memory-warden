"""The replay harness: a synthetic corpus of tool calls (reads, allowed writes,
protected writes, main thread and subagents, quoting, heredocs, MCP calls),
each labelled allow or deny by how the generator built it, never by the guard.
The replay reports decisions, false positives, false negatives and latency."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from conftest import ROOT
from guard import replay


def test_the_corpus_is_the_same_for_the_same_seed():
    assert replay.generate(200, seed=4) == replay.generate(200, seed=4)
    assert replay.generate(200, seed=4) != replay.generate(200, seed=5)


def test_the_corpus_mixes_what_real_sessions_do():
    corpus = replay.generate(1000, seed=1)
    kinds = {c["kind"] for c in corpus}
    assert {
        "read",
        "allowed write",
        "protected write",
        "main-thread write",
        "mcp",
    } <= kinds
    subagents = sum(1 for c in corpus if c["payload"].get("agent_id"))
    assert 0.5 < subagents / len(corpus) < 0.9
    assert any(
        "<<'EOF'" in c["payload"]["tool_input"].get("command", "") for c in corpus
    )
    assert {c["expect"] for c in corpus} == {"allow", "deny"}


def test_the_replay_has_no_false_negatives_or_false_positives():
    r = replay.run(replay.generate(1500, seed=2), sample=0)
    assert r["false_negatives"] == [], r["false_negatives"][:5]
    assert r["false_positives"] == [], r["false_positives"][:5]
    assert r["calls"] == 1500 and r["denied"] > 0 and r["allowed"] > 0


def test_latency_is_reported_in_process_and_through_hook_py():
    r = replay.run(replay.generate(120, seed=3), sample=20)
    assert r["latency_ms"]["in_process"]["p50"] > 0
    assert r["latency_ms"]["hook_py"]["p95"] >= r["latency_ms"]["hook_py"]["p50"] > 0


def test_bare_python_start_up_is_timed_beside_hook_py():
    """So a reader can split a hook call into Python starting and the guard's own load and work."""
    r = replay.run(replay.generate(60, seed=3), sample=10)
    lat = r["latency_ms"]
    assert lat["python_startup"]["n"] == 10
    assert 0 < lat["python_startup"]["p50"] < lat["hook_py"]["p50"]


def test_the_command_line_writes_a_report(tmp_path):
    out = tmp_path / "replay.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard",
            "replay",
            "--n",
            "200",
            "--seed",
            "1",
            "--sample",
            "5",
            "--report",
            str(out),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    data = json.loads(out.read_text())
    assert data["calls"] == 200 and "false_positives" in data
