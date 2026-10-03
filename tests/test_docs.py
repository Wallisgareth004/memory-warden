"""The docs' numbers come from the results, never from memory. The results
files must match a fresh run; the README and the case study must quote them
exactly; numbers measured on private logs must say so (and stay out of the
README, whose numbers are synthetic); and every relative link must resolve."""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter

import pytest

from conftest import ROOT
from guard import attacks, replay

DOCS = ("README.md", "docs/THREAT_MODEL.md", "docs/CASE_STUDY.md")
RESULTS = ROOT / "docs" / "results"
REPLAY_COMMAND = "bin/guard replay --n 2000 --seed 1 --sample 100"

# Numbers measured on private logs or a private setup. Any sentence holding one must say so.
PRIVATE = re.compile(
    r"3,227|6,650|\b25 removed lines|\b23 ms|\b1\.2 ms|\bin 2 s\b|\b17-case\b|\b7 of 17\b|only 7 correctly"
)


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _saved_replay() -> dict:
    return json.loads((RESULTS / "replay.json").read_text())


@pytest.fixture(scope="module")
def suite():
    return attacks.run_all(ROOT / "attacks")


def test_the_attack_results_file_is_a_fresh_run(suite):
    assert (RESULTS / "attacks.md").read_text() == attacks.report(suite)


def test_the_replay_results_file_reproduces():
    saved = _saved_replay()
    assert REPLAY_COMMAND in _text("README.md")
    fresh = replay.run(replay.generate(2000, seed=1), sample=0)
    for key in (
        "calls",
        "allowed",
        "denied",
        "expected_denials",
        "false_positives",
        "false_negatives",
    ):
        assert fresh[key] == saved[key], key
    assert saved["latency_ms"]["hook_py"]["n"] == 100


def test_the_readme_and_case_study_quote_the_attack_summary(suite):
    summary = re.search(r"Caught .*?\)\.", attacks.report(suite)).group(0)
    readme, case_study = _text("README.md"), _text("docs/CASE_STUDY.md")
    assert summary in readme
    assert summary.split(" (C", 1)[0] in case_study  # without the per-component split
    assert f"{len(suite)} cases" in readme and f"{len(suite)} cases" in case_study


def test_the_readme_class_table_adds_up_from_the_results(suite):
    by_class: dict = {}
    for r in suite:
        by_class.setdefault(r.case.cls, Counter())[r.outcome] += 1
    section = _text("README.md").split("## Results", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(
        r"^\| ([a-zA-Z][^|]*?) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", section, re.M
    )
    assert rows
    covered = []
    for names, n, prevented, detected, through in rows:
        group = [c.strip() for c in re.sub(r"\s*\(.*\)$", "", names).split(",")]
        covered += group
        total = sum((by_class[c] for c in group), Counter())
        assert (int(n), int(prevented), int(detected), int(through)) == (
            sum(total.values()),
            total["prevented"],
            total["detected"],
            total["through"],
        ), names
    assert sorted(covered) == sorted(by_class)


def test_the_docs_quote_the_replay_as_it_ran():
    saved = _saved_replay()
    lat = saved["latency_ms"]
    readme, case_study = _text("README.md"), _text("docs/CASE_STUDY.md")
    fp, fn = len(saved["false_positives"]), len(saved["false_negatives"])
    assert f"{saved['calls']:,} synthetic calls" in readme
    assert f"{saved['calls']:,} synthetic calls" in case_study
    assert f"{fp} false positives, {fn} false negatives" in readme
    assert f"{fp} false positives and {fn} false negatives" in case_study
    inp, hook, bare = lat["in_process"], lat["hook_py"], lat["python_startup"]
    assert f"p50 {inp['p50']} ms, p95 {inp['p95']} ms" in readme
    assert f"p50 {hook['p50']} ms and p95 {hook['p95']} ms (n = {hook['n']})" in readme
    assert f"p50 {bare['p50']} ms" in readme
    assert f"{inp['p50']} ms at the median" in case_study
    assert f"about {round(hook['p50'])} ms" in case_study
    assert f"{round(bare['p50'])} ms of it" in case_study
    assert (
        f"about {round(hook['p50'])} ms a call, about {round(bare['p50'])} of it"
        in _text("docs/THREAT_MODEL.md")
    )


def test_the_threat_model_links_every_cve_the_suite_cites():
    threat_model, case_study = (
        _text("docs/THREAT_MODEL.md"),
        _text("docs/CASE_STUDY.md"),
    )
    cited = {}
    for f in sorted((ROOT / "attacks").glob("*.toml")):
        for case in tomllib.loads(f.read_text())["case"]:
            m = re.match(r"(CVE-\d{4}-\d+) (https://[^\s,;]+)", case["source"])
            if m:
                cited[m[1]] = m[2]
    for cve, url in cited.items():
        assert f"[{cve}]({url})" in threat_model, cve
    words = {7: "seven", 2: "two", 9: "nine"}
    advisories = sum("github.com/advisories/" in u for u in cited.values())
    nvd = sum("nvd.nist.gov/" in u for u in cited.values())
    assert advisories + nvd == len(cited)
    assert (
        f"{words[len(cited)]} CVEs, all checked: {words[advisories]} Claude Code advisories"
        f" and {words[nvd]} in the NVD"
    ) in case_study


@pytest.mark.parametrize("name", DOCS)
def test_numbers_from_private_logs_say_so(name):
    text = _text(name)
    if name == "README.md":
        assert not PRIVATE.search(text), PRIVATE.search(text)
        return
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        if PRIVATE.search(sentence):
            assert "private" in sentence.lower(), sentence


def _anchors(markdown: str) -> set[str]:
    return {
        re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
        for h in re.findall(r"^#+ (.+)$", markdown, re.M)
    }


@pytest.mark.parametrize("name", DOCS)
def test_every_relative_link_resolves(name):
    path = ROOT / name
    for target in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://")):
            continue
        file, _, anchor = target.partition("#")
        dest = (path.parent / file).resolve() if file else path
        assert dest.exists(), f"{name}: {target}"
        if anchor:
            assert anchor in _anchors(dest.read_text(encoding="utf-8")), (
                f"{name}: {target}"
            )
