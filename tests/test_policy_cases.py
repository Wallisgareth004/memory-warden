"""C1, the per-agent write policy: the ported decision table.

Every case comes from the hook this guard grew out of (its 69 subagent cases;
the old "ask" case for config files is C4's now), re-pointed at a synthetic
vault: memory/ and hubs/ are protected, memory/daily-log.md is append-only,
inbox/ is where subagents may write, notes/ is unguarded. Reads pass whatever
they name; a subagent's write that lands in a protected root is denied. New
cases at the end cover the append-only rule: grow it, never rewrite it.
"""

from __future__ import annotations

import os
import textwrap
from dataclasses import replace

import pytest

from conftest import GUARD_TOML
from guard import config, policy


@pytest.fixture
def layout(home, vault, tmp_path):
    (vault / "memory" / "goals.md").write_text("goals\n")
    index = home / ".claude" / "projects" / "p" / "memory" / "MEMORY.md"
    index.parent.mkdir(parents=True)
    index.write_text("index\n")
    path = home / "guard.toml"
    path.write_text(
        textwrap.dedent(GUARD_TOML).replace(
            'case_insensitive = "auto"', "case_insensitive = true"
        )
    )
    cfg = config.load(path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    V = str(vault)
    return {
        "cfg": cfg,
        "V": V,
        "SS": f"{V}/memory/state.md",
        "HUB": f"{V}/hubs/trading.md",
        "DL": f"{V}/memory/daily-log.md",
        "INBOX": f"{V}/inbox/probe.md",
        "NOTE": f"{V}/notes/x.md",
        "CANON": f"{V}/memory/facts.md",
        "GOALS": f"{V}/memory/goals.md",
        "MEM": str(index),
        "T": str(scratch),  # a scratch folder outside the vault (stands in for /tmp)
    }


def edit(path, sub=False, old="a", new="b", tool="Edit"):
    p = {
        "tool_name": tool,
        "tool_input": {"file_path": path, "old_string": old, "new_string": new},
    }
    if sub:
        p.update(agent_id="a1", agent_type="general-purpose")
    return p


def bash(cmd, sub=False, cwd=None):
    p = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    if cwd:
        p["cwd"] = cwd
    if sub:
        p.update(agent_id="a1", agent_type="general-purpose")
    return p


def outcome(payload, cfg) -> str:
    out = policy.decide(payload, cfg)
    return "allow" if out is None else out["hookSpecificOutput"]["permissionDecision"]


def cases(L):
    V, SS, HUB, DL, INBOX, NOTE, CANON, GOALS, MEM, T = (
        L[k]
        for k in ("V", "SS", "HUB", "DL", "INBOX", "NOTE", "CANON", "GOALS", "MEM", "T")
    )
    up = lambda p: p.replace("/memory/", "/MEMORY/").replace("/hubs/", "/HUBS/")  # noqa: E731
    return [
        ("subagent Edit state", edit(SS, True), "deny"),
        ("subagent Edit a hub", edit(HUB, True), "deny"),
        ("subagent Write the index", edit(MEM, True, tool="Write"), "deny"),
        (
            "subagent Edit the log (an append)",
            edit(DL, True, old="- line 1\n", new="- line 1\n- line 2\n"),
            "allow",
        ),
        ("subagent Edit the inbox", edit(INBOX, True), "allow"),
        ("subagent Edit an ordinary note", edit(NOTE, True), "allow"),
        ("main Edit state", edit(SS), "allow"),
        ("agent_id absent (schema drift)", {**edit(SS), "agent_type": "x"}, "allow"),
        ("subagent Bash >> state", bash(f'echo x >> "{SS}"', True), "deny"),
        ("subagent Edit STATE (case-insensitive disk)", edit(up(SS), True), "deny"),
        ("subagent Edit a HUB (case-insensitive disk)", edit(up(HUB), True), "deny"),
        (
            "subagent Write memory.md index lowercase",
            edit(MEM.replace("MEMORY.md", "memory.md"), True, tool="Write"),
            "deny",
        ),
        (
            "subagent Edit the LOG upper-case (an append)",
            edit(up(DL), True, old="x", new="xy"),
            "allow",
        ),
        (
            "subagent Edit the INBOX upper-case",
            edit(INBOX.replace("/inbox/", "/INBOX/"), True),
            "allow",
        ),
        ("main Edit STATE upper-case", edit(up(SS)), "allow"),
        # reads pass whatever they name; `2>/dev/null` is not a write
        (
            "R1 grep facts 2>/dev/null",
            bash(f"grep -n rate {CANON} 2>/dev/null", True),
            "allow",
        ),
        (
            "R2 wc goals after 2>/dev/null",
            bash(f"ls x 2>/dev/null; wc -c {GOALS}", True),
            "allow",
        ),
        (
            "R3 cat a hub >/dev/null",
            bash(f"cat '{HUB}' >/dev/null && echo ok", True),
            "allow",
        ),
        (
            "R4 sed -n facts 2>&1",
            bash(f"sed -n 1,80p {CANON} 2>&1 | head", True),
            "allow",
        ),
        # writes
        ("W1 plain append", bash(f"echo x >> {CANON}", True), "deny"),
        (
            'W2 quote-split mem""ory',
            bash(f'echo x >> "{V}/mem""ory/facts.md"', True),
            "deny",
        ),
        (
            "W3 cd + relative path",
            bash(f"cd {V} && echo x >> memory/facts.md", True),
            "deny",
        ),
        (
            "W4 cd into memory",
            bash(f"cd {V}/memory; printf x >> facts.md", True),
            "deny",
        ),
        (
            "W5 variable-built path",
            bash('D=memory; echo x >> "$HOME/vault/$D/facts.md"', True),
            "deny",
        ),
        ("W6 glob", bash("echo x >> ~/vault/mem*/facts.md", True), "deny"),
        (
            "W7 python -c write",
            bash(f"python3 -c \"open('{CANON}','a').write('x')\"", True),
            "deny",
        ),
        (
            "W8 symlink, write through it",
            bash(f"ln -s {V}/memory {T}/m && echo x >> {T}/m/facts.md", True),
            "deny",
        ),
        (
            "W9 relative, session cwd = vault",
            bash("echo x >> memory/facts.md", True, cwd=V),
            "deny",
        ),
        ("W10 tee into a hub", bash(f"tee -a '{HUB}' < {T}/x", True), "deny"),
        ("W11 cp onto a hub", bash(f"cp {T}/x '{HUB}'", True), "deny"),
        ("OK1 log append (design)", bash(f'printf x >> "{DL}"', True), "allow"),
        ("OK2 inbox write (design)", bash(f"echo x > {INBOX}", True), "allow"),
        # the forms around them
        ("X1 bash -c inner write", bash(f"bash -c 'echo x >> {CANON}'", True), "deny"),
        (
            "X2 eval inner write",
            bash('eval "echo x >> $HOME/vault/hubs/h.md"', True),
            "deny",
        ),
        (
            "X3 python heredoc write",
            bash(f"python3 - <<'EOF'\nopen('{CANON}','a').write('x')\nEOF", True),
            "deny",
        ),
        (
            "X4 find -delete in memory",
            bash(f"find {V}/memory -name '*.md' -delete", True),
            "deny",
        ),
        (
            "X5 git checkout a memory file",
            bash("git -C ~/vault checkout -- memory/facts.md", True),
            "deny",
        ),
        ("X6 broken quotes + write", bash(f'echo x >> "{CANON}', True), "deny"),
        ("X7 main thread append", bash(f"echo x >> {CANON}"), "allow"),
        (
            "X8 find -exec grep (a read)",
            bash(f"find {V} -name '*.md' -exec grep -l foo {{}} +", True),
            "allow",
        ),
        (
            "X9 python -c naming memory/",
            bash(f"python3 -c \"print(open('{CANON}').read())\"", True),
            "deny",
        ),
        (
            "X10 relative read, cwd = vault",
            bash("cat memory/facts.md | head", True, cwd=V),
            "allow",
        ),
        (
            "X11 cwd = vault, write to scratch",
            bash(f"grep -rn foo . > {T}/out.txt", True, cwd=V),
            "allow",
        ),
        (
            "X12 cp FROM memory to scratch",
            bash(f"cp {CANON} {T}/facts.md", True),
            "allow",
        ),
        ("X13 mv a hub away", bash(f"mv '{HUB}' {T}/", True), "deny"),
        ("X14 trash goals.md", bash(f"/usr/bin/trash {GOALS}", True), "deny"),
        ("X15 ln -s onto a hub", bash(f"ln -s {T}/evil {V}/hubs/h.md", True), "deny"),
        (
            "X16 sed -i '' on a hub",
            bash(f"sed -i '' 's/a/b/' {V}/hubs/h.md", True),
            "deny",
        ),
        (
            "X17 tee to scratch and memory",
            bash(f"echo x | tee {T}/a '{SS}'", True),
            "deny",
        ),
        (
            "X18 $(...) path, cwd in memory",
            bash('D=$(pwd); echo x >> "$D/facts.md"', True, cwd=f"{V}/memory"),
            "deny",
        ),
        (
            "X19 grep | xargs sed -i",
            bash(f"grep -l a {V}/hubs/*.md | xargs sed -i '' 's/a/b/'", True),
            "deny",
        ),
        (
            "X20 subshell cd, then write",
            bash(f"(cd {T}); echo x >> memory/facts.md", True, cwd=V),
            "deny",
        ),
        (
            "W12 upper-case path (case-insensitive disk)",
            bash("echo x >> ~/VAULT/MEMORY/CANON.md", True),
            "deny",
        ),
        (
            "X21 heredoc into a hub",
            bash(f"cat > {V}/hubs/h.md <<'EOF'\nx\nEOF", True),
            "deny",
        ),
        (
            "X22 for-loop sed -i on hubs",
            bash(f"for f in {V}/hubs/*.md; do sed -i '' 's/a/b/' \"$f\"; done", True),
            "deny",
        ),
        ("X23 git pull in the vault", bash("git -C ~/vault pull", True), "deny"),
        (
            "X24 git status/log in the vault",
            bash("git -C ~/vault status --short && git -C ~/vault log -1", True),
            "allow",
        ),
        (
            "X25 write to $TMPDIR",
            bash(f'grep -c x {GOALS} > "$TMPDIR/n.txt"', True),
            "allow",
        ),
        ("X26 mkdir inside memory", bash(f"mkdir -p {V}/memory/newdir", True), "deny"),
        ("X27 rsync into hubs", bash(f"rsync -a {T}/x.md {V}/hubs/", True), "deny"),
        ("X28 touch an ordinary note", bash(f"touch {V}/notes/y.md", True), "allow"),
        ("X29 append the index", bash(f"echo x >> {MEM}", True), "deny"),
        (
            "X30 heredoc to a note (data)",
            bash(f"cat > {V}/notes/n.md <<'EOF'\nmemory/facts.md is canon\nEOF", True),
            "allow",
        ),
        (
            "X31 loop file names in scratch",
            bash(
                f'cd {T} && for p in 1 2; do grep -c x {GOALS} > "out_$p.txt"; done',
                True,
                cwd=V,
            ),
            "allow",
        ),
        (
            "X32 cd scratch, heredoc file",
            bash(f"cd {T} && cat > dl.py <<'EOF'\nprint(1)\nEOF", True, cwd=V),
            "allow",
        ),
        (
            "X33 unzip -l (a listing)",
            bash(f'cd {T} && for f in *.docx; do unzip -l "$f"; done', True, cwd=V),
            "allow",
        ),
        (
            "X34 python writes a note",
            bash(
                f"python3 - <<'EOF'\np='{V}/notes/x.md'\nopen(p,'a').write('x')\nEOF",
                True,
            ),
            "allow",
        ),
        (
            "X35 cd into hubs, then touch",
            bash(f"cd {V}/hubs && touch h.md", True, cwd=T),
            "deny",
        ),
        (
            "X36 bash -c cd doesn't persist",
            bash(f"bash -c 'cd {T}'; echo x >> memory/facts.md", True, cwd=V),
            "deny",
        ),
        # append-only, new: grow it, never rewrite it
        ("A1 truncate the log", bash(f"echo x > {DL}", True), "deny"),
        ("A2 tee (no -a) onto the log", bash(f"echo x | tee {DL}", True), "deny"),
        ("A3 tee -a onto the log", bash(f"echo x | tee -a {DL}", True), "allow"),
        ("A4 cp onto the log", bash(f"cp {T}/x {DL}", True), "deny"),
        ("A5 rm the log", bash(f"rm {DL}", True), "deny"),
        ("A6 Write (whole file) to the log", edit(DL, True, tool="Write"), "deny"),
        (
            "A7 Edit that deletes a line",
            edit(DL, True, old="- line 1\n", new=""),
            "deny",
        ),
        ("A8 sed -i on the log", bash(f"sed -i '' 's/1/2/' {DL}", True), "deny"),
        ("A9 main thread rewrites the log", bash(f"echo x > {DL}"), "allow"),
    ]


def test_the_table_has_every_ported_case(layout):
    assert len(cases(layout)) == 69 + 9


@pytest.mark.parametrize("i", range(78))
def test_case(layout, i):
    name, payload, want = cases(layout)[i]
    assert outcome(payload, layout["cfg"]) == want, name


def test_a_denial_says_why_and_where_to_write_instead(layout):
    out = policy.decide(bash(f"echo x >> {layout['CANON']}", True), layout["cfg"])
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "facts.md" in reason and "inbox" in reason.lower()


def test_an_allowed_agent_type_may_write(layout):
    cfg = replace(layout["cfg"], agent_types_allowed=("memory-curator",))
    payload = {**edit(layout["SS"], True), "agent_type": "memory-curator"}
    assert outcome(payload, cfg) == "allow"


def test_case_sensitive_disks_keep_cases_apart(layout):
    cfg = replace(layout["cfg"], case_insensitive=False)
    shouty = layout["SS"].replace("/memory/", "/MEMORY/")
    assert outcome(edit(shouty, True), cfg) == "allow"  # a different folder there


def test_when_the_parser_fails_the_old_text_check_still_denies(layout, monkeypatch):
    from guard import resolver

    def boom(*a, **k):
        raise ValueError("parser fell over")

    monkeypatch.setattr(resolver.Resolver, "write_reason", boom)
    assert outcome(bash(f"echo x >> {layout['CANON']}", True), layout["cfg"]) == "deny"
    assert outcome(bash(f"cat {layout['CANON']}", True), layout["cfg"]) == "allow"


def test_the_main_thread_can_be_held_to_the_policy_too(layout):
    cfg = replace(layout["cfg"], main="deny")
    assert outcome(edit(layout["SS"]), cfg) == "deny"


@pytest.mark.parametrize("mcp_scan, want", [(False, "allow"), (True, "deny")])
def test_mcp_arguments_are_scanned_only_when_asked(layout, mcp_scan, want):
    cfg = replace(layout["cfg"], mcp_scan=mcp_scan)
    payload = {
        "tool_name": "mcp__notes__write_note",
        "tool_input": {"path": layout["SS"], "content": "x"},
        "agent_id": "a1",
        "agent_type": "general-purpose",
    }
    assert outcome(payload, cfg) == want


def test_end_to_end_through_hook_py(layout, config_file):
    from conftest import run_hook

    proc = run_hook(
        "policy",
        bash(f"echo x >> {layout['CANON']}", True),
        env={"GUARD_CONFIG": str(config_file)},
    )
    assert '"permissionDecision": "deny"' in proc.stdout
    os.environ.get("TMPDIR")  # the suite never needs a real home or vault


# -- copy destinations: into a folder is not over a folder (found by the replay) --


@pytest.mark.parametrize(
    "cmd, want",
    [
        ("cp {T}/x {V}/", "allow"),  # a file into the vault root never touches memory/
        (
            "cp -R {T}/stuff/ {V}/",
            "deny",
        ),  # a folder's CONTENTS into the vault root could overwrite memory/
        ("rsync -a {T}/x {V}/", "allow"),
        ("rsync -a --delete {T}/empty/ {V}/", "deny"),  # --delete prunes the whole tree
        ("mv {T}/memory {V}/", "deny"),  # a folder named memory lands on memory/
    ],
)
def test_copying_into_a_folder_that_holds_protected_roots(layout, cmd, want):
    command = cmd.replace("{T}", layout["T"]).replace("{V}", layout["V"])
    assert outcome(bash(command, True), layout["cfg"]) == want
