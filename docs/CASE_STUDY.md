# Case study: guard rails for a shared agent memory

## The incident

A personal knowledge base was shared by several agents: one main assistant, its subagents, and a second machine syncing the same folder. Its daily log was append-only by convention. Over about a month, that log was overwritten several times by a stale copy of itself. Each time, lines that had been added in the meantime vanished.

None of it was lost for good, because a git pre-commit gate refused any commit that removed lines from the log (measured on my private setup: it caught 25 removed lines with zero loss). But the gate only acts at the next commit, hours after the fact, when whoever wrote the stale copy is long gone. The cause, found later, was a race between a sync tool and an old hook on the second machine.

So two things were needed: catch the overwrite *in the act*, with evidence, and stop agents from writing shared memory they shouldn't.

## The bypass

The first defence against subagent writes was a text filter on Bash commands: deny any write-shaped command that names the memory folder. Tested against a 17-case probe on my private setup, it decided only 7 correctly. Seven real writes got through, among them a `cd` followed by a relative path, a path built in a variable, a glob, `python3 -c` writing the file, and a write through a symlink. Its only denials in a day of real use were harmless reads, flagged because `2>/dev/null` looked like a write.

The lesson: a filter that reads text answers "does this command mention the folder?", not "where does this write land?". The rebuilt policy parses the command, follows `cd` and variables, resolves every write target to an absolute path, and only then decides. It still can't see a write made from inside a script file, which no command text shows. That led to the second layer: check the effect on disk, not the intent in the text.

## Design

**Prevent where you can, detect everywhere, and make the detector prove it's alive.**

- **Prevent:** the write policy (C1) and self-protection (C4) deny before the tool runs. Deny, never ask, because "ask" doesn't hold in every permission mode.
- **Detect:** the effect check (C2) diffs the disk around every subagent call; the tripwire (C3b) watches append-only files continuously and restores lost lines after keeping the evidence; the commit gate (C3a) is the last line.
- **Prove it's alive:** hooks fail open on a crash, a timeout or a missing script, so the doctor (C5) checks each hook is installed, runnable, deciding (a canned write must come back denied) and firing, and that the tripwire's heartbeat is fresh.

Each preventive layer has a detective partner, because each preventive layer can fail silently.

## Evaluation

**Attack suite:** 53 cases, each citing a CVE, an advisory or a research note (nine CVEs, all checked: seven Claude Code advisories and two in the NVD). Caught 51 of 53 (96%): prevented 40, detected 11. The two that get through are the documented limits: a write landing after the call returns, and a write from outside any tool call to a file that isn't append-only. Full table: [results/attacks.md](results/attacks.md).

**Replay:** on 2,000 synthetic calls labelled by how they were built, 0 false positives and 0 false negatives. The policy's own work takes 0.29 ms at the median; a call through the hook entry, as Claude Code makes it, takes about 27 ms, 16 ms of it Python starting ([results/replay.json](results/replay.json)). The single-file hooks this package grew from were replayed on my private logs: the write policy over 3,227 real subagent commands with no real command newly blocked (its first build had eight false positives, fixed and pinned as tests), and the effect check over 6,650 real subagent calls with no false alarm and about 1.2 ms of its own work per call.

**What the measurements caught:** on its first run the replay found false positives the unit tests had missed: copying a file *into* a folder that holds protected memory was treated as replacing the whole folder, and self-protection blocked any whole-tree write in a project (a plain `git pull`). Both were fixed precisely, with the attack results unchanged. A synthetic corpus is only as good as its mix; this one paid for itself the first time it ran. Tracing the latency figure for these docs caught something too: every hook call was loading the doctor, the commit gate and the network code, none of which a call uses. They now load only when needed, and a test keeps them out of the per-call path.

**Honest limits:** a fixed suite flatters any defence. Adaptive attackers who see the defence do better (Nasr et al. 2025), so the catch rate is a floor for the attacks known, not a promise about the unknown ones. The guard is tamper-evident, not tamper-proof.

## What I'd do next

- Package it as a Claude Code plugin, so install is one step and the doctor reads the plugin's own hook file.
- Run the suite on Linux in CI.
- Close the background-write gap: a short trailing fingerprint after a subagent's last call.
- Watch protected (not only append-only) files outside tool calls, for out-of-band writers.
