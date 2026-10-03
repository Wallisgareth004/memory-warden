# memory-warden: memory integrity for multi-agent Claude Code

When several agents share one memory (a vault of notes, an index, an append-only log), a subagent can overwrite it, by mistake or because something it read told it to, and a stale copy from a sync tool can quietly roll it back. This guard keeps that memory intact. Subagents can't write protected memory; every tool call's real effect on disk is checked against what was allowed; append-only files survive bad overwrites, with evidence of what happened; the guard can't be switched off mid-session; and a doctor proves all of it is installed and firing.

It is **tamper-evident, not tamper-proof**, and it runs **beside** a command guard and the sandbox, never instead of them (see [What it isn't](#what-it-isnt)).

## Install (manual hooks)

Needs Python 3.11+ (standard library only) and, for the commit gate, [gitleaks](https://github.com/gitleaks/gitleaks). The code and its command are called `guard`.

1. Copy [`examples/guard.toml`](examples/guard.toml) to `~/.config/guard/guard.toml` and set your roots.
2. Add the hooks to `~/.claude/settings.json`. Quote the path: a space in it breaks the command.

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
          "hooks": [{"type": "command", "command": "python3 '/path/to/guard/hook.py' policy", "timeout": 10}]},
         {"matcher": "*",
          "hooks": [{"type": "command", "command": "python3 '/path/to/guard/hook.py' effect-pre", "timeout": 10}]}
       ],
       "PostToolUse": [
         {"matcher": "*",
          "hooks": [{"type": "command", "command": "python3 '/path/to/guard/hook.py' effect-post", "timeout": 10}]}
       ],
       "ConfigChange": [
         {"matcher": "user_settings|project_settings|local_settings|skills",
          "hooks": [{"type": "command", "command": "python3 '/path/to/guard/hook.py' config-change", "timeout": 10}]}
       ],
       "SessionStart": [
         {"hooks": [{"type": "command", "command": "python3 '/path/to/guard/hook.py' doctor-fast", "timeout": 30}]}
       ]
     }
   }
   ```
3. Start the tripwire where macOS privacy rules allow it to read your files, e.g. `tmux new-session -d -s guard '/path/to/guard/bin/guard tripwire watch'` (a launchd agent works only if it's granted access to the folder; on Linux, a systemd `--user` service).
4. In each repo that holds memory: `git config core.hooksPath /path/to/guard/githooks`.
5. Run `bin/guard doctor`. Every line should say PASS.

## The six components

**C1 · Per-agent write policy** (PreToolUse). A subagent's write that would land in a protected root is denied; reads always pass. Bash commands are parsed, not pattern-matched: quoting and concatenation vanish, `cd` and variables are followed from the call's working folder, heredocs and `$(...)` are scanned, and every write target is resolved through `~`, globs and symlinks, case-insensitively where the disk is. An append-only file may grow but never be rewritten, truncated, replaced or removed. *Can't see:* a write from inside a script file, or code that builds a path piece by piece (C2 catches both).

**C2 · Intent vs effect** (PreToolUse + PostToolUse). Before a subagent's call it fingerprints every file under the guarded roots and stores the policy's predicted write targets; afterwards it diffs. A protected change, or an append-only file that didn't just grow, makes the call return a block, sends an alert (paths, time, agent type, never content) and keeps the before-copy. It never restores (a restore could wipe a real main-thread write made the same second). *Can't see:* a write that lands after the call returns.

**C3 · Append-only memory.** *C3a, the commit gate:* gitleaks on the staged changes (failing closed when it's missing) and no removed line in any append-only file; escape hatch `git commit --no-verify`, with the reason in the message. *C3b, the tripwire:* polls each append-only file; when lines vanish it keeps the evidence first (the bad copy, last-good, a diff, the time, the process table, open files), then restores last-good plus every new line by an atomic compare-and-swap. *Can't stop:* a same-user process from stopping the watcher (the doctor notices).

**C4 · Self-protection.** No agent, the main thread included, may write the guard's files, its config, the Claude settings that hold the hooks, or skills, mid-session; a mid-session settings change is stopped with exit 2. Deny, never ask: "ask" doesn't hold in every permission mode. There's no in-session unlock: end the session, change it, restart. *Can't block:* `policy_settings` (it's alerted, and the doctor's drift check covers it).

**C5 · Doctor.** Hooks fail open on a crash, a timeout or a missing script, so the doctor checks every guard hook is present with a wide-enough matcher, runnable (Python 3.11+, script present, sane timeout), deciding (a canned subagent write must come back denied), and firing (heartbeats); that the tripwire is alive, the gate installed and gitleaks found; and that nothing drifted from the accepted baseline. At SessionStart it stays silent unless something is wrong.

**C6 · Evaluation.** The ported suites, an attack suite in which every case cites its source, and a replay over a synthetic corpus (below).

## What it isn't

- **Not a general command blocker.** [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) and [cc-safety-net](https://github.com/kenryu42/cc-safety-net) do that.
- **Not OS isolation.** Use Claude Code's `/sandbox` (Seatbelt on macOS, bubblewrap on Linux) or [sandbox-runtime](https://github.com/anthropics/sandbox-runtime).
- **Not a secrets scanner** beyond running gitleaks at commit.

## Threat model and attack classes

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): the threats mapped to OWASP (every quote checked against the official PDFs), the attack classes with their CVEs, and the failure modes.

## Results

All numbers below come from `bin/guard attacks` ([docs/results/attacks.md](docs/results/attacks.md)) and `bin/guard replay --n 2000 --seed 1 --sample 100` ([docs/results/replay.json](docs/results/replay.json)), on synthetic data only.

**Attack suite:** 53 cases, each citing a CVE, an advisory or a research note. Caught 51 of 53 (96%): prevented 40, detected 11 (C1 31, C2 8, C3a 1, C3b 2, C4 8, C5 1).

| Class | Cases | Prevented | Detected | Through |
|---|---|---|---|---|
| quoting, wrappers, variables, subshells | 12 | 12 | 0 | 0 |
| eval, interpreters, base64 | 5 | 2 | 3 | 0 |
| symlinks, case, zsh clobber, cd then write | 10 | 10 | 0 | 0 |
| script files, symlink swap, new file, MCP write | 6 | 1 | 5 | 0 |
| config self-edit | 5 | 5 | 0 | 0 |
| stale overwrite, line deletion, tamper | 5 | 2 | 3 | 0 |
| other write forms (git, find, rsync, tar, dd, truncate, perl, Write) | 8 | 8 | 0 | 0 |
| background write, out-of-band write | 2 | 0 | 0 | 2 |

**What still gets through:** a write that lands after the call returns (outside C2's window; the next call would see it, but a subagent's last call has no next one), and a write from outside any tool call to a protected file that isn't append-only (no tool event fires; the tripwire covers append-only files only). Fixed suites flatter defences: adaptive attackers do better (Nasr et al. 2025), so treat the rate as a floor for what's known, not a promise.

**Replay:** 2,000 synthetic calls (reads, allowed writes, protected writes in many spellings, MCP calls, Edit/Write, subagents and the main thread), labelled by how they were built. 0 false positives, 0 false negatives. The policy's own work: p50 0.29 ms, p95 0.78 ms. Through `hook.py` as Claude Code runs it: p50 26.92 ms and p95 27.85 ms (n = 100), of which a bare Python start-up, timed alongside, is p50 15.61 ms.

## Platform, privacy, licence

- **macOS:** built and tested here (APFS is case-insensitive by default; the probe finds that). **Linux:** standard library only, polling, `notify-send`, systemd; expected to work, not yet run in CI. **Windows:** not supported.
- **Privacy:** no network by default (the webhook sink is opt-in and HTTPS-only). Alerts never hold file content. Evidence folders hold process tables and open-file lists, so they stay local, owner-only, for 30 days.
- **Licence:** MIT; see [LICENSE](LICENSE).

## Development

```sh
bin/test                          # everything, on synthetic fixtures in temp folders
bin/guard attacks                 # the attack suite and its report
bin/guard replay --n 2000         # the replay
bin/guard doctor                  # check a real install
```

Case study: [docs/CASE_STUDY.md](docs/CASE_STUDY.md).
