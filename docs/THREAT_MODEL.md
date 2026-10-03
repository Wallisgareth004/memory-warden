# Threat model

## What is protected

A memory shared by several agents in a Claude Code setup: folders of notes the agents treat as canon (`protected` roots), files that may only grow, like a daily log (`append_only`), and the guard itself (its code, its config, the Claude settings that hold its hooks, and skills).

## Who it defends against

- **A subagent** that writes protected memory, by mistake, by over-eagerness, or because content it read told it to.
- **Injected instructions** arriving inside data an agent reads (web pages, mail, files). The guard doesn't try to judge intent; it acts on where writes land and what changed on disk.
- **A stale overwrite**: a sync tool or a second session writing an older whole-file copy over a newer one.
- **An agent reconfiguring the guard** mid-session.

Out of scope: a malicious process running as the same user outside Claude Code (it can stop the watcher; the guard is tamper-evident, not tamper-proof), the operating system, and general command safety (pair it with a command guard and the sandbox).

## Mapped to OWASP

Every quote was matched word for word against the official PDFs downloaded from genai.owasp.org.

| Threat in this setting | OWASP | Quote | Component |
|---|---|---|---|
| A subagent (or injected content) corrupts shared memory, or a stale copy overwrites it | **ASI06** Memory & Context Poisoning (Top 10 for Agentic Applications 2026) | "In Memory and Context Poisoning, adversaries corrupt or seed this context with malicious or misleading data, causing future reasoning, planning, or tool use to become biased, unsafe, or aid exfiltration." It "focuses on persistent corruption of agent memory and retrievable context that propagates across sessions and alters autonomous reasoning." | C1, C2, C3 |
| The same, in the threats guide | **T1** Memory Poisoning (Agentic AI – Threats and Mitigations, Feb 2025) | "Memory Poisoning exploits AI agents' reliance on short-term and long-term memory, allowing attackers to corrupt stored information" | C1, C2, C3 |
| A subagent acts with the main agent's write rights | **ASI03** Identity and Privilege Abuse | "Identity & Privilege Abuse exploits dynamic trust and delegation in agents to escalate access and bypass controls" | C1 |
| Bash (a legitimate tool) used to write memory by indirection | **ASI02** Tool Misuse and Exploitation; **T2** Tool Misuse | ASI02: "This entry covers cases where the agent operates within its authorized privileges but applies a legitimate tool in an unsafe or unintended way". T2: "Tool Misuse occurs when attackers manipulate AI agents into abusing their authorized tools through deceptive prompts and operational misdirection" | C1 resolver, C2 |
| A script file or generated code does the write | **ASI05** Unexpected Code Execution (RCE) | "Because this code is often generated in real-time by the agent it can bypass traditional security controls." | C2 (effect, not text) |
| Agents with more write power than the task needs | **LLM03:2026** Excessive Agency (was **LLM06:2025**) | Both editions: "Excessive Agency is the vulnerability that enables damaging actions to be performed in response to unexpected, ambiguous or manipulated outputs from an LLM, regardless of what is causing the LLM to malfunction." | C1, C4 |
| Instructions arrive inside data the agent reads | **LLM01:2026** / **LLM01:2025** Prompt Injection | 2026: "LLMs make no architectural distinction between "instructions" and "data"". 2025: "A Prompt Injection Vulnerability occurs when user prompts alter the LLM's behavior or output in unintended ways." | all (it works on effects, not intent) |
| No one can say which agent did it | **T8** Repudiation & Untraceability | "Repudiation and Untraceability occur when AI agents operate autonomously without sufficient logging, traceability, or forensic documentation, making it difficult to audit decisions, attribute accountability, or detect malicious activities." | C2 evidence, C3b evidence |

Sources: OWASP Top 10 for Agentic Applications 2026 (Dec 2025); OWASP Top 10 for LLM Applications 2026 and 2025; OWASP Agentic AI – Threats and Mitigations (Feb 2025).

## Attack classes

Each class has at least one case in [`attacks/`](../attacks); results in [results/attacks.md](results/attacks.md).

| Class | Source |
|---|---|
| Quoting (`"mem""ory"`, `mem\ory`) | research note |
| Full paths and wrappers (`/usr/bin/tee`, `sh -c`, `env`, `nohup`, `timeout`, `xargs`) | research note |
| Variables, `$IFS`, short flags | [CVE-2025-66032](https://github.com/advisories/GHSA-xq4m-mc3c-vvg3) |
| Subshells and backticks | [CVE-2025-54131](https://nvd.nist.gov/vuln/detail/CVE-2025-54131) |
| `eval`, `source <(...)` | research note |
| Heredocs and interpreters (`python -c`) | research note |
| Script files | effect-only (no command text shows the write) |
| base64 into a shell | research note |
| Symlinks | [CVE-2025-59829](https://github.com/advisories/GHSA-66m2-gx93-v996), [CVE-2026-25724](https://github.com/advisories/GHSA-4q92-rfm6-2cqx), [CVE-2026-39861](https://github.com/advisories/GHSA-vp62-r36r-9xqp) |
| Case on a case-insensitive disk | [CVE-2025-59944](https://nvd.nist.gov/vuln/detail/CVE-2025-59944) |
| zsh clobber `>|` | [CVE-2026-24053](https://github.com/advisories/GHSA-q728-gf8j-w49r) |
| `cd` then write | [CVE-2026-25722](https://github.com/advisories/GHSA-66q4-vfjg-2qhh) |
| A file created where none existed; config self-edit | [CVE-2026-25725](https://github.com/advisories/GHSA-ff64-7w26-62rf) |
| Other write forms (`git checkout`, `find -delete`, `rsync --delete`, `tar -x`, `dd of=`, `truncate`, `perl -i`, the Write tool) | research note |
| Memory-specific: stale overwrite, line deletion, a new file in a protected folder, an MCP write, a background write after return, an out-of-band write, a symlink swap, a stopped watcher | re-created incidents (synthetic) |

## Failure modes

| Failure | Effect | Answer |
|---|---|---|
| A hook crashes, times out or goes missing | Fails open: the write proceeds | C2 and C3 detect; C5 checks hooks are present, runnable, deciding and firing |
| A same-user process stops the watcher | No live restore | The doctor's heartbeat check; C3a still guards commits |
| A write lands after the call returns | Outside C2's window | The next call's fingerprint catches it; a subagent's last call has no next one (listed as getting through) |
| An MCP server writes outside a tool call | Not a tool event | C3b for append-only files; otherwise it gets through |
| The main thread writes during a subagent's call | Could be blamed on the subagent | Main-thread markers excuse it |
| A sync tool overwrites with a stale copy | Lost lines | C3b restore and evidence; C3a at commit |
| `git commit --no-verify` | Gate skipped | Documented; C3b still runs |
| `policy_settings` changed | ConfigChange can't block it | Alerted; the doctor's drift check |
| Python start-up per hook | Latency: about 27 ms a call, about 16 of it Python starting | Standard library only; lazy imports, held by a test; measured in the replay |
| A case-insensitive filesystem | Case bypasses | The filesystem is probed and paths matched to suit |

## Why deny, never ask

In bypass-permissions mode prompts are disabled, so an "ask" decision doesn't hold. Before Claude Code 2.1.211, auto mode could approve a Bash command running outside the sandbox without showing the prompt a hook's "ask" requested; from 2.1.211 it shows the prompt. A guard has to hold in every mode and on every version, so the guard denies, and changing a protected setting means ending the session, editing, and restarting.
