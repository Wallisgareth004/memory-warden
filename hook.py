#!/usr/bin/env python3
"""Claude Code hook entry for every component:

    python3 /path/to/hook.py policy         PreToolUse  (C1 write policy, C4 self-protection)
    python3 /path/to/hook.py effect-pre     PreToolUse  (C2 fingerprint + intent)
    python3 /path/to/hook.py effect-post    PostToolUse (C2 effect vs intent)
    python3 /path/to/hook.py config-change  ConfigChange (C4)
    python3 /path/to/hook.py doctor-fast    SessionStart (C5 fast mode)

It reads the hook payload (JSON) on stdin and prints a decision, or nothing.
On anything it can't handle it exits 0 with no output, so it never wedges a
session; the reason goes to stderr.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    component = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    if not isinstance(payload, dict):
        return 0
    try:
        from guard import hooks

        out = hooks.run(component, payload)
    except Exception as e:  # fail open, say why
        print(
            f"guard: {component or '(none)'}: {e} (no decision; the call goes ahead)",
            file=sys.stderr,
        )
        return 0
    if out and "__exit__" in out:  # a blocking exit code, e.g. ConfigChange
        print(out.get("stderr", ""), file=sys.stderr)
        return int(out["__exit__"])
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
