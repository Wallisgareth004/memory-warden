"""guard: the command line.

guard gate                 the pre-commit gate (run by githooks/pre-commit)
guard tripwire check       one tripwire pass over every append-only file
guard tripwire watch       the tripwire, polling (run it in tmux, launchd or systemd)
"""

from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="guard", description="Memory integrity for multi-agent Claude Code setups."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gate", help="the pre-commit gate: secrets and append-only files")
    tw = sub.add_parser(
        "tripwire", help="watch append-only files and restore lost lines"
    )
    tw.add_argument("action", choices=["check", "watch"])
    sub.add_parser(
        "doctor",
        help="prove the guard is installed, runnable, deciding and alive",
        add_help=False,
    )
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["replay"]:
        from . import replay

        return replay.main(argv[1:])
    if argv[:1] == ["attacks"]:
        from . import attacks

        return attacks.main(argv[1:])
    if argv[:1] == ["doctor"]:
        from . import doctor

        return doctor.main(argv[1:])
    args = ap.parse_args(argv)
    if args.cmd == "gate":
        from . import gate

        return gate.main()
    if args.cmd == "tripwire":
        from . import tripwire

        return tripwire.main(args.action)
    return 2


if __name__ == "__main__":
    sys.exit(main())
