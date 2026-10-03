"""Alert sinks. An alert is one line: what, when, which agent. Never file content.

    log           state_dir/alerts.log (owner-only)
    stderr        the hook's or watcher's stderr
    macos-notify  a macOS notification (osascript)
    linux-notify  notify-send
    webhook       an HTTPS POST of {"text": line} to alerts.webhook_url (opt-in)

A sink that fails is skipped; an alert never blocks or crashes its caller.
The notify and webhook sinks import what they need when they fire: the hooks
load this module on every call, and most calls send no alert.
"""

from __future__ import annotations

import json
import os
import sys

from .config import Config, ensure_state_dir


def _log(line: str, cfg: Config) -> None:
    path = ensure_state_dir(cfg) / "alerts.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    os.chmod(path, 0o600)


def send(line: str, cfg: Config) -> None:
    for sink in cfg.sinks:
        try:
            if sink == "log":
                _log(line, cfg)
            elif sink == "stderr":
                print(f"guard: {line}", file=sys.stderr)
            elif sink == "macos-notify":
                import subprocess

                script = f'display notification {json.dumps(line)} with title "guard"'
                subprocess.run(
                    ["osascript", "-e", script], timeout=10, capture_output=True
                )
            elif sink == "linux-notify":
                import subprocess

                subprocess.run(
                    ["notify-send", "guard", line], timeout=10, capture_output=True
                )
            elif sink == "webhook" and cfg.webhook_url:
                import urllib.request

                body = json.dumps({"text": line}).encode()
                req = urllib.request.Request(
                    cfg.webhook_url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=10).close()
        except Exception:
            continue
