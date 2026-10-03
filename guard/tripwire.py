"""C3b, the live tripwire: catch an append-only file losing lines in the act,
keep the evidence, and put the lines back.

A commit gate makes a bad overwrite lossless only at the next commit, hours
later, when whoever did it is long gone. The tripwire runs on the change
itself: every `poll_seconds` it checks each append-only file's mtime, size and
inode, and on a change it compares the file's lines with a rolling last-good
copy (as multisets, blank lines ignored).

  * Lines only added: last-good is refreshed. Nothing else happens.
  * Lines vanished:
      1. evidence first, while the writer may still be alive: the bad file byte
         for byte, last-good, a diff, the time to the second, the process table
         and the open file handles under the folder;
      2. restore: last-good plus every new line in the bad file, except lines
         matching drop_line_patterns, by an atomic compare-and-swap that never
         clobbers a write landing meanwhile;
      3. one alert line (counts and the evidence folder, never content).

Timing: the first sample is taken on wake, and if it removes nothing it
becomes last-good at once, so an append made seconds before an overwrite
survives the restore. Nothing is acted on until the file has held still for
settle_seconds. A trailing line with no newline (a write in progress) never
becomes last-good. A `.rotation-in-progress` flag in the file's folder pauses
it, and the first pass after the flag goes re-baselines instead of alarming.
One pass runs at a time (a lock file).

It's tamper-evident, not tamper-proof: a same-user process can stop the
watcher. Its heartbeat is how the doctor notices.
"""

from __future__ import annotations

import contextlib
import difflib
import fcntl
import hashlib
import os
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from . import alerts, config, retention

ROTATION_FLAG = ".rotation-in-progress"
LOCK_TIMEOUT = 120.0


class Refused(Exception):
    """The tripwire won't run on this path (it would baseline on nothing)."""


def state_for(cfg: config.Config, path: Path) -> Path:
    digest = hashlib.sha1(str(path).encode()).hexdigest()[:12]
    return cfg.state_dir / "tripwire" / f"{Path(path).name}-{digest}"


def _private_dir(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _read(path: Path) -> bytes:
    """The file's bytes; a missing file has lost every line."""
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return b""


def complete(data: bytes) -> bytes:
    """Content up to the last newline: a write still in progress never counts."""
    if not data or data.endswith(b"\n"):
        return data
    cut = data.rfind(b"\n")
    return data[: cut + 1] if cut >= 0 else b""


def _lines(data: bytes) -> list[str]:
    return [
        line
        for line in data.decode("utf-8", "surrogateescape").split("\n")
        if line.strip()
    ]


def removed_count(good: bytes, current: bytes) -> int:
    missing = Counter(_lines(good)) - Counter(_lines(current))
    return sum(missing.values())


def new_lines(good: bytes, current: bytes, drop) -> tuple[list[str], list[str]]:
    """(kept, dropped): non-blank lines of `current` that are new against `good`."""
    left = Counter(_lines(good))
    kept, dropped = [], []
    for line in _lines(current):
        if left[line] > 0:
            left[line] -= 1
        elif any(p.search(line) for p in drop):
            dropped.append(line)
        else:
            kept.append(line)
    return kept, dropped


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


@contextlib.contextmanager
def _lock(path: Path, timeout: float = LOCK_TIMEOUT):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        "another tripwire pass held the lock too long"
                    ) from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def _trace(sd: Path, message: str) -> None:
    with open(sd / "trace.log", "a", encoding="utf-8") as fh:
        fh.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")


def _run_quietly(argv: list[str], timeout: float = 15) -> str:
    try:
        run = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return run.stdout + run.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return f"unavailable: {e}\n"


def _snapshot(sd: Path, folder: Path) -> None:
    """The process table and open files under the folder, as early as possible."""
    stamp = f"# taken {datetime.now().astimezone():%Y-%m-%d %H:%M:%S %Z}\n"
    (sd / "ps.txt").write_text(
        stamp + _run_quietly(["ps", "axo", "pid,ppid,lstart,etime,command"])
    )
    (sd / "lsof.txt").write_text(stamp + _run_quietly(["lsof", "+D", str(folder)]))


def _atomic_replace(path: Path, data: bytes) -> None:
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    tmp = path.with_name(
        f".{path.name}.guard-{os.getpid()}-{threading.get_ident()}.tmp"
    )
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)  # same folder, same volume: an atomic rename


def _evidence_dir(cfg: config.Config) -> Path:
    root = _private_dir(cfg.state_dir / "evidence")
    retention.prune(root)
    stamp = datetime.now()
    base = root / f"{stamp:%Y-%m-%d} - tripwire-{stamp:%H%M%S}"
    candidate, n = base, 2
    while candidate.exists():
        candidate = Path(f"{base}-{n}")
        n += 1
    return _private_dir(candidate)


def check_once(path: Path, cfg: config.Config, settle: float | None = None) -> str:
    """One pass over one append-only file. Returns what it did: initialised,
    nothing, ok, rotation, waiting, rebaselined, restored or gave-up."""
    path = Path(path)
    if not path.parent.is_dir():
        raise Refused(
            f"folder not found: {path.parent}; refusing to baseline on nothing"
        )
    settle = cfg.settle_seconds if settle is None else settle
    config.ensure_state_dir(cfg)
    sd = _private_dir(state_for(cfg, path))
    good_p, seen_p = sd / "last-good", sd / "rotation-seen"
    with _lock(sd / ".lock"):
        if (path.parent / ROTATION_FLAG).exists():
            seen_p.write_text("1")
            _trace(sd, "rotation in progress: no action")
            return "rotation"
        if seen_p.exists() and seen_p.read_text() == "1":
            if not path.exists():
                _trace(sd, "rotation finished but no file yet: waiting")
                return "waiting"
            _write_private(good_p, complete(_read(path)))
            seen_p.write_text("0")
            _trace(sd, "rotation finished: last-good re-baselined, no comparison made")
            return "rebaselined"
        if not good_p.exists():
            if not path.exists():
                _trace(sd, "no file yet: nothing to baseline")
                return "nothing"
            _write_private(good_p, complete(_read(path)))
            _trace(sd, "initialised last-good")
            return "initialised"

        good = good_p.read_bytes()

        def refresh(data: bytes) -> None:
            nonlocal good
            if data != good:
                _write_private(good_p, data)
                good = data

        for swap in range(3):
            snapped = False
            a = b = _read(path)
            for _ in range(30):
                a = _read(path)
                ac = complete(a)
                if removed_count(good, ac) == 0:
                    refresh(ac)
                elif not snapped:
                    _snapshot(sd, path.parent)
                    snapped = True
                time.sleep(settle)
                b = _read(path)
                if a == b:
                    break
            bc = complete(b)
            lost = removed_count(good, bc)
            if lost == 0:
                refresh(bc)
                return "ok"
            if not snapped:
                _snapshot(sd, path.parent)
            kept, dropped = new_lines(good, bc, cfg.drop_line_patterns)
            repair = good + "".join(line + "\n" for line in kept).encode(
                "utf-8", "surrogateescape"
            )
            if _read(path) != b:
                _trace(
                    sd,
                    f"file changed again before the repair: re-evaluating (swap {swap + 1})",
                )
                continue

            e = _evidence_dir(cfg)
            name = path.name
            _write_private(e / f"{name}.bad", b)
            _write_private(e / f"{name}.last-good", good)
            diff = difflib.unified_diff(
                good.decode("utf-8", "surrogateescape").splitlines(keepends=True),
                b.decode("utf-8", "surrogateescape").splitlines(keepends=True),
                f"{name}.last-good",
                f"{name}.bad",
            )
            _write_private(
                e / "diff.patch", "".join(diff).encode("utf-8", "surrogateescape")
            )
            for extra in ("ps.txt", "lsof.txt"):
                if (sd / extra).exists():
                    _write_private(e / extra, (sd / extra).read_bytes())
            _write_private(
                e / "dropped.txt",
                "".join(d + "\n" for d in dropped).encode("utf-8", "surrogateescape"),
            )
            now = datetime.now().astimezone()
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except FileNotFoundError:
                mtime = "file missing"
            _write_private(
                e / "time.txt",
                (
                    f"detected: {now:%Y-%m-%d %H:%M:%S %Z}\nepoch: {int(now.timestamp())}\n"
                    f"file mtime: {mtime}\nlines lost: {lost} · new lines kept: {len(kept)} · dropped: {len(dropped)}\n"
                ).encode(),
            )

            _atomic_replace(path, repair)
            after = complete(_read(path))
            if removed_count(good, after) != 0:
                _trace(sd, f"REPAIR DID NOT HOLD: evidence {e}")
            _write_private(good_p, after)
            good = after
            line = (
                f"{now:%Y-%m-%d %H:%M:%S} · {name} lost {lost} line{'s' if lost != 1 else ''}, restored"
                f" (kept {len(kept)} new, dropped {len(dropped)}) · evidence: {e}"
            )
            _trace(sd, line)
            alerts.send(line, cfg)
            return "restored"
        _trace(
            sd,
            "gave up after 3 compare-and-swap retries: the file keeps changing; no repair",
        )
        return "gave-up"


def watched_files(cfg: config.Config) -> list[Path]:
    """Every append-only file: file roots as they are, folder roots expanded."""
    import glob as _glob

    out = []
    for root in cfg.roots.append_only:
        for match in _glob.glob(root) or [root]:
            p = Path(match)
            if p.is_dir():
                out.extend(
                    sorted(
                        c
                        for c in p.iterdir()
                        if c.is_file() and not c.name.startswith(".")
                    )
                )
            else:
                out.append(p)
    return out


def _signature(path: Path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except FileNotFoundError:
        return None


def watch(
    cfg: config.Config, stop: threading.Event | None = None, poll: float | None = None
) -> None:
    """Poll every append-only file and run a pass when one changes. One watcher
    at a time; a heartbeat file says it's alive."""
    poll = cfg.poll_seconds if poll is None else poll
    stop = stop or threading.Event()
    root = _private_dir(cfg.state_dir / "tripwire")
    fd = os.open(root / "watch.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refused("another tripwire watcher is already running") from None
    last: dict = {}
    try:
        while not stop.is_set():
            for path in watched_files(cfg):
                sig = _signature(path)
                if last.get(path, "unseen") != sig:
                    try:
                        check_once(path, cfg)
                    except Refused as e:
                        print(f"guard tripwire: {e}", file=sys.stderr)
                    last[path] = _signature(path)
            (root / "heartbeat").write_text(f"{time.time():.0f} {os.getpid()}\n")
            stop.wait(poll)
    finally:
        os.close(fd)


def main(action: str) -> int:
    cfg = config.load()
    if action == "check":
        for path in watched_files(cfg):
            try:
                print(f"{path.name}: {check_once(path, cfg)}")
            except Refused as e:
                print(f"{path.name}: refused: {e}", file=sys.stderr)
                return 1
        return 0
    try:
        watch(cfg)
    except KeyboardInterrupt:
        return 0
    except Refused as e:
        print(f"guard tripwire: {e}", file=sys.stderr)
        return 1
    return 0
