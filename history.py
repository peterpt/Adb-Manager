"""Append-only history of every change ADB Manager makes on a phone.

One JSON object per line. Lines are only ever appended (never rewritten), each
write is flushed + fsync'd under an exclusive lock shared by every running copy
of the app, so a crash can at worst leave one half-written LAST line - which the
reader skips and counts instead of failing. The file is private (0600).

This is the record of what happened. It is NOT the undo data: restoring things
uses the app's own restore records, and unfinished operations are tracked by the
pending journal (see adb_manager), so trimming old history never loses an undo.
"""
import json
import os
import time

VERSION = 1
MAX_BYTES = 4 << 20             # then the file is rotated once to <name>.1
MAX_MSG = 500
OUTCOMES = ("verified", "done", "unverified", "refused", "failed", "unsupported", "changed", "skipped",
            "stopped", "not_applied", "uncertain", "restored", "already")


def _lock(fd):
    try:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)
    except ImportError:          # not Linux/macOS: appends are still atomic enough for one copy
        pass


def make_event(serial, what, pkg, outcome, msg="", user=None, target="", source="", now=None):
    if outcome not in OUTCOMES:
        outcome = "failed" if outcome in (None, False) else "done"
    return {"v": VERSION, "t": now or time.strftime("%Y-%m-%d %H:%M:%S"), "serial": str(serial or ""),
            "user": user if isinstance(user, int) else None, "pkg": str(pkg or "")[:255],
            "what": str(what or "")[:60], "target": str(target or "")[:255], "outcome": outcome,
            "msg": str(msg or "").replace("\n", " ")[:MAX_MSG], "source": str(source or "")[:30]}


def append(path, event):
    """Add one event. Returns True only if it's safely on disk.
    The exclusive lock is held on a separate, never-rotated '<file>.lock' for the whole
    check-rotate-append-fsync sequence, so every running copy of the app serialises on
    the same lock even while the history file itself is being rotated."""
    try:
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, mode=0o700, exist_ok=True)
        line = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        lfd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(lfd, 0o600)
            _lock(lfd)                                            # released when lfd is closed
            try:
                if os.path.getsize(path) + len(line) > MAX_BYTES:
                    os.replace(path, path + ".1")                 # keep one older file
            except OSError:
                pass                                              # no file yet / rotation best effort
            fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
                size = os.fstat(fd).st_size
                if size and os.pread(fd, 1, size - 1) != b"\n":
                    line = b"\n" + line                           # a crash left a cut-off line: never glue onto it
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(lfd)
        return True
    except (OSError, TypeError, ValueError):
        return False


def read(path, limit=2000, include_rotated=True):
    """(events newest first, number of unreadable lines). Never raises."""
    events, bad = [], 0
    for p in ([path + ".1"] if include_rotated else []) + [path]:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        for raw in data.split(b"\n"):
            if not raw.strip():
                continue
            try:
                ev = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                bad += 1                                     # e.g. a line cut by a crash
                continue
            if isinstance(ev, dict) and isinstance(ev.get("what"), str) and isinstance(ev.get("t"), str):
                events.append(ev)
            else:
                bad += 1
    events.reverse()
    return events[:limit], bad
