"""
One gate per machine.

Two copies of Probolos -- the service and one started by hand -- used to run
side by side without noticing each other. Both asked about every device and the
first answer won. Worse, the second copy found the gate already closed, took
that for a crashed run ("leftover ... will restore to 1"), and REOPENED it when
it exited, under a service that went on believing it was guarding the ports.

So a gate takes this lock before touching anything, and a second one refuses to
start. The lock is a root-only file in the root-owned state directory. Not the
ledger directory: under --privsep that belongs to `nobody`, and a lock that any
process running as `nobody` can take is a lock that keeps the real gate from
ever starting.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

LOCK_PATH = Path("/var/lib/probolos/instance.lock")


class AlreadyRunning(Exception):
    """Another gate holds the lock."""


def acquire(path=None) -> int:
    """
    Take the lock for the life of this process. Returns the descriptor, which
    the caller keeps open; closing it (or exiting) releases the lock.

    Raises AlreadyRunning if another gate holds it, and OSError if the lock
    file cannot be opened at all.
    """
    from .securefs import open_directory
    path = Path(path or LOCK_PATH)
    directory_fd = open_directory(path.parent, create=True)
    try:
        # Read-only is enough for flock, and it means an inherited descriptor
        # (the --privsep analyzer is forked from this process) cannot write.
        fd = os.open(path.name,
                     os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise AlreadyRunning(str(path)) from None
    except BaseException:
        os.close(fd)
        raise
    return fd


def running(path=None) -> bool:
    """True if a gate holds the lock right now. Never creates anything."""
    path = Path(path or LOCK_PATH)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
