"""Descriptor-relative filesystem operations for privileged startup code."""

import os
import stat
from pathlib import Path


def open_directory(path, create=False, secure=False):
    """Open a directory without following a symlink in ANY component.

    Keep the parent descriptor until the child is open. A rename or symlink
    replacement cannot redirect a later chmod/chown to another directory.
    Callers decide which dedicated directories may be created or modified.
    """
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            if secure:
                st = os.fstat(fd)
                sticky_root = st.st_uid == 0 and st.st_mode & stat.S_ISVTX
                if (st.st_uid not in (0, os.geteuid())
                        or (st.st_mode & 0o022 and not sticky_root)):
                    raise OSError("untrusted or writable ancestor directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_json_file(path, trusted=False):
    """Bound state input, reject FIFOs, and verify the inode actually read."""
    import json
    path = Path(path)
    directory_fd = open_directory(path.parent, secure=trusted)
    fd = None
    try:
        fd = open_regular_at(directory_fd, path.name)
        st = os.fstat(fd)
        if trusted and (st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022):
            raise OSError("untrusted state file owner or permissions")
        with os.fdopen(fd, "rb") as fh:
            fd = None
            data = fh.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("state file exceeds the 8 MiB input limit")
        return json.loads(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)


def open_regular_at(directory_fd, name):
    """Refuse symlinks, special files and hard links before changing metadata."""
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW |
                 os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError("expected a regular file with exactly one link")
        return fd
    except BaseException:
        os.close(fd)
        raise


def append_json_line(path, payload):
    """Append an audit record without following links or opening a FIFO."""
    import json
    path = Path(path)
    directory_fd = open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                     os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid()):
            raise OSError("unsafe audit-log file")
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fd = None
            fh.write(json.dumps(payload) + "\n")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)
