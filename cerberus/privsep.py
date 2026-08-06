"""
Starting the two halves with the right privileges.

The shape, fork-now (systemd-later):

    root process
        |
        | socketpair(AF_UNIX, SOCK_SEQPACKET)
        |
        +-- fork -------------------------------+
        |                                       |
    PARENT stays root                       CHILD drops privilege
    runs the gate server                    runs the analyzer
    answers authorize / open_input          all rules, timing, ledger

SEQPACKET because it preserves message boundaries: every datagram is exactly
one protocol message, so the privileged side never has to parse a byte stream
to find where a request ends -- a parser it would be dangerous to get wrong.

DROPPING PRIVILEGE CORRECTLY
----------------------------
Order matters and is a classic source of silent security holes:

    setgroups([])  -> drop supplementary groups FIRST, or a lingering group
                      (e.g. 'input', 'disk') would survive the drop
    setgid(gid)    -> group before user; after setuid we may not be allowed
                      to change gid any more
    setuid(uid)    -> user last

After dropping, the code asserts it cannot regain root (setuid(0) must fail).
A privilege drop you did not verify is a privilege drop you cannot rely on.

The target user is 'nobody' by default -- present on every Linux system, owns
nothing. A dedicated 'cerberus' user is better for production and is what the
systemd unit will use; this launcher accepts either.
"""

from __future__ import annotations

import os
import pwd
import socket
import sys
from typing import Optional

from . import gate_server


class PrivsepError(Exception):
    pass


def resolve_user(name: str) -> tuple:
    """Return (uid, gid) for a username, or raise if it does not exist."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise PrivsepError(f"user {name!r} does not exist")
    return entry.pw_uid, entry.pw_gid


def drop_privileges(uid: int, gid: int) -> None:
    """
    Irreversibly drop from root to (uid, gid), then prove it took.

    Raises PrivsepError if anything about the drop is not exactly as intended,
    because continuing as root-that-thinks-it-is-not is worse than stopping.
    """
    if os.getuid() != 0:
        # Not root to begin with (e.g. running under an already-unprivileged
        # test). Nothing to drop; do not pretend otherwise.
        return

    os.setgroups([])           # supplementary groups first
    os.setgid(gid)             # then group
    os.setuid(uid)             # then user, last of all

    # Verify. If any of these is wrong, we must not proceed.
    if os.getuid() != uid or os.geteuid() != uid:
        raise PrivsepError("uid did not drop as expected")
    if os.getgid() != gid or os.getegid() != gid:
        raise PrivsepError("gid did not drop as expected")
    try:
        os.setuid(0)
        raise PrivsepError("regained root after drop -- refusing to continue")
    except PermissionError:
        pass  # exactly what we want: root is unreachable now


# Directories the launcher is willing to hand to the analyzer.
#
# prepare_state_dir takes a path from --ledger and chowns its PARENT to the
# unprivileged uid, then chmods it 0700. With no bound on which parent,
# `sudo cerberus --ledger /etc/x.json` makes /etc owned by nobody and mode
# 0700 -- which takes sudo, ssh and PAM with it, on a running system,
# irreversibly. That needs no attacker: a typo in a flag is enough.
#
# So the launcher refuses instead of chowning. The cost of refusing is that the
# analyzer keeps no history; the cost of not refusing is the machine.
STATE_ROOTS = ("/var/lib/cerberus", "/run/cerberus")


def _within_allowed_root(directory: str) -> bool:
    """
    True if `directory` is one of STATE_ROOTS or lies beneath one.

    realpath first, so that --ledger /var/lib/cerberus/../../etc/x.json is
    judged as /etc rather than as something under /var/lib/cerberus. The
    separator is appended before the prefix comparison so that a sibling named
    /var/lib/cerberus-evil does not match a root it merely starts with.
    """
    resolved = os.path.realpath(directory)
    for root in STATE_ROOTS:
        root = os.path.realpath(root)
        if resolved == root or resolved.startswith(root + os.sep):
            return True
    return False


def prepare_trust_readable(path, log=print) -> None:
    """
    Let the analyzer READ the trust store without being able to write it.

    The trust store stays root-owned in a root-owned directory (see
    ledger.default_path for why that separation exists). But the analyzer still
    has to consult it to know whether a device was remembered, and it runs as
    an unprivileged account -- so the file itself is made world-readable while
    its directory stays root-only-writable.

    That trade is deliberate and worth stating: the contents are device
    identities and labels, not secrets, and anyone who can read /var/lib can
    already see which devices exist. What must not leak is WRITE access, and
    that is what the directory ownership protects.
    """
    import os as _os
    target = str(path)
    if not _os.path.exists(target):
        return
    try:
        _os.chmod(target, 0o644)
    except OSError as exc:
        log(f"[privsep] could not make {target} readable by the analyzer: "
            f"{exc}\n[privsep] remembered devices will be asked about again.")


def prepare_state_dir(path, uid: int, gid: int, log=print) -> None:
    """
    Make a state directory writable by the analyzer, before privilege drops.

    The analyzer runs as an unprivileged user and cannot create or write
    /var/lib/cerberus, which is root-owned. Rather than routing ledger writes
    through the privileged gate -- which would mean putting file I/O and a
    serialisation format inside the trusted process, exactly what the split
    exists to avoid -- the launcher hands ownership of one directory to the
    analyzer while it still can.

    REFUSES in two cases, both before any side effect:

      * a directory outside STATE_ROOTS. Chowning an arbitrary parent to an
        unprivileged account is a one-typo way to destroy a running system.
      * a directory that holds a trust store. Whoever can write a directory
        can unlink and replace any file in it regardless of that file's own
        owner, so handing over a directory containing trusted.json would
        silently hand over trust itself -- the exact escalation this split
        exists to prevent.
    """
    import os as _os
    directory = _os.path.dirname(_os.path.abspath(str(path)))

    # Checked BEFORE anything is created or chowned. Both guards must run
    # before the first side effect: refusing after makedirs would already have
    # left a directory behind in a place that was never allowed.
    if not _within_allowed_root(directory):
        log(f"[privsep] REFUSING to hand {directory} to uid {uid}: state "
            f"files must live under one of {', '.join(STATE_ROOTS)}.\n"
            f"[privsep] chowning it would give an unprivileged account "
            f"ownership of a directory the system depends on. Continuing "
            f"without device history.")
        return

    if _os.path.exists(_os.path.join(directory, "trusted.json")):
        log(f"[privsep] REFUSING to hand {directory} to uid {uid}: it holds a "
            f"trust store, and directory write access would allow replacing "
            f"it. The ledger belongs in its own subdirectory.")
        return
    try:
        _os.makedirs(directory, exist_ok=True)
        _os.chown(directory, uid, gid)
        # The directory must also be traversable and writable by the owner;
        # a previous root-only run may have left tighter bits.
        _os.chmod(directory, 0o700)
        target = str(path)
        if _os.path.exists(target):
            _os.chown(target, uid, gid)
            _os.chmod(target, 0o600)
        # Stale temp files from an interrupted save would be root-owned and
        # would block the atomic rename the ledger relies on.
        tmp = _os.path.splitext(target)[0] + ".tmp"
        if _os.path.exists(tmp):
            _os.chown(tmp, uid, gid)
        log(f"[privsep] state dir {directory} handed to uid {uid}")
    except OSError as exc:
        log(f"[privsep] could not prepare {directory}: {exc}\n"
            f"[privsep] the analyzer will not be able to keep device history. "
            f"Fix with: sudo chown -R {uid}:{gid} {directory}")


def start(analyzer_main, drop_to: str = "nobody", log=print,
          state_paths=()) -> int:
    """
    Fork the gate and the analyzer.

    `analyzer_main(gate_client)` is the unprivileged entry point; it receives a
    connected GateClient and runs the whole existing daemon on top of it. The
    parent never returns from here until the analyzer exits: it serves the gate
    and then propagates the child's exit status.
    """
    if os.getuid() != 0:
        raise PrivsepError(
            "privilege separation needs to start as root (it drops privilege "
            "in the child). Try: sudo ...")

    uid, gid = resolve_user(drop_to)

    # Hand over any files the analyzer will need to write, while still root.
    # Several state files usually share one directory; prepare it once.
    seen_dirs = set()
    for path in state_paths:
        if not path:
            continue
        directory = os.path.dirname(os.path.abspath(str(path)))
        quiet = directory in seen_dirs
        seen_dirs.add(directory)
        prepare_state_dir(path, uid, gid,
                          log=(lambda *_a: None) if quiet else log)

    parent_sock, child_sock = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET)

    pid = os.fork()
    if pid == 0:
        # ---- child: becomes the unprivileged analyzer ----
        parent_sock.close()
        try:
            drop_privileges(uid, gid)
        except PrivsepError as exc:
            print(f"[privsep] child could not drop privilege: {exc}",
                  file=sys.stderr)
            os._exit(70)
        from .gate_client import GateClient
        try:
            rc = analyzer_main(GateClient(child_sock))
        except KeyboardInterrupt:
            rc = 0
        except Exception as exc:  # noqa: BLE001
            print(f"[analyzer] crashed: {exc}", file=sys.stderr)
            rc = 1
        finally:
            child_sock.close()
        os._exit(rc or 0)

    # ---- parent: stays root, runs the gate ----
    child_sock.close()

    # Ignore terminal signals in the gate. They are delivered to the whole
    # process group, so without this the gate would tear down its socket at the
    # same instant the analyzer is trying to send its final restore requests
    # through it -- producing the "Broken pipe / FAILED to restore" cascade.
    # The gate instead keeps serving until the analyzer finishes its cleanup
    # and closes the connection, which is what ends serve_forever() cleanly.
    import signal
    for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(_sig, signal.SIG_IGN)
        except (ValueError, OSError):
            pass

    log(f"[privsep] gate running as root (pid {os.getpid()}), "
        f"analyzer as {drop_to} (pid {pid})")
    try:
        gate_server.run_gate(parent_sock, log=log)
    finally:
        parent_sock.close()

    _pid, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)
