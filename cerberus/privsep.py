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


def start(analyzer_main, drop_to: str = "nobody", log=print) -> int:
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
    log(f"[privsep] gate running as root (pid {os.getpid()}), "
        f"analyzer as {drop_to} (pid {pid})")
    try:
        gate_server.run_gate(parent_sock, log=log)
    finally:
        parent_sock.close()

    _pid, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)
