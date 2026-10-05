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
nothing. A dedicated 'probolos' user is better for production and is what the
systemd unit will use; this launcher accepts either.
"""

from __future__ import annotations

import os
import pwd
import socket
import sys

from . import gate_server


class PrivsepError(Exception):
    pass


def resolve_user(name: str) -> tuple:
    """Return (uid, gid) for a username, or raise if it does not exist."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise PrivsepError(f"user {name!r} does not exist") from None
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
    # The supplementary groups were dropped FIRST and never checked, which is
    # the one step of the three this module's own docstring calls "a classic
    # source of silent security holes" and then did not verify. A surviving
    # `input` or `disk` membership is precisely what the privilege split
    # exists to remove: it would let the analyzer open every evdev node and
    # every raw disk on the machine directly, without ever asking the gate --
    # so the gate's entire scoping rule would be bypassed while every uid and
    # gid check above still passed. Some systems leave a group behind
    # regardless of setgroups() (a container with a restricted user namespace
    # is the realistic case), so the assertion has to be made rather than
    # assumed.
    remaining = set(os.getgroups()) - {gid}
    if remaining:
        raise PrivsepError(
            f"supplementary groups survived the drop: {sorted(remaining)} -- "
            f"refusing to continue, because the analyzer would keep direct "
            f"access the gate is supposed to mediate")
    try:
        os.setuid(0)
        raise PrivsepError("regained root after drop -- refusing to continue")
    except PermissionError:
        pass  # exactly what we want: root is unreachable now


# Directories the launcher is willing to hand to the analyzer.
#
# prepare_state_dir takes a path from --ledger and chowns its PARENT to the
# unprivileged uid, then chmods it 0700. With no bound on which parent,
# `sudo probolos --ledger /etc/x.json` makes /etc owned by nobody and mode
# 0700 -- which takes sudo, ssh and PAM with it, on a running system,
# irreversibly. That needs no attacker: a typo in a flag is enough.
#
# So the launcher refuses instead of chowning. The cost of refusing is that the
# analyzer keeps no history; the cost of not refusing is the machine.
STATE_ROOTS = ("/var/lib/probolos/state", "/run/probolos/state")


def _within_allowed_root(directory: str) -> bool:
    # Lexical scope plus open_directory's component-by-component O_NOFOLLOW.
    # Resolving the allowlisted root itself would let a symlink redefine it.
    directory = os.path.abspath(directory)
    return any(directory == os.path.abspath(root)
               or directory.startswith(os.path.abspath(root) + os.sep)
               for root in STATE_ROOTS)


def prepare_trust_readable(path, log=print) -> None:
    """Make only the pinned, regular trust file readable; never follow links."""
    from pathlib import Path
    from .securefs import open_directory, open_regular_at
    path = Path(path)
    directory_fd = fd = None
    try:
        directory_fd = open_directory(path.parent)
        fd = open_regular_at(directory_fd, path.name)
        if os.fstat(fd).st_uid != os.geteuid():
            raise OSError("trust file is not owned by the preparing account")
        os.fchmod(fd, 0o644)
    except FileNotFoundError:
        return
    except OSError as exc:
        log(f"[privsep] REFUSING to change trust permissions: {exc}")
    finally:
        if fd is not None:
            os.close(fd)
        if directory_fd is not None:
            os.close(directory_fd)


def prepare_state_dir(path, uid: int, gid: int, log=print) -> None:
    """Hand over a dedicated state directory using pinned descriptors only."""
    from pathlib import Path
    from .securefs import open_directory, open_regular_at
    path = Path(os.path.abspath(path))
    if not _within_allowed_root(str(path.parent)):
        log(f"[privsep] REFUSING to hand {path.parent} to uid {uid}: "
            f"state must be under {', '.join(STATE_ROOTS)}")
        return
    directory_fd = fd = None
    try:
        directory_fd = open_directory(path.parent, create=True)
        try:
            os.stat("trusted.json", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OSError("directory holds a trust store")
        try:
            fd = open_regular_at(directory_fd, path.name)
        except FileNotFoundError:
            pass
        # Validate the file before making ANY ownership changes. fchown and
        # fchmod act on what was opened, even if its name is swapped meanwhile.
        if fd is not None:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o600)
        os.fchown(directory_fd, uid, gid)
        os.fchmod(directory_fd, 0o700)
        log(f"[privsep] state dir {path.parent} handed to uid {uid}")
    except OSError as exc:
        log(f"[privsep] REFUSING unsafe state preparation for {path}: {exc}")
    finally:
        if fd is not None:
            os.close(fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _run_analyzer(analyzer_main, client) -> int:
    """
    Run the analyzer and turn every way it can end into an exit status.

    The caller is a forked child and must leave through os._exit(), never by
    unwinding: an exception that escapes would carry on through the PARENT's
    stack in this process and run the atexit handlers it inherited. SystemExit
    is caught for that reason too -- serve() raises it (a leftover panic file,
    a missing pyudev) and so does the gate's signal handler -- and it is not
    an Exception, so the handler below never saw it.
    """
    try:
        rc = analyzer_main(client)
    except KeyboardInterrupt:
        return 0
    except SystemExit as exc:
        if exc.code is None or isinstance(exc.code, int):
            return exc.code or 0
        print(exc.code, file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[analyzer] crashed: {exc}", file=sys.stderr)
        return 1
    return rc or 0


def start(analyzer_main, drop_to: str = "nobody", log=print,
          state_paths=(), watch_media: bool = False, trust_path=None,
          close_in_child=()) -> int:
    """
    Fork the gate and the analyzer.

    `analyzer_main(gate_client)` is the unprivileged entry point; it receives a
    connected GateClient and runs the whole existing daemon on top of it. The
    parent never returns from here until the analyzer exits: it serves the gate
    and then propagates the child's exit status.

    `watch_media` is the operator's --watch-media, handed to the gate from
    the root side. The analyzer cannot turn it on: it widens what the gate
    will open, so it must come from the command line, not the socket.

    `trust_path` is where the gate writes "always" (None under --no-trust).
    Root side for the same reason: it is the one file the gate writes, so
    which file that is must not be something the analyzer gets to say.

    `close_in_child` are descriptors the root process holds that the analyzer
    must not inherit: the one-gate-per-machine lock (instance.py). O_CLOEXEC
    acts at exec(), not at fork(), so the analyzer held it too and could
    flock(LOCK_UN) it, letting a second gate start beside this one.
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

    # Ignore terminal signals in the gate. They are delivered to the whole
    # process group, so without this the gate would tear down its socket at the
    # same instant the analyzer is trying to send its final restore requests
    # through it -- producing the "Broken pipe / FAILED to restore" cascade.
    # The gate instead keeps serving until the analyzer finishes its cleanup
    # and closes the connection, which is what ends serve_forever() cleanly.
    #
    # The analyzer is in a session of its own now (see above), so the
    # terminal's Ctrl-C, Ctrl-\ and hangup no longer reach it directly. The
    # gate passes those on instead: the analyzer still sees exactly the signal
    # it used to, and its exit is what ends the gate. SIGTERM is still only
    # ignored -- systemd delivers it to every process in the unit, and
    # forwarding it would deliver it twice.
    #
    # Ctrl-Z is ignored. Off the controlling tty the analyzer is also outside
    # job control, so suspending the gate alone would hand the terminal back
    # to the shell while the analyzer went on reading it.
    #
    # Installed BEFORE fork(). Installed after it, a Ctrl-C landing in between
    # found the gate on Python's default handler: KeyboardInterrupt in the root
    # process, and an analyzer left running with nobody behind its socket.
    # Until fork() returns the analyzer's pid there is nobody to forward to, so
    # a signal in that instant is dropped rather than fatal; the child puts back
    # the dispositions it inherited before it does anything else.
    import signal
    analyzer: list = []

    def _forward(signum, _frame):
        if not analyzer:
            return
        try:
            os.kill(analyzer[0], signum)
        except OSError:
            pass

    inherited: dict = {}
    for _sig, _handler in ((signal.SIGINT, _forward),
                           (signal.SIGHUP, _forward),
                           (signal.SIGQUIT, _forward),
                           (signal.SIGTERM, signal.SIG_IGN),
                           (signal.SIGTSTP, signal.SIG_IGN)):
        try:
            inherited[_sig] = signal.signal(_sig, _handler)
        except (ValueError, OSError):
            pass

    pid = os.fork()
    if pid == 0:
        # ---- child: becomes the unprivileged analyzer ----
        for _sig, _handler in inherited.items():
            try:
                signal.signal(_sig, _handler)
            except (TypeError, ValueError, OSError):
                pass
        parent_sock.close()
        for fd in close_in_child:
            try:
                os.close(fd)
            except OSError:
                pass
        # A session of its own, so the terminal is no longer its CONTROLLING
        # terminal. The analyzer keeps the inherited stdin/stdout -- the
        # terminal prompt needs them -- and on its controlling tty any
        # process may ioctl(TIOCSTI) bytes into the input queue as though
        # they were typed. Those bytes are read by whatever reads the
        # terminal next: the shell that started `sudo probolos`, as root or
        # with a cached sudo ticket, the moment the tool exits. An analyzer
        # compromised by a hostile device would type its own root command.
        # Off the controlling tty, TIOCSTI fails with EPERM for an account
        # without CAP_SYS_ADMIN; reading and writing the terminal still work.
        try:
            os.setsid()
        except OSError as exc:
            print(f"[privsep] child could not leave the terminal's session: "
                  f"{exc}", file=sys.stderr)
            os._exit(70)
        try:
            drop_privileges(uid, gid)
        except PrivsepError as exc:
            print(f"[privsep] child could not drop privilege: {exc}",
                  file=sys.stderr)
            os._exit(70)
        from .gate_client import GateClient
        try:
            rc = _run_analyzer(analyzer_main, GateClient(child_sock))
        finally:
            child_sock.close()
        os._exit(rc)

    # ---- parent: stays root, runs the gate ----
    analyzer.append(pid)
    child_sock.close()

    log(f"[privsep] gate running as root (pid {os.getpid()}), "
        f"analyzer as {drop_to} (pid {pid})")
    # The gate is not allowed to take the reap with it. os.waitpid() used to
    # sit AFTER this block with nothing catching an exception from the gate,
    # so anything that escaped run_gate() -- EPIPE from a reply to an analyzer
    # that had just exited was the realistic one -- skipped the wait entirely:
    # the root process died with a traceback, the analyzer child was orphaned,
    # and the exit status nobody collected was reported to the operator as a
    # crash rather than as the ordinary shutdown it was.
    gate_error = None
    try:
        gate_server.run_gate(parent_sock, log=log, watch_media=watch_media,
                             trust_path=trust_path)
    except Exception as exc:   # noqa: BLE001 -- reap first, re-raise never
        gate_error = exc
    finally:
        parent_sock.close()

    if gate_error is not None:
        log(f"[privsep] the gate stopped with an error: {gate_error!r}")

    try:
        _pid, status = os.waitpid(pid, 0)
    except ChildProcessError:
        # Already reaped (a SIGCHLD handler installed elsewhere, or the child
        # was inherited away). Nothing left to wait for.
        return 1 if gate_error is not None else 0
    code = os.waitstatus_to_exitcode(status)
    return code if code else (1 if gate_error is not None else 0)
