"""
Lifecycle management for the global authorization gate.

THE FAILURE MODE THIS FILE EXISTS TO PREVENT
--------------------------------------------
`authorized_default = 0` is global per root hub and it *persists*. If Probolos
sets it and then dies -- crash, kill -9, closed laptop lid, unhandled traceback
-- every USB device plugged in afterwards stays dead until someone restores the
flag by hand. On a machine whose keyboard is USB, that is a lockout.

So restoration is not a shutdown routine. It is wired into four independent
paths, on the assumption that any single one of them can fail:

  1. the context manager's __exit__      (normal and exception exits)
  2. signal handlers for TERM/INT/HUP    (kill, Ctrl-C, terminal closed)
  3. atexit                              (interpreter shutdown by any route)
  4. the caller's own recovery message   (printed if all else fails)

Only SIGKILL and a kernel panic can defeat this, and for those the README
documents the one-line manual recovery.

WRITES FIRST, WORDS AFTER
-------------------------
Restoring must not depend on being able to say so. Every hub is written
before a single line is logged, and no line that fails to print can stop
anything: see AuthorizationGate.restore.
"""

from __future__ import annotations

import atexit
import os
import signal
import threading
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import deferred_bind, sysfs


def _complain(text: str) -> None:
    """
    The last-resort message on stderr. Never raises.

    It is printed when a hub could NOT be put back, which is exactly when the
    remaining hubs still have to be tried: a stderr that is gone (the
    terminal was closed) must not be what stops them.
    """
    try:
        print(text, file=sys.stderr)
    except Exception:   # noqa: BLE001, S110 -- nowhere left to say it
        pass


class AuthorizationGate:
    """Context manager that closes the USB gate and always reopens it."""

    def __init__(self, dry_run: bool = False, log=print):
        self.dry_run = dry_run
        self.log = log
        self._original: Dict[Path, int] = {}
        self._armed = False
        # Only the process that closed the gate may reopen it. A forked child
        # -- the storage reader in inspect_safely -- inherits this object
        # armed, the signal handlers that call restore(), and under --privsep
        # the socket to the root gate. When the parent ended a stalled read
        # with SIGTERM, the child ran the handler and wrote
        # authorized_default=1 to every hub, while the parent went on
        # believing the gate was closed: a fail-open a hostile medium could
        # time.
        self._owner_pid = os.getpid()
        self._previous_handlers: Dict[int, object] = {}
        # restore() has three callers that do not coordinate: the watchdog
        # thread (on_stall -> opened.restore()), the main thread on the way out
        # of the `with` block, and atexit. Two of them can run at once -- the
        # watchdog firing while the daemon is already shutting down is the
        # normal way a stall ends -- and both rebuild self._original from what
        # they individually managed to restore. Without the lock the second
        # assignment overwrites the first, which can re-list a hub that was
        # already put back and drop one that was not.
        self._lock = threading.RLock()

    # ---------- lifecycle ----------

    def __enter__(self) -> "AuthorizationGate":
        hubs = sysfs.list_root_hubs()
        if not hubs:
            raise RuntimeError("no USB root hubs found under /sys/bus/usb/devices")

        self._armed = True
        self._owner_pid = os.getpid()
        self._install_handlers()
        atexit.register(self.restore)
        try:
            for hub in hubs:
                current = sysfs.get_authorized_default(hub)
                if current is None:
                    self.log(f"  ! {hub.name}: no authorized_default, skipping")
                    continue
                # Remember the original value so it can be put back exactly. Some
                # kernels use 2 ("authorize internal ports only"), and blindly
                # restoring 1 would silently weaken the machine's configuration.
                #
                # EXCEPT when we find it already at 0. A hub sitting at 0 before we
                # touched anything is not a configuration anyone chose -- it is the
                # residue of a previous run that died without restoring. Recording
                # 0 as "the original" and faithfully putting it back on exit would
                # make the lockout permanent, with each run politely preserving the
                # damage done by the last. So 0 is treated as "no valid previous
                # state" and 1 is restored instead, which is the only value that
                # leaves the machine usable.
                if current == 0:
                    self.log(f"  ! {hub.name}: was already closed "
                             f"(authorized_default=0) — this is leftover from a "
                             f"run that did not shut down cleanly; will restore "
                             f"to 1, not 0")
                    self._original[hub] = 1
                else:
                    self._original[hub] = current
                if not self.dry_run:
                    sysfs.set_authorized_default(hub, 0)
                state = "would close" if self.dry_run else "closed"
                self.log(f"  - {hub.name}: {state} (was authorized_default={current})")
        except BaseException:
            self.restore()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.restore()
        return False  # never swallow exceptions

    def restore(self, announce: Optional[str] = None) -> None:
        """
        Idempotent, and safe from more than one thread at a time.

        WRITES FIRST, WORDS AFTER (the lockout this fixes)
        --------------------------------------------------
        Each hub used to be written and then logged, inside one `try`, and
        the signal handler logged before it restored anything. So restoring
        depended on being able to print:

          * `sudo python -m probolos` in a terminal, and the terminal is
            closed (or the SSH session drops). SIGHUP arrives, and stdout and
            stderr are a terminal that is gone: every write to them fails
            with EIO. The handler's own "[signal SIGHUP]" line raised before
            restore() was reached. On the way out the first hub was written,
            its "restored" line raised, that was taken for a failed WRITE,
            and the "FAILED to restore" message on stderr raised out of the
            loop. atexit did the same again. Every root hub but the first
            stayed at authorized_default=0 with nothing left running: no new
            USB device on those ports worked until someone ran --release --
            the lockout this file exists to prevent, from closing a window.
          * the same with output going to a pipe whose reader has gone
            (EPIPE), and, as a hang instead of an error, with a pipe nobody
            reads any more: the line printed before the restore never
            returned.

        Now every hub is written before anything is said, what is said can
        fail without consequence, and it is said after the lock is released,
        so a line that never returns holds up no other caller.

        `announce` is one line for the caller to have said first, after the
        writes like everything else: the signal's name, the watchdog's
        reason.
        """
        with self._lock:
            lines, failures = self._restore_locked()
        if announce:
            self._say(announce)
        for line in lines:
            self._say(line)
        for text in failures:
            _complain(text)

    def _say(self, message: str) -> None:
        """One log line that cannot stop a restore: see restore()."""
        try:
            self.log(message)
        except Exception:   # noqa: BLE001, S110 -- a log that is gone
            pass

    def _restore_locked(self):
        """
        Put every hub back; return (lines to log, failures to complain of).

        Nothing is printed here. See restore().
        """
        lines: List[str] = []
        failures: List[str] = []
        if os.getpid() != self._owner_pid:
            return lines, failures
        # The bus-wide driver switch first, armed or not. --close-race-window
        # holds drivers_autoprobe at 0 around one authorize write, and the
        # watchdog and the panic file reach this from another thread while
        # the main thread may be stuck in exactly that write. Reopening the
        # hubs with autoprobe still 0 let every new device enumerate with no
        # driver -- the rescue keyboard the panic file was used for included.
        # A no-op unless deferred_bind is holding it.
        deferred_bind.emergency_restore()
        if not self._armed:
            return lines, failures
        remaining = {}
        for hub, value in list(self._original.items()):
            try:
                if not self.dry_run:
                    sysfs.set_authorized_default(hub, value)
            except Exception as exc:   # noqa: BLE001 -- the next hub is still tried
                remaining[hub] = value
                # Last resort: tell the human exactly how to fix it themselves.
                failures.append(
                    f"\n!! FAILED to restore {hub.name}: {exc}\n"
                    f"!! Run manually as root:\n"
                    f"!!   echo {value} > {hub}/authorized_default\n")
            else:
                lines.append(
                    f"  - {hub.name}: restored authorized_default={value}")
        self._original = remaining
        self._armed = bool(remaining)
        self._remove_handlers()
        return lines, failures

    # ---------- signal plumbing ----------

    def _install_handlers(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                self._previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass  # e.g. not the main thread; other paths still cover us

    def _remove_handlers(self) -> None:
        for sig, handler in self._previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        self._previous_handlers.clear()

    def _on_signal(self, signum, _frame):
        if os.getpid() != self._owner_pid:
            # A forked child that kept the handler: end it, reopen nothing.
            os._exit(128 + signum)
        # The line is said by restore(), after the hubs are written. Printed
        # here first, it was the first thing to fail when the signal was a
        # hangup: the terminal it goes to is the thing that just went away.
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)
        self.restore(announce=f"\n[signal {name}] shutting down")
        # Re-raise as a normal exit so `finally` blocks upstream still run.
        raise SystemExit(0)


def unauthorized_devices() -> List[sysfs.UsbDevice]:
    """
    Devices currently sitting blocked.

    Useful for diagnostics: if Probolos previously died hard, this shows what
    got stranded, and the CLI can offer to release them.
    """
    return [d for d in sysfs.list_devices()
            if d.authorized == 0 and not d.is_root_hub]
