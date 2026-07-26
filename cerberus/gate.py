"""
Lifecycle management for the global authorization gate.

THE FAILURE MODE THIS FILE EXISTS TO PREVENT
--------------------------------------------
`authorized_default = 0` is global per root hub and it *persists*. If Cerberus
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
"""

from __future__ import annotations

import atexit
import signal
import sys
from pathlib import Path
from typing import Dict, List

from . import sysfs


class AuthorizationGate:
    """Context manager that closes the USB gate and always reopens it."""

    def __init__(self, dry_run: bool = False, log=print):
        self.dry_run = dry_run
        self.log = log
        self._original: Dict[Path, int] = {}
        self._armed = False
        self._previous_handlers: Dict[int, object] = {}

    # ---------- lifecycle ----------

    def __enter__(self) -> "AuthorizationGate":
        hubs = sysfs.list_root_hubs()
        if not hubs:
            raise RuntimeError("no USB root hubs found under /sys/bus/usb/devices")

        for hub in hubs:
            current = sysfs.get_authorized_default(hub)
            if current is None:
                self.log(f"  ! {hub.name}: no authorized_default, skipping")
                continue
            # Remember the exact original value. Some kernels use 2
            # ("authorize internal ports only"); blindly restoring 1 would
            # silently weaken the machine's configuration.
            self._original[hub] = current
            if not self.dry_run:
                sysfs.set_authorized_default(hub, 0)
            state = "would close" if self.dry_run else "closed"
            self.log(f"  - {hub.name}: {state} (was authorized_default={current})")

        self._armed = True
        self._install_handlers()
        atexit.register(self.restore)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.restore()
        return False  # never swallow exceptions

    def restore(self) -> None:
        """Idempotent: safe to call from every path, and it will be."""
        if not self._armed:
            return
        self._armed = False
        for hub, value in self._original.items():
            try:
                if not self.dry_run:
                    sysfs.set_authorized_default(hub, value)
                self.log(f"  - {hub.name}: restored authorized_default={value}")
            except OSError as exc:
                # Last resort: tell the human exactly how to fix it themselves.
                print(
                    f"\n!! FAILED to restore {hub.name}: {exc}\n"
                    f"!! Run manually as root:\n"
                    f"!!   echo {value} > {hub}/authorized_default\n",
                    file=sys.stderr,
                )
        self._remove_handlers()

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
        self.log(f"\n[signal {signal.Signals(signum).name}] shutting down")
        self.restore()
        # Re-raise as a normal exit so `finally` blocks upstream still run.
        raise SystemExit(0)


def unauthorized_devices() -> List[sysfs.UsbDevice]:
    """
    Devices currently sitting blocked.

    Useful for diagnostics: if Cerberus previously died hard, this shows what
    got stranded, and the CLI can offer to release them.
    """
    return [d for d in sysfs.list_devices()
            if d.authorized == 0 and not d.is_root_hub]
