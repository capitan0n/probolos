"""
The guarantees that come before every feature.

A USB admission tool has one failure mode that disqualifies it from being
installed anywhere: leaving somebody without a keyboard. Everything else in
this project is a security feature; this file is a safety feature, and safety
outranks security when the two disagree.

Four independent layers, because one is a single point of failure:

  1. PROTECTED DEVICES  — devices on non-removable ports are never gated
  2. PORT ALLOWLIST     — an operator-declared port that always works
  3. WATCHDOG           — opens the gate if the daemon stops making progress
  4. PANIC FILE         — an escape hatch usable from another terminal or SSH

Layers 1-2 prevent the lockout. Layers 3-4 end one that happened anyway. The
existing restore paths in gate.py cover a daemon that DIES; the watchdog here
covers a daemon that is alive but STUCK, which nothing else catches.

Each of these is stated as an invariant and tested as one. A guarantee that is
not tested is a wish.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

DEFAULT_PANIC_FILE = Path("/tmp/cerberus-panic")


@dataclass
class SafetyPolicy:
    """What must never be blocked, however suspicious it looks."""

    # Ports whose devices are always authorized, given as sysfs names such as
    # "1-4". Intended for the port an operator keeps a rescue keyboard in.
    allowed_ports: List[str] = field(default_factory=list)

    # Devices soldered to the board -- the built-in keyboard and touchpad on a
    # laptop -- report removable="fixed". Gating them is how a user ends up
    # locked out of their own machine with no way to answer the prompt.
    protect_fixed_ports: bool = True

    panic_file: Path = DEFAULT_PANIC_FILE

    def is_protected(self, dev) -> Optional[str]:
        """
        Return the reason this device must not be gated, or None.

        Returning the REASON rather than a boolean is deliberate: the decision
        gets printed, so a user who wonders why a device sailed through can
        find out without reading the source.
        """
        if getattr(dev, "is_root_hub", False):
            return "root hub"
        if dev.name in self.allowed_ports:
            return f"port {dev.name} is on the operator allowlist"
        if self.protect_fixed_ports and getattr(dev, "removable", None) == "fixed":
            return "device is on a non-removable (internal) port"
        return None


class Watchdog:
    """
    Opens the gate if the main loop stops making progress.

    The distinction from gate.py's restore paths matters: those fire when the
    process ENDS. A process that is alive but wedged -- a deadlock, a blocking
    read that never returns, a driver stuck in D state -- ends nothing and
    triggers none of them, while every USB device attached meanwhile stays
    dead. That is the gap this fills.

    Waiting for a human is not a stall, so the prompt runs inside `paused()`.
    """

    def __init__(self, timeout: float, on_stall: Callable[[str], None],
                 policy: Optional[SafetyPolicy] = None,
                 interval: float = 0.5):
        self.timeout = timeout
        self.on_stall = on_stall
        self.policy = policy or SafetyPolicy()
        self.interval = interval
        self._last_beat = time.monotonic()
        self._paused = False
        self._fired = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def beat(self) -> None:
        with self._lock:
            self._last_beat = time.monotonic()

    @contextmanager
    def paused(self):
        """Suspend the timer while legitimately blocked on a human."""
        with self._lock:
            self._paused = True
        try:
            yield
        finally:
            with self._lock:
                self._paused = False
                self._last_beat = time.monotonic()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    @property
    def fired(self) -> bool:
        return self._fired

    def check_once(self) -> Optional[str]:
        """
        One evaluation. Split out from the loop so the logic is testable
        without threads or sleeping.
        """
        if self._fired:
            return None
        if self.policy.panic_file.exists():
            self._fired = True
            return f"panic file {self.policy.panic_file} appeared"
        with self._lock:
            if self._paused:
                return None
            idle = time.monotonic() - self._last_beat
        if idle > self.timeout:
            self._fired = True
            return f"no progress for {idle:.1f}s"
        return None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            reason = self.check_once()
            if reason:
                self.on_stall(reason)
                return
