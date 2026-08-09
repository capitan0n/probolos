"""
Knowing whether anyone is actually at the machine.

WHY THIS MATTERS MORE THAN IT LOOKS
-----------------------------------
The most realistic physical-access attack is not someone plugging a device in
while you watch. It is someone plugging it in while you are away from the desk
and letting it act when you come back -- or letting you approve it yourself,
distractedly, along with everything else you clicked on returning.

A locked screen is the clearest signal available that the owner is not present.
Probolos admits nothing while it is locked, including remembered devices: the
whole point of the trust store is to avoid asking about your own hardware, and
a device attached while you were absent is precisely the case where asking is
the correct behaviour.

The device is not rejected outright, though. It stays blocked and goes into a
queue, and the question is put when the screen unlocks -- so a person returning
to their desk sees the decision without having to unplug and replug anything.

FAILING VISIBLY, NOT SILENTLY
-----------------------------
If the session state cannot be determined -- no logind, a headless machine, an
unusual desktop -- there are two ways to be wrong. Assuming "locked" would
break the tool on any system it does not understand. Assuming "unlocked" would
silently disable a protection the user believes is running.

So it assumes unlocked, and SAYS SO, once, at startup. A protection that is not
working must never look like one that is.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

# Policy names
POLICY_QUEUE = "queue"        # block now, ask when the screen unlocks
POLICY_DENY = "deny"          # block now, do not ask later
POLICY_IGNORE = "ignore"      # take no notice of the lock state


class SessionMonitor:
    """Interface. Implementations answer one question: is the screen locked?"""

    #: Human-readable description of how state is being determined.
    describe = "unknown"

    def is_locked(self) -> Optional[bool]:
        """True, False, or None when it cannot be determined."""
        raise NotImplementedError


class AlwaysUnlocked(SessionMonitor):
    """Fallback when the session state cannot be determined."""

    describe = "unavailable (screen-lock policy inactive)"

    def is_locked(self) -> Optional[bool]:
        return False


class FixedState(SessionMonitor):
    """For tests, and for forcing a state on the command line."""

    def __init__(self, locked: Optional[bool]):
        self._locked = locked
        self.describe = f"forced ({'locked' if locked else 'unlocked'})"

    def is_locked(self) -> Optional[bool]:
        return self._locked


class LogindMonitor(SessionMonitor):
    """
    Ask systemd-logind, over the system bus, via loginctl.

    logind is used rather than the desktop's own screensaver interface for a
    specific reason: the analyzer runs unprivileged and outside the user's
    session, so it has no access to that session's bus. logind lives on the
    system bus and knows the lock state of every seat, which is exactly the
    vantage point this process has.

    `LockedHint` is a hint in the strict sense -- it is set by the session
    manager and a desktop that does not report it will look unlocked. That is
    noted rather than worked around, because guessing would be worse.
    """

    describe = "systemd-logind (LockedHint)"

    def __init__(self, seat_user: Optional[str] = None):
        self.seat_user = seat_user
        self._binary = shutil.which("loginctl")

    def available(self) -> bool:
        return self._binary is not None

    def is_locked(self) -> Optional[bool]:
        if not self._binary:
            return None
        try:
            sessions = self._graphical_sessions()
        except (OSError, subprocess.SubprocessError):
            return None
        if not sessions:
            return None

        # If ANY graphical session is unlocked, someone is present.
        any_known = False
        for session_id in sessions:
            state = self._locked_hint(session_id)
            if state is None:
                continue
            any_known = True
            if state is False:
                return False
        return True if any_known else None

    # ---- internals ----

    def _run(self, *args) -> str:
        result = subprocess.run([self._binary, *args],
                                capture_output=True, text=True, timeout=3)
        return result.stdout if result.returncode == 0 else ""

    def _graphical_sessions(self):
        out = self._run("list-sessions", "--no-legend")
        ids = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                ids.append(parts[0])
        graphical = []
        for session_id in ids:
            info = self._run("show-session", session_id, "-p", "Type",
                             "-p", "Remote")
            values = dict(
                line.split("=", 1) for line in info.splitlines() if "=" in line)
            if values.get("Remote") == "yes":
                continue
            if values.get("Type") in ("x11", "wayland", "mir"):
                graphical.append(session_id)
        return graphical

    def _locked_hint(self, session_id: str) -> Optional[bool]:
        info = self._run("show-session", session_id, "-p", "LockedHint")
        for line in info.splitlines():
            if line.startswith("LockedHint="):
                return line.split("=", 1)[1].strip().lower() == "yes"
        return None


def detect(force: Optional[bool] = None) -> SessionMonitor:
    """
    Choose a monitor for this machine.

    `force` overrides everything, for testing the policy without arranging an
    actual locked screen.
    """
    if force is not None:
        return FixedState(force)
    monitor = LogindMonitor()
    if monitor.available() and monitor.is_locked() is not None:
        return monitor
    return AlwaysUnlocked()
