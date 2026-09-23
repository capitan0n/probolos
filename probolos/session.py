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
import stat as _stat
import subprocess
from typing import Optional

# Policy names
POLICY_QUEUE = "queue"        # block now, ask when the screen unlocks
POLICY_DENY = "deny"          # block now, do not ask later
POLICY_IGNORE = "ignore"      # take no notice of the lock state

# Where loginctl legitimately lives. NOT shutil.which().
#
# which() walks $PATH, and this process is root (or, under --privsep, the
# parent was). `sudo` preserves PATH under a Defaults:!secure_path or
# env_keep configuration, systemd units can be given an Environment=PATH, and
# a cron or service wrapper can set anything at all -- so a writable directory
# appearing earlier in PATH than /usr/bin turns "ask logind whether the screen
# is locked" into "execute whatever is called loginctl", as root, once per
# second from the daemon's main poll loop and again for every device.
#
# That is a privilege-escalation primitive handed out by a convenience call,
# and it costs nothing to close: loginctl is part of systemd and has exactly
# two real locations. An absolute path cannot be redirected by the
# environment, and each candidate is checked to be a regular executable file
# rather than merely present.
_LOGINCTL_CANDIDATES = ("/usr/bin/loginctl", "/bin/loginctl")


def _is_user_class(value: Optional[str]) -> bool:
    """
    True for a logind session that belongs to a person, not to the system.

    A display manager's greeter is a graphical session too: GDM keeps its
    login screen (Class=greeter, user `gdm`) running on tty1 while the real
    session sits on tty2, and it never sets LockedHint. Counted as a user, it
    made every locked screen read as "someone is present", and it could be
    picked as the account allowed to answer the agent. systemd names person
    sessions "user", "user-early", "user-light" and so on; greeter,
    lock-screen, background and manager sessions are not people. A missing
    Class (an old or unusual logind) keeps the previous behaviour.
    """
    return value is None or value.startswith("user")


def _find_loginctl() -> Optional[str]:
    """The real loginctl, found by absolute path rather than through $PATH."""
    for candidate in _LOGINCTL_CANDIDATES:
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if _stat.S_ISREG(info.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    return None


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
        # Absolute path only: see _find_loginctl. Resolving this through $PATH
        # in a root process is an arbitrary-exec hole, and this call is on the
        # daemon's hot loop.
        self._binary = _find_loginctl()

    def available(self) -> bool:
        return self._binary is not None

    def reachable(self) -> bool:
        """True when logind answers at all, even with no sessions yet."""
        if not self._binary:
            return False
        try:
            result = subprocess.run([self._binary, "list-sessions",
                                     "--no-legend"],
                                    capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

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
        """
        One loginctl call. Never raises.

        The handling used to sit around `_graphical_sessions()` only, which
        left `_locked_hint()` -- called from the loop BELOW that try -- able to
        raise TimeoutExpired straight out of `is_locked()`. That call happens
        once a second from the daemon's main poll loop and once per device in
        `_on_add`, so a loginctl that wedged for more than three seconds (a
        stuck system bus, a hung session manager) did not degrade the lock
        policy: it killed the daemon and opened the gate.

        An empty string means "could not tell", which is exactly what the
        callers already treat as unknown, so the policy degrades to its
        documented fail-visible default instead.
        """
        try:
            result = subprocess.run([self._binary, *args],
                                    capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            return ""
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
                             "-p", "Remote", "-p", "Class")
            values = dict(
                line.split("=", 1) for line in info.splitlines() if "=" in line)
            if values.get("Remote") == "yes":
                continue
            if not _is_user_class(values.get("Class")):
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

    Chosen on whether logind answers, not on whether a graphical session
    exists yet: a service started at boot sees no session, and deciding then
    would disable the lock policy for the whole run. Unknown lock state is
    still treated as unlocked by the daemon, exactly as before.
    """
    if force is not None:
        return FixedState(force)
    monitor = LogindMonitor()
    if monitor.available() and monitor.reachable():
        return monitor
    return AlwaysUnlocked()
