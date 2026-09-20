#!/usr/bin/env python3
"""
The desktop agent. Runs as you, in your graphical session.

    python -m probolos.agent

It connects to the running Probolos analyzer, shows a notification when a device
is waiting for a decision, and sends back what you chose. It knows nothing about
USB, sysfs, or rules -- it displays text and reports a click. That narrowness is
deliberate: it runs in your session with your privileges, so it is the component
that should be able to do the least.

HOW THE INTERACTION WORKS
-------------------------
    1. A notification appears: what the device claims to be, and any findings.
    2. Clicking the body means "I want to allow this".
    3. A SECOND notification asks you to confirm. Clicking again authorizes.
    4. Anything else -- dismissing, ignoring, letting it expire -- is a refusal.

The second click is not ceremony. A notification appears next to whatever else
you were doing, and a single misplaced click should never be able to energise
unknown hardware. Two deliberate clicks on two different notifications cannot
happen by accident, and the wording changes between them so the second is read
rather than dismissed.

Refusal is the default at every exit: timeout, dismissal, a closed session, a
crashed agent. The only path to "yes" is two explicit clicks.

WHY gdbus AND NOT A D-BUS LIBRARY
---------------------------------
`gdbus` ships with glib, which is present on every desktop that has a
notification daemon at all -- so this works on KDE, GNOME, XFCE and the rest
with no Python D-Bus binding to install. The notification interface itself
(org.freedesktop.Notifications) is a freedesktop standard, not a KDE or GNOME
extension, which is why one implementation covers all of them.

Clicking the BODY is used rather than action buttons because some desktops
(notably parts of GNOME) do not render buttons on notifications, while the
"default" action -- invoked by clicking the notification itself -- is honoured
essentially everywhere.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import dialogs
from .agentlink import (ANSWER_ALWAYS, ANSWER_NO, ANSWER_UNAVAILABLE,
                        ANSWER_YES, DEFAULT_SOCKET,
                        MAX_MESSAGE, MSG_ANSWER, MSG_CRITICAL, MSG_DECIDE)

APP_NAME = "Probolos"
ICON = "drive-removable-media-usb"

# urgency: 0 low, 1 normal, 2 critical (critical notifications do not expire)
URGENCY_NORMAL = 1
URGENCY_CRITICAL = 2


class NotificationError(Exception):
    pass


class Notifier:
    """
    Sends notifications and waits for the body to be clicked, via gdbus.

    One `gdbus monitor` process is kept running for the lifetime of the agent to
    watch for ActionInvoked and NotificationClosed signals. Starting a monitor
    per notification would race with the user: a fast click could land before
    the watcher was listening.
    """

    def __init__(self, log=print):
        self.log = log
        self._gdbus = shutil.which("gdbus")
        self._monitor: Optional[subprocess.Popen] = None
        self._events: list = []
        self._lock = threading.Lock()

    def available(self) -> bool:
        return self._gdbus is not None

    def start(self) -> bool:
        if not self._gdbus:
            return False
        try:
            self._monitor = subprocess.Popen(
                [self._gdbus, "monitor", "--session",
                 "--dest", "org.freedesktop.Notifications"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError as exc:
            self.log(f"[agent] cannot watch for clicks: {exc}")
            return False
        threading.Thread(target=self._read_signals, daemon=True).start()
        return True

    def stop(self) -> None:
        if self._monitor:
            self._monitor.terminate()
            self._monitor = None

    def _read_signals(self) -> None:
        """Collect ActionInvoked / NotificationClosed lines as they arrive."""
        if not self._monitor or not self._monitor.stdout:
            return
        for line in self._monitor.stdout:
            if "ActionInvoked" in line or "NotificationClosed" in line:
                numbers = re.findall(r"\b(\d+)\b", line)
                if not numbers:
                    continue
                with self._lock:
                    self._events.append((
                        "action" if "ActionInvoked" in line else "closed",
                        int(numbers[0]),
                        line.strip()))

    def notify(self, summary: str, body: str, urgency: int = URGENCY_NORMAL,
               actionable: bool = True, timeout_ms: int = 0) -> Optional[int]:
        """Show a notification. Returns its id, or None on failure."""
        if not self._gdbus:
            return None
        # Register BOTH an explicit button AND the "default" (body-click)
        # action. KDE does not reliably report body-click but shows and reports
        # buttons; some GNOME builds hide buttons but do report "default". With
        # both registered, a click is caught whichever mechanism the desktop
        # actually delivers. The action KEYS are what come back in the signal;
        # the human-readable labels follow each key.
        if actionable:
            actions = '["allow", "Allow", "default", "Allow"]'
        else:
            actions = "[]"
        args = [
            self._gdbus, "call", "--session",
            "--dest", "org.freedesktop.Notifications",
            "--object-path", "/org/freedesktop/Notifications",
            "--method", "org.freedesktop.Notifications.Notify",
            APP_NAME, "0", ICON, summary, body, actions,
            f"{{'urgency': <byte {urgency}>}}", str(timeout_ms),
        ]
        try:
            result = subprocess.run(args, capture_output=True, text=True,
                                    timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            self.log(f"[agent] notification failed: {exc}")
            return None
        if result.returncode != 0:
            self.log(f"[agent] notification rejected: {result.stderr.strip()}")
            return None
        found = re.search(r"uint32 (\d+)", result.stdout)
        return int(found.group(1)) if found else None

    def wait_for_click(self, notification_id: int, timeout: float) -> bool:
        """
        True if the notification was clicked, False for anything else.

        Every non-click ending -- dismissed, expired, session gone -- is False.
        There is exactly one way to say yes.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                events, self._events = self._events, []
            for kind, ident, _raw in events:
                if ident != notification_id:
                    continue
                if kind == "action":
                    return True
                if kind == "closed":
                    return False
            time.sleep(0.1)
        return False

    def close(self, notification_id: int) -> None:
        """
        Best-effort. Tidying up a notification must never cost an answer.

        This is called from the `finally` of _decide(), after the user has
        already chosen. An unhandled TimeoutExpired or OSError from gdbus there
        replaced the return value with an exception, so a hung or missing
        notification daemon discarded a decision the human had just made -- and
        the device stayed blocked with no explanation. A stale notification
        left on screen is the strictly smaller problem.
        """
        if not self._gdbus:
            return
        try:
            subprocess.run(
                [self._gdbus, "call", "--session",
                 "--dest", "org.freedesktop.Notifications",
                 "--object-path", "/org/freedesktop/Notifications",
                 "--method", "org.freedesktop.Notifications.CloseNotification",
                 str(notification_id)],
                capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass


class Agent:
    def __init__(self, socket_path: Path = DEFAULT_SOCKET, log=print):
        self.socket_path = Path(socket_path)
        self.log = log
        self.notifier = Notifier(log=log)
        self.dialog = dialogs.detect(log=log)
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(str(self.socket_path))
            self.sock.settimeout(1.0)
            return True
        except OSError as exc:
            self.log(f"[agent] cannot reach Probolos at {self.socket_path}: "
                     f"{exc}")
            return False

    def run(self) -> int:
        if self.dialog is None:
            self.log("[agent] refusing to start without a way to ask you "
                     "anything.")
            return 1
        if not self.connect():
            return 1
        # Notifications are optional: they announce that something is waiting,
        # but the answer comes from the dialog. A desktop with no notification
        # daemon still gets a working agent.
        if self.notifier.available():
            self.notifier.start()

        self.log(f"[agent] connected to Probolos. Decisions will be asked "
                 f"through {self.dialog.name}.")
        buffer = b""
        try:
            while True:
                try:
                    chunk = self.sock.recv(MAX_MESSAGE)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    self.log("[agent] Probolos closed the connection")
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle(line)
        except KeyboardInterrupt:
            pass
        finally:
            self.notifier.stop()
            if self.sock:
                self.sock.close()
        return 0

    def _handle(self, line: bytes) -> None:
        try:
            message = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        kind = message.get("type")
        if kind == MSG_CRITICAL:
            # Display only. Deliberately offers no way to allow anything.
            self.notifier.notify(
                message.get("title", "Probolos"),
                message.get("body", "") +
                "\n\nThis device matches an attack pattern and cannot be "
                "approved from here. Use the terminal.",
                urgency=URGENCY_CRITICAL, actionable=False)
            return
        if kind != MSG_DECIDE:
            return

        request_id = message.get("id")
        timeout = float(message.get("timeout", 60))
        answer = self._ask_user(message, timeout)
        self._reply(request_id, answer)

    def _ask_user(self, message: dict, timeout: float) -> str:
        """
        Announce, then ask. Two dialogs, both of which must be answered yes.

        The notification exists so the question is not missed if it opens behind
        something; the dialogs are where the decision actually happens.
        """
        title = message.get("title", "New USB device")
        body = message.get("body", "")
        allow_always = bool(message.get("allow_always"))

        announcement = None
        if self.notifier.available():
            announcement = self.notifier.notify(
                title, f"{body}\n\nBlocked — waiting for your decision.",
                urgency=URGENCY_CRITICAL, actionable=False)

        try:
            # ---- first question -------------------------------------------
            allowed = self.dialog.confirm(
                title="Probolos — new USB device",
                text=(f"{title}\n\n{body}\n\n"
                      f"This device is currently BLOCKED and cannot do "
                      f"anything.\n\nAllow it?"),
                yes_label="Allow", no_label="Keep blocked",
                timeout=max(timeout - 5, 10))
            if allowed is None:
                # No way to ask -- no kdialog, no zenity, no tkinter. This is
                # NOT a refusal: the user never saw anything to refuse. Return
                # a value the analyzer does not recognise as a decision, which
                # it treats as "no answer" and falls back to the terminal.
                #
                # (Returning ANSWER_NO here, as this line used to, meant that a
                # machine without a dialog backend silently denied EVERY device
                # while appearing to have asked. Fail-closed in the worst way:
                # invisible, and indistinguishable from the user saying no.)
                return ANSWER_UNAVAILABLE
            if not allowed:
                return ANSWER_NO

            # ---- second question, worded differently on purpose ----------
            # The wording changes so the second dialog is read rather than
            # clicked through by momentum. One misplaced click must never be
            # able to energise unknown hardware.
            confirm_text = ("Switch this device on?\n\n"
                            "It will be able to act on your computer — type, "
                            "read and write storage, or use the network, "
                            "depending on what it is.")

            if not allow_always:
                confirmed = self.dialog.confirm(
                    title="Probolos — confirm",
                    text=confirm_text,
                    yes_label="Yes, switch it on", no_label="Cancel",
                    timeout=30.0)
                return ANSWER_YES if confirmed else ANSWER_NO

            # Three outcomes, the same set the terminal offers. Without this the
            # graphical path would be MORE permissive than the terminal one:
            # "allow" would have to mean "remember forever", so glancing at an
            # unfamiliar stick once would silently create a permanent trust
            # entry. The convenient path must never grant more than the
            # inconvenient one.
            choice = self.dialog.choose(
                title="Probolos — confirm",
                text=confirm_text + "\n\nAllow it once, or remember it for "
                                    "next time as well?",
                once_label="Just this once",
                always_label="Always allow",
                no_label="Cancel",
                timeout=30.0)
            if choice == dialogs.CHOICE_ONCE:
                return ANSWER_YES
            if choice == dialogs.CHOICE_ALWAYS:
                return ANSWER_ALWAYS
            return ANSWER_NO
        finally:
            if announcement is not None:
                self.notifier.close(announcement)

    def _reply(self, request_id, answer: str) -> None:
        if not self.sock:
            return
        try:
            self.sock.sendall((json.dumps({
                "type": MSG_ANSWER, "id": request_id, "answer": answer,
            }) + "\n").encode())
        except OSError:
            pass


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Probolos desktop agent: approve USB devices from a "
                    "notification instead of a terminal.")
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET,
                        help="where the Probolos analyzer is listening")
    parser.add_argument("--test", action="store_true",
                        help="show a sample notification and exit, to check "
                             "that notifications work at all")
    args = parser.parse_args(argv)

    if args.test:
        backend = dialogs.detect()
        notifier = Notifier()

        if notifier.available():
            ident = notifier.notify(
                "Probolos test",
                "Notifications work. A dialog should now appear.",
                actionable=False)
            print("Notification sent."
                  if ident else "Notification could NOT be sent.")
        else:
            print("gdbus not found: notifications unavailable (not fatal — "
                  "the dialog is what takes the decision).")

        if backend is None:
            return 1
        print(f"Dialog backend: {backend.name}. A dialog should be open now...")
        answer = backend.confirm(
            title="Probolos test",
            text=("This is what a device prompt will look like.\n\n"
                  "Press \"Allow\" to continue to the second dialog."),
            yes_label="Allow", no_label="Cancel", timeout=60.0)
        if answer is None:
            print("The dialog could not be shown.")
            return 1
        if not answer:
            print("Dialog works, and you pressed Cancel. That is the safe "
                  "default.")
            return 0

        choice = backend.choose(
            title="Probolos test — three choices",
            text=("The real second dialog offers three outcomes, the same as "
                  "the terminal.\n\nPick any of them."),
            once_label="Just this once", always_label="Always allow",
            no_label="Cancel", timeout=60.0)
        print(f"You chose: {choice}")
        print("Both dialogs work — the agent will function here.")
        return 0

    return Agent(args.socket).run()


if __name__ == "__main__":
    sys.exit(main())
