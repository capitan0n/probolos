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
                        MAX_MESSAGE, MSG_ANSWER, MSG_CRITICAL, MSG_DECIDE,
                        MSG_NOTICE, STEPS_COUNTDOWN, STEPS_ONE, STEPS_TWO)

APP_NAME = "Probolos"
ICON = "drive-removable-media-usb"

# urgency: 0 low, 1 normal, 2 critical (critical notifications do not expire)
URGENCY_NORMAL = 1
URGENCY_CRITICAL = 2


class NotificationError(Exception):
    pass


def _gvariant_string(text: str) -> str:
    """
    `text` as a GVariant text-format string literal, for a gdbus argument.

    gdbus does not pass its arguments through as strings: it PARSES each one
    as GVariant text, and one that does not parse is wrapped in quotes with
    only `"` escaped and parsed again. Either way backslash sequences are
    decoded, so a device name holding the plain ASCII text \\u003c reached the
    notification server as '<' -- after html.escape had already run, and
    after textsafe had turned a real U+202E into the visible text \\u202e,
    which gdbus then turned straight back into U+202E. The two sanitisers in
    front of this call were being undone by the call itself.

    A literal that gdbus parses on its first attempt decodes to exactly the
    text given: backslash and quote are escaped, and control characters are
    written as escapes rather than relied on to survive the tokenizer.
    """
    out = ['"']
    for char in text:
        if char == "\\":
            out.append("\\\\")
        elif char == '"':
            out.append('\\"')
        elif char == "\n":
            out.append("\\n")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


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
        # The body is markup to servers advertising body-markup (Plasma renders
        # links and images from it) and carries device-supplied strings, so it
        # gets the same escaping as the dialogs. The summary is plain text.
        body = dialogs._markup_safe(body)
        # Every string goes in as a quoted GVariant literal, never bare: gdbus
        # decodes backslash escapes in bare arguments. See _gvariant_string.
        args = [
            self._gdbus, "call", "--session",
            "--dest", "org.freedesktop.Notifications",
            "--object-path", "/org/freedesktop/Notifications",
            "--method", "org.freedesktop.Notifications.Notify",
            _gvariant_string(APP_NAME), "0", _gvariant_string(ICON),
            _gvariant_string(summary), _gvariant_string(body), actions,
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


# Bounds on the dialog timeout a message may ask for. The floor keeps a
# question from flashing past unanswerably; the ceiling keeps one from pinning
# a dialog on the user's screen indefinitely.
MIN_DIALOG_TIMEOUT = 10.0
MAX_DIALOG_TIMEOUT = 600.0
DEFAULT_DIALOG_TIMEOUT = 60.0

# How long a notice window stays up when there is no notification server to
# carry it. It approves nothing, so this only bounds how long it is in the way.
NOTICE_TIMEOUT = 120.0


def _as_text(value, fallback: str) -> str:
    """
    A display string from a field on the wire, or the fallback.

    Everything downstream -- html.escape in the dialog backends, string
    concatenation in the notification path, the subprocess argv itself --
    assumes str. A JSON null, number, list or object here raised TypeError or
    AttributeError and took the agent down, which is a way to remove the
    desktop prompt by sending one malformed message. The text is already
    sanitised at the descriptor boundary by textsafe, so nothing is re-cleaned
    here; this is a type check, not a second sanitiser.
    """
    return value if isinstance(value, str) else fallback


def _from_confirm(answer) -> str:
    """A yes/no dialog's result as an answer. Only a real True approves."""
    if answer is None:
        return ANSWER_UNAVAILABLE
    return ANSWER_YES if answer is True else ANSWER_NO


def _from_choice(choice) -> str:
    """A three-way dialog's result as an answer. None is no decision."""
    if choice is None:
        return ANSWER_UNAVAILABLE
    if choice == dialogs.CHOICE_ONCE:
        return ANSWER_YES
    if choice == dialogs.CHOICE_ALWAYS:
        return ANSWER_ALWAYS
    return ANSWER_NO


def _countdown(value) -> float:
    """
    The countdown from the wire, clamped. Never below the daemon's own 10 s
    (it would refuse an earlier yes anyway, so a shorter countdown would only
    show an Allow button that cannot work) and never absurdly long.
    """
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        seconds = 10.0
    if seconds != seconds:          # NaN
        seconds = 10.0
    return min(max(seconds, 10.0), 30.0)


def _dialog_timeout(value) -> float:
    """
    How long to leave the dialog up, from a field on the wire.

    `float(message.get("timeout", 60))` raised ValueError on a string and
    TypeError on a list or a null -- out of _handle(), out of the recv loop,
    and the agent exited. Losing the agent is not a security failure on its own
    (the daemon falls back to the terminal), but it is a way to silently remove
    the desktop prompt, and the value comes off a socket whose occupant the
    agent does not get to choose.

    Anything unusable becomes the default, and the result is clamped: a
    negative or absurd number is as much a way to suppress the question as a
    malformed one.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return DEFAULT_DIALOG_TIMEOUT
    try:
        seconds = float(value)
    except (ValueError, OverflowError):
        return DEFAULT_DIALOG_TIMEOUT
    if seconds != seconds or seconds in (float("inf"), float("-inf")):
        return DEFAULT_DIALOG_TIMEOUT      # NaN / infinity
    if seconds <= 0:
        # 0 means "wait forever" to the daemon's terminal prompt, which a
        # dialog cannot honour. Use the default rather than an unbounded wait.
        return DEFAULT_DIALOG_TIMEOUT
    return max(MIN_DIALOG_TIMEOUT, min(MAX_DIALOG_TIMEOUT, seconds))


class Agent:
    def __init__(self, socket_path: Path = DEFAULT_SOCKET, log=print):
        self.socket_path = Path(socket_path)
        self.log = log
        self.notifier = Notifier(log=log)
        self.dialog = dialogs.detect(log=log)
        self.countdown_dialog = self._pick_countdown_dialog()
        self.sock: Optional[socket.socket] = None
        # Held while a notice WINDOW is on screen; see _show_notice.
        self._notice_window = threading.Lock()

    def _pick_countdown_dialog(self):
        """
        tkinter can draw an "Allow anyway (9)" button that stays disabled
        until the countdown ends; kdialog and zenity cannot, and fall back to
        a read-first window before the question. Prefer the real thing when
        the tk bindings are installed.
        """
        if self.dialog is None or isinstance(self.dialog,
                                             dialogs.TkinterBackend):
            return self.dialog
        tk = dialogs.TkinterBackend()
        return tk if tk.available() else self.dialog

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

        countdown = getattr(self.countdown_dialog, "name", "none")
        self.log(f"[agent] connected to Probolos. Decisions will be asked "
                 f"through {self.dialog.name}; critical ones through "
                 f"{countdown} with a countdown"
                 + ("" if countdown == "tkinter" else
                    " (install tk for a countdown button)") + ".")
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
                if len(buffer) > MAX_MESSAGE:
                    # MAX_MESSAGE bounded each recv() and not their sum, so a
                    # peer that sends bytes and never a newline grew this
                    # without limit. AgentLink.ask() has carried this exact
                    # bound since the same bug was found on the server side;
                    # the agent is the half running in the user's session with
                    # their privileges, and it was the one still unbounded.
                    #
                    # It matters because the agent does not get to choose what
                    # it is talking to: it connects to a path, and anything
                    # able to occupy that path is what answers. A question
                    # from Probolos is a few hundred bytes.
                    self.log("[agent] oversized message from the socket; "
                             "disconnecting")
                    break
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

        if not isinstance(message, dict):
            return

        kind = message.get("type")
        if kind == MSG_CRITICAL:
            # Display only. Deliberately offers no way to allow anything.
            self.notifier.notify(
                _as_text(message.get("title"), "Probolos"),
                _as_text(message.get("body"), "") +
                "\n\nThis device matches an attack pattern and cannot be "
                "approved from here. Use the terminal.",
                urgency=URGENCY_CRITICAL, actionable=False)
            return
        if kind == MSG_NOTICE:
            # Display only, like MSG_CRITICAL: nothing is sent back, and
            # nothing shown offers a way to allow anything.
            self._show_notice(_as_text(message.get("title"), "Probolos"),
                              _as_text(message.get("body"), ""))
            return
        if kind != MSG_DECIDE:
            return

        request_id = message.get("id")
        timeout = _dialog_timeout(message.get("timeout"))
        answer = self._ask_user(message, timeout)
        self._reply(request_id, answer)

    def _show_notice(self, title: str, body: str) -> None:
        """
        Tell the person something, offering no answer -- "this device is
        still blocked; replug it to be asked".

        A notification when the desktop has a notification server, at normal
        urgency: nothing is waiting on anyone. Otherwise the dialog backend's
        one-button notice window. That blocks until it is closed, and this
        runs on the receive loop, so the window gets a thread of its own: the
        next question must not queue behind a window nobody is looking at.
        One window at a time; a notice that arrives while one is up is logged
        rather than stacked, so whatever occupies the socket cannot bury the
        desktop in windows.
        """
        if self.notifier.available() and self.notifier.notify(
                title, body, urgency=URGENCY_NORMAL,
                actionable=False) is not None:
            return
        dialog = self.dialog
        if dialog is None:
            self.log(f"[agent] {title}: {body}")
            return
        guard = getattr(self, "_notice_window", None)
        if guard is None:
            guard = self._notice_window = threading.Lock()
        if not guard.acquire(blocking=False):
            self.log(f"[agent] a notice is already on screen; not showing "
                     f"another: {title}")
            return

        def show() -> None:
            try:
                dialog.notice(f"Probolos — {title}", body,
                              timeout=NOTICE_TIMEOUT)
            except Exception as exc:   # noqa: BLE001 -- a window, not the agent
                self.log(f"[agent] could not show a notice: {exc!r}")
            finally:
                guard.release()

        threading.Thread(target=show, daemon=True).start()

    def _ask_user(self, message: dict, timeout: float) -> str:
        """
        Announce, then ask -- with as much friction as the daemon says this
        device earns (message["steps"]):

          one        a single dialog: Allow / Keep blocked (Allow once /
                     Always allow / Keep blocked when remembering is possible)
          two        that, then a differently worded "switch it on?" naming
                     what this device will be able to do
          countdown  CRITICAL: one window whose "Allow anyway" unlocks after
                     the countdown; never "always"

        The notification is one line. It exists so the question is not missed
        if the dialog opens behind something, not to repeat the dialog.
        """
        title = _as_text(message.get("title"), "New USB device")
        body = _as_text(message.get("body"), "")
        caps = _as_text(message.get("capabilities"), "")
        allow_always = bool(message.get("allow_always"))
        steps = message.get("steps")
        if steps not in (STEPS_ONE, STEPS_TWO, STEPS_COUNTDOWN):
            steps = STEPS_TWO          # unknown or missing: the careful default
        # The analyzer stops listening `timeout` seconds after it asked (the
        # small margin covers the reply's trip back). The first dialog may use
        # nearly all of that, and the second one used to get a fixed 30 s on
        # top -- so a person who read the first dialog carefully could click
        # "Yes, switch it on" after the analyzer had already given up, and the
        # device stayed blocked while they believed they had approved it.
        deadline = time.monotonic() + timeout - 1.0
        can_do = (f"Once on, it will be able to: {caps}." if caps else
                  "Once on, it will be able to act on your computer as "
                  "whatever it claims to be.")

        announcement = None
        if self.notifier.available():
            announcement = self.notifier.notify(
                "Dangerous USB device blocked" if steps == STEPS_COUNTDOWN
                else "USB device blocked",
                f"{title}\nAnswer the Probolos window.",
                urgency=URGENCY_CRITICAL, actionable=False)

        try:
            if steps == STEPS_COUNTDOWN:
                return self._ask_countdown(
                    title, body, can_do,
                    _countdown(message.get("countdown")), deadline,
                    note=_as_text(message.get("note"), ""))

            first_text = (f"{title}\n\n{body}\n\n"
                          f"It is BLOCKED and cannot do anything.")
            first_timeout = max(timeout - 5, 10)

            if steps == STEPS_ONE:
                text = f"{first_text}\n{can_do}\n\nAllow it?"
                if allow_always:
                    return _from_choice(self.dialog.choose(
                        title="Probolos — new USB device", text=text,
                        once_label="Allow once", always_label="Always allow",
                        no_label="Keep blocked", timeout=first_timeout))
                return _from_confirm(self.dialog.confirm(
                    title="Probolos — new USB device", text=text,
                    yes_label="Allow", no_label="Keep blocked",
                    timeout=first_timeout))

            # ---- two steps: first question ---------------------------------
            allowed = self.dialog.confirm(
                title="Probolos — new USB device",
                text=f"{first_text}\n\nAllow it?",
                yes_label="Allow", no_label="Keep blocked",
                timeout=first_timeout)
            if allowed is None:
                # No way to ask -- no kdialog, no zenity, no tkinter -- or
                # nobody answered in time. This is NOT a refusal: the user
                # never refused anything. Return a value the analyzer does not
                # recognise as a decision, which it records as "no answer"
                # (asking on its terminal instead, if it has one).
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
            # clicked through by momentum, and it names what THIS device will
            # be able to do rather than everything a device might.
            confirm_text = f"Switch this device on?\n\n{can_do}"

            # Whatever is left of the analyzer's budget, never more than the
            # 30 s this dialog always had. With nothing left, an answer could
            # not be honoured anyway, so none is collected.
            remaining = min(30.0, deadline - time.monotonic())
            if remaining <= 0:
                return ANSWER_UNAVAILABLE       # out of time: no decision

            if not allow_always:
                return _from_confirm(self.dialog.confirm(
                    title="Probolos — confirm",
                    text=confirm_text,
                    yes_label="Yes, switch it on", no_label="Keep blocked",
                    timeout=remaining))

            # Three outcomes, the same set the terminal offers. Without this the
            # graphical path would be MORE permissive than the terminal one:
            # "allow" would have to mean "remember forever", so glancing at an
            # unfamiliar stick once would silently create a permanent trust
            # entry. The convenient path must never grant more than the
            # inconvenient one.
            return _from_choice(self.dialog.choose(
                title="Probolos — confirm",
                text=confirm_text + "\n\nAllow it once, or remember it for "
                                    "next time as well?",
                once_label="Just this once",
                always_label="Always allow",
                no_label="Keep blocked",
                timeout=remaining))
        finally:
            if announcement is not None:
                self.notifier.close(announcement)

    def _ask_countdown(self, title: str, body: str, can_do: str,
                       countdown: float, deadline: float,
                       note: str = "") -> str:
        """
        A device matching an attack pattern -- previously refused, or the same
        identity now describing itself differently. It can be approved, since
        it may be your own device after a firmware update, but "Allow anyway"
        stays disabled for the countdown and "always" is never offered. The
        daemon refuses an approval that arrives sooner, so a faster dialog or
        a script answering for this one gains nothing.
        """
        remaining = deadline - time.monotonic()
        if remaining <= countdown:
            return ANSWER_UNAVAILABLE
        backend = getattr(self, "countdown_dialog", None) or self.dialog
        note = note or ("This device matches an attack pattern. Allow it "
                        "only if you know exactly why these findings appear.")
        text = f"{title}\n\n{body}\n\n{note}\n\n{can_do}"
        started = time.monotonic()
        allowed = backend.confirm_countdown(
            title="Probolos — DANGEROUS USB device", text=text,
            yes_label="Allow anyway", no_label="Keep blocked",
            delay=countdown, timeout=remaining)
        if (allowed is None and backend is not self.dialog
                and time.monotonic() - started < countdown):
            # No answer before the countdown could even have ended: the
            # window failed rather than timed out. Ask with the main backend.
            self.log("[agent] countdown window failed; using "
                     f"{self.dialog.name} instead")
            allowed = self.dialog.confirm_countdown(
                title="Probolos — DANGEROUS USB device", text=text,
                yes_label="Allow anyway", no_label="Keep blocked",
                delay=countdown,
                timeout=deadline - time.monotonic())
        return _from_confirm(allowed)

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
            print("The dialog could not be shown, or was not answered "
                  "within 60 s.")
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
