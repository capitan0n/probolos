"""
Asking a yes/no question in a graphical session.

WHY A DIALOG AND NOT A NOTIFICATION BUTTON
------------------------------------------
The first version of the agent tried to collect the decision from a click on the
notification itself. It does not work reliably: Plasma advertises the `actions`
capability yet renders no button for it, and the specification itself warns that
clients must not assume the server will report interaction at all -- some
servers do not support it in any form. A security decision cannot rest on a
mechanism that is optional by design.

Every other system that asks this kind of question uses a dialog:

    polkit         asks for authorisation in a window
    USBGuard       ships a notifier for awareness and a separate applet with a
                   window for the decision
    Windows        prompts in a window before installing a driver
    macOS 13+      shows "Allow accessory to connect?" for USB devices

So: the NOTIFICATION tells you something is waiting, and the DIALOG takes the
answer. That split also happens to be better for the decision itself -- a
window with an explicit button is much harder to dismiss by reflex than a popup
that appears beside whatever you were already doing.

THE FALLBACK CHAIN
------------------
Tried in order, first one that exists wins:

    kdialog    native on KDE, part of Plasma
    zenity     native on GNOME and most GTK desktops
    tkinter    a Python dialog, if the tk bindings are installed
    none       give up and let the caller use the terminal

Giving up returns None rather than "no". A question that could not be asked has
no answer, and treating an unaskable question as a refusal would silently reject
devices nobody was ever shown.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Optional


# Three-way answers, matching the terminal prompt's [y]es once / [a]lways / [N]o.
CHOICE_ONCE = "once"
CHOICE_ALWAYS = "always"
CHOICE_NO = "no"


class DialogBackend:
    """A way of asking a question. Returns an answer, or None if it could not
    even be asked."""

    name = "none"

    def available(self) -> bool:
        return False

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
        raise NotImplementedError

    def choose(self, title: str, text: str, once_label: str,
               always_label: str, no_label: str,
               timeout: float) -> Optional[str]:
        """
        Ask the three-way question: allow once, allow always, or refuse.

        This exists because the graphical path must not be more permissive than
        the terminal one. With only Allow/Cancel, "allow" had to mean "remember
        forever", so anyone glancing at an unfamiliar stick once acquired a
        permanent trust entry they never asked for. A security tool whose
        convenient path grants more than its inconvenient path is training its
        users badly.

        Backends that cannot show three buttons fall back to asking twice, which
        is worse ergonomics but the same set of outcomes.
        """
        raise NotImplementedError


class KDialogBackend(DialogBackend):
    """KDE's own dialog tool. Present wherever Plasma is."""

    name = "kdialog"

    def __init__(self):
        self._binary = shutil.which("kdialog")

    def available(self) -> bool:
        return self._binary is not None

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
        # --warningyesno gives a warning icon and two labelled buttons. Exit
        # code 0 means the first (yes) button; anything else is a refusal,
        # including the window being closed.
        args = [self._binary, "--title", title,
                "--yes-label", yes_label, "--no-label", no_label,
                "--warningyesno", text]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return False        # left unanswered: refuse
        except OSError:
            return None         # could not ask at all
        return result.returncode == 0

    def choose(self, title: str, text: str, once_label: str,
               always_label: str, no_label: str,
               timeout: float) -> Optional[str]:
        # kdialog's --warningyesnocancel gives exactly three labelled buttons.
        # Exit codes: 0 = yes, 1 = no, 2 = cancel. The labels are mapped so the
        # least privileged choice (once) is the primary button and the most
        # privileged (always) is the secondary one -- the default should be the
        # smaller grant, not the larger.
        args = [self._binary, "--title", title,
                "--yes-label", once_label,
                "--no-label", always_label,
                "--cancel-label", no_label,
                "--warningyesnocancel", text]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return CHOICE_NO
        except OSError:
            return None
        if result.returncode == 0:
            return CHOICE_ONCE
        if result.returncode == 1:
            return CHOICE_ALWAYS
        return CHOICE_NO


class ZenityBackend(DialogBackend):
    """GTK dialog tool, standard on GNOME and XFCE."""

    name = "zenity"

    def __init__(self):
        self._binary = shutil.which("zenity")

    def available(self) -> bool:
        return self._binary is not None

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
        args = [self._binary, "--question", "--title", title,
                "--text", text,
                "--ok-label", yes_label, "--cancel-label", no_label,
                "--default-cancel"]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            return None
        return result.returncode == 0

    def choose(self, title: str, text: str, once_label: str,
               always_label: str, no_label: str,
               timeout: float) -> Optional[str]:
        # zenity has no third button, but --extra-button adds one that prints
        # its own label on stdout and exits non-zero. So: OK means once, the
        # extra button means always, and anything else is a refusal.
        args = [self._binary, "--question", "--title", title,
                "--text", text,
                "--ok-label", once_label, "--cancel-label", no_label,
                "--extra-button", always_label, "--default-cancel"]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return CHOICE_NO
        except OSError:
            return None
        if result.returncode == 0:
            return CHOICE_ONCE
        if (result.stdout or "").strip() == always_label:
            return CHOICE_ALWAYS
        return CHOICE_NO


class TkinterBackend(DialogBackend):
    """
    A dialog drawn by Python itself, if the tk bindings are installed.

    Run in a subprocess rather than in-process: tkinter must own the main
    thread, and the agent has its own loop. A separate interpreter keeps the two
    from fighting, and means a broken tk install cannot take the agent down.
    """

    name = "tkinter"

    def available(self) -> bool:
        try:
            result = subprocess.run(
                [self._python(), "-c", "import tkinter"],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _python() -> str:
        import sys
        return sys.executable or "python3"

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
        # The default focus is on "no", so pressing Return does not approve.
        script = (
            "import sys, tkinter as tk\n"
            "from tkinter import messagebox\n"
            "root = tk.Tk(); root.withdraw()\n"
            "root.attributes('-topmost', True)\n"
            "answer = messagebox.askyesno(sys.argv[1], sys.argv[2],\n"
            "                             default=messagebox.NO, icon='warning')\n"
            "sys.exit(0 if answer else 1)\n")
        try:
            result = subprocess.run(
                [self._python(), "-c", script, title, text],
                timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            return None
        return result.returncode == 0

    def choose(self, title: str, text: str, once_label: str,
               always_label: str, no_label: str,
               timeout: float) -> Optional[str]:
        # askyesnocancel gives three outcomes: True, False, None. Mapped so that
        # closing the window (None) refuses, matching every other backend.
        script = (
            "import sys, tkinter as tk\n"
            "from tkinter import messagebox\n"
            "root = tk.Tk(); root.withdraw()\n"
            "root.attributes('-topmost', True)\n"
            "answer = messagebox.askyesnocancel(sys.argv[1], sys.argv[2],\n"
            "                                   default=messagebox.CANCEL,\n"
            "                                   icon='warning')\n"
            "sys.exit(0 if answer is True else (1 if answer is False else 2))\n")
        try:
            result = subprocess.run(
                [self._python(), "-c", script, title,
                 f"{text}\n\nYes = {once_label}\nNo = {always_label}"],
                timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return CHOICE_NO
        except OSError:
            return None
        if result.returncode == 0:
            return CHOICE_ONCE
        if result.returncode == 1:
            return CHOICE_ALWAYS
        return CHOICE_NO


def detect(log=print) -> Optional[DialogBackend]:
    """Pick the first dialog mechanism that exists on this desktop."""
    for backend in (KDialogBackend(), ZenityBackend(), TkinterBackend()):
        if backend.available():
            return backend
    log("[agent] no dialog tool found. Install one of:\n"
        "          KDE:   sudo pacman -S kdialog\n"
        "          GTK:   sudo pacman -S zenity\n"
        "          or:    sudo pacman -S tk\n"
        "        Until then decisions must be made in the terminal.")
    return None
