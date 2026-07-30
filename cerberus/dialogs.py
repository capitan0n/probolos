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


class DialogBackend:
    """A way of asking one yes/no question. Returns True, False, or None."""

    name = "none"

    def available(self) -> bool:
        return False

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
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
