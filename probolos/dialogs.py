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

import html
import shutil
import subprocess
from typing import Optional


def _markup_safe(text: str) -> str:
    """
    Neutralise markup for backends that render rich text.

    kdialog renders Qt rich text and zenity renders Pango markup, so a device
    whose iProduct is '<a href="file:///etc/shadow">Kingston</a>' would draw a
    live link -- or worse, restyle the prompt to look reassuring -- right next
    to the Allow button. That is the one surface where the decision is actually
    made, so it must show the name literally.

    This escapes the five characters that begin or end markup (& < > " ')
    via html.escape. A legitimate name like 'A<B & C>D' survives intact, just
    inert: it renders as written instead of being interpreted. Backends that
    render PLAIN text (tkinter, the terminal) must NOT call this -- there the
    escaped entities would show up literally as '&lt;', which is its own kind
    of corruption.
    """
    return html.escape(text, quote=True)


def _backslash_safe(text: str) -> str:
    """
    Protect a dialog's TEXT argument from the backend's own unescaping.

    Neither tool displays --text as given. zenity runs it through
    g_strcompress() before gtk_label_set_markup(), which decodes \\n, \\t and
    octal \\NNN -- so the plain ASCII a device can put in its product string,
    \\074a href=\\042...\\042\\076, came out as a live <a href="..."> link,
    AFTER _markup_safe had checked it and found no '<' to escape. kdialog's
    Utils::parseString() decodes \\n, which forges extra lines in the prompt,
    the thing textsafe escapes U+2028 and every real control character to
    prevent. Both decode a doubled backslash to one, so doubling every
    backslash makes the text they display exactly the text given.
    """
    return text.replace("\\", "\\\\")


# Three-way answers, matching the terminal prompt's [y]es once / [a]lways / [N]o.
CHOICE_ONCE = "once"
CHOICE_ALWAYS = "always"
CHOICE_NO = "no"


class DialogBackend:
    """A way of asking a question. Returns an answer, or None if no answer was
    obtained: the question could not be shown, or nobody answered in time.

    A timeout used to come back as "no", and was recorded as the user refusing
    the device -- which then warned "You have refused this device before" at
    the next plug, about a refusal nobody made. None is still never an
    approval: every caller treats it as falsy or maps it to "no decision"."""

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

    def notice(self, title: str, text: str, timeout: float) -> Optional[bool]:
        """
        Show text with a single button that approves nothing. Returns True if
        the person closed it, False if it stayed open for the whole timeout
        (it is then closed for them), None if it could not be shown.
        """
        raise NotImplementedError

    def confirm_countdown(self, title: str, text: str, yes_label: str,
                          no_label: str, delay: float,
                          timeout: float) -> Optional[bool]:
        """
        Like confirm(), but "yes" cannot be chosen until `delay` seconds have
        passed. For a device matching an attack pattern: approving it must
        take a decision, not a reflex.

        kdialog and zenity cannot disable a button for a while, so this is two
        windows: the findings first, in a window whose only button keeps the
        device blocked and which closes itself after `delay` seconds; then the
        real question. Closing the first window early keeps the device
        blocked. Backends that can draw a countdown button override this.
        """
        import time
        started = time.monotonic()
        early = self.notice(
            title,
            f"{text}\n\nRead this first. The choice to allow it appears "
            f"in {delay:.0f} seconds.\nPressing OK or closing this window "
            f"now keeps the device blocked.",
            timeout=delay)
        if early is None:
            return None
        if early:
            return False
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            return None
        return self.confirm(title, text, yes_label, no_label, remaining)


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
        # kdialog renders the body as Qt rich text, so the device-controlled
        # text is escaped; the title is our own string but escaped too for
        # uniformity and in case a device name is ever folded into it.
        args = [self._binary, "--title", _markup_safe(title),
                "--yes-label", yes_label, "--no-label", no_label,
                "--warningyesno", _backslash_safe(_markup_safe(text))]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return None         # left unanswered: no decision
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
        args = [self._binary, "--title", _markup_safe(title),
                "--yes-label", once_label,
                "--no-label", always_label,
                "--cancel-label", no_label,
                "--warningyesnocancel", _backslash_safe(_markup_safe(text))]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        if result.returncode == 0:
            return CHOICE_ONCE
        if result.returncode == 1:
            return CHOICE_ALWAYS
        return CHOICE_NO

    def notice(self, title: str, text: str, timeout: float) -> Optional[bool]:
        # --sorry: a warning icon and one "OK" button, which the text says
        # keeps the device blocked. When the time is up, subprocess.run kills
        # kdialog, which closes the window.
        args = [self._binary, "--title", _markup_safe(title),
                "--sorry", _backslash_safe(_markup_safe(text))]
        try:
            subprocess.run(args, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            return None
        return True


class ZenityBackend(DialogBackend):
    """GTK dialog tool, standard on GNOME and XFCE."""

    name = "zenity"

    def __init__(self):
        self._binary = shutil.which("zenity")

    def available(self) -> bool:
        return self._binary is not None

    def confirm(self, title: str, text: str, yes_label: str,
                no_label: str, timeout: float) -> Optional[bool]:
        # zenity's --text is interpreted as Pango markup by default. We escape
        # rather than pass --no-markup because --no-markup is absent on older
        # zenity builds and would make the call fail outright; html.escape
        # neutralises the same five characters Pango uses and works everywhere.
        args = [self._binary, "--question", "--title", _markup_safe(title),
                "--text", _backslash_safe(_markup_safe(text)),
                "--ok-label", yes_label, "--cancel-label", no_label,
                "--default-cancel"]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        return result.returncode == 0

    def choose(self, title: str, text: str, once_label: str,
               always_label: str, no_label: str,
               timeout: float) -> Optional[str]:
        # zenity has no third button, but --extra-button adds one that prints
        # its own label on stdout and exits non-zero. So: OK means once, the
        # extra button means always, and anything else is a refusal.
        args = [self._binary, "--question", "--title", _markup_safe(title),
                "--text", _backslash_safe(_markup_safe(text)),
                "--ok-label", once_label, "--cancel-label", no_label,
                "--extra-button", always_label, "--default-cancel"]
        try:
            result = subprocess.run(args, timeout=timeout,
                                    capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        if result.returncode == 0:
            return CHOICE_ONCE
        if (result.stdout or "").strip() == always_label:
            return CHOICE_ALWAYS
        return CHOICE_NO

    def notice(self, title: str, text: str, timeout: float) -> Optional[bool]:
        args = [self._binary, "--warning", "--title", _markup_safe(title),
                "--text", _backslash_safe(_markup_safe(text))]
        try:
            subprocess.run(args, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            return None
        return True


class TkinterBackend(DialogBackend):
    """
    A dialog drawn by Python itself, if the tk bindings are installed.

    Run in a subprocess rather than in-process: tkinter must own the main
    thread, and the agent has its own loop. A separate interpreter keeps the two
    from fighting, and means a broken tk install cannot take the agent down.
    """

    name = "tkinter"

    def available(self) -> bool:
        # Opening (and at once destroying) a root window, not just importing:
        # tkinter imports fine in a service with no $DISPLAY and then fails
        # at the first window, which is too late to pick another backend.
        try:
            result = subprocess.run(
                [self._python(), "-c",
                 "import tkinter; r = tkinter.Tk(); r.withdraw(); r.destroy()"],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # Exit codes the dialog scripts use for their answers. NOT 0/1/2: Python
    # exits 1 on any uncaught exception, so a tk that crashed read as "no"
    # from confirm() and as "Always allow" from choose() -- after the person
    # had clicked Allow once, a crash made the device trusted for good.
    # Anything that is not one of these is "no decision".
    _YES, _NO, _ALWAYS = 10, 11, 12

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
            f"sys.exit({self._YES} if answer else {self._NO})\n")
        try:
            result = subprocess.run(
                [self._python(), "-c", script, title, text],
                timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        if result.returncode not in (self._YES, self._NO):
            return None
        return result.returncode == self._YES

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
            f"sys.exit({self._YES} if answer is True else "
            f"({self._ALWAYS} if answer is False else {self._NO}))\n")
        try:
            result = subprocess.run(
                [self._python(), "-c", script, title,
                 f"{text}\n\nYes = {once_label}\nNo = {always_label}"],
                timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        if result.returncode == self._YES:
            return CHOICE_ONCE
        if result.returncode == self._ALWAYS:
            return CHOICE_ALWAYS
        if result.returncode == self._NO:
            return CHOICE_NO
        return None

    def confirm_countdown(self, title: str, text: str, yes_label: str,
                          no_label: str, delay: float,
                          timeout: float) -> Optional[bool]:
        # A real "Allow anyway (9)" button that stays disabled, in the
        # desktop's own colours: see countdown_dialog.py. Run by file path
        # under -I, so neither the environment nor the current directory can
        # decide what code draws it.
        from pathlib import Path
        script = str(Path(__file__).with_name("countdown_dialog.py"))
        try:
            result = subprocess.run(
                [self._python(), "-I", script, title, text,
                 yes_label, no_label, str(delay)],
                timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        if result.returncode not in (self._YES, self._NO):
            return None             # tk failed: no decision
        return result.returncode == self._YES


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
