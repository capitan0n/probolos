"""
Regression tests: text and keystrokes that crossed a boundary they should not.

Each test fails on the code as it stood before the matching fix, except those
marked GUARD, which check that a fix did not break what it touches.

  * gdbus parses its arguments as GVariant text, so backslash escapes that a
    device wrote as plain ASCII became markup and bidi controls in the
    notification -- after textsafe and html.escape had both passed them.
  * zenity g_strcompress()es and kdialog parseString()s the dialog text, with
    the same effect in the dialog that takes the decision.
  * keystrokes a device sent before EVIOCGRAB were read as the answer to the
    terminal prompt about that same device.
  * the privsep analyzer kept the terminal as its controlling tty, so it could
    TIOCSTI a command into the shell that started Probolos.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import io
import json
import os
import pty
import select
import signal
import termios
import time
import types
import unittest
from unittest import mock

from probolos import agent, daemon, dialogs, privsep

# One backslash. The hostile strings below are plain printable ASCII -- exactly
# what textsafe lets through, because nothing in them is a control character.
B = "\\"


def _glib():
    name = ctypes.util.find_library("glib-2.0")
    if not name:
        return None
    try:
        return ctypes.CDLL(name)
    except OSError:
        return None


class NotificationArgumentsAreLiterals(unittest.TestCase):
    """gdbus decoded escapes in every bare string argument."""

    HOSTILE = ("Kingston " + B + "u003ca href=" + B + "u0022https://evil.example"
               + B + "u0022" + B + "u003eok" + B + "u003c/a" + B + "u003e "
               + B + "u202eevil" + B + "n")

    def _argv(self, summary, body):
        notifier = agent.Notifier(log=lambda *_a: None)
        notifier._gdbus = "/usr/bin/gdbus"
        with mock.patch("subprocess.run") as run:
            run.return_value = types.SimpleNamespace(
                returncode=0, stdout="(uint32 7,)", stderr="")
            notifier.notify(summary, body, actionable=False)
        return run.call_args[0][0]

    def test_every_literal_decodes_to_exactly_its_text(self):
        # The escapes emitted (\\ \" \n \u00XX) are the subset GVariant text
        # and JSON share, so JSON is an independent decoder for them.
        for text in ("plain", 'a "quoted" word', B, B + B + "n",
                     "line\nbreak", "tab\tstop", "é — ü", "", chr(0x7F),
                     self.HOSTILE):
            self.assertEqual(json.loads(agent._gvariant_string(text)), text)

    def test_device_escapes_reach_the_server_as_typed(self):
        argv = self._argv("New USB device", self.HOSTILE)
        body = json.loads(argv[argv.index('"New USB device"') + 1])
        self.assertIn(B + "u003ca href", body)
        self.assertNotIn("<", body)
        self.assertNotIn(chr(0x202E), body)

    @unittest.skipIf(_glib() is None, "libglib-2.0 not available")
    def test_glib_parses_each_literal_back_to_the_text(self):
        lib = _glib()
        lib.g_variant_parse.restype = ctypes.c_void_p
        lib.g_variant_parse.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                        ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p]
        lib.g_variant_get_string.restype = ctypes.c_char_p
        lib.g_variant_get_string.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.g_variant_unref.argtypes = [ctypes.c_void_p]
        body = dialogs._markup_safe(self.HOSTILE) + "\n\nBlocked — waiting"
        for text in (self.HOSTILE, body, 'a "b" c'):
            value = lib.g_variant_parse(
                b"s", agent._gvariant_string(text).encode(), None, None, None)
            self.assertTrue(value, f"GLib refused the literal for {text!r}")
            try:
                self.assertEqual(
                    lib.g_variant_get_string(value, None).decode(), text)
            finally:
                lib.g_variant_unref(value)


class DialogTextIsNotUnescapedByTheBackend(unittest.TestCase):
    """zenity and kdialog decode backslash escapes in the text they show."""

    OCTAL = (B + "074a href=" + B + "042https://evil.example" + B + "042"
             + B + "076ok" + B + "074/a" + B + "076")
    FORGED_LINES = "Kingston" + B + "n" + B + "nNo findings. Safe to allow."

    @staticmethod
    def _argv(backend_cls, method, text):
        backend = backend_cls()
        backend._binary = "/usr/bin/dialog-tool"
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=mock.Mock(returncode=1,
                                                      stdout="")) as run:
            if method == "confirm":
                backend.confirm("t", text, "y", "n", 1.0)
            else:
                backend.choose("t", text, "once", "always", "no", 1.0)
        return run.call_args[0][0]

    @staticmethod
    def _kdialog_shows(text):
        """kdialog's Utils::parseString(): \\\\ -> \\, \\n -> newline."""
        out, escaped = [], False
        for char in text:
            if escaped:
                escaped = False
                out.append(char if char == B
                           else "\n" if char == "n" else B + char)
            elif char == B:
                escaped = True
            else:
                out.append(char)
        if escaped:
            out.append(B)
        return "".join(out)

    def test_kdialog_shows_the_text_it_was_given(self):
        for method in ("confirm", "choose"):
            shown = self._kdialog_shows(
                self._argv(dialogs.KDialogBackend, method,
                           self.FORGED_LINES)[-1])
            self.assertNotIn("\n", shown)
            self.assertEqual(shown, dialogs._markup_safe(self.FORGED_LINES))

    @unittest.skipIf(_glib() is None, "libglib-2.0 not available")
    def test_zenity_shows_the_text_it_was_given(self):
        lib = _glib()
        lib.g_strcompress.restype = ctypes.c_void_p
        lib.g_strcompress.argtypes = [ctypes.c_char_p]
        lib.g_free.argtypes = [ctypes.c_void_p]
        for method in ("confirm", "choose"):
            argv = self._argv(dialogs.ZenityBackend, method, self.OCTAL)
            pointer = lib.g_strcompress(argv[argv.index("--text") + 1].encode())
            try:
                shown = ctypes.string_at(pointer).decode()
            finally:
                lib.g_free(pointer)
            self.assertNotIn("<", shown)
            self.assertEqual(shown, dialogs._markup_safe(self.OCTAL))


class PromptIgnoresTypeAhead(unittest.TestCase):
    """A line queued before the question was asked answered it."""

    def setUp(self):
        try:
            self.master, self.slave = pty.openpty()
        except OSError as exc:
            self.skipTest(f"no pseudo-terminal: {exc}")
        self.stdin = os.fdopen(os.dup(self.slave), "r")

    def tearDown(self):
        self.stdin.close()
        os.close(self.master)
        os.close(self.slave)

    def _type_early(self, data: bytes) -> None:
        """What a device sends before the grab, landing in this terminal."""
        os.write(self.master, data)
        ready, _, _ = select.select([self.slave], [], [], 2.0)
        self.assertTrue(ready, "the pty never delivered the input")

    def _ask(self, findings=()):
        engine = daemon.Probolos(timeout=0.3)
        out = io.StringIO()
        with mock.patch("sys.stdin", self.stdin), mock.patch("sys.stdout", out):
            approved = engine._ask(types.SimpleNamespace(name="1-4"),
                                   list(findings))
        return approved, out.getvalue()

    def test_a_queued_yes_does_not_approve(self):
        self._type_early(b"y\n")
        approved, out = self._ask()
        self.assertFalse(approved)
        self.assertIn("Discarded 2 byte(s)", out)

    def test_a_queued_authorize_does_not_pass_a_critical_prompt(self):
        from probolos import rules
        critical = rules.Finding(rule_id="t", severity=rules.Severity.CRITICAL,
                                 title="t", explanation="t")
        self._type_early(b"authorize\n")
        approved, out = self._ask([critical])
        self.assertFalse(approved)
        self.assertIn("Discarded 10 byte(s)", out)

    def test_nothing_is_left_for_the_next_reader(self):
        self._type_early(b"y\n")
        with mock.patch("sys.stdin", self.stdin):
            self.assertEqual(daemon.Probolos._discard_typeahead(), 2)
        ready, _, _ = select.select([self.slave], [], [], 0.1)
        self.assertFalse(ready)

    def test_input_that_is_not_a_terminal_is_left_alone(self):
        """GUARD: piped or scripted input is not a terminal to flush."""
        with mock.patch("sys.stdin", io.StringIO("y\n")):
            self.assertEqual(daemon.Probolos._discard_typeahead(), 0)
            self.assertEqual(daemon.Probolos(timeout=0)._ask(
                types.SimpleNamespace(name="1-4"), []), True)


@unittest.skipUnless(os.geteuid() == 0, "privsep.start() needs root")
class AnalyzerHasNoControllingTerminal(unittest.TestCase):
    """The analyzer could TIOCSTI into the terminal Probolos was started from."""

    def _run(self, analyzer_body, while_running=None) -> str:
        """
        privsep.start() as a job started from a shell on a terminal.

        The pty child plays the shell: it leads the terminal's session and
        runs the gate in a foreground process group of its own, as a shell
        does. Without that layer the gate's group is orphaned, and the kernel
        discards Ctrl-Z for orphaned groups, which would hide the difference
        the job-control test is about. The "shell" reports on the pipe if the
        gate is ever stopped, and resumes it.
        """
        try:
            privsep.resolve_user("nobody")
        except privsep.PrivsepError as exc:
            self.skipTest(str(exc))
        read_end, write_end = os.pipe()
        pid, master = pty.fork()
        if pid == 0:
            os.close(read_end)
            try:
                gate = os.fork()
                if gate == 0:
                    os.setpgid(0, 0)
                    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                    os.tcsetpgrp(0, os.getpid())
                    signal.signal(signal.SIGTTOU, signal.SIG_DFL)

                    def analyzer_main(_gate):
                        analyzer_body(write_end)
                        return 0
                    try:
                        privsep.start(analyzer_main, log=lambda *_a: None)
                    finally:
                        os._exit(0)
                while True:
                    _pid, status = os.waitpid(gate, os.WUNTRACED)
                    if not os.WIFSTOPPED(status):
                        break
                    os.write(write_end, b"gate-stopped ")
                    os.killpg(gate, signal.SIGCONT)
            finally:
                os._exit(0)
        os.close(write_end)
        report = b""
        finished = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([read_end, master], [], [], 0.2)
                if master in ready:
                    try:
                        os.read(master, 4096)
                    except OSError:
                        pass
                if read_end in ready:
                    chunk = os.read(read_end, 4096)
                    if not chunk:
                        finished = True
                        break
                    report += chunk
                    if while_running is not None and b"ready" in report:
                        while_running(master)
                        while_running = None
        finally:
            os.close(read_end)
            if not finished:
                os.kill(pid, signal.SIGKILL)   # fail, never hang the suite
            os.waitpid(pid, 0)
            os.close(master)
        return report.decode()

    def test_the_analyzer_leads_its_own_session_and_cannot_inject(self):
        import fcntl

        def body(out):
            own = os.getsid(0) == os.getpid()
            try:
                fcntl.ioctl(0, termios.TIOCSTI, b"X")
                injected = "injected"
            except OSError:
                injected = "refused"
            os.write(out, f"session={own} tiocsti={injected}".encode())

        self.assertEqual(self._run(body), "session=True tiocsti=refused")

    @staticmethod
    def _wait_for_ctrl_c(out):
        os.write(out, b"ready ")
        try:
            time.sleep(10)
            os.write(out, b"no-sigint")
        except KeyboardInterrupt:
            os.write(out, b"sigint")

    def test_ctrl_c_at_the_terminal_still_reaches_the_analyzer(self):
        """GUARD: off the terminal's session, Ctrl-C is forwarded by the gate."""
        self.assertEqual(
            self._run(self._wait_for_ctrl_c,
                      while_running=lambda m: os.write(m, b"\x03")),
            "ready sigint")

    def test_ctrl_z_does_not_suspend_the_gate(self):
        """GUARD: a suspended gate would hand the shell a terminal the
        analyzer, outside job control now, is still reading."""
        def press_ctrl_z_then_ctrl_c(master):
            os.write(master, b"\x1a")
            time.sleep(0.3)
            os.write(master, b"\x03")

        self.assertEqual(
            self._run(self._wait_for_ctrl_c, press_ctrl_z_then_ctrl_c),
            "ready sigint")


if __name__ == "__main__":
    unittest.main()
