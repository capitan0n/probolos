"""
Tests for the desktop agent.

Two properties matter more than the rest and are pinned here:

  * a CRITICAL device is never offered as a clickable question, only as a
    warning -- two clicks are too cheap for something matching an attack
    pattern;
  * an agent that cannot answer is not the same as an agent that said no. A
    missing answer falls back to the terminal, because refusing a device the
    user never saw is a decision nobody made.

The notification layer itself is exercised through a fake, since a real one
needs a desktop session. What is tested here is the protocol and the policy --
the parts where a mistake would be silent.
"""

import io
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cerberus import agentlink, daemon as daemon_mod, rules, sysfs, usbclass


class FakeAgent:
    """A minimal agent: connects, answers with whatever it was told to."""

    def __init__(self, path, answer=agentlink.ANSWER_YES, delay=0.0,
                 silent=False):
        self.path = str(path)
        self.answer = answer
        self.delay = delay
        self.silent = silent
        self.received = []
        self.sock = None
        self._stop = threading.Event()

    def start(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        for _ in range(50):
            try:
                self.sock.connect(self.path)
                break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("could not connect to the analyzer socket")
        self.sock.settimeout(0.5)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        buffer = b""
        while not self._stop.is_set():
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                message = json.loads(line.decode())
                self.received.append(message)
                if message.get("type") != agentlink.MSG_DECIDE or self.silent:
                    continue
                if self.delay:
                    time.sleep(self.delay)
                self.sock.sendall((json.dumps({
                    "type": agentlink.MSG_ANSWER,
                    "id": message["id"],
                    "answer": self.answer,
                }) + "\n").encode())

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()


class LinkTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "agent.sock"
        self.link = agentlink.AgentLink(self.path, log=lambda *a: None)
        self.assertTrue(self.link.start())
        self.agent = None

    def tearDown(self):
        if self.agent:
            self.agent.stop()
        self.link.stop()
        self.tmp.cleanup()

    def connect(self, **kwargs):
        self.agent = FakeAgent(self.path, **kwargs)
        self.agent.start()
        for _ in range(50):
            if self.link.connected:
                return
            time.sleep(0.02)
        raise AssertionError("link never registered the agent")


class TestAgentLink(LinkTestCase):

    def test_no_agent_means_no_answer_not_a_refusal(self):
        """
        Nothing connected. ask() must return None so the caller knows to fall
        back, rather than False which would refuse a device nobody was shown.
        """
        self.assertIsNone(self.link.ask("t", "b", "none", False, timeout=0.3))

    def test_a_yes_comes_back(self):
        self.connect(answer=agentlink.ANSWER_YES)
        self.assertEqual(self.link.ask("t", "b", "none", False, timeout=3),
                         agentlink.ANSWER_YES)

    def test_an_always_comes_back(self):
        self.connect(answer=agentlink.ANSWER_ALWAYS)
        self.assertEqual(self.link.ask("t", "b", "none", True, timeout=3),
                         agentlink.ANSWER_ALWAYS)

    def test_a_no_comes_back(self):
        self.connect(answer=agentlink.ANSWER_NO)
        self.assertEqual(self.link.ask("t", "b", "none", False, timeout=3),
                         agentlink.ANSWER_NO)

    def test_a_silent_agent_times_out_to_no_answer(self):
        """A connected but unresponsive agent must not hang the daemon."""
        self.connect(silent=True)
        started = time.monotonic()
        self.assertIsNone(self.link.ask("t", "b", "none", False, timeout=0.6))
        self.assertLess(time.monotonic() - started, 3.0)

    def test_the_question_reaches_the_agent_intact(self):
        self.connect()
        self.link.ask("Title here", "Body here", "WARNING", True, timeout=3)
        decide = [m for m in self.agent.received
                  if m["type"] == agentlink.MSG_DECIDE]
        self.assertEqual(decide[0]["title"], "Title here")
        self.assertTrue(decide[0]["allow_always"])

    def test_a_stale_answer_for_an_old_question_is_ignored(self):
        """
        A late click must never approve a device the user is not looking at now.
        """
        self.connect(silent=True)
        self.assertIsNone(self.link.ask("first", "b", "none", False, timeout=0.4))
        # Reply now, to the question that has already expired.
        self.agent.sock.sendall((json.dumps({
            "type": agentlink.MSG_ANSWER, "id": 1,
            "answer": agentlink.ANSWER_YES}) + "\n").encode())
        time.sleep(0.2)
        self.assertIsNone(self.link.ask("second", "b", "none", False,
                                        timeout=0.4))

    def test_critical_notification_offers_no_answer(self):
        self.connect()
        self.link.notify_critical("Dangerous", "storage that types")
        time.sleep(0.3)
        kinds = [m["type"] for m in self.agent.received]
        self.assertIn(agentlink.MSG_CRITICAL, kinds)
        self.assertNotIn(agentlink.MSG_DECIDE, kinds)

    def test_socket_is_not_world_accessible(self):
        """
        Anyone who can open this socket can approve hardware, so it must not be
        reachable by every local account.
        """
        import stat
        mode = self.path.stat().st_mode
        self.assertFalse(mode & stat.S_IROTH)
        self.assertFalse(mode & stat.S_IWOTH)


class TestDaemonUsesTheAgent(unittest.TestCase):
    """The policy: who gets asked what, and what happens when nobody answers."""

    def device(self, claims=None):
        dev = mock.Mock(spec=sysfs.UsbDevice)
        dev.name = "3-9"
        dev.syspath = Path("/sys/bus/usb/devices/3-9")
        dev.kinds = [usbclass.KIND_STORAGE]
        dev.claims = claims or ["Mass Storage (SCSI)"]
        dev.serial = "ABC"
        dev.vendor_id, dev.product_id = "0951", "1665"
        dev.label.return_value = "Test Stick"
        return dev

    def test_critical_is_never_asked_through_the_agent(self):
        """
        The whole point of the escalated terminal prompt is that it cannot be
        satisfied by clicking. Offering a CRITICAL device to a notification
        would undo it.
        """
        link = mock.Mock()
        link.connected = True
        engine = daemon_mod.Cerberus(agent=link, observe=0)
        finding = rules.Finding("storage-with-keyboard", rules.Severity.CRITICAL,
                                "Storage device that can also type", "")

        with mock.patch("sys.stdin", io.StringIO("no\n")):
            engine._ask(self.device(), [finding])

        link.ask.assert_not_called()
        link.notify_critical.assert_called_once()

    def test_a_normal_device_is_asked_through_the_agent(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_YES
        engine = daemon_mod.Cerberus(agent=link, observe=0)

        self.assertTrue(engine._ask(self.device(), []))
        link.ask.assert_called_once()

    def test_always_through_the_agent_sets_the_remember_flag(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_ALWAYS
        engine = daemon_mod.Cerberus(agent=link, trust_store=mock.Mock(),
                                     observe=0)
        engine._remember = False

        self.assertTrue(engine._ask(self.device(), []))
        self.assertTrue(engine._remember)

    def test_no_answer_falls_back_to_the_terminal(self):
        """
        An agent that could not answer has not made a decision. Treating its
        silence as a refusal would reject devices the user never saw.
        """
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = None
        engine = daemon_mod.Cerberus(agent=link, observe=0)

        with mock.patch("sys.stdin", io.StringIO("y\n")):
            self.assertTrue(engine._ask(self.device(), []),
                            "a missing agent answer must fall through to the "
                            "terminal, not become a refusal")

    def test_a_refusal_from_the_agent_is_respected(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_NO
        engine = daemon_mod.Cerberus(agent=link, observe=0)

        # stdin is left empty: if the terminal were consulted at all the test
        # would read EOF and deny, so the assertion below only proves the point
        # because the agent's answer is what is being respected.
        with mock.patch("sys.stdin", io.StringIO("y\n")):
            self.assertFalse(engine._ask(self.device(), []),
                             "an explicit refusal from the agent must stand, "
                             "not be re-asked on the terminal")

    def test_body_text_stays_short_enough_to_read(self):
        """
        A notification that must be scrolled will not be read, and an unread
        warning trains the habit of clicking through.
        """
        findings = [rules.Finding(f"r{i}", rules.Severity.NOTICE,
                                  f"Finding number {i}", "long explanation")
                    for i in range(6)]
        body = daemon_mod.Cerberus._agent_body(self.device(), findings)
        self.assertLessEqual(len(body.splitlines()), 6)
        self.assertIn("more finding", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDialogBackends(unittest.TestCase):
    """
    The dialog is now where the decision happens, so its failure modes matter
    more than the notification's.
    """

    def test_detect_returns_none_when_nothing_is_installed(self):
        from cerberus import dialogs
        with mock.patch.object(dialogs.shutil, "which", return_value=None), \
             mock.patch.object(dialogs.TkinterBackend, "available",
                               return_value=False):
            self.assertIsNone(dialogs.detect(log=lambda *a: None))

    def test_detect_prefers_kdialog(self):
        from cerberus import dialogs
        with mock.patch.object(dialogs.shutil, "which",
                               side_effect=lambda n: f"/usr/bin/{n}"):
            self.assertEqual(dialogs.detect(log=lambda *a: None).name,
                             "kdialog")

    def test_a_timed_out_dialog_is_a_refusal(self):
        """
        Left unanswered means no. A dialog nobody dealt with must not become an
        approval just because it went away.
        """
        from cerberus import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="kdialog", timeout=1)):
            self.assertIs(backend.confirm("t", "x", "y", "n", 1.0), False)

    def test_a_dialog_that_cannot_run_returns_none_not_false(self):
        """
        None means "could not ask", which is different from "was refused" -- the
        caller falls back to the terminal instead of rejecting silently.
        """
        from cerberus import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=OSError("no display")):
            self.assertIsNone(backend.confirm("t", "x", "y", "n", 1.0))

    def test_nonzero_exit_is_a_refusal(self):
        from cerberus import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        completed = mock.Mock(returncode=1)
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=completed):
            self.assertIs(backend.confirm("t", "x", "y", "n", 1.0), False)

    def test_zero_exit_is_an_approval(self):
        from cerberus import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        completed = mock.Mock(returncode=0)
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=completed):
            self.assertIs(backend.confirm("t", "x", "y", "n", 1.0), True)


class TestAgentNeedsTwoYeses(unittest.TestCase):
    """One misplaced click must never energise unknown hardware."""

    def build(self):
        from cerberus import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance

    def test_both_dialogs_must_be_confirmed(self):
        from cerberus.agentlink import ANSWER_NO, ANSWER_YES
        agent = self.build()

        agent.dialog.confirm.side_effect = [True, True]
        self.assertEqual(agent._ask_user({"title": "t", "body": "b"}, 30),
                         ANSWER_YES)

        agent.dialog.confirm.side_effect = [True, False]
        self.assertEqual(agent._ask_user({"title": "t", "body": "b"}, 30),
                         ANSWER_NO, "the second dialog must be able to cancel")

        agent.dialog.confirm.side_effect = [False]
        self.assertEqual(agent._ask_user({"title": "t", "body": "b"}, 30),
                         ANSWER_NO)

    def test_always_requires_both_dialogs_too(self):
        """
        With a trust store the second dialog is the three-way one, so 'always'
        still needs the first dialog approved AND the choice made explicitly.
        """
        from cerberus import dialogs
        from cerberus.agentlink import ANSWER_ALWAYS, ANSWER_NO
        agent = self.build()

        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_ALWAYS
        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": True},
                            30),
            ANSWER_ALWAYS)

        # Refusing the FIRST dialog must stop it reaching the choice at all.
        agent.dialog.confirm.return_value = False
        agent.dialog.choose.reset_mock()
        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": True},
                            30),
            ANSWER_NO)
        agent.dialog.choose.assert_not_called()


class TestThreeWayChoice(unittest.TestCase):
    """
    The graphical path must offer the same outcomes as the terminal one. When it
    only had Allow/Cancel, "allow" implied "remember forever" -- so the
    convenient path granted MORE than the inconvenient path, which is exactly
    backwards for a security tool.
    """

    def build(self):
        from cerberus import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance

    def test_once_is_reachable_without_being_remembered(self):
        from cerberus import dialogs
        from cerberus.agentlink import ANSWER_YES
        agent = self.build()
        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_ONCE

        answer = agent._ask_user(
            {"title": "t", "body": "b", "allow_always": True}, 30)
        self.assertEqual(answer, ANSWER_YES,
                         "'just this once' must not create a trust entry")

    def test_always_is_reachable_and_distinct(self):
        from cerberus import dialogs
        from cerberus.agentlink import ANSWER_ALWAYS
        agent = self.build()
        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_ALWAYS

        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": True},
                            30),
            ANSWER_ALWAYS)

    def test_cancel_on_the_second_dialog_refuses(self):
        from cerberus import dialogs
        from cerberus.agentlink import ANSWER_NO
        agent = self.build()
        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_NO

        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": True},
                            30),
            ANSWER_NO)

    def test_without_a_trust_store_only_two_buttons_are_used(self):
        """No trust store means nothing to remember, so the three-way question
        would offer a choice that does nothing."""
        from cerberus.agentlink import ANSWER_YES
        agent = self.build()
        agent.dialog.confirm.side_effect = [True, True]

        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": False},
                            30),
            ANSWER_YES)
        agent.dialog.choose.assert_not_called()


class TestKdialogThreeWayMapping(unittest.TestCase):
    """kdialog exit codes: 0 = yes, 1 = no, 2 = cancel."""

    def backend(self):
        from cerberus import dialogs
        b = dialogs.KDialogBackend()
        b._binary = "/usr/bin/kdialog"
        return b

    def test_exit_codes_map_to_the_three_choices(self):
        from cerberus import dialogs
        cases = {0: dialogs.CHOICE_ONCE, 1: dialogs.CHOICE_ALWAYS,
                 2: dialogs.CHOICE_NO}
        for code, expected in cases.items():
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertEqual(
                    self.backend().choose("t", "x", "once", "always", "no", 5),
                    expected)

    def test_a_timeout_refuses(self):
        from cerberus import dialogs
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="kdialog", timeout=1)):
            self.assertEqual(
                self.backend().choose("t", "x", "once", "always", "no", 1),
                dialogs.CHOICE_NO)
