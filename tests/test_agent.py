"""
The desktop agent: the socket it answers on, who may reach it, the dialog
backends, and what the daemon does with its answers.

Covers probolos.agent, probolos.agentlink and probolos.dialogs.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import io
import json
import os
import socket
import stat
import subprocess
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from probolos import agent, agentlink, dialogs, rules, sysfs, usbclass
from probolos import agent as agent_mod
from probolos import daemon as daemon_mod
from probolos.agentlink import (
    ANSWER_ALWAYS,
    ANSWER_NO,
    ANSWER_YES,
    MSG_ANSWER,
    AgentLink,
    peer_credentials,
)


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


SETTLE = 0.15           # let the accept thread run before asserting on it


def _quiet(*_args, **_kwargs):
    pass


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
        engine = daemon_mod.Probolos(agent=link, observe=0)
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
        engine = daemon_mod.Probolos(agent=link, observe=0)

        self.assertTrue(engine._ask(self.device(), []))
        link.ask.assert_called_once()

    def test_always_through_the_agent_sets_the_remember_flag(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_ALWAYS
        engine = daemon_mod.Probolos(agent=link, trust_store=mock.Mock(),
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
        engine = daemon_mod.Probolos(agent=link, observe=0)

        with mock.patch("sys.stdin", io.StringIO("y\n")):
            self.assertTrue(engine._ask(self.device(), []),
                            "a missing agent answer must fall through to the "
                            "terminal, not become a refusal")

    def test_a_refusal_from_the_agent_is_respected(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_NO
        engine = daemon_mod.Probolos(agent=link, observe=0)

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
        body = daemon_mod.Probolos._agent_body(self.device(), findings)
        self.assertLessEqual(len(body.splitlines()), 6)
        self.assertIn("more finding", body)


class TestDialogBackends(unittest.TestCase):
    """
    The dialog is now where the decision happens, so its failure modes matter
    more than the notification's.
    """

    def test_detect_returns_none_when_nothing_is_installed(self):
        from probolos import dialogs
        with mock.patch.object(dialogs.shutil, "which", return_value=None), \
             mock.patch.object(dialogs.TkinterBackend, "available",
                               return_value=False):
            self.assertIsNone(dialogs.detect(log=lambda *a: None))

    def test_detect_prefers_kdialog(self):
        from probolos import dialogs
        with mock.patch.object(dialogs.shutil, "which",
                               side_effect=lambda n: f"/usr/bin/{n}"):
            self.assertEqual(dialogs.detect(log=lambda *a: None).name,
                             "kdialog")

    def test_a_timed_out_dialog_is_a_refusal(self):
        """
        Left unanswered means no. A dialog nobody dealt with must not become an
        approval just because it went away.
        """
        from probolos import dialogs
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
        from probolos import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=OSError("no display")):
            self.assertIsNone(backend.confirm("t", "x", "y", "n", 1.0))

    def test_nonzero_exit_is_a_refusal(self):
        from probolos import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        completed = mock.Mock(returncode=1)
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=completed):
            self.assertIs(backend.confirm("t", "x", "y", "n", 1.0), False)

    def test_zero_exit_is_an_approval(self):
        from probolos import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        completed = mock.Mock(returncode=0)
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=completed):
            self.assertIs(backend.confirm("t", "x", "y", "n", 1.0), True)


class TestAgentNeedsTwoYeses(unittest.TestCase):
    """One misplaced click must never energise unknown hardware."""

    def build(self):
        from probolos import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance

    def test_both_dialogs_must_be_confirmed(self):
        from probolos.agentlink import ANSWER_NO, ANSWER_YES
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
        from probolos import dialogs
        from probolos.agentlink import ANSWER_ALWAYS, ANSWER_NO
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
        from probolos import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance

    def test_once_is_reachable_without_being_remembered(self):
        from probolos import dialogs
        from probolos.agentlink import ANSWER_YES
        agent = self.build()
        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_ONCE

        answer = agent._ask_user(
            {"title": "t", "body": "b", "allow_always": True}, 30)
        self.assertEqual(answer, ANSWER_YES,
                         "'just this once' must not create a trust entry")

    def test_always_is_reachable_and_distinct(self):
        from probolos import dialogs
        from probolos.agentlink import ANSWER_ALWAYS
        agent = self.build()
        agent.dialog.confirm.return_value = True
        agent.dialog.choose.return_value = dialogs.CHOICE_ALWAYS

        self.assertEqual(
            agent._ask_user({"title": "t", "body": "b", "allow_always": True},
                            30),
            ANSWER_ALWAYS)

    def test_cancel_on_the_second_dialog_refuses(self):
        from probolos import dialogs
        from probolos.agentlink import ANSWER_NO
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
        from probolos.agentlink import ANSWER_YES
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
        from probolos import dialogs
        b = dialogs.KDialogBackend()
        b._binary = "/usr/bin/kdialog"
        return b

    def test_exit_codes_map_to_the_three_choices(self):
        from probolos import dialogs
        cases = {0: dialogs.CHOICE_ONCE, 1: dialogs.CHOICE_ALWAYS,
                 2: dialogs.CHOICE_NO}
        for code, expected in cases.items():
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertEqual(
                    self.backend().choose("t", "x", "once", "always", "no", 5),
                    expected)

    def test_a_timeout_refuses(self):
        from probolos import dialogs
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="kdialog", timeout=1)):
            self.assertEqual(
                self.backend().choose("t", "x", "once", "always", "no", 1),
                dialogs.CHOICE_NO)


class TestServePassesAgentUid(unittest.TestCase):
    """
    Regression for audit finding C2: the SO_PEERCRED check in AgentLink._admit
    is only armed when allowed_uids is passed. It was never passed from serve(),
    so the check was dead code and any local process could answer prompts.

    These tests pin the wiring, not the check itself (agentlink's own tests
    cover the check). serve() is short-circuited right after it builds the link
    so the pyudev loop never runs.
    """

    def _run_serve(self, **kwargs):
        captured = {}
        sentinel = RuntimeError("stop here")

        def fake_link(path, allowed_uids=None, owner_uid=None, owner_gid=None):
            captured["allowed_uids"] = allowed_uids
            captured["owner_uid"] = owner_uid
            link = mock.Mock()
            # Stop serve() the instant the link is built, before it tries to
            # open the real USB gate (which needs /sys/bus/usb we do not have).
            link.start.side_effect = sentinel
            return link

        with mock.patch.object(daemon_mod.agentlink, "AgentLink",
                               side_effect=fake_link):
            try:
                daemon_mod.serve(**kwargs)
            except RuntimeError as exc:
                if exc is not sentinel:
                    raise
        return captured

    def test_agent_uid_is_forwarded_as_allowed_uids(self):
        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / "sock"
            captured = self._run_serve(agent_socket=sock, agent_uid=1000)
        # root is always allowed alongside the desktop uid; see the comment in
        # serve() for why refusing uid 0 would buy nothing.
        self.assertEqual(captured["allowed_uids"], {1000, 0})

    def test_no_agent_uid_means_no_restriction_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / "sock"
            captured = self._run_serve(agent_socket=sock, agent_uid=None)
        # None is the documented "any local process" fallback -- but note
        # AgentLink.start() prints a warning in that case so it is not silent.
        self.assertIsNone(captured["allowed_uids"])


class AgentSocketHardening(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.log_lines = []
        self.servers = []
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            try:
                client.close()
            except OSError:
                pass
        for server in self.servers:
            server.stop()
        self._dir.cleanup()

    # ---- helpers ----

    def server(self, allowed_uids=None, quiet=True):
        link = AgentLink(Path(self._dir.name) / f"agent{time.time_ns()}.sock",
                         log=_quiet if quiet else self.log_lines.append,
                         allowed_uids=allowed_uids)
        self.assertTrue(link.start())
        self.servers.append(link)
        return link

    def client(self, link):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(link.path))
        self.clients.append(sock)
        time.sleep(SETTLE)
        return sock

    @staticmethod
    def _answer_honestly(sock, answer, box=None, delay=0.0):
        """Behave like the real agent: read the question, echo its id back."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buffer += chunk
        question = json.loads(buffer.split(b"\n", 1)[0])
        if box is not None:
            box["id"] = question["id"]
        if delay:
            time.sleep(delay)
        try:
            sock.sendall((json.dumps({
                "type": MSG_ANSWER, "id": question["id"], "answer": answer,
            }) + "\n").encode())
        except OSError:
            pass

    def _agent_thread(self, sock, answer, box=None, delay=0.0):
        thread = threading.Thread(
            target=self._answer_honestly, args=(sock, answer, box, delay),
            daemon=True)
        thread.start()
        return thread

    # ---- F1a: answers sent before the question exists ----

    def test_present_answers_do_not_approve_a_device(self):
        """
        A client that fills the buffer with {"id":1..5,"answer":"always"}
        before any device is attached used to win: ids counted from 1, so the
        first real question was answered instantly from the buffer with no
        dialog shown and no human involved.
        """
        link = self.server()
        client = self.client(link)
        for guess in range(1, 6):
            client.sendall((json.dumps({
                "type": MSG_ANSWER, "id": guess, "answer": ANSWER_ALWAYS,
            }) + "\n").encode())
        time.sleep(SETTLE)

        self.assertIsNone(link.ask("dev", "body", "INFO", True, 0.5))

    def test_request_ids_are_not_sequential(self):
        """Two consecutive questions must not have adjacent, guessable ids."""
        link = self.server()
        client = self.client(link)
        seen = []
        for _ in range(2):
            box = {}
            self._agent_thread(client, ANSWER_NO, box=box)
            link.ask("dev", "body", "INFO", True, 2.0)
            seen.append(box["id"])

        self.assertNotEqual(seen[0], seen[1])
        self.assertGreater(min(seen), 2 ** 40)
        self.assertNotEqual(seen[1] - seen[0], 1)

    # ---- F1b: connection hijacking ----

    def test_second_connection_cannot_evict_the_live_agent(self):
        """
        Accepting each new connection over the old one meant anything that
        could open the socket became the thing answering questions about
        hardware. The running agent must keep the slot.
        """
        link = self.server()
        real = self.client(link)
        intruder = self.client(link)

        try:
            intruder.sendall((json.dumps({
                "type": MSG_ANSWER, "id": 1, "answer": ANSWER_ALWAYS,
            }) + "\n").encode())
        except OSError:
            pass                        # refused connections are closed at once

        box = {}
        self._agent_thread(real, ANSWER_NO, box=box)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0), ANSWER_NO)
        self.assertGreater(box["id"], 2 ** 40)

    def test_dead_agent_is_still_replaced(self):
        """
        The other half of the invariant: refusing every second connection
        would break logout, crash and session change. Only a LIVE agent is
        protected.
        """
        link = self.server()
        first = self.client(link)
        first.close()
        time.sleep(SETTLE)

        second = self.client(link)
        self._agent_thread(second, ANSWER_YES)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0), ANSWER_YES)

    # ---- F1c: peer credentials ----

    def test_connection_from_a_foreign_uid_is_refused(self):
        link = self.server(allowed_uids={os.getuid() + 4242}, quiet=False)
        self.client(link)

        self.assertFalse(link.connected)
        self.assertTrue(any("REFUSED" in line for line in self.log_lines))

    def test_connection_from_the_permitted_uid_is_accepted(self):
        link = self.server(allowed_uids={os.getuid()})
        agent = self.client(link)

        self.assertTrue(link.connected)
        self.assertEqual(link.peer[1], os.getuid())
        self._agent_thread(agent, ANSWER_ALWAYS)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0),
                         ANSWER_ALWAYS)

    def test_peer_credentials_report_this_process(self):
        """SO_PEERCRED must be readable at all, on every supported kernel."""
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            pid, uid, gid = peer_credentials(left)
        finally:
            left.close()
            right.close()
        self.assertEqual((pid, uid, gid), (os.getpid(), os.getuid(), os.getgid()))

    # ---- resource and timing bounds ----

    def test_reply_without_a_newline_cannot_grow_without_limit(self):
        """
        MAX_MESSAGE bounded each recv() but not their sum. A peer sending
        bytes and never a line ending grew the buffer until the timeout.
        """
        link = self.server()
        client = self.client(link)

        def flood():
            # Keep sending until the server closes the connection on us. The
            # exact iteration count is not the point -- the point is that the
            # sum crosses MAX_MESSAGE before any newline arrives. Looping until
            # OSError makes that independent of how the two threads interleave,
            # which differs between interpreter versions.
            try:
                while True:
                    client.sendall(b"A" * 4096)
            except OSError:
                pass

        threading.Thread(target=flood, daemon=True).start()
        self.assertIsNone(link.ask("dev", "body", "INFO", True, 10.0))
        self.assertFalse(link.connected)

    def test_answer_arriving_after_the_deadline_is_not_honoured(self):
        """
        The loop checked the deadline only before blocking for a full second,
        so an answer up to a second late was still accepted -- after the user
        had been shown a dialog counting down to that deadline.
        """
        link = self.server()
        client = self.client(link)
        self._agent_thread(client, ANSWER_ALWAYS, delay=1.0)

        started = time.monotonic()
        self.assertIsNone(link.ask("dev", "body", "INFO", True, 0.4))
        self.assertLess(time.monotonic() - started, 0.9)

    def test_a_late_answer_does_not_resolve_the_next_question(self):
        """A reply to question N must not be spent on question N+1."""
        link = self.server()
        client = self.client(link)
        self._agent_thread(client, ANSWER_ALWAYS, delay=0.8)

        self.assertIsNone(link.ask("first", "body", "INFO", True, 0.4))
        self.assertIsNone(link.ask("second", "body", "INFO", True, 0.4))


class SocketOwnership(unittest.TestCase):
    """
    Regression for the no-privsep agent socket being unreachable.

    Observed on a real run: `sudo python -m probolos --agent` (no --privsep)
    left /run/probolos/agent.sock owned root:root 0660, so the agent -- which
    runs as the desktop user -- got EACCES on connect(). start() must chown the
    socket to the desktop owner when it bound it as root.

    os.geteuid and os.chown are patched so the logic is exercised without
    actually being root and without touching real ownership.
    """

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)

    def _link(self, **kw):
        from probolos.agentlink import AgentLink
        return AgentLink(Path(self._dir.name) / "s.sock",
                         log=lambda *_: None, **kw)

    def test_root_bind_chowns_socket_to_owner(self):
        from probolos import agentlink
        link = self._link(owner_uid=1000, owner_gid=1000)
        calls = []
        with mock.patch.object(agentlink.os, "geteuid", return_value=0), \
             mock.patch("probolos.securefs.open_directory",
                        side_effect=lambda p, **kw: os.open(p, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(agentlink.os, "chown",
                               side_effect=lambda p, u, g, **kw:
                                   calls.append((u, g, kw))):
            self.assertTrue(link.start())
        link.stop()
        self.assertTrue(any(c[:2] == (1000, 1000) for c in calls),
                        "socket was not handed to the desktop user")
        # And it must be done relative to the descriptor that was verified,
        # without following a link: by name, a symlink planted at the socket
        # path between bind() and here is a root chown of an arbitrary file.
        kwargs = [c[2] for c in calls if c[:2] == (1000, 1000)][0]
        self.assertIn("dir_fd", kwargs)
        self.assertIs(kwargs.get("follow_symlinks"), False)

    def test_non_root_does_not_attempt_chown(self):
        from probolos import agentlink
        link = self._link(owner_uid=1000, owner_gid=1000)
        with mock.patch.object(agentlink.os, "geteuid", return_value=1000), \
             mock.patch.object(agentlink.os, "chown") as chown:
            self.assertTrue(link.start())
        link.stop()
        chown.assert_not_called()

    def test_no_owner_does_not_attempt_chown(self):
        from probolos import agentlink
        link = self._link()   # owner_uid None: --privsep case
        with mock.patch.object(agentlink.os, "geteuid", return_value=0), \
             mock.patch("probolos.securefs.open_directory",
                        side_effect=lambda p, **kw: os.open(p, os.O_RDONLY | os.O_DIRECTORY)), \
             mock.patch.object(agentlink.os, "chown") as chown:
            self.assertTrue(link.start())
        link.stop()
        chown.assert_not_called()


class SocketDirectoryIsNotGroupWritable(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "probolos"
        patcher = mock.patch.object(agentlink, "DEFAULT_SOCKET",
                                    self.root / "agent.sock")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_group_cannot_replace_the_socket(self):
        agentlink.prepare_socket_dir(self.root / "agent.sock",
                                     os.getuid(), os.getgid())
        mode = stat.S_IMODE(os.stat(self.root).st_mode)
        self.assertFalse(mode & stat.S_IWGRP,
                         f"directory is group-writable (mode {mode:04o}); "
                         f"anyone in that group can unlink the agent socket "
                         f"and bind their own listener in its place")
        self.assertFalse(mode & (stat.S_IRWXO),
                         f"directory is reachable by others (mode {mode:04o})")

    def test_group_can_still_traverse_to_the_socket(self):
        """
        The permission that must survive: without group execute the desktop
        agent cannot reach the socket at all and the prompt disappears.
        """
        agentlink.prepare_socket_dir(self.root / "agent.sock",
                                     os.getuid(), os.getgid())
        mode = stat.S_IMODE(os.stat(self.root).st_mode)
        self.assertTrue(mode & stat.S_IXGRP, "group lost traverse permission")
        self.assertTrue(mode & stat.S_ISGID,
                        "setgid dropped; the socket would not inherit the "
                        "desktop group and the agent could not open it")

    def test_the_directory_must_stay_under_the_runtime_root(self):
        with self.assertRaises(OSError):
            agentlink.prepare_socket_dir(Path("/etc/probolos-agent.sock"),
                                         os.getuid(), os.getgid())


class SocketMetadataIsNotChangedByName(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.sock_path = self.dir / "agent.sock"

    def test_the_socket_is_never_group_readable_by_accident(self):
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None,
                                   allowed_uids={os.getuid()})
        self.assertTrue(link.start())
        self.addCleanup(link.stop)
        mode = stat.S_IMODE(os.lstat(self.sock_path).st_mode)
        self.assertEqual(mode, 0o660, f"socket mode is {mode:04o}")

    def test_a_non_socket_at_the_path_is_refused_rather_than_replaced(self):
        self.sock_path.write_text("something else")
        messages = []
        link = agentlink.AgentLink(self.sock_path, log=messages.append,
                                   allowed_uids={os.getuid()})
        self.assertFalse(link.start())
        self.assertTrue(any("could not listen" in m for m in messages),
                        messages)
        self.assertEqual(self.sock_path.read_text(), "something else")

    def test_chmod_refuses_a_path_that_is_no_longer_a_socket(self):
        """
        The guard itself, exercised directly: a symlink swapped in between
        bind() and the chmod must be an error, not a redirection.
        """
        victim = self.dir / "victim"
        victim.write_text("x")
        victim.chmod(0o600)
        os.symlink(victim, self.sock_path)
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None)
        directory_fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, directory_fd)
        with self.assertRaises(OSError):
            link._chmod_socket(directory_fd, 0o660)
        self.assertEqual(stat.S_IMODE(os.stat(victim).st_mode), 0o600)

    def test_stop_does_not_delete_whatever_sits_at_the_path(self):
        keep = self.dir / "important"
        keep.write_text("do not delete me")
        link = agentlink.AgentLink(keep, log=lambda *_a: None)
        link.stop()
        self.assertTrue(keep.exists(),
                        "stop() unlinked an operator-supplied path that was "
                        "never a socket we created")

    def test_stop_removes_its_own_socket(self):
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None,
                                   allowed_uids={os.getuid()})
        self.assertTrue(link.start())
        link.stop()
        self.assertFalse(self.sock_path.exists())


class AgentReceiveIsBounded(unittest.TestCase):

    def test_a_peer_that_never_sends_a_newline_is_dropped(self):
        """
        MAX_MESSAGE bounded each recv() and not their sum. The agent does not
        get to choose what it is talking to -- it connects to a path -- so an
        occupant of that path could grow this without limit.
        """
        listener, peer = socket.socketpair()
        self.addCleanup(listener.close)
        self.addCleanup(peer.close)

        messages = []
        agent = agent_mod.Agent(Path("/nonexistent"), log=messages.append)
        agent.sock = listener
        agent.sock.settimeout(1.0)
        agent.dialog = mock.Mock()
        agent.notifier = mock.Mock(available=lambda: False)

        sent = [0]

        def flood():
            try:
                # Far more than MAX_MESSAGE, and never a newline. Bounded so
                # the test cannot hang if the guard is missing; the assertion
                # below is what distinguishes "dropped" from "still reading".
                for _ in range(64):
                    peer.sendall(b"A" * 4096)
                    sent[0] += 4096
            except OSError:
                pass

        thread = threading.Thread(target=flood)
        thread.start()
        self.addCleanup(thread.join)

        # connect() would replace the socket with a real one; the loop is what
        # is under test, so it is fed the socketpair directly.
        with mock.patch.object(agent, "connect", return_value=True):
            agent.run()

        self.assertTrue(any("oversized" in m for m in messages), messages)
        agent.dialog.confirm.assert_not_called()


class AgentTimeoutIsValidated(unittest.TestCase):
    """
    `float(message.get("timeout", 60))` raised on a string, a list or a null
    and took the agent down -- a way to remove the desktop prompt by sending
    one malformed message.
    """

    def test_unusable_values_fall_back_to_the_default(self):
        for value in ("soon", None, [], {}, True, float("nan"),
                      float("inf"), -5, 0):
            with self.subTest(value=value):
                result = agent_mod._dialog_timeout(value)
                self.assertGreaterEqual(result, agent_mod.MIN_DIALOG_TIMEOUT)
                self.assertLessEqual(result, agent_mod.MAX_DIALOG_TIMEOUT)

    def test_an_absurd_value_is_clamped_rather_than_honoured(self):
        self.assertEqual(agent_mod._dialog_timeout(10 ** 9),
                         agent_mod.MAX_DIALOG_TIMEOUT)

    def test_an_ordinary_value_passes_through(self):
        self.assertEqual(agent_mod._dialog_timeout(45), 45.0)

    def test_non_string_display_fields_do_not_crash_the_agent(self):
        agent = agent_mod.Agent(Path("/nonexistent"), log=lambda *_a: None)
        agent.notifier = mock.Mock(available=lambda: False)
        agent.dialog = mock.Mock()
        agent.dialog.confirm.return_value = False
        agent.sock = None
        agent._handle(json.dumps({
            "type": agent_mod.MSG_DECIDE, "id": 1,
            "title": {"not": "a string"}, "body": ["nor", "this"],
            "timeout": "whenever",
        }).encode())
        agent.dialog.confirm.assert_called_once()
        text = agent.dialog.confirm.call_args.kwargs["text"]
        self.assertIsInstance(text, str)

    def test_a_message_that_is_not_an_object_is_ignored(self):
        agent = agent_mod.Agent(Path("/nonexistent"), log=lambda *_a: None)
        agent.notifier = mock.Mock(available=lambda: False)
        agent.dialog = mock.Mock()
        agent._handle(b'["not", "an", "object"]')
        agent.dialog.confirm.assert_not_called()


class NotificationBodyIsNotMarkup(unittest.TestCase):
    """Device strings reached the notification body as live markup."""

    def test_device_markup_is_escaped(self):
        notifier = agent.Notifier(log=lambda *_a: None)
        notifier._gdbus = "/usr/bin/gdbus"
        with mock.patch("subprocess.run") as run:
            run.return_value = types.SimpleNamespace(
                returncode=0, stdout="(uint32 7,)", stderr="")
            notifier.notify("New USB device",
                            '<a href="https://evil.example/">approve</a>')
        argv = run.call_args[0][0]
        # String arguments are GVariant literals now; JSON reads that subset.
        import json
        body = json.loads(argv[argv.index('"New USB device"') + 1])
        self.assertNotIn("<a", body)
        self.assertIn("&lt;a href=", body)


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


# --------------------------------------------------------------------------
# 4. The agent's second dialog
# --------------------------------------------------------------------------

class ConfirmationEndsBeforeTheAnalyzerStopsListening(unittest.TestCase):

    def build(self):
        from probolos import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance, agent_mod

    def test_second_dialog_gets_only_what_is_left(self):
        agent, agent_mod = self.build()
        clock = iter([100.0, 150.0])     # the first dialog took 50 of 60 s
        agent.dialog.confirm.side_effect = [True, True]
        with mock.patch.object(agent_mod.time, "monotonic",
                               side_effect=lambda: next(clock)):
            agent._ask_user({"title": "t", "body": "b"}, 60)
        second_timeout = agent.dialog.confirm.call_args_list[1].kwargs["timeout"]
        self.assertLessEqual(second_timeout, 60 - 50)

    def test_no_budget_left_is_a_refusal_not_a_late_yes(self):
        from probolos.agentlink import ANSWER_NO
        agent, agent_mod = self.build()
        clock = iter([100.0, 170.0])
        agent.dialog.confirm.side_effect = [True, True]
        with mock.patch.object(agent_mod.time, "monotonic",
                               side_effect=lambda: next(clock)):
            answer = agent._ask_user({"title": "t", "body": "b"}, 60)
        self.assertEqual(answer, ANSWER_NO)
        self.assertEqual(agent.dialog.confirm.call_count, 1)


# ---------------------------------------------------------------------------
# 8. A decision that was made must not evaporate
# ---------------------------------------------------------------------------

class AnUnofferedAlwaysIsDowngradedNotDiscarded(unittest.TestCase):
    """
    `continue` threw the answer away and went back to waiting, so a user who
    clicked a button got a question that then timed out into a denial -- and
    the daemon, seeing None, announced "no answer from the desktop agent" and
    re-asked in a terminal the user may not have been looking at.

    "Always" is "yes" plus "remember it". With remembering not on offer, the
    honest reading is the yes without the remembering, which is strictly LESS
    than the user asked for and so cannot grant anything unintended.
    """

    def _link_answering(self, answer):
        import json
        link = agentlink.AgentLink(Path("/nonexistent/agent.sock"),
                                   log=lambda *a: None)
        conn = mock.Mock()
        link._conn = conn
        sent = {}

        def sendall(payload):
            sent["id"] = json.loads(payload.decode())["id"]

        conn.sendall.side_effect = sendall
        conn.gettimeout.return_value = 1.0

        def recv(*_a, **_k):
            if "id" not in sent:
                raise BlockingIOError
            return (json.dumps({"type": agentlink.MSG_ANSWER,
                                "id": sent["id"],
                                "answer": answer}) + "\n").encode()

        conn.recv.side_effect = recv
        return link

    def test_always_without_the_offer_becomes_yes(self):
        link = self._link_answering(agentlink.ANSWER_ALWAYS)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=False, timeout=5),
            agentlink.ANSWER_YES,
            "a decision the user made must not be silently dropped")

    def test_always_with_the_offer_stays_always(self):
        link = self._link_answering(agentlink.ANSWER_ALWAYS)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=True, timeout=5),
            agentlink.ANSWER_ALWAYS)

    def test_no_is_still_no(self):
        link = self._link_answering(agentlink.ANSWER_NO)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=False, timeout=5),
            agentlink.ANSWER_NO)

    def test_unavailable_is_still_not_a_decision(self):
        """None means "fall back to the terminal", never "the user said no"."""
        link = self._link_answering(agentlink.ANSWER_UNAVAILABLE)
        self.assertIsNone(
            link.ask("t", "b", "none", allow_always=False, timeout=5))


class SocketChownDoesNotFollowALink(unittest.TestCase):
    """
    start() verified /run/probolos with open_directory(secure=True) and then
    closed the descriptor, after which bind(), chmod() and chown() all worked
    by NAME again. os.chown on a name follows symlinks, so the directory that
    was checked and the one written to were the same only by assumption.
    """

    def test_chown_is_relative_to_the_verified_directory(self):
        import inspect

        from probolos import agentlink

        source = inspect.getsource(agentlink.AgentLink._chown_for_owner)
        self.assertIn("dir_fd=directory_fd", source)
        self.assertIn("follow_symlinks=False", source)
        # The old signature took `created_dir` and promised, in its docstring,
        # that the directory was "only chowned if THIS call created it" -- a
        # protection the body never implemented and never even read the flag
        # for. The parameter must now be one the code actually uses.
        signature = inspect.signature(agentlink.AgentLink._chown_for_owner)
        self.assertNotIn("created_dir", signature.parameters)


class DialogMarkupEscaping(unittest.TestCase):
    """
    The kdialog and zenity backends render markup; a device name that looks
    like HTML must not become HTML in the prompt. tkinter and the terminal
    render plain text and must NOT be escaped.
    """

    def setUp(self):
        from probolos import dialogs
        self.dialogs = dialogs

    def test_markup_safe_neutralises_tags(self):
        self.assertEqual(self.dialogs._markup_safe("<b>x</b>"),
                         "&lt;b&gt;x&lt;/b&gt;")

    def test_markup_safe_neutralises_a_link(self):
        raw = 'Kingston<a href="file:///etc/shadow">.</a>'
        self.assertNotIn("<a", self.dialogs._markup_safe(raw))

    def test_markup_safe_preserves_a_legitimate_name(self):
        """"A<B & C>D" is a real name shape and must survive, just inert."""
        out = self.dialogs._markup_safe("A<B & C>D")
        self.assertEqual(out, "A&lt;B &amp; C&gt;D")
        self.assertNotIn("<", out)

    def test_markup_safe_leaves_ordinary_text_untouched(self):
        self.assertEqual(self.dialogs._markup_safe("Kingston DataTraveler"),
                         "Kingston DataTraveler")


class AgentUnavailableIsNotARefusal(unittest.TestCase):

    def test_sentinel_is_not_a_decision(self):
        """
        The analyzer maps anything outside the three real answers to None, and
        None means "fall back to the terminal". The sentinel must land there --
        if it were ever added to the valid set, every dialog-less machine would
        go back to silently denying devices.
        """
        self.assertNotIn(agentlink.ANSWER_UNAVAILABLE,
                         (agentlink.ANSWER_YES,
                          agentlink.ANSWER_ALWAYS,
                          agentlink.ANSWER_NO))

    def test_sentinel_is_distinct_from_no(self):
        self.assertNotEqual(agentlink.ANSWER_UNAVAILABLE, agentlink.ANSWER_NO)


# ---------------------------------------------------------------------------
# 4. The agent's "I cannot ask" reply was produced and never consumed
# ---------------------------------------------------------------------------

class AgentUnavailableReturnsImmediately(unittest.TestCase):
    """
    ANSWER_UNAVAILABLE exists so a dialog-less agent is told apart from a user
    saying no. The agent sends it; _parse_answer dropped it as "not one of the
    three real answers"; ask() therefore kept waiting for a reply it already
    had, for the whole 60-second budget. The udev loop is single-threaded, so
    every device attached during that minute queued behind a question the agent
    had already declined to ask.
    """

    def _link_over(self, sock):
        link = agentlink.AgentLink.__new__(agentlink.AgentLink)
        link.log = lambda *_a: None
        link._lock = threading.Lock()
        link._conn = sock
        link._asking = 0
        link._peer = None
        sock.settimeout(1.0)
        return link

    def _answer_with(self, value):
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        link = self._link_over(ours)

        def agent():
            try:
                message = json.loads(theirs.recv(65536).decode().strip())
            except (OSError, ValueError):
                return
            theirs.sendall((json.dumps({
                "type": agentlink.MSG_ANSWER,
                "id": message["id"],
                "answer": value}) + "\n").encode())

        thread = threading.Thread(target=agent, daemon=True)
        thread.start()
        started = time.monotonic()
        answer = link.ask("t", "b", "none", True, timeout=8.0)
        return answer, time.monotonic() - started

    def test_unavailable_does_not_wait_out_the_timeout(self):
        answer, elapsed = self._answer_with(agentlink.ANSWER_UNAVAILABLE)
        self.assertIsNone(answer, "not a decision")
        self.assertLess(elapsed, 2.0,
                        "the reply was already in hand; ask() must not block")

    def test_unavailable_is_still_not_read_as_consent(self):
        answer, _ = self._answer_with(agentlink.ANSWER_UNAVAILABLE)
        self.assertNotEqual(answer, agentlink.ANSWER_YES)
        self.assertNotEqual(answer, agentlink.ANSWER_ALWAYS)

    def test_a_real_answer_still_works(self):
        answer, elapsed = self._answer_with(agentlink.ANSWER_YES)
        self.assertEqual(answer, agentlink.ANSWER_YES)
        self.assertLess(elapsed, 2.0)

    def test_nonsense_answers_are_still_ignored(self):
        """An unknown string is not a decision AND not a reason to give up."""
        answer, elapsed = self._answer_with("maybe")
        self.assertIsNone(answer)
        self.assertGreater(elapsed, 7.0, "kept waiting for a real answer")


class NotificationCleanupNeverCostsAnAnswer(unittest.TestCase):
    """
    Notifier.close() runs in the `finally` of the agent's decision path, after
    the human has already chosen. An unhandled TimeoutExpired there replaced
    the return value with an exception and the decision was lost.
    """

    def test_a_hung_gdbus_is_swallowed(self):
        from probolos import agent

        notifier = agent.Notifier.__new__(agent.Notifier)
        notifier._gdbus = "/bin/true"

        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="gdbus", timeout=5))
        try:
            notifier.close(7)      # must simply return
        finally:
            subprocess.run = real_run


if __name__ == "__main__":
    unittest.main()
