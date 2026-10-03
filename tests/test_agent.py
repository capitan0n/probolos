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
from tests._support import ServiceStdin


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
        self.link.notify_critical("USB device still blocked", "port 3-9")
        for _ in range(50):
            if self.agent.received:
                break
            time.sleep(0.02)
        self.assertEqual(self.agent.received, [{
            "type": agentlink.MSG_CRITICAL,
            "title": "USB device still blocked", "body": "port 3-9"}])
        self.assertTrue(self.link.is_live())

    def test_a_notice_is_display_only(self):
        """No id, so there is nothing to answer and nothing to approve."""
        self.connect()
        self.link.notify("USB device still blocked",
                         "USB storage · port 3-9\nNobody answered in time.")
        for _ in range(50):
            if self.agent.received:
                break
            time.sleep(0.02)
        self.assertEqual(self.agent.received, [{
            "type": agentlink.MSG_NOTICE, "title": "USB device still blocked",
            "body": "USB storage · port 3-9\nNobody answered in time."}])
        self.assertTrue(self.link.is_live(), "a notice costs nothing")

    # ---- liveness: `connected` is not "someone is there" ----

    def test_nobody_connected_is_not_live(self):
        self.assertFalse(self.link.is_live())

    def test_a_connected_agent_is_live(self):
        self.connect()
        self.assertTrue(self.link.is_live())
        self.assertTrue(self.link.connected, "probing must not drop it")
        self.assertEqual(self.link.ask("t", "b", "none", False, timeout=3),
                         agentlink.ANSWER_YES)

    def test_an_agent_that_logged_out_is_dropped_and_replaceable(self):
        """
        A logged-out agent leaves its connection object behind: `connected`
        stayed True, and the daemon sent questions into a dead socket.
        """
        self.connect()
        # What the agent's process exiting does to its end. close() alone
        # would wait for the fake's reader thread, which is blocked in recv()
        # on the same socket, before the peer saw anything.
        self.agent.sock.shutdown(socket.SHUT_RDWR)
        self.agent.stop()
        time.sleep(SETTLE)
        self.assertTrue(self.link.connected, "the dead object is still there")
        self.assertFalse(self.link.is_live())
        self.assertFalse(self.link.connected, "is_live() frees the slot")
        self.connect()
        self.assertTrue(self.link.is_live())

    def test_a_question_in_flight_is_never_probed(self):
        """
        ask() is in recv() on the socket, and the probe switches its blocking
        mode -- the race that let a connection attempt cancel a question.
        """
        self.connect(silent=True)
        box = {}
        asking = threading.Thread(target=lambda: box.setdefault(
            "answer", self.link.ask("t", "b", "none", False, timeout=1.0)))
        probed = AssertionError("probed a socket ask() is reading")
        with mock.patch.object(agentlink, "_still_connected",
                               side_effect=probed) as probe:
            asking.start()
            for _ in range(200):
                if self.link._asking:
                    break
                time.sleep(0.005)
            self.assertTrue(self.link._asking, "the question never went out")
            self.assertTrue(self.link.is_live())
            asking.join(5)
        probe.assert_not_called()
        self.assertIsNone(box["answer"], "the silent agent never answered")

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

    def test_critical_is_asked_with_a_countdown_and_never_always(self):
        """
        Under the service there is no terminal, so a CRITICAL device that could
        only be approved by typing there could not be approved at all. It is
        offered through the agent now -- with a countdown, and never "always".
        """
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_NO
        engine = daemon_mod.Probolos(agent=link, trust_store=mock.Mock(),
                                     observe=0)
        finding = rules.Finding("storage-with-keyboard", rules.Severity.CRITICAL,
                                "Storage device that can also type", "")

        self.assertFalse(engine._ask(self.device(), [finding]))
        kwargs = link.ask.call_args.kwargs
        self.assertEqual(kwargs["steps"], agentlink.STEPS_COUNTDOWN)
        self.assertEqual(kwargs["countdown"], daemon_mod.CRITICAL_COUNTDOWN)
        self.assertFalse(kwargs["allow_always"])

    def test_the_countdown_note_fits_the_finding(self):
        note = daemon_mod.Probolos._critical_note

        def f(rid):
            return rules.Finding(rid, rules.Severity.CRITICAL, "t", "")
        refused = note([f("previously-rejected")])
        self.assertIn("refusing it was a mistake", refused)
        self.assertNotIn("attack pattern", refused)
        self.assertIn("why it changed", note([f("descriptor-drift")]))
        both = note([f("previously-rejected"), f("descriptor-drift")])
        self.assertIn("mistake", both)
        self.assertIn("why it changed", both)
        self.assertIn("attack pattern",
                      note([f("previously-rejected"),
                            f("storage-with-keyboard")]),
                      "a real attack finding keeps the strong wording")
        self.assertEqual(note([rules.Finding("w", rules.Severity.WARNING,
                                             "t", "")]), "")

    def test_the_note_reaches_the_agent(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_NO
        engine = daemon_mod.Probolos(agent=link, observe=0)
        engine._ask(self.device(), [rules.Finding(
            "previously-rejected", rules.Severity.CRITICAL, "t", "")])
        self.assertIn("mistake", link.ask.call_args.kwargs["note"])

    def _critical_answer_after(self, seconds, answer=agentlink.ANSWER_YES):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = answer
        engine = daemon_mod.Probolos(agent=link, observe=0)
        finding = rules.Finding("previously-rejected", rules.Severity.CRITICAL,
                                "Changed what it claims to be", "")
        clock = iter([100.0, 100.0 + seconds])
        with mock.patch.object(daemon_mod.time, "monotonic",
                               side_effect=lambda: next(clock)), \
             mock.patch("sys.stdin", io.StringIO("")), \
             mock.patch("sys.stdout", io.StringIO()):
            return engine._ask(self.device(), [finding]), engine

    def test_a_critical_approval_before_the_countdown_is_ignored(self):
        """The daemon enforces the countdown too: whatever answered in 3 s,
        it was not a person waiting for the button to unlock."""
        approved, engine = self._critical_answer_after(3.0)
        self.assertFalse(approved)
        self.assertFalse(engine._answered)

    def test_a_critical_approval_after_the_countdown_stands(self):
        approved, _ = self._critical_answer_after(12.0)
        self.assertTrue(approved)

    def test_always_is_never_remembered_for_a_critical_device(self):
        approved, engine = self._critical_answer_after(
            12.0, answer=agentlink.ANSWER_ALWAYS)
        self.assertTrue(approved)
        self.assertFalse(getattr(engine, "_remember", False))

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

    def test_always_is_not_offered_when_trust_cannot_be_saved(self):
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = agentlink.ANSWER_YES
        store = mock.Mock(**{"writable.return_value": False})
        engine = daemon_mod.Probolos(agent=link, trust_store=store, observe=0)

        self.assertTrue(engine._ask(self.device(), []))
        self.assertFalse(link.ask.call_args.kwargs["allow_always"])

    def test_no_answer_falls_back_to_the_terminal(self):
        """
        An agent that could not answer has not made a decision. Treating its
        silence as a refusal would reject devices the user never saw. Where
        there IS a terminal, the question goes there, exactly as before.
        """
        link = mock.Mock()
        link.connected = True
        link.ask.return_value = None
        engine = daemon_mod.Probolos(agent=link, observe=0)

        with mock.patch("sys.stdin", io.StringIO("y\n")), \
                mock.patch.object(engine, "_has_terminal", return_value=True):
            self.assertTrue(engine._ask(self.device(), []),
                            "a missing agent answer must fall through to the "
                            "terminal, not become a refusal")
        link.notify.assert_not_called()

    def test_no_answer_without_a_terminal_is_not_read_from_stdin(self):
        """
        The service's stdin is /dev/null: "asking here" read EOF and denied,
        a refusal in all but name. Without a terminal the device is denied as
        unanswered, the agent is told so, and stdin is never touched.
        """
        link = mock.Mock()
        link.is_live.return_value = True
        link.ask.return_value = None
        engine = daemon_mod.Probolos(agent=link, observe=0)
        stdin = ServiceStdin()
        self.addCleanup(stdin.release)

        with mock.patch("sys.stdin", stdin), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch.object(engine, "_has_terminal", return_value=False):
            self.assertFalse(engine._ask(self.device(), []))
        self.assertEqual(stdin.touches, [], "the terminal was read")
        self.assertFalse(engine._answered, "nobody answered")
        self.assertFalse(engine._hold_instead, "the agent is still there")
        title, body = link.notify.call_args.args
        self.assertEqual(title, "USB device still blocked")
        self.assertEqual(body.splitlines(), [
            "Mass Storage (SCSI) · port 3-9",
            "Nobody answered in time. Unplug it and plug it in again to be "
            "asked."])

    def test_an_agent_that_left_mid_question_means_hold_not_deny(self):
        link = mock.Mock()
        link.ask.return_value = None
        # Live when asked, gone once the question came back empty.
        link.is_live.side_effect = [True, False]
        engine = daemon_mod.Probolos(agent=link, observe=0)
        stdin = ServiceStdin()
        self.addCleanup(stdin.release)

        with mock.patch("sys.stdin", stdin), \
                mock.patch("sys.stdout", io.StringIO()), \
                mock.patch.object(engine, "_has_terminal", return_value=False):
            self.assertFalse(engine._ask(self.device(), []))
        self.assertTrue(engine._hold_instead)
        self.assertFalse(engine._answered)
        link.notify.assert_not_called()
        self.assertEqual(stdin.touches, [])

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

    def test_every_finding_is_shown_most_severe_first(self):
        """"...and 1 more finding(s)" hid warnings on the one screen where the
        decision is made."""
        findings = ([rules.Finding(f"n{i}", rules.Severity.NOTICE,
                                   f"Notice {i}", "") for i in range(3)]
                    + [rules.Finding("w", rules.Severity.WARNING,
                                     "The warning", "")])
        body = daemon_mod.Probolos._agent_body(self.device(), findings)
        lines = body.splitlines()
        self.assertIn("0951:1665", lines[0])
        self.assertIn("The warning", lines[2], "most severe first")
        for i in range(3):
            self.assertIn(f"Notice {i}", body)
        self.assertNotIn("more", body)

    def test_a_pathological_list_is_capped_and_says_where_the_rest_is(self):
        findings = [rules.Finding(f"r{i}", rules.Severity.NOTICE,
                                  f"Finding {i}", "") for i in range(12)]
        body = daemon_mod.Probolos._agent_body(self.device(), findings)
        self.assertIn("4 more", body)
        self.assertIn("journalctl", body)


def _iface(cls, sub=0, proto=0):
    from types import SimpleNamespace
    return SimpleNamespace(interface_class=cls, interface_subclass=sub,
                           interface_protocol=proto)


class PromptFrictionMatchesTheRisk(unittest.TestCase):
    """Two dialogs for everything trains the reflex to click through both."""

    def device(self, *interfaces):
        dev = mock.Mock(spec=sysfs.UsbDevice)
        dev.name = "3-9"
        dev.interfaces = list(interfaces)
        dev.claims = []
        return dev

    def steps(self, dev, *severities):
        findings = [rules.Finding(f"f{i}", sev, "t", "")
                    for i, sev in enumerate(severities)]
        return daemon_mod.Probolos._prompt_steps(dev, findings)

    def test_a_clean_storage_device_gets_one_dialog(self):
        self.assertEqual(self.steps(self.device(_iface(0x08, 6, 0x50))),
                         agentlink.STEPS_ONE)

    def test_a_notice_does_not_add_a_step(self):
        self.assertEqual(self.steps(self.device(_iface(0x08)),
                                    rules.Severity.NOTICE),
                         agentlink.STEPS_ONE)

    def test_a_warning_adds_the_second_confirmation(self):
        self.assertEqual(self.steps(self.device(_iface(0x08)),
                                    rules.Severity.WARNING),
                         agentlink.STEPS_TWO)

    def test_anything_that_can_type_or_carry_traffic_gets_two(self):
        for cls in (0x03, 0x02, 0x0A, 0xE0, 0xFF, 0x42):
            self.assertEqual(self.steps(self.device(_iface(0x08), _iface(cls))),
                             agentlink.STEPS_TWO, f"class 0x{cls:02x}")

    def test_unknown_interfaces_are_not_assumed_safe(self):
        self.assertEqual(self.steps(self.device()), agentlink.STEPS_TWO)

    def test_critical_gets_the_countdown(self):
        self.assertEqual(self.steps(self.device(_iface(0x08)),
                                    rules.Severity.CRITICAL),
                         agentlink.STEPS_COUNTDOWN)

    def test_title_and_capabilities_are_plain_and_specific(self):
        dev = self.device(_iface(0x08, 6, 0x50), _iface(0x03, 1, 1))
        title = daemon_mod.Probolos._agent_title(dev)
        self.assertIn("USB storage", title)
        self.assertIn("keyboard", title)
        self.assertIn("port 3-9", title)
        caps = daemon_mod.Probolos._agent_capabilities(dev)
        self.assertIn("read and write files", caps)
        self.assertIn("type", caps)
        self.assertNotIn("network", caps, "only what THIS device declared")


class AgentAsksWithTheRightFriction(unittest.TestCase):

    def build(self):
        from probolos import agent as agent_mod
        agent = agent_mod.Agent.__new__(agent_mod.Agent)
        agent.log = lambda *a: None
        agent.notifier = mock.Mock(**{"available.return_value": True,
                                      "notify.return_value": 7})
        agent.dialog = mock.Mock()
        agent.countdown_dialog = mock.Mock()
        agent.sock = None
        return agent

    def ask(self, agent, **fields):
        return agent._ask_user({"title": "USB storage · port 3-9",
                                "body": "Stick · 0951:1665",
                                "capabilities": "read and write files",
                                **fields}, 60)

    def test_one_step_is_a_single_dialog(self):
        agent = self.build()
        agent.dialog.confirm.return_value = True
        self.assertEqual(self.ask(agent, steps=agentlink.STEPS_ONE),
                         agentlink.ANSWER_YES)
        self.assertEqual(agent.dialog.confirm.call_count, 1)
        self.assertIn("read and write files",
                      agent.dialog.confirm.call_args.kwargs["text"])

    def test_one_step_with_remembering_offers_the_three_choices_at_once(self):
        from probolos import dialogs
        agent = self.build()
        agent.dialog.choose.return_value = dialogs.CHOICE_ALWAYS
        self.assertEqual(self.ask(agent, steps=agentlink.STEPS_ONE,
                                  allow_always=True),
                         agentlink.ANSWER_ALWAYS)
        agent.dialog.confirm.assert_not_called()

    def test_the_second_dialog_names_what_this_device_can_do(self):
        agent = self.build()
        agent.dialog.confirm.side_effect = [True, True]
        self.ask(agent, steps=agentlink.STEPS_TWO)
        second = agent.dialog.confirm.call_args_list[1].kwargs["text"]
        self.assertIn("read and write files", second)
        self.assertNotIn("use the network", second)

    def test_a_missing_or_unknown_step_is_the_careful_two(self):
        agent = self.build()
        agent.dialog.confirm.side_effect = [True, True]
        self.ask(agent, steps="zero")
        self.assertEqual(agent.dialog.confirm.call_count, 2)

    def test_countdown_uses_the_countdown_dialog_and_only_true_approves(self):
        agent = self.build()
        # The fallback (main dialog) also has no answer, so None stays None.
        agent.dialog.confirm_countdown.return_value = None
        for result, expected in ((True, agentlink.ANSWER_YES),
                                 (False, agentlink.ANSWER_NO),
                                 (None, agentlink.ANSWER_UNAVAILABLE),
                                 (mock.Mock(), agentlink.ANSWER_NO)):
            agent.countdown_dialog.confirm_countdown.return_value = result
            self.assertEqual(self.ask(agent, steps=agentlink.STEPS_COUNTDOWN,
                                      countdown=10, allow_always=True),
                             expected)
        kwargs = agent.countdown_dialog.confirm_countdown.call_args.kwargs
        self.assertEqual(kwargs["delay"], 10)
        agent.dialog.choose.assert_not_called()

    def test_the_countdown_window_shows_the_note_it_was_sent(self):
        agent = self.build()
        agent.countdown_dialog.confirm_countdown.return_value = False
        self.ask(agent, steps=agentlink.STEPS_COUNTDOWN, countdown=10,
                 note="You refused this device before.")
        text = agent.countdown_dialog.confirm_countdown.call_args.kwargs["text"]
        self.assertIn("You refused this device before.", text)
        self.assertNotIn("attack pattern", text)

    def test_every_refusal_button_says_keep_blocked(self):
        from probolos import dialogs
        agent = self.build()
        agent.dialog.confirm.side_effect = [True, False]
        self.ask(agent, steps=agentlink.STEPS_TWO)
        self.assertEqual(agent.dialog.confirm.call_args.kwargs["no_label"],
                         "Keep blocked")
        agent.dialog.confirm.side_effect = [True]
        agent.dialog.choose.return_value = dialogs.CHOICE_NO
        self.ask(agent, steps=agentlink.STEPS_TWO, allow_always=True)
        self.assertEqual(agent.dialog.choose.call_args.kwargs["no_label"],
                         "Keep blocked")

    def test_the_countdown_is_never_shorter_than_ten_seconds(self):
        from probolos import agent as agent_mod
        for value, expected in ((0, 10), (3, 10), ("x", 10), (None, 10),
                                (float("nan"), 10), (15, 15), (999, 30)):
            self.assertEqual(agent_mod._countdown(value), expected, value)

    def test_the_notification_is_one_line_not_the_dialog_again(self):
        agent = self.build()
        agent.dialog.confirm.return_value = False
        self.ask(agent, steps=agentlink.STEPS_TWO)
        title, text = agent.notifier.notify.call_args.args[:2]
        self.assertEqual(title, "USB device blocked")
        self.assertNotIn("0951:1665", text)
        self.assertLessEqual(len(text.splitlines()), 2)


class CountdownDialogs(unittest.TestCase):
    """kdialog and zenity cannot disable a button, so they show the findings
    in a window that approves nothing first; tkinter draws a real countdown."""

    def backend(self):
        from probolos import dialogs
        b = dialogs.KDialogBackend()
        b._binary = "/usr/bin/kdialog"
        return b

    def test_closing_the_first_window_early_keeps_it_blocked(self):
        b = self.backend()
        with mock.patch.object(b, "notice", return_value=True), \
             mock.patch.object(b, "confirm") as confirm:
            self.assertIs(b.confirm_countdown("t", "x", "Allow", "No", 10, 60),
                          False)
        confirm.assert_not_called()

    def test_the_question_comes_only_after_the_countdown(self):
        b = self.backend()
        with mock.patch.object(b, "notice", return_value=False) as notice, \
             mock.patch.object(b, "confirm", return_value=True) as confirm:
            self.assertIs(b.confirm_countdown("t", "x", "Allow", "No", 10, 60),
                          True)
        self.assertEqual(notice.call_args.kwargs["timeout"], 10)
        self.assertLessEqual(confirm.call_args.args[4], 60)

    def test_a_window_that_cannot_be_shown_is_no_decision(self):
        b = self.backend()
        with mock.patch.object(b, "notice", return_value=None):
            self.assertIsNone(b.confirm_countdown("t", "x", "A", "N", 10, 60))

    def test_kdialog_notice_outcomes(self):
        from probolos import dialogs
        b = self.backend()
        run = dialogs.subprocess
        cases = ((run.TimeoutExpired(cmd="kdialog", timeout=10), False),
                 (OSError("no display"), None))
        for effect, expected in cases:
            with mock.patch.object(run, "run", side_effect=effect):
                self.assertIs(b.notice("t", "x", 10), expected)
        with mock.patch.object(run, "run", return_value=mock.Mock(returncode=0)):
            self.assertIs(b.notice("t", "x", 10), True)

    def test_tkinter_notice_outcomes(self):
        """The base class raised NotImplementedError for tkinter, so a
        tkinter-only desktop with no notification server was told nothing."""
        from probolos import dialogs
        b = dialogs.TkinterBackend()
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=mock.Mock(returncode=11)) as run:
            self.assertIs(b.notice("t", "x", 10), True)
        argv = run.call_args.args[0]
        self.assertEqual(argv[1:3], ["-I", "-c"], "isolated from env and cwd")
        self.assertEqual(argv[-2:], ["t", "x"])
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        # A crashed tk (exit 1, say) never drew the window: not shown.
        for code in (0, 1, 2, 10, 12):
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertIsNone(b.notice("t", "x", 10), f"exit {code}")
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="python", timeout=10)):
            self.assertIs(b.notice("t", "x", 10), False)
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=OSError("no python")):
            self.assertIsNone(b.notice("t", "x", 10))

    def test_tkinter_countdown_outcomes(self):
        from probolos import dialogs
        b = dialogs.TkinterBackend()
        with mock.patch.object(dialogs.subprocess, "run",
                               return_value=mock.Mock(returncode=11)) as run:
            b.confirm_countdown("t", "x", "A", "N", 10, 60)
        argv = run.call_args.args[0]
        self.assertEqual(argv[1], "-I", "isolated from env and cwd")
        self.assertTrue(argv[2].endswith("countdown_dialog.py"))
        self.assertTrue(Path(argv[2]).is_file())
        # 1 is what Python exits with on ANY crash (no $DISPLAY, say): it is
        # no decision, never "Keep blocked" and never an approval.
        for code, expected in ((10, True), (11, False), (0, None), (1, None),
                               (2, None)):
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertIs(b.confirm_countdown("t", "x", "A", "N", 10, 60),
                              expected, f"exit {code}")
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="python", timeout=60)):
            self.assertIsNone(b.confirm_countdown("t", "x", "A", "N", 10, 60))

    def test_the_window_takes_kde_colours_and_font_and_ignores_junk(self):
        import configparser
        from probolos import countdown_dialog as cd
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(
            "[Colors:Window]\nBackgroundNormal=32,35,38\n"
            "ForegroundNormal=252,252,252\nForegroundNegative=999,0,0\n"
            "[Colors:Selection]\nBackgroundNormal=not,a,colour\n"
            "[General]\nfont=Noto Sans,10,-1,5,50,0,0,0,0,0\n")
        colors = cd.kde_colors(parser)
        self.assertEqual(colors["bg"], "#202326")
        self.assertEqual(colors["fg"], "#fcfcfc")
        self.assertNotIn("danger", colors, "out-of-range values are dropped")
        self.assertNotIn("accent", colors)
        self.assertEqual(cd.kde_font(parser), ("Noto Sans", 10))
        empty = configparser.ConfigParser()
        self.assertEqual(cd.kde_colors(empty), {})
        self.assertIsNone(cd.kde_font(empty))

    def test_a_crashed_tk_is_never_always_allow(self):
        """choose() mapped exit 1 to "Always allow", and Python exits 1 on any
        crash -- reached only after the person clicked Allow once."""
        from probolos import dialogs
        b = dialogs.TkinterBackend()
        for code in (0, 1, 2):
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertIsNone(b.choose("t", "x", "o", "a", "n", 5))
                self.assertIsNone(b.confirm("t", "x", "y", "n", 5))
        answers = {10: dialogs.CHOICE_ONCE, 12: dialogs.CHOICE_ALWAYS,
                   11: dialogs.CHOICE_NO}
        for code, expected in answers.items():
            with mock.patch.object(dialogs.subprocess, "run",
                                   return_value=mock.Mock(returncode=code)):
                self.assertEqual(b.choose("t", "x", "o", "a", "n", 5), expected)

    def test_a_failed_countdown_window_falls_back_to_the_main_dialog(self):
        from probolos import agent as agent_mod
        agent = agent_mod.Agent.__new__(agent_mod.Agent)
        agent.log = lambda *a: None
        agent.dialog = mock.Mock(**{"confirm_countdown.return_value": True})
        agent.dialog.name = "kdialog"
        agent.countdown_dialog = mock.Mock(
            **{"confirm_countdown.return_value": None})
        import time
        answer = agent._ask_countdown("t", "b", "c", 10,
                                      time.monotonic() + 60)
        self.assertEqual(answer, agentlink.ANSWER_YES)
        agent.dialog.confirm_countdown.assert_called_once()


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

    def test_a_timed_out_dialog_is_no_answer_and_never_a_yes(self):
        """
        A dialog nobody dealt with must not become an approval just because it
        went away -- and must not become a recorded refusal either, or the
        next plug warns "You have refused this device before" about a refusal
        nobody made. None: falsy, and "no decision" to every caller.
        """
        from probolos import dialogs
        backend = dialogs.KDialogBackend()
        backend._binary = "/usr/bin/kdialog"
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="kdialog", timeout=1)):
            self.assertIsNone(backend.confirm("t", "x", "y", "n", 1.0))

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

    def test_a_timeout_is_no_answer(self):
        from probolos import dialogs
        with mock.patch.object(dialogs.subprocess, "run",
                               side_effect=dialogs.subprocess.TimeoutExpired(
                                   cmd="kdialog", timeout=1)):
            self.assertIsNone(
                self.backend().choose("t", "x", "once", "always", "no", 1))


class ADialogThatDiesIsNotAnAnswer(unittest.TestCase):
    """
    kdialog and zenity mapped every exit code that was not "yes" to "Keep
    blocked". A dialog killed under nobody's hand -- Qt aborts (-6) when the
    display goes away at logout, SIGTERM is -15, a tool failing on its own
    exits 254/255 -- was therefore sent back as "no", recorded as "user
    rejected", and the next plug got the previously-rejected countdown for a
    refusal nobody made. Only a button is an answer.
    """

    NOT_BUTTONS = (-6, -15, -9, 254, 255, 5)

    def _backend(self, cls):
        backend = cls()
        backend._binary = "/usr/bin/dialog-tool"
        return backend

    def _run(self, code, stdout=""):
        from probolos import dialogs
        return mock.patch.object(
            dialogs.subprocess, "run",
            return_value=mock.Mock(returncode=code, stdout=stdout))

    def test_confirm_answers_only_for_a_button(self):
        from probolos import dialogs
        for cls in (dialogs.KDialogBackend, dialogs.ZenityBackend):
            backend = self._backend(cls)
            for code, expected in ((0, True), (1, False)):
                with self.subTest(cls=cls.name, code=code), self._run(code):
                    self.assertIs(backend.confirm("t", "x", "y", "n", 1.0),
                                  expected)
            for code in self.NOT_BUTTONS:
                with self.subTest(cls=cls.name, code=code), self._run(code):
                    self.assertIsNone(backend.confirm("t", "x", "y", "n", 1.0))

    def test_choose_answers_only_for_a_button(self):
        from probolos import dialogs
        kdialog = self._backend(dialogs.KDialogBackend)
        zenity = self._backend(dialogs.ZenityBackend)
        for code in self.NOT_BUTTONS:
            with self.subTest(code=code), self._run(code, stdout="always"):
                self.assertIsNone(
                    kdialog.choose("t", "x", "once", "always", "no", 1.0))
                self.assertIsNone(
                    zenity.choose("t", "x", "once", "always", "no", 1.0))
        cases = ((0, "", dialogs.CHOICE_ONCE),
                 (1, "always\n", dialogs.CHOICE_ALWAYS),
                 (1, "", dialogs.CHOICE_NO))
        for code, stdout, expected in cases:
            with self.subTest(code=code, stdout=stdout), \
                    self._run(code, stdout=stdout):
                self.assertEqual(
                    zenity.choose("t", "x", "once", "always", "no", 1.0),
                    expected)

    def test_a_dead_dialog_reaches_the_analyzer_as_no_decision(self):
        from probolos import agent as agent_mod
        from probolos import dialogs
        from probolos.agentlink import ANSWER_UNAVAILABLE
        agent = agent_mod.Agent.__new__(agent_mod.Agent)
        agent.log = lambda *a: None
        agent.notifier = mock.Mock(**{"available.return_value": False})
        agent.dialog = self._backend(dialogs.KDialogBackend)
        with self._run(-6):
            self.assertEqual(
                agent._ask_user({"title": "t", "body": "b", "steps": "one"},
                                30),
                ANSWER_UNAVAILABLE)

    def test_an_unanswered_dialog_reaches_the_analyzer_as_no_decision(self):
        """Both dialogs, both ways they can go unanswered."""
        from probolos import agent as agent_mod
        from probolos.agentlink import ANSWER_UNAVAILABLE
        agent = agent_mod.Agent.__new__(agent_mod.Agent)
        agent.log = lambda *a: None
        agent.notifier = mock.Mock(**{"available.return_value": False})
        agent.dialog = mock.Mock()
        cases = [
            ({"allow_always": False}, [None], None),         # first dialog
            ({"allow_always": False}, [True, None], None),   # confirm
            ({"allow_always": True}, [True], None),          # three-way
        ]
        for extra, confirms, choice in cases:
            agent.dialog.confirm.side_effect = confirms
            agent.dialog.choose.return_value = choice
            self.assertEqual(
                agent._ask_user({"title": "t", "body": "b", **extra}, 30),
                ANSWER_UNAVAILABLE, f"{extra} {confirms}")


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

    def test_a_dead_agent_with_unread_bytes_is_still_replaced(self):
        """
        It closed AFTER sending -- a late answer, then a logout. The peek
        that judged liveness saw that byte rather than the EOF behind it, so
        the dead agent kept the slot and its successor was refused.
        """
        link = self.server()
        first = self.client(link)
        first.sendall(b'{"type": "answer", "id": 1, "answer": "no"}\n')
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

    def test_a_directory_systemd_already_made_2750_needs_no_chmod(self):
        """
        Under the shipped unit RestrictSUIDSGID=yes makes every chmod that
        carries the setgid bit fail with EPERM, and systemd has already
        created the directory 2750 (RuntimeDirectoryMode). The service used
        to chmod it anyway and crash-looped with the gate open.
        """
        self.root.mkdir()
        os.chmod(self.root, 0o2750)
        refused = PermissionError(1, "Operation not permitted")
        with mock.patch.object(agentlink.os, "fchmod", side_effect=refused):
            agentlink.prepare_socket_dir(self.root / "agent.sock",
                                         os.getuid(), os.getgid())
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o2750)


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


class AgentShowsNoticesWithoutOfferingAnAnswer(unittest.TestCase):
    """
    MSG_NOTICE: "this device is still blocked; replug it to be asked". It is
    shown, never answered, and nothing it shows can allow anything.
    """

    def build(self, notifications=True, notify_result=7):
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *_a: None
        instance.notifier = mock.Mock(**{
            "available.return_value": notifications,
            "notify.return_value": notify_result})
        instance.dialog = mock.Mock()
        instance.countdown_dialog = mock.Mock()
        instance.sock = mock.Mock()
        return instance

    @staticmethod
    def send(instance, **fields):
        instance._handle(json.dumps(
            {"type": agentlink.MSG_NOTICE, **fields}).encode())

    def assert_offered_nothing(self, instance):
        for method in ("confirm", "choose", "confirm_countdown"):
            getattr(instance.dialog, method).assert_not_called()
        self.assertEqual(instance.countdown_dialog.mock_calls, [])
        instance.sock.sendall.assert_not_called()

    @staticmethod
    def window_closed(instance):
        """Wait for the notice window's thread to let go of the slot."""
        for _ in range(200):
            if not instance._notice_window.locked():
                return True
            time.sleep(0.01)
        return False

    def test_it_is_a_plain_notification(self):
        instance = self.build()
        self.send(instance, title="USB device still blocked",
                  body="USB storage · port 3-9\nNobody answered in time.")
        instance.notifier.notify.assert_called_once_with(
            "USB device still blocked",
            "USB storage · port 3-9\nNobody answered in time.",
            urgency=agent_mod.URGENCY_NORMAL, actionable=False)
        instance.dialog.notice.assert_not_called()
        self.assert_offered_nothing(instance)

    def test_fields_that_are_not_text_do_not_crash_the_agent(self):
        instance = self.build()
        self.send(instance, title={"not": "text"}, body=["nor", "this"])
        self.assertEqual(instance.notifier.notify.call_args.args,
                         ("Probolos", ""))
        self.assert_offered_nothing(instance)

    def test_without_notifications_a_window_shows_it_off_the_receive_loop(self):
        instance = self.build(notifications=False)
        shown, release = threading.Event(), threading.Event()

        def window(*_args, **_kwargs):
            shown.set()
            release.wait(5)
            return True

        instance.dialog.notice.side_effect = window
        started = time.monotonic()
        self.send(instance, title="USB device still blocked", body="port 3-9")
        self.assertLess(time.monotonic() - started, 1.0,
                        "the receive loop waited for the window")
        self.assertTrue(shown.wait(2), "the window was never shown")
        # While it is up, another is not stacked on top of it.
        self.send(instance, title="again", body="port 3-10")
        release.set()
        self.assertTrue(self.window_closed(instance))
        instance.dialog.notice.assert_called_once()
        args, kwargs = instance.dialog.notice.call_args
        self.assertEqual(args, ("Probolos — USB device still blocked",
                                "port 3-9"))
        self.assertEqual(kwargs["timeout"], agent_mod.NOTICE_TIMEOUT)
        self.assert_offered_nothing(instance)

    def test_a_critical_notice_is_the_same_notice_at_critical_urgency(self):
        """
        MSG_CRITICAL used to append "cannot be approved from here. Use the
        terminal." -- untrue since CRITICAL devices got the countdown, and the
        service has no terminal. It is now the "still blocked" notice.
        """
        instance = self.build()
        instance._handle(json.dumps({
            "type": agentlink.MSG_CRITICAL, "title": "USB device still blocked",
            "body": "port 3-9\nNobody answered in time."}).encode())
        instance.notifier.notify.assert_called_once_with(
            "USB device still blocked", "port 3-9\nNobody answered in time.",
            urgency=agent_mod.URGENCY_CRITICAL, actionable=False)
        self.assertNotIn("terminal",
                         instance.notifier.notify.call_args.args[1])
        self.assert_offered_nothing(instance)

    def test_a_critical_notice_without_notifications_is_a_window(self):
        instance = self.build(notifications=False)
        instance.dialog.notice.return_value = True
        instance._handle(json.dumps({
            "type": agentlink.MSG_CRITICAL, "title": "t",
            "body": "b"}).encode())
        self.assertTrue(self.window_closed(instance))
        instance.dialog.notice.assert_called_once()
        self.assert_offered_nothing(instance)

    def test_a_failed_notification_falls_back_to_the_window(self):
        instance = self.build(notify_result=None)
        instance.dialog.notice.return_value = True
        self.send(instance, title="t", body="b")
        self.assertTrue(self.window_closed(instance))
        instance.dialog.notice.assert_called_once()

    def test_a_backend_that_cannot_show_it_does_not_take_the_agent_down(self):
        instance = self.build(notifications=False)
        instance.dialog.notice.side_effect = NotImplementedError
        self.send(instance, title="t", body="b")
        self.assertTrue(self.window_closed(instance))
        # The slot was given back: the next notice is still shown.
        instance.dialog.notice.side_effect = None
        self.send(instance, title="t", body="b")
        self.assertTrue(self.window_closed(instance))
        self.assertEqual(instance.dialog.notice.call_count, 2)


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

    def test_no_budget_left_is_no_decision_not_a_late_yes(self):
        """Out of time before the second dialog: never a yes, and not a
        refusal the user made either."""
        from probolos.agentlink import ANSWER_UNAVAILABLE
        agent, agent_mod = self.build()
        clock = iter([100.0, 170.0])
        agent.dialog.confirm.side_effect = [True, True]
        with mock.patch.object(agent_mod.time, "monotonic",
                               side_effect=lambda: next(clock)):
            answer = agent._ask_user({"title": "t", "body": "b"}, 60)
        self.assertEqual(answer, ANSWER_UNAVAILABLE)
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


class LivenessAndNoticesOverASocketPair(unittest.TestCase):
    """
    is_live() and notify() against a connection whose far end is gone --
    what a logged-out agent leaves behind.
    """

    def _pair(self):
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        link = agentlink.AgentLink(Path("/nonexistent/agent.sock"), log=_quiet)
        link._conn = ours
        return link, theirs

    def test_a_closed_peer_is_dropped(self):
        link, theirs = self._pair()
        self.assertTrue(link.is_live())
        theirs.close()
        self.assertFalse(link.is_live())
        self.assertFalse(link.connected)

    def test_a_peer_that_closed_after_sending_is_dropped(self):
        """
        A late answer, then a logout. A one-byte MSG_PEEK saw the answer, not
        the EOF behind it, so the dead agent counted as there: a device would
        be switched on for inspection with nobody to ask, and the held queue
        drained into a socket nobody reads.
        """
        link, theirs = self._pair()
        theirs.sendall(b'{"type": "answer", "id": 7, "answer": "yes"}\n')
        theirs.close()
        self.assertFalse(link.is_live())
        self.assertFalse(link.connected)

    def test_an_open_peer_with_data_waiting_is_live_and_nothing_is_eaten(self):
        link, theirs = self._pair()
        theirs.sendall(b"x")
        self.assertTrue(link.is_live())
        link._conn.settimeout(1.0)
        self.assertTrue(link.is_live())
        self.assertEqual(link._conn.gettimeout(), 1.0)
        self.assertEqual(link._conn.recv(1, socket.MSG_PEEK), b"x")

    def test_an_open_question_short_circuits_the_probe(self):
        link, theirs = self._pair()
        theirs.close()                      # dead -- but a question is open
        link._asking = 1
        with mock.patch.object(agentlink, "_still_connected",
                               wraps=agentlink._still_connected) as probe:
            self.assertTrue(link.is_live())
            probe.assert_not_called()
            link._asking = 0
            self.assertFalse(link.is_live())
            probe.assert_called_once()

    def test_notify_reaches_a_live_agent_as_a_notice(self):
        link, theirs = self._pair()
        link.notify("USB device still blocked", "port 3-9")
        theirs.settimeout(2.0)
        self.assertEqual(json.loads(theirs.recv(4096).decode()), {
            "type": agentlink.MSG_NOTICE,
            "title": "USB device still blocked", "body": "port 3-9"})

    def test_notify_never_raises_and_drops_a_dead_connection(self):
        link, theirs = self._pair()
        theirs.close()
        link.notify("USB device still blocked", "port 3-9")    # EPIPE inside
        self.assertFalse(link.connected)
        link.notify("t", "b")           # nobody connected: nothing to do


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
