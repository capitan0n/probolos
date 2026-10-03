"""
The daemon loop: screen-lock policy, the held queue, stage ordering, the
terminal prompt, and recovery when the event stream or a medium fails.

Covers probolos.daemon and probolos.session.
"""

from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import pty
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from probolos import __main__ as cli
from probolos import (
    agentlink,
    daemon,
    gate_client,
    mediawatch,
    quarantine,
    report,
    rules,
    safety,
    session,
    storage,
    sysfs,
    trust,
    usbclass,
)
from probolos import daemon as daemon_mod
from probolos import ledger as ledger_mod
from tests._support import ServiceStdin


def make_device(name="3-9", kinds=None):
    dev = mock.Mock(spec=sysfs.UsbDevice)
    dev.name = name
    dev.syspath = Path(f"/sys/bus/usb/devices/{name}")
    dev.kinds = kinds or [usbclass.KIND_STORAGE]
    dev.is_root_hub = False
    dev.claims = ["Mass Storage (SCSI)"]
    dev.vendor_id, dev.product_id = "0951", "1665"
    dev.serial = "ABC"
    dev.raw_descriptors = b"\x12\x01test"
    dev.removable = "removable"
    dev.label.return_value = "Kingston DataTraveler"
    # The fields rules.evaluate() actually walks. They were missing, and a
    # bare Mock returns another Mock for each -- which is not iterable, so
    # SemanticAnalyzer raised TypeError on every device in this module and
    # analyzers.run() swallowed it as a NOTICE. The tests still passed,
    # because a NOTICE is below CRITICAL and the trust path only checks that
    # threshold: the suite was exercising the fail-open rather than the rule
    # engine. Now that a decisive analyzer's failure is itself CRITICAL, the
    # stub has to be a device the rules can actually read.
    dev.interfaces = []
    dev.interface_classes = []
    dev.manufacturer = "Kingston"
    dev.product = "DataTraveler"
    dev.parse_error = None
    dev.descriptor_set = None
    dev.string_notes = []
    dev.string_note_fields = {}
    dev.speed = "480"
    dev.instance_id = (1, 1000 + abs(hash(name)) % 1000)
    dev.inspection_safe = True
    return dev


def make_stage_device(name="3-9", kinds=None):
    dev = mock.Mock(spec=sysfs.UsbDevice)
    dev.name = name
    dev.syspath = Path(f"/sys/bus/usb/devices/{name}")
    dev.kinds = kinds or [usbclass.KIND_STORAGE]
    dev.is_root_hub = False
    dev.claims = ["Mass Storage (SCSI)"]
    dev.vendor_id, dev.product_id = "0951", "1665"
    dev.serial = "ABC"
    dev.raw_descriptors = b"\x12\x01test"
    dev.removable = "removable"
    dev.label.return_value = "Kingston DataTraveler"
    return dev


# --------------------------------------------------------------------------
# 1. The event stream
# --------------------------------------------------------------------------

class _FakeMonitor:
    """Stands in for pyudev.Monitor: raises `errors` in order, then stops."""

    def __init__(self, errors, stop_event, fd):
        self._errors = list(errors)
        self._stop = stop_event
        self._fd = fd
        self.polls = 0

    def filter_by(self, **_kw):
        pass

    def start(self):
        pass

    def fileno(self):
        return self._fd

    def poll(self, timeout=None):
        self.polls += 1
        if self._errors:
            raise self._errors.pop(0)
        self._stop.set()
        return None


# ---------------------------------------------------------------------------
# 7. Port is not device
# ---------------------------------------------------------------------------

def _device(name="3-9", instance=(7, 4242)):
    dev = mock.Mock(spec=sysfs.UsbDevice)
    dev.name = name
    dev.syspath = Path(f"/sys/bus/usb/devices/{name}")
    dev.instance_id = instance
    dev.is_root_hub = False
    dev.kinds = ["storage"]
    dev.claims = []
    dev.vendor_id, dev.product_id, dev.serial = "0951", "1665", "A"
    dev.raw_descriptors = b"\x12\x01"
    dev.removable = "removable"
    dev.interfaces, dev.interface_classes = [], []
    dev.manufacturer, dev.product = "K", "DT"
    dev.parse_error = dev.descriptor_set = None
    dev.string_notes, dev.string_note_fields = [], {}
    dev.speed, dev.inspection_safe = "480", True
    dev.label.return_value = "K DT"
    return dev


class TestSessionMonitors(unittest.TestCase):

    def test_fixed_state_reports_what_it_was_given(self):
        self.assertTrue(session.FixedState(True).is_locked())
        self.assertFalse(session.FixedState(False).is_locked())

    def test_fallback_reports_unlocked_and_says_so(self):
        """
        Assuming 'locked' would break the tool on any system it does not
        understand; assuming 'unlocked' silently would disable a protection the
        user believes is running. So it assumes unlocked AND describes itself
        as inactive, which is printed at startup.
        """
        fallback = session.AlwaysUnlocked()
        self.assertFalse(fallback.is_locked())
        self.assertIn("inactive", fallback.describe)

    def test_detect_honours_a_forced_state(self):
        self.assertTrue(session.detect(force=True).is_locked())
        self.assertFalse(session.detect(force=False).is_locked())

    def test_logind_without_the_binary_returns_unknown(self):
        monitor = session.LogindMonitor()
        monitor._binary = None
        self.assertIsNone(monitor.is_locked())


class TestLockedBehaviour(unittest.TestCase):

    def setUp(self):
        self.writes = []
        self.engine = daemon_mod.Probolos(
            monitor=session.FixedState(True),
            lock_policy=session.POLICY_QUEUE,
            observe=0)

    def run_add(self, dev):
        with mock.patch.object(daemon_mod.sysfs, "set_authorized",
                               side_effect=lambda p, v: self.writes.append(v)), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            self.engine._on_add(str(dev.syspath))

    def test_device_is_held_not_authorized(self):
        dev = make_device()
        self.run_add(dev)
        self.assertEqual(self.writes, [0], "device must be left blocked")
        self.assertIn("3-9", self.engine.pending)

    def test_the_device_is_never_powered_up_while_locked(self):
        """
        Quarantine and the storage scan both switch the device on. Neither may
        run while nobody is present -- powering up unknown hardware in an empty
        room is the situation being defended against.
        """
        dev = make_device(kinds=[usbclass.KIND_INPUT, usbclass.KIND_STORAGE])
        with mock.patch.object(self.engine, "_quarantine") as quarantine_fn, \
             mock.patch.object(self.engine, "_inspect_medium") as inspect_fn:
            self.run_add(dev)
            quarantine_fn.assert_not_called()
            inspect_fn.assert_not_called()
        self.assertNotIn(1, self.writes, "device must never be authorized")

    def test_a_remembered_device_is_still_held(self):
        """
        Trust exists to avoid asking about your own hardware. A device attached
        while you were absent is exactly when asking is correct, so trust does
        not apply here.
        """
        trust_store = mock.Mock()
        trust_store.is_trusted.return_value = True
        self.engine.trust = trust_store

        dev = make_device()
        self.run_add(dev)

        self.assertIn("3-9", self.engine.pending)
        self.assertNotIn(1, self.writes)

    def test_deny_policy_does_not_queue(self):
        engine = daemon_mod.Probolos(monitor=session.FixedState(True),
                                     lock_policy=session.POLICY_DENY,
                                     observe=0)
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._on_add(str(dev.syspath))
        self.assertEqual(engine.pending, {})

    def test_ignore_policy_asks_normally(self):
        engine = daemon_mod.Probolos(monitor=session.FixedState(True),
                                     lock_policy=session.POLICY_IGNORE,
                                     observe=0)
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(engine, "_ask", return_value=False) as ask, \
             mock.patch.object(daemon_mod.report, "render", return_value=""), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"), \
             mock.patch.object(engine, "_inspect_medium", return_value=None):
            engine._on_add(str(dev.syspath))
            ask.assert_called_once()


class TestUnlockDrainsTheQueue(unittest.TestCase):

    def test_held_devices_are_asked_about_on_unlock(self):
        """The requirement: no unplug-and-replug just because you stepped away."""
        engine = daemon_mod.Probolos(monitor=session.FixedState(True),
                                     lock_policy=session.POLICY_QUEUE,
                                     observe=0)
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), None)

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, ["/sys/bus/usb/devices/3-9"])
        self.assertEqual(engine.pending, {})

    def test_a_device_unplugged_while_held_is_not_asked_about(self):
        engine = daemon_mod.Probolos(monitor=session.FixedState(True),
                                     observe=0)
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), None)

        asked = []
        with mock.patch.object(Path, "exists", return_value=False), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, [])

    def test_removal_withdraws_a_held_question(self):
        engine = daemon_mod.Probolos(observe=0)
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), None)
        engine._on_remove("/sys/bus/usb/devices/3-9")
        self.assertEqual(engine.pending, {})

    def test_queue_preserves_arrival_order(self):
        engine = daemon_mod.Probolos(observe=0)
        for name in ("3-1", "3-2", "3-3"):
            engine.pending[name] = (Path(f"/sys/bus/usb/devices/{name}"), None)

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(Path(p).name)):
            engine._drain_pending()

        self.assertEqual(asked, ["3-1", "3-2", "3-3"])

    def test_draining_an_empty_queue_is_harmless(self):
        engine = daemon_mod.Probolos(observe=0)
        engine._drain_pending()      # must not raise
        self.assertEqual(engine.pending, {})


class TestStrandedDevicesAtStartup(unittest.TestCase):
    """
    Found in use: after Ctrl-C with a device still held, restarting Probolos
    treated that device as part of the baseline. It stayed at authorized=0 --
    dead -- and was never asked about, so the only way to get a question was to
    unplug and replug the hardware. Exactly what the hold queue exists to avoid.

    A device at authorized=0 is not "already working, leave it alone"; it is
    something that was blocked and never decided.
    """

    def make(self, name, authorized):
        dev = mock.Mock(spec=sysfs.UsbDevice)
        dev.name = name
        dev.syspath = Path(f"/sys/bus/usb/devices/{name}")
        dev.authorized = authorized
        dev.is_root_hub = False
        return dev

    def test_blocked_devices_are_queued_not_ignored(self):
        engine = daemon_mod.Probolos(observe=0)
        devices = [self.make("3-1", 1), self.make("3-9", 0)]

        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=devices), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine.snapshot()

        self.assertIn("3-1", engine.known, "working devices stay in baseline")
        self.assertNotIn("3-9", engine.known, "blocked device must not be baseline")
        self.assertIn("3-9", engine.pending, "blocked device must be queued")

    def test_root_hubs_are_never_queued(self):
        engine = daemon_mod.Probolos(observe=0)
        hub = self.make("usb1", 0)
        hub.is_root_hub = True

        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=[hub]), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine.snapshot()

        self.assertEqual(engine.pending, {})

    def test_devices_with_unknown_state_stay_in_baseline(self):
        """Only an explicit 0 means blocked; None means we could not read it."""
        engine = daemon_mod.Probolos(observe=0)
        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=[self.make("3-4", None)]), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine.snapshot()
        self.assertIn("3-4", engine.known)
        self.assertEqual(engine.pending, {})

    def test_exit_reports_what_is_left_blocked(self):
        """Leaving hardware dead without saying so is how a tool gets a name
        for breaking things."""
        engine = daemon_mod.Probolos(observe=0)
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), None)
        with mock.patch("builtins.print") as printed:
            engine.report_blocked_on_exit()
        text = " ".join(str(c) for c in printed.call_args_list)
        self.assertIn("3-9", text)
        self.assertIn("--release", text)


class TestHeldDevicesBypassTrust(unittest.TestCase):
    """
    Deferring a question must not quietly become approving it.

    "Nothing is admitted while you are away, including remembered devices" is
    only true if the deferred question is actually put. If the trust shortcut
    applies when the queue drains, the policy silently degrades to "nothing is
    admitted until you get back, then everything is".
    """

    def build(self):
        dev = make_device()
        trust_store = mock.Mock()
        trust_store.is_trusted.return_value = True
        engine = daemon_mod.Probolos(observe=0, trust_store=trust_store,
                                     monitor=session.FixedState(False),
                                     lock_policy=session.POLICY_IGNORE,
                                     inspect_storage=False)
        return engine, dev

    def run_add(self, engine, dev, was_held):
        asked = []
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(engine, "_ask",
                               side_effect=lambda *a, **k: asked.append(1) or False), \
             mock.patch.object(daemon_mod.report, "render", return_value=""), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._on_add(str(dev.syspath), was_held=was_held)
        return asked

    def test_a_held_device_is_asked_about_even_when_remembered(self):
        engine, dev = self.build()
        self.assertTrue(self.run_add(engine, dev, was_held=True),
                        "a device that arrived while you were away must be "
                        "asked about, remembered or not")

    def test_a_normally_attached_remembered_device_is_still_silent(self):
        """The everyday case must stay frictionless, or the tool gets switched off."""
        engine, dev = self.build()
        self.assertFalse(self.run_add(engine, dev, was_held=False))

    def test_drain_marks_devices_as_held(self):
        engine, dev = self.build()
        engine.pending[dev.name] = (dev.syspath, dev.instance_id)
        seen = []
        # _still_same_device is stubbed True: this test is about the was_held
        # flag, and the port-recycling check has tests of its own below.
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_still_same_device", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: seen.append(was_held)):
            engine._drain_pending()
        self.assertEqual(seen, [True])


class StageOrdering(unittest.TestCase):

    def setUp(self):
        self.writes = []
        # Unlocked, storage inspection ON, no observation window so the grab
        # path itself does not need a real device. observe=0 means stage 3 is
        # skipped, which is fine: what we are pinning is that stage 4 does not
        # authorize a device that can type.
        self.engine = daemon_mod.Probolos(
            monitor=session.AlwaysUnlocked(),
            observe=0,
            inspect_storage=True)

    def run_add(self, dev, approved=False):
        with mock.patch.object(daemon_mod.sysfs, "set_authorized",
                               side_effect=lambda p, v: self.writes.append(v)), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(self.engine, "_ask", return_value=approved), \
             mock.patch.object(daemon_mod.report, "one_liner",
                               return_value="x"), \
             mock.patch.object(daemon_mod.report, "render",
                               return_value="x"):
            self.engine._on_add(str(dev.syspath))

    def test_composite_input_storage_is_not_inspected(self):
        dev = make_stage_device(kinds=[usbclass.KIND_INPUT, usbclass.KIND_STORAGE])
        with mock.patch.object(self.engine, "_inspect_medium") as inspect_fn:
            self.run_add(dev, approved=False)
            inspect_fn.assert_not_called()

    def test_composite_input_storage_is_never_authorized_before_decision(self):
        """
        The whole point of C1: no set_authorized(1) may reach a device that can
        type until the human has said yes. With observe=0 and a rejection, the
        only writes should be the deny-by-default blocking writes -- never a 1.
        """
        dev = make_stage_device(kinds=[usbclass.KIND_INPUT, usbclass.KIND_STORAGE])
        self.run_add(dev, approved=False)
        self.assertNotIn(1, self.writes,
                         "a device that can type was authorized before the "
                         "human decided -- this is the C1 exposure window")

    def test_pure_storage_is_still_inspected(self):
        """The fix must not disable stage 4 for ordinary flash drives."""
        dev = make_stage_device(kinds=[usbclass.KIND_STORAGE])
        with mock.patch.object(self.engine, "_inspect_medium",
                               return_value=None) as inspect_fn:
            self.run_add(dev, approved=False)
            inspect_fn.assert_called_once()

    def test_storage_plus_other_functions_is_not_inspected(self):
        """
        Storage + network (RNDIS/ECM), serial or vendor interfaces: stage 4
        would switch those functions on before any decision. Only a device
        that declares storage and nothing else may be activated to look.
        """
        for extra in (usbclass.KIND_OTHER, usbclass.KIND_WIRELESS,
                      usbclass.KIND_HUB):
            with self.subTest(extra=extra):
                self.writes.clear()
                dev = make_stage_device(kinds=[usbclass.KIND_STORAGE, extra])
                with mock.patch.object(self.engine,
                                       "_inspect_medium") as inspect_fn:
                    self.run_add(dev, approved=False)
                    inspect_fn.assert_not_called()
                self.assertNotIn(1, self.writes)

    def test_parsed_storage_plus_rndis_is_never_authorized_before_decision(self):
        """End to end from a real blob: a Pi Zero g_multi-style composite."""
        import struct
        import tempfile

        from probolos import storage

        def intf(num, cls, sub, proto):
            return (struct.pack("<BBBBBBBBB", 9, 4, num, 0, 1, cls, sub, proto, 0)
                    + struct.pack("<BBBBHB", 7, 5, 0x81, 2, 512, 0))

        body = intf(0, 0xE0, 1, 3) + intf(1, 0x0A, 0, 0) + intf(2, 0x08, 6, 0x50)
        blob = (struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0xEF, 2, 1, 64,
                            0x1d6b, 0x0104, 0x0100, 1, 2, 3, 1)
                + struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 3, 1, 0, 0x80, 50)
                + body)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "3-9"
            path.mkdir()
            for name, value in (("idVendor", "1d6b"), ("idProduct", "0104"),
                                ("authorized", "0"), ("removable", "removable")):
                (path / name).write_text(value)
            (path / "descriptors").write_bytes(blob)
            dev = sysfs.load_device(path)
            self.assertTrue(dev.inspection_safe)
            self.assertIn(usbclass.KIND_STORAGE, dev.kinds)
            with mock.patch.object(storage, "find_block_devices",
                                   return_value=[]):
                self.run_add(dev, approved=False)
        self.assertNotIn(1, self.writes,
                         "a storage+network composite was switched on before "
                         "the human decided")


class LockMonitorIsNotDecidedBeforeLogin(unittest.TestCase):
    """
    detect() fell back to AlwaysUnlocked whenever no graphical session existed
    yet -- which is always the case for a service started at boot -- and the
    lock policy then stayed off for the whole run.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.flag = os.path.join(self.tmp, "logged-in")
        self.loginctl = os.path.join(self.tmp, "loginctl")
        with open(self.loginctl, "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                'if [ "$1" = list-sessions ]; then\n'
                f'  [ -f {self.flag} ] && echo "2 1000 alice seat0 tty2"\n'
                "  exit 0\n"
                "fi\n"
                'case "$*" in *LockedHint*) echo LockedHint=yes ;;\n'
                "  *) echo Type=wayland; echo Remote=no ;; esac\n")
        os.chmod(self.loginctl, 0o755)

    def test_lock_is_seen_after_a_login_that_followed_startup(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (self.loginctl,)):
            monitor = session.detect()
            self.assertIsNone(monitor.is_locked())      # nobody logged in yet
            open(self.flag, "w").close()                 # login, then lock
            self.assertTrue(monitor.is_locked())

    def test_no_logind_still_falls_back(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (os.path.join(self.tmp, "absent"),)):
            self.assertIsInstance(session.detect(), session.AlwaysUnlocked)


class GreeterSessionIsNotSomeonePresent(unittest.TestCase):
    """
    GDM keeps its greeter (user `gdm`, Class=greeter, Type=wayland) running
    beside the real session and never sets LockedHint. It counted as an
    unlocked graphical session, so a locked screen read as "someone present"
    and the greeter account could be chosen to answer the agent.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.loginctl = os.path.join(self.tmp, "loginctl")
        with open(self.loginctl, "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                'if [ "$1" = list-sessions ]; then\n'
                '  echo "c1 120 gdm seat0 tty1"; echo "2 1000 alice seat0 tty2"\n'
                "  exit 0\n"
                "fi\n"
                'sid="$2"; shift 2\n'
                'for p in "$@"; do case "$sid:$p" in\n'
                "  c1:Class) echo Class=greeter;; 2:Class) echo Class=user;;\n"
                "  c1:LockedHint) echo LockedHint=no;; 2:LockedHint) echo LockedHint=yes;;\n"
                "  c1:Name) echo Name=gdm;; 2:Name) echo Name=alice;;\n"
                "  c1:Active) echo Active=no;; 2:Active) echo Active=yes;;\n"
                "  *:Type) echo Type=wayland;; *:Remote) echo Remote=no;;\n"
                "esac; done\n")
        os.chmod(self.loginctl, 0o755)

    def test_locked_user_session_is_locked_despite_greeter(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (self.loginctl,)):
            self.assertTrue(session.detect().is_locked())

    def test_agent_user_is_the_active_person_not_the_greeter(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (self.loginctl,)), \
                mock.patch.dict(os.environ, {"SUDO_USER": ""}):
            self.assertEqual(cli._active_session_user(), "alice")


class MissingPyudevIsRefusedBeforeTheGateCloses(unittest.TestCase):

    def test_the_gate_is_never_entered(self):
        with mock.patch.object(daemon_mod, "pyudev", None), \
                mock.patch.object(daemon_mod.gate, "AuthorizationGate") as gate, \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                daemon_mod.serve(dry_run=True)
        self.assertIn("pyudev", str(caught.exception))
        gate.assert_not_called()


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


class EventStreamOverflowDoesNotEndTheGate(unittest.TestCase):

    def _run(self, errors):
        stop = threading.Event()
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        monitor = _FakeMonitor(errors, stop, a.fileno())
        fake_pyudev = mock.Mock()
        fake_pyudev.Monitor.from_netlink.return_value = monitor
        engine = daemon_mod.Probolos(monitor=session.AlwaysUnlocked(),
                                     stop_event=stop)
        with mock.patch.object(daemon_mod, "pyudev", fake_pyudev), \
                mock.patch("builtins.print"):
            engine.run()
        return monitor

    def test_enobufs_from_poll_is_survived(self):
        """
        Uncaught, this left run(): the `with AuthorizationGate` block reopened
        every root hub and the daemon exited, from an overflow a busy loop can
        produce.
        """
        monitor = self._run([OSError(errno.ENOBUFS, "No buffer space")] * 3)
        self.assertEqual(monitor.polls, 4, "the loop kept polling afterwards")

    def test_other_stream_errors_still_propagate(self):
        with self.assertRaises(OSError):
            self._run([OSError(errno.EBADF, "Bad file descriptor")])


# ---------------------------------------------------------------------------
# 6. Wiring: daemon and command line
# ---------------------------------------------------------------------------

class DaemonWiring(unittest.TestCase):

    def setUp(self):
        self.watch = mock.Mock(spec=mediawatch.MediaWatch)
        self.engine = daemon_mod.Probolos(monitor=session.AlwaysUnlocked(),
                                          observe=0, inspect_storage=False,
                                          media_watch=self.watch)

    def test_block_events_reach_the_watcher(self):
        event = mock.Mock(subsystem="block", action="change",
                          sys_path="/sys/x/block/sdb",
                          properties={"DISK_MEDIA_CHANGE": "1"})
        self.engine._dispatch(event)
        self.watch.handle.assert_called_once_with(
            "change", "/sys/x/block/sdb", {"DISK_MEDIA_CHANGE": "1"})

    def test_usb_events_still_reach_the_gate(self):
        event = mock.Mock(subsystem="usb", action="add", sys_path="/sys/x/1-2")
        with mock.patch.object(self.engine, "_on_add") as on_add:
            self.engine._dispatch(event)
        on_add.assert_called_once_with("/sys/x/1-2")
        self.watch.handle.assert_not_called()

    def test_an_approved_reader_is_registered(self):
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "admit_device"), \
             mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(self.engine, "_ask", return_value=True), \
             mock.patch.object(daemon_mod.report, "one_liner",
                               return_value="x"), \
             mock.patch.object(daemon_mod.report, "render",
                               return_value="x"), \
             redirect_stdout(io.StringIO()):
            self.engine._on_add(str(dev.syspath))
        self.watch.register.assert_called_once_with(dev, "approved")

    def test_a_rejected_reader_is_not_registered(self):
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(self.engine, "_ask", return_value=False), \
             mock.patch.object(daemon_mod.report, "one_liner",
                               return_value="x"), \
             mock.patch.object(daemon_mod.report, "render",
                               return_value="x"), \
             redirect_stdout(io.StringIO()):
            self.engine._on_add(str(dev.syspath))
        self.watch.register.assert_not_called()

    def test_baseline_readers_are_registered_at_startup(self):
        dev = make_device("1-7")
        dev.authorized = 1
        dev.is_root_hub = False
        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=[dev]), \
             redirect_stdout(io.StringIO()):
            self.engine.snapshot()
        self.watch.register.assert_called_once_with(dev, "present at startup")

    def test_removal_unregisters(self):
        with redirect_stdout(io.StringIO()):
            self.engine._on_remove("/sys/bus/usb/devices/1-2")
        self.watch.unregister.assert_called_once_with("1-2")

    def test_a_policy_deauthorization_puts_the_reader_back_behind_the_gate(self):
        dev = make_device("1-2")
        self.engine.known.add("1-2")
        self.engine._media_policy_deauthorized(dev, [])
        self.assertNotIn("1-2", self.engine.known)


# ---------------------------------------------------------------------------
# 6. loginctl
# ---------------------------------------------------------------------------

class LoginctlIsNotResolvedThroughPath(unittest.TestCase):
    """
    shutil.which() walks $PATH, and this runs as root -- once a second from
    the daemon's poll loop, and again for every device. sudo preserves PATH
    under a !secure_path or env_keep configuration and a systemd unit can be
    given any Environment=PATH at all, so a writable directory earlier in PATH
    turned "ask logind whether the screen is locked" into "execute whatever is
    called loginctl", as root.

    In __main__ it is worse than an exec: a fake loginctl that simply PRINTS a
    chosen Name= hands the agent slot -- who may answer questions about
    hardware -- to a uid of its choosing.
    """

    def setUp(self):
        self.fake = Path(tempfile.mkdtemp())
        impostor = self.fake / "loginctl"
        impostor.write_text("#!/bin/sh\necho owned\n")
        impostor.chmod(0o755)
        self._path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fake}:{self._path}"

    def tearDown(self):
        os.environ["PATH"] = self._path

    def test_a_planted_loginctl_on_path_is_never_chosen(self):
        found = session._find_loginctl()
        self.assertNotEqual(found, str(self.fake / "loginctl"))
        if found is not None:
            self.assertIn(found, session._LOGINCTL_CANDIDATES)

    def test_the_monitor_does_not_pick_it_up_either(self):
        monitor = session.LogindMonitor()
        self.assertNotEqual(monitor._binary, str(self.fake / "loginctl"))

    def test_only_absolute_candidates_are_considered(self):
        for candidate in session._LOGINCTL_CANDIDATES:
            self.assertTrue(candidate.startswith("/"),
                            "a relative candidate would reintroduce the hole")

    def test_a_non_executable_candidate_is_skipped(self):
        decoy = self.fake / "loginctl-noexec"
        decoy.write_text("")
        decoy.chmod(0o644)
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES", (str(decoy),)):
            self.assertIsNone(session._find_loginctl())

    def test_a_directory_named_loginctl_is_skipped(self):
        decoy = self.fake / "as-a-dir"
        decoy.mkdir()
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES", (str(decoy),)):
            self.assertIsNone(session._find_loginctl())


class AHeldQuestionBelongsToADeviceNotAPort(unittest.TestCase):
    """
    A sysfs name like "1-4" is a PORT. The held queue stored only that name
    and its path, so an attacker with physical access -- the threat the whole
    lock policy exists for -- could pull the held device while the screen was
    locked and insert their own at the same port. Both are named "1-4", and
    the operator's question, and their expectation of what they were being
    asked about, transferred silently to the substitute.
    """

    def test_a_recycled_port_does_not_inherit_the_question(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(False))
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), (7, 4242))

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_still_same_device", return_value=False), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, [], "a different device at the same port must "
                                    "not be asked about under the old entry")
        self.assertEqual(engine.pending, {})

    def test_the_same_device_is_still_asked_about(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(False))
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), (7, 4242))

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_still_same_device", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, ["/sys/bus/usb/devices/3-9"])

    def test_still_same_device_compares_the_real_inode(self):
        root = Path(tempfile.mkdtemp())
        devdir = root / "3-9"
        devdir.mkdir()
        st = devdir.stat()
        self.assertTrue(daemon_mod.Probolos._still_same_device(
            devdir, (st.st_dev, st.st_ino)))
        self.assertFalse(daemon_mod.Probolos._still_same_device(
            devdir, (st.st_dev, st.st_ino + 1)))

    def test_a_vanished_path_is_not_the_same_device(self):
        self.assertFalse(daemon_mod.Probolos._still_same_device(
            Path("/nonexistent/3-9"), (1, 2)))

    def test_queueing_records_the_instance(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(True),
                                     lock_policy=session.POLICY_QUEUE)
        dev = _device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._hold_until_unlocked(dev)
        self.assertEqual(engine.pending["3-9"], (dev.syspath, (7, 4242)))


class AnAdmittedDeviceIsNotReGated(unittest.TestCase):
    """
    `known` only ever held the startup baseline: nothing recorded that a
    device had been admitted. udev delivers duplicate 'add' events routinely
    (a `udevadm trigger`, a settle, a subsystem rescan), and each one re-ran
    the whole gate on hardware that was past it -- including _quarantine(),
    which writes authorized=0 and back to 1 on a device the user is USING and
    takes an EVIOCGRAB on input they expect to reach their session.
    """

    def _engine(self):
        return daemon_mod.Probolos(observe=0, inspect_storage=False,
                                   monitor=session.FixedState(False),
                                   lock_policy=session.POLICY_IGNORE)

    def _add(self, engine, dev, approve=True):
        with mock.patch.object(daemon_mod.sysfs, "admit_device"), \
             mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(engine, "_ask", return_value=approve), \
             mock.patch.object(daemon_mod.report, "render", return_value=""), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._on_add(str(dev.syspath))

    def test_an_approved_device_is_recorded_as_known(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)
        self.assertIn("3-9", engine.known,
                      "a device past the gate must not be gated again")

    def test_a_second_add_for_an_approved_device_is_ignored(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)

        asked = []
        with mock.patch.object(engine, "_load_with_retry",
                               side_effect=lambda p: asked.append(p)):
            engine._on_add(str(dev.syspath))
        self.assertEqual(asked, [], "a duplicate udev 'add' must not re-run "
                                    "the gate on live hardware")

    def test_a_rejected_device_is_NOT_recorded(self):
        """
        The other direction matters just as much: a device the user refused
        must be asked about again if it comes back, not silently ignored.
        """
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=False)
        self.assertNotIn("3-9", engine.known)

    def test_removal_clears_the_record(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)
        engine._on_remove(str(dev.syspath))
        self.assertNotIn("3-9", engine.known,
                         "the port must be gated again after an unplug")


class ThePromptOffersWhatItAccepts(unittest.TestCase):
    """
    With --timeout set, the countdown prompt replaced the whole prompt string
    with "[y/N]" -- dropping [a]lways from the text while the parser below
    went on accepting it. That is a hidden control on the one prompt in the
    tool that grants something permanent: a user typing `a` for "abort", which
    is what a bare [y/N] invites you to assume it is not, created a trust
    entry that admits that device silently from then on.
    """

    def _engine(self, *, timeout, has_trust, writable=True):
        from probolos import daemon as daemon_mod

        engine = daemon_mod.Probolos.__new__(daemon_mod.Probolos)
        engine.timeout = timeout
        engine.trust = (mock.Mock(**{"writable.return_value": writable})
                        if has_trust else None)
        engine.agent = None
        engine.observe = 0
        return engine

    def _prompt_for(self, *, timeout, has_trust, writable=True, typed=""):
        import io
        import sys as _sys

        from probolos import daemon as daemon_mod

        engine = self._engine(timeout=timeout, has_trust=has_trust,
                              writable=writable)
        captured = io.StringIO()
        real_stdout, real_stdin = _sys.stdout, _sys.stdin
        _sys.stdout = captured
        _sys.stdin = io.StringIO(typed)   # "" = EOF -> denied, after the prompt
        try:
            self.answer = daemon_mod.Probolos._ask(engine, dev=None,
                                                   findings=())
        except Exception:
            self.answer = None
        finally:
            _sys.stdout, _sys.stdin = real_stdout, real_stdin
        return captured.getvalue()

    def test_always_is_shown_whenever_always_is_accepted(self):
        text = self._prompt_for(timeout=30.0, has_trust=True)
        self.assertIn("[a]lways", text.lower(),
                      "the countdown prompt accepts 'a' but did not offer it")

    def test_no_always_is_offered_without_a_trust_store(self):
        text = self._prompt_for(timeout=30.0, has_trust=False)
        self.assertNotIn("[a]lways", text.lower())

    def test_no_always_is_offered_when_trust_cannot_be_saved(self):
        """Under --privsep the analyzer reads trust and cannot write it; an
        "always" there admitted once and silently lost the trust entry."""
        for timeout in (0.0, 30.0):
            text = self._prompt_for(timeout=timeout, has_trust=True,
                                    writable=False)
            self.assertNotIn("[a]lways", text.lower())

    def _answered_after(self, typed):
        import io
        import sys as _sys
        from probolos import daemon as daemon_mod
        engine = self._engine(timeout=0.0, has_trust=False)
        real = _sys.stdin, _sys.stdout
        _sys.stdin, _sys.stdout = io.StringIO(typed), io.StringIO()
        try:
            approved = daemon_mod.Probolos._ask(engine, dev=None, findings=())
        finally:
            _sys.stdin, _sys.stdout = real
        return approved, engine._answered

    def test_no_input_denies_but_is_not_an_answer(self):
        """The service's stdin is /dev/null: EOF must deny, and must not be
        recorded as a person saying no."""
        self.assertEqual(self._answered_after(""), (False, False))

    def test_a_typed_no_is_an_answer(self):
        self.assertEqual(self._answered_after("n\n"), (False, True))

    def test_always_typed_anyway_is_not_accepted_when_not_offered(self):
        self._prompt_for(timeout=0.0, has_trust=True, writable=False,
                         typed="a\n")
        self.assertFalse(self.answer)


class LoginctlTimeoutIsContained(unittest.TestCase):
    """
    is_locked() is called once a second from the main loop and once per device.

    The handling only ever wrapped _graphical_sessions(). _locked_hint() runs
    in the loop BELOW that try, so a loginctl call that exceeded its three
    second timeout raised TimeoutExpired out of is_locked() and killed the
    daemon -- a lock-state lookup taking the gate down with it.
    """

    def test_a_hung_loginctl_degrades_to_unknown(self):
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"

        calls = {"n": 0}

        def hang(*args, **kwargs):
            calls["n"] += 1
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        real_run = subprocess.run
        subprocess.run = hang
        try:
            self.assertIsNone(monitor.is_locked())
        finally:
            subprocess.run = real_run
        self.assertGreater(calls["n"], 0)

    def test_a_hung_hint_lookup_does_not_escape_either(self):
        """The specific gap: the sessions list succeeds, the hint call hangs."""
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"
        monitor._graphical_sessions = lambda: ["c1"]

        def hang(session_id):
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        monitor._locked_hint = hang
        with self.assertRaises(subprocess.TimeoutExpired):
            monitor._locked_hint("c1")     # the hazard is real...
        # ...and _run(), which is where the real call lives, contains it.
        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="loginctl", timeout=3))
        try:
            self.assertEqual(session.LogindMonitor._run(monitor, "x"), "")
        finally:
            subprocess.run = real_run


class DaemonWaitsForTheNode(unittest.TestCase):
    """The poll waits on the /dev node, not only on the sysfs entry."""

    def setUp(self):
        self.engine = daemon_mod.Probolos(
            monitor=session.AlwaysUnlocked(), observe=0, inspect_storage=True)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dev = types.SimpleNamespace(syspath=Path(tmp.name), name="3-9")

    def _run(self, pending):
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(daemon_mod.storage, "find_block_devices",
                               return_value=["/dev/sda"]), \
             mock.patch.object(daemon_mod.sysfs, "block_node_pending",
                               side_effect=pending) as pending_fn, \
             mock.patch.object(daemon_mod.storage, "inspect_safely",
                               return_value=storage.MediumReport(
                                   device="/dev/sda", scheme="none")) as scan, \
             contextlib.redirect_stdout(io.StringIO()):
            medium = self.engine._inspect_medium(self.dev)
        return medium, pending_fn, scan

    def test_a_late_node_is_waited_for_then_inspected(self):
        late = ["device node does not exist yet"] * 3 + [None]
        medium, pending_fn, scan = self._run(late)
        self.assertEqual(pending_fn.call_count, 4)
        scan.assert_called_once()
        self.assertIsNone(medium.error)

    def test_a_node_that_never_appears_is_reported_as_such(self):
        medium, _pending, scan = self._run(
            lambda _p: "device node does not exist yet")
        scan.assert_not_called()
        self.assertIn("did not become ready", medium.error)
        # The node path and the pending reason are audit detail, not prompt text.
        self.assertNotIn("/dev/sda", medium.error)
        self.assertIn("does not exist yet", medium.detail)


class EveryMediumFailureTakesOnePath(unittest.TestCase):
    """
    Removal during inspection reached the operator two ways. When the switch-on
    write failed, the raw FileNotFoundError -- with the full sysfs path -- was
    printed at the prompt and no MEDIUM block or identity-only notice followed.
    When the block node never appeared, both were shown. Every failure now
    converges on the second behaviour, with the raw detail kept for the log.
    """

    SYSPATH_LEAK = "/sys/devices/pci0000:00/0000:00:14.0/usb3/3-9"

    def setUp(self):
        self.engine = daemon_mod.Probolos(
            monitor=session.AlwaysUnlocked(), observe=0, inspect_storage=True)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dev = types.SimpleNamespace(syspath=Path(tmp.name), name="3-9")

    def _switch_on_fails(self):
        def refuse(_path, value):
            if value == 1:
                raise FileNotFoundError(2, "No such file or directory",
                                        self.SYSPATH_LEAK)
        out = io.StringIO()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized", refuse), \
             contextlib.redirect_stdout(out):
            medium = self.engine._inspect_medium(self.dev)
        return medium, out.getvalue()

    def _assert_unexamined_and_clean(self, medium, printed):
        self.assertIsNotNone(medium)
        rendered = " ".join(
            report.render_medium(medium, rules.storage_findings(medium)).split())
        shown = printed + rendered
        self.assertIn("not inspected", rendered)
        self.assertIn("judged on its declared identity alone", rendered)
        self.assertNotIn(self.SYSPATH_LEAK, shown)
        self.assertNotIn("Errno", shown)

    def test_a_refused_switch_on_is_reported_as_unexamined(self):
        medium, printed = self._switch_on_fails()
        self._assert_unexamined_and_clean(medium, printed)
        self.assertIn("switched on", medium.error)
        self.assertIn(self.SYSPATH_LEAK, medium.detail)

    def test_a_device_gone_by_then_is_reported_as_removed(self):
        self.dev.syspath = Path(self.dev.syspath) / "gone"
        medium, printed = self._switch_on_fails()
        self._assert_unexamined_and_clean(medium, printed)
        self.assertEqual(medium.error,
                         "the device was removed during inspection")

    def test_a_raw_read_error_stays_out_of_the_prompt(self):
        raw = storage.MediumReport(
            device="/dev/sda",
            error="[Errno 5] Input/output error: '/dev/sda'")
        out = io.StringIO()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(daemon_mod.storage, "find_block_devices",
                               return_value=["/dev/sda"]), \
             mock.patch.object(daemon_mod.sysfs, "block_node_pending",
                               return_value=None), \
             mock.patch.object(daemon_mod.storage, "inspect_safely",
                               return_value=raw), \
             contextlib.redirect_stdout(out):
            medium = self.engine._inspect_medium(self.dev)
        self._assert_unexamined_and_clean(medium, out.getvalue())
        self.assertNotIn("/dev/sda", medium.error)
        self.assertIn("Input/output error", medium.detail)

    def test_the_warning_survives_the_rule_being_disabled(self):
        medium, _printed = self._switch_on_fails()
        rendered = " ".join(report.render_medium(medium, []).split())
        self.assertIn("judged on declared identity alone", rendered)

    def test_the_detail_reaches_the_audit_log(self):
        medium, _printed = self._switch_on_fails()
        dev = mock.Mock(name="dev", vendor_id="058f", product_id="6387",
                        manufacturer="m", product="p", serial="s",
                        claims=[], kinds=[])
        dev.name = "3-9"
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            self.engine.json_log = log
            self.engine.ledger = None
            self.engine._record(
                daemon_mod.Decision(dev, False, "user rejected", 0.0),
                rules.storage_findings(medium), medium)
            entry = json.loads(log.read_text().splitlines()[-1])
        self.assertFalse(entry["medium"]["examined"])
        self.assertIn(self.SYSPATH_LEAK, entry["medium"]["detail"])


# ---------------------------------------------------------------------------
# "Always" under --privsep: the analyzer cannot write trust, the gate can
# ---------------------------------------------------------------------------

class AlwaysUnderPrivsep(unittest.TestCase):
    """
    Under --privsep the analyzer runs as `nobody` and cannot write the
    root-owned trust store, so "always" was never offered and the service
    asked about its owner's own mouse on every plug. The gate now writes the
    entry (REQ_TRUST); the daemon must offer "always" when that path exists,
    use it, and pick up what the gate wrote.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "trusted.json"
        self.store = trust.TrustStore(self.path)
        # The analyzer's view: it can read the store, never write it.
        patcher = mock.patch.object(self.store, "writable", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = mock.Mock()
        self.client.trust.side_effect = self._gate_writes
        previous = sysfs._backend
        self.addCleanup(sysfs.install_backend, previous)
        sysfs.install_backend(gate_client.GateBackend(self.client))
        self.dev = _device()

    def _gate_writes(self, syspath, instance, key, label):
        """What the root gate does on success: a whole new file on disk."""
        writer = trust.TrustStore(self.path)
        writer.devices[key] = trust.TrustedDevice(
            key=key, identity="0951:1665:A", label=label,
            descriptor_hash=key.split("#")[1], trusted_at=1.0, last_seen=1.0,
            times_admitted=1, ports=["3-9"])
        self.assertIsNone(writer.save(readable=True))

    def _engine(self):
        return daemon_mod.Probolos(observe=0, inspect_storage=False,
                                   monitor=session.FixedState(False),
                                   lock_policy=session.POLICY_IGNORE,
                                   trust_store=self.store)

    def _add(self, engine, typed="a\n"):
        """Plug the device in and answer the terminal prompt with `typed`."""
        out = io.StringIO()
        with mock.patch.object(daemon_mod.sysfs, "admit_device") as admit, \
                mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
                mock.patch.object(daemon_mod.analyzers, "run", return_value=[]), \
                mock.patch.object(engine, "_load_with_retry",
                                  return_value=self.dev), \
                mock.patch.object(daemon_mod.report, "render", return_value=""), \
                mock.patch.object(daemon_mod.report, "one_liner",
                                  return_value="x"), \
                mock.patch("sys.stdin", io.StringIO(typed)), \
                redirect_stdout(out):
            engine._on_add(str(self.dev.syspath))
        return out.getvalue(), admit

    # -- whether "always" is offered ------------------------------------

    def test_always_is_offered_when_the_gate_can_keep_it(self):
        self.assertTrue(self._engine()._can_remember())

    def test_not_offered_without_a_backend_that_can_trust(self):
        sysfs.install_backend(sysfs._DirectBackend())
        self.assertFalse(self._engine()._can_remember())

    def test_not_offered_when_the_store_cannot_be_vouched_for(self):
        """The gate refuses to rewrite such a store, so the answer would be lost."""
        self.store.load_error = "trust store mode is 0666"
        self.assertFalse(self._engine()._can_remember())

    def test_not_offered_without_a_trust_store(self):
        engine = self._engine()
        engine.trust = None
        self.assertFalse(engine._can_remember())

    def test_not_offered_when_the_gate_would_have_to_create_the_directory(self):
        """The gate does not create the store's directory, so "always"
        clicked then would admit once and keep nothing."""
        self.store.path = self.path.parent / "absent" / "trusted.json"
        self.assertFalse(self._engine()._can_remember())

    # -- what "always" does --------------------------------------------

    def test_always_goes_through_the_gate_and_takes_effect(self):
        engine = self._engine()
        printed, admit = self._add(engine)
        self.assertIn("[a]lways", printed)
        admit.assert_called_once_with(self.dev)
        self.client.trust.assert_called_once_with(
            self.dev.syspath, self.dev.instance_id, trust.key_for(self.dev),
            "K DT")
        self.assertIn("remembered for future admissions", printed)
        # Refreshed from the gate's write: the very next plug is not asked.
        self.assertTrue(self.store.is_trusted(self.dev))
        self.assertTrue(trust.TrustStore(self.path).is_trusted(self.dev))

    def test_a_gate_refusal_is_reported_and_the_device_stays_admitted(self):
        self.client.trust.side_effect = gate_client.GateError(
            "trust failed: denied: device fingerprint does not match")
        engine = self._engine()
        printed, admit = self._add(engine)
        admit.assert_called_once_with(self.dev)
        self.assertIn("trust could not be saved: trust failed: denied: "
                      "device fingerprint does not match", printed)
        self.assertNotIn("remembered for future admissions", printed)
        self.assertIn(self.dev.name, engine.known)
        self.assertFalse(self.store.is_trusted(self.dev))

    def test_a_device_with_no_fingerprint_is_not_sent(self):
        self.dev.raw_descriptors = None
        printed, _admit = self._add(self._engine())
        self.client.trust.assert_not_called()
        self.assertIn("nothing to pin it to", printed)

    def test_a_write_that_cannot_be_read_back_is_not_reported_as_kept(self):
        self.client.trust.side_effect = None      # "OK", but nothing on disk
        printed, _admit = self._add(self._engine())
        self.assertNotIn("remembered for future admissions", printed)
        self.assertIn("cannot be read back", printed)

    def test_yes_once_does_not_ask_the_gate(self):
        printed, admit = self._add(self._engine(), typed="y\n")
        admit.assert_called_once_with(self.dev)
        self.client.trust.assert_not_called()

    # -- remembered devices ----------------------------------------------

    def test_a_trusted_device_is_admitted_without_a_doomed_save(self):
        """record_admission + save() failed on every plug under --privsep and
        printed "could not update trust store" about bookkeeping the gate
        deliberately does not take."""
        self._gate_writes(None, None, trust.key_for(self.dev), "K DT")
        engine = self._engine()
        with mock.patch.object(self.store, "save",
                               return_value="Permission denied") as save:
            printed, admit = self._add(engine, typed="")
        admit.assert_called_once_with(self.dev)
        save.assert_not_called()
        self.assertNotIn("could not update trust store", printed)
        self.assertIn("TRUSTED", printed)

    # -- what serve() says at startup -------------------------------------

    def _startup(self):
        out = io.StringIO()
        with mock.patch.object(daemon_mod, "pyudev", None), \
                mock.patch.object(trust.TrustStore, "writable",
                                  return_value=False), \
                redirect_stdout(out), self.assertRaises(SystemExit):
            daemon_mod.serve(dry_run=True, trust_path=self.path)
        return out.getvalue()

    def test_startup_does_not_say_always_is_unavailable_under_the_gate(self):
        printed = self._startup()
        self.assertNotIn("is not offered", printed)
        self.assertIn("saved by the privileged gate", printed)

    def test_startup_still_says_so_when_nothing_can_keep_it(self):
        sysfs.install_backend(sysfs._DirectBackend())
        self.assertIn("\"always\" is not offered", self._startup())


# ---------------------------------------------------------------------------
# Nobody to ask: the service before login, an agent that leaves, a dialog
# nobody answers
# ---------------------------------------------------------------------------

class _FakeAgentLink:
    """
    Stands in for agentlink.AgentLink: an agent that is there or is not, and
    answers each question from a script. A scripted answer may be a callable,
    run at the moment the question is put -- to leave mid-question, or to let
    a fake clock run on.
    """

    def __init__(self, live=False, answers=()):
        self.live = live
        self.answers = list(answers)
        self.asked = []
        self.notices = []

    def is_live(self):
        return self.live

    @property
    def connected(self):
        return self.live

    def ask(self, **question):
        self.asked.append(question)
        answer = self.answers.pop(0) if self.answers else None
        return answer(self) if callable(answer) else answer

    def notify(self, title, body):
        self.notices.append((title, body))


def _leaves(link):
    """A scripted answer: the agent's session ends mid-question."""
    link.live = False
    return None


class _ScriptedMonitor:
    """Stands in for pyudev.Monitor: no events, one step per poll, then stop."""

    def __init__(self, steps, stop_event):
        self._steps = list(steps)
        self._stop = stop_event

    def filter_by(self, **_kw):
        pass

    def start(self):
        pass

    def poll(self, timeout=None):
        if self._steps:
            self._steps.pop(0)()
        else:
            self._stop.set()
        return None


class _NobodyToAskCase(unittest.TestCase):
    """
    The service before anyone has logged in: an agent socket is configured,
    no agent is connected, and stdin is /dev/null. The device sits on a real
    directory, so the held queue's instance check compares a real inode.
    """

    terminal = False

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ledger = ledger_mod.Ledger(self.root / "ledger.json")
        self.link = _FakeAgentLink(live=False)
        self.writes = []
        self.admit = mock.Mock()
        # /dev/null, as under systemd. Only a terminal prompt touches it.
        self.stdin = ServiceStdin()
        self.addCleanup(self.stdin.release)
        self.out = io.StringIO()
        self.dev = make_device("3-9")
        self.dev.syspath = self.root / "3-9"
        self.dev.syspath.mkdir()
        st = self.dev.syspath.stat()
        self.dev.instance_id = (st.st_dev, st.st_ino)

    def engine(self, **options):
        settings = dict(observe=0, inspect_storage=False, ledger=self.ledger,
                        agent=self.link, monitor=session.AlwaysUnlocked())
        settings.update(options)
        return daemon_mod.Probolos(**settings)

    @contextlib.contextmanager
    def patched(self, engine):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                daemon_mod.sysfs, "set_authorized",
                side_effect=lambda _path, value: self.writes.append(value)))
            stack.enter_context(mock.patch.object(
                daemon_mod.sysfs, "admit_device", self.admit))
            stack.enter_context(mock.patch.object(
                engine, "_load_with_retry", return_value=self.dev))
            stack.enter_context(mock.patch.object(
                engine, "_has_terminal", return_value=self.terminal))
            stack.enter_context(mock.patch.object(
                daemon_mod.report, "render", return_value=""))
            stack.enter_context(mock.patch("sys.stdin", self.stdin))
            stack.enter_context(redirect_stdout(self.out))
            yield

    def plug(self, engine):
        with self.patched(engine):
            engine._on_add(str(self.dev.syspath))

    def run_loop(self, engine, *steps):
        """engine.run() over a monitor that delivers no events."""
        stop = threading.Event()
        engine.stop_event = stop
        fake_pyudev = mock.Mock()
        fake_pyudev.Monitor.from_netlink.return_value = _ScriptedMonitor(
            steps, stop)
        with self.patched(engine), \
                mock.patch.object(daemon_mod, "pyudev", fake_pyudev):
            engine.run()

    def decisions(self):
        entry = self.ledger.lookup(self.dev)
        return entry.decisions if entry is not None else []

    def held(self):
        """The queue entry a held self.dev must have: path AND instance."""
        return {"3-9": (self.dev.syspath, self.dev.instance_id)}


class NobodyToAskHoldsTheDevice(_NobodyToAskCase):
    """
    Before login there is no agent, and the service's stdin is /dev/null, so
    the terminal "fallback" read EOF and denied every device on the spot. A
    keyboard plugged in at the login screen was dead by the time anyone could
    be asked, and getting the question meant unplugging and replugging it.
    """

    def _held_before_stages_3_and_4(self, kinds):
        self.dev.kinds = kinds
        engine = self.engine(observe=3.0, inspect_storage=True)
        with mock.patch.object(engine, "_quarantine") as quarantine_fn, \
                mock.patch.object(engine, "_inspect_medium") as inspect_fn:
            self.plug(engine)
        quarantine_fn.assert_not_called()
        inspect_fn.assert_not_called()
        self.assertNotIn(1, self.writes, "switched on with nobody to ask")
        self.admit.assert_not_called()
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(), ["held: no desktop agent"])
        self.assertEqual(self.link.asked, [])
        self.assertEqual(self.stdin.touches, [], "the terminal was read")
        printed = self.out.getvalue()
        self.assertIn("NO DESKTOP AGENT — holding", printed)
        self.assertIn("You will be asked when the agent connects", printed)

    def test_an_input_device_is_held_before_quarantine(self):
        self._held_before_stages_3_and_4([usbclass.KIND_INPUT])

    def test_a_storage_device_is_held_before_its_medium_is_read(self):
        self._held_before_stages_3_and_4([usbclass.KIND_STORAGE])

    def test_a_remembered_keyboard_at_the_login_screen_is_still_admitted(self):
        store = mock.Mock(**{"is_trusted.return_value": True,
                             "writable.return_value": False})
        engine = self.engine(trust_store=store)
        self.plug(engine)
        self.admit.assert_called_once_with(self.dev)
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.decisions(), ["trusted"])

    def test_an_allowlisted_port_is_still_admitted_without_a_question(self):
        engine = self.engine(policy=safety.SafetyPolicy(allowed_ports=["3-9"]))
        self.plug(engine)
        self.admit.assert_called_once_with(self.dev)
        self.assertEqual(engine.pending, {})

    def test_with_a_terminal_the_terminal_is_asked_as_before(self):
        self.terminal = True
        self.stdin = io.StringIO("y\n")
        engine = self.engine()
        self.plug(engine)
        self.admit.assert_called_once_with(self.dev)
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.decisions(), ["user approved"])

    def test_with_no_agent_configured_nothing_changes(self):
        """No --agent: the operator chose to answer in a terminal."""
        self.stdin = io.StringIO("")
        engine = self.engine(agent=None)
        self.plug(engine)
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.decisions(), ["no answer"])

    def test_dry_run_holds_nothing(self):
        engine = self.engine(dry_run=True)
        self.plug(engine)
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.writes, [])
        self.assertIn("[dry-run]", self.out.getvalue())

    def test_startup_holds_stranded_devices_instead_of_denying_them(self):
        """Left blocked by an earlier run, found at boot: no agent yet."""
        self.dev.authorized = 0
        engine = self.engine()
        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=[self.dev]), \
                redirect_stdout(self.out):
            engine.snapshot()
        self.run_loop(engine)
        self.assertEqual(engine.pending, self.held())
        # Left queued as found, not re-read and held again: nothing new to
        # record until somebody can be asked.
        self.assertEqual(self.decisions(), [])
        self.assertIn("stay blocked until the desktop agent connects",
                      self.out.getvalue())
        self.assertEqual(self.stdin.touches, [])
        self.admit.assert_not_called()


class HeldDevicesAreAskedWhenTheAgentConnects(_NobodyToAskCase):

    def test_the_next_pass_after_the_agent_connects_asks(self):
        engine = self.engine()
        self.plug(engine)
        self.link.answers = [agentlink.ANSWER_YES]

        def agent_connects():
            self.assertEqual(self.link.asked, [],
                             "asked before anyone could answer")
            self.link.live = True

        self.run_loop(engine, agent_connects)

        self.assertEqual(len(self.link.asked), 1)
        self.admit.assert_called_once_with(self.dev)
        self.assertIn("3-9", engine.known)
        self.assertEqual(engine.pending, {})
        # Held once -- the startup drain, with nobody there yet, leaves the
        # queue alone rather than holding it again -- then approved. A hold
        # is not a refusal: the question is the ordinary one, not the
        # countdown "you have refused this device before" gets.
        self.assertEqual(self.decisions(), ["held: no desktop agent",
                                            "user approved"])
        self.assertNotEqual(self.link.asked[0]["steps"],
                            agentlink.STEPS_COUNTDOWN)
        self.assertIn("[▶] Desktop agent connected — asking about 1 held "
                      "device(s) now.", self.out.getvalue())

    def test_not_asked_while_the_screen_is_locked(self):
        monitor = session.FixedState(False)
        engine = self.engine(monitor=monitor,
                             lock_policy=session.POLICY_QUEUE)
        self.plug(engine)                   # held: no agent, screen unlocked
        monitor._locked = True              # the screen locks...
        self.link.live = True               # ...and the agent connects
        seen = []
        self.link.answers = [lambda _link: seen.append(monitor.is_locked())
                             or agentlink.ANSWER_YES]

        def still_locked():
            self.assertEqual(self.link.asked, [])

        def unlock():
            still_locked()
            monitor._locked = False

        self.run_loop(engine, still_locked, still_locked, unlock)
        self.assertEqual(seen, [False], "asked only once unlocked")
        self.admit.assert_called_once_with(self.dev)
        self.assertIn("[▶] Screen unlocked", self.out.getvalue())

    def test_under_the_deny_policy_it_waits_for_the_unlock_too(self):
        """
        Drained while locked, it would be denied as "screen locked": a device
        that did not arrive behind a locked screen and that nobody was ever
        asked about.
        """
        monitor = session.FixedState(False)
        engine = self.engine(monitor=monitor, lock_policy=session.POLICY_DENY)
        self.plug(engine)
        monitor._locked = True
        self.link.live = True
        self.link.answers = [agentlink.ANSWER_YES]

        def unlock():
            self.assertEqual(self.link.asked, [])
            self.assertEqual(engine.pending, self.held())
            monitor._locked = False

        self.run_loop(engine, lambda: None, unlock)
        self.assertNotIn("denied: screen locked", self.decisions())
        self.admit.assert_called_once_with(self.dev)

    def test_a_recycled_port_is_not_asked_about_under_the_old_entry(self):
        engine = self.engine()
        self.plug(engine)
        self.link.answers = [agentlink.ANSWER_YES]

        def swap_then_connect():
            # The held device is pulled and something else is plugged into
            # the same port: the same name, a different kernel directory.
            fresh = self.root / "3-9.new"
            fresh.mkdir()
            self.dev.syspath.rmdir()
            fresh.rename(self.dev.syspath)
            self.link.live = True

        self.run_loop(engine, swap_then_connect)
        self.assertEqual(self.link.asked, [])
        self.admit.assert_not_called()
        self.assertEqual(engine.pending, {})
        self.assertIn("DIFFERENT device", self.out.getvalue())

    def test_an_agent_that_leaves_again_does_not_make_the_loop_spin(self):
        engine = self.engine()
        self.plug(engine)
        self.link.answers = [_leaves]
        asked_by_then = []

        def agent_connects():
            self.link.live = True

        def gone_again():
            asked_by_then.append(len(self.link.asked))

        self.run_loop(engine, agent_connects, gone_again, gone_again,
                      gone_again)
        self.assertEqual(asked_by_then, [1, 1, 1], "asked once, not per pass")
        self.assertEqual(self.out.getvalue().count("[▶]"), 1,
                         "only the agent's arrival drains: the startup "
                         "drain has nobody to ask")
        self.assertEqual(engine.pending, self.held())
        self.assertNotIn("no answer", self.decisions())
        self.admit.assert_not_called()

    def test_held_again_during_a_drain_waits_for_the_next_one(self):
        engine = self.engine()
        engine.pending.update(self.held())
        self.link.live = True
        calls = []

        def held_again(path, was_held=False):
            calls.append(path)
            engine._hold(self.dev, "held: no desktop agent")

        with self.patched(engine), \
                mock.patch.object(engine, "_on_add", side_effect=held_again):
            engine._drain_pending("Desktop agent connected")
        self.assertEqual(calls, [str(self.dev.syspath)])
        self.assertEqual(engine.pending, self.held())


class HoldingDoesNotWearDownTheLedger(_NobodyToAskCase):
    """
    The ledger keeps a device's last MAX_DECISIONS, and previously-rejected
    looks for "user rejected" among them. Putting a held device back through
    _on_add at every drain -- each unlock, each restart -- and recording it
    as held each time would let enough unlocks with no agent push a real
    refusal out of the history, and the countdown with it, without anyone
    deciding anything.
    """

    def drain(self, engine, cause="Screen unlocked"):
        with self.patched(engine):
            engine._drain_pending(cause)

    def test_drains_with_nobody_to_ask_record_nothing(self):
        self.ledger.record(self.dev, "user rejected")
        engine = self.engine()
        self.plug(engine)
        for _ in range(ledger_mod.MAX_DECISIONS + 5):
            self.drain(engine)
        self.assertEqual(self.decisions(),
                         ["user rejected", "held: no desktop agent"])
        self.assertEqual(engine.pending, self.held())
        self.link.live = True
        self.drain(engine, "Desktop agent connected")
        question = self.link.asked[0]
        self.assertEqual(question["steps"], agentlink.STEPS_COUNTDOWN)
        self.assertEqual(question["countdown"], daemon_mod.CRITICAL_COUNTDOWN)
        self.assertFalse(question["allow_always"])

    def test_held_again_for_the_same_reason_is_recorded_once(self):
        engine = self.engine()
        self.plug(engine)
        self.link.live = True
        self.link.answers = [_leaves]
        self.drain(engine, "Desktop agent connected")
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(), ["held: no desktop agent"])

    def test_an_agent_that_keeps_leaving_does_not_switch_it_on_forever(self):
        """An agent that crashes on the question and is restarted by systemd
        would otherwise inspect -- switch on -- the same device every few
        seconds for as long as the crash lasts."""
        engine = self.engine()
        self.plug(engine)
        for _ in range(daemon_mod.Probolos.MAX_UNSEEN_ASKS + 2):
            self.link.live = True
            self.link.answers = [_leaves]
            self.drain(engine, "Desktop agent connected")
        self.assertEqual(len(self.link.asked),
                         daemon_mod.Probolos.MAX_UNSEEN_ASKS)
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.decisions(),
                         ["held: no desktop agent", "no answer"])
        self.assertNotIn("user rejected", self.decisions())
        self.admit.assert_not_called()
        self.assertIn("no longer held", self.out.getvalue())

    def test_a_replug_starts_the_count_again(self):
        engine = self.engine()
        self.plug(engine)
        engine._unseen_asks["3-9"] = (self.dev.instance_id, 2)
        with redirect_stdout(self.out):
            engine._on_remove(str(self.dev.syspath))
        self.assertNotIn("3-9", engine._unseen_asks)
        self.assertNotIn("3-9", engine._last_recorded)


class ADuplicateAddForAHeldDevice(_NobodyToAskCase):
    """
    udev replays 'add' for devices already present -- `udevadm trigger`, a
    settle, a rescan. For a device sitting in the held queue that replay was
    gated as a new arrival: asked now and again at the drain, or, held behind
    a locked screen and replayed after the unlock, admitted on trust without
    the question a device that turned up while nobody was there must get.
    """

    def test_it_is_not_asked_twice(self):
        engine = self.engine()
        self.plug(engine)                   # held: no agent yet
        self.link.live = True
        self.plug(engine)                   # the replay
        self.assertEqual(self.link.asked, [])
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(), ["held: no desktop agent"])
        self.assertIn("already held", self.out.getvalue())

    def test_held_behind_the_lock_it_is_not_admitted_on_trust(self):
        monitor = session.FixedState(True)
        store = mock.Mock(**{"is_trusted.return_value": True,
                             "writable.return_value": True})
        self.link.live = True
        self.link.answers = [agentlink.ANSWER_YES]
        engine = self.engine(monitor=monitor, trust_store=store,
                             lock_policy=session.POLICY_QUEUE)
        self.plug(engine)                   # held: screen locked
        monitor._locked = False
        self.plug(engine)                   # replayed before the drain
        self.admit.assert_not_called()
        self.assertNotIn("trusted", self.decisions())
        with self.patched(engine):
            engine._drain_pending("Screen unlocked")
        self.assertEqual(len(self.link.asked), 1, "asked, not waved through")
        self.assertEqual(self.decisions()[-1], "user approved")

    def test_a_different_device_at_the_port_is_gated_as_new(self):
        """The held one left and its 'remove' was lost: the entry is stale."""
        engine = self.engine()
        self.plug(engine)
        # A new kernel directory under the same name. Made before the old one
        # goes, so it cannot simply be handed the freed inode number.
        fresh = self.root / "3-9.new"
        fresh.mkdir()
        self.dev.syspath.rmdir()
        fresh.rename(self.dev.syspath)
        st = self.dev.syspath.stat()
        self.dev.instance_id = (st.st_dev, st.st_ino)
        self.link.live = True
        self.link.answers = [agentlink.ANSWER_YES]
        self.plug(engine)
        self.assertEqual(len(self.link.asked), 1)
        self.admit.assert_called_once_with(self.dev)
        self.assertEqual(engine.pending, {})


class AnUnansweredQuestionIsNotADeadEnd(_NobodyToAskCase):
    """
    The agent is there, the dialog was on screen, and nobody answered it. The
    terminal fallback that followed was the same denial in disguise (stdin is
    /dev/null), and the device was simply dead with nobody told why.
    """

    def setUp(self):
        super().setUp()
        self.link.live = True

    def test_denied_as_no_answer_and_the_agent_is_told(self):
        engine = self.engine()
        self.plug(engine)
        self.assertEqual(len(self.link.asked), 1)
        self.assertEqual(self.decisions(), ["no answer"])
        title = daemon_mod.Probolos._agent_title(self.dev)
        self.assertEqual(self.link.notices, [(
            "USB device still blocked",
            f"{title}\nNobody answered in time. Unplug it and plug it in "
            f"again to be asked.")])
        # Not re-queued: that would re-ask, forever, a person not there.
        self.assertEqual(engine.pending, {})
        self.assertEqual(self.writes, [0])
        self.admit.assert_not_called()
        self.assertEqual(self.stdin.touches, [], "the terminal was read")
        self.assertIn("DENIED, NOT ANSWERED", self.out.getvalue())
        self.assertNotIn("REJECTED", self.out.getvalue())

    def test_the_replug_is_not_treated_as_a_refused_device(self):
        """
        Recorded as "user rejected", the unanswered question would turn the
        replug the notice asks for into the CRITICAL countdown, warning about
        a refusal nobody made.
        """
        engine = self.engine()
        self.plug(engine)
        self.link.answers = [agentlink.ANSWER_YES]
        self.plug(engine)                   # replugged, as the notice says
        replug = self.link.asked[1]
        self.assertNotEqual(replug["steps"], agentlink.STEPS_COUNTDOWN)
        self.assertEqual(replug["countdown"], 0)
        self.assertNotIn("user rejected", self.decisions())
        self.admit.assert_called_once_with(self.dev)

    def test_an_agent_gone_mid_question_means_held_not_denied(self):
        self.link.answers = [_leaves]
        engine = self.engine()
        self.plug(engine)
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(), ["held: no desktop agent"])
        self.assertEqual(self.link.notices, [])
        self.assertNotIn(1, self.writes)
        self.admit.assert_not_called()
        self.assertEqual(self.stdin.touches, [])

    def test_an_agent_gone_during_inspection_means_held_not_asked(self):
        """Stage 4 can take seconds, and the agent can leave in them."""
        engine = self.engine(inspect_storage=True)

        def agent_leaves(_dev):
            self.link.live = False
            return None

        with mock.patch.object(engine, "_inspect_medium",
                               side_effect=agent_leaves):
            self.plug(engine)
        self.assertEqual(self.link.asked, [])
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(), ["held: no desktop agent"])
        self.assertEqual(self.stdin.touches, [])

    def test_with_a_terminal_the_old_fallback_is_unchanged(self):
        self.terminal = True
        self.stdin = io.StringIO("y\n")
        engine = self.engine()
        self.plug(engine)
        self.assertIn("(no answer from the desktop agent; asking here)",
                      self.out.getvalue())
        self.admit.assert_called_once_with(self.dev)
        self.assertEqual(self.link.notices, [])
        self.assertEqual(self.decisions(), ["user approved"])


class ACriticalDeviceWithNoAgent(_NobodyToAskCase):
    """
    The hold does not depend on what the identity stage found, and it comes
    before quarantine, so behaviour is observed once someone is there to see
    it. Drained, a CRITICAL device gets the countdown the daemon enforces
    itself, and never "always".
    """

    def setUp(self):
        super().setUp()
        self.dev.kinds = [usbclass.KIND_INPUT]
        # Refused once before, so previously-rejected makes it CRITICAL.
        self.ledger.record(self.dev, "user rejected")
        self.store = mock.Mock(**{"is_trusted.return_value": False,
                                  "writable.return_value": True})
        self.now = 1000.0

    def engine(self, **options):
        options.setdefault("observe", 3.0)
        options.setdefault("trust_store", self.store)
        return super().engine(**options)

    def after(self, seconds, answer):
        """A scripted answer that arrives `seconds` after the question."""
        def scripted(_link):
            self.now += seconds
            return answer
        return scripted

    def hold_then_drain(self, answer):
        engine = self.engine()
        order = []
        observation = quarantine.Observation(
            duration=3.0, error="no input nodes appeared; nothing to observe")

        def observe(_dev):
            order.append("quarantine")
            return observation

        def answered(link):
            order.append("asked")
            return answer(link)

        with mock.patch.object(engine, "_quarantine",
                               side_effect=observe) as quarantine_fn:
            self.plug(engine)
            self.assertEqual(quarantine_fn.call_count, 0,
                             "switched on with nobody to ask")
            self.link.live = True
            self.link.answers = [answered]
            with self.patched(engine), \
                    mock.patch.object(daemon_mod.time, "monotonic",
                                      lambda: self.now), \
                    mock.patch.object(daemon_mod.report, "render_behaviour",
                                      return_value=""):
                engine._drain_pending("Desktop agent connected")
        return engine, order

    def test_held_before_quarantine_like_any_other_device(self):
        engine = self.engine()
        with mock.patch.object(engine, "_quarantine") as quarantine_fn:
            self.plug(engine)
        quarantine_fn.assert_not_called()
        self.assertEqual(engine.pending, self.held())
        self.assertEqual(self.decisions(),
                         ["user rejected", "held: no desktop agent"])
        self.assertIn("CRITICAL", self.out.getvalue())
        self.assertEqual(self.link.asked, [])

    def test_drained_it_gets_the_countdown_and_never_always(self):
        engine, order = self.hold_then_drain(
            self.after(12.0, agentlink.ANSWER_ALWAYS))
        question = self.link.asked[0]
        self.assertEqual(question["steps"], agentlink.STEPS_COUNTDOWN)
        self.assertEqual(question["countdown"], daemon_mod.CRITICAL_COUNTDOWN)
        self.assertTrue(engine._can_remember(), "'always' could be kept...")
        self.assertFalse(question["allow_always"], "...and is not offered")
        self.assertEqual(order, ["quarantine", "asked"])
        self.admit.assert_called_once_with(self.dev)
        self.store.trust.assert_not_called()
        self.assertEqual(self.decisions()[-1], "user approved")

    def test_an_approval_inside_the_countdown_is_still_refused(self):
        engine, _order = self.hold_then_drain(
            self.after(3.0, agentlink.ANSWER_YES))
        self.admit.assert_not_called()
        self.assertEqual(self.decisions()[-1], "no answer")
        self.assertEqual(len(self.link.notices), 1)
        self.assertEqual(engine.pending, {})


class TerminalDetection(unittest.TestCase):
    """What counts as a terminal somebody could answer on."""

    def test_what_is_not_a_terminal_is_none(self):
        with open(os.devnull) as devnull:
            for stdin in (devnull, io.StringIO("y\n"), None):
                with self.subTest(stdin=stdin), mock.patch("sys.stdin", stdin):
                    self.assertFalse(daemon_mod.Probolos._has_terminal())

    def test_a_pseudo_terminal_is_one(self):
        try:
            master, slave = pty.openpty()
        except OSError as exc:
            self.skipTest(f"no pseudo-terminal: {exc}")
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        with os.fdopen(os.dup(slave)) as tty, mock.patch("sys.stdin", tty):
            self.assertTrue(daemon_mod.Probolos._has_terminal())


if __name__ == "__main__":
    unittest.main()
