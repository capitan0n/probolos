"""
Tests for the screen-lock policy.

The requirement being encoded: a device attached while nobody is at the machine
must not be powered up, must not be admitted even if remembered, and must not
have to be unplugged and replugged for its owner to decide about it.

All of it is driven through an injected session monitor, so the behaviour is
tested without arranging a real locked screen.
"""

import unittest
from pathlib import Path
from unittest import mock

from probolos import daemon as daemon_mod
from probolos import session, sysfs, usbclass


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
        engine.pending["3-9"] = Path("/sys/bus/usb/devices/3-9")

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
        engine.pending["3-9"] = Path("/sys/bus/usb/devices/3-9")

        asked = []
        with mock.patch.object(Path, "exists", return_value=False), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, [])

    def test_removal_withdraws_a_held_question(self):
        engine = daemon_mod.Probolos(observe=0)
        engine.pending["3-9"] = Path("/sys/bus/usb/devices/3-9")
        engine._on_remove("/sys/bus/usb/devices/3-9")
        self.assertEqual(engine.pending, {})

    def test_queue_preserves_arrival_order(self):
        engine = daemon_mod.Probolos(observe=0)
        for name in ("3-1", "3-2", "3-3"):
            engine.pending[name] = Path(f"/sys/bus/usb/devices/{name}")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)


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
        engine.pending["3-9"] = Path("/sys/bus/usb/devices/3-9")
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
        engine.pending[dev.name] = dev.syspath
        seen = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: seen.append(was_held)):
            engine._drain_pending()
        self.assertEqual(seen, [True])
