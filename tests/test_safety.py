"""
Tests for the safety layer.

These are invariants, not features. Each one describes a way a user could end
up unable to use their own computer, and asserts that it cannot happen. They
are the tests that must never be deleted to make a feature pass.
"""

import tempfile
import time
import unittest
from pathlib import Path

from cerberus import safety


class Dev:
    def __init__(self, name="1-4", removable="removable", is_root_hub=False):
        self.name = name
        self.removable = removable
        self.is_root_hub = is_root_hub


class TestProtectedDevices(unittest.TestCase):

    def test_internal_keyboard_is_never_gated(self):
        """
        THE invariant. A laptop's built-in keyboard sits on a fixed port. If it
        is ever gated, the user cannot answer the prompt that would unblock it.
        """
        policy = safety.SafetyPolicy()
        self.assertIsNotNone(policy.is_protected(Dev(removable="fixed")))

    def test_ordinary_removable_device_is_gated(self):
        policy = safety.SafetyPolicy()
        self.assertIsNone(policy.is_protected(Dev(removable="removable")))

    def test_unknown_removability_is_still_gated(self):
        """
        Absence of information is not protection. Treating "unknown" as fixed
        would let any device that omits the attribute skip every check.
        """
        policy = safety.SafetyPolicy()
        self.assertIsNone(policy.is_protected(Dev(removable="unknown")))
        self.assertIsNone(policy.is_protected(Dev(removable=None)))

    def test_operator_allowlisted_port_is_protected(self):
        policy = safety.SafetyPolicy(allowed_ports=["1-4"])
        self.assertIsNotNone(policy.is_protected(Dev(name="1-4")))
        self.assertIsNone(policy.is_protected(Dev(name="1-5")))

    def test_root_hubs_are_protected(self):
        policy = safety.SafetyPolicy()
        self.assertIsNotNone(policy.is_protected(Dev(is_root_hub=True)))

    def test_protection_explains_itself(self):
        """The reason is printed to the user, so it must be human-readable."""
        reason = safety.SafetyPolicy().is_protected(Dev(removable="fixed"))
        self.assertIn("internal", reason.lower())

    def test_fixed_protection_can_be_turned_off_but_is_on_by_default(self):
        self.assertTrue(safety.SafetyPolicy().protect_fixed_ports)
        opted_out = safety.SafetyPolicy(protect_fixed_ports=False)
        self.assertIsNone(opted_out.is_protected(Dev(removable="fixed")))


class TestWatchdog(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.panic = Path(self.tmp.name) / "panic"
        self.policy = safety.SafetyPolicy(panic_file=self.panic)
        self.stalls = []

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, timeout=0.05):
        return safety.Watchdog(timeout, self.stalls.append, self.policy)

    def test_progress_keeps_the_watchdog_quiet(self):
        dog = self.make(timeout=10.0)
        dog.beat()
        self.assertIsNone(dog.check_once())

    def test_stall_is_detected(self):
        """The case gate.py cannot cover: alive but wedged."""
        dog = self.make(timeout=0.01)
        time.sleep(0.05)
        self.assertIn("no progress", dog.check_once())

    def test_waiting_for_a_human_is_not_a_stall(self):
        dog = self.make(timeout=0.01)
        with dog.paused():
            time.sleep(0.05)
            self.assertIsNone(dog.check_once())

    def test_pause_resets_the_clock_on_exit(self):
        dog = self.make(timeout=0.5)
        with dog.paused():
            time.sleep(0.05)
        self.assertIsNone(dog.check_once())

    def test_panic_file_forces_the_gate_open(self):
        """Escape hatch usable from another TTY or over SSH."""
        dog = self.make(timeout=1000.0)
        dog.beat()
        self.assertIsNone(dog.check_once())
        self.panic.touch()
        self.assertIn("panic file", dog.check_once())

    def test_watchdog_fires_only_once(self):
        dog = self.make(timeout=0.01)
        time.sleep(0.05)
        self.assertIsNotNone(dog.check_once())
        self.assertIsNone(dog.check_once())

    def test_thread_delivers_the_callback(self):
        dog = safety.Watchdog(0.01, self.stalls.append, self.policy,
                              interval=0.01)
        dog.start()
        time.sleep(0.15)
        dog.stop()
        self.assertTrue(self.stalls, "watchdog thread never fired")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestGateDoesNotPerpetuateLockout(unittest.TestCase):
    """
    A regression found on real hardware: after a run crashed leaving
    authorized_default=0, the NEXT run recorded 0 as "the original value" and
    faithfully restored 0 on exit -- so every subsequent run politely preserved
    the lockout, and USB stayed dead until fixed by hand.

    0 must be treated as "no valid previous state", not as a setting to honour.
    """

    def test_zero_is_not_recorded_as_the_state_to_restore(self):
        from unittest import mock
        from pathlib import Path
        from cerberus import gate as gate_mod

        hub = Path("/sys/bus/usb/devices/usb1")
        with mock.patch.object(gate_mod.sysfs, "list_root_hubs",
                               return_value=[hub]), \
             mock.patch.object(gate_mod.sysfs, "get_authorized_default",
                               return_value=0), \
             mock.patch.object(gate_mod.sysfs, "set_authorized_default"):
            g = gate_mod.AuthorizationGate(dry_run=True, log=lambda *a: None)
            with g:
                # 0 found on entry must be replaced by 1 as the restore target
                self.assertEqual(g._original[hub], 1)

    def test_a_real_setting_is_preserved_exactly(self):
        """Value 2 (internal ports only) must be restored as 2, not as 1."""
        from unittest import mock
        from pathlib import Path
        from cerberus import gate as gate_mod

        hub = Path("/sys/bus/usb/devices/usb1")
        with mock.patch.object(gate_mod.sysfs, "list_root_hubs",
                               return_value=[hub]), \
             mock.patch.object(gate_mod.sysfs, "get_authorized_default",
                               return_value=2), \
             mock.patch.object(gate_mod.sysfs, "set_authorized_default"):
            g = gate_mod.AuthorizationGate(dry_run=True, log=lambda *a: None)
            with g:
                self.assertEqual(g._original[hub], 2)
