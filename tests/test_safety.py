"""
The safety layer: what must never be gated, and the escape hatches for
when it is. These are invariants, not features -- each one describes a
way a user could end up unable to use their own computer.

Merged from: test_safety.py, test_safety_panic.py
"""
from __future__ import annotations

# =========================================================================
# test_safety.py
#
# Tests for the safety layer.
# =========================================================================

import os
import tempfile
import time
import unittest
from pathlib import Path

from probolos import safety


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
        # The panic file must normally be root-owned in a root-owned directory.
        # Under test we create it as the current user in a user-owned tmpdir,
        # so tell the policy to accept that uid; the ownership LOGIC is exercised
        # by test_safety_panic.py, not here.
        self.policy = safety.SafetyPolicy(panic_file=self.panic,
                                          panic_file_uid=os.getuid())
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
        from probolos import gate as gate_mod

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
        from probolos import gate as gate_mod

        hub = Path("/sys/bus/usb/devices/usb1")
        with mock.patch.object(gate_mod.sysfs, "list_root_hubs",
                               return_value=[hub]), \
             mock.patch.object(gate_mod.sysfs, "get_authorized_default",
                               return_value=2), \
             mock.patch.object(gate_mod.sysfs, "set_authorized_default"):
            g = gate_mod.AuthorizationGate(dry_run=True, log=lambda *a: None)
            with g:
                self.assertEqual(g._original[hub], 2)


# =========================================================================
# test_safety_panic.py
#
# Regression tests for the panic file, one per way it could be forged.
# =========================================================================

import os
import tempfile
import unittest
from pathlib import Path

from probolos import safety


class PanicFileValidation(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        os.chmod(self.dir, 0o700)
        self.uid = os.getuid()
        self.panic = self.dir / "probolos.panic"
        self.messages = []

    def tearDown(self):
        self._dir.cleanup()

    def valid(self, path=None):
        return safety.panic_file_is_valid(path or self.panic, self.uid,
                                          self.messages.append)

    def assertRefused(self, because):
        self.assertFalse(self.valid())
        self.assertTrue(self.messages, "a refusal must say why")
        self.assertIn(because, self.messages[-1].lower())

    # ---- the hatch still works ----

    def test_a_file_placed_by_the_operator_is_honoured(self):
        self.panic.touch()
        self.assertTrue(self.valid())

    def test_no_file_is_not_a_panic_and_says_nothing(self):
        self.assertFalse(self.valid())
        self.assertEqual(self.messages, [])

    # ---- F4: forging it ----

    def test_a_symlink_is_not_a_panic_file(self):
        """
        Path.exists() follows symlinks, so a link to any file that happens to
        exist used to open the gate for every device on the machine.
        """
        self.panic.symlink_to("/etc/hostname")
        self.assertRefused("symlink")

    def test_a_dangling_symlink_is_reported_not_ignored(self):
        self.panic.symlink_to(self.dir / "does-not-exist")
        self.assertRefused("symlink")

    def test_a_fifo_is_not_a_panic_file(self):
        os.mkfifo(self.panic)
        self.assertRefused("not a regular file")

    def test_a_file_owned_by_someone_else_is_not_a_panic_file(self):
        self.panic.touch()
        self.assertFalse(safety.panic_file_is_valid(
            self.panic, self.uid + 4242, self.messages.append))
        self.assertIn("owned by uid", self.messages[-1])

    def test_a_hardlinked_file_is_not_a_panic_file(self):
        """
        --panic-file is operator-supplied. In a directory an attacker can
        write to, `ln /etc/hostname <panic path>` yields a regular file owned
        by root that appears exactly when they choose. Ownership of the file
        says nothing about who put it there.
        """
        decoy = self.dir / "decoy"
        decoy.write_text("x")
        os.link(decoy, self.panic)
        self.assertRefused("hard link")

    def test_a_directory_writable_by_others_disqualifies_the_file(self):
        """The check that closes the hardlink route at its source."""
        loose = Path(tempfile.mkdtemp())
        try:
            os.chmod(loose, 0o777)
            panic = loose / "probolos.panic"
            panic.touch()
            self.assertFalse(self.valid(panic))
            self.assertIn("writable by others", self.messages[-1])
        finally:
            for child in loose.iterdir():
                child.unlink()
            loose.rmdir()

    def test_the_default_location_is_not_world_writable(self):
        """
        /tmp is 1777 and /run/probolos is chowned to 2770 by
        prepare_socket_dir. Neither can hold the off switch.
        """
        self.assertEqual(safety.DEFAULT_PANIC_FILE, Path("/run/probolos.panic"))
        self.assertEqual(safety.DEFAULT_PANIC_FILE.parent, Path("/run"))


class WatchdogPanic(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        os.chmod(self.dir, 0o700)
        self.panic = self.dir / "probolos.panic"
        self.messages = []
        self.policy = safety.SafetyPolicy(panic_file=self.panic,
                                          panic_file_uid=os.getuid())

    def tearDown(self):
        self._dir.cleanup()

    def dog(self, timeout=60.0):
        return safety.Watchdog(timeout, lambda _reason: None, self.policy,
                               log=self.messages.append)

    def test_a_valid_panic_file_fires_the_watchdog(self):
        watchdog = self.dog()
        self.assertIsNone(watchdog.check_once())
        self.panic.touch()
        self.assertIn("panic file", watchdog.check_once() or "")

    def test_a_forged_panic_file_does_not_fire_the_watchdog(self):
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        self.assertIsNone(watchdog.check_once())
        self.assertFalse(watchdog.fired)

    def test_the_hatch_works_while_waiting_for_a_human(self):
        """
        The panic check runs before the paused check, because waiting for a
        human is exactly when someone reaches for the hatch.
        """
        watchdog = self.dog()
        self.panic.touch()
        with watchdog.paused():
            self.assertIsNotNone(watchdog.check_once())

    def test_a_stall_is_not_reported_while_paused(self):
        """The other half: a human taking their time is not a malfunction."""
        watchdog = self.dog(timeout=0.0)
        with watchdog.paused():
            self.assertIsNone(watchdog.check_once())
        self.assertIsNotNone(watchdog.check_once())

    def test_an_invalid_panic_file_is_reported_once_not_every_pass(self):
        """
        check_once runs every 0.5s. Complaining on each pass would print the
        same refusal twice a second until someone removed the file, burying
        the findings the user needs to read.
        """
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        for _ in range(10):
            watchdog.check_once()
        self.assertEqual(len(self.messages), 1, self.messages)

    def test_it_complains_again_if_the_bad_file_returns(self):
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        watchdog.check_once()
        self.panic.unlink()
        watchdog.check_once()
        self.panic.symlink_to("/etc/hostname")
        watchdog.check_once()
        self.assertEqual(len(self.messages), 2, self.messages)


if __name__ == "__main__":
    unittest.main()
