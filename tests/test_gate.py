"""
Closing and restoring the gate, and the safety layer around it: exempt
ports, the watchdog and the panic file.

Covers probolos.gate and probolos.safety.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from probolos import gate, safety, sysfs
from tests._support import FakeSysfs, descriptor_blob, make_device


class Dev:
    def __init__(self, name="1-4", removable="removable", is_root_hub=False):
        self.name = name
        self.removable = removable
        self.is_root_hub = is_root_hub


# ---------------------------------------------------------------------------
# P2 -- removable=fixed is only platform testimony on a root-hub port
# ---------------------------------------------------------------------------

class FixedPortExemption(unittest.TestCase):
    """
    A device claiming `fixed` skips analyzers, quarantine and the prompt
    entirely. Behind an external hub that claim comes from the hub's own
    DeviceRemovable bitmap, so one hostile hub disabled the gate for everything
    plugged into it.
    """

    def setUp(self):
        self.fake = FakeSysfs()
        self.policy = safety.SafetyPolicy()

    def tearDown(self):
        self.fake.destroy()

    def _device_at(self, path, removable="fixed"):
        return make_device(
            descriptor_blob((0x08, 0x06, 0x50), (0x03, 0x01, 0x01)),
            removable=removable, syspath=str(path), name=path.name)

    def test_soldered_device_on_a_root_hub_port_is_still_protected(self):
        internal = self.fake.add_device("1-3", removable="fixed")
        self.assertEqual(
            self.policy.is_protected(self._device_at(internal)),
            "device is on a non-removable (internal) port")

    def test_internal_device_behind_an_internal_hub_is_still_protected(self):
        """No regression for laptops whose camera sits behind a soldered hub."""
        hub = self.fake.add_device("1-2", removable="fixed")
        camera = self.fake.add_device("1-2.1", parent=hub, removable="fixed")
        self.assertIsNotNone(self.policy.is_protected(self._device_at(camera)))

    def test_device_behind_a_hostile_hub_is_not_exempt(self):
        rogue = self.fake.add_device("1-4", removable="removable")
        victim = self.fake.add_device("1-4.2", parent=rogue, removable="fixed")
        self.assertIsNone(
            self.policy.is_protected(self._device_at(victim)),
            "a hub's own firmware must not be able to switch the gate off")

    def test_unreadable_ancestor_denies_the_exemption(self):
        hub = self.fake.add_device("1-7", removable="fixed")
        child = self.fake.add_device("1-7.1", parent=hub, removable="fixed")
        (hub / "removable").unlink()
        self.assertIsNone(self.policy.is_protected(self._device_at(child)))

    def test_bus_view_path_still_resolves_to_the_real_chain(self):
        self.fake.add_device("1-8", removable="fixed")
        self.assertIsNotNone(
            self.policy.is_protected(self._device_at(self.fake.bus / "1-8")),
            "the flat bus view must be resolved before the chain is walked")

    def test_operator_allowlist_is_unaffected(self):
        policy = safety.SafetyPolicy(allowed_ports=["1-9"])
        rogue = self.fake.add_device("1-9", removable="removable")
        self.assertIn("allowlist", policy.is_protected(self._device_at(rogue)))


class GateRestoreIsThreadSafe(unittest.TestCase):
    """
    restore() has three uncoordinated callers: the watchdog thread via
    on_stall, the main thread leaving the `with` block, and atexit. Two can
    run at once -- the watchdog firing during shutdown is the normal way a
    stall ends -- and each rebuilt self._original from what it alone managed
    to restore, so the later assignment discarded the other's result.
    """

    def test_concurrent_restores_do_not_lose_a_hub(self):
        from probolos import gate as gate_mod
        from probolos import sysfs

        hubs = [Path(f"/sys/bus/usb/devices/usb{n}") for n in range(1, 9)]
        written = []
        barrier = threading.Barrier(2)

        def slow_write(hub, value):
            written.append((hub.name, value))

        real = sysfs.set_authorized_default
        sysfs.set_authorized_default = slow_write
        try:
            g = gate_mod.AuthorizationGate(log=lambda *a: None)
            g._original = {h: 1 for h in hubs}
            g._armed = True

            def run():
                barrier.wait()
                g.restore()

            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
        finally:
            sysfs.set_authorized_default = real

        # Every hub restored exactly once, and nothing left armed.
        self.assertEqual(sorted(n for n, _ in written),
                         sorted(h.name for h in hubs))
        self.assertFalse(g._armed)
        self.assertEqual(g._original, {})


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
        from pathlib import Path
        from unittest import mock

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
        from pathlib import Path
        from unittest import mock

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


class UnreadableHubDefaultStaysRestorable(unittest.TestCase):
    """
    A root hub whose authorized_default could not be read was closed anyway and
    then never recorded, so restore() -- which only walks the recorded hubs --
    skipped it. The hub stayed at 0 after the daemon exited: no USB device on
    it binds a driver again until someone writes the file by hand.
    """

    def test_an_unreadable_previous_value_still_records_a_restore_target(self):
        import tempfile

        from probolos import gate_server, protocol

        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / "usb1"
            hub.mkdir()
            attr = hub / "authorized_default"
            attr.write_text("not-a-number")

            gate = gate_server.GateServer.__new__(gate_server.GateServer)
            gate._authorized_here = set()
            gate._closed_defaults = {}
            gate._open_leases = {}
            gate._instances = {}
            gate._safe_usb_path = staticmethod(lambda p: hub)
            gate.log = lambda *a: None

            resp = gate_server.GateServer._do_set_default(
                gate, protocol.Request(protocol.REQ_SET_DEFAULT, str(hub), 0))

            self.assertTrue(resp.ok, resp.detail)
            self.assertEqual(attr.read_text(), "0")
            self.assertIn(str(hub), gate._closed_defaults)
            self.assertEqual(gate._closed_defaults[str(hub)], 1)


class GateLifecycle(unittest.TestCase):
    def test_partial_startup_restores_already_closed_hubs(self):
        writes = []
        def write(hub, value):
            writes.append((hub.name, value))
            if hub.name == "usb2" and value == 0:
                raise OSError("controller disappeared")
        with mock.patch.object(sysfs, "list_root_hubs", return_value=[Path("usb1"), Path("usb2")]), \
             mock.patch.object(sysfs, "get_authorized_default", return_value=1), \
             mock.patch.object(sysfs, "set_authorized_default", side_effect=write):
            with self.assertRaises(OSError):
                with gate.AuthorizationGate(log=lambda *_: None):
                    self.fail("startup must fail")
        self.assertIn(("usb1", 1), writes)

    def test_failed_restore_can_be_retried(self):
        obj = gate.AuthorizationGate(log=lambda *_: None)
        obj._armed = True
        obj._original = {Path("usb1"): 1}
        with mock.patch.object(sysfs, "set_authorized_default", side_effect=[OSError("busy"), None]) as write:
            obj.restore()
            obj.restore()
            self.assertEqual(write.call_count, 2)
            self.assertFalse(obj._armed)


if __name__ == "__main__":
    unittest.main()
