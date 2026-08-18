"""
Tests for driverless authorization.

This module previously had NO tests at all, which is why it could sit in the
tree for months being called on every input device and doing nothing. The first
test here is the one that would have caught it: it builds sysfs the way the
kernel actually presents it -- a device held at authorized=0 has no interface
directories -- and asserts that a capability check based on counting those
directories is always wrong.

Everything is exercised against a synthetic tree, so none of it needs USB
hardware or root.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from probolos import deferred_bind, sysfs


class FakeBackend:
    """Records privileged writes instead of performing them."""

    supports_bus_wide = True

    def __init__(self, tree: Path, device: Path, create_on_authorize=()):
        self.tree = tree
        self.device = device
        self.create_on_authorize = list(create_on_authorize)
        self.autoprobe_writes = []
        self.interface_writes = []
        self.probes = []
        self.device_authorized = None

    # -- the bus-wide pair --------------------------------------------------
    def set_drivers_autoprobe(self, value):
        self.autoprobe_writes.append(value)
        (self.tree / "drivers_autoprobe").write_text(str(value))

    def trigger_driver_probe(self, name):
        self.probes.append(name)

    # -- per-device ---------------------------------------------------------
    def authorize(self, syspath, value):
        self.device_authorized = value
        if value == 1:
            # The kernel creates the interface directories inside
            # usb_set_configuration(), which runs only now. Reproducing that
            # ordering is the entire point of this fake.
            for name in self.create_on_authorize:
                d = self.device.parent / name
                d.mkdir(exist_ok=True)
                (d / "authorized").write_text("1")

    def authorize_interface(self, intf_dir, value):
        self.interface_writes.append((Path(intf_dir).name, value))
        (Path(intf_dir) / "authorized").write_text(str(value))

    def set_default(self, hub, value):
        pass


class DeferredBindTests(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tree = Path(self._tmp.name)
        self.device = self.tree / "3-1"
        self.device.mkdir()
        (self.device / "authorized").write_text("0")
        (self.tree / "drivers_autoprobe").write_text("1")
        (self.tree / "drivers_probe").write_text("")

        self._saved = (sysfs.DRIVERS_AUTOPROBE, sysfs.DRIVERS_PROBE,
                       sysfs._backend)
        sysfs.DRIVERS_AUTOPROBE = self.tree / "drivers_autoprobe"
        sysfs.DRIVERS_PROBE = self.tree / "drivers_probe"
        self.backend = FakeBackend(self.tree, self.device,
                                   create_on_authorize=["3-1:1.0", "3-1:1.1"])
        sysfs.install_backend(self.backend)
        deferred_bind._autoprobe_original = None

    def tearDown(self):
        sysfs.DRIVERS_AUTOPROBE, sysfs.DRIVERS_PROBE, backend = self._saved
        sysfs.install_backend(backend)
        deferred_bind._autoprobe_original = None
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # The bug itself
    # ------------------------------------------------------------------

    def test_a_blocked_device_has_no_interface_directories(self):
        """The kernel fact the old implementation was built on top of, wrongly.

        If this ever starts failing, the premise of this whole module changed
        and deferred_bind should be revisited -- so it is asserted, not assumed.
        """
        self.assertEqual(deferred_bind.interface_dirs(self.device), [])

    def test_capability_is_not_decided_by_counting_interfaces(self):
        """The regression guard.

        The old check was `len(interface_dirs(path)) > 0`, evaluated while the
        device was blocked. Since the directories do not exist yet, it returned
        False on every device forever, and the daemon silently took the racy
        path. supported() must answer from the BUS, which is available.
        """
        self.assertEqual(deferred_bind.interface_dirs(self.device), [])
        self.assertTrue(deferred_bind.supported(self.device))

    # ------------------------------------------------------------------
    # The mechanism
    # ------------------------------------------------------------------

    def test_autoprobe_is_off_only_across_the_authorize(self):
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            self.assertEqual(self.backend.autoprobe_writes, [0])
            db.authorize_device()
            # Restored as soon as the device is up: the bus-wide exposure must
            # not last for the observation window.
            self.assertEqual(self.backend.autoprobe_writes, [0, 1])
            self.assertEqual(
                (self.tree / "drivers_autoprobe").read_text(), "1")

    def test_interfaces_are_closed_after_authorization_not_before(self):
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            self.assertEqual(self.backend.interface_writes, [])
            db.authorize_device()
            self.assertEqual(
                sorted(self.backend.interface_writes),
                [("3-1:1.0", 0), ("3-1:1.1", 0)])

    def test_release_authorizes_and_then_forces_a_probe(self):
        """Authorizing an interface does not rebind on its own.

        interface_authorized_store() sets the flag and stops; without the write
        to drivers_probe, usbhid never attaches and no evdev node appears -- the
        device would be admitted and then be silently dead.
        """
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            db.authorize_device()
            self.backend.interface_writes.clear()
            db.release_interfaces()

        self.assertEqual(sorted(self.backend.interface_writes),
                         [("3-1:1.0", 1), ("3-1:1.1", 1)])
        self.assertEqual(sorted(self.backend.probes), ["3-1:1.0", "3-1:1.1"])

    # ------------------------------------------------------------------
    # Fail-safes
    # ------------------------------------------------------------------

    def test_autoprobe_is_restored_when_authorization_raises(self):
        """A machine that binds no drivers is worse than one dead device."""
        def explode(_syspath, _value):
            raise OSError("device vanished")
        self.backend.authorize = explode

        with self.assertRaises(OSError):
            with deferred_bind.DeferredBind(self.device,
                                            log=lambda _m: None) as db:
                db.authorize_device()

        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_emergency_restore_works_without_the_object(self):
        """Signal handlers and atexit have no DeferredBind to call."""
        db = deferred_bind.DeferredBind(self.device, log=lambda _m: None)
        db.__enter__()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "0")
        deferred_bind.emergency_restore()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_emergency_restore_is_idempotent(self):
        deferred_bind.emergency_restore()
        deferred_bind.emergency_restore()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_original_value_is_preserved_not_assumed(self):
        """Some systems run with autoprobe already at 0. Restoring 1 would be
        a silent configuration change made by a security tool."""
        (self.tree / "drivers_autoprobe").write_text("0")
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            db.authorize_device()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "0")

    def test_interfaces_left_closed_are_reopened_on_exit(self):
        db = deferred_bind.DeferredBind(self.device, log=lambda _m: None)
        with db:
            db.authorize_device()
            # release_interfaces() deliberately not called: simulates an
            # exception between authorization and release.
        self.assertEqual(sorted(self.backend.interface_writes)[-2:],
                         [("3-1:1.1", 0), ("3-1:1.1", 1)])
        for name in ("3-1:1.0", "3-1:1.1"):
            self.assertEqual(
                (self.tree / name / "authorized").read_text(), "1")

    # ------------------------------------------------------------------
    # Privilege separation
    # ------------------------------------------------------------------

    def test_unsupported_when_the_backend_refuses_bus_wide_writes(self):
        """Under --privsep the gate cannot scope a bus-wide operation.

        supported() must say no BEFORE anything is written, otherwise the
        mechanism gets halfway through with autoprobe already at 0 and then
        discovers it cannot finish.
        """
        class Scoped(FakeBackend):
            supports_bus_wide = False

        sysfs.install_backend(Scoped(self.tree, self.device))
        self.assertFalse(deferred_bind.supported(self.device))
        self.assertIn("privsep", deferred_bind.unsupported_reason())

    def test_unsupported_when_the_kernel_lacks_autoprobe(self):
        sysfs.DRIVERS_AUTOPROBE = self.tree / "does-not-exist"
        self.assertFalse(deferred_bind.supported(self.device))
        self.assertIn("not readable", deferred_bind.unsupported_reason())


if __name__ == "__main__":
    unittest.main()
