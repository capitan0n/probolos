"""
Regression tests for the stage-3-before-stage-4 ordering (audit finding C1).

The defect: stage 4 (storage inspection) authorized the WHOLE device to make
its block node appear, and it ran BEFORE stage 3 (the EVIOCGRAB quarantine).
On a composite storage+keyboard BadUSB that meant the keyboard interface was
live and ungrabbed for up to ~3 seconds while the partition table was read.

These tests pin two properties, both driven through mocks so they need no USB,
no root, and no graphical session:

  1. A composite input+storage device is NEVER handed to _inspect_medium,
     because authorizing it to look would switch its input half on without a
     grab. (_inspect_medium is the only place stage 4 calls set_authorized(1).)

  2. A pure storage device -- no input interface -- IS still inspected, so the
     fix did not simply disable stage 4.

The screen is UNLOCKED here on purpose: the locked case is already covered by
test_session.py. This is the case where the tool is actively working and the
ordering has to hold anyway.
"""

import unittest
from pathlib import Path
from unittest import mock

from cerberus import daemon as daemon_mod
from cerberus import session, sysfs, usbclass


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


class StageOrdering(unittest.TestCase):

    def setUp(self):
        self.writes = []
        # Unlocked, storage inspection ON, no observation window so the grab
        # path itself does not need a real device. observe=0 means stage 3 is
        # skipped, which is fine: what we are pinning is that stage 4 does not
        # authorize a device that can type.
        self.engine = daemon_mod.Cerberus(
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
        dev = make_device(kinds=[usbclass.KIND_INPUT, usbclass.KIND_STORAGE])
        with mock.patch.object(self.engine, "_inspect_medium") as inspect_fn:
            self.run_add(dev, approved=False)
            inspect_fn.assert_not_called()

    def test_composite_input_storage_is_never_authorized_before_decision(self):
        """
        The whole point of C1: no set_authorized(1) may reach a device that can
        type until the human has said yes. With observe=0 and a rejection, the
        only writes should be the deny-by-default blocking writes -- never a 1.
        """
        dev = make_device(kinds=[usbclass.KIND_INPUT, usbclass.KIND_STORAGE])
        self.run_add(dev, approved=False)
        self.assertNotIn(1, self.writes,
                         "a device that can type was authorized before the "
                         "human decided -- this is the C1 exposure window")

    def test_pure_storage_is_still_inspected(self):
        """The fix must not disable stage 4 for ordinary flash drives."""
        dev = make_device(kinds=[usbclass.KIND_STORAGE])
        with mock.patch.object(self.engine, "_inspect_medium",
                               return_value=None) as inspect_fn:
            self.run_add(dev, approved=False)
            inspect_fn.assert_called_once()


if __name__ == "__main__":
    unittest.main()
