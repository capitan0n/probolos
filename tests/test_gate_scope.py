"""
Regression tests for gate scoping (audit finding C4).

Before the fix, the gate validated that a path was a real USB / input / block
node but not that it was the device under quarantine. A compromised analyzer
could therefore ask the root gate to:

  * open /dev/input/event0 -- the built-in keyboard -- as a system keylogger,
  * read /dev/sda -- the system disk,
  * authorize or deauthorize a device you were actively using.

The gate now derives scope from the kernel: it acts only on a USB device whose
`authorized` flag reads 0, and on input/block nodes whose USB parent is such a
device. These tests build a synthetic sysfs tree in a tempdir and point the
gate's prefix globals at it, so the kernel-derivation logic is exercised with
no root and no real hardware.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import gate_server


class GateScope(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        self.devices = self.root / "sys/devices"
        self.usb_blocked = self.devices / "pci0/usb1/1-1"
        self.usb_blocked.mkdir(parents=True)
        (self.usb_blocked / "authorized").write_text("0\n")
        self.usb_authed = self.devices / "pci0/usb1/1-2"
        self.usb_authed.mkdir(parents=True)
        (self.usb_authed / "authorized").write_text("1\n")
        self.ps2 = self.devices / "platform/i8042/serio0"
        self.ps2.mkdir(parents=True)

        self.busview = self.root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        os.symlink(self.usb_blocked, self.busview / "1-1")
        os.symlink(self.usb_authed, self.busview / "1-2")

        self.cls = self.root / "sys/class"
        self._make_class_node("input", "event5", self.usb_blocked)
        self._make_class_node("input", "event9", self.usb_authed)
        self._make_class_node("input", "event0", self.ps2)
        self._make_class_node("block", "sdz", self.usb_blocked)

        self.dev = self.root / "dev"
        (self.dev / "input").mkdir(parents=True)
        for n in ("event5", "event9", "event0"):
            (self.dev / "input" / n).write_bytes(b"")
        (self.dev / "sdz").write_bytes(b"")

        self._patchers = [
            mock.patch.object(gate_server, "USB_REAL_PREFIX",
                              str(self.devices) + "/"),
            mock.patch.object(gate_server, "USB_LINK_PREFIX",
                              str(self.busview) + "/"),
            mock.patch.object(gate_server, "SYS_CLASS_PREFIX",
                              str(self.cls) + "/"),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

    def _make_class_node(self, cls_dir, node, real_dev):
        d = self.root / "sys/class" / cls_dir / node
        d.mkdir(parents=True)
        os.symlink(real_dev, d / "device")

    # ---- _usb_device_is_blocked ----

    def test_blocked_device_reads_as_blocked(self):
        self.assertTrue(
            gate_server.GateServer._usb_device_is_blocked(self.usb_blocked))

    def test_authorized_device_reads_as_not_blocked(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.usb_authed))

    def test_missing_authorized_fails_closed(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.ps2))

    # ---- _blocked_usb_parent_of ----

    def test_event_under_quarantined_device_is_in_scope(self):
        node = self.dev / "input" / "event5"
        self.assertEqual(
            gate_server.GateServer._blocked_usb_parent_of(node),
            self.usb_blocked)

    def test_event_under_authorized_device_is_out_of_scope(self):
        node = self.dev / "input" / "event9"
        self.assertIsNone(
            gate_server.GateServer._blocked_usb_parent_of(node))

    def test_builtin_ps2_keyboard_is_never_in_scope(self):
        """The keylogger vector: event0 has no USB parent, so it is refused."""
        node = self.dev / "input" / "event0"
        self.assertIsNone(
            gate_server.GateServer._blocked_usb_parent_of(node))

    def test_usb_disk_under_quarantine_is_in_scope(self):
        node = self.dev / "sdz"
        self.assertEqual(
            gate_server.GateServer._blocked_usb_parent_of(node),
            self.usb_blocked)


if __name__ == "__main__":
    unittest.main()
