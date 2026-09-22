"""
Two gaps in the privilege split itself.

  1. The gate undoes everything it changed when the analyzer goes away --
     devices it authorized are re-blocked, root hubs it closed are reopened --
     except interface authorization, which had no entry in that ledger at all.
     `authorize_interface(intf, 0)` therefore survived the analyzer's death:
     a device configured but with its keyboard half permanently driverless,
     looking healthy in sysfs, with nothing in restore() that would ever touch
     it again. That is persistent damage an analyzer compromise could leave
     behind, and SECURITY.md's lockout-safety argument applies to it exactly
     as written.

  2. drop_privileges() verified the uid and the gid and not the supplementary
     groups -- the one step its own docstring calls "a classic source of
     silent security holes". A surviving `input` or `disk` membership is
     precisely what the split exists to remove: the analyzer could open every
     evdev node and every raw disk directly, bypassing the gate's whole
     scoping rule, while every check that WAS made still passed.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import gate_server, privsep, protocol


class InterfacesAreRestored(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        self.devices = self.root / "sys/devices"
        self.device = self.devices / "pci0/usb1/1-1"
        self.device.mkdir(parents=True)
        (self.device / "authorized").write_text("0\n")
        self.iface = self.device / "1-1:1.0"
        self.iface.mkdir()
        (self.iface / "authorized").write_text("1\n")

        self.busview = self.root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        os.symlink(self.device, self.busview / "1-1")
        os.symlink(self.iface, self.busview / "1-1:1.0")

        for name, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/")):
            patcher = mock.patch.object(gate_server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.gate = gate_server.GateServer(sock=None, log=lambda *_a: None)

    def _unbind(self):
        return self.gate._do_authorize_interface(protocol.Request(
            protocol.REQ_AUTHORIZE_INTERFACE, str(self.iface), 0))

    def test_an_unbound_interface_is_put_back_on_restore(self):
        self.assertTrue(self._unbind().ok)
        self.assertEqual((self.iface / "authorized").read_text(), "0")

        self.gate.restore()
        self.assertEqual((self.iface / "authorized").read_text(), "1",
                         "the gate left an interface deauthorized after the "
                         "analyzer went away; nothing else will ever put it "
                         "back")

    def test_an_interface_the_analyzer_rebound_is_not_touched_again(self):
        self.assertTrue(self._unbind().ok)
        self.assertTrue(self.gate._do_authorize_interface(protocol.Request(
            protocol.REQ_AUTHORIZE_INTERFACE, str(self.iface), 1)).ok)
        self.assertEqual(self.gate._interfaces_off, {})

    def test_a_recycled_port_is_not_re_authorized(self):
        """
        The same instance discipline the device paths already get. A port
        recycled since the write means this directory belongs to different
        hardware, and authorizing an interface of a device nobody inspected is
        what _do_authorize_interface refuses to do on the request path.
        """
        self.assertTrue(self._unbind().ok)
        replacement = self.device / "replacement"
        replacement.mkdir()
        (replacement / "authorized").write_text("0\n")
        self.iface.rename(self.device / "gone")
        replacement.rename(self.iface)

        self.gate.restore()
        self.assertEqual((self.iface / "authorized").read_text().strip(), "0")

    def test_restore_reports_a_failure_instead_of_raising(self):
        self.assertTrue(self._unbind().ok)
        (self.iface / "authorized").unlink()
        messages = []
        self.gate.log = messages.append
        self.gate.restore()          # must not raise
        self.assertTrue(any("re-authorize" in m for m in messages), messages)


class SupplementaryGroupsMustBeGone(unittest.TestCase):

    def _drop_with_groups(self, groups):
        """Run drop_privileges as though it were root, with a chosen result."""
        with mock.patch.object(os, "getuid", return_value=0), \
             mock.patch.object(os, "setgroups"), \
             mock.patch.object(os, "setgid"), \
             mock.patch.object(os, "setuid",
                               side_effect=[None, PermissionError()]), \
             mock.patch.object(os, "geteuid", return_value=65534), \
             mock.patch.object(os, "getgid", return_value=65534), \
             mock.patch.object(os, "getegid", return_value=65534), \
             mock.patch.object(os, "getgroups", return_value=groups):
            # getuid must read 0 on entry and 65534 after the drop.
            os.getuid.side_effect = [0, 65534]
            privsep.drop_privileges(65534, 65534)

    def test_a_surviving_group_stops_the_drop(self):
        with self.assertRaises(privsep.PrivsepError) as caught:
            self._drop_with_groups([65534, 27])     # 27 == sudo on Debian
        self.assertIn("supplementary groups", str(caught.exception))

    def test_the_primary_gid_alone_is_accepted(self):
        self._drop_with_groups([65534])             # must not raise

    def test_no_groups_at_all_is_accepted(self):
        self._drop_with_groups([])                  # must not raise


if __name__ == "__main__":
    unittest.main()
