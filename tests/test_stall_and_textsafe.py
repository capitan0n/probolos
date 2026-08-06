"""
Regression tests for two defects that were documented but never applied.

F5 -- a stalled storage read opened the gate system-wide.
    inspect() had no time bound. A device that stalls its own security scan
    froze the daemon; with the watchdog running, that freeze became the
    watchdog reopening authorized_default for EVERY port. A stall in the scan
    causing a system-wide fail-open.

F3 -- textsafe was imported by nothing.
    Device strings went from sysfs to the terminal, the JSON log, the trust
    store and the dialogs completely unsanitised, so an iProduct carrying ESC
    sequences could rewrite the report the operator was reading -- including
    the CRITICAL line. The sanitiser existed; it was never wired to the one
    place raw bytes become Python strings.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cerberus import storage, sysfs, textsafe


class StorageStall(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.tmp = self._d.name

    def test_a_stalled_inspection_times_out_instead_of_freezing(self):
        """A reader on a writer-less fifo blocks forever; it must be killed."""
        fifo = os.path.join(self.tmp, "stall")
        os.mkfifo(fifo)
        report = storage.inspect_safely(fifo, timeout=1.0)
        self.assertFalse(report.inspected)
        self.assertIn("did not respond", report.error)

    def test_the_timeout_is_actually_enforced(self):
        """Pin the bound itself: an unbounded read would never return."""
        import time
        fifo = os.path.join(self.tmp, "stall2")
        os.mkfifo(fifo)
        started = time.monotonic()
        storage.inspect_safely(fifo, timeout=1.0)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_a_healthy_medium_still_inspects(self):
        """The bound must not break the normal path."""
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(b"\x00" * (storage.SECTOR - 2) + b"\x55\xaa")
            fh.write(b"\x00" * (storage.HEADER_READ - storage.SECTOR))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertIsNone(report.error)


class TextsafeChokepoint(unittest.TestCase):
    """
    load_device must sanitise, and must RECORD why. The rules engine already
    turns string_notes into findings (crafted-strings); before this wiring it
    read an attribute nothing ever set, so the rule could never fire on real
    hardware no matter how hostile the device.
    """

    def _load_with_strings(self, **strings):
        # load_device returns None without these: an interface directory has
        # no idVendor, and that is how it tells devices from interfaces.
        strings.setdefault("idVendor", "abcd")
        strings.setdefault("idProduct", "1234")

        def fake_read_attr(path, name, **kw):
            return strings.get(name)

        with mock.patch.object(sysfs, "read_attr", side_effect=fake_read_attr), \
             mock.patch.object(sysfs, "read_int_attr", return_value=None):
            return sysfs.load_device(Path("/sys/bus/usb/devices/9-9"))

    def test_escape_sequences_are_neutralised(self):
        dev = self._load_with_strings(product="Kingston\x1b[2J\x1b[1A")
        self.assertIsNotNone(dev)
        self.assertNotIn("\x1b", dev.product,
                         "a raw ESC reached the device object: it can rewrite "
                         "the report the operator is reading")

    def test_the_reason_is_recorded_for_the_rules_engine(self):
        dev = self._load_with_strings(product="Kingston\x1b[2J")
        self.assertIn(textsafe.NOTE_CONTROL, dev.string_notes)
        self.assertIn("iProduct", dev.string_note_fields)

    def test_an_honest_device_gets_no_notes(self):
        dev = self._load_with_strings(manufacturer="Kingston",
                                      product="DataTraveler 3.0",
                                      serial="ABC123")
        self.assertEqual(dev.string_notes, [])
        self.assertEqual(dev.string_note_fields, {})
        self.assertEqual(dev.product, "DataTraveler 3.0")


if __name__ == "__main__":
    unittest.main()
