"""
Tests for the descriptor parser.

These matter more than they look. The parser is the only thing standing
between Cerberus and a device that lies about its own structure, and it is the
one component that can be tested without any hardware at all -- which is
exactly why it is the part that gets tested properly.
"""

import struct
import unittest

from cerberus import descriptors, usbclass


# ---------------------------------------------------------------------------
# Builders: synthesise the same bytes the kernel would hand us
# ---------------------------------------------------------------------------

def device_desc(vid, pid, dev_class=0x00, num_configs=1):
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01,          # bLength, DEVICE
        0x0200,            # bcdUSB 2.0
        dev_class, 0, 0,   # class/subclass/protocol
        64,                # bMaxPacketSize0
        vid, pid,
        0x0100,            # bcdDevice
        1, 2, 3,           # string indices
        num_configs,
    )


def config_desc(total_len, num_ifaces, value=1):
    return struct.pack("<BBHBBBBB",
                       9, 0x02, total_len, num_ifaces, value, 0, 0x80, 50)


def iface_desc(num, cls, subcls=0, proto=0, alt=0, n_eps=1):
    return struct.pack("<BBBBBBBBB",
                       9, 0x04, num, alt, n_eps, cls, subcls, proto, 0)


def endpoint_desc():
    return struct.pack("<BBBBHB", 7, 0x05, 0x81, 0x02, 512, 0)


# ---------------------------------------------------------------------------

class TestParser(unittest.TestCase):

    def test_plain_flash_drive(self):
        """One mass-storage interface: the boring, correct case."""
        body = (config_desc(9 + 9 + 7, 1)
                + iface_desc(0, 0x08, subcls=0x06, proto=0x50)
                + endpoint_desc())
        blob = device_desc(0x0781, 0x5567) + body

        ds = descriptors.parse(blob)

        self.assertEqual(ds.device.vendor_id, 0x0781)
        self.assertEqual(ds.device.num_configurations, 1)
        self.assertEqual(ds.interface_classes(), [0x08])
        self.assertFalse(ds.declared_interface_mismatch())

    def test_badusb_composite_storage_plus_keyboard(self):
        """
        The signature pattern: a flash drive that also declares a keyboard.

        The storage half provides the alibi ("of course it's a USB stick, look,
        files appeared"), while the HID half does the typing. If the parser
        misses this, the entire tool misses BadUSB.
        """
        body = (config_desc(9 + (9 + 7) * 2, 2)
                + iface_desc(0, 0x08, subcls=0x06, proto=0x50)
                + endpoint_desc()
                + iface_desc(1, 0x03, subcls=0x01, proto=0x01)  # boot keyboard
                + endpoint_desc())
        blob = device_desc(0x0781, 0x5567) + body

        ds = descriptors.parse(blob)
        classes = ds.interface_classes()

        self.assertIn(0x08, classes)
        self.assertIn(0x03, classes)
        kinds = {usbclass.kind_of(c) for c in classes}
        self.assertEqual(kinds, {usbclass.KIND_STORAGE, usbclass.KIND_INPUT})

        described = [usbclass.describe_interface(i.interface_class,
                                                 i.interface_subclass,
                                                 i.interface_protocol)
                     for i in ds.primary_interfaces()]
        # "(SCSI)" comes from subclass 0x06 / protocol 0x50 -- bulk-only
        # transport, which is what every ordinary flash drive uses.
        self.assertEqual(described, ["Mass Storage (SCSI)", "KEYBOARD"])

    def test_alternate_settings_do_not_inflate_interface_list(self):
        """A webcam's alt settings must not look like extra devices."""
        body = (config_desc(9 + 9 * 3, 1)
                + iface_desc(0, 0x0E, alt=0, n_eps=0)
                + iface_desc(0, 0x0E, alt=1)
                + iface_desc(0, 0x0E, alt=2))
        ds = descriptors.parse(device_desc(0x046D, 0x0825) + body)

        self.assertEqual(len(ds.primary_interfaces()), 1)
        self.assertFalse(ds.declared_interface_mismatch())

    def test_unknown_descriptor_types_are_skipped(self):
        """A HID report descriptor (0x21) sits between interface and endpoint."""
        hid_extra = struct.pack("<BBHBBBH", 9, 0x21, 0x0111, 0, 1, 0x22, 65)
        body = (config_desc(9 + 9 + 9 + 7, 1)
                + iface_desc(0, 0x03, subcls=0x01, proto=0x02)
                + hid_extra
                + endpoint_desc())
        ds = descriptors.parse(device_desc(0x046D, 0xC077) + body)

        self.assertEqual(ds.interface_classes(), [0x03])
        self.assertEqual(
            usbclass.describe_interface(0x03, 0x01, 0x02), "MOUSE")

    def test_declared_count_mismatch_is_detected(self):
        """Config says 3 interfaces, delivers 1. Honest hardware doesn't."""
        body = config_desc(9 + 9, 3) + iface_desc(0, 0x08)
        ds = descriptors.parse(device_desc(0x1234, 0x5678) + body)
        self.assertTrue(ds.declared_interface_mismatch())

    def test_zero_length_descriptor_does_not_hang(self):
        """A hostile device can emit bLength=0. We must refuse, not spin."""
        blob = device_desc(0x1234, 0x5678) + b"\x00\x02\x00\x00"
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_truncated_tail_keeps_what_was_parsed(self):
        """Half an endpoint descriptor should not discard a valid interface."""
        body = config_desc(9 + 9 + 7, 1) + iface_desc(0, 0x08) + b"\x07\x05\x81"
        ds = descriptors.parse(device_desc(0x1234, 0x5678) + body)
        self.assertEqual(ds.interface_classes(), [0x08])

    def test_too_short_blob_rejected(self):
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(b"\x12\x01")

    def test_wrong_first_descriptor_rejected(self):
        blob = bytearray(device_desc(0x1234, 0x5678))
        blob[1] = 0x02  # claim it's a config descriptor
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(bytes(blob))


if __name__ == "__main__":
    unittest.main(verbosity=2)
