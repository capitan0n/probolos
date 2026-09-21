"""
Descriptor parsing: the well-formed path and the hostile one.

The sysfs `descriptors` blob is the only thing Probolos can read while
a device is still blocked, so every claim the rules judge comes through
here. Both halves live together because they are the same question
asked twice: what does this device say, and what happens when it lies
about how much it is saying.

Merged from: test_descriptors.py, test_descriptors_malformed.py
"""
from __future__ import annotations

# =========================================================================
# test_descriptors.py
#
# Tests for the descriptor parser.
# =========================================================================

import struct
import unittest

from probolos import descriptors, usbclass


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


# =========================================================================
# test_descriptors_malformed.py
#
# test_descriptors_malformed.py — Regression tests για το αμυντικό parsing.
# =========================================================================

import sys

# Δουλεύει και ως μέρος του πακέτου (pytest από τη ρίζα του repo)
# και σκέτο (python test_descriptors_malformed.py μέσα στον φάκελο).
try:
    from probolos.descriptors_safe import (        # type: ignore
        DescriptorParsingError,
        effective_total_length,
        safe_parse,
        take,
        walk_descriptors,
        walk_hid_items,
        wtotallength_mismatch,
    )
except ImportError:
    from descriptors_safe import (                 # type: ignore
        DescriptorParsingError,
        effective_total_length,
        safe_parse,
        take,
        walk_descriptors,
        walk_hid_items,
        wtotallength_mismatch,
    )

def _expect_error(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        # Οι generators δεν εκτελούνται μέχρι να καταναλωθούν.
        if hasattr(result, "__iter__") and not isinstance(result, (bytes, str)):
            list(result)
    except DescriptorParsingError:
        return True
    raise AssertionError(f"περίμενα DescriptorParsingError από {fn.__name__}")


# --------------------------------------------------------------------------
# take() — το σιωπηλό slicing της Python
# --------------------------------------------------------------------------


class DefensiveParsing(unittest.TestCase):
    """
    The descriptors_safe checks, wrapped in a TestCase.

    These were bare module-level functions, which `python -m unittest
    discover` does not collect -- only the project's own tests/run_all.py
    picked them up, through an inspect.getmembers() scan. The command the
    README documents therefore ran 535 tests while these 20 never
    executed, so a regression in the hostile-descriptor parser was
    invisible to anyone following the documented instructions. Wrapping
    them makes the two runners agree.
    """

    def test_take_rejects_read_past_end(self):
        """Η ρίζα του προβλήματος: b"abc"[0:100] επιστρέφει b"abc" χωρίς σφάλμα."""
        buf = b"\x12\x01\x00\x02"
        assert buf[0:100] == buf          # τεκμηρίωση της συμπεριφοράς της Python
        _expect_error(take, buf, 0, 100, "device descriptor")


    def test_take_rejects_negative_offset(self):
        _expect_error(take, b"\x00\x01", -1, 1, "x")


    # --------------------------------------------------------------------------
    # walk_descriptors — ο πραγματικός DoS
    # --------------------------------------------------------------------------
    def test_zero_blength_does_not_hang(self):
        """bLength=0: χωρίς έλεγχο ο δείκτης δεν προχωρά ποτέ.

        Αν αυτό το test κρεμάσει αντί να αποτύχει, η επίθεση δουλεύει.
        """
        hostile = b"\x00\x02\xff\xff\xff\xff"
        _expect_error(walk_descriptors, hostile)


    def test_blength_one_rejected(self):
        """bLength=1 είναι επίσης μικρότερο από το ελάχιστο header."""
        _expect_error(walk_descriptors, b"\x01\x02\x00\x00")


    def test_descriptor_overruns_buffer(self):
        """Δηλώνει 64 bytes ενώ υπάρχουν 4."""
        _expect_error(walk_descriptors, b"\x40\x02\x00\x00")


    def test_truncated_header(self):
        """Απομένει ένα μόνο byte στο τέλος της αλυσίδας."""
        valid = b"\x04\x02\x00\x00"
        _expect_error(walk_descriptors, valid + b"\x09")


    def test_item_flood_rejected(self):
        """Χιλιάδες ελάχιστα descriptors — exhaustion μέσω πλήθους, όχι μεγέθους."""
        flood = b"\x02\x02" * 5000
        _expect_error(walk_descriptors, flood)


    def test_valid_chain_parses(self):
        """Θετικός έλεγχος: μια νόμιμη αλυσίδα δεν πρέπει να απορρίπτεται.

        Config (9B) + Interface (9B). Χωρίς αυτό το test, ένας υπερβολικά
        αυστηρός parser θα «περνούσε» απορρίπτοντας τα πάντα.
        """
        config = bytes([0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32])
        iface = bytes([0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00])
        items = list(walk_descriptors(config + iface))
        assert len(items) == 2
        assert items[0][0] == 0x02          # CONFIGURATION
        assert items[1][0] == 0x04          # INTERFACE
        assert len(items[0][1]) == 9


    # --------------------------------------------------------------------------
    # wTotalLength
    # --------------------------------------------------------------------------
    def test_wtotallength_clamped_to_reality(self):
        """Δηλώνει 0xFFFF ενώ στέλνει 9 bytes."""
        cfg = bytes([0x09, 0x02, 0xFF, 0xFF, 0x01, 0x01, 0x00, 0x80, 0x32])
        assert effective_total_length(cfg) == 9
        assert wtotallength_mismatch(cfg) == 0xFFFF - 9


    # --------------------------------------------------------------------------
    # HID items
    # --------------------------------------------------------------------------
    def test_hid_push_without_pop_rejected(self):
        """0xA4 = Global/Push με μηδέν bytes δεδομένων."""
        _expect_error(walk_hid_items, b"\xa4" * 100)


    def test_hid_pop_without_push_rejected(self):
        _expect_error(walk_hid_items, b"\xb4")


    def test_hid_collection_depth_limited(self):
        """0xA1 0x01 = Main/Collection (Application), επαναλαμβανόμενο."""
        _expect_error(walk_hid_items, b"\xa1\x01" * 200)


    def test_hid_end_collection_without_open(self):
        """0xC0 = Main/End Collection."""
        _expect_error(walk_hid_items, b"\xc0")


    def test_hid_unbalanced_collection_at_eof(self):
        """Ανοίγει Collection και δεν το κλείνει ποτέ."""
        _expect_error(walk_hid_items, b"\xa1\x01")


    def test_hid_absurd_report_size_rejected(self):
        """ReportSize=32 (0x75 0x20), ReportCount=0xFFFF (0x96), μετά Input (0x81).

        2 Mbit «report» — memory exhaustion κατά την κατανομή buffers.
        """
        hostile = b"\x75\x20" + b"\x96\xff\xff" + b"\x81\x02"
        _expect_error(walk_hid_items, hostile)


    def test_hid_truncated_item_data(self):
        """0x75 δηλώνει 1 byte δεδομένων που δεν υπάρχει."""
        _expect_error(walk_hid_items, b"\x75")


    def test_hid_valid_mouse_descriptor_parses(self):
        """Θετικός έλεγχος με πραγματικό boot-protocol mouse descriptor.

        Αντιστοιχεί στην κατηγορία του PixArt/Lenovo ποντικιού (17ef:608d).
        """
        mouse = bytes([
            0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01,
            0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03,
            0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01,
            0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x03,
            0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81,
            0x25, 0x7F, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
            0xC0, 0xC0,
        ])
        items = list(walk_hid_items(mouse))
        # 24 short items των 2 bytes + 2 items του 1 byte (0xC0 End Collection)
        assert len(items) == 26


    # --------------------------------------------------------------------------
    # safe_parse — fail-closed
    # --------------------------------------------------------------------------
    def test_safe_parse_converts_error_to_value(self):
        def boom(_):
            raise DescriptorParsingError("bLength=0")

        result, err = safe_parse(boom, b"")
        assert result is None
        assert "bLength=0" in err


    def test_safe_parse_catches_unexpected_bug(self):
        """Ένα bug στον parser δεν επιτρέπεται να ρίξει τον daemon."""
        def bug(_):
            return [][5]

        result, err = safe_parse(bug, b"")
        assert result is None
        assert "IndexError" in err


    def test_safe_parse_passes_through_success(self):
        result, err = safe_parse(lambda x: x * 2, 21)
        assert result == 42 and err is None


    # --------------------------------------------------------------------------
