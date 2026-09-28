"""
USB descriptor parsing: the well-formed path, the hardened walker, and
declared power.

Covers probolos.descriptors, probolos.descriptors_safe and probolos.usbclass.
"""

from __future__ import annotations

import struct
import unittest

from probolos import descriptors, descriptors_safe, rules, usbclass
from probolos.descriptors_safe import (
    DescriptorParsingError,
    effective_total_length,
    safe_parse,
    take,
    walk_descriptors,
    walk_hid_items,
    wtotallength_mismatch,
)
from tests._support import (
    config_desc,
    device_desc,
    endpoint_desc,
    iface_desc,
    power_config_desc,
    power_device_desc,
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


def _device_descriptor() -> bytes:
    return bytes([18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 64,
                  0xd2, 0x04, 0x2b, 0xc5, 0x00, 0x01, 1, 2, 3, 1])


def hid_device_desc(vid=0x1234, pid=0x5678, bcd_usb=0x0200, num_configs=1):
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01, bcd_usb, 0x00, 0, 0, 64,
        vid, pid, 0x0100, 0, 0, 0, num_configs)


def hid_config_desc(total, n_ifaces=1, max_power=50):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, n_ifaces, 1, 0, 0x80,
                       max_power)


def hid_iface_desc(cls=0x03, num=0):
    return struct.pack("<BBBBBBBBB", 9, 0x04, num, 0, 1, cls, 0, 0, 0)


class _Stub:
    """Duck-typed device, matching tests/test_rules.py's FakeDevice.

    interfaces and interface_classes must be properties derived from the
    descriptor set, not empty lists: the rule engine reads them, and a stub
    that hands back [] silently disables half the rules under test.
    """

    def __init__(self, ds):
        self.descriptor_set = ds
        self.vendor_id = "1234"
        self.product_id = "5678"
        self.manufacturer = None
        self.product = None
        self.serial = None
        self.speed = "12"
        self.parse_error = None

    @property
    def interfaces(self):
        return self.descriptor_set.primary_interfaces()

    @property
    def interface_classes(self):
        return self.descriptor_set.interface_classes()

    def label(self):
        return ""


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
        """Χιλιάδες ελάχιστα descriptors — exhaustion μέσω πλήθους, όχι μεγέθους.

        Το πλήθος παράγεται από το ίδιο το MAX_DESCRIPTOR_ITEMS. Με σταθερό
        νούμερο (ήταν 5000) το test περνούσε ή έπεφτε ανάλογα με το όριο, κι
        έτσι μια αλλαγή του ορίου δεν φαινόταν εδώ ως αλλαγή συμπεριφοράς.
        """
        from probolos.descriptors_safe import MAX_DESCRIPTOR_ITEMS
        flood = b"\x02\x02" * (MAX_DESCRIPTOR_ITEMS + 1)
        _expect_error(walk_descriptors, flood)

    def test_a_realistic_composite_device_is_not_a_flood(self):
        """Μια webcam με πολλά alternate settings δεν είναι επίθεση.

        Το όριο ήταν 256 descriptors για ΟΛΟ το blob, και μια συνηθισμένη UVC
        κάμερα το ξεπερνά. Το αποτέλεσμα ήταν μη ανακτήσιμο σφάλμα: όλο το
        descriptor set απορριπτόταν, χωρίς στάδιο 3 ή 4, με WARNING σε
        υλικό που δεν είχε κάνει τίποτα.
        """
        chain = bytes([0x09, 0x04, 0x00, 0x00, 0x01, 0x0E, 0x02, 0x00, 0x00])
        items = list(walk_descriptors(chain * 300))
        assert len(items) == 300


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


class FloodGuardSitsAboveRealHardware(unittest.TestCase):

    def test_a_webcams_worth_of_descriptors_is_accepted(self):
        iface = bytes([0x09, 0x04, 0x00, 0x00, 0x01, 0x0E, 0x02, 0x00, 0x00])
        config = bytes([0x09, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32])
        parsed = descriptors.parse(_device_descriptor() + config + iface * 400)
        self.assertIsNone(parsed.truncated)
        self.assertEqual(len(parsed.configs[0].interfaces), 400)

    def test_the_guard_still_exists(self):
        blob = _device_descriptor() + b"\x02\x02" * (
            descriptors_safe.MAX_DESCRIPTOR_ITEMS + 1)
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_a_zero_length_descriptor_is_still_refused(self):
        """
        The termination guarantee, which is the reason the walker exists at
        all: bLength=0 would never advance the offset.
        """
        with self.assertRaises(descriptors_safe.DescriptorParsingError):
            list(descriptors_safe.walk_descriptors(b"\x00\x02\x00\x00"))


class TestPowerUnits(unittest.TestCase):
    """The shipped bug. One byte, two meanings, depending on bcdUSB."""

    def test_usb2_uses_2ma_units(self):
        ds = descriptors.parse(power_device_desc(0x0200) + power_config_desc(50))
        self.assertEqual(ds.configs[0].max_power_ma, 100)
        self.assertEqual(ds.configs[0].power_unit_ma, 2)

    def test_superspeed_uses_8ma_units(self):
        """The same byte means four times as much on USB 3.x."""
        ds = descriptors.parse(power_device_desc(0x0300) + power_config_desc(50))
        self.assertEqual(ds.configs[0].max_power_ma, 400)
        self.assertEqual(ds.configs[0].power_unit_ma, 8)

    def test_usb31_and_32_also_use_8ma_units(self):
        for bcd in (0x0310, 0x0320):
            ds = descriptors.parse(power_device_desc(bcd) + power_config_desc(50))
            self.assertEqual(ds.configs[0].max_power_ma, 400)

    def test_raw_byte_is_preserved_for_audit(self):
        ds = descriptors.parse(power_device_desc(0x0300) + power_config_desc(50))
        self.assertEqual(ds.configs[0].max_power_raw, 50)

    def test_bus_limits_follow_the_specification(self):
        self.assertEqual(descriptors.bus_power_limit_ma(0x0200), 500)
        self.assertEqual(descriptors.bus_power_limit_ma(0x0300), 900)

    def test_attribute_bits_are_decoded(self):
        bus = descriptors.parse(power_device_desc() + power_config_desc(50, attrs=0x80))
        self.assertFalse(bus.configs[0].self_powered)

        selfp = descriptors.parse(power_device_desc() + power_config_desc(0, attrs=0xC0))
        self.assertTrue(selfp.configs[0].self_powered)

        wake = descriptors.parse(power_device_desc() + power_config_desc(50, attrs=0xA0))
        self.assertTrue(wake.configs[0].remote_wakeup)


# ==========================================================================
# descriptors.parse() now walks through descriptors_safe
# ==========================================================================

class ParserUsesTheHardenedWalker(unittest.TestCase):

    def test_a_flood_of_tiny_descriptors_is_refused(self):
        """The protection that only descriptors_safe had, and nothing used.

        The loop this replaced bounded every descriptor's SIZE but never their
        COUNT, so 200_000 two-byte items were walked one at a time. Not fatal
        on its own -- which is exactly how a bound goes missing.
        """
        from probolos.descriptors_safe import MAX_DESCRIPTOR_ITEMS
        blob = hid_device_desc() + b"\x02\x02" * (MAX_DESCRIPTOR_ITEMS + 1)
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_an_ordinary_composite_device_is_not_refused_as_a_flood(self):
        """The ceiling must sit above real hardware, not through it.

        At 256 descriptors for the whole blob, a UVC webcam with its usual
        run of alternate settings tripped the flood guard, and the flood
        guard is non-recoverable -- so the device was refused outright:
        parse_error set, inspection_safe False, no behavioural or storage
        stage, and a WARNING on somebody's own camera.
        """
        body = hid_config_desc(total=9 + 9 * 300) + hid_iface_desc() * 300
        ds = descriptors.parse(hid_device_desc() + body)
        self.assertIsNone(ds.truncated)
        self.assertEqual(len(ds.configs), 1)
        self.assertEqual(len(ds.configs[0].interfaces), 300)

    def test_a_truncated_tail_is_still_kept_and_now_reported(self):
        """The behaviour that had to survive the rewrite.

        A tail that stops early is common on merely buggy hardware, so it must
        not become a refusal. What changed is that it is no longer discarded in
        silence.
        """
        body = hid_config_desc(total=27) + hid_iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(hid_device_desc() + body)
        self.assertEqual(len(ds.primary_interfaces()), 1)
        self.assertIsNotNone(ds.truncated)

    def test_the_truncation_reaches_the_operator_as_a_finding(self):
        body = hid_config_desc(total=27) + hid_iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(hid_device_desc() + body)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-chain-truncated", {f.rule_id for f in found})

    def test_overstated_wtotallength_is_reported(self):
        """The fingerprint of a hand-edited descriptor set: vendor toolchains
        compute this field, so a mismatch is not a typo."""
        body = hid_config_desc(total=0xFFFF) + hid_iface_desc()
        ds = descriptors.parse(hid_device_desc() + body)
        self.assertGreater(ds.length_overstated, 0)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-length-overstated",
                      {f.rule_id for f in found})

    def test_an_honest_device_produces_neither_finding(self):
        """The false-positive guard. A rule that fires on ordinary hardware is
        worse than no rule, because it teaches the operator to click through."""
        body = hid_config_desc(total=18) + hid_iface_desc()
        ds = descriptors.parse(hid_device_desc() + body)
        self.assertIsNone(ds.truncated)
        self.assertEqual(ds.length_overstated, 0)
        ids = {f.rule_id for f in rules.evaluate(_Stub(ds))}
        self.assertNotIn("descriptor-chain-truncated", ids)
        self.assertNotIn("descriptor-length-overstated", ids)

    def test_zero_blength_is_still_fatal(self):
        """Not recoverable, and must not be softened into a warning: the walk
        cannot advance past it by any amount."""
        blob = hid_device_desc() + b"\x00\x02\xff\xff"
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)


if __name__ == "__main__":
    unittest.main()
