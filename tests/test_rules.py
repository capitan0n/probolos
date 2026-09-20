"""
Tests for the stage 2 rule engine.

The most valuable tests here are the boring ones: three devices inventoried
from a real laptop, asserted to produce NO findings at all. Every rule in this
project is one careless generalisation away from flagging ordinary hardware,
and these fixtures are the tripwire for that.

They are named after what they really are, so that a future contributor
understands they are field data and not invented examples.
"""

import unittest

from probolos import descriptors, rules, usbclass
from tests.test_descriptors import (config_desc, device_desc, endpoint_desc,
                                    iface_desc)


class FakeDevice:
    """
    Minimal stand-in for sysfs.UsbDevice.

    The rule engine deliberately takes a duck-typed device so it can be tested
    without touching /sys, which means the rules run in CI on any machine.
    """

    def __init__(self, vid, pid, manufacturer, product, speed, blob,
                 parse_error=None):
        self.vendor_id = vid
        self.product_id = pid
        self.manufacturer = manufacturer
        self.product = product
        self.speed = speed
        self.parse_error = parse_error
        self.descriptor_set = descriptors.parse(blob) if blob else None

    @property
    def interfaces(self):
        return self.descriptor_set.primary_interfaces() if self.descriptor_set else []

    @property
    def interface_classes(self):
        return self.descriptor_set.interface_classes() if self.descriptor_set else []

    def label(self):
        return " ".join(p for p in (self.manufacturer, self.product) if p)


def build(*ifaces):
    """Assemble a one-config device blob from (class, subclass, protocol)."""
    body = config_desc(9 + (9 + 7) * len(ifaces), len(ifaces))
    for n, (cls, sub, proto) in enumerate(ifaces):
        body += iface_desc(n, cls, subcls=sub, proto=proto) + endpoint_desc()
    return device_desc(0x1234, 0x5678) + body


# ---------------------------------------------------------------------------
# Field data: devices actually present on the developer's machine.
# These MUST stay silent. If a new rule breaks one of these, the rule is wrong.
# ---------------------------------------------------------------------------

def real_microsoft_mouse():
    """045e:00cb — Microsoft VID, but the strings say PixArt (sensor vendor)."""
    return FakeDevice("045e", "00cb", "PixArt", "Microsoft USB Optical Mouse",
                      "1.5", build((0x03, 0x01, 0x02)))


def real_lenovo_mouse():
    """
    17ef:608d — Lenovo's VID, and the strings say PixArt again.

    A second, independent instance of the same trap: two mice from different
    brands, both reporting the sensor vendor as manufacturer. Cross-branded
    strings are not an edge case, they are the norm.
    """
    return FakeDevice("17ef", "608d", "PixArt", "Lenovo USB Optical Mouse",
                      "1.5", build((0x03, 0x01, 0x02)))


def real_realtek_bluetooth():
    """0bda:4853 — two 0xe0 interfaces: HCI plus isochronous voice."""
    return FakeDevice("0bda", "4853", "Realtek", "Bluetooth Radio", "12",
                      build((0xE0, 0x01, 0x01), (0xE0, 0x01, 0x01)))


def real_chicony_camera():
    """04f2:b7ba — UVC mandates the control + streaming interface pair."""
    return FakeDevice("04f2", "b7ba", "Chicony Electronics Co.,Ltd.",
                      "Integrated Camera", "480",
                      build((0x0E, 0x01, 0x01), (0x0E, 0x02, 0x01)))


class TestNoFalsePositivesOnRealHardware(unittest.TestCase):

    def test_microsoft_mouse_is_silent(self):
        self.assertEqual(rules.evaluate(real_microsoft_mouse()), [])

    def test_lenovo_mouse_is_silent(self):
        self.assertEqual(rules.evaluate(real_lenovo_mouse()), [])

    def test_realtek_bluetooth_is_silent(self):
        self.assertEqual(rules.evaluate(real_realtek_bluetooth()), [])

    def test_chicony_camera_is_silent(self):
        self.assertEqual(rules.evaluate(real_chicony_camera()), [])

    def test_cross_branded_strings_are_never_flagged(self):
        """
        The mouse reports manufacturer 'PixArt' under Microsoft's VID 045e.
        A vendor/VID cross-check rule would flag it. We must never add one.
        """
        findings = rules.evaluate(real_microsoft_mouse())
        self.assertEqual(rules.worst(findings), rules.Severity.INFO)

    def test_ordinary_flash_drive_is_silent(self):
        dev = FakeDevice("0781", "5567", "SanDisk", "Cruzer Blade", "480",
                         build((0x08, 0x06, 0x50)))
        self.assertEqual(rules.evaluate(dev), [])

    def test_headset_with_hid_buttons_is_silent(self):
        """Audio + HID is a headset with volume keys, not an attack."""
        dev = FakeDevice("046d", "0a38", "Logitech", "USB Headset", "12",
                         build((0x01, 0x01, 0x00), (0x01, 0x02, 0x00),
                               (0x03, 0x00, 0x00)))
        self.assertEqual(rules.evaluate(dev), [])


class TestDetection(unittest.TestCase):

    def test_badusb_storage_plus_keyboard_is_critical(self):
        dev = FakeDevice("0781", "5567", "SanDisk", "Cruzer Blade", "480",
                         build((0x08, 0x06, 0x50), (0x03, 0x01, 0x01)))
        findings = rules.evaluate(dev)
        ids = [f.rule_id for f in findings]

        self.assertIn("storage-with-keyboard", ids)
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)
        # The worst finding must sort first: the report shows it at the top.
        self.assertEqual(findings[0].rule_id, "storage-with-keyboard")

    def test_self_contradiction_also_fires_on_badusb(self):
        dev = FakeDevice("0781", "5567", "SanDisk", "Cruzer Blade", "480",
                         build((0x08, 0x06, 0x50), (0x03, 0x01, 0x01)))
        ids = [f.rule_id for f in rules.evaluate(dev)]
        self.assertIn("self-contradictory-identity", ids)

    def test_keyboard_with_network_is_critical(self):
        dev = FakeDevice("1234", "5678", "Generic", "Keyboard", "480",
                         build((0x03, 0x01, 0x01), (0x02, 0x06, 0x00)))
        ids = [f.rule_id for f in rules.evaluate(dev)]
        self.assertIn("network-with-keyboard", ids)

    def test_mouse_with_storage_is_not_the_keyboard_rule(self):
        """
        A claimed mouse is not a declared keyboard, but its unread report
        descriptor may contain keyboard usages. The existing conservative
        storage/HID rule must still apply to this combination.
        """
        dev = FakeDevice("1234", "5678", "Generic", "Combo", "480",
                         build((0x08, 0x06, 0x50), (0x03, 0x01, 0x02)))
        findings = rules.evaluate(dev)
        ids = [f.rule_id for f in findings]

        self.assertNotIn("storage-with-keyboard", ids)
        self.assertIn("storage-with-undeclared-hid", ids)
        self.assertIn("multiple-distinct-functions", ids)
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)

    def test_unreadable_descriptors_is_a_finding(self):
        dev = FakeDevice("1234", "5678", None, None, "480", None,
                         parse_error="invalid bLength=0 at offset 27")
        ids = [f.rule_id for f in rules.evaluate(dev)]
        self.assertIn("unreadable-descriptors", ids)

    def test_high_speed_keyboard_is_only_a_notice(self):
        dev = FakeDevice("1234", "5678", "Generic", "Keyboard", "480",
                         build((0x03, 0x01, 0x01)))
        findings = rules.evaluate(dev)
        self.assertEqual([f.rule_id for f in findings],
                         ["keyboard-at-high-speed"])
        self.assertEqual(rules.worst(findings), rules.Severity.NOTICE)

    def test_low_speed_keyboard_is_silent(self):
        dev = FakeDevice("1234", "5678", "Generic", "Keyboard", "1.5",
                         build((0x03, 0x01, 0x01)))
        self.assertEqual(rules.evaluate(dev), [])


class TestSuppressionCannotHideAttacks(unittest.TestCase):

    def test_benign_group_never_suppresses_a_critical_rule(self):
        """
        Adding an audio interface makes the class set look more ordinary. It
        must not silence the storage+keyboard finding: a malicious device must
        never be able to hide by also looking like something normal.
        """
        dev = FakeDevice("0781", "5567", "Generic", "Combo", "480",
                         build((0x08, 0x06, 0x50), (0x03, 0x01, 0x01),
                               (0x01, 0x01, 0x00)))
        ids = [f.rule_id for f in rules.evaluate(dev)]
        self.assertIn("storage-with-keyboard", ids)

    def test_disabling_a_rule_is_honoured(self):
        cfg = rules.RuleConfig(disabled={"keyboard-at-high-speed"})
        dev = FakeDevice("1234", "5678", "Generic", "Keyboard", "480",
                         build((0x03, 0x01, 0x01)))
        self.assertEqual(rules.evaluate(dev, cfg), [])

    def test_severity_override_is_honoured(self):
        cfg = rules.RuleConfig(
            severity_overrides={"keyboard-at-high-speed": rules.Severity.WARNING})
        dev = FakeDevice("1234", "5678", "Generic", "Keyboard", "480",
                         build((0x03, 0x01, 0x01)))
        self.assertEqual(rules.worst(rules.evaluate(dev, cfg)),
                         rules.Severity.WARNING)


class TestKeyboardPredicate(unittest.TestCase):

    def test_only_boot_keyboard_protocol_counts(self):
        self.assertTrue(usbclass.is_keyboard(0x03, 0x01, 0x01))
        self.assertFalse(usbclass.is_keyboard(0x03, 0x01, 0x02))   # mouse
        self.assertFalse(usbclass.is_keyboard(0x03, 0x00, 0x00))   # generic HID
        self.assertFalse(usbclass.is_keyboard(0x08, 0x06, 0x50))   # storage


if __name__ == "__main__":
    unittest.main(verbosity=2)
