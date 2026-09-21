"""
The rule engine: identity, crafted strings, and declared power.

One file because one function is under test -- rules.evaluate() and the
helpers it calls. Splitting them by which rule fired meant three places
to look when a device produced an unexpected verdict.

Merged from: test_rules.py, test_rules_crafted_strings.py, test_power.py
"""
from __future__ import annotations

# =========================================================================
# test_rules.py
#
# Tests for the stage 2 rule engine.
# =========================================================================

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


# =========================================================================
# test_rules_crafted_strings.py
#
# Regression tests for the report-level consequences of a crafted string.
# =========================================================================

import html
import unittest
from types import SimpleNamespace

from probolos import rules, textsafe
from probolos.textsafe import NOTE_BIDI, NOTE_CONTROL, NOTE_INVISIBLE


def _device(*, notes=(), per_field=None, keyboard=False, classes=(),
            interfaces=None):
    """
    A stub carrying exactly what evaluate() reads for these rules.

    string_notes and string_note_fields are what descriptors.py attaches after
    sanitising; the rest is the minimum evaluate() touches without erroring.
    """
    ifaces = interfaces if interfaces is not None else []
    return SimpleNamespace(
        string_notes=tuple(notes),
        string_note_fields=per_field or {},
        interfaces=ifaces,
        interface_classes=list(classes),
        manufacturer="stub", product="stub", serial="stub",
    )


class CraftedStringFinding(unittest.TestCase):

    def _findings(self, dev):
        return {f.rule_id: f for f in rules.evaluate(dev)}

    def test_a_control_character_produces_a_warning(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]})
        found = self._findings(dev)
        self.assertIn("crafted-strings", found)
        self.assertEqual(found["crafted-strings"].severity,
                         rules.Severity.WARNING)

    def test_a_bidi_override_produces_the_same_warning(self):
        dev = _device(notes=(NOTE_BIDI,),
                      per_field={"iProduct": [NOTE_BIDI]})
        self.assertIn("crafted-strings", self._findings(dev))

    def test_the_finding_names_the_field_that_was_crafted(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL],
                                 "iProduct": [], "iSerialNumber": []})
        finding = self._findings(dev)["crafted-strings"]
        self.assertIn("manufacturer name", finding.explanation)

    def test_invisible_characters_are_a_notice_not_a_warning(self):
        dev = _device(notes=(NOTE_INVISIBLE,),
                      per_field={"iSerialNumber": [NOTE_INVISIBLE]})
        found = self._findings(dev)
        self.assertIn("invisible-string-characters", found)
        self.assertEqual(found["invisible-string-characters"].severity,
                         rules.Severity.NOTICE)
        self.assertNotIn("crafted-strings", found)

    def test_a_clean_device_produces_no_string_finding(self):
        dev = _device()
        found = self._findings(dev)
        self.assertNotIn("crafted-strings", found)
        self.assertNotIn("invisible-string-characters", found)

    def test_the_real_test_devices_produce_no_string_finding(self):
        """The zero-finding fixtures must stay at zero for these rules."""
        for name in ("PixArt", "Realtek", "Chicony", "General UDisk"):
            dev = _device()
            dev.manufacturer = name
            self.assertNotIn("crafted-strings", self._findings(dev), name)

    # ---- the escalation: crafted name AND able to type ----

    def test_a_typing_device_with_a_crafted_name_is_critical(self):
        """
        Keyboard + control characters in its own name is intent, not
        sloppiness, and is treated like the other BadUSB signatures.
        """
        kbd = SimpleNamespace(interface_class=rules.CLS_HID,
                              interface_subclass=1, interface_protocol=1)
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]},
                      classes=(rules.CLS_HID,), interfaces=[kbd])
        found = self._findings(dev)
        self.assertIn("crafted-strings-hid", found)
        self.assertEqual(found["crafted-strings-hid"].severity,
                         rules.Severity.CRITICAL)

    def test_a_non_typing_device_with_a_crafted_name_is_only_a_warning(self):
        """The escalation must require the keyboard, not just the strings."""
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iProduct": [NOTE_CONTROL]},
                      classes=(rules.CLS_MASS_STORAGE,))
        found = self._findings(dev)
        self.assertNotIn("crafted-strings-hid", found)
        self.assertIn("crafted-strings", found)

    # ---- configurability, via the existing machinery ----

    def test_the_string_rule_can_be_raised_to_critical_by_config(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]})
        cfg = rules.RuleConfig(
            severity_overrides={"crafted-strings": rules.Severity.CRITICAL})
        found = {f.rule_id: f for f in rules.evaluate(dev, cfg)}
        self.assertEqual(found["crafted-strings"].severity,
                         rules.Severity.CRITICAL)

    def test_the_invisible_rule_can_be_silenced_independently(self):
        dev = _device(notes=(NOTE_INVISIBLE,),
                      per_field={"iSerialNumber": [NOTE_INVISIBLE]})
        cfg = rules.RuleConfig(disabled={"invisible-string-characters"})
        found = {f.rule_id: f for f in rules.evaluate(dev, cfg)}
        self.assertNotIn("invisible-string-characters", found)


class DialogMarkupEscaping(unittest.TestCase):
    """
    The kdialog and zenity backends render markup; a device name that looks
    like HTML must not become HTML in the prompt. tkinter and the terminal
    render plain text and must NOT be escaped.
    """

    def setUp(self):
        from probolos import dialogs
        self.dialogs = dialogs

    def test_markup_safe_neutralises_tags(self):
        self.assertEqual(self.dialogs._markup_safe("<b>x</b>"),
                         "&lt;b&gt;x&lt;/b&gt;")

    def test_markup_safe_neutralises_a_link(self):
        raw = 'Kingston<a href="file:///etc/shadow">.</a>'
        self.assertNotIn("<a", self.dialogs._markup_safe(raw))

    def test_markup_safe_preserves_a_legitimate_name(self):
        """"A<B & C>D" is a real name shape and must survive, just inert."""
        out = self.dialogs._markup_safe("A<B & C>D")
        self.assertEqual(out, "A&lt;B &amp; C&gt;D")
        self.assertNotIn("<", out)

    def test_markup_safe_leaves_ordinary_text_untouched(self):
        self.assertEqual(self.dialogs._markup_safe("Kingston DataTraveler"),
                         "Kingston DataTraveler")


# =========================================================================
# test_power.py
#
# Tests for declared power consumption.
# =========================================================================

import struct
import unittest

from probolos import descriptors, rules
from tests.test_descriptors import endpoint_desc, iface_desc


def power_device_desc(bcd_usb=0x0200, num_configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 0x01, bcd_usb, 0, 0, 0, 64,
                       0x1234, 0x5678, 0x0100, 1, 2, 3, num_configs)


def power_config_desc(raw_power, attrs=0x80, num_ifaces=1, value=1, total=9):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, num_ifaces, value, 0,
                       attrs, raw_power)


class Dev:
    """Duck-typed device carrying only what the power rules read."""

    def __init__(self, blob, manufacturer="Generic", product="Thing",
                 speed="480"):
        self.descriptor_set = descriptors.parse(blob)
        self.manufacturer = manufacturer
        self.product = product
        self.speed = speed
        self.parse_error = None
        self.vendor_id = "1234"
        self.product_id = "5678"

    @property
    def interfaces(self):
        return self.descriptor_set.primary_interfaces()

    @property
    def interface_classes(self):
        return self.descriptor_set.interface_classes()

    def label(self):
        return f"{self.manufacturer} {self.product}"


def build_power_device(raw_power, ifaces, bcd_usb=0x0200, attrs=0x80):
    body = power_config_desc(raw_power, attrs=attrs, num_ifaces=len(ifaces))
    for n, (cls, sub, proto) in enumerate(ifaces):
        body += iface_desc(n, cls, subcls=sub, proto=proto) + endpoint_desc()
    return power_device_desc(bcd_usb) + body


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


class TestOrdinaryDevicesStaySilent(unittest.TestCase):
    """
    Field values from real hardware. A mouse at 100 mA and a webcam at the
    full 500 mA are completely normal and must never produce a finding.
    """

    def test_typical_mouse_is_silent(self):
        dev = Dev(build_power_device(50, [(0x03, 0x01, 0x02)]))          # 100 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_webcam_at_the_full_bus_limit_is_silent(self):
        """Exactly at the limit is legal. Only above it is a finding."""
        dev = Dev(build_power_device(250, [(0x0E, 0x01, 0x01)]))         # 500 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_ordinary_flash_drive_is_silent(self):
        dev = Dev(build_power_device(100, [(0x08, 0x06, 0x50)]))         # 200 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_self_powered_hub_drawing_a_little_is_silent(self):
        dev = Dev(build_power_device(1, [(0x09, 0x00, 0x00)], attrs=0xC0))   # 2 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_realtek_bluetooth_self_powered_at_500ma_is_silent(self):
        """
        Field data: 0bda:4853, an internal Realtek Bluetooth radio, declares
        the self-powered flag AND bMaxPower=250 (500 mA).

        A rule that flagged this shipped briefly and was removed. bMaxPower
        states the maximum a device MAY draw; a self-powered device is not
        forbidden from drawing bus power, and declaring the maximum regardless
        is common. This test is the tripwire against writing it again.
        """
        dev = Dev(build_power_device(250, [(0xE0, 0x01, 0x01), (0xE0, 0x01, 0x01)],
                        attrs=0xC0),
                  manufacturer="Realtek", product="Bluetooth Radio",
                  speed="12")
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])
        self.assertEqual(rules.evaluate(dev), [])

    def test_superspeed_device_is_not_flagged_by_the_old_bug(self):
        """
        bMaxPower=100 on USB 3 is 800 mA: legal. Under the old 2 mA assumption
        it read as 200 mA, and under a naive 8 mA rule with a USB 2 limit it
        would have looked like a violation. Neither happens now.
        """
        dev = Dev(build_power_device(100, [(0x08, 0x06, 0x50)], bcd_usb=0x0320))
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])


class TestPowerContradictions(unittest.TestCase):

    def ids(self, dev):
        return [f.rule_id for f in rules._power_findings(dev,
                                                         rules.DEFAULT_CONFIG)]

    def test_declaring_more_than_the_bus_allows(self):
        """Objective: the number comes from the specification, not a guess."""
        dev = Dev(build_power_device(255, [(0x03, 0x01, 0x01)]))         # 510 mA on USB 2
        self.assertIn("power-exceeds-bus-limit", self.ids(dev))

    def test_superspeed_limit_is_higher(self):
        dev = Dev(build_power_device(120, [(0x08, 0x06, 0x50)], bcd_usb=0x0300))  # 960 mA
        self.assertIn("power-exceeds-bus-limit", self.ids(dev))

    def test_storage_that_costs_nothing_to_run(self):
        dev = Dev(build_power_device(10, [(0x08, 0x06, 0x50)]))          # 20 mA
        self.assertIn("storage-declares-negligible-power", self.ids(dev))

    def test_power_findings_stay_low_severity(self):
        """
        Declarations are paperwork, not measurement. None of these may be
        CRITICAL, or a forged bMaxPower would carry more weight than observed
        behaviour.
        """
        dev = Dev(build_power_device(10, [(0x08, 0x06, 0x50)]))
        findings = rules._power_findings(dev, rules.DEFAULT_CONFIG)
        self.assertTrue(findings)
        for finding in findings:
            self.assertLess(finding.severity, rules.Severity.CRITICAL)

    def test_badusb_still_leads_on_behaviourally_grounded_rules(self):
        """
        A storage+keyboard device with an odd power claim must still be judged
        primarily on the interface combination, not on its paperwork.
        """
        dev = Dev(build_power_device(10, [(0x08, 0x06, 0x50), (0x03, 0x01, 0x01)]))
        findings = rules.evaluate(dev)
        self.assertEqual(findings[0].rule_id, "storage-with-keyboard")

    def test_rules_can_be_disabled(self):
        cfg = rules.RuleConfig(disabled={"power-exceeds-bus-limit"})
        dev = Dev(build_power_device(255, [(0x03, 0x01, 0x01)]))
        ids = [f.rule_id for f in rules._power_findings(dev, cfg)]
        self.assertNotIn("power-exceeds-bus-limit", ids)

    def test_device_without_descriptors_produces_nothing(self):
        class Bare:
            descriptor_set = None
        self.assertEqual(
            rules._power_findings(Bare(), rules.DEFAULT_CONFIG), [])


if __name__ == "__main__":
    unittest.main()
