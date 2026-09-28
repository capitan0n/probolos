"""
The rule engine: identity and consistency findings, crafted strings, rule
configuration, analyzer containment and the rendered report.

Covers probolos.rules, probolos.analyzers and probolos.report.
"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from probolos import (
    analyzers,
    daemon,
    descriptors,
    report,
    rules,
    sysfs,
    textsafe,
    usbclass,
)
from probolos.textsafe import NOTE_BIDI, NOTE_CONTROL, NOTE_INVISIBLE
from tests._support import (
    STORAGE_BLOB,
    config_desc,
    descriptor_blob,
    device_desc,
    endpoint_desc,
    iface_desc,
    make_device,
    make_widget_device,
    power_config_desc,
    power_device_desc,
    storage_config_desc,
    storage_device_desc,
    storage_iface_desc,
)


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


# ---------------------------------------------------------------------------
# 5. The BadUSB rule was evadable with two zero bytes
# ---------------------------------------------------------------------------

class _Iface:
    number = 0
    alternate = 0
    num_endpoints = 1

    def __init__(self, cls, subcls, proto):
        self.interface_class = cls
        self.interface_subclass = subcls
        self.interface_protocol = proto


class _Device:
    parse_error = None
    descriptor_set = None
    serial = None
    string_notes = ()
    string_note_fields = {}

    def __init__(self, ifaces, manufacturer="Acme", product="Widget",
                 speed="12"):
        self.interfaces = ifaces
        self.manufacturer = manufacturer
        self.product = product
        self.speed = speed

    @property
    def interface_classes(self):
        out = []
        for i in self.interfaces:
            if i.interface_class not in out:
                out.append(i.interface_class)
        return out

    def label(self):
        return f"{self.manufacturer} {self.product}"


STORAGE = _Iface(0x08, 0x06, 0x50)


BOOT_KEYBOARD = _Iface(0x03, 0x01, 0x01)


BOOT_MOUSE = _Iface(0x03, 0x01, 0x02)


UNDECLARED_HID = _Iface(0x03, 0x00, 0x00)


BLUETOOTH = _Iface(0xE0, 0x01, 0x01)


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


# --------------------------------------------------------------------------
# 2. Incomplete descriptor views
# --------------------------------------------------------------------------

class IncompleteDescriptorViewsAreCritical(unittest.TestCase):

    def _worst(self, dev, rule_id):
        findings = rules.evaluate(dev)
        self.assertIn(rule_id, {f.rule_id for f in findings})
        return rules.worst(findings)

    def test_unparseable_descriptors_need_the_typed_word(self):
        dev = make_widget_device(STORAGE_BLOB, parse_error="more than 4096 descriptors")
        self.assertEqual(self._worst(dev, "unreadable-descriptors"),
                         rules.Severity.CRITICAL)

    def test_missing_configurations_need_the_typed_word(self):
        dev = make_widget_device(storage_device_desc(num_configs=2) + storage_config_desc(18)
                          + storage_iface_desc())
        self.assertEqual(self._worst(dev, "configurations-missing"),
                         rules.Severity.CRITICAL)
        self.assertFalse(dev.inspection_safe)

    def test_a_truncated_chain_needs_the_typed_word(self):
        dev = make_widget_device(storage_device_desc() + storage_config_desc(27) + storage_iface_desc()
                          + b"\x09\x04\x00")
        self.assertEqual(self._worst(dev, "descriptor-chain-truncated"),
                         rules.Severity.CRITICAL)

    def test_a_complete_ordinary_device_stays_quiet(self):
        findings = rules.evaluate(make_widget_device(STORAGE_BLOB))
        ids = {f.rule_id for f in findings}
        self.assertFalse(ids & {"unreadable-descriptors",
                                "configurations-missing",
                                "descriptor-chain-truncated"})
        self.assertLess(rules.worst(findings), rules.Severity.WARNING)


# ---------------------------------------------------------------------------
# P4 -- the device does not get to draw on the decision screen
# ---------------------------------------------------------------------------

class ReportBoxHoldsItsShape(unittest.TestCase):

    EXPECTED = report.WIDTH + 2

    def _rows(self, block):
        return [line for line in block.splitlines()
                if line.startswith(("┌", "└", "├", "│"))]

    def _assert_square(self, block, label):
        for line in self._rows(block):
            self.assertEqual(
                textsafe.display_width(line), self.EXPECTED,
                f"{label}: row is {textsafe.display_width(line)} columns, "
                f"box is {self.EXPECTED}: {line[:80]!r}")

    def test_ordinary_device(self):
        device = make_device(manufacturer="PixArt", product="USB Optical Mouse")
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "ordinary")

    def test_long_ascii_name_cannot_push_the_border_off(self):
        device = make_device(product="Logitech USB Receiver " + "A" * 100)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "long ASCII")

    def test_wide_glyphs_are_measured_in_columns(self):
        device = make_device(manufacturer="羅技",
                             product="無線鍵盤滑鼠組" * 3)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "CJK")

    def test_device_cannot_forge_a_row_of_the_report(self):
        forged = ("Wireless Mouse" + " " * 44 + "│"
                  + " No inconsistencies found in what it claims"
                  + " " * 18 + "│")
        device = make_device(product=forged)
        block = report.render(device, rules.evaluate(device))
        self._assert_square(block, "forged border")

    def test_a_long_unbroken_token_inside_a_finding_is_split_not_dropped(self):
        name = "Flash" + "Z" * 90          # trips self-contradictory-identity
        device = make_device(
            descriptor_blob((0x03, 0x01, 0x01)), product=name)
        findings = rules.evaluate(device)
        self.assertTrue(any(f.rule_id == "self-contradictory-identity"
                            for f in findings))
        block = report.render(device, findings)
        self._assert_square(block, "device name inside a finding")
        self.assertIn("ZZZ", block, "the evidence must survive the wrapping")

    def test_combining_marks_do_not_shrink_the_box(self):
        device = make_device(product="Kingston" + "́" * 40)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "stacked marks")

    def test_split_width_loses_nothing(self):
        text = "abc" + "字" * 10 + "def"
        pieces = textsafe.split_width(text, 7)
        self.assertEqual("".join(pieces), text)
        for piece in pieces:
            self.assertLessEqual(textsafe.display_width(piece), 7)


# ---------------------------------------------------------------------------
# 1. A failed decisive analyzer must not read as a clean device
# ---------------------------------------------------------------------------

class CrashedRuleEngineIsNotACleanVerdict(unittest.TestCase):
    """
    The containment in analyzers.run() is correct and must stay; what was
    wrong was the SEVERITY it assigned. SemanticAnalyzer holds every CRITICAL
    identity rule, so its silence cannot be told apart from "this device is
    fine" -- and three separate consumers read the difference:

      * daemon._on_add admits a remembered device when worst() < CRITICAL
      * the terminal prompt drops to [y/N] instead of demanding the word
      * the desktop agent is offered the device as a clickable question

    so a NOTICE there was a device-triggerable fail-open.
    """

    class Exploding(analyzers.SemanticAnalyzer):
        def analyze(self, ctx):
            raise RuntimeError("descriptor walk blew up")

    class ExplodingCosmetic(analyzers.LedgerAnalyzer):
        def analyze(self, ctx):
            raise RuntimeError("history unreadable")

    def test_a_decisive_analyzer_failing_is_itself_critical(self):
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding()])
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL,
                         "a crashed rule engine must not read as a clean "
                         "device; it is what produces the verdict")

    def test_the_trust_shortcut_no_longer_applies_to_it(self):
        """The precise condition daemon._on_add tests before admitting."""
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding()])
        self.assertFalse(rules.worst(findings) < rules.Severity.CRITICAL,
                         "a remembered device must not be waved through on "
                         "the strength of a check that never ran")

    def test_a_cosmetic_analyzer_failing_stays_a_notice(self):
        """
        The other half of the fix. Escalating EVERY failure would make a
        broken history file block a keyboard, which is the lockout the whole
        project is built to avoid.
        """
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.ExplodingCosmetic()])
        self.assertEqual(rules.worst(findings), rules.Severity.NOTICE)

    def test_the_run_still_continues_past_a_crash(self):
        """Containment intact: the other analyzers still ran."""
        class Quiet(analyzers.Analyzer):
            id = "quiet"
            def analyze(self, ctx):
                return [rules.Finding("saw-it", rules.Severity.INFO, "t", "e")]

        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding(), Quiet()])
        self.assertIn("saw-it", [f.rule_id for f in findings])

    def test_every_verdict_bearing_analyzer_is_marked_decisive(self):
        """
        Guards the fix against drift. A new analyzer that carries CRITICAL
        rules and forgets `decisive` reintroduces the hole silently, so the
        list is asserted rather than trusted.
        """
        for analyzer in (analyzers.SemanticAnalyzer(),
                         analyzers.BehaviourAnalyzer(),
                         analyzers.PayloadAnalyzer(),
                         analyzers.StorageAnalyzer()):
            self.assertTrue(analyzer.decisive,
                            f"{analyzer.id} produces findings the decision "
                            f"rests on and must be marked decisive")


class RuleConfigFailsAsAConfigError(unittest.TestCase):

    def setUp(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "rules.yaml"

    def _load(self, text):
        self.path.write_text(text)
        return rules.load_config(self.path)

    def test_a_file_that_is_not_a_mapping_is_a_value_error(self):
        for text in ("- one\n- two\n", "just a string\n", "42\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_a_severity_block_of_the_wrong_shape_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self._load("severity:\n  - not-a-mapping\n")

    def test_benign_groups_must_be_lists_of_class_codes(self):
        for text in ("benign_groups: 3\n",
                     "benign_groups:\n  - 3\n",
                     "benign_groups:\n  - [3, 'ff']\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_disabled_must_be_a_list(self):
        with self.assertRaises(ValueError):
            self._load("disabled: keyboard-at-high-speed\n")

    def test_a_yaml_syntax_error_is_a_value_error(self):
        # yaml.YAMLError is not a ValueError; unconverted, it escaped the
        # entry point's handler as a traceback.
        for text in ("severity: [unclosed\n", "disabled:\n  - a\n - b\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_a_well_formed_file_still_loads(self):
        config = self._load(
            "disabled:\n"
            "  - keyboard-at-high-speed\n"
            "severity:\n"
            "  multiple-distinct-functions: warning\n"
            "benign_groups:\n"
            "  - [3, 255]\n")
        self.assertFalse(config.enabled("keyboard-at-high-speed"))
        self.assertEqual(config.severity("multiple-distinct-functions",
                                         rules.Severity.NOTICE),
                         rules.Severity.WARNING)
        self.assertEqual(config.extra_benign_groups, [{3, 255}])

    def test_the_entry_point_reports_it_as_a_config_error(self):
        """
        The consequence, not just the exception type: __main__ catches
        RuntimeError, ValueError and OSError around load_config, so anything
        else escaped as a traceback and the gate never closed.
        """
        from unittest import mock

        from probolos import __main__ as entry
        self.path.write_text("- not a mapping\n")
        with mock.patch.object(entry, "require_usb"), \
             mock.patch.object(entry.daemon, "serve") as serve:
            with self.assertRaises(SystemExit) as caught:
                entry.main(["--dry-run", "--rules", str(self.path)])
        self.assertIn("rule config", str(caught.exception))
        serve.assert_not_called()


class TestAnalyzerContainment(unittest.TestCase):

    class Exploding(analyzers.Analyzer):
        id = "exploding"

        def analyze(self, ctx):
            raise RuntimeError("heuristic went wrong")

    def test_a_broken_analyzer_cannot_stop_the_others(self):
        """
        A crash in a speculative check must never prevent somebody from
        admitting their keyboard.
        """
        findings = analyzers.run(
            analyzers.Context(device=None),
            analyzers=[self.Exploding()])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].rule_id.startswith("analyzer-failed"))

    def test_failure_is_visible_rather_than_silent(self):
        findings = analyzers.run(analyzers.Context(device=None),
                                 analyzers=[self.Exploding()])
        self.assertNotEqual(rules.worst(findings), rules.Severity.INFO)

    def test_analyzers_needing_an_observation_are_skipped_without_one(self):
        findings = analyzers.run(
            analyzers.Context(device=None, observation=None),
            analyzers=[analyzers.BehaviourAnalyzer()])
        self.assertEqual(findings, [])

    def test_findings_come_back_worst_first(self):
        class Noisy(analyzers.Analyzer):
            id = "noisy"

            def analyze(self, ctx):
                return [
                    rules.Finding("a", rules.Severity.NOTICE, "n", ""),
                    rules.Finding("b", rules.Severity.CRITICAL, "c", ""),
                    rules.Finding("c", rules.Severity.WARNING, "w", ""),
                ]

        findings = analyzers.run(analyzers.Context(device=None),
                                 analyzers=[Noisy()])
        self.assertEqual([f.severity for f in findings],
                         [rules.Severity.CRITICAL, rules.Severity.WARNING,
                          rules.Severity.NOTICE])


class UndeclaredHidIsNotInnocence(unittest.TestCase):
    """
    is_keyboard() fires only on subclass 0x01 / protocol 0x01. A HID interface
    declaring 0x00 / 0x00 is legal, common, and still a working keyboard under
    Linux -- usbhid reads the REPORT descriptor, which is not in the sysfs blob
    and cannot be fetched without talking to a device we are holding precisely
    because we do not trust it. So the whole BadUSB rule was evadable by
    omitting the boot protocol.
    """

    def _ids(self, dev):
        return {f.rule_id for f in rules.evaluate(dev)}

    # -- the classification primitives ------------------------------------

    def test_declared_keyboard_is_a_keyboard(self):
        self.assertTrue(usbclass.is_keyboard(0x03, 0x01, 0x01))
        self.assertFalse(usbclass.is_undeclared_hid(0x03, 0x01, 0x01))

    def test_declared_mouse_has_answered_the_question(self):
        self.assertFalse(usbclass.is_undeclared_hid(0x03, 0x01, 0x02))
        self.assertFalse(usbclass.may_type(0x03, 0x01, 0x02))

    def test_hid_without_a_boot_protocol_might_type(self):
        self.assertFalse(usbclass.is_keyboard(0x03, 0x00, 0x00))
        self.assertTrue(usbclass.is_undeclared_hid(0x03, 0x00, 0x00))
        self.assertTrue(usbclass.may_type(0x03, 0x00, 0x00))

    def test_non_hid_never_types(self):
        self.assertFalse(usbclass.may_type(0x08, 0x06, 0x50))

    # -- the regression ----------------------------------------------------

    def test_declared_badusb_is_still_critical(self):
        dev = _Device([STORAGE, BOOT_KEYBOARD])
        self.assertIn("storage-with-keyboard", self._ids(dev))
        self.assertEqual(rules.worst(rules.evaluate(dev)),
                         rules.Severity.CRITICAL)

    def test_evasive_badusb_is_now_critical_too(self):
        dev = _Device([STORAGE, UNDECLARED_HID])
        self.assertIn("storage-with-undeclared-hid", self._ids(dev))
        self.assertEqual(rules.worst(rules.evaluate(dev)),
                         rules.Severity.CRITICAL)

    def test_network_plus_undeclared_hid_is_a_warning_not_a_verdict(self):
        """
        Graded lower on purpose: some radios expose a vendor HID channel, and
        what the interface does cannot be read from the descriptors.
        """
        dev = _Device([BLUETOOTH, UNDECLARED_HID])
        found = rules.evaluate(dev)
        self.assertIn("network-with-undeclared-hid",
                      {f.rule_id for f in found})
        self.assertEqual(rules.worst(found), rules.Severity.WARNING)

    def test_disguised_injector_without_a_boot_protocol_is_caught(self):
        dev = _Device([UNDECLARED_HID], manufacturer="Kingston",
                      product="DataTraveler")
        self.assertIn("self-contradictory-identity", self._ids(dev))

    # -- and the design principle it must not break ------------------------

    def test_an_ordinary_mouse_stays_silent(self):
        self.assertEqual(self._ids(_Device([BOOT_MOUSE], "Logitech", "M185")),
                         set())

    def test_a_subclass_zero_mouse_stays_silent(self):
        """The common shape. Flagging it alone would train people to ignore us."""
        self.assertEqual(
            self._ids(_Device([UNDECLARED_HID], "Logitech", "G502")), set())

    def test_a_headset_with_hid_buttons_stays_silent(self):
        dev = _Device([_Iface(0x01, 0x01, 0x00), _Iface(0x01, 0x02, 0x00),
                       UNDECLARED_HID], "Sennheiser", "PC 8")
        self.assertEqual(self._ids(dev), set())

    def test_a_plain_flash_drive_stays_silent(self):
        self.assertEqual(
            self._ids(_Device([STORAGE], "Kingston", "DataTraveler")), set())


class DescriptorCoverage(unittest.TestCase):
    def device(self, truncated=False):
        # Build explicitly: first config storage, second config HID.
        raw = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x200, 0, 0, 0, 64,
                          0x1234, 0x5678, 0x100, 0, 0, 0, 2)
        for value, cls in ((1, 8), (2, 3)):
            raw += struct.pack("<BBHBBBBB", 9, 2, 18, 1, value, 0, 0x80, 50)
            raw += struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, cls, 1, 1, 0)
        ds = descriptors.parse(raw)
        if truncated:
            ds.truncated = "missing tail"
        return sysfs.UsbDevice(Path("unused"), "1-1", "1234", "5678", None,
                              None, None, 1, 2, "12", 0, 0, ds)

    def test_later_configuration_cannot_hide_input_from_storage_guard(self):
        dev = self.device()
        self.assertIn("input", dev.kinds)
        self.assertIn("storage", dev.kinds)
        self.assertEqual(rules.worst(rules.evaluate(dev)), rules.Severity.CRITICAL)

    def test_truncated_descriptors_disable_early_activation(self):
        self.assertFalse(self.device(truncated=True).inspection_safe)

    def test_removed_baseline_port_is_not_ignored_forever(self):
        engine = daemon.Probolos()
        engine.known.add("1-1")
        engine._on_remove("/sys/bus/usb/devices/1-1")
        self.assertNotIn("1-1", engine.known)


if __name__ == "__main__":
    unittest.main()
