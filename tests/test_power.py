"""
Tests for declared power consumption.

The unit tests come first because they guard a bug that was actually shipped:
bMaxPower was scaled by 2 mA unconditionally, which under-reports every USB 3
device by a factor of four. Any rule written on top of that number would have
been quietly wrong, so the multiplier is pinned here before anything judges it.
"""

import struct
import unittest

from probolos import descriptors, rules
from tests.test_descriptors import endpoint_desc, iface_desc


def device_desc(bcd_usb=0x0200, num_configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 0x01, bcd_usb, 0, 0, 0, 64,
                       0x1234, 0x5678, 0x0100, 1, 2, 3, num_configs)


def config_desc(raw_power, attrs=0x80, num_ifaces=1, value=1, total=9):
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


def build(raw_power, ifaces, bcd_usb=0x0200, attrs=0x80):
    body = config_desc(raw_power, attrs=attrs, num_ifaces=len(ifaces))
    for n, (cls, sub, proto) in enumerate(ifaces):
        body += iface_desc(n, cls, subcls=sub, proto=proto) + endpoint_desc()
    return device_desc(bcd_usb) + body


class TestPowerUnits(unittest.TestCase):
    """The shipped bug. One byte, two meanings, depending on bcdUSB."""

    def test_usb2_uses_2ma_units(self):
        ds = descriptors.parse(device_desc(0x0200) + config_desc(50))
        self.assertEqual(ds.configs[0].max_power_ma, 100)
        self.assertEqual(ds.configs[0].power_unit_ma, 2)

    def test_superspeed_uses_8ma_units(self):
        """The same byte means four times as much on USB 3.x."""
        ds = descriptors.parse(device_desc(0x0300) + config_desc(50))
        self.assertEqual(ds.configs[0].max_power_ma, 400)
        self.assertEqual(ds.configs[0].power_unit_ma, 8)

    def test_usb31_and_32_also_use_8ma_units(self):
        for bcd in (0x0310, 0x0320):
            ds = descriptors.parse(device_desc(bcd) + config_desc(50))
            self.assertEqual(ds.configs[0].max_power_ma, 400)

    def test_raw_byte_is_preserved_for_audit(self):
        ds = descriptors.parse(device_desc(0x0300) + config_desc(50))
        self.assertEqual(ds.configs[0].max_power_raw, 50)

    def test_bus_limits_follow_the_specification(self):
        self.assertEqual(descriptors.bus_power_limit_ma(0x0200), 500)
        self.assertEqual(descriptors.bus_power_limit_ma(0x0300), 900)

    def test_attribute_bits_are_decoded(self):
        bus = descriptors.parse(device_desc() + config_desc(50, attrs=0x80))
        self.assertFalse(bus.configs[0].self_powered)

        selfp = descriptors.parse(device_desc() + config_desc(0, attrs=0xC0))
        self.assertTrue(selfp.configs[0].self_powered)

        wake = descriptors.parse(device_desc() + config_desc(50, attrs=0xA0))
        self.assertTrue(wake.configs[0].remote_wakeup)


class TestOrdinaryDevicesStaySilent(unittest.TestCase):
    """
    Field values from real hardware. A mouse at 100 mA and a webcam at the
    full 500 mA are completely normal and must never produce a finding.
    """

    def test_typical_mouse_is_silent(self):
        dev = Dev(build(50, [(0x03, 0x01, 0x02)]))          # 100 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_webcam_at_the_full_bus_limit_is_silent(self):
        """Exactly at the limit is legal. Only above it is a finding."""
        dev = Dev(build(250, [(0x0E, 0x01, 0x01)]))         # 500 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_ordinary_flash_drive_is_silent(self):
        dev = Dev(build(100, [(0x08, 0x06, 0x50)]))         # 200 mA
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])

    def test_self_powered_hub_drawing_a_little_is_silent(self):
        dev = Dev(build(1, [(0x09, 0x00, 0x00)], attrs=0xC0))   # 2 mA
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
        dev = Dev(build(250, [(0xE0, 0x01, 0x01), (0xE0, 0x01, 0x01)],
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
        dev = Dev(build(100, [(0x08, 0x06, 0x50)], bcd_usb=0x0320))
        self.assertEqual(rules._power_findings(dev, rules.DEFAULT_CONFIG), [])


class TestPowerContradictions(unittest.TestCase):

    def ids(self, dev):
        return [f.rule_id for f in rules._power_findings(dev,
                                                         rules.DEFAULT_CONFIG)]

    def test_declaring_more_than_the_bus_allows(self):
        """Objective: the number comes from the specification, not a guess."""
        dev = Dev(build(255, [(0x03, 0x01, 0x01)]))         # 510 mA on USB 2
        self.assertIn("power-exceeds-bus-limit", self.ids(dev))

    def test_superspeed_limit_is_higher(self):
        dev = Dev(build(120, [(0x08, 0x06, 0x50)], bcd_usb=0x0300))  # 960 mA
        self.assertIn("power-exceeds-bus-limit", self.ids(dev))

    def test_storage_that_costs_nothing_to_run(self):
        dev = Dev(build(10, [(0x08, 0x06, 0x50)]))          # 20 mA
        self.assertIn("storage-declares-negligible-power", self.ids(dev))

    def test_power_findings_stay_low_severity(self):
        """
        Declarations are paperwork, not measurement. None of these may be
        CRITICAL, or a forged bMaxPower would carry more weight than observed
        behaviour.
        """
        dev = Dev(build(10, [(0x08, 0x06, 0x50)]))
        findings = rules._power_findings(dev, rules.DEFAULT_CONFIG)
        self.assertTrue(findings)
        for finding in findings:
            self.assertLess(finding.severity, rules.Severity.CRITICAL)

    def test_badusb_still_leads_on_behaviourally_grounded_rules(self):
        """
        A storage+keyboard device with an odd power claim must still be judged
        primarily on the interface combination, not on its paperwork.
        """
        dev = Dev(build(10, [(0x08, 0x06, 0x50), (0x03, 0x01, 0x01)]))
        findings = rules.evaluate(dev)
        self.assertEqual(findings[0].rule_id, "storage-with-keyboard")

    def test_rules_can_be_disabled(self):
        cfg = rules.RuleConfig(disabled={"power-exceeds-bus-limit"})
        dev = Dev(build(255, [(0x03, 0x01, 0x01)]))
        ids = [f.rule_id for f in rules._power_findings(dev, cfg)]
        self.assertNotIn("power-exceeds-bus-limit", ids)

    def test_device_without_descriptors_produces_nothing(self):
        class Bare:
            descriptor_set = None
        self.assertEqual(
            rules._power_findings(Bare(), rules.DEFAULT_CONFIG), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
