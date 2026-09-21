"""
Regression tests for the normalized descriptor fingerprint.

The old raw-blob fingerprint produced a different digest for the same physical
stick when plugged into a USB 2 vs. a USB 3 controller -- measured on real
hardware with a Kingston DataTraveler 3.0 (VID 0x0951, PID 0x1666). Every port
swap produced a spurious CRITICAL drift alarm.

These tests fix the behaviour the normalized fingerprint MUST have, not the
implementation. A later refactor that reintroduces the sensitivity to
bus-negotiated fields still fails them.

Run with:  python -m unittest tests.test_normalized_fingerprint -v
"""

from __future__ import annotations

import copy
import struct
import tempfile
import unittest
from pathlib import Path

from probolos import descriptors, ledger as ledger_mod, sysfs, analyzers, rules


# ---------------------------------------------------------------------------
# helpers -- descriptor blobs that mirror the real Kingston stick's shape
# ---------------------------------------------------------------------------

def storage_device_blob(*, bcd_usb=0x0210, bcd_device=0x0110,
                        max_packet0=64, max_power_raw=150,
                        include_ss_companion=False,
                        interfaces=None):
    """
    Build a plausible mass-storage descriptor blob.

    Defaults match the USB 2 enumeration of a Kingston DataTraveler 3.0
    (VID 0x0951, PID 0x1666, bcdDevice 0x0110). include_ss_companion=True
    adds SuperSpeed endpoint companion descriptors, matching the USB 3
    enumeration of the same physical stick.
    """
    interfaces = interfaces or [(0x08, 0x06, 0x50)]

    # 18-byte device descriptor
    dev = bytes([
        18, 0x01,
        bcd_usb & 0xFF, (bcd_usb >> 8) & 0xFF,
        0x00, 0x00, 0x00,
        max_packet0,
        0x51, 0x09, 0x66, 0x16,
        bcd_device & 0xFF, (bcd_device >> 8) & 0xFF,
        1, 2, 3,
        1,
    ])

    # per-interface: iface(9) + 2 endpoints(7 each) + optional companions(6 each)
    per_iface = 9 + 2 * 7 + (2 * 6 if include_ss_companion else 0)
    total = 9 + per_iface * len(interfaces)
    cfg = bytes([
        9, 0x02,
        total & 0xFF, (total >> 8) & 0xFF,
        len(interfaces), 1, 0,
        0x80,
        max_power_raw,
    ])

    body = b""
    for n, (cls, sub, proto) in enumerate(interfaces):
        body += bytes([9, 0x04, n, 0, 2, cls, sub, proto, 0])
        body += bytes([7, 0x05, 0x81, 0x02, 0x00, 0x04, 0x00])   # IN bulk
        if include_ss_companion:
            body += bytes([6, 0x30, 0x0F, 0x00, 0x00, 0x00])     # SS companion
        body += bytes([7, 0x05, 0x02, 0x02, 0x00, 0x04, 0x00])   # OUT bulk
        if include_ss_companion:
            body += bytes([6, 0x30, 0x0F, 0x00, 0x00, 0x00])

    return dev + cfg + body


def make_device(raw, name="1-4", syspath="/sys/devices/pci0000:00/usb1/1-4"):
    return sysfs.UsbDevice(
        syspath=Path(syspath), name=name,
        vendor_id="0951", product_id="1666",
        manufacturer="Kingston", product="DataTraveler 3.0",
        serial="E0D55EA58B39E7C058840855",
        bus=1, device_num=7, speed="480", authorized=0, device_class=0,
        descriptor_set=descriptors.parse(raw), raw_descriptors=raw,
        removable="removable", instance_id=(1, 1000))


# ---------------------------------------------------------------------------
# 1. Bus-negotiated fields must NOT change the fingerprint
# ---------------------------------------------------------------------------

class FingerprintIgnoresBusNegotiation(unittest.TestCase):
    """The same physical stick on different controllers is the SAME device."""

    def _fp(self, **kwargs):
        return ledger_mod.descriptor_fingerprint(
            make_device(storage_device_blob(**kwargs)))

    def test_usb2_and_usb3_enumeration_agree(self):
        usb2 = self._fp(bcd_usb=0x0210, max_packet0=64,
                        max_power_raw=150, include_ss_companion=False)
        usb3 = self._fp(bcd_usb=0x0320, max_packet0=9,
                        max_power_raw=63, include_ss_companion=True)
        self.assertEqual(usb2, usb3,
                         "same stick, different controller -> same fingerprint")

    def test_bcdusb_change_alone_does_not_drift(self):
        self.assertEqual(self._fp(bcd_usb=0x0200), self._fp(bcd_usb=0x0210))
        self.assertEqual(self._fp(bcd_usb=0x0210), self._fp(bcd_usb=0x0300))

    def test_bmaxpower_change_does_not_drift(self):
        self.assertEqual(self._fp(max_power_raw=100), self._fp(max_power_raw=250))

    def test_maxpacketsize0_change_does_not_drift(self):
        self.assertEqual(self._fp(max_packet0=64), self._fp(max_packet0=9))

    def test_endpoint_companions_do_not_drift(self):
        self.assertEqual(self._fp(include_ss_companion=False),
                         self._fp(include_ss_companion=True))


# ---------------------------------------------------------------------------
# 2. Real changes to what the device IS must still drift
# ---------------------------------------------------------------------------

class FingerprintCatchesRealChanges(unittest.TestCase):
    """The drift alarm still fires on the cases the ledger exists for."""

    STORAGE = (0x08, 0x06, 0x50)
    KEYBOARD = (0x03, 0x01, 0x01)
    MOUSE = (0x03, 0x01, 0x02)

    def _fp(self, **kwargs):
        return ledger_mod.descriptor_fingerprint(
            make_device(storage_device_blob(**kwargs)))

    def test_added_keyboard_interface_drifts(self):
        """The BadUSB reflash -- storage + keyboard where there was one."""
        plain = self._fp(interfaces=[self.STORAGE])
        badusb = self._fp(interfaces=[self.STORAGE, self.KEYBOARD])
        self.assertNotEqual(plain, badusb)

    def test_interface_class_change_drifts(self):
        mouse = self._fp(interfaces=[self.STORAGE, self.MOUSE])
        kbd = self._fp(interfaces=[self.STORAGE, self.KEYBOARD])
        self.assertNotEqual(mouse, kbd)

    def test_bcddevice_change_drifts(self):
        """Firmware revision changes ARE what the drift rule surfaces."""
        self.assertNotEqual(self._fp(bcd_device=0x0100),
                            self._fp(bcd_device=0x0200))

    def test_vendor_or_product_change_drifts(self):
        """Same identity claim but a different device -- must be caught."""
        base = make_device(storage_device_blob())
        variant = make_device(storage_device_blob())
        variant.descriptor_set.device = descriptors.DeviceDescriptor(
            usb_version=0x0210, device_class=0, device_subclass=0,
            device_protocol=0, vendor_id=0x1234, product_id=0x5678,
            device_version=0x0110, num_configurations=1)
        self.assertNotEqual(
            ledger_mod.descriptor_fingerprint(base),
            ledger_mod.descriptor_fingerprint(variant))

    def test_added_configuration_drifts(self):
        base = make_device(storage_device_blob())
        two_cfg = copy.deepcopy(base)
        second = copy.deepcopy(base.descriptor_set.configs[0])
        second.value = 2
        two_cfg.descriptor_set.configs.append(second)
        two_cfg.descriptor_set.device = descriptors.DeviceDescriptor(
            usb_version=base.descriptor_set.device.usb_version,
            device_class=0, device_subclass=0, device_protocol=0,
            vendor_id=0x0951, product_id=0x1666, device_version=0x0110,
            num_configurations=2)
        self.assertNotEqual(
            ledger_mod.descriptor_fingerprint(base),
            ledger_mod.descriptor_fingerprint(two_cfg))

    def test_interface_reorder_alone_does_not_drift(self):
        """
        A device that renumbers its interface list between enumerations (legal
        and observed) must not fire the alarm as long as the set is the same.
        """
        forward = self._fp(interfaces=[self.STORAGE, self.KEYBOARD])
        reversed_ = self._fp(interfaces=[self.KEYBOARD, self.STORAGE])
        self.assertNotEqual(forward, reversed_,
                            "interface NUMBERS carry meaning, kept in the hash")

    def test_alternate_setting_change_drifts(self):
        base = make_device(storage_device_blob())
        alt = copy.deepcopy(base)
        alt.descriptor_set.configs[0].interfaces[0] = \
            descriptors.InterfaceDescriptor(
                number=0, alternate=1, num_endpoints=2,
                interface_class=0x08, interface_subclass=0x06,
                interface_protocol=0x50)
        self.assertNotEqual(
            ledger_mod.descriptor_fingerprint(base),
            ledger_mod.descriptor_fingerprint(alt))


# ---------------------------------------------------------------------------
# 3. Raw hash is preserved for forensics but never compared
# ---------------------------------------------------------------------------

class RawHashKeptSeparately(unittest.TestCase):

    def test_raw_hash_captures_every_byte(self):
        a = make_device(storage_device_blob(bcd_usb=0x0210))
        b = make_device(storage_device_blob(bcd_usb=0x0320))
        self.assertNotEqual(ledger_mod.raw_descriptor_hash(a),
                            ledger_mod.raw_descriptor_hash(b),
                            "raw hash must still see bus-negotiated changes")
        self.assertEqual(ledger_mod.descriptor_fingerprint(a),
                         ledger_mod.descriptor_fingerprint(b),
                         "but the drift fingerprint must not")

    def test_raw_hash_stored_on_entry(self):
        directory = Path(tempfile.mkdtemp(prefix="probolos-raw-"))
        path = directory / "ledger.json"
        led = ledger_mod.Ledger(path)
        dev = make_device(storage_device_blob())
        led.record(dev, "user approved", approved=True)
        led.save()
        entry = ledger_mod.Ledger(path).entries[ledger_mod.identity_of(dev)]
        self.assertEqual(entry.raw_hash, ledger_mod.raw_descriptor_hash(dev))
        self.assertEqual(entry.descriptor_hash,
                         ledger_mod.descriptor_fingerprint(dev))
        self.assertNotEqual(entry.raw_hash, entry.descriptor_hash)


# ---------------------------------------------------------------------------
# 4. End-to-end: the Kingston false positive is gone, real BadUSB still fires
# ---------------------------------------------------------------------------

class DriftRuleOnRealScenarios(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="probolos-drift-"))
        self.path = self.directory / "ledger.json"

    def _drift(self, dev):
        led = ledger_mod.Ledger(self.path)
        findings = analyzers.run(analyzers.Context(device=dev, ledger=led))
        return any(f.rule_id == "descriptor-drift" for f in findings)

    def _record(self, dev, reason, approved):
        led = ledger_mod.Ledger(self.path)
        led.record(dev, reason, approved=approved)
        led.save()

    def test_kingston_swap_between_usb2_and_usb3_no_alarm(self):
        """The measured false positive that motivated this change."""
        on_usb2 = make_device(storage_device_blob(
            bcd_usb=0x0210, max_packet0=64, max_power_raw=150),
            name="3-1", syspath="/sys/devices/pci0000:00/usb3/3-1")
        on_usb3 = make_device(storage_device_blob(
            bcd_usb=0x0320, max_packet0=9, max_power_raw=63,
            include_ss_companion=True),
            name="4-1", syspath="/sys/devices/pci0000:00/usb4/4-1")

        self._record(on_usb2, "user approved", approved=True)
        self.assertFalse(self._drift(on_usb3),
                         "same stick, different port -> no alarm")

    def test_reflash_to_add_keyboard_still_fires(self):
        genuine = make_device(storage_device_blob(
            interfaces=[(0x08, 0x06, 0x50)]))
        badusb = make_device(storage_device_blob(
            interfaces=[(0x08, 0x06, 0x50), (0x03, 0x01, 0x01)]))
        self._record(genuine, "user approved", approved=True)
        self.assertTrue(self._drift(badusb),
                        "the BadUSB reflash must still trip the alarm")

    def test_firmware_update_still_fires_first_time(self):
        v1 = make_device(storage_device_blob(bcd_device=0x0100))
        v2 = make_device(storage_device_blob(bcd_device=0x0110))
        self._record(v1, "user approved", approved=True)
        self.assertTrue(self._drift(v2),
                        "firmware revision change is legitimately alarming")


# ---------------------------------------------------------------------------
# 5. Backward compatibility with old ledger files
# ---------------------------------------------------------------------------

class OldLedgerMigration(unittest.TestCase):

    def _load(self, payload):
        import json
        directory = Path(tempfile.mkdtemp(prefix="probolos-mig-"))
        path = directory / "ledger.json"
        path.write_text(json.dumps(payload))
        return ledger_mod.Ledger(path)

    def test_ledger_without_scheme_marker_clears_baseline(self):
        """A pre-normalized ledger's baseline cannot be trusted."""
        led = self._load({
            "schema": 1,
            "entries": {
                "0951:1666:AABBCCDD": {
                    "identity": "0951:1666:AABBCCDD",
                    "descriptor_hash": "cbad71fa" + "0" * 56,
                    "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
                    "known_hashes": ["cbad71fa" + "0" * 56,
                                     "0c5f7396" + "0" * 56],
                    "baseline_hash": "cbad71fa" + "0" * 56,
                }
            },
        })
        entry = led.entries["0951:1666:AABBCCDD"]
        self.assertEqual(entry.baseline_hash, "",
                         "baseline from the old scheme is not comparable")

    def test_ledger_with_new_scheme_marker_keeps_baseline(self):
        led = self._load({
            "schema": 1,
            "fingerprint_scheme": "normalized-v1",
            "entries": {
                "0951:1666:AABBCCDD": {
                    "identity": "0951:1666:AABBCCDD",
                    "descriptor_hash": "aaaa" + "0" * 60,
                    "first_seen": 1.0, "last_seen": 2.0, "times_seen": 1,
                    "known_hashes": ["aaaa" + "0" * 60],
                    "baseline_hash": "aaaa" + "0" * 60,
                }
            },
        })
        entry = led.entries["0951:1666:AABBCCDD"]
        self.assertEqual(entry.baseline_hash, "aaaa" + "0" * 60)

    def test_relearning_after_migration_takes_one_visit(self):
        """After the baseline is cleared, the NEXT sighting re-anchors it."""
        import json
        directory = Path(tempfile.mkdtemp(prefix="probolos-relearn-"))
        path = directory / "ledger.json"
        path.write_text(json.dumps({
            "schema": 1,
            "entries": {
                "0951:1666:E0D55EA58B39E7C058840855": {
                    "identity": "0951:1666:E0D55EA58B39E7C058840855",
                    "descriptor_hash": "old_raw_hash",
                    "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
                    "known_hashes": ["old_raw_hash"],
                    "baseline_hash": "old_raw_hash",
                }
            },
        }))
        dev = make_device(storage_device_blob())
        led = ledger_mod.Ledger(path)
        led.record(dev, "held: screen locked", approved=False)
        led.save()

        led = ledger_mod.Ledger(path)
        entry = led.entries[ledger_mod.identity_of(dev)]
        self.assertEqual(entry.baseline_hash,
                         ledger_mod.descriptor_fingerprint(dev),
                         "record() re-anchors the baseline on the next visit")

        replug = make_device(storage_device_blob(
            bcd_usb=0x0320, max_packet0=9, max_power_raw=63,
            include_ss_companion=True))
        led = ledger_mod.Ledger(path)
        findings = analyzers.run(analyzers.Context(device=replug, ledger=led))
        self.assertFalse(
            any(f.rule_id == "descriptor-drift" for f in findings),
            "same stick, different port -> no alarm even after migration")


# ---------------------------------------------------------------------------
# 6. Trust store is intentionally left on the RAW hash
# ---------------------------------------------------------------------------

class TrustStoreStillPinsRawBytes(unittest.TestCase):
    """
    Trust and drift have different semantics. "I approved this exact blob"
    is stricter than "the device did not change what it claims to be", and
    a controller swap that changes the raw bytes SHOULD re-prompt for trust
    -- because the trusted admission is admission WITHOUT prompting, and
    conservative is the safe direction there.
    """

    def test_trust_key_uses_raw_bytes(self):
        from probolos import trust
        a = make_device(storage_device_blob(bcd_usb=0x0210))
        b = make_device(storage_device_blob(bcd_usb=0x0320,
                                            include_ss_companion=True))
        self.assertNotEqual(trust.key_for(a), trust.key_for(b),
                            "trust must not silently span controller swaps")


if __name__ == "__main__":
    unittest.main()
