"""
The ledger: history across visits, malformed state files, and the
normalized descriptor fingerprint that drift is measured against.

The fingerprint tests belong beside the ledger tests because the
fingerprint is only meaningful as the thing the ledger stores and the
drift rule compares -- tested apart, both halves can pass while
disagreeing about what a device is.

Merged from: test_ledger.py, test_ledger_malformed.py, test_normalized_fingerprint.py
"""
from __future__ import annotations

# =========================================================================
# test_ledger.py
#
# Tests for identity across time.
# =========================================================================

import json
import tempfile
import unittest
from pathlib import Path

from probolos import analyzers, ledger as ledger_mod, rules


class Dev:
    def __init__(self, vid="0781", pid="5567", serial="ABC123",
                 raw=b"\x12\x01original", name="1-4"):
        self.vendor_id = vid
        self.product_id = pid
        self.serial = serial
        self.raw_descriptors = raw
        self.name = name


class TestLedgerStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_sighting_is_recorded(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(), "user approved")
        self.assertIsNone(store.save())

        reloaded = ledger_mod.Ledger(self.path)
        entry = reloaded.lookup(Dev())
        self.assertIsNotNone(entry)
        self.assertEqual(entry.times_seen, 1)

    def test_repeat_sighting_increments_rather_than_duplicating(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(), "user approved")
        store.record(Dev(), "user approved")
        self.assertEqual(len(store.entries), 1)
        self.assertEqual(store.lookup(Dev()).times_seen, 2)

    def test_changed_descriptors_are_remembered_as_history(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(raw=b"first"), "user approved")
        store.record(Dev(raw=b"second"), "user approved")
        entry = store.lookup(Dev())
        self.assertEqual(len(entry.known_hashes), 2)

    def test_corrupt_ledger_does_not_stop_the_gate(self):
        """
        Losing history is an inconvenience. Refusing to admit a keyboard
        because a JSON file is malformed is a lockout.
        """
        self.path.write_text("{ not json")
        store = ledger_mod.Ledger(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.entries, {})

    def test_unknown_schema_is_refused_rather_than_misread(self):
        self.path.write_text(json.dumps({"schema": 999, "entries": {}}))
        store = ledger_mod.Ledger(self.path)
        self.assertIn("schema", store.load_error)

    def test_decision_history_is_bounded(self):
        store = ledger_mod.Ledger(self.path)
        for _ in range(50):
            store.record(Dev(), "user approved")
        self.assertLessEqual(len(store.lookup(Dev()).decisions), 20)

    def test_identity_uses_the_claimed_serial(self):
        a = ledger_mod.identity_of(Dev(serial="AAA"))
        b = ledger_mod.identity_of(Dev(serial="BBB"))
        self.assertNotEqual(a, b)

    def test_missing_serial_does_not_crash_identity(self):
        self.assertIn("-", ledger_mod.identity_of(Dev(serial=None)))

    def test_fingerprint_hashes_raw_bytes_not_the_parsed_view(self):
        one = ledger_mod.descriptor_fingerprint(Dev(raw=b"aaa"))
        two = ledger_mod.descriptor_fingerprint(Dev(raw=b"aab"))
        self.assertNotEqual(one, two)
        self.assertIsNone(ledger_mod.descriptor_fingerprint(Dev(raw=None)))


class TestDriftDetection(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ledger_mod.Ledger(Path(self.tmp.name) / "l.json")

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, dev):
        return analyzers.LedgerAnalyzer().analyze(
            analyzers.Context(device=dev, ledger=self.store))

    def test_a_device_never_seen_before_is_not_suspicious(self):
        """Novelty is not guilt, or the first run would flag everything."""
        self.assertEqual(self.analyze(Dev()), [])

    def test_same_device_unchanged_is_not_suspicious(self):
        self.store.record(Dev(), "user approved")
        self.assertEqual(self.analyze(Dev()), [])

    def test_descriptor_drift_is_critical(self):
        """The flash drive that comes back with a keyboard interface."""
        self.store.record(Dev(raw=b"innocent-stick"), "user approved")
        findings = self.analyze(Dev(raw=b"now-with-a-keyboard"))
        ids = [f.rule_id for f in findings]

        self.assertIn("descriptor-drift", ids)
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)

    def test_a_previously_rejected_device_is_flagged_on_return(self):
        self.store.record(Dev(), "user rejected")
        ids = [f.rule_id for f in self.analyze(Dev())]
        self.assertIn("previously-rejected", ids)

    def test_no_ledger_configured_means_no_findings(self):
        result = analyzers.LedgerAnalyzer().analyze(
            analyzers.Context(device=Dev(), ledger=None))
        self.assertEqual(result, [])

    def test_unreadable_ledger_is_disclosed_not_hidden(self):
        self.store.load_error = "disk on fire"
        ids = [f.rule_id for f in self.analyze(Dev())]
        self.assertIn("ledger-unavailable", ids)



class TestDefaultPath(unittest.TestCase):
    """The path bug: a root-only default broke every non-root --dry-run."""

    def test_root_uses_var_lib(self):
        import os
        from probolos import ledger as l
        real = os.geteuid
        os.geteuid = lambda: 0
        try:
            # The `state/` subdirectory is load-bearing, not cosmetic: it is
            # the only directory handed to the analyzer under --privsep, which
            # is what keeps trusted.json (in the root-owned parent) out of a
            # hostile `nobody` process's reach. See ledger.default_path.
            self.assertEqual(str(l.default_path()),
                             "/var/lib/probolos/state/ledger.json")
        finally:
            os.geteuid = real

    def test_non_root_uses_a_writable_location(self):
        import os
        from probolos import ledger as l
        real = os.geteuid
        os.geteuid = lambda: 1000
        try:
            path = l.default_path()
            self.assertNotIn("/var/lib", str(path))
            self.assertIn("probolos", str(path))
        finally:
            os.geteuid = real


# =========================================================================
# test_ledger_malformed.py
#
# Regression tests for a ledger file that is valid JSON but wrong inside.
# =========================================================================

import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from probolos.ledger import ENTRY_FIELD_NAMES, Entry, Ledger

# Every field of Entry has to appear here, or test_from_raw_covers_every_field
# fails on purpose -- that test is the guard that keeps GOOD and Entry in step.
# When a field is added to Entry, its expected loaded value goes here too. The
# baseline_hash and raw_hash fields were added in round 5 (normalized
# descriptor fingerprint); they default to the same digest so that a first
# sighting has no drift to report and the raw-hash column is populated on
# ledgers written before the field existed.
GOOD = {
    "identity": "1234:5678:-",
    "descriptor_hash": "ab" * 32,
    "first_seen": 1.0,
    "last_seen": 2.0,
    "times_seen": 3,
    "ports": ["1-1"],
    "decisions": ["yes"],
    "known_hashes": ["ab" * 32],
    "baseline_hash": "ab" * 32,
    "raw_hash": "ab" * 32,
}


class MalformedLedger(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / "ledger.json"

    def tearDown(self):
        self._dir.cleanup()

    def write(self, entries, schema=1):
        # The `fingerprint_scheme: normalized-v1` marker is added at the file
        # level so from_raw does not clear baselines on the migration path --
        # every fixture in this suite is describing the CURRENT scheme.
        self.path.write_text(json.dumps({
            "schema": schema,
            "fingerprint_scheme": "normalized-v1",
            "entries": entries,
        }))

    # ---- F7: the gate must still start ----

    def test_malformed_entry_does_not_prevent_the_gate_from_starting(self):
        """
        Every shape below raised out of Ledger.__init__ before. Any one of
        them, written by anything with access to the state directory, kept
        authorized_default at 1 for as long as it stayed there.
        """
        self.write({
            "usable": GOOD,
            "unexpected_key": dict(GOOD, injected=True),
            "missing_required": {"identity": "x"},
            "null_entry": None,
            "wrong_types": dict(GOOD, identity=5),
            "boolean_timestamp": dict(GOOD, first_seen=True),
            "string_timestamp": dict(GOOD, last_seen="yesterday"),
        })

        ledger = Ledger(self.path)          # must not raise

        self.assertEqual(sorted(ledger.entries),
                         ["unexpected_key", "usable"])
        self.assertIsNotNone(ledger.load_error)

    def test_entries_as_a_list_does_not_prevent_startup(self):
        """`"entries": []` is schema-valid JSON and used to hit .items()."""
        self.write([])
        ledger = Ledger(self.path)
        self.assertEqual(ledger.entries, {})
        self.assertIsNotNone(ledger.load_error)

    def test_a_dropped_entry_is_reported_and_not_silent(self):
        """
        A skipped entry is a device whose history is gone: it will look like a
        first sighting and no drift can be reported for it. Corrupting one
        entry must not be a quiet way of erasing the ledger's memory of one
        chosen device.
        """
        self.write({"broken": {"identity": "x"}})
        ledger = Ledger(self.path)
        self.assertIn("drift", ledger.load_error)

    # ---- what must NOT change ----

    def test_unknown_keys_are_dropped_not_rejected(self):
        """A ledger from a newer version degrades; it is not discarded."""
        self.write({"forward": dict(GOOD, field_from_the_future="x")})
        ledger = Ledger(self.path)
        self.assertIn("forward", ledger.entries)
        self.assertEqual(ledger.entries["forward"].descriptor_hash,
                         GOOD["descriptor_hash"])

    def test_a_good_entry_survives_a_save_and_reload_unchanged(self):
        self.write({"usable": GOOD})
        first = Ledger(self.path)
        self.assertIsNone(first.load_error)
        first.save()

        second = Ledger(self.path)
        self.assertIsNone(second.load_error)
        self.assertEqual(second.entries["usable"], first.entries["usable"])

    def test_from_raw_covers_every_field_of_entry(self):
        """
        A field added to Entry and not to from_raw would load as its default:
        real history silently replaced by an empty list, rather than loudly
        refused. This is the guard that keeps the two in step.
        """
        # from_raw expects the file-level marker on each dict passed in, so
        # baseline_hash is trusted rather than cleared for the migration.
        raw = dict(GOOD, fingerprint_scheme="normalized-v1")
        rebuilt = Entry.from_raw(raw)
        self.assertIsNotNone(rebuilt)
        self.assertEqual(set(asdict(rebuilt)), set(ENTRY_FIELD_NAMES))
        for name in ENTRY_FIELD_NAMES:
            self.assertEqual(asdict(rebuilt)[name], GOOD[name], name)

    def test_from_raw_rejects_non_mappings(self):
        for raw in (None, [], "string", 7):
            self.assertIsNone(Entry.from_raw(raw), repr(raw))


# =========================================================================
# test_normalized_fingerprint.py
#
# Regression tests for the normalized descriptor fingerprint.
# =========================================================================

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
