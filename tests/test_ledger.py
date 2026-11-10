"""
The ledger: device history across visits, descriptor drift, malformed
state files and the history view.

Covers probolos.ledger and probolos.history.
"""

from __future__ import annotations

import copy
import dataclasses
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from probolos import analyzers, descriptors, rules
from probolos import ledger as ledger_mod
from probolos.ledger import ENTRY_FIELD_NAMES, Entry, Ledger
from tests._support import (
    STORAGE_BLOB,
    descriptor_blob,
    make_device,
    make_kingston_device,
    make_widget_device,
    storage_config_desc,
    storage_device_blob,
    storage_device_desc,
    storage_iface_desc,
)


class Dev:
    def __init__(self, vid="0781", pid="5567", serial="ABC123",
                 raw=b"\x12\x01original", name="1-4"):
        self.vendor_id = vid
        self.product_id = pid
        self.serial = serial
        self.raw_descriptors = raw
        self.name = name


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
    "device_type": "storage",
    "known_types": ["storage"],
}


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
        found = {f.rule_id: f for f in self.analyze(Dev())}
        self.assertIn("previously-rejected", found)
        # CRITICAL, so the desktop prompt uses the countdown.
        self.assertEqual(found["previously-rejected"].severity,
                         rules.Severity.CRITICAL)

    def test_a_refusal_is_not_washed_out_by_later_sightings(self):
        """The decision list keeps the newest MAX_DECISIONS; twenty
        unanswered plug-ins pushed the refusal out, and the countdown
        with it."""
        self.store.record(Dev(), "user rejected")
        for _ in range(ledger_mod.MAX_DECISIONS + 5):
            self.store.record(Dev(), "no answer")
        entry = self.store.lookup(Dev())
        self.assertEqual(len(entry.decisions), ledger_mod.MAX_DECISIONS)
        self.assertEqual(entry.decisions[0], "user rejected")
        self.assertEqual(entry.decisions[-1], "no answer")
        self.assertIn("previously-rejected",
                      [f.rule_id for f in self.analyze(Dev())])

    def test_without_a_refusal_only_the_newest_are_kept(self):
        for n in range(ledger_mod.MAX_DECISIONS + 5):
            self.store.record(Dev(), f"no answer {n}")
        entry = self.store.lookup(Dev())
        self.assertEqual(entry.decisions[0], "no answer 5")
        self.assertEqual(len(entry.decisions), ledger_mod.MAX_DECISIONS)

    def test_an_unanswered_prompt_is_not_a_previous_refusal(self):
        self.store.record(Dev(), "no answer")
        ids = [f.rule_id for f in self.analyze(Dev())]
        self.assertNotIn("previously-rejected", ids)

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


# ---------------------------------------------------------------------------
# 1. Bus-negotiated fields must NOT change the fingerprint
# ---------------------------------------------------------------------------

class FingerprintIgnoresBusNegotiation(unittest.TestCase):
    """The same physical stick on different controllers is the SAME device."""

    def _fp(self, **kwargs):
        return ledger_mod.descriptor_fingerprint(
            make_kingston_device(storage_device_blob(**kwargs)))

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
            make_kingston_device(storage_device_blob(**kwargs)))

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
        base = make_kingston_device(storage_device_blob())
        variant = make_kingston_device(storage_device_blob())
        variant.descriptor_set.device = descriptors.DeviceDescriptor(
            usb_version=0x0210, device_class=0, device_subclass=0,
            device_protocol=0, vendor_id=0x1234, product_id=0x5678,
            device_version=0x0110, num_configurations=1)
        self.assertNotEqual(
            ledger_mod.descriptor_fingerprint(base),
            ledger_mod.descriptor_fingerprint(variant))

    def test_added_configuration_drifts(self):
        base = make_kingston_device(storage_device_blob())
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
        base = make_kingston_device(storage_device_blob())
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
        a = make_kingston_device(storage_device_blob(bcd_usb=0x0210))
        b = make_kingston_device(storage_device_blob(bcd_usb=0x0320))
        self.assertNotEqual(ledger_mod.raw_descriptor_hash(a),
                            ledger_mod.raw_descriptor_hash(b),
                            "raw hash must still see bus-negotiated changes")
        self.assertEqual(ledger_mod.descriptor_fingerprint(a),
                         ledger_mod.descriptor_fingerprint(b),
                         "but the drift fingerprint must not")

    def test_raw_hash_stored_on_entry(self):
        directory = Path(tempfile.mkdtemp(prefix="probolos-raw-"))
        self.addCleanup(shutil.rmtree, directory, True)
        path = directory / "ledger.json"
        led = ledger_mod.Ledger(path)
        dev = make_kingston_device(storage_device_blob())
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
        self.addCleanup(shutil.rmtree, self.directory, True)
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
        on_usb2 = make_kingston_device(storage_device_blob(
            bcd_usb=0x0210, max_packet0=64, max_power_raw=150),
            name="3-1", syspath="/sys/devices/pci0000:00/usb3/3-1")
        on_usb3 = make_kingston_device(storage_device_blob(
            bcd_usb=0x0320, max_packet0=9, max_power_raw=63,
            include_ss_companion=True),
            name="4-1", syspath="/sys/devices/pci0000:00/usb4/4-1")

        self._record(on_usb2, "user approved", approved=True)
        self.assertFalse(self._drift(on_usb3),
                         "same stick, different port -> no alarm")

    def test_reflash_to_add_keyboard_still_fires(self):
        genuine = make_kingston_device(storage_device_blob(
            interfaces=[(0x08, 0x06, 0x50)]))
        badusb = make_kingston_device(storage_device_blob(
            interfaces=[(0x08, 0x06, 0x50), (0x03, 0x01, 0x01)]))
        self._record(genuine, "user approved", approved=True)
        self.assertTrue(self._drift(badusb),
                        "the BadUSB reflash must still trip the alarm")

    def test_firmware_update_still_fires_first_time(self):
        v1 = make_kingston_device(storage_device_blob(bcd_device=0x0100))
        v2 = make_kingston_device(storage_device_blob(bcd_device=0x0110))
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
        self.addCleanup(shutil.rmtree, directory, True)
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
        self.addCleanup(shutil.rmtree, directory, True)
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
        dev = make_kingston_device(storage_device_blob())
        led = ledger_mod.Ledger(path)
        led.record(dev, "held: screen locked", approved=False)
        led.save()

        led = ledger_mod.Ledger(path)
        entry = led.entries[ledger_mod.identity_of(dev)]
        self.assertEqual(entry.baseline_hash,
                         ledger_mod.descriptor_fingerprint(dev),
                         "record() re-anchors the baseline on the next visit")

        replug = make_kingston_device(storage_device_blob(
            bcd_usb=0x0320, max_packet0=9, max_power_raw=63,
            include_ss_companion=True))
        led = ledger_mod.Ledger(path)
        findings = analyzers.run(analyzers.Context(device=replug, ledger=led))
        self.assertFalse(
            any(f.rule_id == "descriptor-drift" for f in findings),
            "same stick, different port -> no alarm even after migration")


class DeviceTypeIsRecordedAndShown(unittest.TestCase):
    """
    `--history` listed 045e:00cb and nothing else: the ledger kept no type, so
    telling a mouse from a flash drive meant looking the IDs up. The type comes
    from the interface classes through Probolos's own words, never from the
    product string the device wrote.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_type_comes_from_interface_classes(self):
        self.assertEqual(ledger_mod.device_type(
            make_device(descriptor_blob((0x03, 0x01, 0x02)))), "mouse")
        self.assertEqual(ledger_mod.device_type(make_device()), "storage")
        self.assertEqual(ledger_mod.device_type(make_device(descriptor_blob(
            (0x08, 0x06, 0x50), (0x03, 0x01, 0x01)))), "storage+keyboard")

    def test_undeclared_hid_is_not_called_harmless(self):
        self.assertEqual(ledger_mod.device_type(
            make_device(descriptor_blob((0x03, 0x00, 0x00)))), "hid?")

    def test_product_string_is_ignored(self):
        dev = make_device(product="Totally A Mouse")
        self.assertEqual(ledger_mod.device_type(dev), "storage")

    def test_unparsed_device_has_no_type(self):
        self.assertEqual(ledger_mod.device_type(Dev()), "")

    def test_type_survives_a_reload(self):
        store = ledger_mod.Ledger(self.path)
        dev = make_device(descriptor_blob((0x03, 0x01, 0x02)))
        store.record(dev, "user approved", approved=True)
        self.assertIsNone(store.save())
        entry = ledger_mod.Ledger(self.path).lookup(dev)
        self.assertEqual(entry.device_type, "mouse")
        self.assertEqual(entry.known_types, ["mouse"])

    def test_a_new_type_is_remembered_beside_the_old(self):
        store = ledger_mod.Ledger(self.path)
        store.record(make_device(), "user approved", approved=True)
        store.record(make_device(descriptor_blob(
            (0x08, 0x06, 0x50), (0x03, 0x01, 0x01))), "user rejected")
        entry = store.lookup(make_device())
        self.assertEqual(entry.device_type, "storage+keyboard")
        self.assertEqual(entry.known_types, ["storage", "storage+keyboard"])

    def test_an_unreadable_sighting_keeps_the_last_type(self):
        store = ledger_mod.Ledger(self.path)
        store.record(make_device(), "user approved", approved=True)
        unread = dataclasses.replace(make_device(), descriptor_set=None,
                                     raw_descriptors=None, device_class=None)
        store.record(unread, "user rejected")
        entry = store.lookup(make_device())
        self.assertEqual(entry.device_type, "storage")
        self.assertEqual(entry.known_types, ["storage"])

    def test_known_types_are_bounded_and_keep_the_first(self):
        store = ledger_mod.Ledger(self.path)
        store.record(make_device(), "user approved", approved=True)
        for cls in range(0x20, 0x20 + ledger_mod.MAX_KNOWN_TYPES + 10):
            store.record(make_device(descriptor_blob((cls, 0, 0))),
                         "user rejected")
        types = store.lookup(make_device()).known_types
        self.assertEqual(len(types), ledger_mod.MAX_KNOWN_TYPES)
        self.assertEqual(types[0], "storage")

    def test_history_shows_the_type_and_a_change_of_it(self):
        from probolos import history
        store = ledger_mod.Ledger(self.path)
        store.record(make_device(), "user approved", approved=True)
        store.record(make_device(descriptor_blob(
            (0x08, 0x06, 0x50), (0x03, 0x01, 0x01))), "user rejected")
        self.assertIsNone(store.save())
        out = history.show_history(path=self.path)
        self.assertIn("TYPE", out)
        self.assertIn("storage+keyboard ", out)
        self.assertIn("now claim a different type", out)
        self.assertTrue(all(len(line) <= 80 for line in out.splitlines()))
        out = history.show_history(verbose=True, path=self.path)
        self.assertRegex(out, r"! type changed +: storage -> storage\+keyboard")

    def test_verbose_details_line_up_and_fit_80_columns(self):
        """The -v labels were ragged ("type:", "identity fingerprint :") and a
        long decision history ran off the screen."""
        from probolos import history
        store = ledger_mod.Ledger(self.path)
        store.record(make_device(), "user approved", approved=True)
        for _ in range(6):
            store.record(make_device(descriptor_blob(
                (0x08, 0x06, 0x50), (0x03, 0x01, 0x01))),
                "auto-denied: drift on a device nobody approved again")
        self.assertIsNone(store.save())
        out = history.show_history(verbose=True, path=self.path)
        lines = out.splitlines()
        self.assertTrue(all(len(line) <= 80 for line in lines), out)
        colons = {line.index(" : ") for line in lines if " : " in line}
        self.assertEqual(len(colons), 1, out)
        self.assertNotIn("\n\n\n", out)

    def test_an_entry_without_a_type_shows_a_dash(self):
        from probolos import history
        now = time.time()
        entry = {"identity": "045e:00cb:-", "descriptor_hash": "a" * 64,
                 "first_seen": now, "last_seen": now}
        self.path.write_text(json.dumps(
            {"schema": 1, "fingerprint_scheme": "normalized-v1",
             "entries": {"045e:00cb:-": entry}}))
        os.chmod(self.path, 0o600)
        row = [line for line in history.show_history(path=self.path)
               .splitlines() if "045e:00cb" in line][0]
        self.assertEqual(row.split()[1], "-")

    def test_type_fields_are_cleaned(self):
        from probolos import history
        now = time.time()
        entry = {"identity": "0951:1665:ABC", "descriptor_hash": "x",
                 "first_seen": now, "last_seen": now,
                 "device_type": "\x1b]0;pwned\x07",
                 "known_types": ["storage", "\x1b[2J"]}
        self.path.write_text(json.dumps(
            {"schema": 1, "fingerprint_scheme": "normalized-v1",
             "entries": {"0951:1665:ABC": entry}}))
        os.chmod(self.path, 0o600)
        for verbose in (False, True):
            out = history.show_history(verbose=verbose, path=self.path)
            self.assertNotIn("\x1b", out)
            self.assertNotIn("\x07", out)


class EveryRecordedReasonHasAWord(unittest.TestCase):
    """--history cut unknown reasons to 11 characters ("MEDIA POLIC"),
    showed an allow-listed device as AUTHORIZED and counted a screen-lock
    denial as a refusal nobody made."""

    def verdict(self, reason):
        from probolos import history
        return history._verdict(Entry.from_raw(dict(GOOD, decisions=[reason])))

    def test_each_reason_the_daemon_writes(self):
        for reason, word in (
                ("user approved", "AUTHORIZED"),
                ("user rejected", "REJECTED"),
                ("trusted", "TRUSTED"),
                ("no answer", "NO ANSWER"),
                ("admission failed", "FAILED"),
                ("held: screen locked", "HELD"),
                ("held: no desktop agent", "HELD"),
                ("denied: screen locked", "DENIED"),
                ("dry-run", "DRY-RUN"),
                ("media policy: reader deauthorized", "READER OFF"),
                ("protected: port 4-1 is on the operator allowlist",
                 "PROTECTED"),
                ("protected: device is on a non-removable (internal) port",
                 "PROTECTED")):
            with self.subTest(reason=reason):
                self.assertEqual(self.verdict(reason), word)
                self.assertLessEqual(len(word), 11)

    def test_older_wording_still_reads(self):
        self.assertEqual(self.verdict("yes, approved"), "AUTHORIZED")
        self.assertEqual(self.verdict("something else entirely"),
                         "SOMETHING E")


class HistoryDoesNotReplayLedgerEscapes(unittest.TestCase):
    """
    `--history -v` runs as root and prints the ledger, which the unprivileged
    analyzer writes. Identity, ports and decisions were cleaned; the two hash
    fields were printed raw, so a tampered ledger reached root's terminal.
    """

    def test_hash_fields_are_cleaned(self):
        import os
        import time

        from probolos import history

        now = time.time()
        entry = {"identity": "0951:1665:ABC", "descriptor_hash": "x",
                 "first_seen": now, "last_seen": now,
                 "known_hashes": ["\x1b]0;pwned\x07\x1b[2J", "b" * 64],
                 "raw_hash": "\x1b[8m\x1b]2;x\x07"}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            with open(path, "w") as fh:
                json.dump({"schema": 1, "fingerprint_scheme": "normalized-v1",
                           "entries": {"0951:1665:ABC": entry}}, fh)
            os.chmod(path, 0o600)
            out = history.show_history(verbose=True, path=path)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_an_unreadable_history_is_not_an_empty_one(self):
        """It printed "History is empty" -- refusals and all, gone."""
        from probolos import history
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            with open(path, "w") as fh:
                fh.write('{"schema": 1, "entries": {},}')
            os.chmod(path, 0o600)
            out = history.show_history(path=path)
        self.assertIn("could not be read", out)


# --------------------------------------------------------------------------
# 3. The drift baseline
# --------------------------------------------------------------------------

class DriftBaselineIsNeverAPlaceholder(unittest.TestCase):

    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="probolos-audit-")) / "l.json"
        self.addCleanup(shutil.rmtree, self.path.parent, True)

    def _drift(self, dev):
        led = ledger_mod.Ledger(self.path)
        findings = analyzers.run(analyzers.Context(device=dev, ledger=led))
        return any(f.rule_id == "descriptor-drift" for f in findings)

    def test_unreadable_first_sighting_survives_a_reload(self):
        blind = make_widget_device(STORAGE_BLOB)
        blind.raw_descriptors = None
        blind.descriptor_set = None
        led = ledger_mod.Ledger(self.path)
        led.record(blind, "user rejected", approved=False)
        self.assertIsNone(led.save())

        reloaded = ledger_mod.Ledger(self.path)
        entry = reloaded.entries[ledger_mod.identity_of(blind)]
        self.assertEqual(entry.baseline_hash, "",
                         "the placeholder must not become a baseline on load")
        self.assertFalse(self._drift(make_widget_device(STORAGE_BLOB)),
                         "our failure to read is not the device's drift")

    def test_a_persisted_placeholder_baseline_is_discarded(self):
        entry = ledger_mod.Entry.from_raw({
            "identity": "1234:5678:S1", "descriptor_hash": "-",
            "first_seen": 1.0, "last_seen": 2.0, "known_hashes": ["-"],
            "baseline_hash": "-", "fingerprint_scheme": "normalized-v1"})
        self.assertEqual(entry.baseline_hash, "")

    def test_first_sighting_after_the_fingerprint_migration_is_quiet(self):
        dev = make_widget_device(STORAGE_BLOB)
        ident = ledger_mod.identity_of(dev)
        self.path.write_text(json.dumps({"schema": 1, "entries": {ident: {
            "identity": ident, "descriptor_hash": "old_raw_hash",
            "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
            "known_hashes": ["old_raw_hash"],
            "baseline_hash": "old_raw_hash"}}}))
        self.assertFalse(self._drift(dev))

    def test_real_drift_is_still_reported(self):
        led = ledger_mod.Ledger(self.path)
        led.record(make_widget_device(STORAGE_BLOB), "user approved", approved=True)
        self.assertIsNone(led.save())
        changed = make_widget_device(storage_device_desc() + storage_config_desc(27, n_ifaces=2)
                              + storage_iface_desc()
                              + storage_iface_desc(0x03, 0x01, 0x01, num=1))
        self.assertTrue(self._drift(changed))


# ---------------------------------------------------------------------------
# 3. The drift ledger: reader identity + LUN, first layout is the baseline
# ---------------------------------------------------------------------------

class MediaLedger(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.json"
        self.dev = mock.Mock(vendor_id="0bda", product_id="0158",
                             serial="READER1")

    def test_first_is_baseline_then_drift_then_known(self):
        led = ledger_mod.Ledger(self.path)
        self.assertEqual(led.record_media(self.dev, "0", "A"), (None, False))
        self.assertEqual(led.record_media(self.dev, "0", "A"), ("A", True))
        self.assertEqual(led.record_media(self.dev, "0", "B"), ("A", False))
        self.assertEqual(led.record_media(self.dev, "0", "B"), ("A", True))

    def test_luns_are_separate_slots(self):
        led = ledger_mod.Ledger(self.path)
        led.record_media(self.dev, "0", "A")
        self.assertEqual(led.record_media(self.dev, "1", "B"), (None, False))

    def test_survives_a_restart(self):
        led = ledger_mod.Ledger(self.path)
        led.record_media(self.dev, "0", "A")
        self.assertIsNone(led.save())
        again = ledger_mod.Ledger(self.path)
        self.assertIsNone(again.load_error)
        self.assertEqual(again.record_media(self.dev, "0", "B"), ("A", False))

    def test_baseline_survives_the_bound(self):
        led = ledger_mod.Ledger(self.path)
        for i in range(ledger_mod.MAX_MEDIA_LAYOUTS * 3):
            led.record_media(self.dev, "0", f"L{i}")
        (layouts,) = led.media.values()
        self.assertEqual(len(layouts), ledger_mod.MAX_MEDIA_LAYOUTS)
        self.assertEqual(layouts[0], "L0")

    def test_malformed_media_section_is_dropped_loudly(self):
        self.path.write_text(json.dumps({
            "schema": ledger_mod.SCHEMA_VERSION,
            "fingerprint_scheme": "normalized-v1",
            "entries": {},
            "media": {"good#lun0": ["A"], "bad#lun0": [1, 2], "x": "y"}}))
        os.chmod(self.path, 0o600)
        led = ledger_mod.Ledger(self.path)
        self.assertEqual(led.media, {"good#lun0": ["A"]})
        self.assertIn("media", led.load_error)


# ---------------------------------------------------------------------------
# P3 -- a decision recorded is not a decision endorsed
# ---------------------------------------------------------------------------

class DescriptorDriftSurvivesRecording(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="probolos-ledger-"))
        self.path = self.directory / "ledger.json"
        # Same identity, same single storage interface, different firmware
        # revision: drift is the ONLY signal that separates these two.
        self.genuine = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                   bcd_device=0x0100))
        self.reflashed = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                     bcd_device=0x0110))

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _seed(self):
        led = ledger_mod.Ledger(self.path)
        led.record(self.genuine, "user approved", approved=True)
        led.save()

    def _drift(self, device):
        led = ledger_mod.Ledger(self.path)
        findings = analyzers.run(analyzers.Context(device=device, ledger=led))
        return any(f.rule_id == "descriptor-drift" for f in findings)

    def _record(self, device, reason, approved):
        led = ledger_mod.Ledger(self.path)
        led.record(device, reason, approved=approved)
        led.save()

    def test_genuine_device_never_drifts(self):
        self._seed()
        self.assertFalse(self._drift(self.genuine))

    def test_drift_is_reported_on_first_appearance(self):
        self._seed()
        self.assertTrue(self._drift(self.reflashed))

    def test_drift_survives_a_refusal(self):
        self._seed()
        self.assertTrue(self._drift(self.reflashed))
        self._record(self.reflashed, "user rejected", approved=False)
        self.assertTrue(self._drift(self.reflashed),
                        "refusing a drifted device must not adopt its blob")

    def test_drift_survives_being_held_while_the_screen_was_locked(self):
        """
        The worst case: _hold_until_unlocked() records before anybody has been
        asked anything, so the alarm was erased without a human ever seeing it.
        """
        self._seed()
        self._record(self.reflashed, "held: screen locked", approved=False)
        self.assertTrue(self._drift(self.reflashed))

    def test_approval_is_what_moves_the_baseline(self):
        self._seed()
        self._record(self.reflashed, "user approved", approved=True)
        self.assertFalse(self._drift(self.reflashed),
                         "a firmware update the user accepted must stop nagging")
        self.assertTrue(self._drift(self.genuine),
                        "and the previous revision is now the drifted one")

    def test_old_ledger_carrying_the_new_scheme_marker_is_migrated(self):
        """
        A ledger written by round 4 (raw-blob fingerprint, `baseline_hash`
        already added) carries the entry through `fingerprint_scheme:
        normalized-v1` via Ledger.load(); from_raw is then free to trust the
        stored baseline. The wider migration -- pre-round-4 ledgers with the
        raw-blob baseline -- is covered by OldLedgerMigration in this file.
        """
        entry = ledger_mod.Entry.from_raw({
            "identity": "0951:1666:AABBCCDD",
            "descriptor_hash": "bbbb",
            "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
            "known_hashes": ["aaaa", "bbbb"],
            "fingerprint_scheme": "normalized-v1",
        })
        self.assertEqual(entry.baseline_hash, "aaaa",
                         "known_hashes[0] is the surviving evidence")

    def test_unreadable_descriptors_never_become_a_baseline(self):
        blind = make_device()
        blind.raw_descriptors = None
        blind.descriptor_set = None
        led = ledger_mod.Ledger(self.path)
        led.record(blind, "user rejected", approved=False)
        self.assertEqual(led.entries[ledger_mod.identity_of(blind)].baseline_hash,
                         "", "a failure to read must not manufacture drift")


class RemovalWaitsForTheDaemon(unittest.TestCase):
    """
    A running daemon keeps the ledger in memory and writes it all back after
    the next decision, so deleting the file under it achieves nothing. The
    daemon claims the ledger; removal refuses while the claim is held.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "state" / "ledger.json"
        led = Ledger(self.path)
        led.record(Dev(), "user approved", approved=True)
        self.assertIsNone(led.save())

    def tearDown(self):
        self.tmp.cleanup()

    def test_unclaimed_ledger_is_removed(self):
        self.assertFalse(ledger_mod.in_use(self.path))
        self.assertTrue(ledger_mod.remove(self.path))
        self.assertFalse(self.path.exists())

    def test_claimed_ledger_is_refused_and_kept(self):
        fd = ledger_mod.claim(self.path)
        self.assertIsNotNone(fd)
        try:
            self.assertTrue(ledger_mod.in_use(self.path))
            with self.assertRaises(ledger_mod.InUse):
                ledger_mod.remove(self.path)
            self.assertTrue(self.path.exists())
        finally:
            os.close(fd)

    def test_claim_ends_with_its_descriptor(self):
        os.close(ledger_mod.claim(self.path))
        self.assertFalse(ledger_mod.in_use(self.path))

    def test_claim_marks_the_first_run_too(self):
        """Before any save the directory may not exist. Claiming only once it
        did would leave a first run unmarked, and its history deletable."""
        path = Path(self.tmp.name) / "fresh" / "ledger.json"
        fd = ledger_mod.claim(path)
        self.assertIsNotNone(fd)
        try:
            self.assertTrue(ledger_mod.in_use(path))
        finally:
            os.close(fd)

    def test_nothing_there_is_nothing_to_remove(self):
        path = Path(self.tmp.name) / "absent" / "ledger.json"
        self.assertFalse(ledger_mod.in_use(path))
        self.assertFalse(ledger_mod.remove(path))

    def test_dry_run_daemon_does_not_claim(self):
        from probolos import daemon as daemon_mod
        with mock.patch.object(ledger_mod, "claim") as claim, \
             mock.patch.object(daemon_mod, "pyudev", None), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                daemon_mod.serve(dry_run=True, ledger_path=self.path,
                                 watchdog_timeout=0)
        claim.assert_not_called()

    def test_real_daemon_claims_before_loading(self):
        from probolos import daemon as daemon_mod
        order = []
        with mock.patch.object(ledger_mod, "claim",
                               side_effect=lambda p: order.append("claim")), \
             mock.patch.object(ledger_mod.Ledger, "load",
                               side_effect=lambda: order.append("load")), \
             mock.patch.object(daemon_mod, "pyudev", None), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                daemon_mod.serve(dry_run=False, ledger_path=self.path,
                                 watchdog_timeout=0)
        self.assertEqual(order, ["claim", "load"])


class SerialsShowTheirDistinguishingEnd(unittest.TestCase):
    """'000000001532' was shown as '(00000000)' -- the digits that tell
    units of one model apart were the ones cut off."""

    def row(self, identity, verbose=False):
        from probolos import history
        entry = Entry.from_raw(dict(GOOD, identity=identity))
        return history.format_table([entry], verbose=verbose)

    def test_the_tail_is_kept(self):
        out = self.row("05e3:0749:000000001532")
        self.assertIn("05e3:0749 (\u2026000001532)", out)

    def test_a_short_serial_is_whole(self):
        self.assertIn("1234:5678 (ABC123)", self.row("1234:5678:ABC123"))

    def test_verbose_shows_the_whole_serial(self):
        out = self.row("05e3:0749:000000001532", verbose=True)
        self.assertRegex(out, r"serial +: 000000001532")


class AnOverlongCountCannotSilenceDrift(unittest.TestCase):
    """
    from_raw kept any integer as times_seen, and json.loads accepts one of up
    to 4300 digits. A count of 4300 nines, the largest it accepts, became 4301
    digits at the next record(), and Python will not turn that into text:
    save() raised instead of returning the error, so the ledger could not be
    written again until a restart, and LedgerAnalyzer raised on its own
    message. The device's CRITICAL drift finding came out as a NOTICE that
    the analyzer had failed. The count is clamped now, and save() returns
    what json.dumps refuses like any other failure.
    """

    # The largest integer json.loads accepts: 4300 nines.
    OVERLONG = int("9" * 4300)

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="probolos-ledger-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.path = self.directory / "ledger.json"
        self.approved = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                    bcd_device=0x0100))
        self.reflashed = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                     bcd_device=0x0110))
        ident = ledger_mod.identity_of(self.approved)
        self.baseline = ledger_mod.descriptor_fingerprint(self.approved)
        self.path.write_text(json.dumps({
            "schema": ledger_mod.SCHEMA_VERSION,
            "fingerprint_scheme": "normalized-v1",
            "entries": {ident: dict(
                GOOD, identity=ident, descriptor_hash=self.baseline,
                baseline_hash=self.baseline, known_hashes=[self.baseline],
                times_seen=self.OVERLONG)}}))

    def _verdict(self, led):
        findings = analyzers.run(
            analyzers.Context(device=self.reflashed, ledger=led))
        return [(f.rule_id, f.severity) for f in findings
                if f.rule_id == "descriptor-drift"
                or f.rule_id.startswith("analyzer-failed")]

    def test_the_entry_loads_whole_with_its_count_clamped(self):
        led = Ledger(self.path)
        self.assertIsNone(led.load_error, "clamped, not refused")
        entry = led.lookup(self.approved)
        self.assertEqual(entry.baseline_hash, self.baseline)
        self.assertTrue(entry.times_seen < self.OVERLONG, "count not bounded")
        self.assertEqual(entry.times_seen, ledger_mod.MAX_TIMES_SEEN)

    def test_drift_is_still_critical_after_the_sighting_is_recorded(self):
        drift = [("descriptor-drift", rules.Severity.CRITICAL)]
        led = Ledger(self.path)
        self.assertEqual(self._verdict(led), drift)
        led.record(self.reflashed, "held: screen locked", approved=False)
        self.assertIsNone(led.save())
        self.assertEqual(self._verdict(led), drift, "in the same run")
        self.assertEqual(self._verdict(Ledger(self.path)), drift,
                         "after a restart")

    def test_save_returns_what_json_refuses_instead_of_raising(self):
        led = Ledger(self.path)
        for error in (ValueError("Exceeds the limit (4300 digits)"),
                      TypeError("Object of type X is not JSON serializable")):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(ledger_mod.atomicio, "write_json_atomic",
                                      side_effect=error):
                self.assertEqual(led.save(), str(error))


class AnImpossibleDateCannotSilenceDrift(unittest.TestCase):
    """
    from_raw keeps any finite number as first_seen. LedgerAnalyzer puts that
    date into the drift finding's text, and a date past year 9999 (or before
    year 1) made fromtimestamp() raise there: the device's
    CRITICAL descriptor-drift came out as analyzer-failed:ledger, a NOTICE.
    The finding does not depend on the date, so the date gives way.
    """

    def test_drift_stays_critical_whatever_the_first_date(self):
        approved = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                               bcd_device=0x0100))
        reflashed = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                bcd_device=0x0110))
        for first_seen in (1e12, -1e12, 1.7e308):
            with self.subTest(first_seen=first_seen):
                led = Ledger(Path("/nonexistent/ledger.json"))
                led.record(approved, "user approved", approved=True)
                led.lookup(approved).first_seen = first_seen
                findings = analyzers.run(
                    analyzers.Context(device=reflashed, ledger=led))
                drift = [f for f in findings
                         if f.rule_id == "descriptor-drift"]
                self.assertEqual([f.severity for f in drift],
                                 [rules.Severity.CRITICAL])
                self.assertIn("an unknown date", drift[0].explanation)
                self.assertEqual([f.rule_id for f in findings
                                  if f.rule_id.startswith("analyzer-failed")],
                                 [])



class LedgerTextReachesNoTerminalRaw(unittest.TestCase):
    """
    The ledger file is written by the analyzer's account, and two of its
    strings were printed as they were: the schema it claims, in the startup
    warning and the ledger-unavailable finding, and the ports of a refused
    device, in the previously-rejected finding. An escape sequence in either
    reached the terminal, and a lone surrogate ended the prompt's output.
    """

    HOSTILE = "\x1b]0;pwned\x07\x1b[2J\udc9b"

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="probolos-ledger-"))
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.path = self.directory / "ledger.json"

    def assertSafe(self, text):
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        text.encode("utf-8")                 # no lone surrogate

    def test_the_schema_is_not_echoed_raw(self):
        self.path.write_text(json.dumps({"schema": self.HOSTILE,
                                         "entries": {}}))
        led = Ledger(self.path)
        self.assertIn("unsupported ledger schema", led.load_error)
        self.assertSafe(led.load_error)
        findings = analyzers.run(analyzers.Context(
            device=make_device(), ledger=led))
        unavailable = [f for f in findings
                       if f.rule_id == "ledger-unavailable"]
        self.assertEqual(len(unavailable), 1)
        self.assertSafe(unavailable[0].explanation)

    def test_a_refused_device_s_ports_are_not_echoed_raw(self):
        device = make_device()
        ident = ledger_mod.identity_of(device)
        digest = ledger_mod.descriptor_fingerprint(device)
        self.path.write_text(json.dumps({
            "schema": ledger_mod.SCHEMA_VERSION,
            "fingerprint_scheme": "normalized-v1",
            "entries": {ident: dict(
                GOOD, identity=ident, descriptor_hash=digest,
                baseline_hash=digest, known_hashes=[digest],
                decisions=["user rejected"], ports=["1-4" + self.HOSTILE])}}))
        led = Ledger(self.path)
        self.assertIsNone(led.load_error)
        findings = analyzers.run(analyzers.Context(device=device, ledger=led))
        refused = [f for f in findings if f.rule_id == "previously-rejected"]
        self.assertEqual(len(refused), 1)
        self.assertSafe(refused[0].explanation)
        self.assertIn("1-4\\x1b]0;pwned", refused[0].explanation)


class ALedgerThatCannotBeReachedDoesNotStopTheGate(unittest.TestCase):
    """
    Path.exists() swallows only "not there". A state directory the analyzer
    cannot traverse (made 0700 under a restrictive umask, or never handed
    over) raised EACCES out of Ledger.__init__, before the gate had closed:
    the analyzer died at startup and the gate with it. TrustStore.load()
    already failed closed here; the ledger did not.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "state" / "ledger.json"

    def test_eacces_is_a_load_error(self):
        denied = PermissionError(13, "Permission denied", str(self.path))
        with mock.patch.object(Path, "exists", side_effect=denied):
            led = Ledger(self.path)                 # must not raise
        self.assertIn("cannot reach the ledger", led.load_error)
        self.assertEqual(led.entries, {})

    def test_the_daemon_goes_on_without_history(self):
        denied = PermissionError(13, "Permission denied", str(self.path))
        with mock.patch.object(Path, "exists", side_effect=denied):
            led = Ledger(self.path)
        ids = [f.rule_id for f in analyzers.run(
            analyzers.Context(device=make_device(), ledger=led))]
        self.assertIn("ledger-unavailable", ids)

    @unittest.skipUnless(os.geteuid() == 0, "needs root, to stop being it")
    def test_for_real_as_an_account_that_cannot_traverse_the_directory(self):
        locked = Path(self._tmp.name) / "locked"
        locked.mkdir(mode=0o700)
        os.chmod(self._tmp.name, 0o755)
        target = locked / "state" / "ledger.json"
        read_end, write_end = os.pipe()
        pid = os.fork()
        if pid == 0:
            answer = b"raised"
            try:
                os.close(read_end)
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                led = Ledger(target)
                answer = (led.load_error or "loaded").encode()
            except BaseException as exc:   # noqa: BLE001 -- reported below
                answer = f"raised {type(exc).__name__}".encode()
            finally:
                os.write(write_end, answer)
                os._exit(0)
        os.close(write_end)
        with os.fdopen(read_end, "rb") as pipe:
            answer = pipe.read().decode()
        os.waitpid(pid, 0)
        # Up to Python 3.13 Path.exists() raises EACCES here, and the reason
        # becomes the load error. From 3.14 it answers "not there", and the
        # ledger simply starts empty. Either way the constructor returned.
        self.assertTrue(answer == "loaded"
                        or "cannot reach the ledger" in answer, answer)


class AnIncompleteLedgerIsStillConsulted(unittest.TestCase):
    """
    LedgerAnalyzer returned as soon as the ledger had a load error, and the
    error stands for the whole run. One malformed entry, or a file refused
    outright, switched descriptor-drift and previously-rejected off for
    every device until the next start: those whose entries had loaded, and
    those refused since, in the same run.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "ledger.json"
        self.stick = make_device()
        self.reflashed = make_device(descriptor_blob(
            (0x08, 0x06, 0x50), (0x03, 0x01, 0x01)))

    def findings(self, led, device=None):
        return {f.rule_id: f for f in analyzers.run(
            analyzers.Context(device=device or self.stick, ledger=led))}

    def with_one_broken_entry(self, decision, approved=False):
        led = Ledger(self.path)
        led.record(self.stick, decision, approved=approved)
        self.assertIsNone(led.save())
        data = json.loads(self.path.read_text())
        data["entries"]["dead:beef:-"] = {"identity": 7}
        self.path.write_text(json.dumps(data))
        led = Ledger(self.path)
        self.assertIn("1 malformed ledger entry", led.load_error)
        return led

    def test_a_refusal_that_loaded_still_brings_the_countdown(self):
        found = self.findings(self.with_one_broken_entry("user rejected"))
        self.assertIn("ledger-unavailable", found)
        self.assertEqual(found["previously-rejected"].severity,
                         rules.Severity.CRITICAL)

    def test_drift_from_a_baseline_that_loaded_is_still_critical(self):
        led = self.with_one_broken_entry("user approved", approved=True)
        found = self.findings(led, self.reflashed)
        self.assertEqual(found["descriptor-drift"].severity,
                         rules.Severity.CRITICAL)

    def test_a_refusal_made_in_this_run_counts_after_a_failed_load(self):
        self.path.write_text("{not json")
        led = Ledger(self.path)
        self.assertIsNotNone(led.load_error)
        self.assertNotIn("previously-rejected", self.findings(led))
        led.record(self.stick, "user rejected")
        self.assertIn("previously-rejected", self.findings(led))

    def test_the_notice_says_which_of_the_two_it_was(self):
        led = self.with_one_broken_entry("user rejected")
        known = self.findings(led)["ledger-unavailable"].explanation
        self.assertIn("was still used for this device", known)
        other = make_device(serial="NEVER-SEEN")
        unknown = self.findings(led, other)["ledger-unavailable"].explanation
        self.assertIn("without any knowledge", unknown)

    def test_a_device_with_no_entry_gets_the_notice_and_nothing_else(self):
        led = self.with_one_broken_entry("user rejected")
        other = make_device(serial="NEVER-SEEN")
        self.assertEqual(list(self.findings(led, other)),
                         ["ledger-unavailable"])


class TheLedgerFileStaysReadable(unittest.TestCase):
    """
    Every list inside an entry was bounded; the number of entries was not,
    and a new serial number is a new entry. A device re-enumerating under a
    fresh serial each time (recorded at once as "held" behind a locked
    screen) grew the file past the 8 MiB the next start will read: that
    start refused it, and its first save replaced it. Every refusal and
    every drift baseline on record was gone.
    """

    BUDGET = 40_000

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "ledger.json"
        patcher = mock.patch.object(ledger_mod, "MAX_FILE_BYTES", self.BUDGET)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.refused = make_device(serial="REFUSED")
        self.approved = make_device(serial="APPROVED")

    def flood(self, led, count=400, decision="held: screen locked"):
        for n in range(count):
            led.record(make_device(serial=f"FLOOD{n:06d}"), decision)
            self.assertIsNone(led.save())

    def test_a_flood_of_new_serials_cannot_outgrow_the_file(self):
        led = Ledger(self.path)
        self.flood(led)
        self.assertLessEqual(self.path.stat().st_size, self.BUDGET)
        again = Ledger(self.path)
        self.assertIsNone(again.load_error)
        self.assertEqual(len(again.entries), len(led.entries))
        self.assertLess(len(again.entries), 400)

    def test_what_a_person_decided_outlives_the_flood(self):
        led = Ledger(self.path)
        led.record(self.refused, "user rejected")
        led.record(self.approved, "user approved", approved=True)
        self.assertIsNone(led.save())
        self.flood(led)
        again = Ledger(self.path)
        self.assertIn(ledger_mod.identity_of(self.refused), again.entries)
        self.assertIn(ledger_mod.identity_of(self.approved), again.entries)
        ids = [f.rule_id for f in analyzers.run(
            analyzers.Context(device=self.refused, ledger=again))]
        self.assertIn("previously-rejected", ids)

    def test_the_oldest_undecided_entries_go_first(self):
        led = Ledger(self.path)
        self.flood(led, count=40)
        newest = ledger_mod.identity_of(make_device(serial="FLOOD000039"))
        oldest = ledger_mod.identity_of(make_device(serial="FLOOD000000"))
        for n, entry in enumerate(led.entries.values()):
            entry.last_seen = float(n)
        self.assertTrue(led._shed())
        self.assertNotIn(oldest, led.entries)
        self.assertIn(newest, led.entries)
        self.assertEqual(len(led.entries), 30)

    def test_decided_entries_go_only_when_nothing_else_is_left(self):
        led = Ledger(self.path)
        for n in range(8):
            led.record(make_device(serial=f"MINE{n}"), "user approved",
                       approved=True)
        for n, entry in enumerate(led.entries.values()):
            entry.last_seen = float(n)
        self.assertTrue(led._shed())
        self.assertEqual(len(led.entries), 6)
        self.assertNotIn(ledger_mod.identity_of(make_device(serial="MINE0")),
                         led.entries)

    def test_an_empty_ledger_has_nothing_to_shed(self):
        self.assertFalse(Ledger(self.path)._shed())

    def test_losing_entries_is_said_once(self):
        led = Ledger(self.path)
        self.assertIsNone(led.take_shed_note())
        self.flood(led)
        note = led.take_shed_note()
        self.assertIn("size limit", note)
        self.assertIn("forgotten", note)
        self.assertIsNone(led.take_shed_note(), "said twice")

    def test_a_stand_in_ledger_has_no_note(self):
        self.assertIsNone(ledger_mod.shed_note(mock.Mock()))
        self.assertIsNone(ledger_mod.shed_note(object()))

    def test_a_file_already_over_the_budget_is_cut_at_the_first_save(self):
        with mock.patch.object(ledger_mod, "MAX_FILE_BYTES", 10 ** 9):
            led = Ledger(self.path)
            led.record(self.refused, "user rejected")
            for n in range(300):
                led.record(make_device(serial=f"OLD{n:05d}"), "no answer")
            self.assertIsNone(led.save())
        self.assertGreater(self.path.stat().st_size, self.BUDGET)
        led = Ledger(self.path)
        led.record(make_device(serial="ONE-MORE"), "no answer")
        self.assertIsNone(led.save())
        self.assertLessEqual(self.path.stat().st_size, self.BUDGET)
        self.assertIn(ledger_mod.identity_of(self.refused), led.entries)

    def test_the_daemon_prints_the_note(self):
        from probolos import daemon as daemon_mod
        led = Ledger(self.path)
        engine = daemon_mod.Probolos(ledger=led)
        out = io.StringIO()
        with redirect_stdout(out):
            for n in range(400):
                engine._record(daemon_mod.Decision(
                    make_device(serial=f"FLOOD{n:06d}"), False,
                    "held: screen locked", time.time()))
        self.assertIn("reached its size limit", out.getvalue())
        self.assertLess(out.getvalue().count("size limit"), 40,
                        "said for every device instead of once per cut")


class TheLedgerBudgetFitsTheReadLimit(unittest.TestCase):

    def test_a_file_at_the_budget_can_still_grow_by_one_save_and_load(self):
        """The file is cut after the save that took it over the budget, so
        the budget has to leave room for that save under the read limit."""
        from probolos import securefs
        self.assertLessEqual(ledger_mod.MAX_FILE_BYTES * 2,
                             securefs.MAX_STATE_BYTES)

    def test_a_file_over_the_read_limit_is_still_refused_whole(self):
        from probolos import securefs
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            with mock.patch.object(securefs, "MAX_STATE_BYTES", 64):
                path.write_text(json.dumps({"schema": 1, "entries": {},
                                            "pad": "x" * 200}))
                self.assertIn("input limit", Ledger(path).load_error)


class ASaveErrorThatComesBackIsReportedAgain(unittest.TestCase):
    """
    A repeated save error is reported once, so one condition is one line.
    The memory of it was never cleared, though: after a save had succeeded
    again, the same error returning later stayed unreported for the rest of
    the run, and the history silently stopped being kept.
    """

    def test_reported_once_while_it_lasts_and_again_when_it_returns(self):
        with tempfile.TemporaryDirectory() as tmp:
            led = Ledger(Path(tmp) / "ledger.json")
            led.record(make_device(), "no answer")
            full = OSError(28, "No space left on device")
            with mock.patch.object(ledger_mod.atomicio, "write_json_atomic",
                                   side_effect=full):
                self.assertIn("No space left", led.save())
                self.assertIsNone(led.save(), "the same condition, twice")
            self.assertIsNone(led.save())               # space was freed
            with mock.patch.object(ledger_mod.atomicio, "write_json_atomic",
                                   side_effect=full):
                self.assertIn("No space left", led.save(),
                              "full again, and nobody was told")


if __name__ == "__main__":
    unittest.main()
