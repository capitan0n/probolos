"""
The trust store: what it admits without asking, who may write it, and
the atomic write that keeps a crash from leaving it half-formed.

Merged from: test_trust_storage.py, test_trust_integrity.py, test_atomicio.py
"""
from __future__ import annotations

# =========================================================================
# test_trust_storage.py
#
# Tests for remembered devices (allowlist) and for stage 4 medium inspection.
# =========================================================================

import struct
import tempfile
import unittest
from pathlib import Path

from probolos import rules, storage, trust


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def mbr_with(*entries, signature=True):
    """Build a 512-byte MBR. Each entry is (type, start_lba, sectors, boot)."""
    data = bytearray(512)
    for i, (ptype, start, sectors, boot) in enumerate(entries):
        struct.pack_into("<BBBBBBBBII", data, 446 + i * 16,
                         0x80 if boot else 0x00, 0, 0, 0,
                         ptype, 0, 0, 0, start, sectors)
    if signature:
        struct.pack_into("<H", data, 510, 0xAA55)
    return bytes(data)


def medium(partitions, size_sectors, signatures=None, scheme="mbr"):
    return storage.MediumReport(
        device="/dev/sdb", size_sectors=size_sectors, scheme=scheme,
        partitions=partitions, signatures=signatures or {})


class Dev:
    def __init__(self, vid="0951", pid="1665", serial="ABC",
                 raw=b"\x12\x01descriptors", name="3-9"):
        self.vendor_id, self.product_id = vid, pid
        self.serial = serial
        self.raw_descriptors = raw
        self.name = name

    def label(self):
        return "Kingston DataTraveler"


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------

class TestTrustStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "trusted.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_trust_survives_a_restart(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        self.assertIsNone(store.save())
        self.assertTrue(trust.TrustStore(self.path).is_trusted(Dev()))

    def test_changed_descriptors_are_not_the_trusted_device(self):
        """
        The property that makes this more than a VID/PID allowlist: the same
        identity with different descriptors is something CLAIMING to be the
        trusted device, and must be asked about.
        """
        store = trust.TrustStore(self.path)
        store.trust(Dev(raw=b"original"))
        self.assertTrue(store.is_trusted(Dev(raw=b"original")))
        self.assertFalse(store.is_trusted(Dev(raw=b"rewritten")))

    def test_different_serial_is_a_different_device(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev(serial="AAA"))
        self.assertFalse(store.is_trusted(Dev(serial="BBB")))

    def test_a_device_with_unreadable_descriptors_cannot_be_trusted(self):
        """Nothing to pin trust to, so it must be asked about every time."""
        store = trust.TrustStore(self.path)
        self.assertIsNone(store.trust(Dev(raw=None)))
        self.assertFalse(store.is_trusted(Dev(raw=None)))

    def test_corrupt_store_trusts_nothing(self):
        """Fail closed: a damaged file must not become an open door."""
        self.path.write_text("{ this is not json")
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertFalse(store.is_trusted(Dev()))

    def test_unknown_schema_trusts_nothing(self):
        import json
        self.path.write_text(json.dumps({"schema": 99, "devices": {}}))
        self.assertIsNotNone(trust.TrustStore(self.path).load_error)

    def test_forget_matches_on_a_human_readable_name(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        self.assertTrue(store.forget("kingston"))
        self.assertFalse(store.is_trusted(Dev()))

    def test_clear_removes_everything(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev(serial="A"))
        store.trust(Dev(serial="B"))
        self.assertEqual(store.clear(), 2)

    def test_admissions_are_counted(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        store.record_admission(Dev())
        store.record_admission(Dev())
        self.assertEqual(store.lookup(Dev()).times_admitted, 2)


# ---------------------------------------------------------------------------
# Storage: ordinary media must stay silent
# ---------------------------------------------------------------------------

class TestOrdinaryMediaAreSilent(unittest.TestCase):

    def test_typical_fat32_stick(self):
        """One FAT32 partition at the standard 1 MiB alignment."""
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 7811072, False)))
        report = medium(parts, 7813120, {0: "FAT32"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_exfat_stick_declared_as_ntfs_type(self):
        """0x07 covers NTFS and exFAT alike; this pairing is routine."""
        parts = storage.parse_mbr(mbr_with((0x07, 2048, 15000000, False)))
        report = medium(parts, 15002048, {0: "exFAT"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_superfloppy_without_a_partition_table(self):
        """Plenty of sticks ship with a filesystem and no partition table."""
        report = medium([], 7813120, {-1: "FAT32"}, scheme="none")
        self.assertEqual(rules.storage_findings(report), [])

    def test_eight_mib_alignment_is_accepted(self):
        """Some tools align to 8 MiB; that must not read as a hidden area."""
        parts = storage.parse_mbr(mbr_with((0x0C, 16384, 7790000, False)))
        report = medium(parts, 7813120, {0: "FAT32"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_two_partitions_side_by_side(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 4000000, False),
                                           (0x83, 4002048, 3800000, False)))
        report = medium(parts, 7813120, {0: "FAT32", 1: "ext2/3/4"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_bootable_linux_installer_is_not_flagged(self):
        """A bootable USB is an everyday object, not a finding."""
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 7000000, True)))
        report = medium(parts, 7813120, {0: "FAT32"})
        self.assertEqual(rules.storage_findings(report), [])


class TestStorageContradictions(unittest.TestCase):

    def ids(self, report):
        return [f.rule_id for f in rules.storage_findings(report)]

    def test_partition_past_the_end_of_the_device(self):
        """
        Impossible on honest media, and the signature of a drive lying about
        its capacity -- data written past the real end is silently lost.
        """
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 100_000_000, False)))
        report = medium(parts, 7813120, {0: "FAT32"})
        self.assertIn("partition-beyond-end-of-device", self.ids(report))

    def test_overlapping_partitions(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 4000000, False),
                                           (0x83, 3000000, 1000000, False)))
        report = medium(parts, 7813120)
        self.assertIn("overlapping-partitions", self.ids(report))

    def test_declared_type_disagrees_with_content(self):
        parts = storage.parse_mbr(mbr_with((0x83, 2048, 4000000, False)))
        report = medium(parts, 7813120, {0: "NTFS"})
        self.assertIn("filesystem-type-mismatch", self.ids(report))

    def test_large_gap_before_the_first_partition(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 400000, 7000000, False)))
        report = medium(parts, 7813120, {0: "FAT32"})
        self.assertIn("large-unallocated-gap", self.ids(report))

    def test_unreadable_medium_is_disclosed(self):
        report = storage.MediumReport(error="Permission denied")
        self.assertIn("storage-unreadable", self.ids(report))

    def test_storage_findings_are_never_critical(self):
        """
        A partition table is metadata, not behaviour. These findings inform a
        decision; they do not by themselves prove hostility, and inflating them
        to CRITICAL would put them above evidence that does.
        """
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 100_000_000, False)))
        for finding in rules.storage_findings(medium(parts, 7813120)):
            self.assertLess(finding.severity, rules.Severity.CRITICAL)


class TestMbrParsing(unittest.TestCase):

    def test_missing_signature_yields_no_partitions(self):
        self.assertEqual(
            storage.parse_mbr(mbr_with((0x0C, 2048, 1000, False),
                                       signature=False)), [])

    def test_empty_slots_are_skipped(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 1000, False)))
        self.assertEqual(len(parts), 1)

    def test_truncated_data_does_not_raise(self):
        self.assertEqual(storage.parse_mbr(b"\x00" * 10), [])

    def test_filesystem_signatures(self):
        fat32 = bytearray(512)
        fat32[82:87] = b"FAT32"
        self.assertEqual(storage.sniff_filesystem(bytes(fat32)), "FAT32")

        ntfs = bytearray(512)
        ntfs[3:11] = b"NTFS    "
        self.assertEqual(storage.sniff_filesystem(bytes(ntfs)), "NTFS")

        ext = bytearray(0x440)
        struct.pack_into("<H", ext, 0x438, 0xEF53)
        self.assertEqual(storage.sniff_filesystem(bytes(ext)), "ext2/3/4")

        self.assertIsNone(storage.sniff_filesystem(bytes(512)))



class TestNumberedManagement(unittest.TestCase):
    """ufw-style: list numbered, delete by number. Stable ordering is what
    makes the numbers safe to act on."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = trust.TrustStore(Path(self.tmp.name) / "t.json")
        import time
        for serial, raw in [("AAA", b"a"), ("BBB", b"b"), ("CCC", b"c")]:
            self.store.trust(Dev(serial=serial, raw=raw))
            time.sleep(0.001)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ordered_is_stable_by_trust_time(self):
        serials = [e.identity.split(":")[-1] for e in self.store.ordered()]
        self.assertEqual(serials, ["AAA", "BBB", "CCC"])

    def test_forget_by_number_removes_the_shown_entry(self):
        removed = self.store.forget_index(2)
        self.assertIn("BBB", removed)
        remaining = [e.identity.split(":")[-1] for e in self.store.ordered()]
        self.assertEqual(remaining, ["AAA", "CCC"])

    def test_forget_out_of_range_is_refused(self):
        self.assertIsNone(self.store.forget_index(0))
        self.assertIsNone(self.store.forget_index(99))
        self.assertEqual(len(self.store.ordered()), 3, "nothing removed")

    def test_numbers_renumber_after_a_delete(self):
        """After deleting [2], the old [3] becomes the new [2] -- exactly like
        ufw, so a second delete acts on what is now shown."""
        self.store.forget_index(2)               # removes BBB
        removed = self.store.forget_index(2)     # now removes CCC
        self.assertIn("CCC", removed)


# =========================================================================
# test_trust_integrity.py
#
# Regression tests for trust store integrity (audit finding C3, second half).
# =========================================================================

import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from probolos import privsep, trust


def good_entry(key="v:p:s#abc"):
    return {
        "key": key,
        "identity": "v:p:s",
        "label": "Kingston",
        "descriptor_hash": "abc",
        "trusted_at": 1.0,
        "last_seen": 2.0,
        "times_admitted": 3,
        "note": "",
        "ports": ["1-1"],
    }


class DirectorySeparation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = Path(self._d.name)

    def test_refuses_to_hand_over_a_directory_holding_trust(self):
        """The core of the fix: that directory must never be chowned away."""
        (self.root / "trusted.json").write_text("{}")
        ledger = self.root / "ledger.json"
        logged = []
        privsep.prepare_state_dir(ledger, uid=65534, gid=65534,
                                  log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged),
                        "handing over a trust-store directory was not refused")

    def test_a_clean_subdirectory_is_still_handed_over(self):
        """The refusals must not break the legitimate ledger path."""
        state = self.root / "state"
        state.mkdir()
        ledger = state / "ledger.json"
        logged = []
        # The tempdir is outside STATE_ROOTS, which is itself a refusal reason
        # (see test_refuses_a_directory_outside_the_state_roots). Point the
        # allowlist at it so this test exercises only the trust-store rule.
        with mock.patch.object(privsep, "STATE_ROOTS", (str(self.root),)):
            # chown will fail for non-root; what matters is that it was
            # ATTEMPTED, i.e. we got past both refusals.
            privsep.prepare_state_dir(ledger, uid=os.getuid(), gid=os.getgid(),
                                      log=logged.append)
        self.assertFalse(any("REFUSING" in line for line in logged))

    def test_refuses_a_directory_outside_the_state_roots(self):
        """
        A typo must not cost the machine: `--ledger /etc/x.json` would chown
        /etc to an unprivileged account at mode 0700, taking sudo, ssh and PAM
        with it on a running system.
        """
        logged = []
        privsep.prepare_state_dir("/etc/probolos-typo.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_traversal_out_of_a_state_root_is_refused(self):
        """realpath runs first, so ../ cannot smuggle a path back out."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos/../../../etc/x.json",
                                  uid=65534, gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_a_sibling_sharing_the_prefix_is_refused(self):
        """/var/lib/probolos-evil must not match /var/lib/probolos."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos-evil/x.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_trust_is_made_readable_not_writable(self):
        target = self.root / "trusted.json"
        target.write_text("{}")
        os.chmod(target, 0o600)
        privsep.prepare_trust_readable(target, log=lambda *_: None)
        mode = target.stat().st_mode & 0o777
        self.assertTrue(mode & 0o044, "analyzer cannot read the trust store")
        self.assertFalse(mode & 0o022, "trust store became group/other writable")


class EntryValidation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.path = Path(self._d.name) / "trusted.json"

    def _store_with(self, devices):
        self.path.write_text(json.dumps({
            "schema": trust.SCHEMA_VERSION, "devices": devices}))
        return trust.TrustStore(self.path)

    def test_a_well_formed_entry_loads(self):
        store = self._store_with({"v:p:s#abc": good_entry()})
        self.assertIn("v:p:s#abc", store.devices)

    def test_wrong_types_are_not_trusted(self):
        bad = good_entry()
        bad["descriptor_hash"] = 12345          # must be a string
        store = self._store_with({"v:p:s#abc": bad})
        self.assertEqual(store.devices, {})

    def test_missing_fingerprint_is_not_trusted(self):
        bad = good_entry()
        bad["descriptor_hash"] = ""             # pins trust to nothing
        store = self._store_with({"v:p:s#abc": bad})
        self.assertEqual(store.devices, {})

    def test_key_mismatch_is_rejected(self):
        """The shape that used to make trust un-revocable."""
        store = self._store_with({"filed-under-this": good_entry("but-says-this")})
        self.assertEqual(store.devices, {})

    def test_malformed_entries_are_reported_not_silent(self):
        bad = good_entry()
        bad["trusted_at"] = "yesterday"
        store = self._store_with({"v:p:s#abc": bad})
        self.assertIsNotNone(store.load_error)

    def test_forget_index_always_revokes(self):
        store = self._store_with({"v:p:s#abc": good_entry()})
        self.assertEqual(len(store.devices), 1)
        removed = store.forget_index(1)
        self.assertEqual(removed, "v:p:s")
        self.assertEqual(store.devices, {})


# =========================================================================
# test_atomicio.py
#
# Regression tests for the symlink-safe state writes (audit finding C3), and for
# =========================================================================

import fnmatch
import json
import os
import tempfile
import unittest
from pathlib import Path

from probolos import atomicio


class WriteJsonAtomic(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def _staging_leftovers(self, target: Path):
        pattern = atomicio.temp_glob_for(target)
        return [n for n in os.listdir(self.root)
                if fnmatch.fnmatch(n, pattern)]

    def test_normal_write_round_trips(self):
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"a": 1, "b": [2, 3]})
        self.assertEqual(json.loads(target.read_text()), {"a": 1, "b": [2, 3]})

    def test_staging_path_is_never_the_old_predictable_name(self):
        """
        The regression itself: with_suffix(".tmp") is a name anyone sharing the
        directory can compute, and computing it is all an attacker needs.
        """
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"a": 1})
        self.assertFalse((self.root / "store.tmp").exists())

    def test_planted_file_at_predictable_name_does_not_block_saves(self):
        """
        The denial of service O_EXCL introduced: an ordinary file squatting on
        the staging path used to make every future save fail with EEXIST.
        """
        target = self.root / "store.json"
        squat = self.root / "store.tmp"
        squat.write_text("squatting")

        atomicio.write_json_atomic(target, {"x": 1})
        atomicio.write_json_atomic(target, {"x": 2})

        self.assertEqual(json.loads(target.read_text()), {"x": 2})
        self.assertEqual(squat.read_text(), "squatting")

    def test_symlink_at_predictable_name_is_never_written_through(self):
        """
        The C3 property, restated for the new naming: whatever an attacker
        plants, the victim's contents are untouched.
        """
        target = self.root / "store.json"
        victim = self.root / "victim"
        victim.write_text("SACRED")
        os.symlink(victim, self.root / "store.tmp")

        atomicio.write_json_atomic(target, {"pwned": True})

        self.assertEqual(victim.read_text(), "SACRED")
        self.assertEqual(json.loads(target.read_text()), {"pwned": True})

    def test_symlink_at_our_own_staging_path_is_refused(self):
        """
        Directly: O_NOFOLLOW still refuses, for the (now unguessable) name we
        actually use. Proven by monkeypatching the name generator so the test
        can plant the symlink the attacker cannot find.
        """
        target = self.root / "store.json"
        victim = self.root / "victim"
        victim.write_text("SACRED")
        chosen = self.root / ".store.json.fixed.tmp"
        os.symlink(victim, chosen)

        original = atomicio._staging_path
        atomicio._staging_path = lambda _path: chosen
        try:
            with self.assertRaises(OSError):
                atomicio.write_json_atomic(target, {"pwned": True})
        finally:
            atomicio._staging_path = original

        self.assertEqual(victim.read_text(), "SACRED")
        self.assertFalse(target.exists())

    def test_mode_is_not_world_readable(self):
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"a": 1})
        mode = target.stat().st_mode & 0o077
        self.assertEqual(mode, 0, "state file must not be group/other accessible")

    def test_no_staging_file_is_left_behind(self):
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"first": 1})
        atomicio.write_json_atomic(target, {"second": 2})
        self.assertEqual(json.loads(target.read_text()), {"second": 2})
        self.assertEqual(self._staging_leftovers(target), [])

    def test_dotted_names_do_not_collide(self):
        """
        with_suffix REPLACES the last suffix, so probolos.state.json staged at
        probolos.state.tmp and two stores differing only after the final dot
        shared one staging path. Appending removes the whole class of collision.
        """
        a = self.root / "probolos.state.json"
        b = self.root / "probolos.state.db"
        atomicio.write_json_atomic(a, {"which": "a"})
        atomicio.write_json_atomic(b, {"which": "b"})
        self.assertEqual(json.loads(a.read_text()), {"which": "a"})
        self.assertEqual(json.loads(b.read_text()), {"which": "b"})


class SaveMethodsSurviveAPlantedTemp(unittest.TestCase):
    """The properties hold through the real save() call sites, not just the helper."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def test_trust_store_save_is_not_blocked_and_spares_the_victim(self):
        from probolos import trust
        victim = self.root / "victim"
        victim.write_text("SACRED")
        store = trust.TrustStore(self.root / "trusted.json")
        os.symlink(victim, self.root / "trusted.tmp")

        self.assertIsNone(store.save())
        self.assertEqual(victim.read_text(), "SACRED")

    def test_ledger_save_is_not_blocked_and_spares_the_victim(self):
        from probolos import ledger
        victim = self.root / "victim"
        victim.write_text("SACRED")
        store = ledger.Ledger(self.root / "ledger.json")
        os.symlink(victim, self.root / "ledger.tmp")

        self.assertIsNone(store.save())
        self.assertEqual(victim.read_text(), "SACRED")


if __name__ == "__main__":
    unittest.main()
