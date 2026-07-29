"""
Tests for remembered devices (allowlist) and for stage 4 medium inspection.

The trust tests exist to pin one property above all: trust must never be able
to silence a CRITICAL finding. An allowlist that can be used to wave through an
attack is worse than no allowlist, because it converts a moment of impatience
into a permanent hole.

The storage tests, as with every rule in this project, lead with layouts that
must stay SILENT. Ordinary USB sticks are formatted in a handful of ways and
every one of them has to pass without comment.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from cerberus import rules, storage, trust


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
