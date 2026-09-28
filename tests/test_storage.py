"""
Stage 4 and media: partition tables, filesystem signatures and forged ones,
storage findings, and the card-reader media watch.

Covers probolos.storage, probolos.storage_hardening and probolos.mediawatch.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from probolos import gate_server, mediawatch, report, rules, storage, sysfs, usbclass
from probolos import ledger as ledger_mod
from probolos import report as report_mod
from tests import _media
from tests._support import _TreeCase

DEVICE_BYTES = 128 * 1024


STICK_SECTORS = 7866368           # the 3.8 GiB stick from the report


def _pvd_image(mutate=None, **kwargs):
    """A valid ISO 9660 image whose PVD (at 0x8000) `mutate` may damage."""
    data = _media.iso9660_image(DEVICE_BYTES, **kwargs)
    if mutate:
        mutate(memoryview(data)[0x8000:0x8800])
    return data


class _Inspect(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def inspect(self, data, sectors=None):
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        size = sectors if sectors is not None else len(data) // storage.SECTOR
        with mock.patch.object(storage, "read_size_sectors",
                               return_value=size):
            return storage.inspect(path)

    def assertRefused(self, data, reason, sectors=None):
        medium = self.inspect(data, sectors)
        self.assertEqual(medium.signatures, {})
        self.assertEqual(len(medium.hollow_signatures), 1)
        self.assertIn(reason, medium.hollow_signatures[0])
        return medium


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class FakeReader:
    """Just enough of a UsbDevice for the watcher, the ledger and one_liner."""

    def __init__(self, syspath, kinds=None, safe=True):
        self.syspath = Path(syspath)
        self.name = self.syspath.name
        st = os.stat(syspath)
        self.instance_id = (st.st_dev, st.st_ino)
        self.kinds = kinds or [usbclass.KIND_STORAGE]
        self.inspection_safe = safe
        self.vendor_id, self.product_id = "0bda", "0158"
        self.serial = "READER1"
        self.claims = ["Mass Storage (SCSI)"]
        self.manufacturer, self.product = "Generic", "Card Reader"

    def label(self):
        return "Generic Card Reader"


def mbr(*entries, size_sectors=None):
    """A 512-byte MBR; entries are (type_byte, start, sectors, bootable)."""
    data = bytearray(512)
    for i, (ptype, start, sectors, boot) in enumerate(entries):
        struct.pack_into("<BBBBBBBBII", data, 446 + i * 16,
                         0x80 if boot else 0, 0, 0, 0, ptype, 0, 0, 0,
                         start, sectors)
    struct.pack_into("<H", data, 510, 0xAA55)
    return bytes(data)


def gpt_image(entries, entries_lba=2):
    """Protective MBR + GPT header + entries, as HEADER_READ would see it."""
    data = bytearray(storage.HEADER_READ)
    data[:512] = mbr((0xEE, 1, 100000, False))
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<QII", header, 72, entries_lba, 128, 128)
    data[512:512 + 92] = header
    for i, (guid, attrs) in enumerate(entries):
        off = 1024 + i * 128
        data[off:off + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<Q", data, off + 48, attrs)
    return bytes(data)


def medium(partitions=(), scheme="mbr", size=62333952, signatures=None,
           gpt_entries=(), error=None):
    return storage.MediumReport(
        device="/dev/sdz", size_sectors=size, scheme=scheme,
        partitions=[storage.Partition(i, b, t, s, n)
                    for i, (t, s, n, b) in enumerate(partitions)],
        signatures=dict(signatures or {}), gpt_entries=list(gpt_entries),
        gpt_entries_parsed=scheme == "gpt", error=error)


FAT_CARD = dict(partitions=[(0x0C, 8192, 62325760, False)],
                signatures={0: "FAT32"})


ESP_CARD = dict(partitions=[(0xEF, 2048, 1048576, False),
                            (0x0C, 1050624, 61283328, False)])


# ---------------------------------------------------------------------------
# 4. The watcher, over a synthetic sysfs tree
# ---------------------------------------------------------------------------

class WatcherTestBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.host = root / "sys/devices/pci0/usb1/1-2"
        self.lun = self.host / "1-2:1.0/host6/target6:0:0/6:0:0:1"
        self.disk = self.lun / "block/sdz"
        self.disk.mkdir(parents=True)
        os.symlink(self.lun, self.disk / "device")
        (self.disk / "events").write_text("media_change\n")
        (self.disk / "events_poll_msecs").write_text("2000\n")
        self.other = root / "sys/devices/pci0/ata1/host0/block/sdy"
        self.other.mkdir(parents=True)
        self.mounts = root / "mounts"
        self.mounts.write_text("")
        self.logfile = root / "audit.jsonl"

        self.size = 62333952
        self.card = medium(**FAT_CARD)
        self.inspected = []
        self.writes = []
        self.lines = []
        self.deauthorized = []

        def fake_inspect(disk):
            self.inspected.append(disk)
            return self.card

        for target, attr, value in (
                (storage, "read_size_sectors", lambda _d: self.size),
                (mediawatch.MediaWatch, "_inspect",
                 staticmethod(fake_inspect)),
                (mediawatch, "PROC_MOUNTS", str(self.mounts)),
                (sysfs, "set_authorized",
                 lambda p, v: self.writes.append((str(p), v)))):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)

        self.reader = FakeReader(self.host)
        self.ledger = ledger_mod.Ledger(root / "ledger.json")

    def watcher(self, policy=mediawatch.POLICY_LOG, locked=False):
        w = mediawatch.MediaWatch(
            policy=policy, ledger=self.ledger, json_log=self.logfile,
            is_locked=lambda: locked, log=self.lines.append,
            on_deauthorized=lambda dev, f: self.deauthorized.append(dev))
        self.assertTrue(w.register(self.reader, "test"))
        return w

    def change(self, w, props=None):
        w.handle("change", str(self.disk),
                 dict({"DEVTYPE": "disk", "DISK_MEDIA_CHANGE": "1"},
                      **(props or {})))

    def output(self):
        return "\n".join(str(line) for line in self.lines)


IMAGE_BYTES = 128 * 1024


def _mbr_with(ptype, start, sectors):
    data = bytearray(IMAGE_BYTES)
    struct.pack_into("<BBBBBBBBII", data, 446,
                     0, 0, 0, 0, ptype, 0, 0, 0, start, sectors)
    data[510:512] = b"\x55\xaa"
    return data


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


def simple_medium(partitions, size_sectors, signatures=None, scheme="mbr"):
    return storage.MediumReport(
        device="/dev/sdb", size_sectors=size_sectors, scheme=scheme,
        partitions=partitions, signatures=signatures or {})


class PartitionSignaturesAreReachable(unittest.TestCase):
    """Per-partition reads were one sector: ext and btrfs magics never fit."""

    def _image(self, magic_offset, magic, part_type):
        path = os.path.join(self.tmp, "disk.img")
        data = bytearray(1024 * 1024)
        struct.pack_into("<BBBBBBBBII", data, 446,
                         0, 0, 0, 0, part_type, 0, 0, 0, 128, 1024)
        data[510:512] = b"\x55\xaa"
        data[128 * 512 + magic_offset:128 * 512 + magic_offset + len(magic)] = magic
        with open(path, "wb") as fh:
            fh.write(data)
        return path, len(data) // 512

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _inspect(self, path, sectors):
        with mock.patch.object(storage, "read_size_sectors",
                               return_value=sectors):
            return storage.inspect(path)

    def test_ext_inside_a_fat_partition_is_recognised(self):
        report = self._inspect(*self._image(0x438, b"\x53\xef", 0x0C))
        self.assertEqual(report.signatures.get(0), "ext2/3/4")

    def test_btrfs_inside_a_partition_is_recognised(self):
        report = self._inspect(*self._image(0x10040, b"_BHRfS_M", 0x83))
        self.assertEqual(report.signatures.get(0), "btrfs")


class TheDecoyFromTheReport(_Inspect):
    """Acceptance 1: `printf '\\x01CD001\\x01' | dd seek=32768` on zeros."""

    def decoy(self):
        data = bytearray(DEVICE_BYTES)
        data[0x8000:0x8007] = b"\x01CD001\x01"
        return data

    def test_is_not_reported_as_iso9660(self):
        medium = self.assertRefused(self.decoy(), "ISO 9660 signature",
                                    STICK_SECTORS)
        self.assertEqual(medium.scheme, "none")

    def test_operator_sees_no_known_filesystem_and_why(self):
        medium = self.inspect(self.decoy(), STICK_SECTORS)
        findings = rules.storage_findings(medium)
        self.assertEqual([f.rule_id for f in findings],
                         ["filesystem-signature-without-structure"])
        self.assertEqual(findings[0].severity, rules.Severity.NOTICE)
        text = report_mod.render_medium(medium, findings)
        self.assertIn("contains no known filesystem", text)
        self.assertNotIn("ISO 9660 filesystem", text)
        self.assertIn("NOTICE", text)
        self.assertEqual(findings[0].title,
                         "A filesystem signature is present without the "
                         "filesystem")

    def test_the_rule_can_be_disabled_like_any_other(self):
        cfg = rules.RuleConfig(disabled={"filesystem-signature-without-structure"})
        medium = self.inspect(self.decoy(), STICK_SECTORS)
        self.assertEqual(rules.storage_findings(medium, cfg), [])


class GenuineVolumesStillPass(_Inspect):
    """Acceptance 2 and 3."""

    def test_valid_volume_is_iso9660_with_no_finding(self):
        medium = self.inspect(_pvd_image(), STICK_SECTORS)
        self.assertEqual(medium.signatures, {-1: "ISO 9660"})
        self.assertEqual(medium.hollow_signatures, [])
        self.assertEqual(rules.storage_findings(medium), [])
        self.assertIn("whole-device ISO 9660 filesystem (no partition table)",
                      report_mod.render_medium(medium, []))

    def test_el_torito_boot_record_before_the_pvd(self):
        boot = _media.descriptor(0, b"CD001")
        self.assertEqual(self.inspect(_pvd_image(before=[boot])).signatures,
                         {-1: "ISO 9660"})

    def test_joliet_and_enhanced_descriptors_after_the_pvd(self):
        joliet = _media.descriptor(2, b"CD001", 1)
        enhanced = _media.descriptor(2, b"CD001", 2)
        data = _pvd_image(after=[joliet, enhanced])
        self.assertEqual(self.inspect(data).signatures, {-1: "ISO 9660"})

    def test_volume_filling_the_device_exactly(self):
        data = _pvd_image(volume_blocks=DEVICE_BYTES // 2048)
        self.assertEqual(self.inspect(data).signatures, {-1: "ISO 9660"})

    def test_all_zero_device_is_unchanged(self):
        medium = self.inspect(bytearray(DEVICE_BYTES), STICK_SECTORS)
        self.assertEqual((medium.signatures, medium.hollow_signatures), ({}, []))
        self.assertIn("contains no known filesystem",
                      report_mod.render_medium(medium, []))


class EachStructuralCheckBites(_Inspect):
    """One damaged field at a time; each must be enough to refuse."""

    def test_volume_space_size_encodings_disagree(self):
        def damage(pvd):
            pvd[84:88] = (65).to_bytes(4, "big")
        self.assertRefused(_pvd_image(damage), "volume space size")

    def test_volume_space_size_zero(self):
        def damage(pvd):
            pvd[80:88] = bytes(8)
        self.assertRefused(_pvd_image(damage), "volume space size")

    def test_block_size_4096_is_not_iso9660(self):
        """ECMA-119: no larger than the 2048-byte logical sector."""
        self.assertRefused(_pvd_image(block_size=4096, volume_blocks=16),
                           "logical block size")

    def test_block_size_encodings_disagree(self):
        def damage(pvd):
            pvd[130:132] = (1024).to_bytes(2, "big")
        self.assertRefused(_pvd_image(damage), "logical block size")

    def test_volume_set_sequence_beyond_set_size(self):
        def damage(pvd):
            pvd[124:128] = (3).to_bytes(2, "little") + (3).to_bytes(2, "big")
        self.assertRefused(_pvd_image(damage), "volume set size")

    def test_path_table_size_encodings_disagree(self):
        def damage(pvd):
            pvd[136:140] = (11).to_bytes(4, "big")
        self.assertRefused(_pvd_image(damage), "path table size")

    def test_pvd_version_other_than_1(self):
        def damage(pvd):
            pvd[6] = 2
        self.assertRefused(_pvd_image(damage), "version 2")

    def test_root_record_is_not_a_directory(self):
        def damage(pvd):
            pvd[156 + 25] = 0x00
        self.assertRefused(_pvd_image(damage), "root directory record")

    def test_root_record_extent_outside_the_volume(self):
        def damage(pvd):
            pvd[158:166] = (64).to_bytes(4, "little") + (64).to_bytes(4, "big")
        self.assertRefused(_pvd_image(damage), "root directory record")

    def test_file_structure_version(self):
        def damage(pvd):
            pvd[881] = 0
        self.assertRefused(_pvd_image(damage), "file structure version")

    def test_volume_larger_than_the_device(self):
        self.assertRefused(_pvd_image(volume_blocks=65), "claims 133120 bytes")

    def test_no_terminator(self):
        data = _media.image(DEVICE_BYTES, 0x8000,
                            _media.primary_volume_descriptor())
        self.assertRefused(data, "without a terminator")

    def test_no_primary_volume_descriptor(self):
        data = _media.image(DEVICE_BYTES, 0x8000,
                            _media.descriptor(0, b"CD001"),
                            _media.descriptor(0xFF, b"CD001"))
        self.assertRefused(data, "no primary volume descriptor")

    def test_undefined_descriptor_type(self):
        data = _pvd_image(after=[_media.descriptor(7, b"CD001")])
        self.assertRefused(data, "undefined type 7")

    def test_terminator_never_reached_within_the_bound(self):
        svds = [_media.descriptor(2, b"CD001")] * storage.OPTICAL_MAX_DESCRIPTORS
        data = _pvd_image(after=svds)
        self.assertRefused(data, "no set terminator")

    def test_descriptor_set_cut_off_by_the_end_of_the_device(self):
        data = _media.image(0x8800 + 16, 0x8000,
                            _media.iso9660_descriptors())[:0x8800 + 16]
        self.assertRefused(data, "cut off")


class UdfNeedsItsRecognitionSequence(_Inspect):

    def slot(self, ident, stype=0, version=1, size=0x800):
        slot = bytearray(size)
        slot[0], slot[1:6], slot[6] = stype, ident, version
        return bytes(slot)

    def test_bare_nsr02_is_refused(self):
        data = _media.image(DEVICE_BYTES, 0x8800, self.slot(b"NSR02"))
        self.assertRefused(data, "UDF signature")

    def test_nsr_without_tea01(self):
        data = _media.image(DEVICE_BYTES, 0x8000,
                            self.slot(b"BEA01"), self.slot(b"NSR03"))
        self.assertRefused(data, "UDF signature")

    def test_out_of_order_sequence(self):
        data = _media.image(DEVICE_BYTES, 0x8000, self.slot(b"BEA01"),
                            self.slot(b"TEA01"), self.slot(b"NSR02"))
        self.assertRefused(data, "UDF signature")

    def test_wrong_descriptor_version(self):
        data = _media.image(DEVICE_BYTES, 0x8000, self.slot(b"BEA01"),
                            self.slot(b"NSR02", version=0),
                            self.slot(b"TEA01"))
        self.assertRefused(data, "UDF signature")

    def test_valid_sequences(self):
        for label, data in (
                ("2k", _media.image(DEVICE_BYTES, 0x8000, _media.udf_vrs())),
                ("4k", _media.image(DEVICE_BYTES, 0x8000,
                                    _media.udf_vrs(0x1000, b"NSR03")))):
            with self.subTest(label):
                medium = self.inspect(data)
                self.assertEqual(medium.signatures, {-1: "UDF"})
                self.assertEqual(medium.hollow_signatures, [])

    def test_bridge_with_a_forged_iso_half_claims_only_udf(self):
        """The label names what checked out, and the rest is reported."""
        data = _media.image(DEVICE_BYTES, 0x8000,
                            _media.descriptor(1, b"CD001"),
                            _media.descriptor(0xFF, b"CD001"),
                            _media.udf_vrs())
        medium = self.inspect(data)
        self.assertEqual(medium.signatures, {-1: "UDF"})
        self.assertIn("ISO 9660 signature", medium.hollow_signatures[0])


class InsideAPartition(_Inspect):

    def mbr(self, data, ptype=0x17, start=128, sectors=200):
        struct.pack_into("<BBBBBBBBII", data, 446,
                         0x80, 0, 0, 0, ptype, 0, 0, 0, start, sectors)
        data[510:512] = b"\x55\xaa"
        return data

    def test_forged_magic_in_a_partition_is_reported_by_partition(self):
        data = bytearray(DEVICE_BYTES * 2)
        data[128 * 512 + 0x8000:128 * 512 + 0x8007] = b"\x01CD001\x01"
        medium = self.inspect(self.mbr(data))
        self.assertEqual(medium.signatures, {})
        self.assertTrue(medium.hollow_signatures[0].startswith("partition 1:"))

    def test_real_volume_in_a_partition(self):
        data = bytearray(DEVICE_BYTES * 2)
        iso = _media.iso9660_descriptors()
        data[128 * 512 + 0x8000:128 * 512 + 0x8000 + len(iso)] = iso
        self.assertEqual(self.inspect(self.mbr(data)).signatures,
                         {0: "ISO 9660"})

    def test_partition_volume_is_bounded_by_the_device_end(self):
        """The partition length is the medium's claim; the device's is not."""
        data = bytearray(DEVICE_BYTES * 2)
        iso = _media.iso9660_descriptors(volume_blocks=100)
        data[128 * 512 + 0x8000:128 * 512 + 0x8000 + len(iso)] = iso
        medium = self.inspect(self.mbr(data))
        self.assertIn("claims 204800 bytes", medium.hollow_signatures[0])


@unittest.skipUnless(shutil.which("xorriso") or shutil.which("genisoimage")
                     or shutil.which("mkudffs"),
                     "no ISO/UDF mastering tool installed")
class RealMasteringTools(_Inspect):
    """Positive control against what real tools write, when they exist."""

    def build(self, argv, out):
        tree = os.path.join(self.tmp, "tree")
        os.makedirs(os.path.join(tree, "boot"), exist_ok=True)
        with open(os.path.join(tree, "readme.txt"), "w") as fh:
            fh.write("hello\n")
        subprocess.run(argv + [tree], check=True, capture_output=True)
        with open(out, "rb") as fh:
            return fh.read(storage.PARTITION_SNIFF_READ + 4096)

    def check(self, tool, args, expected):
        if not shutil.which(tool):
            self.skipTest(f"{tool} not installed")
        out = os.path.join(self.tmp, "out.iso")
        head = self.build([tool] + args + ["-o", out], out)
        medium = self.inspect(head + bytes(64), STICK_SECTORS)
        self.assertEqual(medium.signatures, {-1: expected})
        self.assertEqual(medium.hollow_signatures, [])

    def test_xorriso_joliet_rock_ridge(self):
        self.check("xorriso", ["-as", "mkisofs", "-J", "-R"], "ISO 9660")

    def test_genisoimage_level4(self):
        self.check("genisoimage", ["-iso-level", "4"], "ISO 9660")

    def test_genisoimage_udf_bridge(self):
        self.check("genisoimage", ["-udf", "-J", "-R"],
                   "UDF (ISO 9660 bridge)")

    def test_mkudffs_block_sizes(self):
        if not shutil.which("mkudffs"):
            self.skipTest("mkudffs not installed")
        for block in (512, 2048, 4096):
            with self.subTest(block=block):
                img = os.path.join(self.tmp, f"udf{block}.img")
                with open(img, "wb") as fh:
                    fh.truncate(8 * 1024 * 1024)
                subprocess.run(["mkudffs", "--media-type=hd",
                                f"--blocksize={block}", img],
                               check=True, capture_output=True)
                with open(img, "rb") as fh:
                    head = fh.read(storage.PARTITION_SNIFF_READ)
                self.assertEqual(self.inspect(head, STICK_SECTORS).signatures,
                                 {-1: "UDF"})


# ---------------------------------------------------------------------------
# 1. GPT entries are read, within the bytes already read
# ---------------------------------------------------------------------------

class GptEntriesAreParsed(unittest.TestCase):

    def test_esp_and_hidden_attribute_are_found(self):
        data = gpt_image([(storage.GPT_ESP_GUID, 0),
                          ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                           storage.GPT_ATTR_HIDDEN)])
        entries = storage.parse_gpt_entries(data)
        self.assertEqual([e.type_guid for e in entries],
                         [storage.GPT_ESP_GUID,
                          "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"])
        self.assertTrue(entries[1].attributes & storage.GPT_ATTR_HIDDEN)

    def test_entries_elsewhere_are_not_chased(self):
        """The header chooses where its entries are; we do not read there."""
        data = gpt_image([(storage.GPT_ESP_GUID, 0)], entries_lba=4096)
        self.assertIsNone(storage.parse_gpt_entries(data))

    def test_inspect_records_them(self):
        data = gpt_image([(storage.GPT_ESP_GUID, 0)])
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(data + bytes(storage.PARTITION_SNIFF_READ))
            fh.flush()
            with mock.patch.object(storage, "read_size_sectors",
                                   return_value=200000):
                report = storage.inspect(fh.name)
        self.assertEqual(report.scheme, "gpt")
        self.assertTrue(report.gpt_entries_parsed)
        self.assertEqual(report.gpt_entries[0].type_guid, storage.GPT_ESP_GUID)


# ---------------------------------------------------------------------------
# 2. The media rules
# ---------------------------------------------------------------------------

class MediaRules(unittest.TestCase):

    def ids(self, findings):
        return {f.rule_id: f.severity for f in findings}

    def test_an_ordinary_card_produces_nothing(self):
        self.assertEqual(rules.media_findings(medium(**FAT_CARD)), [])

    def test_mbr_efi_system_partition_is_critical(self):
        found = self.ids(rules.media_findings(medium(**ESP_CARD)))
        self.assertEqual(found["media-efi-system-partition"],
                         rules.Severity.CRITICAL)

    def test_gpt_efi_system_partition_is_critical(self):
        esp = storage.GptEntry(0, storage.GPT_ESP_GUID, 0)
        found = self.ids(rules.media_findings(
            medium(partitions=[(0xEE, 1, 1000, False)], scheme="gpt",
                   gpt_entries=[esp])))
        self.assertIn("media-efi-system-partition", found)

    def test_hidden_partition_is_critical(self):
        found = self.ids(rules.media_findings(
            medium(partitions=[(0x1C, 2048, 1000, False)])))
        self.assertEqual(found["media-hidden-partition"],
                         rules.Severity.CRITICAL)

    def test_new_layout_is_a_warning_and_a_known_one_a_notice(self):
        new = self.ids(rules.media_findings(medium(**FAT_CARD), drift="aa"))
        known = self.ids(rules.media_findings(medium(**FAT_CARD), drift="aa",
                                              drift_known=True))
        self.assertEqual(new["media-layout-drift"], rules.Severity.WARNING)
        self.assertEqual(known["media-layout-drift"], rules.Severity.NOTICE)

    def test_insert_while_locked_is_reported_even_if_unreadable(self):
        found = self.ids(rules.media_findings(
            medium(error="its block device could not be read"), locked=True))
        self.assertEqual(set(found), {"media-inserted-while-locked"})

    def test_severity_is_overridable_like_every_other_rule(self):
        cfg = rules.RuleConfig(severity_overrides={
            "media-efi-system-partition": rules.Severity.NOTICE})
        found = self.ids(rules.media_findings(medium(**ESP_CARD), config=cfg))
        self.assertEqual(found["media-efi-system-partition"],
                         rules.Severity.NOTICE)


class WatcherBehaviour(WatcherTestBase):

    def test_a_card_in_a_watched_reader_is_inspected_and_reported(self):
        w = self.watcher()
        self.change(w)
        self.assertEqual(self.inspected, ["sdz"])
        self.assertIn("MEDIUM CHANGE", self.output())
        self.assertIn("LUN 1", self.output())
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertEqual(entry["event"], "media-change")
        self.assertEqual(entry["enforcement"], "logged")

    def test_a_disk_that_is_not_a_watched_readers_is_ignored(self):
        w = self.watcher()
        w.handle("change", str(self.other), {"DEVTYPE": "disk"})
        self.assertEqual(self.inspected, [])

    def test_partitions_are_ignored(self):
        w = self.watcher()
        w.handle("change", str(self.disk) + "/sdz1", {"DEVTYPE": "partition"})
        self.assertEqual(self.inspected, [])

    def test_an_empty_slot_is_not_read_and_a_removal_is_logged(self):
        w = self.watcher()
        self.size = 0
        self.change(w)
        self.assertEqual(self.inspected, [])
        self.size = 62333952
        self.change(w)
        self.size = 0
        self.change(w)
        self.assertIn("medium removed", self.output())

    def test_repeated_change_for_the_same_medium_is_reported_once(self):
        w = self.watcher()
        self.change(w)
        w.handle("change", str(self.disk), {"DEVTYPE": "disk"})  # rescan
        self.assertEqual(self.output().count("MEDIUM CHANGE"), 1)

    def test_a_different_card_is_drift_against_the_first(self):
        w = self.watcher()
        self.change(w)
        self.card = medium(partitions=[(0x07, 2048, 1000000, False)],
                           signatures={0: "exFAT"})
        self.change(w)
        self.assertIn("A medium this slot has never seen", self.output())

    def test_the_report_says_when_the_read_was_post_hoc(self):
        w = self.watcher()
        self.mounts.write_text("/dev/sdz1 /run/media/u/CARD vfat rw 0 0\n")
        self.change(w)
        self.assertIn("ALREADY MOUNTED", self.output())

    def test_the_report_says_when_automount_was_inhibited(self):
        w = self.watcher()
        self.change(w, {"UDISKS_AUTO": "0"})
        self.assertIn("inhibited for udisks", self.output())

    def test_the_report_says_when_automount_was_not_inhibited(self):
        w = self.watcher()
        self.change(w)
        self.assertIn("NOT inhibited", self.output())

    def test_a_slot_that_cannot_report_changes_is_flagged(self):
        (self.disk / "events").write_text("\n")
        w = self.watcher()
        self.change(w)
        self.assertIn("does not report media changes", self.output())

    def test_a_recycled_port_is_not_watched(self):
        w = self.watcher()
        w.hosts["1-2"].instance = (0, 0)
        self.change(w)
        self.assertEqual(self.inspected, [])
        self.assertNotIn("1-2", w.hosts)

    def test_a_composite_reader_is_never_registered(self):
        w = mediawatch.MediaWatch(log=self.lines.append)
        for kinds in ([usbclass.KIND_STORAGE, usbclass.KIND_INPUT],
                      [usbclass.KIND_STORAGE, usbclass.KIND_OTHER]):
            self.assertFalse(w.register(FakeReader(self.host, kinds), "t"))
        self.assertFalse(w.register(FakeReader(self.host, safe=False), "t"))

    def test_locked_session_is_a_finding(self):
        w = self.watcher(locked=True)
        self.change(w)
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertIn("media-inserted-while-locked",
                      [f["rule"] for f in entry["findings"]])


class WatcherEnforcement(WatcherTestBase):

    def test_log_policy_never_touches_the_reader(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_LOG)
        self.change(w)
        self.assertEqual(self.writes, [])
        self.assertIn("reader stays authorized", self.output())

    def test_deauthorize_policy_drops_the_whole_reader_on_critical(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        self.change(w)
        self.assertEqual(self.writes, [(str(self.host), 0)])
        self.assertEqual(self.deauthorized, [self.reader])
        self.assertNotIn("1-2", w.hosts)
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertEqual(entry["enforcement"], "reader deauthorized")

    def test_deauthorize_policy_ignores_anything_below_critical(self):
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        self.change(w)
        self.card = medium(partitions=[(0x07, 2048, 1000000, False)])
        self.change(w)                       # drift: WARNING only
        self.assertEqual(self.writes, [])

    def test_a_refused_deauthorization_is_loud(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        with mock.patch.object(sysfs, "set_authorized",
                               side_effect=OSError("denied")):
            self.change(w)
        self.assertIn("COULD NOT DEAUTHORIZE", self.output())
        self.assertEqual(self.deauthorized, [])

    def test_unknown_policy_is_refused(self):
        with self.assertRaises(ValueError):
            mediawatch.MediaWatch(policy="block-the-card")


# ---------------------------------------------------------------------------
# 5. Block device names
# ---------------------------------------------------------------------------

class OnlyWholeUsbDisksAreEverOpened(unittest.TestCase):
    """
    The directory entry under `block/` was concatenated straight into
    "/dev/{name}" and handed to os.open() in the direct backend. The
    privileged gate refuses anything but /dev/sdX, so under --privsep this was
    a denied request -- but the direct backend has no such gate, and the two
    halves must agree about what a whole USB disk is rather than one relying
    on the other.
    """

    def _tree(self, *names):
        root = Path(tempfile.mkdtemp())
        block = root / "host0" / "target" / "block"
        block.mkdir(parents=True)
        for name in names:
            (block / name).mkdir()
        return root

    def test_a_traversal_name_is_refused(self):
        """
        ".." cannot be mkdir'd, so the escape is exercised through the filter
        with the names os.walk would hand it. A name containing a separator or
        a dot-dot leaves /dev entirely once concatenated into "/dev/{name}",
        which is what made this a containment failure rather than a tidiness
        one.
        """
        for hostile in ("..", "../../etc/shadow", "sda/../../dev/nvme0n1",
                        ".", "", "sd a"):
            self.assertFalse(storage._WHOLE_DISK_NAME.match(hostile),
                             f"{hostile!r} must never become a /dev path")

    def test_a_plausible_tree_yields_only_the_whole_disk(self):
        root = self._tree("sda", "sda1")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sda"])

    def test_a_partition_node_is_refused(self):
        """
        Probolos inspects the medium it was handed, not a partition of it: a
        partition node would let it reach into a disk it was never asked about.
        """
        root = self._tree("sda", "sda1", "sda2")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sda"])

    def test_an_internal_disk_name_is_refused(self):
        root = self._tree("nvme0n1", "mmcblk0", "sdb")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sdb"])

    def test_mapper_and_loop_names_are_refused(self):
        root = self._tree("dm-0", "loop3", "sdc")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sdc"])

    def test_the_gate_and_the_finder_agree(self):
        """
        Same rule on both sides of the split. If these two regexes ever drift,
        one deployment mode silently inspects something the other refuses.
        """
        for name in ("sda", "sdz", "sdaa"):
            self.assertTrue(storage._WHOLE_DISK_NAME.match(name))
            self.assertTrue(gate_server._BLOCK_NAME.match(name))
        for name in ("sda1", "nvme0n1", "dm-0", "..", "loop0", ""):
            self.assertFalse(storage._WHOLE_DISK_NAME.match(name))
            self.assertFalse(gate_server._BLOCK_NAME.match(name))


class PartitionlessMedia(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _inspect(self, data):
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        with mock.patch.object(storage, "read_size_sectors",
                               return_value=len(data) // storage.SECTOR):
            return storage.inspect(path)

    # -- 1. the regression ---------------------------------------------------

    def test_raw_iso9660_image_is_recognised(self):
        """LBA 0 all zeros, a real PVD set from 0x8000: the Slax stick."""
        data = _media.iso9660_image(IMAGE_BYTES)
        report = self._inspect(data)
        self.assertIsNone(report.error)
        self.assertEqual(report.scheme, "none")
        self.assertEqual(report.signatures.get(-1), "ISO 9660")

    def test_rendered_report_no_longer_says_no_known_filesystem(self):
        data = _media.iso9660_image(IMAGE_BYTES)
        text = report_mod.render_medium(self._inspect(data), [])
        self.assertIn("whole-device ISO 9660 filesystem", text)
        self.assertNotIn("no known", text)

    def test_isohybrid_with_mbr_boot_code_but_no_partitions(self):
        """Boot code and 0x55AA in the system area, empty partition table."""
        data = _media.iso9660_image(IMAGE_BYTES)
        data[0:4] = b"\xeb\x63\x90\x00"
        data[510:512] = b"\x55\xaa"
        self.assertEqual(self._inspect(data).signatures.get(-1), "ISO 9660")

    def test_udf_is_recognised(self):
        data = _media.image(IMAGE_BYTES, 0x8000, _media.udf_vrs())
        self.assertEqual(self._inspect(data).signatures.get(-1), "UDF")

    def test_udf_with_4k_blocks_is_recognised(self):
        data = _media.image(IMAGE_BYTES, 0x8000,
                            _media.udf_vrs(stride=0x1000, nsr=b"NSR03"))
        self.assertEqual(self._inspect(data).signatures.get(-1), "UDF")

    def test_udf_iso_bridge_is_reported_as_both(self):
        data = _media.image(IMAGE_BYTES, 0x8000,
                            _media.iso9660_descriptors(), _media.udf_vrs())
        self.assertEqual(self._inspect(data).signatures.get(-1),
                         "UDF (ISO 9660 bridge)")

    def test_bea01_alone_is_not_udf(self):
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x00BEA01"
        self.assertIsNone(self._inspect(data).signatures.get(-1))

    def test_btrfs_without_a_partition_table_is_recognised(self):
        """Same short-read cause: 0x10040 was never reached at LBA 0."""
        data = bytearray(IMAGE_BYTES)
        data[0x10040:0x10048] = b"_BHRfS_M"
        self.assertEqual(self._inspect(data).signatures.get(-1), "btrfs")

    # -- 2..5. behaviour that must not change --------------------------------

    def test_fat32_inside_an_mbr_partition_is_unchanged(self):
        data = _mbr_with(0x0C, 128, 64)
        data[128 * 512 + 82:128 * 512 + 87] = b"FAT32"
        report = self._inspect(data)
        self.assertEqual(report.scheme, "mbr")
        self.assertEqual(report.signatures, {0: "FAT32"})

    def test_superfloppy_fat32(self):
        data = bytearray(IMAGE_BYTES)
        data[82:90] = b"FAT32   "
        data[510:512] = b"\x55\xaa"
        self.assertEqual(self._inspect(data).signatures.get(-1), "FAT32")

    def test_superfloppy_exfat(self):
        data = bytearray(IMAGE_BYTES)
        data[3:11] = b"EXFAT   "
        data[510:512] = b"\x55\xaa"
        self.assertEqual(self._inspect(data).signatures.get(-1), "exFAT")

    def test_lba0_filesystem_wins_over_system_area_contents(self):
        """A FAT boot sector at LBA 0 is what the medium is mounted as."""
        data = bytearray(IMAGE_BYTES)
        data[82:90] = b"FAT32   "
        data[510:512] = b"\x55\xaa"
        data[0x8000:0x8006] = b"\x01CD001"
        self.assertEqual(self._inspect(data).signatures.get(-1), "FAT32")

    def test_gpt_is_still_gpt(self):
        data = _mbr_with(storage.PROTECTIVE_MBR_TYPE, 1, 255)
        data[512:520] = storage.GPT_SIGNATURE
        self.assertEqual(self._inspect(data).scheme, "gpt")

    # -- 6. a genuinely blank medium -----------------------------------------

    def test_blank_device_still_reports_no_known_filesystem(self):
        report = self._inspect(bytearray(IMAGE_BYTES))
        self.assertEqual(report.scheme, "none")
        self.assertEqual(report.signatures, {})
        text = report_mod.render_medium(report, [])
        self.assertIn("contains no known filesystem", text)

    def test_raw_iso_raises_no_storage_findings(self):
        data = _media.iso9660_image(IMAGE_BYTES)
        self.assertEqual(rules.storage_findings(self._inspect(data)), [])

    # -- 7. short media and the read path ------------------------------------

    def test_device_shorter_than_the_descriptor_area_does_not_raise(self):
        for size in (storage.SECTOR, 0x8000, 0x8003):
            with self.subTest(size=size):
                report = self._inspect(bytearray(size))
                self.assertIsNone(report.error)
                self.assertEqual(report.signatures, {})

    def test_iso_descriptor_cut_off_by_end_of_device(self):
        data = bytearray(0x8004)
        data[0x8000:0x8004] = b"\x01CD0"
        self.assertEqual(self._inspect(data).signatures, {})

    def test_second_read_uses_the_same_descriptor(self):
        """Under --privsep there is exactly one fd; nothing may reopen."""
        data = _media.iso9660_image(IMAGE_BYTES)
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        fd = os.open(path, os.O_RDONLY)
        opens = []

        def open_fn(dev):
            opens.append(dev)
            return fd

        with mock.patch.object(storage, "read_size_sectors",
                               return_value=len(data) // storage.SECTOR):
            report = storage.inspect(path, open_fn=open_fn)
        self.assertEqual(opens, [path])
        self.assertEqual(report.signatures.get(-1), "ISO 9660")

    def test_inspect_safely_path(self):
        data = _media.iso9660_image(IMAGE_BYTES)
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertEqual(report.signatures.get(-1), "ISO 9660")


class SniffOptical(unittest.TestCase):

    def test_iso_signature(self):
        data = _media.iso9660_image(storage.PARTITION_SNIFF_READ)
        self.assertEqual(storage.sniff_filesystem(bytes(data)), "ISO 9660")

    def test_header_sized_buffer_cannot_see_iso(self):
        """Documents why inspect() reads further for partitionless media."""
        self.assertLess(storage.HEADER_READ, storage.OPTICAL_VD_START)


class StorageStall(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.tmp = self._d.name

    def test_a_stalled_inspection_times_out_instead_of_freezing(self):
        """A reader on a writer-less fifo blocks forever; it must be killed."""
        fifo = os.path.join(self.tmp, "stall")
        os.mkfifo(fifo)
        report = storage.inspect_safely(fifo, timeout=1.0)
        self.assertFalse(report.inspected)
        self.assertIn("did not respond", report.error)

    def test_the_timeout_is_actually_enforced(self):
        """Pin the bound itself: an unbounded read would never return."""
        import time
        fifo = os.path.join(self.tmp, "stall2")
        os.mkfifo(fifo)
        started = time.monotonic()
        storage.inspect_safely(fifo, timeout=1.0)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_a_healthy_medium_still_inspects(self):
        """The bound must not break the normal path."""
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(b"\x00" * (storage.SECTOR - 2) + b"\x55\xaa")
            fh.write(b"\x00" * (storage.HEADER_READ - storage.SECTOR))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertIsNone(report.error)


# ---------------------------------------------------------------------------
# Storage: ordinary media must stay silent
# ---------------------------------------------------------------------------

class TestOrdinaryMediaAreSilent(unittest.TestCase):

    def test_typical_fat32_stick(self):
        """One FAT32 partition at the standard 1 MiB alignment."""
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 7811072, False)))
        report = simple_medium(parts, 7813120, {0: "FAT32"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_exfat_stick_declared_as_ntfs_type(self):
        """0x07 covers NTFS and exFAT alike; this pairing is routine."""
        parts = storage.parse_mbr(mbr_with((0x07, 2048, 15000000, False)))
        report = simple_medium(parts, 15002048, {0: "exFAT"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_superfloppy_without_a_partition_table(self):
        """Plenty of sticks ship with a filesystem and no partition table."""
        report = simple_medium([], 7813120, {-1: "FAT32"}, scheme="none")
        self.assertEqual(rules.storage_findings(report), [])

    def test_eight_mib_alignment_is_accepted(self):
        """Some tools align to 8 MiB; that must not read as a hidden area."""
        parts = storage.parse_mbr(mbr_with((0x0C, 16384, 7790000, False)))
        report = simple_medium(parts, 7813120, {0: "FAT32"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_two_partitions_side_by_side(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 4000000, False),
                                           (0x83, 4002048, 3800000, False)))
        report = simple_medium(parts, 7813120, {0: "FAT32", 1: "ext2/3/4"})
        self.assertEqual(rules.storage_findings(report), [])

    def test_bootable_linux_installer_is_not_flagged(self):
        """A bootable USB is an everyday object, not a finding."""
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 7000000, True)))
        report = simple_medium(parts, 7813120, {0: "FAT32"})
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
        report = simple_medium(parts, 7813120, {0: "FAT32"})
        self.assertIn("partition-beyond-end-of-device", self.ids(report))

    def test_overlapping_partitions(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 2048, 4000000, False),
                                           (0x83, 3000000, 1000000, False)))
        report = simple_medium(parts, 7813120)
        self.assertIn("overlapping-partitions", self.ids(report))

    def test_declared_type_disagrees_with_content(self):
        parts = storage.parse_mbr(mbr_with((0x83, 2048, 4000000, False)))
        report = simple_medium(parts, 7813120, {0: "NTFS"})
        self.assertIn("filesystem-type-mismatch", self.ids(report))

    def test_large_gap_before_the_first_partition(self):
        parts = storage.parse_mbr(mbr_with((0x0C, 400000, 7000000, False)))
        report = simple_medium(parts, 7813120, {0: "FAT32"})
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
        for finding in rules.storage_findings(simple_medium(parts, 7813120)):
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


# ==========================================================================
# storage.inspect() now uses every hardening function, not one of four
# ==========================================================================

class StorageHardeningIsInForce(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "disk.img"

    def tearDown(self):
        self._tmp.cleanup()

    def _mbr(self, entries):
        """Build a 4 KiB image with an MBR carrying the given partitions."""
        sector = bytearray(512)
        for i, (start, sectors) in enumerate(entries):
            off = 446 + i * 16
            sector[off + 0] = 0x00          # not bootable
            sector[off + 4] = 0x83          # Linux
            sector[off + 8:off + 12] = struct.pack("<I", start)
            sector[off + 12:off + 16] = struct.pack("<I", sectors)
        sector[510:512] = b"\x55\xaa"
        self.path.write_bytes(bytes(sector) + bytes(4096 - 512))
        return str(self.path)

    def test_a_partition_longer_than_the_disk_is_refused_and_reported(self):
        """The gap that only filter_safe_partitions closed.

        safe_read_offset() validates the START of a partition, and only the
        start. A partition beginning at sector 1 of an 8192-sector disk has a
        perfectly legal start, so it passed that check and was read -- even
        though it claims to run four billion sectors past the end of the
        medium. The impossibility was never recorded anywhere.
        """
        device = self._mbr([(1, 0xFFFFFFFF)])
        self._pretend_disk_is(8192)
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertTrue(report.suspicious,
                        "an impossible partition length must be recorded")
        self.assertIn("8192", report.suspicious[0])

    def test_an_absurd_declared_device_size_is_discarded_not_trusted(self):
        """The size is device-controlled AND is what every per-partition bound
        is measured against, so an absurd one does not merely produce a wrong
        number -- it disables the checks that depend on it."""
        device = self._mbr([(1, 6)])
        self._pretend_disk_is(10 ** 15)
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertIsNone(report.size_sectors,
                          "an implausible size must be discarded, not used")
        self.assertTrue(any("size" in s for s in report.suspicious))

    def _pretend_disk_is(self, sectors):
        """Override the sysfs size lookup, which cannot see a temp file."""
        original = storage.read_size_sectors
        storage.read_size_sectors = lambda _device: sectors
        self.addCleanup(lambda: setattr(storage, "read_size_sectors", original))

    def test_impossible_geometry_becomes_a_finding(self):
        """report.suspicious was written by the inspector and read by nobody.

        A refusal that never reaches the operator is indistinguishable from a
        check that was never performed.
        """
        report = storage.MediumReport(device="/dev/sdz", scheme="mbr")
        report.suspicious = ["partition 0: ends at 4294967296 — unrealistic"]
        found = rules.storage_findings(report)
        self.assertIn("impossible-partition-geometry",
                      {f.rule_id for f in found})

    def test_an_ordinary_layout_stays_silent(self):
        device = self._mbr([(1, 6)])
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertEqual(report.suspicious, [])
        self.assertEqual(
            [f.rule_id for f in rules.storage_findings(report)], [])


class Stage4ReachesTheMedium(_TreeCase):
    """Acceptance 4 and 5, through the real open and read path."""

    SECTORS = 256

    def _inspect(self, content):
        self.tree.disk("sda", 8, 0)
        node = self.tree.node("sda", 8, 0, content)
        with mock.patch.object(storage, "read_size_sectors",
                               return_value=self.SECTORS):
            return storage.inspect_safely(node, timeout=5.0,
                                          open_fn=sysfs.open_block_device)

    def test_whole_device_iso9660_is_reported(self):
        data = _media.iso9660_image(self.SECTORS * 512)
        medium = self._inspect(bytes(data))
        self.assertIsNone(medium.error)
        self.assertIn("whole-device ISO 9660 filesystem (no partition table)",
                      report.render_medium(medium, []))

    def test_all_zero_disk_contains_no_known_filesystem(self):
        medium = self._inspect(bytes(self.SECTORS * 512))
        self.assertIsNone(medium.error)
        self.assertIn("contains no known filesystem",
                      report.render_medium(medium, []))

    def test_unreadable_whole_disk_still_degrades_to_the_notice(self):
        def eio(*_a, **_kw):
            raise OSError(errno.EIO, "Input/output error")
        with mock.patch("os.pread", eio):
            medium = self._inspect(bytes(self.SECTORS * 512))
        self.assertIn("Input/output error", medium.error)
        findings = rules.storage_findings(medium)
        self.assertEqual([f.title for f in findings],
                         ["The medium could not be read"])


if __name__ == "__main__":
    unittest.main()
