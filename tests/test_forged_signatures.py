"""
Stage 4 accepted a forged ISO 9660 magic.

Six bytes -- 01 "CD001" 01 at 0x8000 -- on an otherwise blank device made stage
4 report "whole-device ISO 9660 filesystem". The medium is attacker-controlled,
so the label shown to the operator was the attacker's choice. ISO 9660 and UDF
are now reported only when the volume structure behind the magic checks out,
and a magic with nothing behind it becomes a finding of its own.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from probolos import report as report_mod
from probolos import rules, storage
from tests import _media

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


if __name__ == "__main__":
    unittest.main()
