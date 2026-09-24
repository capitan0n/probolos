"""
Stage 4 reported a raw-written ISO 9660 live image as "no known filesystem".

With no partition table, inspect() sniffed only the header read (0x4400
bytes), which ends before the ISO 9660 / UDF volume descriptors at 0x8000. A
dd-written Slax stick -- a whole operating system -- was described to the
operator as if it were blank.
"""
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from probolos import report as report_mod
from probolos import rules, storage

IMAGE_BYTES = 128 * 1024


def _mbr_with(ptype, start, sectors):
    data = bytearray(IMAGE_BYTES)
    struct.pack_into("<BBBBBBBBII", data, 446,
                     0, 0, 0, 0, ptype, 0, 0, 0, start, sectors)
    data[510:512] = b"\x55\xaa"
    return data


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
        """LBA 0 all zeros, PVD "CD001" at 0x8000: the Slax stick."""
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8010] = b"\x01CD001\x01\x00LINUX   "
        report = self._inspect(data)
        self.assertIsNone(report.error)
        self.assertEqual(report.scheme, "none")
        self.assertEqual(report.signatures.get(-1), "ISO 9660")

    def test_rendered_report_no_longer_says_no_known_filesystem(self):
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x01CD001"
        text = report_mod.render_medium(self._inspect(data), [])
        self.assertIn("whole-device ISO 9660 filesystem", text)
        self.assertNotIn("no known", text)

    def test_isohybrid_with_mbr_boot_code_but_no_partitions(self):
        """Boot code and 0x55AA in the system area, empty partition table."""
        data = bytearray(IMAGE_BYTES)
        data[0:4] = b"\xeb\x63\x90\x00"
        data[510:512] = b"\x55\xaa"
        data[0x8000:0x8006] = b"\x01CD001"
        self.assertEqual(self._inspect(data).signatures.get(-1), "ISO 9660")

    def test_udf_is_recognised(self):
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x00BEA01"
        data[0x8800:0x8806] = b"\x00NSR02"
        data[0x9000:0x9006] = b"\x00TEA01"
        self.assertEqual(self._inspect(data).signatures.get(-1), "UDF")

    def test_udf_with_4k_blocks_is_recognised(self):
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x00BEA01"
        data[0x9000:0x9006] = b"\x00NSR03"
        self.assertEqual(self._inspect(data).signatures.get(-1), "UDF")

    def test_udf_iso_bridge_is_reported_as_both(self):
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x01CD001"
        data[0x8800:0x8806] = b"\x00BEA01"
        data[0x9000:0x9006] = b"\x00NSR02"
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
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x01CD001"
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
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x01CD001"
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
        data = bytearray(IMAGE_BYTES)
        data[0x8000:0x8006] = b"\x01CD001"
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertEqual(report.signatures.get(-1), "ISO 9660")


class SniffOptical(unittest.TestCase):

    def test_iso_signature(self):
        data = bytearray(0x8800)
        data[0x8000:0x8006] = b"\x01CD001"
        self.assertEqual(storage.sniff_filesystem(bytes(data)), "ISO 9660")

    def test_header_sized_buffer_cannot_see_iso(self):
        """Documents why inspect() reads further for partitionless media."""
        self.assertLess(storage.HEADER_READ, storage.OPTICAL_VD_START)


if __name__ == "__main__":
    unittest.main()
