"""
Tests for code that existed but was connected to nothing.

Every case here follows the same shape: a module was written correctly, carried
its own unit tests, and was then never called from the path it was written for.
The unit tests passed the whole time. That is precisely why these tests are
written from the OUTSIDE -- through descriptors.parse(), through
storage.inspect(), through TrustStore(...) -- because only a test that enters
by the front door can tell whether the protection is actually in force.

Deleting the wiring must turn these red. That property was checked by reverting
each fix in turn; if you change one of these, check it again.
"""

import json
import os
import stat
import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from probolos import descriptors, rules, storage, trust


def device_desc(vid=0x1234, pid=0x5678, bcd_usb=0x0200, num_configs=1):
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01, bcd_usb, 0x00, 0, 0, 64,
        vid, pid, 0x0100, 0, 0, 0, num_configs)


def config_desc(total, n_ifaces=1, max_power=50):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, n_ifaces, 1, 0, 0x80,
                       max_power)


def iface_desc(cls=0x03, num=0):
    return struct.pack("<BBBBBBBBB", 9, 0x04, num, 0, 1, cls, 0, 0, 0)


# ==========================================================================
# descriptors.parse() now walks through descriptors_safe
# ==========================================================================

class ParserUsesTheHardenedWalker(unittest.TestCase):

    def test_a_flood_of_tiny_descriptors_is_refused(self):
        """The protection that only descriptors_safe had, and nothing used.

        The loop this replaced bounded every descriptor's SIZE but never their
        COUNT, so 200_000 two-byte items were walked one at a time. Not fatal
        on its own -- which is exactly how a bound goes missing.
        """
        blob = device_desc() + b"\x02\x02" * 5000
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_a_truncated_tail_is_still_kept_and_now_reported(self):
        """The behaviour that had to survive the rewrite.

        A tail that stops early is common on merely buggy hardware, so it must
        not become a refusal. What changed is that it is no longer discarded in
        silence.
        """
        body = config_desc(total=27) + iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(device_desc() + body)
        self.assertEqual(len(ds.primary_interfaces()), 1)
        self.assertIsNotNone(ds.truncated)

    def test_the_truncation_reaches_the_operator_as_a_finding(self):
        body = config_desc(total=27) + iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(device_desc() + body)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-chain-truncated", {f.rule_id for f in found})

    def test_overstated_wtotallength_is_reported(self):
        """The fingerprint of a hand-edited descriptor set: vendor toolchains
        compute this field, so a mismatch is not a typo."""
        body = config_desc(total=0xFFFF) + iface_desc()
        ds = descriptors.parse(device_desc() + body)
        self.assertGreater(ds.length_overstated, 0)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-length-overstated",
                      {f.rule_id for f in found})

    def test_an_honest_device_produces_neither_finding(self):
        """The false-positive guard. A rule that fires on ordinary hardware is
        worse than no rule, because it teaches the operator to click through."""
        body = config_desc(total=18) + iface_desc()
        ds = descriptors.parse(device_desc() + body)
        self.assertIsNone(ds.truncated)
        self.assertEqual(ds.length_overstated, 0)
        ids = {f.rule_id for f in rules.evaluate(_Stub(ds))}
        self.assertNotIn("descriptor-chain-truncated", ids)
        self.assertNotIn("descriptor-length-overstated", ids)

    def test_zero_blength_is_still_fatal(self):
        """Not recoverable, and must not be softened into a warning: the walk
        cannot advance past it by any amount."""
        blob = device_desc() + b"\x00\x02\xff\xff"
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)


class _Stub:
    """Duck-typed device, matching tests/test_rules.py's FakeDevice.

    interfaces and interface_classes must be properties derived from the
    descriptor set, not empty lists: the rule engine reads them, and a stub
    that hands back [] silently disables half the rules under test.
    """

    def __init__(self, ds):
        self.descriptor_set = ds
        self.vendor_id = "1234"
        self.product_id = "5678"
        self.manufacturer = None
        self.product = None
        self.serial = None
        self.speed = "12"
        self.parse_error = None

    @property
    def interfaces(self):
        return self.descriptor_set.primary_interfaces()

    @property
    def interface_classes(self):
        return self.descriptor_set.interface_classes()

    def label(self):
        return ""


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


# ==========================================================================
# C3: the trust store is an admission list, so its permissions are load bearing
# ==========================================================================

class TrustStoreIntegrity(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trusted.json"
        self.path.write_text(json.dumps({
            "schema": trust.SCHEMA_VERSION,
            "devices": {
                "1234:5678:AB#" + "a" * 64: {
                    "key": "1234:5678:AB#" + "a" * 64,
                    "identity": "1234:5678:AB",
                    "descriptor_hash": "a" * 64,
                    "trusted_at": 0.0,
                    "last_seen": 0.0,
                    "label": "test",
                },
            },
        }))
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_correct_store_still_loads(self):
        """The check must not break the normal case, or it will be removed."""
        store = trust.TrustStore(self.path)
        self.assertIsNone(store.load_error)
        self.assertEqual(len(store.devices), 1)

    def test_a_world_writable_store_is_not_believed(self):
        """Whoever can write this file can admit any device without ever
        touching the machine. Writing it at 0600 says nothing about the file
        we are about to READ: cp does not preserve mode, and restores and
        backups do not go through our writer."""
        os.chmod(self.path, 0o666)
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {},
                         "fail closed: an untrustworthy store is an empty one")

    def test_a_group_writable_store_is_not_believed(self):
        os.chmod(self.path, 0o660)
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_the_advice_in_the_error_is_actionable(self):
        os.chmod(self.path, 0o666)
        store = trust.TrustStore(self.path)
        self.assertIn("chmod 600", store.load_error)

    def test_a_symlink_is_refused_rather_than_followed(self):
        """lstat, not stat. Following the link would check one inode's
        ownership and then read a different inode's contents."""
        real = Path(self._tmp.name) / "elsewhere.json"
        real.write_text(self.path.read_text())
        link = Path(self._tmp.name) / "link.json"
        link.symlink_to(real)
        store = trust.TrustStore(link)
        self.assertIsNotNone(store.load_error)
        self.assertIn("symlink", store.load_error)
        self.assertEqual(store.devices, {})

    def test_a_missing_store_is_not_an_error(self):
        """First run. Nothing trusted yet is the normal state, not a fault."""
        store = trust.TrustStore(Path(self._tmp.name) / "absent.json")
        self.assertIsNone(store.load_error)
        self.assertEqual(store.devices, {})


# ==========================================================================
# The two version strings that disagreed
# ==========================================================================

class VersionHasOneSource(unittest.TestCase):

    def test_the_package_version_matches_pyproject(self):
        import probolos

        root = Path(__file__).resolve().parent.parent
        pyproject = (root / "pyproject.toml").read_text()
        declared = None
        for line in pyproject.splitlines():
            if line.startswith("version ="):
                declared = line.split("=", 1)[1].strip().strip('"')
                break

        self.assertIsNotNone(declared, "pyproject.toml has no version")
        # Installed: exactly equal. Source checkout: the "+source" fallback,
        # which must still carry the same base number.
        self.assertTrue(
            probolos.__version__ in (declared, declared + "+source"),
            f"{probolos.__version__!r} does not match pyproject {declared!r}")


if __name__ == "__main__":
    unittest.main()
