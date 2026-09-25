"""
Stage 4 refused a healthy whole USB disk: "not a whole-disk block device".

The guard answered None for everything it did not like, and folded an os.stat()
failure into the same None. The daemon waited only for the sysfs `block/sdX`
entry, which the kernel creates before the /dev node, and then opened once. A
/dev/sda that was not there yet was therefore refused with a reason that was
false about the device, and stage 4 was skipped: the medium was judged on its
declared identity alone.

These tests build a synthetic /dev and /sys/dev/block. A block node needs root
to create and a real device behind it to open, so the node is an ordinary file
and os.stat / os.fstat report it as a block device with a chosen device
number. Everything else -- realpath, the sysfs lookup, the open, the read -- is
real.
"""

from __future__ import annotations

import contextlib
import errno
import io
import os
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from probolos import daemon as daemon_mod
from probolos import gate_server, report, rules, session, storage, sysfs
from tests import _media

SCSI_DEVICE = "devices/pci0000:00/0000:00:14.0/usb3/3-9/3-9:1.0/host1/" \
              "target1:0:0/1:0:0:0"

_real_stat = os.stat
_real_fstat = os.fstat


class _Tree:
    """A /dev directory and a /sys tree whose /sys/dev/block index is real."""

    def __init__(self, root: Path):
        self.dev = root / "dev"
        self.sys = root / "sys"
        self.dev.mkdir()
        (self.sys / "dev" / "block").mkdir(parents=True)
        self.devnums = {}        # (st_dev, st_ino) of a fake node -> st_rdev

    @property
    def dev_block(self) -> str:
        return str(self.sys / "dev" / "block")

    def disk(self, kernel_name, major, minor, partition_of=None):
        """Register a block device with the fake kernel under major:minor."""
        if partition_of:
            home = self.sys / SCSI_DEVICE / "block" / partition_of / kernel_name
            home.mkdir(parents=True, exist_ok=True)
            (home / "partition").write_text("1\n")
        else:
            home = self.sys / SCSI_DEVICE / "block" / kernel_name
            home.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(home, self.dev_block),
                   os.path.join(self.dev_block, f"{major}:{minor}"))

    def node(self, name, major, minor, content=b""):
        """A /dev node that stat reports as block device major:minor."""
        path = self.dev / name
        path.write_bytes(content)
        st = _real_stat(path)
        self.devnums[(st.st_dev, st.st_ino)] = os.makedev(major, minor)
        return str(path)

    def _fake(self, st):
        rdev = self.devnums.get((st.st_dev, st.st_ino))
        if rdev is None:
            return st
        return types.SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o660, st_rdev=rdev, st_dev=st.st_dev,
            st_ino=st.st_ino, st_size=st.st_size)

    def patches(self):
        def fake_stat(path, *a, **kw):
            return self._fake(_real_stat(path, *a, **kw))

        def fake_fstat(fd):
            return self._fake(_real_fstat(fd))

        return [
            mock.patch("os.stat", fake_stat),
            mock.patch("os.fstat", fake_fstat),
            mock.patch.object(sysfs, "_BLOCK_DIR", str(self.dev)),
            mock.patch.object(sysfs, "SYS_DEV_BLOCK", self.dev_block),
            mock.patch.object(gate_server, "BLOCK_PREFIX", str(self.dev) + "/"),
            mock.patch.object(gate_server, "SYS_DEV_BLOCK", self.dev_block),
        ]


class _TreeCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tree = _Tree(Path(tmp.name))
        for patcher in self.tree.patches():
            patcher.start()
            self.addCleanup(patcher.stop)

    def refusal(self, path):
        with self.assertRaises(OSError) as caught:
            os.close(sysfs._DirectBackend().open_block(path))
        return str(caught.exception)


class WholeDiskIsAccepted(_TreeCase):
    """Acceptance 1 and 3: the kernel's answer, with no minor-number rule."""

    def test_whole_usb_disk_is_accepted(self):
        self.tree.disk("sda", 8, 0)
        node = self.tree.node("sda", 8, 0)
        self.assertEqual(sysfs._safe_block_node(node), Path(node))
        fd = sysfs._DirectBackend().open_block(node)
        os.close(fd)

    def test_minor_is_not_consulted(self):
        """sda on an arbitrary number, as after a re-enumeration."""
        for name, major, minor in (("sda", 8, 48), ("sdb", 65, 0),
                                   ("sdaa", 259, 7)):
            with self.subTest(number=f"{major}:{minor}"):
                self.tree.disk(name, major, minor)
                node = self.tree.node(name, major, minor)
                self.assertEqual(sysfs._safe_block_node(node), Path(node))

    def test_nothing_is_pending_for_a_ready_node(self):
        self.tree.disk("sda", 8, 0)
        self.assertIsNone(sysfs.block_node_pending(self.tree.node("sda", 8, 0)))


class PartitionsAreRefused(_TreeCase):
    """Acceptance 2: the guard's intent is kept."""

    def setUp(self):
        super().setUp()
        self.tree.disk("sda", 8, 0)
        self.tree.disk("sda1", 8, 1, partition_of="sda")

    def test_partition_node_is_refused_with_the_same_notice(self):
        message = self.refusal(self.tree.node("sda1", 8, 1))
        self.assertIn("not a whole-disk block device", message)

    def test_disk_named_node_on_a_partition_number_is_refused(self):
        """The kernel's `partition` attribute decides, not the name."""
        message = self.refusal(self.tree.node("sda", 8, 1))
        self.assertIn("not a whole-disk block device", message)
        self.assertIn("partition", message)

    def test_node_whose_number_belongs_to_another_disk_is_refused(self):
        self.tree.disk("sdb", 8, 16)
        message = self.refusal(self.tree.node("sda", 8, 16))
        self.assertIn("sdb to the kernel", message)

    def test_a_definitive_refusal_is_not_waited_on(self):
        """Waiting would only lengthen the authorized window."""
        self.assertIsNone(sysfs.block_node_pending(self.tree.node("sda1", 8, 1)))

    def test_a_regular_file_is_still_not_a_block_device(self):
        path = self.tree.dev / "sdq"
        path.write_bytes(b"")
        self.assertIn("not a block device", self.refusal(str(path)))


class ALateNodeIsNotMisreported(_TreeCase):
    """The regression: a node that is not there yet is not "not a disk"."""

    def test_missing_node_says_so(self):
        self.tree.disk("sda", 8, 0)
        message = self.refusal(str(self.tree.dev / "sda"))
        self.assertIn("does not exist yet", message)
        self.assertNotIn("not a whole-disk", message)

    def test_missing_node_is_pending(self):
        self.assertIn("does not exist yet",
                      sysfs.block_node_pending(str(self.tree.dev / "sda")))

    def test_node_before_its_sysfs_entry_is_pending(self):
        node = self.tree.node("sda", 8, 0)
        self.assertIn("no block device 8:0",
                      sysfs.block_node_pending(node))


class TheTwoHalvesAgree(_TreeCase):
    """gate_server duplicates the check; pin it to the same answers."""

    def test_same_verdicts(self):
        self.tree.disk("sda", 8, 0)
        self.tree.disk("sda1", 8, 1, partition_of="sda")
        self.tree.disk("sdb", 8, 16)
        cases = {
            "whole": self.tree.node("sda", 8, 0),
            "partition name": self.tree.node("sda1", 8, 1),
            "partition number": self.tree.node("sdc", 8, 1),
            "other disk": self.tree.node("sdd", 8, 16),
            "missing": str(self.tree.dev / "sde"),
            "outside": "/etc/passwd",
        }
        for label, path in cases.items():
            with self.subTest(label):
                direct = sysfs._check_block_node(path)
                gated = gate_server.GateServer._check_block_path(path)
                self.assertEqual(direct[0], gated[0])
                self.assertEqual(direct[1], gated[1])
        self.assertIsNotNone(gate_server.GateServer._safe_block_path(
            cases["whole"]))


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


class DaemonWaitsForTheNode(unittest.TestCase):
    """The poll waits on the /dev node, not only on the sysfs entry."""

    def setUp(self):
        self.engine = daemon_mod.Probolos(
            monitor=session.AlwaysUnlocked(), observe=0, inspect_storage=True)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dev = types.SimpleNamespace(syspath=Path(tmp.name), name="3-9")

    def _run(self, pending):
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(daemon_mod.storage, "find_block_devices",
                               return_value=["/dev/sda"]), \
             mock.patch.object(daemon_mod.sysfs, "block_node_pending",
                               side_effect=pending) as pending_fn, \
             mock.patch.object(daemon_mod.storage, "inspect_safely",
                               return_value=storage.MediumReport(
                                   device="/dev/sda", scheme="none")) as scan, \
             contextlib.redirect_stdout(io.StringIO()):
            medium = self.engine._inspect_medium(self.dev)
        return medium, pending_fn, scan

    def test_a_late_node_is_waited_for_then_inspected(self):
        late = ["device node does not exist yet"] * 3 + [None]
        medium, pending_fn, scan = self._run(late)
        self.assertEqual(pending_fn.call_count, 4)
        scan.assert_called_once()
        self.assertIsNone(medium.error)

    def test_a_node_that_never_appears_is_reported_as_such(self):
        medium, _pending, scan = self._run(
            lambda _p: "device node does not exist yet")
        scan.assert_not_called()
        self.assertIn("did not become ready", medium.error)
        self.assertIn("does not exist yet", medium.error)


if __name__ == "__main__":
    unittest.main()
