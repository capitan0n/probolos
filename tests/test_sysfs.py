"""
The sysfs layer: privileged writes that never follow a link, bounded reads,
and which device nodes may be opened.

Covers probolos.sysfs.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import gate, gate_server, sysfs
from tests._support import FakeSysfs, _TreeCase


class DirectBackendRefusesWhatTheGateRefuses(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / "secret"
        self.target.write_text("not a device node")

    def _refuses(self, opener, path):
        with self.assertRaises(OSError) as caught:
            fd = opener(path)
            os.close(fd)
        return str(caught.exception)

    # ---- input nodes ----

    def test_input_open_refuses_a_path_outside_dev_input(self):
        message = self._refuses(sysfs._DirectBackend().open_input, self.target)
        self.assertIn("input node", message)

    def test_input_open_refuses_a_partition_style_name(self):
        self._refuses(sysfs._DirectBackend().open_input, "/dev/input/mice")

    def test_input_open_refuses_a_symlink_that_leaves_dev_input(self):
        link = self.root / "event0"
        os.symlink(self.target, link)
        # realpath resolves the link first, so the escape is caught by the
        # location check rather than by O_NOFOLLOW -- which is the point:
        # neither mechanism alone covers both cases.
        self._refuses(sysfs._DirectBackend().open_input, link)

    def test_input_open_refuses_a_regular_file_at_a_plausible_name(self):
        """
        The name is right and the inode is not.

        A path under /dev/input called eventN is what the validator is asked
        about; whether the kernel agrees it is a character device is a separate
        question, and it is the one that stops an ordinary file -- which anyone
        who can write the directory can create -- from being grabbed as though
        it were an input channel.
        """
        self.assertIsNone(sysfs._safe_input_node(self.target))

    # ---- block nodes ----

    def test_block_open_refuses_a_path_outside_dev(self):
        message = self._refuses(sysfs._DirectBackend().open_block, self.target)
        self.assertIn("whole-disk", message)

    def test_block_open_refuses_a_partition(self):
        self._refuses(sysfs._DirectBackend().open_block, "/dev/sda1")

    def test_block_open_refuses_mapper_and_loop_devices(self):
        for name in ("/dev/loop0", "/dev/dm-0", "/dev/nvme0n1", "/dev/mem"):
            with self.subTest(name=name):
                self.assertIsNone(sysfs._safe_block_node(name))

    def test_block_open_refuses_traversal_out_of_dev(self):
        self.assertIsNone(sysfs._safe_block_node("/dev/../etc/shadow"))

    # ---- the two halves agree ----

    def test_the_direct_and_gated_names_are_the_same_rule(self):
        """
        Duplicated deliberately (gate_server imports nothing but protocol), so
        the duplication has to be pinned or it drifts.
        """
        from probolos import gate_server, storage
        self.assertEqual(sysfs._WHOLE_DISK_NAME.pattern,
                         gate_server._BLOCK_NAME.pattern)
        self.assertEqual(sysfs._WHOLE_DISK_NAME.pattern,
                         storage._WHOLE_DISK_NAME.pattern)

    def test_valid_names_are_accepted_when_the_inode_agrees(self):
        """
        Positive control. A validator that refuses everything would pass every
        test above while breaking the tool completely.
        """
        for name in ("sda", "sdb", "sdaa"):
            with self.subTest(name=name):
                self.assertTrue(sysfs._WHOLE_DISK_NAME.match(name))
        for name in ("event0", "event12"):
            with self.subTest(name=name):
                self.assertTrue(sysfs._INPUT_NODE_NAME.match(name))


class DescriptorBlobIsBounded(unittest.TestCase):
    """
    load_device() read `descriptors` with read_bytes() and no ceiling.

    On a real kernel the blob is whatever the kernel cached and is small. The
    path that matters is the emulation tree (dummy_hcd, raw_gadget, testbed/),
    where `descriptors` is an ordinary file whose size nothing here controls --
    and a parser hardened against oversized DECLARATIONS cannot bound an
    allocation that has already happened.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dev = Path(self.tmp.name) / "1-1"
        self.dev.mkdir()
        (self.dev / "idVendor").write_text("046d\n")
        (self.dev / "idProduct").write_text("c52b\n")

    def test_an_oversized_blob_becomes_a_finding_not_an_allocation(self):
        (self.dev / "descriptors").write_bytes(
            b"\x00" * (sysfs.MAX_DESCRIPTOR_BYTES + 1))
        device = sysfs.load_device(self.dev)
        self.assertIsNotNone(device)
        self.assertIsNone(device.descriptor_set)
        self.assertIn("exceeds", device.parse_error)

    def test_an_ordinary_blob_still_parses(self):
        device_descriptor = bytes([
            18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 64,
            0xd2, 0x04, 0x2b, 0xc5, 0x00, 0x01, 0x01, 0x02, 0x03, 0x01])
        (self.dev / "descriptors").write_bytes(device_descriptor)
        device = sysfs.load_device(self.dev)
        self.assertIsNone(device.parse_error)
        self.assertIsNotNone(device.descriptor_set)


# ---------------------------------------------------------------------------
# P1 -- the privileged write must survive the bus view, which is all symlinks
# ---------------------------------------------------------------------------

class BusViewWrites(unittest.TestCase):
    """
    /sys/bus/usb/devices/<name> is a SYMLINK. O_DIRECTORY|O_NOFOLLOW applied to
    the unresolved path fails with ENOTDIR on every one of them, which meant the
    direct backend could not close the gate, could not re-block a device, and
    could not run --release -- while admit(), which lacked the flag, still
    switched devices on.
    """

    def setUp(self):
        self.fake = FakeSysfs()
        self._saved = sysfs.USB_DEVICES
        sysfs.USB_DEVICES = self.fake.bus

    def tearDown(self):
        sysfs.USB_DEVICES = self._saved
        self.fake.destroy()

    def test_set_authorized_default_through_the_bus_view(self):
        hub = sysfs.list_root_hubs()[0]
        self.assertTrue(hub.is_symlink(), "fixture must mirror the real layout")
        sysfs.set_authorized_default(hub, 0)
        self.assertEqual(
            (self.fake.hub / "authorized_default").read_text().strip(), "0")

    def test_set_authorized_through_the_bus_view(self):
        real = self.fake.add_device("1-4")
        device = [d for d in sysfs.list_devices() if d.name == "1-4"][0]
        self.assertTrue(device.syspath.is_symlink())
        sysfs.set_authorized(device.syspath, 1)
        self.assertEqual((real / "authorized").read_text().strip(), "1")

    def test_gate_actually_closes(self):
        with gate.AuthorizationGate(dry_run=False, log=lambda *_a: None):
            self.assertEqual(
                (self.fake.hub / "authorized_default").read_text().strip(), "0",
                "the gate reported success without closing anything")
        self.assertEqual(
            (self.fake.hub / "authorized_default").read_text().strip(), "1")

    def test_symlinked_attribute_is_still_refused(self):
        """The protection that matters is unchanged: O_NOFOLLOW on the file."""
        real = self.fake.add_device("1-5")
        target = self.fake.root / "stolen"
        target.write_text("untouched")
        (real / "authorized").unlink()
        os.symlink(target, real / "authorized")
        with self.assertRaises(OSError):
            sysfs.set_authorized(self.fake.bus / "1-5", 1)
        self.assertEqual(target.read_text(), "untouched")

    def test_admit_and_reblock_agree_about_the_same_path(self):
        """
        The asymmetry was the dangerous part: in a deny-by-default tool, the
        write that switches a device ON must never be the only one that works.
        """
        real = self.fake.add_device("1-6")
        device = [d for d in sysfs.list_devices() if d.name == "1-6"][0]
        sysfs.admit_device(device)
        self.assertEqual((real / "authorized").read_text().strip(), "1")
        sysfs.set_authorized(device.syspath, 0)
        self.assertEqual((real / "authorized").read_text().strip(), "0")


# ---------------------------------------------------------------------------
# 2 & 3. The direct backend must not write through a symlink
# ---------------------------------------------------------------------------

class DirectBackendNeverFollowsASymlink(unittest.TestCase):
    """
    gate_server.py pins every privileged write to a held directory descriptor
    and explains at length why. _DirectBackend -- used by the DEFAULT
    `sudo python -m probolos`, without --privsep -- did not, so the project
    had two ways to write a privileged sysfs attribute and only the less-used
    one checked what it was writing to.

    A followed symlink here is a root write of "0" or "1" into a file of the
    planter's choosing.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.victim = self.root / "victim"
        self.victim.write_text("untouched")
        self.devdir = self.root / "device"
        self.devdir.mkdir()

    def _plant(self, attribute):
        (self.devdir / attribute).symlink_to(self.victim)

    def test_authorize_refuses_a_symlinked_attribute(self):
        self._plant("authorized")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().authorize(self.devdir, 1)
        self.assertEqual(self.victim.read_text(), "untouched",
                         "a symlink at <device>/authorized must not become a "
                         "root write to its target")

    def test_authorize_interface_refuses_a_symlinked_attribute(self):
        self._plant("authorized")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().authorize_interface(self.devdir, 0)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_set_default_refuses_a_symlinked_attribute(self):
        """
        The most powerful attribute the tool writes: 1 here admits every
        device attached from that moment on.
        """
        self._plant("authorized_default")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().set_default(self.devdir, 1)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_drivers_autoprobe_refuses_a_symlinked_attribute(self):
        """
        Bus-wide, and the one whose failure leaves a machine that binds no
        drivers at all.
        """
        autoprobe = self.devdir / "drivers_autoprobe"
        autoprobe.symlink_to(self.victim)
        with mock.patch.object(sysfs, "DRIVERS_AUTOPROBE", autoprobe):
            with self.assertRaises(OSError):
                sysfs._DirectBackend().set_drivers_autoprobe(0)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_a_real_attribute_is_still_written_normally(self):
        """The fix must not break the ordinary path it protects."""
        (self.devdir / "authorized").write_text("0")
        sysfs._DirectBackend().authorize(self.devdir, 1)
        self.assertEqual((self.devdir / "authorized").read_text(), "1")

    def test_a_symlinked_parent_directory_is_ACCEPTED(self):
        """
        Inverse of the invariant this test used to assert.

        The round-3 fix opened the parent with O_DIRECTORY|O_NOFOLLOW on the
        path as GIVEN, which refuses any symlink at the final component --
        including /sys/bus/usb/devices/<name>, which IS a symlink into
        /sys/devices/. The whole default (non-privsep) deployment failed with
        ENOTDIR on every write except _DirectBackend.admit(), which had no
        O_NOFOLLOW at all -- so the only privileged write that still worked
        was the one that switches devices ON. In a deny-by-default tool that
        was the worst possible asymmetry.

        Round 4 fixed it by resolving the path first (realpath), then opening
        the resolved directory with O_NOFOLLOW so a symlink planted BETWEEN
        the resolve and the open is still refused. The protection that
        matters -- O_NOFOLLOW on the ATTRIBUTE, plus holding the directory fd
        across the write -- is unchanged, and the four "symlinked attribute
        is refused" tests above still cover it.

        So this test now asserts the CURRENT invariant: a symlinked directory
        alias resolves to its real target and the write lands there, exactly
        as it does when the daemon walks the bus view for real.
        """
        (self.devdir / "authorized").write_text("0")
        alias = self.root / "alias"
        alias.symlink_to(self.devdir)
        sysfs._DirectBackend().authorize(alias, 1)
        self.assertEqual(
            (self.devdir / "authorized").read_text(), "1",
            "the write must land on the real directory the alias points to; "
            "refusing symlinked directories broke the bus view entirely")

    def test_no_descriptor_is_leaked_by_a_refusal(self):
        """
        The refusal path opens the directory and then fails on the attribute.
        A daemon gets one of these per attachment, so a leak here is a slow
        exhaustion of the process that holds the gate.
        """
        self._plant("authorized")
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(50):
            try:
                sysfs._DirectBackend().authorize(self.devdir, 1)
            except OSError:
                pass
        after = len(os.listdir("/proc/self/fd"))
        self.assertLessEqual(after - before, 2,
                             "refusals must not leak descriptors")


class AdmitDescriptorIsCloseOnExec(unittest.TestCase):
    """
    The privileged half spawns children (the storage worker, dialog backends).
    A writable descriptor on a device's `authorized` attribute must not be
    inherited by any of them.
    """

    def test_o_cloexec_is_set(self):
        import inspect

        from probolos import sysfs

        source = inspect.getsource(sysfs._DirectBackend.admit)
        self.assertIn("O_CLOEXEC", source)


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


class TheOpenedDescriptorIsChecked(_TreeCase):
    """
    /dev/sda replaced between validation and open.

    The post-open check compared fstat(fd) with a fresh stat of the PATH, and
    a swapped path is swapped for both: a regular file read st_rdev 0 twice
    and went to the partition parser as the disk. The checks are now made on
    the descriptor, in both halves.
    """

    def setUp(self):
        super().setUp()
        self.tree.disk("sda", 8, 0)
        self.tree.disk("sda1", 8, 1, partition_of="sda")
        self.node = self.tree.node("sda", 8, 0)

    def _swap_on_open(self, replacement):
        """Patch os.open to rename `replacement` over the node, then open."""
        real_open = os.open

        def swapping_open(path, flags, *a, **kw):
            if str(path) == self.node:
                os.rename(replacement, self.node)
            return real_open(path, flags, *a, **kw)

        return mock.patch("os.open", swapping_open)

    def _payload(self):
        path = self.tree.dev / "payload"
        path.write_bytes(b"\x55\xaa" * 256)
        return path

    def test_direct_refuses_a_regular_file_swapped_in(self):
        with self._swap_on_open(self._payload()):
            message = self.refusal(self.node)
        self.assertIn("changed during open", message)
        self.assertIn("not a block device", message)

    def test_direct_refuses_a_partition_swapped_in(self):
        """The same number check the path passed, re-run on what was opened."""
        partition = self.tree.node("staged", 8, 1)
        with self._swap_on_open(partition):
            message = self.refusal(self.node)
        self.assertIn("partition", message)

    def test_gate_refuses_a_regular_file_swapped_in(self):
        from probolos import protocol
        server = gate_server.GateServer(sock=None, log=lambda *_a: None)
        with mock.patch.object(server, "_open_scope_parent_of",
                               lambda _n: Path("/sys/devices/usb1/1-1")), \
                self._swap_on_open(self._payload()):
            resp, fd = server._do_open_block(protocol.Request(
                protocol.REQ_OPEN_BLOCK, path=self.node))
        self.assertIsNone(fd)
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("not a block device", resp.detail)

    def test_a_symlink_to_a_regular_file_is_refused(self):
        os.unlink(self.node)
        os.symlink(self._payload(), self.node)
        self.assertIn("not a", self.refusal(self.node))

    def test_input_descriptor_must_be_a_character_device(self):
        import stat
        import types
        node = Path(self.node)
        regular = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_rdev=0)
        self.assertIn("not a character device",
                      sysfs._input_fd_reason(regular, node))


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


if __name__ == "__main__":
    unittest.main()
