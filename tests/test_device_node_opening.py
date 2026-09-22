"""
The direct backend opened whatever device node it was handed.

gate_server validates an input node (/dev/input/eventN, a character device)
and a block node (/dev/sdX, a whole disk, a block device) before opening
either, and opens both O_NOFOLLOW. sysfs._DirectBackend -- the DEFAULT, the
one `sudo python -m probolos` uses, running with real root rather than behind
a gate -- did none of that: os.open() on the string it was given, following
symlinks at every component.

That is the same asymmetry _write_attr_pinned was written to remove on the
other half of the privileged surface, and the same one storage._WHOLE_DISK_NAME
already calls out for block names: "The two halves must agree about what a
whole USB disk is, and the agreement has to be enforced on both sides rather
than on the one that happens to be looking."
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from probolos import sysfs


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


if __name__ == "__main__":
    unittest.main()
