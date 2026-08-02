"""
Regression tests for the panic file, one per way it could be forged.

The panic file is an off switch for a security tool, so the question each test
asks is not "does the hatch work" but "can somebody other than the operator
pull it". Every shape below used to be accepted by a bare Path.exists().

These run as any uid: SafetyPolicy.panic_file_uid is set to the uid running
the suite, so the invariant "only the owner of the gate may place this file"
is exercised without the suite needing root. In production that uid is 0.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from cerberus import safety


class PanicFileValidation(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        os.chmod(self.dir, 0o700)
        self.uid = os.getuid()
        self.panic = self.dir / "cerberus.panic"
        self.messages = []

    def tearDown(self):
        self._dir.cleanup()

    def valid(self, path=None):
        return safety.panic_file_is_valid(path or self.panic, self.uid,
                                          self.messages.append)

    def assertRefused(self, because):
        self.assertFalse(self.valid())
        self.assertTrue(self.messages, "a refusal must say why")
        self.assertIn(because, self.messages[-1].lower())

    # ---- the hatch still works ----

    def test_a_file_placed_by_the_operator_is_honoured(self):
        self.panic.touch()
        self.assertTrue(self.valid())

    def test_no_file_is_not_a_panic_and_says_nothing(self):
        self.assertFalse(self.valid())
        self.assertEqual(self.messages, [])

    # ---- F4: forging it ----

    def test_a_symlink_is_not_a_panic_file(self):
        """
        Path.exists() follows symlinks, so a link to any file that happens to
        exist used to open the gate for every device on the machine.
        """
        self.panic.symlink_to("/etc/hostname")
        self.assertRefused("symlink")

    def test_a_dangling_symlink_is_reported_not_ignored(self):
        self.panic.symlink_to(self.dir / "does-not-exist")
        self.assertRefused("symlink")

    def test_a_fifo_is_not_a_panic_file(self):
        os.mkfifo(self.panic)
        self.assertRefused("not a regular file")

    def test_a_file_owned_by_someone_else_is_not_a_panic_file(self):
        self.panic.touch()
        self.assertFalse(safety.panic_file_is_valid(
            self.panic, self.uid + 4242, self.messages.append))
        self.assertIn("owned by uid", self.messages[-1])

    def test_a_hardlinked_file_is_not_a_panic_file(self):
        """
        --panic-file is operator-supplied. In a directory an attacker can
        write to, `ln /etc/hostname <panic path>` yields a regular file owned
        by root that appears exactly when they choose. Ownership of the file
        says nothing about who put it there.
        """
        decoy = self.dir / "decoy"
        decoy.write_text("x")
        os.link(decoy, self.panic)
        self.assertRefused("hard link")

    def test_a_directory_writable_by_others_disqualifies_the_file(self):
        """The check that closes the hardlink route at its source."""
        loose = Path(tempfile.mkdtemp())
        try:
            os.chmod(loose, 0o777)
            panic = loose / "cerberus.panic"
            panic.touch()
            self.assertFalse(self.valid(panic))
            self.assertIn("writable by others", self.messages[-1])
        finally:
            for child in loose.iterdir():
                child.unlink()
            loose.rmdir()

    def test_the_default_location_is_not_world_writable(self):
        """
        /tmp is 1777 and /run/cerberus is chowned to 2770 by
        prepare_socket_dir. Neither can hold the off switch.
        """
        self.assertEqual(safety.DEFAULT_PANIC_FILE, Path("/run/cerberus.panic"))
        self.assertEqual(safety.DEFAULT_PANIC_FILE.parent, Path("/run"))


class WatchdogPanic(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        os.chmod(self.dir, 0o700)
        self.panic = self.dir / "cerberus.panic"
        self.messages = []
        self.policy = safety.SafetyPolicy(panic_file=self.panic,
                                          panic_file_uid=os.getuid())

    def tearDown(self):
        self._dir.cleanup()

    def dog(self, timeout=60.0):
        return safety.Watchdog(timeout, lambda _reason: None, self.policy,
                               log=self.messages.append)

    def test_a_valid_panic_file_fires_the_watchdog(self):
        watchdog = self.dog()
        self.assertIsNone(watchdog.check_once())
        self.panic.touch()
        self.assertIn("panic file", watchdog.check_once() or "")

    def test_a_forged_panic_file_does_not_fire_the_watchdog(self):
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        self.assertIsNone(watchdog.check_once())
        self.assertFalse(watchdog.fired)

    def test_the_hatch_works_while_waiting_for_a_human(self):
        """
        The panic check runs before the paused check, because waiting for a
        human is exactly when someone reaches for the hatch.
        """
        watchdog = self.dog()
        self.panic.touch()
        with watchdog.paused():
            self.assertIsNotNone(watchdog.check_once())

    def test_a_stall_is_not_reported_while_paused(self):
        """The other half: a human taking their time is not a malfunction."""
        watchdog = self.dog(timeout=0.0)
        with watchdog.paused():
            self.assertIsNone(watchdog.check_once())
        self.assertIsNotNone(watchdog.check_once())

    def test_an_invalid_panic_file_is_reported_once_not_every_pass(self):
        """
        check_once runs every 0.5s. Complaining on each pass would print the
        same refusal twice a second until someone removed the file, burying
        the findings the user needs to read.
        """
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        for _ in range(10):
            watchdog.check_once()
        self.assertEqual(len(self.messages), 1, self.messages)

    def test_it_complains_again_if_the_bad_file_returns(self):
        watchdog = self.dog()
        self.panic.symlink_to("/etc/hostname")
        watchdog.check_once()
        self.panic.unlink()
        watchdog.check_once()
        self.panic.symlink_to("/etc/hostname")
        watchdog.check_once()
        self.assertEqual(len(self.messages), 2, self.messages)


if __name__ == "__main__":
    unittest.main()
