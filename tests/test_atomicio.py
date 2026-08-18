"""
Regression tests for the symlink-safe state writes (audit finding C3), and for
the staging-name follow-up.

The attack originally closed: the state directory is nobody-owned under
--privsep, so a hostile nobody process can plant a symlink at the staging path.
The old write_text() followed it, and a later root-run save() (e.g. --forget)
then wrote the store's JSON through the symlink onto whatever it pointed at.

WHAT CHANGED, AND WHY THESE TESTS CHANGED WITH IT
-------------------------------------------------
The staging path used to be path.with_suffix(".tmp") -- predictable, and shared
by every process. O_EXCL made that safe against being FOLLOWED and unsafe
against being OCCUPIED: planting an ordinary file at ledger.tmp made every save
fail with EEXIST forever, and Ledger.save reports a repeated error only once, so
the ledger silently stopped recording. A `touch` disabled drift detection.

The staging name is now unique and unguessable. So the tests below no longer
plant a symlink at a name we will use -- there isn't one to guess -- and instead
pin the property that survived the change: nothing is ever WRITTEN through a
symlink, a leftover at any predictable name cannot stop a save, and the store
still lands atomically with restrictive permissions.
"""

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
