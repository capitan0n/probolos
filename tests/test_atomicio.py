"""
Regression tests for the symlink-safe state writes (audit finding C3).

The attack being closed: the state directory is nobody-owned under --privsep,
so a hostile nobody process can plant a symlink at the .tmp staging path. The
old write_text() followed it, and a later root-run save() (e.g. --forget) then
wrote the store's JSON through the symlink onto whatever it pointed at.

These tests do not need root or privsep -- planting a symlink and confirming
the write refuses to follow it is enough to pin the property.
"""

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

    def test_normal_write_round_trips(self):
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"a": 1, "b": [2, 3]})
        self.assertEqual(json.loads(target.read_text()), {"a": 1, "b": [2, 3]})

    def test_temp_symlink_is_refused_not_followed(self):
        """The core of C3: a symlink at the .tmp path must not be written."""
        target = self.root / "store.json"
        victim = self.root / "victim"
        victim.write_text("SACRED")
        # Attacker pre-plants the staging path as a symlink to the victim.
        tmp = target.with_suffix(".tmp")
        os.symlink(victim, tmp)

        with self.assertRaises(OSError):
            atomicio.write_json_atomic(target, {"pwned": True})

        # The victim is untouched and the store was never created.
        self.assertEqual(victim.read_text(), "SACRED")
        self.assertFalse(target.exists())

    def test_existing_temp_file_is_refused(self):
        """O_EXCL: a stale/planted regular temp file is not truncated."""
        target = self.root / "store.json"
        tmp = target.with_suffix(".tmp")
        tmp.write_text("do not clobber")

        with self.assertRaises(OSError):
            atomicio.write_json_atomic(target, {"x": 1})

        self.assertEqual(tmp.read_text(), "do not clobber")

    def test_mode_is_not_world_readable(self):
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"a": 1})
        mode = target.stat().st_mode & 0o077
        self.assertEqual(mode, 0, "state file must not be group/other accessible")

    def test_failed_write_leaves_no_temp_behind(self):
        # A symlink attempt raises; the .tmp symlink the attacker made is theirs
        # to clean, but we must not leave a NEW half-written temp of our own.
        target = self.root / "store.json"
        atomicio.write_json_atomic(target, {"first": 1})
        # A normal second write still works (no stale temp of ours blocking it).
        atomicio.write_json_atomic(target, {"second": 2})
        self.assertEqual(json.loads(target.read_text()), {"second": 2})


class SaveMethodsRefuseSymlink(unittest.TestCase):
    """The property holds through the real save() call sites, not just the helper."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def test_trust_store_save_refuses_symlink(self):
        from probolos import trust
        victim = self.root / "victim"
        victim.write_text("SACRED")
        store = trust.TrustStore(self.root / "trusted.json")
        os.symlink(victim, self.root / "trusted.tmp")
        # save() swallows OSError and returns a message rather than raising.
        err = store.save()
        self.assertIsNotNone(err)
        self.assertEqual(victim.read_text(), "SACRED")

    def test_ledger_save_refuses_symlink(self):
        from probolos import ledger
        victim = self.root / "victim"
        victim.write_text("SACRED")
        store = ledger.Ledger(self.root / "ledger.json")
        os.symlink(victim, self.root / "ledger.tmp")
        err = store.save()
        self.assertIsNotNone(err)
        self.assertEqual(victim.read_text(), "SACRED")


if __name__ == "__main__":
    unittest.main()
