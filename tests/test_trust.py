"""
The trust store: what it admits without asking, who may write it, and the
atomic writes underneath it.

Covers probolos.trust and probolos.atomicio.
"""

from __future__ import annotations

import fnmatch
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from tempfile import TemporaryDirectory

from probolos import atomicio, trust
from probolos import ledger as ledger_mod
from probolos import trust as trust_mod
from tests._support import make_kingston_device, storage_device_blob


class Dev:
    def __init__(self, vid="0951", pid="1665", serial="ABC",
                 raw=b"\x12\x01descriptors", name="3-9"):
        self.vendor_id, self.product_id = vid, pid
        self.serial = serial
        self.raw_descriptors = raw
        self.name = name

    def label(self):
        return "Kingston DataTraveler"


def good_entry(key="v:p:s#abc"):
    return {
        "key": key,
        "identity": "v:p:s",
        "label": "Kingston",
        "descriptor_hash": "abc",
        "trusted_at": 1.0,
        "last_seen": 2.0,
        "times_admitted": 3,
        "note": "",
        "ports": ["1-1"],
    }


# ---------------------------------------------------------------------------
# Trust store
# ---------------------------------------------------------------------------

class TestTrustStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "trusted.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_trust_survives_a_restart(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        self.assertIsNone(store.save())
        self.assertTrue(trust.TrustStore(self.path).is_trusted(Dev()))

    def test_changed_descriptors_are_not_the_trusted_device(self):
        """
        The property that makes this more than a VID/PID allowlist: the same
        identity with different descriptors is something CLAIMING to be the
        trusted device, and must be asked about.
        """
        store = trust.TrustStore(self.path)
        store.trust(Dev(raw=b"original"))
        self.assertTrue(store.is_trusted(Dev(raw=b"original")))
        self.assertFalse(store.is_trusted(Dev(raw=b"rewritten")))

    def test_different_serial_is_a_different_device(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev(serial="AAA"))
        self.assertFalse(store.is_trusted(Dev(serial="BBB")))

    def test_a_device_with_unreadable_descriptors_cannot_be_trusted(self):
        """Nothing to pin trust to, so it must be asked about every time."""
        store = trust.TrustStore(self.path)
        self.assertIsNone(store.trust(Dev(raw=None)))
        self.assertFalse(store.is_trusted(Dev(raw=None)))

    def test_corrupt_store_trusts_nothing(self):
        """Fail closed: a damaged file must not become an open door."""
        self.path.write_text("{ this is not json")
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertFalse(store.is_trusted(Dev()))

    def test_unknown_schema_trusts_nothing(self):
        import json
        self.path.write_text(json.dumps({"schema": 99, "devices": {}}))
        self.assertIsNotNone(trust.TrustStore(self.path).load_error)

    def test_forget_matches_on_a_human_readable_name(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        self.assertTrue(store.forget("kingston"))
        self.assertFalse(store.is_trusted(Dev()))

    def test_clear_removes_everything(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev(serial="A"))
        store.trust(Dev(serial="B"))
        self.assertEqual(store.clear(), 2)

    def test_admissions_are_counted(self):
        store = trust.TrustStore(self.path)
        store.trust(Dev())
        store.record_admission(Dev())
        store.record_admission(Dev())
        self.assertEqual(store.lookup(Dev()).times_admitted, 2)


class TestNumberedManagement(unittest.TestCase):
    """ufw-style: list numbered, delete by number. Stable ordering is what
    makes the numbers safe to act on."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = trust.TrustStore(Path(self.tmp.name) / "t.json")
        import time
        for serial, raw in [("AAA", b"a"), ("BBB", b"b"), ("CCC", b"c")]:
            self.store.trust(Dev(serial=serial, raw=raw))
            time.sleep(0.001)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ordered_is_stable_by_trust_time(self):
        serials = [e.identity.split(":")[-1] for e in self.store.ordered()]
        self.assertEqual(serials, ["AAA", "BBB", "CCC"])

    def test_forget_by_number_removes_the_shown_entry(self):
        removed = self.store.forget_index(2)
        self.assertIn("BBB", removed)
        remaining = [e.identity.split(":")[-1] for e in self.store.ordered()]
        self.assertEqual(remaining, ["AAA", "CCC"])

    def test_forget_out_of_range_is_refused(self):
        self.assertIsNone(self.store.forget_index(0))
        self.assertIsNone(self.store.forget_index(99))
        self.assertEqual(len(self.store.ordered()), 3, "nothing removed")

    def test_numbers_renumber_after_a_delete(self):
        """After deleting [2], the old [3] becomes the new [2] -- exactly like
        ufw, so a second delete acts on what is now shown."""
        self.store.forget_index(2)               # removes BBB
        removed = self.store.forget_index(2)     # now removes CCC
        self.assertIn("CCC", removed)


class EntryValidation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.path = Path(self._d.name) / "trusted.json"

    def _store_with(self, devices):
        self.path.write_text(json.dumps({
            "schema": trust.SCHEMA_VERSION, "devices": devices}))
        return trust.TrustStore(self.path)

    def test_a_well_formed_entry_loads(self):
        store = self._store_with({"v:p:s#abc": good_entry()})
        self.assertIn("v:p:s#abc", store.devices)

    def test_wrong_types_are_not_trusted(self):
        bad = good_entry()
        bad["descriptor_hash"] = 12345          # must be a string
        store = self._store_with({"v:p:s#abc": bad})
        self.assertEqual(store.devices, {})

    def test_missing_fingerprint_is_not_trusted(self):
        bad = good_entry()
        bad["descriptor_hash"] = ""             # pins trust to nothing
        store = self._store_with({"v:p:s#abc": bad})
        self.assertEqual(store.devices, {})

    def test_key_mismatch_is_rejected(self):
        """The shape that used to make trust un-revocable."""
        store = self._store_with({"filed-under-this": good_entry("but-says-this")})
        self.assertEqual(store.devices, {})

    def test_malformed_entries_are_reported_not_silent(self):
        bad = good_entry()
        bad["trusted_at"] = "yesterday"
        store = self._store_with({"v:p:s#abc": bad})
        self.assertIsNotNone(store.load_error)

    def test_forget_index_always_revokes(self):
        store = self._store_with({"v:p:s#abc": good_entry()})
        self.assertEqual(len(store.devices), 1)
        removed = store.forget_index(1)
        self.assertEqual(removed, "v:p:s")
        self.assertEqual(store.devices, {})


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


# ---------------------------------------------------------------------------
# 6. Trust store is intentionally left on the RAW hash
# ---------------------------------------------------------------------------

class TrustStoreStillPinsRawBytes(unittest.TestCase):
    """
    Trust and drift have different semantics. "I approved this exact blob"
    is stricter than "the device did not change what it claims to be", and
    a controller swap that changes the raw bytes SHOULD re-prompt for trust
    -- because the trusted admission is admission WITHOUT prompting, and
    conservative is the safe direction there.
    """

    def test_trust_key_uses_raw_bytes(self):
        from probolos import trust
        a = make_kingston_device(storage_device_blob(bcd_usb=0x0210))
        b = make_kingston_device(storage_device_blob(bcd_usb=0x0320,
                                            include_ss_companion=True))
        self.assertNotEqual(trust.key_for(a), trust.key_for(b),
                            "trust must not silently span controller swaps")


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

    def test_a_store_that_cannot_be_reached_fails_closed_not_loudly(self):
        """The analyzer runs as `nobody`. A trust directory it cannot traverse
        -- made 0700 under a restrictive umask -- made Path.exists() raise
        EACCES out of the constructor, which ended the analyzer at startup
        and the gate with it. Nothing trusted, reason given, no exception."""
        writer = trust.TrustStore(self.path)
        writer.trust(Dev())
        self.assertIsNone(writer.save())
        denied = PermissionError(13, "Permission denied", str(self.path))
        with mock.patch.object(Path, "exists", side_effect=denied):
            store = trust.TrustStore(self.path)
            self.assertIn("cannot reach the trust store", store.load_error)
            self.assertEqual(store.devices, {})
            # What every plug calls; it must not raise either, and the
            # device the file does trust is not trusted from a store that
            # could not be read.
            self.assertFalse(store.is_trusted(Dev()))


# ---------------------------------------------------------------------------
# 2. State files: valid JSON that is not an object
# ---------------------------------------------------------------------------

class NonObjectStateFiles(unittest.TestCase):
    """
    `[]` is valid JSON, so json.loads succeeds and .get() raises
    AttributeError -- out of load(), out of __init__, uncaught. The daemon dies
    during startup, BEFORE authorized_default is set to 0, so the gate never
    closes. A one-byte file disables the tool and looks like a crash.
    """

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def test_ledger_survives_a_json_array(self):
        path = self.root / "ledger.json"
        path.write_text("[]")
        store = ledger_mod.Ledger(path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.entries, {})

    def test_ledger_survives_a_json_scalar(self):
        path = self.root / "ledger.json"
        path.write_text("42")
        self.assertIsNotNone(ledger_mod.Ledger(path).load_error)

    def _trust_file(self, text):
        path = self.root / "trusted.json"
        path.write_text(text)
        os.chmod(path, 0o600)
        return path

    def test_trust_store_survives_a_json_scalar(self):
        store = trust_mod.TrustStore(self._trust_file('"hello"'))
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_trust_store_survives_a_non_empty_devices_array(self):
        """`or {}` saved the empty case only; a non-empty list is truthy."""
        store = trust_mod.TrustStore(
            self._trust_file('{"schema": 1, "devices": ["a", "b"]}'))
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_a_good_store_still_loads(self):
        store = trust_mod.TrustStore(
            self._trust_file('{"schema": 1, "devices": {}}'))
        self.assertIsNone(store.load_error)


class StateReload(unittest.TestCase):
    def test_broken_reload_revokes_cached_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trusted.json"
            path.write_text('{"schema":1,"devices":{}}')
            obj = trust.TrustStore(path)
            obj.devices["stale"] = object()
            path.write_text("[]")
            obj.load()
            self.assertEqual(obj.devices, {})
            self.assertIsNotNone(obj.load_error)

    def test_nonfinite_timestamps_are_rejected(self):
        for value in (float("inf"), float("nan"), 10 ** 1000):
            data = good_entry()
            data["trusted_at"] = value
            self.assertIsNone(trust.TrustedDevice.from_raw(data["key"], data))


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Revocation reaches a daemon that is already running
# ---------------------------------------------------------------------------

class RevocationReachesARunningDaemon(unittest.TestCase):
    """
    `--remove-trusted` edits the file from one process while the daemon holds
    its own TrustStore in another. The daemon used to load once at startup,
    so a revoked device stayed admitted until a restart, and its next save
    wrote the revoked entry back.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "trusted.json"
        self.a = Dev(serial="AAA", raw=b"a")
        self.b = Dev(serial="BBB", raw=b"b")
        self.daemon = trust.TrustStore(self.path)
        self.daemon.trust(self.a)
        self.daemon.trust(self.b)
        self.assertIsNone(self.daemon.save())

    def tearDown(self):
        self.tmp.cleanup()

    def _revoke_a_elsewhere(self):
        cli = trust.TrustStore(self.path)
        self.assertIn("AAA", cli.forget_index(1))
        self.assertIsNone(cli.save())

    def test_revoked_device_is_no_longer_trusted(self):
        self._revoke_a_elsewhere()
        self.assertFalse(self.daemon.is_trusted(self.a))
        self.assertTrue(self.daemon.is_trusted(self.b))

    def test_admitting_another_device_does_not_bring_it_back(self):
        self._revoke_a_elsewhere()
        self.daemon.record_admission(self.b)
        self.assertIsNone(self.daemon.save())
        fresh = trust.TrustStore(self.path)
        self.assertFalse(fresh.is_trusted(self.a))
        self.assertTrue(fresh.is_trusted(self.b))

    def test_remembering_a_new_device_does_not_bring_it_back(self):
        self._revoke_a_elsewhere()
        self.daemon.trust(Dev(serial="CCC", raw=b"c"))
        self.assertIsNone(self.daemon.save())
        self.assertFalse(trust.TrustStore(self.path).is_trusted(self.a))

    def test_deleted_file_means_nothing_is_trusted(self):
        self.path.unlink()
        self.assertFalse(self.daemon.is_trusted(self.a))

    def test_unchanged_file_is_not_read_again(self):
        with mock.patch.object(self.daemon, "load") as load:
            self.assertTrue(self.daemon.is_trusted(self.a))
        load.assert_not_called()

    def test_a_store_made_untrustworthy_meanwhile_fails_closed(self):
        os.chmod(self.path, 0o666)
        self.assertFalse(self.daemon.is_trusted(self.a))
        self.assertIsNotNone(self.daemon.load_error)


class SaveKeepsReadBitsNeverWriteBits(unittest.TestCase):
    """Under --privsep the launcher makes the store 0644 so the analyzer can
    read it. A root-run edit that rewrote it 0600 locked the analyzer out."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "trusted.json"
        self.store = trust.TrustStore(self.path)
        self.store.trust(Dev())

    def tearDown(self):
        self.tmp.cleanup()

    def _mode(self):
        return os.stat(self.path).st_mode & 0o777

    def test_a_new_store_is_private(self):
        self.store.save()
        self.assertEqual(self._mode(), 0o600)

    def test_a_readable_store_stays_readable(self):
        self.store.save()
        os.chmod(self.path, 0o644)
        self.store.save()
        self.assertEqual(self._mode(), 0o644)

    def test_write_bits_are_never_carried_over(self):
        self.store.save()
        os.chmod(self.path, 0o666)
        self.store.save()
        self.assertEqual(self._mode(), 0o644)

    # The root gate writes "always" under --privsep, and the analyzer that
    # must read it back is `nobody`. A store the gate CREATED 0600 would
    # remember the device on disk and ask about it on every plug anyway.

    def test_a_new_store_can_be_created_readable(self):
        self.assertIsNone(self.store.save(readable=True))
        self.assertEqual(self._mode(), 0o644)

    def test_readable_does_not_widen_an_existing_private_store(self):
        self.store.save()
        self.store.save(readable=True)
        self.assertEqual(self._mode(), 0o600)

    def test_readable_never_brings_write_bits(self):
        self.store.save()
        os.chmod(self.path, 0o666)
        self.store.save(readable=True)
        self.assertEqual(self._mode(), 0o644)

    def test_a_readable_store_reloads_cleanly(self):
        self.store.save(readable=True)
        fresh = trust.TrustStore(self.path)
        self.assertIsNone(fresh.load_error)
        self.assertTrue(fresh.is_trusted(Dev()))


class WritableSaysWhetherAlwaysCanBeKept(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_writable_directory_is_writable(self):
        store = trust.TrustStore(Path(self.tmp.name) / "trusted.json")
        self.assertTrue(store.writable())

    def test_a_missing_directory_is_judged_by_the_nearest_existing_one(self):
        store = trust.TrustStore(Path(self.tmp.name) / "a" / "b" / "t.json")
        with mock.patch("os.access", return_value=True) as access:
            self.assertTrue(store.writable())
        self.assertEqual(access.call_args.args[0], self.tmp.name)

    def test_a_read_only_directory_is_not(self):
        store = trust.TrustStore(Path(self.tmp.name) / "trusted.json")
        with mock.patch("os.access", return_value=False):
            self.assertFalse(store.writable())
