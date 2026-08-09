"""
Regression tests for trust store integrity (audit finding C3, second half).

Two separate defects are pinned here.

1. STRUCTURAL: the trust store and the ledger shared one directory, and that
   directory was chowned to `nobody` so the analyzer could write the ledger.
   Directory write permission allows unlinking and replacing ANY file in it
   regardless of that file's own owner, so `nobody` -- a shared account --
   could replace trusted.json with one admitting its own device. The fix moves
   the ledger into a subdirectory and refuses to hand over any directory that
   still holds a trust store.

2. VALIDATION: TrustedDevice(**raw) accepted whatever types the file happened
   to contain, while the far less security-critical ledger validated carefully.
   from_raw now rejects malformed entries instead of trusting them, and it
   requires the entry's key to match the dict key it was filed under -- the
   mismatch that used to make trust un-revocable via forget_index.
"""

import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from probolos import privsep, trust


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


class DirectorySeparation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = Path(self._d.name)

    def test_refuses_to_hand_over_a_directory_holding_trust(self):
        """The core of the fix: that directory must never be chowned away."""
        (self.root / "trusted.json").write_text("{}")
        ledger = self.root / "ledger.json"
        logged = []
        privsep.prepare_state_dir(ledger, uid=65534, gid=65534,
                                  log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged),
                        "handing over a trust-store directory was not refused")

    def test_a_clean_subdirectory_is_still_handed_over(self):
        """The refusals must not break the legitimate ledger path."""
        state = self.root / "state"
        state.mkdir()
        ledger = state / "ledger.json"
        logged = []
        # The tempdir is outside STATE_ROOTS, which is itself a refusal reason
        # (see test_refuses_a_directory_outside_the_state_roots). Point the
        # allowlist at it so this test exercises only the trust-store rule.
        with mock.patch.object(privsep, "STATE_ROOTS", (str(self.root),)):
            # chown will fail for non-root; what matters is that it was
            # ATTEMPTED, i.e. we got past both refusals.
            privsep.prepare_state_dir(ledger, uid=os.getuid(), gid=os.getgid(),
                                      log=logged.append)
        self.assertFalse(any("REFUSING" in line for line in logged))

    def test_refuses_a_directory_outside_the_state_roots(self):
        """
        A typo must not cost the machine: `--ledger /etc/x.json` would chown
        /etc to an unprivileged account at mode 0700, taking sudo, ssh and PAM
        with it on a running system.
        """
        logged = []
        privsep.prepare_state_dir("/etc/probolos-typo.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_traversal_out_of_a_state_root_is_refused(self):
        """realpath runs first, so ../ cannot smuggle a path back out."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos/../../../etc/x.json",
                                  uid=65534, gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_a_sibling_sharing_the_prefix_is_refused(self):
        """/var/lib/probolos-evil must not match /var/lib/probolos."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos-evil/x.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_trust_is_made_readable_not_writable(self):
        target = self.root / "trusted.json"
        target.write_text("{}")
        os.chmod(target, 0o600)
        privsep.prepare_trust_readable(target, log=lambda *_: None)
        mode = target.stat().st_mode & 0o777
        self.assertTrue(mode & 0o044, "analyzer cannot read the trust store")
        self.assertFalse(mode & 0o022, "trust store became group/other writable")


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


if __name__ == "__main__":
    unittest.main()
