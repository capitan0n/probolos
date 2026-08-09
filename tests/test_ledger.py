"""
Tests for identity across time.

The central case is descriptor drift: a device that was one thing yesterday and
is another thing today. Everything else here exists to make sure that signal
does not fire on ordinary use, because a drift alarm that cries wolf is worse
than none.
"""

import json
import tempfile
import unittest
from pathlib import Path

from probolos import analyzers, ledger as ledger_mod, rules


class Dev:
    def __init__(self, vid="0781", pid="5567", serial="ABC123",
                 raw=b"\x12\x01original", name="1-4"):
        self.vendor_id = vid
        self.product_id = pid
        self.serial = serial
        self.raw_descriptors = raw
        self.name = name


class TestLedgerStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_sighting_is_recorded(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(), "user approved")
        self.assertIsNone(store.save())

        reloaded = ledger_mod.Ledger(self.path)
        entry = reloaded.lookup(Dev())
        self.assertIsNotNone(entry)
        self.assertEqual(entry.times_seen, 1)

    def test_repeat_sighting_increments_rather_than_duplicating(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(), "user approved")
        store.record(Dev(), "user approved")
        self.assertEqual(len(store.entries), 1)
        self.assertEqual(store.lookup(Dev()).times_seen, 2)

    def test_changed_descriptors_are_remembered_as_history(self):
        store = ledger_mod.Ledger(self.path)
        store.record(Dev(raw=b"first"), "user approved")
        store.record(Dev(raw=b"second"), "user approved")
        entry = store.lookup(Dev())
        self.assertEqual(len(entry.known_hashes), 2)

    def test_corrupt_ledger_does_not_stop_the_gate(self):
        """
        Losing history is an inconvenience. Refusing to admit a keyboard
        because a JSON file is malformed is a lockout.
        """
        self.path.write_text("{ not json")
        store = ledger_mod.Ledger(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.entries, {})

    def test_unknown_schema_is_refused_rather_than_misread(self):
        self.path.write_text(json.dumps({"schema": 999, "entries": {}}))
        store = ledger_mod.Ledger(self.path)
        self.assertIn("schema", store.load_error)

    def test_decision_history_is_bounded(self):
        store = ledger_mod.Ledger(self.path)
        for _ in range(50):
            store.record(Dev(), "user approved")
        self.assertLessEqual(len(store.lookup(Dev()).decisions), 20)

    def test_identity_uses_the_claimed_serial(self):
        a = ledger_mod.identity_of(Dev(serial="AAA"))
        b = ledger_mod.identity_of(Dev(serial="BBB"))
        self.assertNotEqual(a, b)

    def test_missing_serial_does_not_crash_identity(self):
        self.assertIn("-", ledger_mod.identity_of(Dev(serial=None)))

    def test_fingerprint_hashes_raw_bytes_not_the_parsed_view(self):
        one = ledger_mod.descriptor_fingerprint(Dev(raw=b"aaa"))
        two = ledger_mod.descriptor_fingerprint(Dev(raw=b"aab"))
        self.assertNotEqual(one, two)
        self.assertIsNone(ledger_mod.descriptor_fingerprint(Dev(raw=None)))


class TestDriftDetection(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ledger_mod.Ledger(Path(self.tmp.name) / "l.json")

    def tearDown(self):
        self.tmp.cleanup()

    def analyze(self, dev):
        return analyzers.LedgerAnalyzer().analyze(
            analyzers.Context(device=dev, ledger=self.store))

    def test_a_device_never_seen_before_is_not_suspicious(self):
        """Novelty is not guilt, or the first run would flag everything."""
        self.assertEqual(self.analyze(Dev()), [])

    def test_same_device_unchanged_is_not_suspicious(self):
        self.store.record(Dev(), "user approved")
        self.assertEqual(self.analyze(Dev()), [])

    def test_descriptor_drift_is_critical(self):
        """The flash drive that comes back with a keyboard interface."""
        self.store.record(Dev(raw=b"innocent-stick"), "user approved")
        findings = self.analyze(Dev(raw=b"now-with-a-keyboard"))
        ids = [f.rule_id for f in findings]

        self.assertIn("descriptor-drift", ids)
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)

    def test_a_previously_rejected_device_is_flagged_on_return(self):
        self.store.record(Dev(), "user rejected")
        ids = [f.rule_id for f in self.analyze(Dev())]
        self.assertIn("previously-rejected", ids)

    def test_no_ledger_configured_means_no_findings(self):
        result = analyzers.LedgerAnalyzer().analyze(
            analyzers.Context(device=Dev(), ledger=None))
        self.assertEqual(result, [])

    def test_unreadable_ledger_is_disclosed_not_hidden(self):
        self.store.load_error = "disk on fire"
        ids = [f.rule_id for f in self.analyze(Dev())]
        self.assertIn("ledger-unavailable", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDefaultPath(unittest.TestCase):
    """The path bug: a root-only default broke every non-root --dry-run."""

    def test_root_uses_var_lib(self):
        import os
        from probolos import ledger as l
        real = os.geteuid
        os.geteuid = lambda: 0
        try:
            # The `state/` subdirectory is load-bearing, not cosmetic: it is
            # the only directory handed to the analyzer under --privsep, which
            # is what keeps trusted.json (in the root-owned parent) out of a
            # hostile `nobody` process's reach. See ledger.default_path.
            self.assertEqual(str(l.default_path()),
                             "/var/lib/probolos/state/ledger.json")
        finally:
            os.geteuid = real

    def test_non_root_uses_a_writable_location(self):
        import os
        from probolos import ledger as l
        real = os.geteuid
        os.geteuid = lambda: 1000
        try:
            path = l.default_path()
            self.assertNotIn("/var/lib", str(path))
            self.assertIn("probolos", str(path))
        finally:
            os.geteuid = real
