"""
Regression tests for a ledger file that is valid JSON but wrong inside.

The existing tests cover a ledger that cannot be read and a ledger that is not
JSON. This file covers the gap between those two: JSON that parses, matches
the schema version, and still cannot be turned into entries. That gap used to
raise TypeError out of Entry.__init__, from load(), from Ledger.__init__ --
which meant the daemon never finished starting and the gate never closed.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from cerberus.ledger import ENTRY_FIELD_NAMES, Entry, Ledger

GOOD = {
    "identity": "1234:5678:-",
    "descriptor_hash": "ab" * 32,
    "first_seen": 1.0,
    "last_seen": 2.0,
    "times_seen": 3,
    "ports": ["1-1"],
    "decisions": ["yes"],
    "known_hashes": ["ab" * 32],
}


class MalformedLedger(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = Path(self._dir.name) / "ledger.json"

    def tearDown(self):
        self._dir.cleanup()

    def write(self, entries, schema=1):
        self.path.write_text(json.dumps({"schema": schema,
                                         "entries": entries}))

    # ---- F7: the gate must still start ----

    def test_malformed_entry_does_not_prevent_the_gate_from_starting(self):
        """
        Every shape below raised out of Ledger.__init__ before. Any one of
        them, written by anything with access to the state directory, kept
        authorized_default at 1 for as long as it stayed there.
        """
        self.write({
            "usable": GOOD,
            "unexpected_key": dict(GOOD, injected=True),
            "missing_required": {"identity": "x"},
            "null_entry": None,
            "wrong_types": dict(GOOD, identity=5),
            "boolean_timestamp": dict(GOOD, first_seen=True),
            "string_timestamp": dict(GOOD, last_seen="yesterday"),
        })

        ledger = Ledger(self.path)          # must not raise

        self.assertEqual(sorted(ledger.entries),
                         ["unexpected_key", "usable"])
        self.assertIsNotNone(ledger.load_error)

    def test_entries_as_a_list_does_not_prevent_startup(self):
        """`"entries": []` is schema-valid JSON and used to hit .items()."""
        self.write([])
        ledger = Ledger(self.path)
        self.assertEqual(ledger.entries, {})
        self.assertIsNotNone(ledger.load_error)

    def test_a_dropped_entry_is_reported_and_not_silent(self):
        """
        A skipped entry is a device whose history is gone: it will look like a
        first sighting and no drift can be reported for it. Corrupting one
        entry must not be a quiet way of erasing the ledger's memory of one
        chosen device.
        """
        self.write({"broken": {"identity": "x"}})
        ledger = Ledger(self.path)
        self.assertIn("drift", ledger.load_error)

    # ---- what must NOT change ----

    def test_unknown_keys_are_dropped_not_rejected(self):
        """A ledger from a newer version degrades; it is not discarded."""
        self.write({"forward": dict(GOOD, field_from_the_future="x")})
        ledger = Ledger(self.path)
        self.assertIn("forward", ledger.entries)
        self.assertEqual(ledger.entries["forward"].descriptor_hash,
                         GOOD["descriptor_hash"])

    def test_a_good_entry_survives_a_save_and_reload_unchanged(self):
        self.write({"usable": GOOD})
        first = Ledger(self.path)
        self.assertIsNone(first.load_error)
        first.save()

        second = Ledger(self.path)
        self.assertIsNone(second.load_error)
        self.assertEqual(second.entries["usable"], first.entries["usable"])

    def test_from_raw_covers_every_field_of_entry(self):
        """
        A field added to Entry and not to from_raw would load as its default:
        real history silently replaced by an empty list, rather than loudly
        refused. This is the guard that keeps the two in step.
        """
        rebuilt = Entry.from_raw(dict(GOOD))
        self.assertIsNotNone(rebuilt)
        self.assertEqual(set(asdict(rebuilt)), set(ENTRY_FIELD_NAMES))
        for name in ENTRY_FIELD_NAMES:
            self.assertEqual(asdict(rebuilt)[name], GOOD[name], name)

    def test_from_raw_rejects_non_mappings(self):
        for raw in (None, [], "string", 7):
            self.assertIsNone(Entry.from_raw(raw), repr(raw))


if __name__ == "__main__":
    unittest.main()
