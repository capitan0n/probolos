"""
The testbed presets, checked without root or hardware.

Each preset in testbed/spawn.py exists to make Probolos raise one particular
rule on a real kernel. The `overpowered` preset could not even be built: it
declared 800 mA, which does not fit bMaxPower's one byte of 2 mA units, so
struct.pack raised before anything was presented. Nothing ran the presets
except a person at a dummy_hcd setup, so nothing noticed. This builds every
preset's descriptors and runs them through the same parser and rules the
daemon uses.

Covers testbed.spawn and testbed.emulate.
"""

from __future__ import annotations

import unittest

from probolos import ledger, rules
from testbed import spawn
from tests._support import make_device


def _device(name):
    emulated = spawn.PRESETS[name]()
    return make_device(emulated.full_descriptors_blob(),
                       manufacturer=emulated.manufacturer,
                       product=emulated.product, serial=emulated.serial)


def _rule_ids(name):
    return {f.rule_id for f in rules.evaluate(_device(name))}


class EveryPresetBuilds(unittest.TestCase):

    def test_every_preset_produces_a_parseable_descriptor_set(self):
        for name in spawn.PRESETS:
            with self.subTest(name):
                dev = _device(name)
                self.assertIsNone(dev.descriptor_set.truncated)
                self.assertTrue(dev.descriptor_set.primary_interfaces())
                self.assertNotIn("unreadable-descriptors", _rule_ids(name))


class EachPresetRaisesItsRule(unittest.TestCase):
    """What testbed/README.md promises each preset will make Probolos say."""

    def test_the_honest_devices_are_quiet(self):
        for name in ("flashdrive", "drift-innocent"):
            with self.subTest(name):
                self.assertEqual(_rule_ids(name), set())

    def test_badusb_is_storage_that_types(self):
        self.assertIn("storage-with-keyboard", _rule_ids("badusb"))

    def test_the_keyboard_raises_nothing_above_a_notice(self):
        findings = rules.evaluate(_device("keyboard"))
        self.assertLessEqual(rules.worst(findings), rules.Severity.NOTICE)

    def test_overpowered_exceeds_the_bus_limit(self):
        self.assertIn("power-exceeds-bus-limit", _rule_ids("overpowered"))

    def test_the_drift_pair_shares_an_identity_and_not_a_fingerprint(self):
        """descriptor-drift needs both, from the ledger, across two plugs."""
        before, after = _device("drift-innocent"), _device("drift-weaponized")
        self.assertEqual(ledger.identity_of(before), ledger.identity_of(after))
        self.assertNotEqual(ledger.descriptor_fingerprint(before),
                            ledger.descriptor_fingerprint(after))
        self.assertIn("storage-with-keyboard", _rule_ids("drift-weaponized"))


if __name__ == "__main__":
    unittest.main()
