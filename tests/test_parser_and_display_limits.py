"""
Limits that were wrong in one direction or the other.

  * the descriptor flood guard sat below real hardware, and refusing the whole
    descriptor set is not a small consequence: no stage 3, no stage 4, and a
    WARNING on a device that had done nothing;
  * the escape for a code point above U+FFFF decoded to a different character
    than the one it described, which is the only job an escape has;
  * the rule file was assumed to have the right shape throughout, so a file of
    the wrong shape produced a traceback rather than the one-line config error
    __main__ is written to print -- and the gate never closed.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from probolos import descriptors, descriptors_safe, rules, textsafe


def _device_descriptor() -> bytes:
    return bytes([18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 64,
                  0xd2, 0x04, 0x2b, 0xc5, 0x00, 0x01, 1, 2, 3, 1])


class FloodGuardSitsAboveRealHardware(unittest.TestCase):

    def test_a_webcams_worth_of_descriptors_is_accepted(self):
        iface = bytes([0x09, 0x04, 0x00, 0x00, 0x01, 0x0E, 0x02, 0x00, 0x00])
        config = bytes([0x09, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32])
        parsed = descriptors.parse(_device_descriptor() + config + iface * 400)
        self.assertIsNone(parsed.truncated)
        self.assertEqual(len(parsed.configs[0].interfaces), 400)

    def test_the_guard_still_exists(self):
        blob = _device_descriptor() + b"\x02\x02" * (
            descriptors_safe.MAX_DESCRIPTOR_ITEMS + 1)
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_a_zero_length_descriptor_is_still_refused(self):
        """
        The termination guarantee, which is the reason the walker exists at
        all: bLength=0 would never advance the offset.
        """
        with self.assertRaises(descriptors_safe.DescriptorParsingError):
            list(descriptors_safe.walk_descriptors(b"\x00\x02\x00\x00"))


class EscapesDecodeToWhatTheyDescribe(unittest.TestCase):

    def test_an_astral_code_point_is_not_written_as_five_hex_digits(self):
        """
        U+E0001 became `\\u e0001`, which reads as U+0E00 followed by `1`. The
        escape exists so the operator sees exactly what the device sent.
        """
        cleaned = textsafe.sanitize("A\U000E0001B")
        self.assertIn("\\U000e0001", cleaned.text)
        self.assertNotIn("\\ue0001", cleaned.text)

    def test_the_escape_round_trips_through_python(self):
        for char in ("\x1b", "‮", "\U000E0001"):
            with self.subTest(char=char):
                escaped = textsafe._escape(char)
                self.assertEqual(escaped.encode().decode("unicode_escape"),
                                 char)

    def test_ordinary_escapes_are_unchanged(self):
        self.assertEqual(textsafe._escape("\x1b"), "\\x1b")
        self.assertEqual(textsafe._escape("‮"), "\\u202e")


class RuleConfigFailsAsAConfigError(unittest.TestCase):

    def setUp(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "rules.yaml"

    def _load(self, text):
        self.path.write_text(text)
        return rules.load_config(self.path)

    def test_a_file_that_is_not_a_mapping_is_a_value_error(self):
        for text in ("- one\n- two\n", "just a string\n", "42\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_a_severity_block_of_the_wrong_shape_is_a_value_error(self):
        with self.assertRaises(ValueError):
            self._load("severity:\n  - not-a-mapping\n")

    def test_benign_groups_must_be_lists_of_class_codes(self):
        for text in ("benign_groups: 3\n",
                     "benign_groups:\n  - 3\n",
                     "benign_groups:\n  - [3, 'ff']\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_disabled_must_be_a_list(self):
        with self.assertRaises(ValueError):
            self._load("disabled: keyboard-at-high-speed\n")

    def test_a_well_formed_file_still_loads(self):
        config = self._load(
            "disabled:\n"
            "  - keyboard-at-high-speed\n"
            "severity:\n"
            "  multiple-distinct-functions: warning\n"
            "benign_groups:\n"
            "  - [3, 255]\n")
        self.assertFalse(config.enabled("keyboard-at-high-speed"))
        self.assertEqual(config.severity("multiple-distinct-functions",
                                         rules.Severity.NOTICE),
                         rules.Severity.WARNING)
        self.assertEqual(config.extra_benign_groups, [{3, 255}])

    def test_the_entry_point_reports_it_as_a_config_error(self):
        """
        The consequence, not just the exception type: __main__ catches
        RuntimeError, ValueError and OSError around load_config, so anything
        else escaped as a traceback and the gate never closed.
        """
        from unittest import mock

        from probolos import __main__ as entry
        self.path.write_text("- not a mapping\n")
        with mock.patch.object(entry, "require_usb"), \
             mock.patch.object(entry.daemon, "serve") as serve:
            with self.assertRaises(SystemExit) as caught:
                entry.main(["--dry-run", "--rules", str(self.path)])
        self.assertIn("rule config", str(caught.exception))
        serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
