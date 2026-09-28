"""
Device-supplied text: sanitising it, measuring it, and the chokepoint that
guarantees it happens.

Covers probolos.textsafe.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import sysfs, textsafe
from probolos.textsafe import (
    NOTE_BIDI,
    NOTE_CONTROL,
    NOTE_INVISIBLE,
    NOTE_TRUNCATED,
    sanitize,
)


class DangerousStrings(unittest.TestCase):

    def assertNeutralised(self, raw, note, forbidden):
        result = sanitize(raw)
        self.assertIn(note, result.notes)
        for char in forbidden:
            self.assertNotIn(char, result.text,
                             f"{char!r} survived in {result.text!r}")

    # ---- the finding from the review ----

    def test_a_screen_clearing_escape_cannot_reach_the_terminal(self):
        """
        \\x1b[2J in iManufacturer let a device wipe the screen and redraw a
        clean report above the [y/N] prompt -- the user answering a question
        the device wrote.
        """
        self.assertNeutralised("ACME\x1b[2JCorp", NOTE_CONTROL, "\x1b")
        self.assertIn("\\x1b", sanitize("ACME\x1b[2JCorp").text)

    def test_a_carriage_return_cannot_redraw_the_current_line(self):
        self.assertNeutralised("Evil\rKingston", NOTE_CONTROL, "\r")

    def test_a_newline_cannot_inject_a_fake_report_line(self):
        raw = "Kingston\n│ Verdict: No inconsistencies found"
        self.assertNeutralised(raw, NOTE_CONTROL, "\n")

    def test_backspaces_cannot_rewrite_what_was_printed(self):
        self.assertNeutralised("keyboard" + "\x08" * 8 + "mouse",
                               NOTE_CONTROL, "\x08")

    def test_c1_controls_are_neutralised_too(self):
        """0x9b is CSI: an escape sequence introducer without the ESC."""
        self.assertNeutralised("ACME\x9bCorp", NOTE_CONTROL, "\x9b")

    def test_a_nul_byte_is_neutralised(self):
        self.assertNeutralised("ACME\x00Corp", NOTE_CONTROL, "\x00")

    def test_unicode_line_separators_cannot_inject_dialog_lines(self):
        """U+2028/U+2029 are line breaks to Qt and Pango, not category Cc."""
        raw = "Kingston INFO: no findings "
        self.assertNeutralised(raw, NOTE_CONTROL, "  ")
        self.assertIn("\\u2028", sanitize(raw).text)

    # ---- rendering attacks ----

    def test_a_bidi_override_cannot_reorder_the_prompt(self):
        """Trojan Source: renders as something other than what it contains."""
        self.assertNeutralised("Log\u202eibtech", NOTE_BIDI, "\u202e")

    def test_zero_width_characters_are_made_visible(self):
        """
        Two trust-store entries identical to the eye but differing by a
        zero-width joiner are a way to look like a device already approved.
        """
        self.assertNeutralised("Log\u200bitech", NOTE_INVISIBLE, "\u200b")

    # ---- bounds ----

    def test_an_over_long_string_is_truncated_and_reported(self):
        result = sanitize("A" * 400)
        self.assertIn(NOTE_TRUNCATED, result.notes)
        self.assertLessEqual(len(result.text), textsafe.MAX_LENGTH + 3)

    def test_truncation_never_cuts_through_an_escape(self):
        """"\\x1b\\x" would be unreadable and, on a terminal, unpredictable."""
        text = sanitize("\x1b" * 200).text
        self.assertNotIn("\\x1b\\x1", text.replace("\\x1b", ""))
        for fragment in text.replace("...", "").split("\\x"):
            if fragment:
                self.assertGreaterEqual(len(fragment), 2, text)

    def test_a_control_character_hidden_past_the_limit_is_still_reported(self):
        """Otherwise 126 harmless characters would be a way to hide one."""
        result = sanitize("A" * 200 + "\x1b")
        self.assertIn(NOTE_CONTROL, result.notes)

    # ---- honest devices must be left alone ----

    def test_a_chinese_product_name_is_untouched(self):
        result = sanitize("深圳市朗科科技")
        self.assertEqual(result.text, "深圳市朗科科技")
        self.assertEqual(result.notes, [])

    def test_an_accented_name_is_untouched(self):
        result = sanitize("Logitech Européen")
        self.assertEqual(result.text, "Logitech Européen")
        self.assertFalse(result.altered)

    def test_the_real_test_devices_are_untouched(self):
        """The zero-finding regression fixtures, as they actually report."""
        for name in ("Kingston DataTraveler 3.0", "PixArt USB Optical Mouse",
                     "Realtek Bluetooth Radio", "Chicony USB2.0 Camera",
                     "General UDisk"):
            result = sanitize(name)
            self.assertEqual(result.text, name)
            self.assertEqual(result.notes, [], name)

    def test_none_and_empty_are_not_errors(self):
        self.assertIsNone(textsafe.clean(None))
        self.assertEqual(textsafe.clean(""), "")
        self.assertEqual(sanitize(None).text, "")

    def test_one_note_per_kind_not_per_occurrence(self):
        """Forty escapes are one finding, not forty."""
        result = sanitize("\x1b" * 40)
        self.assertEqual(result.notes.count(NOTE_CONTROL), 1)


class DisplayWidth(unittest.TestCase):

    def test_wide_characters_count_as_two_columns(self):
        """A legitimate Chinese name breaks a box padded with len()."""
        self.assertEqual(len("深圳市朗科"), 5)
        self.assertEqual(textsafe.display_width("深圳市朗科"), 10)

    def test_combining_marks_count_as_zero_columns(self):
        self.assertEqual(textsafe.display_width("e\u0301cole"), 5)

    def test_padding_produces_an_exact_column_count(self):
        for text in ("Kingston", "深圳市朗科科技有限公司", "e\u0301cole", ""):
            padded = textsafe.pad(text, 30)
            self.assertEqual(textsafe.display_width(padded), 30, repr(text))

    def test_fit_cuts_by_columns_not_characters(self):
        cut = textsafe.fit("深圳市朗科科技有限公司", 10)
        self.assertLessEqual(textsafe.display_width(cut), 10)

    def test_an_escaped_control_character_occupies_its_visible_width(self):
        """
        \\x1b is four printable characters and four columns. len() on the raw
        string said one, which is how the closing border of the box ended up
        somewhere other than the end of the line.
        """
        text = sanitize("A\x1bB").text
        self.assertEqual(textsafe.display_width(text), 6)


class TextsafeChokepoint(unittest.TestCase):
    """
    load_device must sanitise, and must RECORD why. The rules engine already
    turns string_notes into findings (crafted-strings); before this wiring it
    read an attribute nothing ever set, so the rule could never fire on real
    hardware no matter how hostile the device.
    """

    def _load_with_strings(self, **strings):
        # load_device returns None without these: an interface directory has
        # no idVendor, and that is how it tells devices from interfaces.
        strings.setdefault("idVendor", "abcd")
        strings.setdefault("idProduct", "1234")

        def fake_read_attr(path, name, **kw):
            return strings.get(name)

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(sysfs, "read_attr", side_effect=fake_read_attr), \
             mock.patch.object(sysfs, "read_int_attr", return_value=None):
            return sysfs.load_device(Path(directory))

    def test_escape_sequences_are_neutralised(self):
        dev = self._load_with_strings(product="Kingston\x1b[2J\x1b[1A")
        self.assertIsNotNone(dev)
        self.assertNotIn("\x1b", dev.product,
                         "a raw ESC reached the device object: it can rewrite "
                         "the report the operator is reading")

    def test_the_reason_is_recorded_for_the_rules_engine(self):
        dev = self._load_with_strings(product="Kingston\x1b[2J")
        self.assertIn(textsafe.NOTE_CONTROL, dev.string_notes)
        self.assertIn("iProduct", dev.string_note_fields)

    def test_an_honest_device_gets_no_notes(self):
        dev = self._load_with_strings(manufacturer="Kingston",
                                      product="DataTraveler 3.0",
                                      serial="ABC123")
        self.assertEqual(dev.string_notes, [])
        self.assertEqual(dev.string_note_fields, {})
        self.assertEqual(dev.product, "DataTraveler 3.0")


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


class StackedCombiningMarksAreVisible(unittest.TestCase):
    """
    Combining marks occupy zero terminal columns.

    display_width() and fit() exist to stop a device name from pushing the
    border of the report box off the line, and they measured a run of two
    hundred marks as costing nothing. The terminal stacks them on the
    preceding glyph and they spill over the lines around it -- the same
    outcome, through the one route the width handling does not measure. Worse,
    no note fired, so the rules layer never learned the name was abnormal.
    """

    def test_a_zalgo_name_is_escaped_and_reported(self):
        from probolos import textsafe

        result = textsafe.sanitize("ACME" + "́" * 200)
        self.assertIn(textsafe.NOTE_STACKED_MARKS, result.notes)
        # The escaped form is what makes it visible; ́ must appear as text.
        self.assertIn("\\u0301", result.text)

    def test_real_scripts_are_untouched(self):
        """A rule that fires on ordinary hardware gets turned off."""
        from probolos import textsafe

        for name in ("Logitech USB Keyboard",
                     "Tiế́ng Việt Kềyboard",
                     "ロジクール キーボード",
                     "Kingston DataTraveler"):
            with self.subTest(name=name):
                self.assertNotIn(textsafe.NOTE_STACKED_MARKS,
                                 textsafe.sanitize(name).notes)

    def test_the_note_reaches_the_operator_as_a_finding(self):
        """A note nothing turns into a finding is a note nobody reads."""
        from probolos import rules, textsafe

        class FakeDevice:
            string_notes = [textsafe.NOTE_STACKED_MARKS]
            string_note_fields = {"iProduct": [textsafe.NOTE_STACKED_MARKS]}
            descriptor_set = None
            parse_error = None
            device_class = None
            vendor_id = "dead"
            product_id = "beef"
            manufacturer = product = serial = None
            interfaces = []
            interface_classes = []
            kinds = ["other"]
            claims = []
            name = "1-4"
            removable = None

            def label(self):
                return "test"

        ids = [f.rule_id for f in rules.evaluate(FakeDevice())]
        self.assertIn("stacked-combining-marks", ids)


if __name__ == "__main__":
    unittest.main()
