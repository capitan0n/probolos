"""
Device-supplied text: sanitising it, and the chokepoint that guarantees
every display path goes through the sanitiser.

Merged from: test_textsafe.py, test_stall_and_textsafe.py
"""
from __future__ import annotations

# =========================================================================
# test_textsafe.py
#
# Regression tests for device-supplied text, one per way it could forge the UI.
# =========================================================================

import unittest

from probolos import textsafe
from probolos.textsafe import (NOTE_BIDI, NOTE_CONTROL, NOTE_INVISIBLE,
                               NOTE_TRUNCATED, sanitize)


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


# =========================================================================
# test_stall_and_textsafe.py
#
# Regression tests for two defects that were documented but never applied.
# =========================================================================

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import storage, sysfs, textsafe


class StorageStall(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.tmp = self._d.name

    def test_a_stalled_inspection_times_out_instead_of_freezing(self):
        """A reader on a writer-less fifo blocks forever; it must be killed."""
        fifo = os.path.join(self.tmp, "stall")
        os.mkfifo(fifo)
        report = storage.inspect_safely(fifo, timeout=1.0)
        self.assertFalse(report.inspected)
        self.assertIn("did not respond", report.error)

    def test_the_timeout_is_actually_enforced(self):
        """Pin the bound itself: an unbounded read would never return."""
        import time
        fifo = os.path.join(self.tmp, "stall2")
        os.mkfifo(fifo)
        started = time.monotonic()
        storage.inspect_safely(fifo, timeout=1.0)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_a_healthy_medium_still_inspects(self):
        """The bound must not break the normal path."""
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(b"\x00" * (storage.SECTOR - 2) + b"\x55\xaa")
            fh.write(b"\x00" * (storage.HEADER_READ - storage.SECTOR))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertIsNone(report.error)


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


if __name__ == "__main__":
    unittest.main()
