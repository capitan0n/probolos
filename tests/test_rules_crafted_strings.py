"""
Regression tests for the report-level consequences of a crafted string.

test_textsafe.py proves the bytes are neutralised. These prove the two places
that neutralisation has to surface: a finding the user can read, and a dialog
string that a markup-rendering backend cannot be tricked by.

Both use stub devices rather than real hardware: the rule reads three
attributes off `dev` and the dialog helper is a pure function, so nothing here
needs USB, root, or a graphical session.
"""

from __future__ import annotations

import html
import unittest
from types import SimpleNamespace

from cerberus import rules, textsafe
from cerberus.textsafe import NOTE_BIDI, NOTE_CONTROL, NOTE_INVISIBLE


def _device(*, notes=(), per_field=None, keyboard=False, classes=(),
            interfaces=None):
    """
    A stub carrying exactly what evaluate() reads for these rules.

    string_notes and string_note_fields are what descriptors.py attaches after
    sanitising; the rest is the minimum evaluate() touches without erroring.
    """
    ifaces = interfaces if interfaces is not None else []
    return SimpleNamespace(
        string_notes=tuple(notes),
        string_note_fields=per_field or {},
        interfaces=ifaces,
        interface_classes=list(classes),
        manufacturer="stub", product="stub", serial="stub",
    )


class CraftedStringFinding(unittest.TestCase):

    def _findings(self, dev):
        return {f.rule_id: f for f in rules.evaluate(dev)}

    def test_a_control_character_produces_a_warning(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]})
        found = self._findings(dev)
        self.assertIn("crafted-strings", found)
        self.assertEqual(found["crafted-strings"].severity,
                         rules.Severity.WARNING)

    def test_a_bidi_override_produces_the_same_warning(self):
        dev = _device(notes=(NOTE_BIDI,),
                      per_field={"iProduct": [NOTE_BIDI]})
        self.assertIn("crafted-strings", self._findings(dev))

    def test_the_finding_names_the_field_that_was_crafted(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL],
                                 "iProduct": [], "iSerialNumber": []})
        finding = self._findings(dev)["crafted-strings"]
        self.assertIn("manufacturer name", finding.explanation)

    def test_invisible_characters_are_a_notice_not_a_warning(self):
        dev = _device(notes=(NOTE_INVISIBLE,),
                      per_field={"iSerialNumber": [NOTE_INVISIBLE]})
        found = self._findings(dev)
        self.assertIn("invisible-string-characters", found)
        self.assertEqual(found["invisible-string-characters"].severity,
                         rules.Severity.NOTICE)
        self.assertNotIn("crafted-strings", found)

    def test_a_clean_device_produces_no_string_finding(self):
        dev = _device()
        found = self._findings(dev)
        self.assertNotIn("crafted-strings", found)
        self.assertNotIn("invisible-string-characters", found)

    def test_the_real_test_devices_produce_no_string_finding(self):
        """The zero-finding fixtures must stay at zero for these rules."""
        for name in ("PixArt", "Realtek", "Chicony", "General UDisk"):
            dev = _device()
            dev.manufacturer = name
            self.assertNotIn("crafted-strings", self._findings(dev), name)

    # ---- the escalation: crafted name AND able to type ----

    def test_a_typing_device_with_a_crafted_name_is_critical(self):
        """
        Keyboard + control characters in its own name is intent, not
        sloppiness, and is treated like the other BadUSB signatures.
        """
        kbd = SimpleNamespace(interface_class=rules.CLS_HID,
                              interface_subclass=1, interface_protocol=1)
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]},
                      classes=(rules.CLS_HID,), interfaces=[kbd])
        found = self._findings(dev)
        self.assertIn("crafted-strings-hid", found)
        self.assertEqual(found["crafted-strings-hid"].severity,
                         rules.Severity.CRITICAL)

    def test_a_non_typing_device_with_a_crafted_name_is_only_a_warning(self):
        """The escalation must require the keyboard, not just the strings."""
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iProduct": [NOTE_CONTROL]},
                      classes=(rules.CLS_MASS_STORAGE,))
        found = self._findings(dev)
        self.assertNotIn("crafted-strings-hid", found)
        self.assertIn("crafted-strings", found)

    # ---- configurability, via the existing machinery ----

    def test_the_string_rule_can_be_raised_to_critical_by_config(self):
        dev = _device(notes=(NOTE_CONTROL,),
                      per_field={"iManufacturer": [NOTE_CONTROL]})
        cfg = rules.RuleConfig(
            severity_overrides={"crafted-strings": rules.Severity.CRITICAL})
        found = {f.rule_id: f for f in rules.evaluate(dev, cfg)}
        self.assertEqual(found["crafted-strings"].severity,
                         rules.Severity.CRITICAL)

    def test_the_invisible_rule_can_be_silenced_independently(self):
        dev = _device(notes=(NOTE_INVISIBLE,),
                      per_field={"iSerialNumber": [NOTE_INVISIBLE]})
        cfg = rules.RuleConfig(disabled={"invisible-string-characters"})
        found = {f.rule_id: f for f in rules.evaluate(dev, cfg)}
        self.assertNotIn("invisible-string-characters", found)


class DialogMarkupEscaping(unittest.TestCase):
    """
    The kdialog and zenity backends render markup; a device name that looks
    like HTML must not become HTML in the prompt. tkinter and the terminal
    render plain text and must NOT be escaped.
    """

    def setUp(self):
        from cerberus import dialogs
        self.dialogs = dialogs

    def test_markup_safe_neutralises_tags(self):
        self.assertEqual(self.dialogs._markup_safe("<b>x</b>"),
                         "&lt;b&gt;x&lt;/b&gt;")

    def test_markup_safe_neutralises_a_link(self):
        raw = 'Kingston<a href="file:///etc/shadow">.</a>'
        self.assertNotIn("<a", self.dialogs._markup_safe(raw))

    def test_markup_safe_preserves_a_legitimate_name(self):
        """"A<B & C>D" is a real name shape and must survive, just inert."""
        out = self.dialogs._markup_safe("A<B & C>D")
        self.assertEqual(out, "A&lt;B &amp; C&gt;D")
        self.assertNotIn("<", out)

    def test_markup_safe_leaves_ordinary_text_untouched(self):
        self.assertEqual(self.dialogs._markup_safe("Kingston DataTraveler"),
                         "Kingston DataTraveler")


if __name__ == "__main__":
    unittest.main()
