# F3 — ο κανόνας `crafted-strings` για το `rules.py`

Διορθωμένος στο πραγματικό API: `Finding(rule_id, severity, title, explanation)`,
`frozen=True`, χωρίς `evidence`. Το `add()` είναι closure μέσα στην `evaluate()`.

---

## Πού μπαίνει

Μέσα στην `evaluate()`, μετά τους υπάρχοντες κανόνες ταυτότητας (μετά το
`network-with-keyboard`, πριν το `return`). Χρησιμοποιεί το ίδιο `add()` closure
που ήδη υπάρχει, οπότε γίνεται αυτόματα ρυθμιζόμενος από YAML όπως όλοι οι
άλλοι.

```python
    # -- N. Strings crafted to attack the person reading the report --------
    # textsafe records, on the device, WHY each string needed cleaning. Those
    # notes are the finding. No legitimate device puts an escape character in
    # its manufacturer string; the only reason to is to write on the screen of
    # the person deciding, or to make one device's name look like another's.
    string_notes = set(getattr(dev, "string_notes", ()))

    if textsafe.NOTE_CONTROL in string_notes or textsafe.NOTE_BIDI in string_notes:
        fields = _crafted_fields(dev, (textsafe.NOTE_CONTROL, textsafe.NOTE_BIDI))
        add("crafted-strings", Severity.WARNING,
            "This device's name can rewrite what you see",
            f"The device's {fields} contain characters that move the cursor, "
            f"clear the screen, or reorder text as it is drawn. Nothing "
            f"legitimate needs them. Their purpose is to change what this "
            f"report looks like, so read the raw name shown above -- the "
            f"escapes have been made visible on purpose -- rather than the "
            f"shape of the box.")

    elif textsafe.NOTE_INVISIBLE in string_notes:
        fields = _crafted_fields(dev, (textsafe.NOTE_INVISIBLE,))
        add("invisible-string-characters", Severity.NOTICE,
            "This device's name contains invisible characters",
            f"The device's {fields} contain characters that take up no space "
            f"when displayed. Two devices whose names look identical to you "
            f"may differ by one, which is a way for a device to appear to be "
            f"one you have already approved.")
```

Ένα ξεχωριστό `rule_id` για την invisible περίπτωση, ώστε να ρυθμίζεται
ανεξάρτητα: κάποιος μπορεί να σιωπήσει το `invisible-string-characters` (θόρυβος
από φτηνά devices) κρατώντας το `crafted-strings` ενεργό.

---

## Το βοηθητικό, σε module level

Δίπλα στα υπάρχοντα βοηθητικά (π.χ. κοντά στο `_is_benign_group`):

```python
# Which named descriptor fields triggered a crafted-string finding. The report
# already shows the escaped strings; naming the field tells the user WHERE to
# look without making them scan three lines for the one with a backslash in it.
_STRING_FIELD_LABELS = {
    "iManufacturer": "manufacturer name",
    "iProduct": "product name",
    "iSerialNumber": "serial number",
}


def _crafted_fields(dev, notes_of_interest) -> str:
    """
    Human-readable list of the fields whose notes intersect notes_of_interest.

    Falls back to "name" when the per-field breakdown is unavailable, so the
    finding still reads correctly against a stub device in the tests.
    """
    per_field = getattr(dev, "string_note_fields", None)
    if not per_field:
        return "name"
    hit = [
        _STRING_FIELD_LABELS.get(field, field)
        for field, notes in per_field.items()
        if set(notes) & set(notes_of_interest)
    ]
    if not hit:
        return "name"
    if len(hit) == 1:
        return hit[0]
    return ", ".join(hit[:-1]) + " and " + hit[-1]
```

---

## Import

Στην κορυφή του `rules.py`, δίπλα στο `from . import usbclass`:

```python
from . import textsafe, usbclass
```

---

## Ερώτημα σχεδιασμού που άφησα ανοιχτό — τώρα με απάντηση από τον κώδικα

Είχα πει «default WARNING, CRITICAL για control-chars + HID». Ο μηχανισμός για
το δεύτερο μισό υπάρχει ήδη και είναι κομψός: δεν χρειάζεται ειδική περίπτωση
στον κανόνα. Πρόσθεσε αυτό αμέσως μετά το `crafted-strings`:

```python
    # A device that BOTH types and hides escapes in its own name is not a
    # sloppy manufacturer. The BadUSB rule already escalates storage+keyboard;
    # this is the same reasoning for keyboard + a crafted identity.
    if (textsafe.NOTE_CONTROL in string_notes
            and has_keyboard):
        add("crafted-strings-hid", Severity.CRITICAL,
            "A keyboard whose name is built to deceive",
            "This device can type, and its descriptor strings contain "
            "characters chosen to alter what you see on screen. A real "
            "keyboard has no reason to do either of those things to its own "
            "name. Treat the two together as intent, not coincidence.")
```

Το `has_keyboard` υπολογίζεται ήδη στην αρχή της `evaluate()` (το είδα στο
grep), οπότε είναι διαθέσιμο χωρίς επιπλέον δουλειά. Έτσι το CRITICAL μένει
δεσμευμένο για «ταιριάζει με μοτίβο επίθεσης», που είναι η υπάρχουσα σημασία
του — δεν αραιώνει η λέξη.
