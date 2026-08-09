"""
One place where device-supplied text stops being dangerous.

WHY THIS IS ITS OWN MODULE
--------------------------
Strings in USB descriptors are chosen by the device. iManufacturer, iProduct
and iSerialNumber are attacker-controlled in exactly the way a filename in a
zip archive is, and they end up in a terminal, in kdialog, in zenity, in a
freedesktop notification, in a JSON log, in the trust store and in the ledger.
Sanitising at each of those points means six places to remember and one to
forget, so this happens once, at the boundary where descriptor bytes become a
Python string, and everything downstream inherits it.

WHY NOT ONLY AT DISPLAY TIME
----------------------------
Because the log is a display surface too, just a delayed one. If the analyzer
writes the raw string to probolos.jsonl, a `cat` three days later re-runs the
attack -- in a different terminal, in a different context, possibly on a
different machine after the file was mailed to someone. A payload that waits
in a file for someone to read it is not a smaller problem than one that fires
at the prompt; it is a larger one, because by then nobody is expecting it.

Nothing is lost by cleaning at the source: the unmodified bytes are still in
`raw_descriptors`, which is what the ledger hashes, so drift detection is
untouched and the forensic record is complete.

WHY ESCAPE RATHER THAN STRIP
----------------------------
A control character is replaced with its visible \\xNN form, not deleted. The
user should see WHAT the device sent. "ACME\\x1b[2JCorp" is readable, harmless
-- the ESC is the only dangerous byte, and once it is text the "[2J" beside it
is just letters -- and it is evidence. Deleting it would leave "ACME[2JCorp"
and the person reading it would have no idea why the name looks odd.

WHAT THIS DOES NOT DO
---------------------
It does not stop homoglyphs. A Cyrillic 'а' in "Lоgitech" survives, because
it is a legitimate character that legitimate manufacturers use, and stripping
non-ASCII would mangle every honest device with a Chinese or Japanese name.
Names are not identity in this tool anyway -- the descriptor hash is -- and
the report is built so the decision never rests on a string the device chose.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional

# Longest device string shown or stored. USB string descriptors are bounded by
# bLength at 126 UTF-16 code units, so anything past this is already outside
# the specification and is truncated rather than trusted.
MAX_LENGTH = 126

# Direction-changing characters. These are the Trojan Source family: they
# reorder how text RENDERS without changing what it contains, so a device can
# make "keyboard" appear as something reassuring in the prompt while the
# string that the rules matched on is unchanged.
_BIDI = {
    "\u061c",                                        # arabic letter mark
    "\u200e", "\u200f",                              # LRM, RLM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # embedding/override
    "\u2066", "\u2067", "\u2068", "\u2069",          # isolates
}

# Invisible characters. Two trust-store entries that look identical to a human
# but differ by a zero-width joiner are a way to make a device appear to be
# one that was already approved.
_INVISIBLE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}

# Notes are stable identifiers, not sentences: the rules layer matches on
# them, and the report turns them into English. Changing the wording of a
# message should never change what a rule fires on.
NOTE_CONTROL = "control-characters"
NOTE_BIDI = "bidi-overrides"
NOTE_INVISIBLE = "invisible-characters"
NOTE_TRUNCATED = "over-length"
NOTE_UNDECODABLE = "undecodable-bytes"


@dataclass
class Sanitized:
    """A cleaned string, and what had to be done to it."""
    text: str
    notes: List[str] = field(default_factory=list)

    @property
    def altered(self) -> bool:
        return bool(self.notes)

    def __str__(self) -> str:
        return self.text


def _escape(char: str) -> str:
    """Visible, unambiguous, and ASCII: \\x1b or \\u202e."""
    point = ord(char)
    return f"\\x{point:02x}" if point < 0x100 else f"\\u{point:04x}"


def sanitize(value, limit: int = MAX_LENGTH) -> Sanitized:
    """
    Make one device-supplied string safe to print, log and store.

    Returns the cleaned text together with a list of note identifiers. The
    notes matter as much as the text: no legitimate device puts an escape
    character in its manufacturer string, so removing one silently would
    destroy the strongest single indicator that a descriptor was crafted
    rather than filled in. The caller is expected to turn notes into findings.
    """
    if value is None:
        return Sanitized("")

    notes: List[str] = []

    if isinstance(value, (bytes, bytearray)):
        # Descriptor strings are UTF-16LE per the specification, but a device
        # is free to send something else, and a decoder that raises here would
        # let a malformed string stop the daemon rather than be reported by it.
        text = bytes(value).decode("utf-8", errors="replace")
        if "\ufffd" in text:
            notes.append(NOTE_UNDECODABLE)
    else:
        text = str(value)
        if "\ufffd" in text:
            notes.append(NOTE_UNDECODABLE)

    # Built as TOKENS -- one per source character, each either the character
    # itself or its multi-character escape -- so the length budget below can
    # never cut through the middle of an escape and leave "\x1b\x" behind,
    # which would be both unreadable and, on a terminal, unpredictable.
    out: List[str] = []
    used = 0
    truncated = False
    for char in text:
        category = unicodedata.category(char)

        # Cc is C0 and C1 control characters: ESC, CR, BS, NUL and the 0x80-9f
        # range that some terminals still interpret. This is the class that
        # lets a device redraw the screen above the prompt.
        if category == "Cc":
            notes.append(NOTE_CONTROL)
            token = _escape(char)
        elif char in _BIDI:
            notes.append(NOTE_BIDI)
            token = _escape(char)
        elif char in _INVISIBLE:
            notes.append(NOTE_INVISIBLE)
            token = _escape(char)
        # Cf: remaining format characters. Cs/Co/Cn: surrogates, private use,
        # unassigned -- nothing a real product name contains, and their
        # rendering is undefined, which is the problem.
        elif category in ("Cf", "Cs", "Co", "Cn"):
            notes.append(NOTE_INVISIBLE)
            token = _escape(char)
        else:
            token = char

        if used + len(token) > limit:
            # Keep scanning rather than breaking: a control character past the
            # cut is still evidence about the device, and a device could
            # otherwise hide one behind 126 harmless characters.
            truncated = True
            continue
        out.append(token)
        used += len(token)

    cleaned = "".join(out)
    if truncated:
        cleaned += "..."
        notes.append(NOTE_TRUNCATED)

    # Order-preserving dedupe: one note per KIND of problem, not per
    # occurrence, so a string with forty escapes produces one finding.
    seen, unique = set(), []
    for note in notes:
        if note not in seen:
            seen.add(note)
            unique.append(note)

    return Sanitized(cleaned, unique)


def clean(value, limit: int = MAX_LENGTH) -> Optional[str]:
    """sanitize() when only the text is wanted. None in, None out."""
    if value is None:
        return None
    return sanitize(value, limit).text


# ---------------------------------------------------------------------------
# Display width
# ---------------------------------------------------------------------------

def display_width(text: str) -> int:
    """
    How many terminal columns `text` occupies.

    len() is the wrong answer twice over, and one of the two is not an attack
    at all: a combining accent adds a character and no column, while a CJK
    ideograph adds one character and two columns. A Chinese product name is
    perfectly legitimate and breaks a box drawn with len()-based padding, so
    this is a correctness fix that happens to also close a forgery route.
    """
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def fit(text: str, columns: int) -> str:
    """
    Cut `text` so it occupies at most `columns` terminal columns.

    Cutting by characters would overshoot on wide ones -- the practical effect
    being a device whose name is chosen to push the closing border of the box
    off the line, so the report no longer looks like a report.
    """
    if display_width(text) <= columns:
        return text
    out, width = [], 0
    for char in text:
        step = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in ("W", "F") else 1)
        if width + step > columns - 3:
            break
        out.append(char)
        width += step
    return "".join(out) + "..."


def pad(text: str, columns: int) -> str:
    """Left-align to an exact column count, cutting first if necessary."""
    text = fit(text, columns)
    return text + " " * max(0, columns - display_width(text))
