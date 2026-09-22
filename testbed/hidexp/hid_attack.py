#!/usr/bin/env python3
"""
hid_attack.py -- Simulates BadUSB keystroke injection, HARMLESSLY.

WHAT IT DOES
------------
Once the gadget is live, sends HID keyboard reports to /dev/hidg0 with the
STRUCTURE of a real DuckyScript payload:

    GUI+r            (open run dialog -- the classic first move)
    <delay>
    burst of keys    (the "payload")
    ENTER

...but the CONTENT is harmless: a repeated marker, not a command. Nothing
executes. The point is to measure LEAKAGE (how many key events reach the
session), not to cause harm.

WHY A HARMLESS PAYLOAD IS SCIENTIFICALLY BETTER
-----------------------------------------------
A real payload that opens a terminal would contaminate the measurement (you
would have to clean up whatever ran) and add risk to your own machine. A
single marker is MEASURABLE: you know exactly how many were sent, so
leaked = (sent) - (Probolos caught).

TIMING IS THE POINT
-------------------
We send with ~8 ms between keys and near-zero variance. This trips ALL
THREE of the detection paths in rules.py:
  - machine-generated (mean < 50 ms, CV < 0.20)
  - immediate-activity (first key < 500 ms after authorize)
  - unprompted-typing (>= 5 keys with nobody touching it)

Run as root (needs write to /dev/hidg0):
    sudo python3 hid_attack.py [--markers N] [--interval-ms M]
"""

import argparse
import os
import sys
import time

HIDG = "/dev/hidg0"

# --- HID usage codes (boot keyboard) --------------------------------------
# Report format: [modifiers, reserved, key1..key6]
MOD_GUI = 0x08              # left GUI (Windows/Super) -- bit in the modifier byte
KEY_R = 0x15                # 'r'
KEY_ENTER = 0x28
KEY_C, KEY_E, KEY_R_, KEY_B, KEY_U, KEY_S = 0x06, 0x08, 0x15, 0x05, 0x18, 0x16
# "CERBS" -- the marker keys (case does not matter; we count events)
MARKER_KEYS = [KEY_C, KEY_E, KEY_R_, KEY_B, KEY_S]

RELEASE = bytes(8)          # all zeros = no key pressed


def _report(modifiers: int = 0, key: int = 0) -> bytes:
    """One 8-byte boot keyboard report: one key at a time."""
    return bytes([modifiers, 0, key, 0, 0, 0, 0, 0])


def _press(fd: int, modifiers: int, key: int, interval: float) -> None:
    """Press + release one key, at the inhuman interval."""
    os.write(fd, _report(modifiers, key))   # press
    time.sleep(interval / 2)
    os.write(fd, RELEASE)                    # release
    time.sleep(interval / 2)


def run_attack(markers: int, interval_ms: float) -> int:
    interval = interval_ms / 1000.0

    if not os.path.exists(HIDG):
        print(f"[!] {HIDG} does not exist. Run hid_gadget_up.sh first.")
        return 0

    fd = os.open(HIDG, os.O_WRONLY)
    sent = 0
    try:
        # --- Phase 1: GUI+r (the Rubber Ducky signature move) ---
        # Modifier + key together, then release.
        os.write(fd, _report(MOD_GUI, KEY_R))
        time.sleep(interval / 2)
        os.write(fd, RELEASE)
        time.sleep(interval / 2)
        sent += 1

        # A short pause, as a real payload would wait for the dialog.
        time.sleep(0.05)

        # --- Phase 2: burst of markers, inhuman rhythm ---
        for _ in range(markers):
            for key in MARKER_KEYS:
                _press(fd, 0, key, interval)
                sent += 1

        # --- Phase 3: ENTER (execution, in the real attack) ---
        _press(fd, 0, KEY_ENTER, interval)
        sent += 1

    finally:
        os.write(fd, RELEASE)   # always leave the keys released
        os.close(fd)

    print(f"[+] Sent {sent} keystrokes at {interval_ms:.0f} ms intervals "
          f"(inhuman: steady, no variance).")
    print(f"    All {sent} should have been caught by Probolos.")
    print(f"    Whatever reached the session = LEAKAGE.")
    return sent


def main():
    ap = argparse.ArgumentParser(
        description="Harmless BadUSB keystroke injection for leakage measurement")
    ap.add_argument("--markers", type=int, default=8,
                    help="how many times to repeat the 5-key marker "
                         "(default 8 => 40 keystrokes)")
    ap.add_argument("--interval-ms", type=float, default=8.0,
                    help="ms between keys (default 8, below the 50 ms threshold)")
    args = ap.parse_args()

    sent = run_attack(args.markers, args.interval_ms)
    sys.exit(0 if sent else 1)


if __name__ == "__main__":
    main()
