#!/usr/bin/env python3
"""
hid_attack.py — Προσομοιώνει BadUSB keystroke injection, ΑΒΛΑΒΩΣ.

ΤΙ ΚΑΝΕΙ
--------
Μόλις το gadget είναι live, στέλνει HID keyboard reports στο /dev/hidg0 με
τη ΔΟΜΗ ενός πραγματικού DuckyScript payload:

    GUI+r            (άνοιγμα run dialog — η κλασική πρώτη κίνηση)
    <delay>
    ριπή χαρακτήρων  (το "payload")
    ENTER

...αλλά το ΠΕΡΙΕΧΟΜΕΝΟ είναι αβλαβές: επαναλαμβανόμενος marker, όχι εντολή.
Τίποτα δεν εκτελείται. Ο σκοπός είναι να μετρήσουμε ΔΙΑΡΡΟΗ (πόσα key
events φτάνουν στη συνεδρία), όχι να προκαλέσουμε ζημιά.

ΓΙΑΤΙ ΑΒΛΑΒΕΣ ΠΕΡΙΕΧΟΜΕΝΟ ΕΙΝΑΙ ΕΠΙΣΤΗΜΟΝΙΚΑ ΣΩΣΤΟΤΕΡΟ
------------------------------------------------------
Ένα πραγματικό payload που ανοίγει terminal θα μόλυνε τη μέτρηση (θα έπρεπε
να καθαρίσεις ό,τι εκτελέστηκε) και θα πρόσθετε ρίσκο στο δικό σου μηχάνημα.
Ο μοναδικός marker είναι ΜΕΤΡΗΣΙΜΟΣ: ξέρεις ακριβώς πόσα στάλθηκαν, άρα
πόσα διέρρευσαν = (στάλθηκαν) - (έπιασε ο Probolos).

ΤΟ TIMING ΕΙΝΑΙ ΤΟ ΚΡΙΣΙΜΟ
--------------------------
Στέλνουμε με ~8 ms ανάμεσα στα πλήκτρα και σχεδόν μηδενική διακύμανση. Αυτό
πυροδοτεί ΚΑΙ ΤΙΣ ΤΡΕΙΣ διαδρομές ανίχνευσης του rules.py:
  - machine-generated (mean < 50 ms, CV < 0.20)
  - immediate-activity (πρώτο πλήκτρο < 500 ms μετά το authorize)
  - unprompted-typing (>= 5 πλήκτρα χωρίς άγγιγμα)

Τρέξε ως root (χρειάζεται write στο /dev/hidg0):
    sudo python3 hid_attack.py [--markers N] [--interval-ms M]
"""

import argparse
import os
import sys
import time

HIDG = "/dev/hidg0"

# --- HID usage codes (boot keyboard) --------------------------------------
# Report format: [modifiers, reserved, key1..key6]
MOD_GUI = 0x08              # left GUI (Windows/Super) — bit στο modifier byte
KEY_R = 0x15               # 'r'
KEY_ENTER = 0x28
KEY_C, KEY_E, KEY_R_, KEY_B, KEY_U, KEY_S = 0x06, 0x08, 0x15, 0x05, 0x18, 0x16
# "CERBS" — τα πλήκτρα του marker (κεφαλαία δεν χρειάζονται· μετράμε events)
MARKER_KEYS = [KEY_C, KEY_E, KEY_R_, KEY_B, KEY_S]

RELEASE = bytes(8)         # όλα μηδέν = κανένα πλήκτρο πατημένο


def _report(modifiers: int = 0, key: int = 0) -> bytes:
    """Ένα 8-byte boot keyboard report: ένα πλήκτρο τη φορά."""
    return bytes([modifiers, 0, key, 0, 0, 0, 0, 0])


def _press(fd: int, modifiers: int, key: int, interval: float) -> None:
    """Πάτημα + απελευθέρωση ενός πλήκτρου, με το inhuman interval."""
    os.write(fd, _report(modifiers, key))   # press
    time.sleep(interval / 2)
    os.write(fd, RELEASE)                    # release
    time.sleep(interval / 2)


def run_attack(markers: int, interval_ms: float) -> int:
    interval = interval_ms / 1000.0

    if not os.path.exists(HIDG):
        print(f"[!] {HIDG} δεν υπάρχει. Τρέξε πρώτα το hid_gadget_up.sh")
        return 1

    fd = os.open(HIDG, os.O_WRONLY)
    sent = 0
    try:
        # --- Φάση 1: GUI+r (η υπογραφή του Rubber Ducky) ---
        # Modifier + πλήκτρο ταυτόχρονα, μετά release.
        os.write(fd, _report(MOD_GUI, KEY_R))
        time.sleep(interval / 2)
        os.write(fd, RELEASE)
        time.sleep(interval / 2)
        sent += 1

        # Μια μικρή παύση όπως θα έκανε ένα payload περιμένοντας το dialog.
        time.sleep(0.05)

        # --- Φάση 2: ριπή markers, inhuman ρυθμός ---
        for _ in range(markers):
            for key in MARKER_KEYS:
                _press(fd, 0, key, interval)
                sent += 1

        # --- Φάση 3: ENTER (εκτέλεση, στο πραγματικό attack) ---
        _press(fd, 0, KEY_ENTER, interval)
        sent += 1

    finally:
        os.write(fd, RELEASE)   # πάντα άφησε τα πλήκτρα ελεύθερα
        os.close(fd)

    print(f"[+] Στάλθηκαν {sent} keystrokes σε ρυθμό {interval_ms:.0f} ms "
          f"(inhuman: σταθερό, χωρίς διακύμανση)")
    print(f"    Απ' αυτά, {sent} θα έπρεπε να πιαστούν από τον Probolos.")
    print(f"    Ό,τι έφτασε στη συνεδρία = ΔΙΑΡΡΟΗ.")
    return sent


def main():
    ap = argparse.ArgumentParser(description="Αβλαβής BadUSB keystroke injection για μέτρηση διαρροής")
    ap.add_argument("--markers", type=int, default=8,
                    help="πόσες φορές να επαναληφθεί το 5-key marker (default 8 => 40 keystrokes)")
    ap.add_argument("--interval-ms", type=float, default=8.0,
                    help="ms ανάμεσα στα πλήκτρα (default 8, κάτω από το 50ms κατώφλι)")
    args = ap.parse_args()

    sent = run_attack(args.markers, args.interval_ms)
    sys.exit(0 if sent else 1)


if __name__ == "__main__":
    main()
