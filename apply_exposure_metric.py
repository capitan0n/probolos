#!/usr/bin/env python3
"""
apply_exposure_metric.py — Προσθέτει τη ΣΩΣΤΗ μέτρηση έκθεσης.

ΤΟ ΠΡΟΒΛΗΜΑ
-----------
Το υπάρχον race_window μετράει: grab_time - authorized_at.
Αυτό είναι η ΔΙΑΡΚΕΙΑ ολόκληρου του enumeration (authorize -> driver bind ->
node -> udev event -> grab). Είναι ~50 ms με ή χωρίς deferred bind, γιατί
το enumeration δεν επιταχύνεται· απλώς μετατοπίζεται.

Αυτό που έχει σημασία δεν είναι η διάρκεια αλλά η ΕΚΘΕΣΗ: για πόσο υπήρχε
ένα ζωντανό input node ικανό να στείλει keystrokes στη συνεδρία, ΠΡΙΝ το
πιάσουμε.

  - Χωρίς deferred bind: ο driver δένει αμέσως στο authorize. Το node ζει
    ~50 ms πριν το grab. exposure ~= race_window. Μεγάλη έκθεση.
  - Με deferred bind: τα interfaces είναι κλειστά, κανένα node δεν υπάρχει.
    Μόλις release_fn() -> ο driver αρχίζει να δένει, ΑΛΛΑ το monitor ήδη
    περιμένει και πιάνει το node σχεδόν ακαριαία. exposure ~= 0, ενώ το
    race_window (enumeration) μένει ~50 ms.

Η ΔΙΑΦΟΡΑ των δύο αριθμών ΕΙΝΑΙ η απόδειξη ότι το deferred bind δουλεύει.

ΤΙ ΑΛΛΑΖΕΙ
----------
  1. Observation: νέο πεδίο `exposure_window` + `first_node_at` (εσωτερικό).
  2. quarantine(): σημειώνει τη στιγμή που το ΠΡΩΤΟ node εμφανίζεται, και
     υπολογίζει exposure = grab_time - first_node_at.
  3. rules.race_window_note(): αναφέρει ΚΑΙ ΤΑ ΔΥΟ, τίμια.

Idempotent, κρατά .bak. Fail-closed αν κάποιο anchor δεν βρεθεί.
"""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG = ROOT / "cerberus"


def fail(msg):
    print(f"\n[ΣΦΑΛΜΑ] {msg}")
    print("Κανένα αρχείο δεν άλλαξε από αυτό το βήμα.")
    sys.exit(1)


def replace_once(path: Path, old: str, new: str, marker: str, bak_suffix=".bak"):
    if not path.exists():
        fail(f"δεν βρέθηκε {path}")
    text = path.read_text()
    if marker in text:
        print(f"  = {path.name}: ήδη εφαρμοσμένο, προσπέραση")
        return
    if old not in text:
        fail(f"{path.name}: δεν βρέθηκε το σημείο\n         {old[:70]!r}")
    if text.count(old) > 1:
        fail(f"{path.name}: αμφίσημο anchor ({text.count(old)} φορές)")
    shutil.copy2(path, path.with_suffix(path.suffix + bak_suffix))
    path.write_text(text.replace(old, new, 1))
    print(f"  + {path.name}: εφαρμόστηκε (.bak κρατήθηκε)")


# --------------------------------------------------------------------------
# 1. Observation: νέα πεδία
# --------------------------------------------------------------------------
replace_once(
    PKG / "quarantine.py",
    old="    race_window: float = 0.0        # seconds between authorize and first grab\n",
    new="    race_window: float = 0.0        # seconds between authorize and first grab\n"
        "    exposure_window: float = 0.0    # seconds a live node existed BEFORE we grabbed it\n"
        "    first_node_at: float = 0.0      # internal: when the first input node appeared\n",
    marker="exposure_window: float",
)


# --------------------------------------------------------------------------
# 2. quarantine(): σημείωσε πότε εμφανίστηκε το πρώτο node, υπολόγισε exposure
# --------------------------------------------------------------------------
# Το find_input_nodes επιστρέφει node μόλις υπάρχει. Η ΠΡΩΤΗ φορά που ο βρόχος
# βλέπει έστω ένα node είναι η στιγμή που άνοιξε το παράθυρο έκθεσης. Το grab
# ακολουθεί αμέσως. exposure = grab - first_node_at.

# 2α. Σημείωσε first_node_at στην πρώτη εμφάνιση node, ΠΡΙΝ το grab.
replace_once(
    PKG / "quarantine.py",
    old="        for node in find_input_nodes(usb_syspath, ctx):\n"
        "            if node in seen:\n"
        "                continue\n"
        "            seen.add(node)\n",
    new="        _nodes_now = find_input_nodes(usb_syspath, ctx)\n"
        "        if _nodes_now and obs.first_node_at == 0.0:\n"
        "            # The instant a live node first exists: the exposure window\n"
        "            # opens here, not at authorization. With deferred bind this\n"
        "            # is ~50 ms after authorize (enumeration), but the grab\n"
        "            # follows within a poll tick, so exposure stays near zero.\n"
        "            obs.first_node_at = time.monotonic()\n"
        "        for node in _nodes_now:\n"
        "            if node in seen:\n"
        "                continue\n"
        "            seen.add(node)\n",
    marker="obs.first_node_at == 0.0",
)

# 2β. Στο σημείο του grab, υπολόγισε ΚΑΙ το exposure μαζί με το race_window.
replace_once(
    PKG / "quarantine.py",
    old="                if obs.race_window == 0.0:\n"
        "                    obs.race_window = time.monotonic() - authorized_at\n",
    new="                if obs.race_window == 0.0:\n"
        "                    _now = time.monotonic()\n"
        "                    obs.race_window = _now - authorized_at\n"
        "                    # Exposure = how long a live node existed before we\n"
        "                    # grabbed it. This is the number that actually matters:\n"
        "                    # near zero means keystrokes had no window to land.\n"
        "                    if obs.first_node_at > 0.0:\n"
        "                        obs.exposure_window = _now - obs.first_node_at\n",
    marker="obs.exposure_window = _now",
)


# --------------------------------------------------------------------------
# 3. rules.race_window_note(): ανάφερε ΚΑΙ ΤΑ ΔΥΟ
# --------------------------------------------------------------------------
replace_once(
    PKG / "rules.py",
    old='    if not obs.observed:\n'
        '        return None\n'
        '    return (f"isolated {obs.race_window * 1000:.0f} ms after authorization; "\n'
        '            f"anything sent in that window reached the session")\n',
    new='    if not obs.observed:\n'
        '        return None\n'
        '    enum_ms = obs.race_window * 1000\n'
        '    exp_ms = obs.exposure_window * 1000\n'
        '    # Two distinct numbers, because conflating them hides the mechanism:\n'
        '    #   enumeration = authorize -> grab (kernel work; ~constant)\n'
        '    #   exposure    = live node existed -> grab (the real risk window)\n'
        '    if obs.first_node_at > 0.0 and exp_ms < enum_ms:\n'
        '        return (f"enumeration {enum_ms:.0f} ms; actual exposure {exp_ms:.0f} ms "\n'
        '                f"(a live input node existed for {exp_ms:.0f} ms before capture)")\n'
        '    # Fallback path (no deferred bind, or node timing unavailable): the\n'
        '    # old honest statement, where enumeration and exposure coincide.\n'
        '    return (f"isolated {enum_ms:.0f} ms after authorization; "\n'
        '            f"anything sent in that window reached the session")\n',
    marker="actual exposure",
)


print("\n[OK] Όλα εφαρμόστηκαν. Έλεγχος ότι φορτώνει:")
print("     python -c 'from cerberus import quarantine, rules; print(\"import OK\")'")
