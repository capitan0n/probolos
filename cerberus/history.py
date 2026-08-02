"""
history.py — Εμφανίζει το ιστορικό όλων των USB συσκευών ως πίνακα.

Το ledger.json ΗΔΗ κρατά ό,τι χρειάζεται: ταυτότητα, πρώτη/τελευταία εμφάνιση,
πλήθος, ports, αποφάσεις, και κάθε descriptor hash που παρουσιάστηκε. Αυτό το
module απλώς το ΔΙΑΒΑΖΕΙ (ποτέ δεν γράφει) και το παρουσιάζει.

Ενσωματώνεται ως νέα εντολή στο __main__.py:

    python -m cerberus --history          # όλες οι συσκευές, σύνοψη
    python -m cerberus --history -v       # με hashes και πλήρεις αποφάσεις

Read-only: δεν αγγίζει καμία συσκευή, δεν χρειάζεται root, δεν τρέχει daemon.
"""

from __future__ import annotations

import time
from typing import List

from . import ledger as ledger_mod


def _age(ts: float, now: float) -> str:
    """Ανθρώπινη μορφή για 'πόσο πριν'. Σύντομο, για να χωρά σε στήλη."""
    delta = now - ts
    if delta < 60:
        return "τώρα"
    if delta < 3600:
        return f"{int(delta // 60)}λ πριν"
    if delta < 86400:
        return f"{int(delta // 3600)}ω πριν"
    return f"{int(delta // 86400)}μ πριν"


def _verdict(entry) -> str:
    """
    Η πιο πρόσφατη απόφαση για αυτή τη συσκευή, σε μία λέξη.

    Οι decisions αποθηκεύονται χρονολογικά· η τελευταία είναι η τρέχουσα
    στάση. Ένα device που κάποτε απορρίφθηκε και μετά εγκρίθηκε δείχνει
    'authorized' — αλλά το ιστορικό (στο -v) κρατά και τις δύο.
    """
    if not entry.decisions:
        return "—"
    last = entry.decisions[-1]
    # Κανονικοποίηση σε σύντομες, σταθερές ετικέτες.
    mapping = {
        "authorized": "AUTHORIZED",
        "allowed": "AUTHORIZED",
        "trusted": "TRUSTED",
        "rejected": "REJECTED",
        "denied": "REJECTED",
        "blocked": "BLOCKED",
    }
    return mapping.get(last.lower(), last.upper()[:10])


def _drift_flag(entry) -> str:
    """
    '⚠ DRIFT' αν η συσκευή έχει παρουσιάσει πάνω από ένα descriptor hash.

    Πολλαπλά hashes κάτω από την ίδια ταυτότητα σημαίνει ότι η συσκευή άλλαξε
    τι δηλώνει ότι είναι — το ακριβές σημάδι ενός descriptor-spoofing ή ενός
    reprogrammed BadUSB. Αυτό είναι το ισχυρότερο στοιχείο του πίνακα.
    """
    hashes = getattr(entry, "known_hashes", None) or []
    if len(hashes) > 1:
        return f"DRIFT×{len(hashes)}"
    return ""


def format_table(entries: List, verbose: bool = False) -> str:
    """Χτίζει τον πίνακα ως string. Κρατιέται στενός για terminal 80 στηλών."""
    now = time.time()

    if not entries:
        return "Το ιστορικό είναι κενό — καμία συσκευή δεν έχει καταγραφεί ακόμη."

    # Ταξινόμηση: πιο πρόσφατα ιδωμένες πρώτα.
    entries = sorted(entries, key=lambda e: e.last_seen, reverse=True)

    lines = []
    lines.append("")
    lines.append(f"  Καταγεγραμμένες συσκευές: {len(entries)}")
    lines.append("")

    # Κεφαλίδα
    header = f"  {'ΤΑΥΤΟΤΗΤΑ':<24} {'ΦΟΡΕΣ':>5}  {'ΤΕΛΕΥΤΑΙΑ':<10} {'ΑΠΟΦΑΣΗ':<11} {'ΣΗΜΕΙΩΣΗ'}"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))

    for e in entries:
        identity = (e.identity[:23] + "…") if len(e.identity) > 24 else e.identity
        times = e.times_seen
        last = _age(e.last_seen, now)
        verdict = _verdict(e)
        drift = _drift_flag(e)

        lines.append(f"  {identity:<24} {times:>5}  {last:<10} {verdict:<11} {drift}")

        if verbose:
            # Πλήρεις λεπτομέρειες κάτω από κάθε γραμμή.
            ports = ", ".join(dict.fromkeys(e.ports)) or "—"
            lines.append(f"       ports: {ports}")
            if e.decisions:
                # Δείξε τη διαδρομή αποφάσεων, όχι μόνο την τελευταία.
                hist = " → ".join(e.decisions[-6:])
                lines.append(f"       ιστορικό αποφάσεων: {hist}")
            hashes = getattr(e, "known_hashes", None) or []
            if len(hashes) > 1:
                lines.append(f"       ⚠ {len(hashes)} διαφορετικά descriptor hashes "
                             f"(η συσκευή άλλαξε ταυτότητα):")
                for h in hashes:
                    lines.append(f"           {h[:16]}…")
            elif hashes:
                lines.append(f"       descriptor: {hashes[0][:16]}…")
            lines.append("")

    if not verbose:
        lines.append("")
        lines.append("  (--history -v για ports, ιστορικό αποφάσεων, και descriptor drift)")

    # Σύνοψη κινδύνου: πόσες συσκευές έχουν drift ή απόρριψη.
    drifted = sum(1 for e in entries if len(getattr(e, "known_hashes", []) or []) > 1)
    rejected = sum(1 for e in entries if _verdict(e) == "REJECTED")
    if drifted or rejected:
        lines.append("")
        if drifted:
            lines.append(f"  ⚠ {drifted} συσκευή(ές) άλλαξαν descriptor — πιθανό spoofing/reprogramming")
        if rejected:
            lines.append(f"  ⚠ {rejected} συσκευή(ές) έχουν απορριφθεί στο παρελθόν")

    lines.append("")
    return "\n".join(lines)


def show_history(verbose: bool = False, path=None) -> str:
    """
    Entry point για το CLI. Φορτώνει το ledger και επιστρέφει τον πίνακα.

    Καλείται από το __main__.py:

        if args.history:
            print(history.show_history(verbose=args.verbose))
            return
    """
    led = ledger_mod.Ledger(path) if path else ledger_mod.Ledger()
    # Ο Ledger φορτώνει μόνος του στο __init__· δεν ξανακαλούμε load().
    entries = list(led.entries.values()) if hasattr(led, "entries") else []
    return format_table(entries, verbose=verbose)
