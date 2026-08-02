"""
history.py — Show the recorded history of every USB device as a table.

The ledger.json already stores everything needed: identity, first/last seen,
count, ports, decisions, and every descriptor hash presented. This module only
READS it (never writes) and presents it.

Wired into __main__.py as a new command:

    python -m cerberus --history          # all devices, summary
    python -m cerberus --history -v       # with hashes and full decisions

Read-only: touches no device, needs no root beyond ledger access, runs no daemon.
"""

from __future__ import annotations

import time
from typing import List

from . import ledger as ledger_mod


def _age(ts: float, now: float) -> str:
    """Human form of 'how long ago'. Short, to fit a column."""
    delta = now - ts
    if delta < 60:
        return "now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def _clean(text: str) -> str:
    """
    Strip device-controlled strings of non-printable/dangerous characters.

    A General UDisk's serial (and other cheap devices') often contains invalid
    UTF bytes that render as mojibake. Worse, a hostile serial could carry
    terminal escape sequences. Keep only printable ASCII plus a few safe
    punctuation characters; anything else becomes '.'.
    """
    if not text:
        return text
    out = []
    for ch in text:
        if 0x20 <= ord(ch) < 0x7F or ch in "-_.:":
            out.append(ch)
        else:
            out.append(".")
    return "".join(out)


def _verdict(entry) -> str:
    """
    The most recent decision for this device, in one word.

    Decisions are stored chronologically; the last is the current stance. A
    device once rejected and later approved shows 'AUTHORIZED' -- but the full
    history (in -v) keeps both. Real strings the daemon writes: "user approved",
    "user rejected", "trusted", "dry-run", "protected: ...", "auto-denied ...".
    """
    if not entry.decisions:
        return "-"
    last = entry.decisions[-1].lower().strip()
    if "trusted" in last:
        return "TRUSTED"
    if "approv" in last or "allow" in last:
        return "AUTHORIZED"
    if "reject" in last or "den" in last:
        return "REJECTED"
    if "protect" in last:
        return "PROTECTED"
    if "dry" in last:
        return "DRY-RUN"
    return _clean(last.upper())[:11]


def _drift_flag(entry) -> str:
    """
    'DRIFTxN' if the device has presented more than one descriptor hash.

    Multiple hashes under one identity means the device changed what it claims
    to be -- the exact signature of descriptor spoofing or a reprogrammed
    BadUSB. This is the strongest signal in the table.
    """
    hashes = getattr(entry, "known_hashes", None) or []
    if len(hashes) > 1:
        return f"DRIFTx{len(hashes)}"
    return ""


def format_table(entries: List, verbose: bool = False) -> str:
    """Build the table as a string. Kept narrow for an 80-column terminal."""
    now = time.time()

    if not entries:
        return "History is empty -- no device has been recorded yet."

    # Sort: most recently seen first.
    entries = sorted(entries, key=lambda e: e.last_seen, reverse=True)

    lines = []
    lines.append("")
    lines.append(f"  Recorded devices: {len(entries)}")
    lines.append("")

    header = f"  {'IDENTITY':<22} {'SEEN':>5}  {'LAST':<9} {'DECISION':<11} {'NOTE'}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))

    for e in entries:
        # Identity is vendor:product:serial. The serial may contain mojibake
        # (device-controlled), so we clean it. Keep vendor:product intact and
        # show a cleaned serial only when present.
        raw_id = _clean(e.identity)
        parts = raw_id.split(":")
        if len(parts) >= 3:
            vidpid = ":".join(parts[:2])
            serial = ":".join(parts[2:]).strip()
            if serial and serial != "-":
                identity = f"{vidpid} ({serial[:8]})"
            else:
                identity = vidpid
        else:
            identity = raw_id
        identity = (identity[:21] + "\u2026") if len(identity) > 22 else identity

        times = e.times_seen
        last = _age(e.last_seen, now)
        verdict = _verdict(e)
        drift = _drift_flag(e)

        lines.append(f"  {identity:<22} {times:>5}  {last:<9} {verdict:<11} {drift}")

        if verbose:
            ports = ", ".join(dict.fromkeys(_clean(p) for p in e.ports)) or "-"
            lines.append(f"       ports: {ports}")
            if e.decisions:
                hist = " -> ".join(_clean(d) for d in e.decisions[-6:])
                lines.append(f"       decision history: {hist}")
            hashes = getattr(e, "known_hashes", None) or []
            if len(hashes) > 1:
                lines.append(f"       ! {len(hashes)} different descriptor hashes "
                             f"(device changed its identity):")
                for h in hashes:
                    lines.append(f"           {h[:16]}\u2026")
            elif hashes:
                lines.append(f"       descriptor: {hashes[0][:16]}\u2026")
            lines.append("")

    if not verbose:
        lines.append("")
        lines.append("  (--history -v for ports, decision history, and descriptor drift)")

    # Risk summary: how many devices show drift or a rejection.
    drifted = sum(1 for e in entries if len(getattr(e, "known_hashes", []) or []) > 1)
    rejected = sum(1 for e in entries if _verdict(e) == "REJECTED")
    if drifted or rejected:
        lines.append("")
        if drifted:
            lines.append(f"  ! {drifted} device(s) changed descriptors -- possible spoofing/reprogramming")
        if rejected:
            lines.append(f"  ! {rejected} device(s) have been rejected before")

    lines.append("")
    return "\n".join(lines)


def show_history(verbose: bool = False, path=None) -> str:
    """
    CLI entry point. Loads the ledger and returns the table.

    Called from __main__.py:

        if args.history:
            print(history.show_history(verbose=args.verbose))
            return
    """
    led = ledger_mod.Ledger(path) if path else ledger_mod.Ledger()
    # Ledger loads itself in __init__; we do not call load() again.
    entries = list(led.entries.values()) if hasattr(led, "entries") else []
    return format_table(entries, verbose=verbose)
