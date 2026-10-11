"""
history.py — Show the recorded history of every USB device as a table.

The ledger.json already stores everything needed: identity, device type,
first/last seen, count, ports, decisions, and every descriptor hash presented.
This module only READS it (never writes) and presents it.

Wired into __main__.py as a new command:

    python -m probolos --history          # all devices, summary
    python -m probolos --history -v       # with hashes and full decisions

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


def _fit(text: str, width: int) -> str:
    """Cut `text` to `width` columns, marking the cut."""
    return (text[:width - 1] + "\u2026") if len(text) > width else text


def _type_changed(entry) -> bool:
    """True if the device has claimed more than one type under this identity."""
    return len(getattr(entry, "known_types", None) or []) > 1


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

    header = (f"  {'IDENTITY':<22} {'TYPE':<16} {'SEEN':>5}  {'LAST':<9} "
              f"{'DECISION':<11} {'NOTE'}")
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
        identity = _fit(identity, 22)
        # Words from Probolos's own table, but read from a file the
        # unprivileged analyzer writes, so cleaned like everything else.
        kind = _clean(getattr(e, "device_type", "") or "") or "-"

        times = e.times_seen
        last = _age(e.last_seen, now)
        verdict = _verdict(e)
        drift = _drift_flag(e)

        lines.append(f"  {identity:<22} {_fit(kind, 16):<16} {times:>5}  "
                     f"{last:<9} {verdict:<11} {drift}")

        if verbose:
            types = getattr(e, "known_types", None) or []
            if len(types) > 1:
                shown = types if len(types) <= 6 else types[:1] + types[-5:]
                lines.append("       ! type changed: "
                             + " -> ".join(_clean(t) for t in shown))
            else:
                lines.append(f"       type: {kind}")
            ports = ", ".join(dict.fromkeys(_clean(p) for p in e.ports)) or "-"
            lines.append(f"       ports: {ports}")
            if e.decisions:
                hist = " -> ".join(_clean(d) for d in e.decisions[-6:])
                lines.append(f"       decision history: {hist}")
            hashes = getattr(e, "known_hashes", None) or []
            # The hashes shown here are the NORMALIZED fingerprints -- what
            # the drift alarm compares. Their labelling matters: a user who
            # reads "different descriptor hashes" alongside a raw-byte diff
            # is entitled to think the two disagree, when in fact the raw
            # blob can differ (bus negotiation) without the drift fingerprint
            # changing. The raw hash is printed separately below so both
            # views are visible.
            # Cleaned like every other field: the ledger is written by the
            # unprivileged analyzer, and these strings are printed to root.
            if len(hashes) > 1:
                lines.append(f"       ! {len(hashes)} different identity "
                             f"fingerprints (device changed what it claims):")
                for h in hashes:
                    lines.append(f"           {_clean(h[:16])}\u2026")
            elif hashes:
                lines.append(f"       identity fingerprint : "
                             f"{_clean(hashes[0][:16])}\u2026")
            raw = getattr(e, "raw_hash", "") or ""
            if raw:
                lines.append(f"       raw descriptor bytes : {_clean(raw[:16])}\u2026")
            lines.append("")

    if not verbose:
        lines.append("")
        lines.append("  (--history -v for ports, decision history, and descriptor drift)")

    # Risk summary: how many devices show drift or a rejection.
    drifted = sum(1 for e in entries if len(getattr(e, "known_hashes", []) or []) > 1)
    retyped = sum(1 for e in entries if _type_changed(e))
    rejected = sum(1 for e in entries if _verdict(e) == "REJECTED")
    if drifted or retyped or rejected:
        lines.append("")
        if drifted:
            lines.append(f"  ! {drifted} device(s) changed descriptors -- possible spoofing/reprogramming")
        if retyped:
            lines.append(f"  ! {retyped} device(s) now claim a different type "
                         f"than before (--history -v)")
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
    table = format_table(entries, verbose=verbose)
    # A ledger that did not load used to print "History is empty", which
    # reads as nothing ever having been seen -- refusals included.
    error = getattr(led, "load_error", None)
    if error:
        return (f"[!] The history file could not be read: {_clean(str(error))}\n"
                f"    Only what could be read is shown.\n" + table)
    return table
