#!/usr/bin/env python3
"""
apply_integrations.py — Ενσωματώνει τα δύο νέα modules στη ροή.

Δύο ανεξάρτητες αλλαγές:
  1. __main__.py: νέο --history flag + handler (read-only, δίπλα στο --trusted)
  2. storage.py: θωράκιση του partition offset (safe_read_offset αντί για
     γυμνό start_lba * SECTOR) + suspicious field στο report

Idempotent, κρατά .bak, fail-closed αν κάποιο anchor δεν βρεθεί.
Τρέξε από τη ρίζα του repo:  python apply_integrations.py
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


def replace_once(path, old, new, marker):
    if not path.exists():
        fail(f"δεν βρέθηκε {path}")
    text = path.read_text()
    if marker in text:
        print(f"  = {path.name}: ήδη εφαρμοσμένο ({marker!r}), προσπέραση")
        return
    if old not in text:
        fail(f"{path.name}: δεν βρέθηκε το σημείο\n         {old[:70]!r}")
    if text.count(old) > 1:
        fail(f"{path.name}: αμφίσημο anchor ({text.count(old)} φορές)")
    shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.write_text(text.replace(old, new, 1))
    print(f"  + {path.name}: εφαρμόστηκε (.bak κρατήθηκε)")


# --------------------------------------------------------------------------
# 1. __main__.py — flag + handler
# --------------------------------------------------------------------------
# 1α. Το flag, δίπλα στο --trusted.
replace_once(
    PKG / "__main__.py",
    old='    parser.add_argument("--forget", metavar="PATTERN",\n'
        '                        help="remove a remembered device: a number from "\n'
        '                             "--trusted, a name/id substring, or \'all\'")\n',
    new='    parser.add_argument("--forget", metavar="PATTERN",\n'
        '                        help="remove a remembered device: a number from "\n'
        '                             "--trusted, a name/id substring, or \'all\'")\n'
        '    parser.add_argument("--history", action="store_true",\n'
        '                        help="show the recorded history of every USB device seen, and exit")\n',
    marker='"--history"',
)

# 1β. Ο handler, δίπλα στο --trusted dispatch.
replace_once(
    PKG / "__main__.py",
    old="    if args.trusted:\n"
        "        cmd_trusted(trust_path)\n"
        "        return\n",
    new="    if args.trusted:\n"
        "        cmd_trusted(trust_path)\n"
        "        return\n"
        "    if args.history:\n"
        "        from . import history\n"
        "        print(history.show_history(verbose=args.verbose,\n"
        "                                   path=args.ledger if args.ledger else None))\n"
        "        return\n",
    marker="args.history:",
)


# --------------------------------------------------------------------------
# 2. storage.py — θωράκιση offset
# --------------------------------------------------------------------------
# 2α. import του hardening + suspicious field.
replace_once(
    PKG / "storage.py",
    old="from typing import List, Optional\n",
    new="from typing import List, Optional\n"
        "\n"
        "from . import storage_hardening\n",
    marker="from . import storage_hardening",
)

replace_once(
    PKG / "storage.py",
    old='    signatures: dict = field(default_factory=dict)  # partition index -> fs name\n'
        '    error: Optional[str] = None\n',
    new='    signatures: dict = field(default_factory=dict)  # partition index -> fs name\n'
        '    suspicious: List[str] = field(default_factory=list)  # impossible/hostile partitions\n'
        '    error: Optional[str] = None\n',
    marker="suspicious: List[str]",
)

# 2β. Το κρίσιμο: αντικατάσταση του γυμνού offset με τον ασφαλή έλεγχο.
replace_once(
    PKG / "storage.py",
    old="    # Read the first sector of each partition to see what is actually there.\n"
        "    for part in report.partitions:\n"
        "        if part.type_byte == PROTECTIVE_MBR_TYPE:\n"
        "            continue\n"
        "        offset = part.start_lba * SECTOR\n"
        "        chunk = _read_at(device, offset, SECTOR, open_fn)\n",
    new="    # Read the first sector of each partition to see what is actually there.\n"
        "    for part in report.partitions:\n"
        "        if part.type_byte == PROTECTIVE_MBR_TYPE:\n"
        "            continue\n"
        "        # HARDENING: never seek to a device-controlled offset without\n"
        "        # checking it fits inside the real device first. A partition\n"
        "        # claiming start_lba=0xFFFFFFFF would otherwise seek to ~2 TB.\n"
        "        offset = storage_hardening.safe_read_offset(\n"
        "            part.start_lba, report.size_sectors)\n"
        "        if offset is None:\n"
        "            report.suspicious.append(\n"
        "                f'partition {part.index}: start_lba {part.start_lba} '\n"
        "                f'does not fit the device; not read')\n"
        "            continue\n"
        "        chunk = _read_at(device, offset, SECTOR, open_fn)\n",
    marker="storage_hardening.safe_read_offset",
)


print("\n[OK] Όλα εφαρμόστηκαν. Έλεγχος:")
print("     python -c 'from cerberus import __main__, storage, history, storage_hardening; print(\"import OK\")'")
print("     python -m cerberus --history")
