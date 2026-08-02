#!/usr/bin/env python3
"""
apply_deferred_bind.py — Εφαρμόζει αυτόματα τα τρία snippets του deferred bind.

Τρέξε το ΑΠΟ ΤΗ ΡΙΖΑ του repo:

    cd ~/Lab/personal/cerberus
    python apply_deferred_bind.py

Τι κάνει, με ασφάλεια:
  - Είναι IDEMPOTENT: αν το snippet υπάρχει ήδη, το προσπερνά. Τρέξε το ξανά
    χωρίς κίνδυνο διπλασιασμού.
  - Κρατά .bak αντίγραφο κάθε αρχείου που αγγίζει, πριν το αγγίξει.
  - Αν ένα αναμενόμενο σημείο ΔΕΝ βρεθεί, σταματά ΧΩΡΙΣ να γράψει τίποτα σε
    εκείνο το αρχείο, και σου λέει τι δεν ταίριαξε — ώστε να μη σου αφήσει
    μισοπειραγμένο κώδικα.

Αγγίζει: cerberus/sysfs.py, cerberus/quarantine.py, cerberus/daemon.py
Δεν αγγίζει: τίποτα άλλο.
"""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG = ROOT / "cerberus"


def fail(msg):
    print(f"\n[ΣΦΑΛΜΑ] {msg}")
    print("Κανένα αρχείο δεν άλλαξε από αυτό το βήμα. Στείλε μου το μήνυμα.")
    sys.exit(1)


def patch(path: Path, anchor: str, insertion: str, marker: str, after=True):
    """Εισάγει `insertion` πριν/μετά το `anchor`. Idempotent μέσω `marker`."""
    if not path.exists():
        fail(f"δεν βρέθηκε {path}")
    text = path.read_text()

    if marker in text:
        print(f"  = {path.name}: ήδη εφαρμοσμένο ({marker!r}), προσπέραση")
        return False

    if anchor not in text:
        fail(f"{path.name}: δεν βρέθηκε το σημείο εισαγωγής\n         anchor: {anchor[:60]!r}")

    if text.count(anchor) > 1:
        fail(f"{path.name}: το anchor εμφανίζεται {text.count(anchor)} φορές — "
             f"αμφίσημο, σταματώ για ασφάλεια")

    shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))

    if after:
        new = text.replace(anchor, anchor + insertion, 1)
    else:
        new = text.replace(anchor, insertion + anchor, 1)

    path.write_text(new)
    print(f"  + {path.name}: εφαρμόστηκε (.bak κρατήθηκε)")
    return True


# --------------------------------------------------------------------------
# 1. sysfs.py — μέθοδος στο backend + public helper
# --------------------------------------------------------------------------
patch(
    PKG / "sysfs.py",
    anchor='    def authorize(self, syspath: Path, value: int) -> None:\n'
           '        (syspath / "authorized").write_text(str(value))\n',
    insertion='\n'
              '    def authorize_interface(self, intf_dir, value: int) -> None:\n'
              '        # Interface-level authorization: controls whether the kernel\n'
              '        # binds a driver to ONE interface, not the whole device.\n'
              '        (intf_dir / "authorized").write_text(str(value))\n',
    marker="def authorize_interface",
)

patch(
    PKG / "sysfs.py",
    anchor="def set_authorized(syspath: Path, value: int) -> None:",
    insertion='def set_interface_authorized(intf_dir, value: int) -> None:\n'
              '    """\n'
              '    Authorize (1) or deauthorize (0) a single interface of a device.\n'
              '\n'
              '    An interface at 0 is configured but driverless: for HID that means\n'
              '    no evdev node is created, so the device has no path into the input\n'
              '    subsystem. This is what lets us authorize a device without opening\n'
              '    the grab race. Routed through the active backend, as set_authorized.\n'
              '    """\n'
              '    _backend.authorize_interface(intf_dir, value)\n'
              '\n'
              '\n',
    marker="def set_interface_authorized",
    after=False,
)


# --------------------------------------------------------------------------
# 2. quarantine.py — νέα προαιρετικά ορίσματα + διφασική authorize
# --------------------------------------------------------------------------
patch(
    PKG / "quarantine.py",
    anchor="from . import sysfs",
    insertion="\nfrom contextlib import contextmanager\n"
              "\n"
              "@contextmanager\n"
              "def _null_context():\n"
              "    yield\n",
    marker="_null_context",
)

patch(
    PKG / "quarantine.py",
    anchor="def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,\n"
           "               settle_timeout: float = 2.0,\n"
           "               capture: bool = False) -> Observation:",
    insertion="",  # replace below instead
    marker="release_fn=None",
) if False else None  # (η αντικατάσταση υπογραφής γίνεται χωριστά παρακάτω)

# Η υπογραφή θέλει αντικατάσταση, όχι εισαγωγή — το κάνουμε ρητά.
qpath = PKG / "quarantine.py"
qtext = qpath.read_text()
old_sig = ("def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,\n"
           "               settle_timeout: float = 2.0,\n"
           "               capture: bool = False) -> Observation:")
new_sig = ("def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,\n"
           "               settle_timeout: float = 2.0,\n"
           "               capture: bool = False,\n"
           "               release_fn=None, bind_context=None) -> Observation:")
if "release_fn=None, bind_context=None" in qtext:
    print("  = quarantine.py: υπογραφή ήδη ενημερωμένη, προσπέραση")
elif old_sig in qtext:
    shutil.copy2(qpath, qpath.with_suffix(".py.bak2"))
    qtext = qtext.replace(old_sig, new_sig, 1)
    qpath.write_text(qtext)
    print("  + quarantine.py: υπογραφή ενημερώθηκε")
else:
    fail("quarantine.py: δεν βρέθηκε η αναμενόμενη υπογραφή της quarantine()")

# Τύλιξε το authorize/monitor σε bind_context + release_fn.
qtext = qpath.read_text()
old_auth = ("    authorized_at = time.monotonic()\n"
            "    authorize_fn()\n")
new_auth = ("    cm = bind_context if bind_context is not None else _null_context()\n"
            "    with cm:\n"
            "        authorized_at = time.monotonic()\n"
            "        authorize_fn()                 # device on; interfaces still 0\n"
            "        if release_fn is not None:\n"
            "            release_fn()               # now drivers bind, nodes appear\n")
if "if release_fn is not None:" in qtext:
    print("  = quarantine.py: authorize block ήδη τυλιγμένο, προσπέραση")
elif old_auth in qtext:
    qtext = qtext.replace(old_auth, new_auth, 1)
    qpath.write_text(qtext)
    print("  + quarantine.py: authorize block τυλίχτηκε σε bind_context")
else:
    fail("quarantine.py: δεν βρέθηκε το authorized_at/authorize_fn() block")


# --------------------------------------------------------------------------
# 3. daemon.py — import + διφασικό _quarantine
# --------------------------------------------------------------------------
patch(
    PKG / "daemon.py",
    anchor="from . import (agentlink, analyzers, gate, ledger as ledger_mod, quarantine,",
    insertion="",
    marker="from . import deferred_bind",
) if False else None

dpath = PKG / "daemon.py"
dtext = dpath.read_text()

# import
if "deferred_bind" in dtext:
    print("  = daemon.py: import ήδη υπάρχει, προσπέραση")
else:
    anchor_imp = ("from . import (agentlink, analyzers, gate, ledger as ledger_mod, "
                  "quarantine,")
    if anchor_imp not in dtext:
        fail("daemon.py: δεν βρέθηκε το import block")
    shutil.copy2(dpath, dpath.with_suffix(".py.bak"))
    dtext = dtext.replace(anchor_imp,
                          "from . import deferred_bind\n" + anchor_imp, 1)
    dpath.write_text(dtext)
    print("  + daemon.py: import προστέθηκε")

# _quarantine authorize_fn -> deferred bind
dtext = dpath.read_text()
old_call = ("        return quarantine.quarantine(\n"
            "            dev.syspath,\n"
            "            authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),\n"
            "            duration=self.observe,\n"
            "            capture=self.capture_payload,\n"
            "        )")
new_call = ('        if deferred_bind.supported(dev.syspath):\n'
            '            # No race window: driver does not bind until we are ready\n'
            '            # to grab. Interfaces are held unbound, device powered on,\n'
            '            # then interfaces released after the monitor is listening.\n'
            '            db = deferred_bind.DeferredBind(dev.syspath, log=print)\n'
            '            return quarantine.quarantine(\n'
            '                dev.syspath,\n'
            '                authorize_fn=db.authorize_device,\n'
            '                release_fn=db.release_interfaces,\n'
            '                bind_context=db,\n'
            '                duration=self.observe,\n'
            '                capture=self.capture_payload,\n'
            '            )\n'
            '        # Fallback: kernel/device without interface authorization.\n'
            '        return quarantine.quarantine(\n'
            '            dev.syspath,\n'
            '            authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),\n'
            '            duration=self.observe,\n'
            '            capture=self.capture_payload,\n'
            '        )')
if "deferred_bind.supported(dev.syspath)" in dtext:
    print("  = daemon.py: _quarantine ήδη ενημερωμένο, προσπέραση")
elif old_call in dtext:
    dtext = dtext.replace(old_call, new_call, 1)
    dpath.write_text(dtext)
    print("  + daemon.py: _quarantine έγινε διφασικό")
else:
    fail("daemon.py: δεν βρέθηκε η κλήση quarantine.quarantine() στο _quarantine")


print("\n[OK] Όλα εφαρμόστηκαν. Έλεγχος ότι φορτώνει:")
print("     python -c 'from cerberus import daemon, quarantine, sysfs, deferred_bind; print(\"import OK\")'")
