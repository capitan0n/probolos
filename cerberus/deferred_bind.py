"""
deferred_bind.py — Κλείσιμο του race window μέσω interface-level authorization.

ΤΟ ΠΡΟΒΛΗΜΑ ΠΟΥ ΛΥΝΕΙ
----------------------
Σήμερα η ροή είναι: authorized=1  ->  ο kernel δένει ΑΜΕΣΩΣ τον usbhid  ->
δημιουργείται evdev node  ->  εμείς κάνουμε grab. Ανάμεσα στο δέσιμο του
driver και στο grab μας μεσολαβούν 41-85 ms (μετρημένα σε πραγματικό υλικό)
στα οποία τα keystrokes της συσκευής φτάνουν στη συνεδρία. Αυτό είναι το
race window του quarantine.py.

Ο kernel Linux (>= 4.4) εκθέτει authorization ΑΝΑ INTERFACE, όχι μόνο ανά
συσκευή:

    /sys/bus/usb/devices/<dev>/authorized              <- ολόκληρη η συσκευή
    /sys/bus/usb/devices/<dev>:<cfg>.<intf>/authorized <- ένα interface

Αν ένα interface είναι authorized=0, ο kernel το ΔΙΑΜΟΡΦΩΝΕΙ αλλά ΔΕΝ δένει
driver πάνω του. Χωρίς driver -> χωρίς usbhid -> χωρίς evdev node -> τα
reports δεν έχουν διαδρομή προς το input subsystem.

Η ΝΕΑ ΣΤΡΑΤΗΓΙΚΗ
----------------
    1. Θέσε κάθε interface authorized=0  (ενόσω η συσκευή είναι ακόμη off)
    2. Θέσε τη συσκευή authorized=1       (διαμορφώνεται, ΚΑΝΕΝΑΣ driver δεν δένει)
    3. Ξεκίνα το monitor
    4. Θέσε τα interfaces authorized=1 ΕΝΑ-ΕΝΑ· τώρα δένει ο driver, εμφανίζεται
       το node, το πιάνουμε
Το παράθυρο δεν μικραίνει — παύει να υπάρχει, γιατί ο driver δεν δένει ποτέ
πριν είμαστε έτοιμοι να πιάσουμε.

ΓΙΑΤΙ INTERFACE-LEVEL ΚΑΙ ΟΧΙ drivers_autoprobe=0
-------------------------------------------------
Ο καθολικός διακόπτης /sys/bus/usb/drivers_autoprobe είναι system-wide state.
Αν ο Cerberus πεθάνει με τον διακόπτη στο 0, ΚΑΜΙΑ νέα συσκευή σε ΟΛΟ το
σύστημα δεν παίρνει driver — το ίδιο lockout που το gate.py παλεύει να
αποτρέψει, σε χειρότερη μορφή. Το interface authorization είναι per-device:
ό,τι πειράζουμε αφορά μόνο τη συγκεκριμένη συσκευή, και αν κάτι πάει στραβά
η ζημιά περιορίζεται σε αυτήν.

FAIL-SAFE
---------
Κάθε interface που θέτουμε σε 0 καταγράφεται. Το context manager τα επαναφέρει
όλα σε 1 στην έξοδο — και σε normal exit ΚΑΙ σε exception — ώστε μια συσκευή
που εγκρίθηκε να μη μείνει με νεκρά interfaces. Αν η συσκευή αποσυνδεθεί στο
ενδιάμεσο, η επαναφορά αγνοεί σιωπηλά τα χαμένα paths.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, List, Optional

from . import sysfs

# Interface directories: <bus>-<port>[.<port>...]:<config>.<interface>
# π.χ. 3-1:1.0, 3-10:1.1. Το config είναι πάντα παρόν, όπως και το interface.
_INTERFACE_RE = re.compile(r":\d+\.\d+$")


def interface_dirs(usb_syspath: Path) -> List[Path]:
    """Τα interface directories που ανήκουν σε ΑΥΤΗ τη συσκευή.

    ΔΥΟ ΜΟΡΦΕΣ PATH — και οι δύο πρέπει να δουλεύουν (bug #1/#5 ξανά):

      bus-view (symlink):   /sys/bus/usb/devices/3-1
          εδώ τα interfaces είναι SIBLINGS: /sys/bus/usb/devices/3-1:1.0
          (ο κατάλογος είναι επίπεδος, όλα δίπλα-δίπλα)

      resolved (pyudev):    /sys/devices/pci.../usb3/3-1
          εδώ τα interfaces είναι CHILDREN: .../usb3/3-1/3-1:1.0
          (το πραγματικό δέντρο συσκευών, ιεραρχικό)

    Ο daemon περνάει τη resolved μορφή (device.sys_path από pyudev), οπότε αν
    ψάχναμε μόνο siblings θα βρίσκαμε 0 interfaces και θα πέφταμε σιωπηλά στο
    fallback — που είναι ακριβώς τι συνέβαινε. Ψάχνουμε και τις δύο θέσεις.

    Ένα interface του '3-1' ονομάζεται πάντα '3-1:<cfg>.<intf>', όπου κι αν
    κάθεται. Το ':' μετά το όνομα είναι που ξεχωρίζει το '3-1:1.0' από το
    '3-10:1.0' — χωρίς αυτό, το prefix '3-1' θα έπιανε λάθος και το '3-10'.
    """
    name = usb_syspath.name
    prefix = name + ":"
    result: List[Path] = []
    seen: set = set()

    # Ψάξε ΚΑΙ μέσα στο ίδιο το device dir (children, resolved μορφή)
    # ΚΑΙ στον γονικό του (siblings, bus-view μορφή).
    for base in (usb_syspath, usb_syspath.parent):
        try:
            entries = sorted(base.iterdir())
        except OSError:
            # Η συσκευή αποσυνδέθηκε ή το path δεν υπάρχει — προσπέρασε.
            continue
        for entry in entries:
            if entry.name in seen:
                continue
            if entry.name.startswith(prefix) and _INTERFACE_RE.search(entry.name):
                if (entry / "authorized").exists():
                    result.append(entry)
                    seen.add(entry.name)
    return result


def supported(usb_syspath: Path) -> bool:
    """True αν αυτή η συσκευή εκθέτει per-interface authorized attributes.

    Αν επιστρέψει False, ο caller πρέπει να πέσει πίσω στην παλιά συμπεριφορά
    (whole-device authorize + grab-race). Η νέα στρατηγική δεν είναι
    διαθέσιμη σε κάθε kernel/συσκευή, και δεν σπάμε τίποτα όταν λείπει.
    """
    return len(interface_dirs(usb_syspath)) > 0


class DeferredBind:
    """Κρατά τα interfaces μιας συσκευής δεμένα-όχι, και τα απελευθερώνει ελεγχόμενα.

    Χρήση ως context manager ΜΕΣΑ στο quarantine authorize_fn:

        with DeferredBind(dev.syspath) as db:
            db.authorize_device()      # συσκευή on, κανένας driver
            ... (ο caller ξεκινά το monitor) ...
            db.release_interfaces()    # τώρα δένουν οι drivers, εμφανίζονται nodes

    Στην έξοδο, όποιο interface έμεινε σε 0 επαναφέρεται σε 1, ώστε μια
    εγκεκριμένη συσκευή να μη μείνει μισο-νεκρή αν κάτι πεταχτεί ενδιάμεσα.
    """

    def __init__(self, usb_syspath: Path, log: Callable[[str], None] = print,
                 dry_run: bool = False):
        self.syspath = usb_syspath
        self.log = log
        self.dry_run = dry_run
        self.interfaces = interface_dirs(usb_syspath)
        self._deauthorized: List[Path] = []
        self._device_authorized = False

    def __enter__(self) -> "DeferredBind":
        # ΒΗΜΑ 1: κλείσε κάθε interface ΠΡΙΝ ανάψεις τη συσκευή. Έτσι όταν
        # η συσκευή γίνει authorized=1, ο kernel δεν έχει σε τι να δέσει driver.
        for intf in self.interfaces:
            if not self.dry_run:
                _write_interface_authorized(intf, 0)
            self._deauthorized.append(intf)
        self.log(f"  - {self.syspath.name}: {len(self._deauthorized)} interface(s) "
                 f"held unbound before power-on")
        return self

    def authorize_device(self) -> None:
        """ΒΗΜΑ 2: άναψε τη συσκευή. Διαμορφώνεται· κανένας driver δεν δένει."""
        if not self.dry_run:
            sysfs.set_authorized(self.syspath, 1)
        self._device_authorized = True

    def release_interfaces(self) -> None:
        """ΒΗΜΑ 4: επίτρεψε το binding, ένα interface τη φορά.

        Μόλις κάθε interface γίνει 1, ο kernel δένει τον driver του και
        (για HID) εμφανίζεται το evdev node — που το monitor του quarantine
        ήδη περιμένει. Επειδή τα βγάζουμε από τη _deauthorized καθώς
        απελευθερώνονται, το __exit__ δεν θα προσπαθήσει να τα ξανα-θέσει.
        """
        for intf in list(self._deauthorized):
            if not self.dry_run:
                _write_interface_authorized(intf, 1)
            self._deauthorized.remove(intf)

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Fail-safe: ό,τι interface έμεινε σε 0 (π.χ. σφάλμα πριν το release,
        # ή interfaces που δεν προλάβαμε) επαναφέρεται σε 1. Μια εγκεκριμένη
        # συσκευή δεν επιτρέπεται να μείνει με νεκρά interfaces.
        #
        # ΠΡΟΣΟΧΗ στη λογική: αν η συσκευή ΔΕΝ εγκρίθηκε τελικά (ο χρήστης
        # είπε όχι), τα interfaces της είναι ούτως ή άλλως άσχετα — η whole
        # device θα γίνει authorized=0 από τον daemon και τα interfaces
        # παύουν να υπάρχουν. Το restore-σε-1 εδώ είναι ασφαλές είτε έτσι
        # είτε αλλιώς: σε deauthorized device δεν κάνει κακό.
        for intf in self._deauthorized:
            try:
                if not self.dry_run:
                    _write_interface_authorized(intf, 1)
            except OSError:
                pass  # συσκευή αποσυνδέθηκε· το path χάθηκε, δεν πειράζει
        self._deauthorized.clear()
        return False  # ποτέ δεν καταπίνουμε exceptions


def _write_interface_authorized(intf_dir: Path, value: int) -> None:
    """Γράφει το authorized ενός interface, μέσω του backend του sysfs.

    Περνά από το ίδιο backend με τα υπόλοιπα privileged writes, ώστε κάτω
    από privilege separation η εγγραφή να γίνεται στο root gate και όχι εδώ.
    """
    sysfs.set_interface_authorized(intf_dir, value)
