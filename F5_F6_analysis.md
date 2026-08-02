# F5 + F6 — storage inspection: το stall και η σειρά

Δύο findings που μοιράζονται το ίδιο κομμάτι κώδικα (Stage 4), αλλά είναι
ανεξάρτητα και έχουν πολύ διαφορετικό μέγεθος. Το F5 είναι σίγουρο και μικρό.
Το F6 εξαρτάται από ένα γεγονός για το σύστημα που πρέπει να επιβεβαιώσεις.

---

## F5 — ένα stall στην επιθεώρηση ανοίγει την πύλη

### Το πρόβλημα, ξεκάθαρα

Το `_inspect_medium` διαβάζει το block device. Μια συσκευή μπορεί να κολλήσει
μια ανάγνωση επ' αόριστον — USB storage που δεν απαντά είναι κλασικό, και μια
**κακόβουλη** συσκευή το κάνει επίτηδες. Αν αυτή η ανάγνωση δεν είναι μέσα σε
`watchdog.paused()`, τότε:

```
συσκευή κολλάει read → daemon παγώνει → watchdog: "no progress 60s"
    → on_stall → opened.restore() → authorized_default=1 → ΠΥΛΗ ΑΝΟΙΧΤΗ
```

Το fail-safe του watchdog (που υπάρχει για να μη σε κλειδώσει έξω) γίνεται
fail-**open**: μια συσκευή που κολλάει τη δική της επιθεώρηση ασφαλείας
κατεβάζει την άμυνα για **όλες** τις θύρες.

### Γιατί δεν αρκεί το `paused()`

Προσοχή — εδώ είναι το λεπτό σημείο. Το `paused()` λέει στο watchdog «μη
μετράς, περιμένω κάτι νόμιμο». Αλλά μια ανάγνωση που κολλάει **δεν είναι
νόμιμη αναμονή** — είναι ακριβώς η επίθεση. Αν απλώς τυλίξεις το inspect σε
`paused()`, το stall δεν πυροδοτεί πια το watchdog, αλλά ο daemon **παραμένει
παγωμένος για πάντα** και καμία επόμενη συσκευή δεν εξετάζεται. Μετέτρεψες ένα
fail-open σε deadlock.

Η σωστή διόρθωση είναι **timeout στην ίδια την ανάγνωση**, ΚΑΙ `paused()` γύρω
από αυτήν:

- Το timeout εξασφαλίζει ότι το inspect τελειώνει πάντα, είτε με δεδομένα είτε
  με «η συσκευή δεν απάντησε — finding».
- Το `paused()` εξασφαλίζει ότι όσο τρέχει το (φραγμένο πλέον) inspect, το
  watchdog δεν το εκλαμβάνει ως stall.

### Ο μηχανισμός του timeout

Ένα `signal.alarm` δεν κάνει: το inspect τρέχει στο νήμα του udev loop, όχι
στο main thread, και τα POSIX signals παραδίδονται μόνο στο main thread. Δύο
επιλογές που δουλεύουν:

**Επιλογή Α — read σε child process με `subprocess`/`multiprocessing` +
timeout.** Το πιο ανθεκτικό: ένα κολλημένο `read()` σε D-state δεν διακόπτεται
ούτε από signal, οπότε μόνο η θανάτωση ξεχωριστής διεργασίας το σκοτώνει
σίγουρα. Ακριβότερο σε πολυπλοκότητα.

**Επιλογή Β — μη-φραγμένο I/O με `select`/`poll` και deadline.** Ανοίγεις το
block device με `os.O_NONBLOCK`, και κάθε `read` προηγείται από `select` με
υπόλοιπο χρόνο. Καθαρότερο, αλλά το `O_NONBLOCK` σε block device δεν εγγυάται
non-blocking reads σε όλους τους kernels — για τακτικά αρχεία/block ο πυρήνας
μπορεί να αγνοήσει το flag.

Χρειάζομαι τον κώδικα του `storage.py` για να διαλέξω. Αν το inspect είναι ήδη
δομημένο ως «άνοιξε fd, διάβασε N γνωστά offsets», η Επιλογή Α τυλίγει όλη τη
συνάρτηση σε process με timeout και είναι λίγες γραμμές. Η μορφή:

```python
import multiprocessing

def inspect_medium_with_timeout(devnode, timeout=10.0):
    """
    Run the raw-block inspection under a hard time limit.

    A storage device can stall a read forever -- ordinary for flaky USB, and a
    deliberate move for a hostile one. Without a bound the daemon freezes; with
    the watchdog watching, that freeze becomes the watchdog opening the gate
    system-wide. So the read runs in a child process that is killed on timeout,
    and a timeout is itself a finding: a device that will not let itself be
    inspected has told you something.
    """
    parent_conn, child_conn = multiprocessing.Pipe()
    proc = multiprocessing.Process(
        target=_inspect_worker, args=(devnode, child_conn), daemon=True)
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():
            proc.kill()
        return StorageReport(
            error="device did not respond within "
                  f"{timeout:.0f}s -- inspection abandoned",
            timed_out=True)
    if parent_conn.poll():
        return parent_conn.recv()
    return StorageReport(error="inspection process produced no result")
```

### Και το `paused()`, στο `daemon.py`

Όπου καλείται σήμερα το inspect, τυλίγεται:

```python
    if self.inspect_storage and _is_storage(dev):
        # paused(): the inspection is legitimate work, not a stall, so the
        # watchdog must not count it. The timeout INSIDE inspect_medium is what
        # actually bounds it -- paused() alone would turn a hostile stall from
        # a fail-open into a permanent freeze. Both are needed: the timeout
        # guarantees the work ends, paused() stops the watchdog misreading it
        # while it runs.
        with self.watchdog.paused() if self.watchdog else _nullcontext():
            report = storage.inspect_medium_with_timeout(devnode)
        findings += rules.storage_findings(report, self.rule_config)
```

με `_nullcontext` για την περίπτωση χωρίς watchdog (dry-run/tests):

```python
from contextlib import nullcontext as _nullcontext   # py3.7+
```

---

## F6 — η σειρά: authorize πριν την ανθρώπινη απόφαση

### Το ερώτημα που καθορίζει τα πάντα

Το docstring του `storage.py` λέει ότι διαβάζει το **raw block device**
read-only. Αν αυτό ισχύει, το `/dev/sdX` node πρέπει να είναι προσβάσιμο. Το
κρίσιμο: **υπάρχει το node όσο η συσκευή είναι `authorized=0`;**

Τρέξε αυτό με μια πραγματική στικ:

```bash
# σε ένα terminal, κράτα τη συσκευή στο authorized=0 χειροκίνητα:
echo 0 | sudo tee /sys/bus/usb/devices/<port>/authorized
# υπάρχει block node;
ls -l /sys/bus/usb/devices/<port>/*/host*/target*/*/block/ 2>/dev/null
lsblk
```

**Αν το node ΔΕΝ υπάρχει στο authorized=0** → ο σχεδιασμός έχει εγγενή
αντίφαση: πρέπει να εξουσιοδοτήσεις για να επιθεωρήσεις, και μόλις
εξουσιοδοτήσεις το udisks2 κάνει automount. Η μόνη σωστή λύση είναι
**interface-level authorization**: εξουσιοδοτείς τη συσκευή αλλά κρατάς το
mass-storage interface στο `authorized=0` μέσω
`/sys/bus/usb/devices/<port>/<port>:1.0/authorized`. Αυτό είναι το ίδιο
μηχανισμός με το F8 (`interface_authorized_default`) που ήδη έχεις στο
roadmap — τα δύο ενώνονται. Μεγάλη αλλαγή, δική της παρτίδα.

**Αν το node ΥΠΑΡΧΕΙ στο authorized=0** → το `set_authorized(1)` στο 240 είναι
απλώς πρόωρο. Το inspect μπορεί να διαβάσει το raw device χωρίς αυτό, και το
`authorized=1` μετακινείται **μετά** την ανθρώπινη απόφαση. Απλή αναδιάταξη:

```
ΤΩΡΑ:   authorize(1) → inspect → prompt → [αν no: authorize(0)]
                ↑ automount window ανοίγει εδώ

ΣΩΣΤΟ:  inspect (raw, στο authorized=0) → prompt → [αν yes: authorize(1)]
                                                          ↑ automount μόνο μετά το yes
```

### Ένα ενδιάμεσο μέτρο ανεξάρτητα από την απάντηση

Ό,τι κι αν ισχύει, το automount μπορεί να ανασταλεί ρητά όσο η συσκευή είναι
υπό κρίση, με udev property:

```
# /etc/udev/rules.d/60-cerberus-inhibit.rules
# Όσο υπάρχει το flag, το udisks2 δεν κάνει automount σε νέες συσκευές.
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", \
  ENV{UDISKS_IGNORE}="1"
```

Αυτό είναι πολύ χοντρό (μπλοκάρει ΚΑΘΕ USB automount), αλλά δείχνει τον
μηχανισμό: το `UDISKS_IGNORE=1` σε μια συσκευή την κρύβει από το udisks2. Η
σωστή μορφή θέτει το flag στο `add` και το αφαιρεί μόνο όταν ο Cerberus
αποφασίσει «yes» — που πάλι απαιτεί τον Cerberus να τρέχει ως udev helper, όχι
απλός observer. Θέμα για συζήτηση όταν δω τη ροή.

---

## Τι χρειάζομαι για τα ακριβή patches

```bash
# Η σειρά authorize/inspect/prompt -- ΤΟ ΚΡΙΣΙΜΟ για το F6
sed -n '200,320p' cerberus/daemon.py

# Το storage.py: δομή του inspect, πώς ανοίγει το device, τι είναι StorageReport
sed -n '55,140p' cerberus/storage.py
grep -n "def inspect\|def _inspect_medium\|O_RDONLY\|O_NONBLOCK\|open(\|def __init__\|class .*Report\|devnode\|block" cerberus/storage.py

# Το πείραμα του node στο authorized=0 (με πραγματική στικ)
```

Και η απάντηση στο πείραμα node@authorized=0 — αυτή διαλέγει ανάμεσα σε «απλή
αναδιάταξη» και «interface-level authorization, δική της παρτίδα».
