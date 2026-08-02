# Ενσωμάτωση deferred_bind.py

Τρία αρχεία αγγίζονται. Το `deferred_bind.py` είναι νέο· τα άλλα δύο παίρνουν
μικρές, στοχευμένες προσθήκες. **Κανένα αρχείο δεν αφαιρείται.**

---

## 1. `cerberus/deferred_bind.py` — νέο αρχείο

```bash
\cp -f ~/Downloads/deferred_bind.py ~/cerberus/cerberus/
```

---

## 2. `cerberus/sysfs.py` — δύο προσθήκες

### 2α. Στο `_DirectBackend`, δίπλα στο `authorize`:

```python
    def authorize_interface(self, intf_dir, value: int) -> None:
        (intf_dir / "authorized").write_text(str(value))
```

Αυτό ταιριάζει ακριβώς με το υπάρχον `authorize` — ίδιο pattern, interface
αντί για whole device. Αν έχεις privsep backend, πρόσθεσε την ίδια μέθοδο
εκεί ώστε η εγγραφή να δρομολογείται στο root gate. Αν λείπει, το gate
πρέπει να δέχεται και το νέο μήνυμα· δες σημείωση privsep παρακάτω.

### 2β. Public helper, δίπλα στο `set_authorized`:

```python
def set_interface_authorized(intf_dir, value: int) -> None:
    """
    Authorize (1) or deauthorize (0) a single interface of a device.

    Unlike set_authorized, which switches the whole device on, this controls
    whether the kernel binds a driver to one interface. An interface at 0 is
    configured but driverless: for HID that means no evdev node is created,
    so the device has no path into the input subsystem. This is what lets us
    authorize a device without opening the grab race.

    Routed through the active backend, as with set_authorized.
    """
    _backend.authorize_interface(intf_dir, value)
```

---

## 3. `cerberus/daemon.py` — άλλαξε το `authorize_fn` στο `_quarantine`

Αυτό είναι το μόνο σημείο ουσίας. Σήμερα (γραμμή ~516):

```python
        return quarantine.quarantine(
            dev.syspath,
            authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),
            duration=self.observe,
            capture=self.capture_payload,
        )
```

Το `authorize_fn` κάνει σήμερα ΕΝΑ βήμα: άναψε τη συσκευή. Χρειάζεται να γίνει
ΔΥΟ-φασικό — άναψε χωρίς binding, μετά (αφού ξεκινήσει το monitor)
απελευθέρωσε. Επειδή το `quarantine()` ξεκινά το monitor ΜΕΤΑ το
`authorize_fn()`, χρειάζεται μικρή αλλαγή και στο quarantine (βλ. §4).

Η καθαρή προσέγγιση: πέρνα στο quarantine ΔΥΟ callables αντί για ένα.

Νέο `_quarantine`:

```python
    def _quarantine(self, dev: sysfs.UsbDevice):
        print("  This is an input device. Cerberus will switch it on with its")
        print("  input captured, so nothing it sends can reach your session.")
        print(f"  >>> DO NOT TOUCH IT for the next {self.observe:.0f} seconds. <<<")
        print()

        if deferred_bind.supported(dev.syspath):
            # Νέα διαδρομή: κανένα race window. Ο driver δεν δένει μέχρι να
            # είμαστε έτοιμοι να πιάσουμε.
            db = deferred_bind.DeferredBind(dev.syspath, log=print)
            return quarantine.quarantine(
                dev.syspath,
                authorize_fn=db.authorize_device,   # ΒΗΜΑ 2 (συσκευή on, no bind)
                release_fn=db.release_interfaces,    # ΒΗΜΑ 4 (μετά το monitor)
                bind_context=db,                     # κλείνει interfaces (ΒΗΜΑ 1) + restore
                duration=self.observe,
                capture=self.capture_payload,
            )
        else:
            # Fallback: kernel/συσκευή χωρίς interface authorization. Παλιά
            # συμπεριφορά, με το γνωστό race window που το race_window_note
            # ήδη αναφέρει τίμια.
            return quarantine.quarantine(
                dev.syspath,
                authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),
                duration=self.observe,
                capture=self.capture_payload,
            )
```

Και στην κορυφή του daemon.py, στα imports:

```python
from . import deferred_bind
```

---

## 4. `cerberus/quarantine.py` — δέξου τα νέα προαιρετικά ορίσματα

Η υπογραφή γίνεται (γραμμή ~198):

```python
def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,
               settle_timeout: float = 2.0,
               capture: bool = False,
               release_fn=None,          # νέο: καλείται ΜΕΤΑ την έναρξη monitor
               bind_context=None):       # νέο: context manager για interface hold/restore
```

Μέσα στο σώμα, τύλιξε τη ροή authorize/monitor. Το κρίσιμο: το
`bind_context.__enter__` (που κλείνει τα interfaces) πρέπει να τρέξει ΠΡΙΝ το
`authorize_fn`, και το `release_fn` ΑΜΕΣΩΣ ΜΕΤΑ την έναρξη του monitor:

```python
    # ... μετά το monitor.filter_by / monitor.start(), υπάρχει σήμερα:
    #     authorized_at = time.monotonic()
    #     authorize_fn()
    # Γίνεται:

    cm = bind_context if bind_context is not None else _null_context()
    with cm:
        authorized_at = time.monotonic()
        authorize_fn()                    # ΒΗΜΑ 2: συσκευή on, interfaces ακόμη 0
        if release_fn is not None:
            release_fn()                  # ΒΗΜΑ 4: τώρα δένουν οι drivers
        # ... από εδώ και κάτω, ΟΛΟΣ ο υπάρχων βρόχος grab μένει ίδιος ...
```

όπου `_null_context` είναι απλό:

```python
from contextlib import contextmanager

@contextmanager
def _null_context():
    yield
```

ΣΗΜΕΙΩΣΗ: το `bind_context.__enter__` κλείνει τα interfaces (ΒΗΜΑ 1). Άρα η
σειρά είναι: enter (interfaces->0) -> authorize device -> release (interfaces->1)
-> grab. Το race_window μετριέται όπως πριν, από το authorized_at· τώρα όμως
θα πρέπει να είναι δραματικά μικρότερο, γιατί ο driver δεν είχε δέσει νωρίτερα.

---

## privsep σημείωση

Αν τρέχεις με `--privsep`, ο analyzer (nobody) δεν γράφει sysfs — στέλνει
αίτημα στο root gate. Το gate πρέπει να μάθει το νέο μήνυμα
"authorize_interface". Αυτό είναι ~5 γραμμές στο gate_server.py (ίδιο pattern
με το υπάρχον authorize). Αν ΔΕΝ το προσθέσεις, το deferred bind θα δουλεύει
μόνο χωρίς privsep· με privsep θα πέφτει στο OSError και το DeferredBind θα
το χειριστεί ως αποτυχία. Πες μου να γράψω και το gate κομμάτι όταν φτάσεις εκεί.

---

## Επαλήθευση

```bash
cd ~/cerberus

# 1. Πρώτα dry-run: δες ότι εντοπίζει interfaces χωρίς να πειράξει τίποτα
sudo python -m cerberus --dry-run --list -v

# 2. Πραγματικό, με το ποντίκι σου (17ef:608d) — ασφαλές, PS/2 keyboard σε καλύπτει
sudo python -m cerberus --observe 3

# 3. Κοίτα το exposure gap στο report: πρέπει να πέσει κοντά στο 0
#    (από 41-85 ms). Κράτα την τιμή — είναι δεδομένο για τη διπλωματική.
```

Αν το gap ΔΕΝ πέσει, το πιθανότερο είναι ότι το release_fn τρέχει πολύ νωρίς
ή πολύ αργά σε σχέση με το monitor — πες μου την τιμή και το ρυθμίζουμε.
