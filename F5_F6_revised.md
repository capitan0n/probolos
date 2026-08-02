# F5 + F6 — αναθεωρημένο μετά τον κώδικα

Ο κώδικας ανέτρεψε το review σε ένα από τα δύο. Με τη σειρά.

---

## F6 — ΔΕΝ ισχύει σε αυτή την έκδοση

Το review λέει «Stage 4 authorizes storage before the human decides · udisks2
will automount it during that window». Η πραγματική ροή στο `daemon.py` είναι:

```
analyzers (identity) → [trust shortcut] → render → stage 4 inspect
    → stage 3 quarantine (input only) → prompt → authorize
```

Το `set_authorized(1)` καλείται σε **τρία μόνο** σημεία:
1. protected devices (γραμμή 240) — internal/allowlist, πριν κάθε επιθεώρηση,
   σκόπιμα (safety before security)
2. trusted devices — μετά τους analyzers, ποτέ πριν
3. μετά την ανθρώπινη έγκριση

Το Stage 4 **δεν εξουσιοδοτεί τίποτα**. Και η απόδειξη είναι στον ίδιο τον
κώδικα του `storage.py`: το `find_block_devices` περπατά το sysfs και το
`read_size_sectors` διαβάζει `/sys/block/<name>/size`, ενώ το inspection
διαβάζει raw `/dev/sdX`. Αυτό **απαντά το πείραμα που θα ζητούσα**: το block
node υπάρχει στο `authorized=0`, αλλιώς αυτός ο κώδικας δεν θα δούλευε ποτέ.

**Συμπέρασμα:** είτε το F6 διορθώθηκε μετά το review, είτε ο reviewer διάβασε
λάθος τη ροή. Σε κάθε περίπτωση, δεν υπάρχει pre-authorize του storage εδώ. Δεν
γράφω patch — δεν υπάρχει bug να διορθωθεί.

### Μία πραγματική εκδοχή του, που ΔΕΝ είναι το F6

Το σχόλιο του quarantine (γραμμή ~300) παραδέχεται ρητά:

> a composite storage + keyboard device would have its storage half live and
> available for automount during that same window

Αυτό ισχύει, αλλά είναι **περιορισμένο και ήδη τεκμηριωμένο**: συμβαίνει μόνο
για `KIND_INPUT` devices (το quarantine τρέχει only τότε), διαρκεί όσο το
observation window (τα 41-85 ms + observe time), και ο κώδικας το ξέρει — γι'
αυτό κάνει `set_authorized(0)` αμέσως μετά. Είναι η ίδια ρίζα με το F8: όσο δεν
υπάρχει interface-level authorization, το «switch on για observation» ανάβει
**όλα** τα interfaces. Η πλήρης λύση είναι το `interface_authorized_default`
του F8 — όταν το φτιάξεις, κλείνει και αυτό το παράθυρο ταυτόχρονα. Μέχρι τότε
το παράθυρο είναι millisecond-scale και μόνο για input devices, όχι το
system-wide automount που περιγράφει το F6.

---

## F5 — ισχύει, ακριβώς όπως εντοπίστηκε

Το `_inspect_medium(dev)` (γραμμή 288) καλείται **χωρίς** `paused()`, και το
`inspect()` (γραμμή 202) κάνει raw `os.read` σε **δύο** σημεία — γραμμές 217
και 282 — κανένα με timeout. Κακόβουλη συσκευή κολλάει το read → daemon παγώνει
→ watchdog πυροδοτεί → πύλη ανοίγει system-wide.

Τρία πράγματα από τον κώδικα κάνουν το patch καθαρότερο απ' ό,τι περίμενα:

1. Το `inspect(device, open_fn=None)` **έχει ήδη injection hook** (216, 280).
   Τα tests δεν χρειάζονται fifo — περνούν `open_fn` που κολλάει.
2. Το `self.watchdog` είναι το όνομα (82), και το `daemon.py:337-338`
   **ήδη** κάνει `with self.watchdog.paused():`. Υπάρχει πρότυπο να αντιγράψω.
3. **Δύο** read paths (217, 282). Ένας φραγμός γύρω από όλο το `inspect()`
   τους καλύπτει και τους δύο — καλύτερο από per-read timeout.

Επαληθευμένο εκτελεστικά (πραγματικό `safety.py`, O_RDONLY, δύο read paths):
- timeout: κολλημένο inspect σκοτώνεται στο όριο (1.00s), δεν παγώνει
- paused: εργασία 0.5s > timeout 0.3s δεν πυροδοτεί μέσα σε `paused()`
- υγιές: `inspected=True`, scheme=mbr, τα bytes περνούν

### Patch 1/2 — `storage.py`: timeout γύρω από όλο το `inspect()`

**Μην** τυλίξεις κάθε `os.read` χωριστά. Τύλιξε ολόκληρο το `inspect()` σε child
process: καλύπτει και τα δύο read paths με έναν φραγμό, και το `inspect()` μένει
αμετάβλητο (χρήσιμο — έχει ήδη tests).

Πρόσθεσε δίπλα στο `inspect()`:

```python
import multiprocessing


def _inspect_worker(device: str, conn) -> None:
    """Runs inspect() in a child so a stalled read can be killed."""
    try:
        conn.send(("ok", inspect(device)))
    except Exception as exc:                       # noqa: BLE001 — fail-closed
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def inspect_safely(device: str, timeout: float = 10.0) -> MediumReport:
    """
    inspect() under a hard time limit. This is what the daemon should call.

    A storage device can stall a read forever -- ordinary for flaky USB, a
    deliberate move for a hostile one. Without a bound the daemon freezes, and
    with the watchdog running that freeze becomes the watchdog opening the gate
    for the whole system: a stall in the SECURITY SCAN causing a system-wide
    fail-open. So inspect() runs in a child process that is killed if it
    overruns, and a timeout becomes a finding -- a device that will not let
    itself be inspected has told you something.

    A child process rather than signal.alarm: inspect() runs off the main
    thread (signals reach the main thread only), and a read wedged in
    uninterruptible sleep ignores signals entirely. Only killing the process
    reliably ends it. This wraps the whole of inspect() rather than each
    os.read so that BOTH read paths (the header read and read_at) are bounded
    by one guard.
    """
    parent_conn, child_conn = multiprocessing.Pipe()
    proc = multiprocessing.Process(
        target=_inspect_worker, args=(device, child_conn), daemon=True)
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(1.0)
        if proc.is_alive():
            proc.kill()
        # inspected stays False (scheme unknown), so no rule mistakes a stalled
        # device for one that passed. The scan's silence becomes a finding.
        return MediumReport(
            device=device,
            error=f"device did not respond within {timeout:.0f}s -- "
                  f"inspection abandoned")
    if parent_conn.poll():
        kind, payload = parent_conn.recv()
        return payload if kind == "ok" else MediumReport(device=device,
                                                        error=payload)
    return MediumReport(device=device,
                        error="inspection process produced no result")
```

### Patch 2/2 — `daemon.py`: το `_inspect_medium` καλεί το ασφαλές, μέσα σε `paused()`

Το `_inspect_medium` (γραμμή 464) καλεί σήμερα το `storage.inspect`. Δύο
αλλαγές: να καλεί το `inspect_safely`, και να τυλίγεται σε `paused()` — ακριβώς
όπως ήδη κάνει ο κώδικας στο 337-338.

Στο `_inspect_medium` (464), άλλαξε την κλήση από `storage.inspect(device)` σε
`storage.inspect_safely(device)`.

Στο call site (288):

**Πριν:**

```python
            medium = self._inspect_medium(dev)
```

**Μετά:**

```python
            # paused(): the scan is legitimate work, not a stall. The timeout
            # inside inspect_safely bounds it; paused() stops the watchdog
            # counting the up-to-10s scan as the daemon wedging. Both are
            # needed -- see below. Mirrors the existing paused() at line 337.
            if self.watchdog:
                with self.watchdog.paused():
                    medium = self._inspect_medium(dev)
            else:
                medium = self._inspect_medium(dev)
```

Δεν χρειάζεται `nullcontext` import — ο κώδικας στο 337 χρησιμοποιεί κιόλας το
ίδιο `if self.watchdog:` μοτίβο, οπότε μένω συνεπής μαζί του αντί να εισάγω νέο
στιλ.

### Γιατί χρειάζονται ΚΑΙ ΤΑ ΔΥΟ

Αυτό είναι το λεπτό σημείο, και είναι εύκολο να μπει λάθος:

| Μόνο timeout | Μόνο paused() | Και τα δύο |
|---|---|---|
| Read τελειώνει σε 10s | Read κολλάει για πάντα | Read τελειώνει σε 10s |
| Watchdog πυροδοτεί στα 60s αν το inspect κρατήσει (δεν κρατά, αλλά αν) | Watchdog δεν πυροδοτεί | Watchdog δεν πυροδοτεί |
| ⚠️ οριακό | ❌ deadlock | ✅ σωστό |

Το «μόνο paused()» είναι η προφανής αλλά **λάθος** διόρθωση: σταματά το
fail-open μετατρέποντάς το σε permanent freeze. Η προφανής κίνηση εδώ κάνει το
πρόβλημα χειρότερο, όχι καλύτερο.

---

## Regression test (πάει στο tests/)

Το `inspect()` έχει ήδη `open_fn` injection, οπότε ένα κολλημένο read
προσομοιώνεται με ένα `open_fn` που επιστρέφει fd ο οποίος μπλοκάρει — καθαρό,
χωρίς fifo στο filesystem. Αλλά επειδή το `inspect_safely` τρέχει σε **child
process**, το `open_fn` πρέπει να είναι picklable (module-level function), όχι
lambda ή closure.

```python
# Σε επίπεδο module του test αρχείου -- πρέπει να είναι picklable για το child.
def _stalling_open(device):
    """An fd whose reads block forever: a reader on a writer-less pipe."""
    import os
    read_fd, _write_fd = os.pipe()   # _write_fd never written to, never closed
    return read_fd


class StorageStall(unittest.TestCase):

    def test_a_stalled_inspection_times_out_instead_of_freezing(self):
        """
        Finding F5. A device that stalls its own scan must not freeze the
        daemon -- which, with the watchdog running, opens the gate
        system-wide. inspect_safely bounds it and a timeout becomes a finding.
        """
        report = storage.inspect_safely("/dev/does-not-matter", timeout=1.0)
        self.assertFalse(report.inspected)
        self.assertIn("did not respond", report.error)

    def test_a_healthy_inspection_still_works(self):
        """The bound must not break the normal path."""
        # A real small MBR image on disk, inspected through the safe wrapper.
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as f:
            f.write(b"\x00" * (storage.SECTOR - 2) + b"\x55\xaa")  # MBR sig
            f.write(b"\x00" * (storage.HEADER_READ - storage.SECTOR))
        report = storage.inspect_safely(path, timeout=5.0)
        self.assertIsNone(report.error)
```

Για το πρώτο test, το `inspect_safely` δεν δέχεται `open_fn` σήμερα — δες τη
σημείωση παρακάτω. Αν προτιμάς να μην αλλάξεις την υπογραφή, το test
χρησιμοποιεί fifo όπως πριν:

```python
    def test_a_stalled_inspection_times_out_instead_of_freezing(self):
        fifo = os.path.join(self.tmp, "stall")
        os.mkfifo(fifo)                  # a reader with no writer blocks forever
        try:
            report = storage.inspect_safely(fifo, timeout=1.0)
        finally:
            os.unlink(fifo)
        self.assertFalse(report.inspected)
        self.assertIn("did not respond", report.error)
```

**Σημείωση για την υπογραφή:** αν θες τα tests να περνούν `open_fn` μέσα από το
`inspect_safely`, πρόσθεσε το ως προαιρετικό όρισμα που προωθείται στο worker:

```python
def inspect_safely(device, timeout=10.0, open_fn=None):
    ...
    proc = multiprocessing.Process(
        target=_inspect_worker, args=(device, child_conn, open_fn), daemon=True)
```

με το `_inspect_worker` να κάνει `inspect(device, open_fn)`. Το `open_fn`
πρέπει να είναι picklable (module-level), γι' αυτό η fifo προσέγγιση είναι
απλούστερη για το test.

---

## Επιβεβαιωμένα νούμερα γραμμών (από τα greps)

Όλα τα σημεία που αγγίζει το patch, επαληθευμένα:

| σημείο | γραμμή |
|---|---|
| `HEADER_READ = SECTOR * 34` | storage.py:57 |
| `def inspect(device, open_fn=None)` | storage.py:202 |
| πρώτο `os.read(fd, HEADER_READ)` | storage.py:217 |
| δεύτερο `os.read(fd, length)` (read_at) | storage.py:282 |
| `self.watchdog = watchdog` | daemon.py:82 |
| υπάρχον `with self.watchdog.paused():` (πρότυπο) | daemon.py:337-338 |
| `medium = self._inspect_medium(dev)` (call site) | daemon.py:288 |
| `def _inspect_medium(self, dev)` | daemon.py:464 |

Το patch είναι έτοιμο να εφαρμοστεί χωρίς άλλα greps.
