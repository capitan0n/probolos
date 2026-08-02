# F3 — σύνδεση του `textsafe`

Το `cerberus/textsafe.py` και το `tests/test_textsafe.py` είναι πλήρη αρχεία.
Εδώ είναι τα σημεία που πρέπει να το χρησιμοποιήσουν.

---

## Η αρχή: καθαρισμός στην **πηγή**, όχι στην έξοδο

Τα strings της συσκευής καταλήγουν σήμερα σε έξι προορισμούς: terminal,
kdialog, zenity, tkinter, freedesktop notification, JSON log, trust store,
ledger. Καθαρισμός σε καθέναν σημαίνει **οκτώ σημεία να θυμάσαι και ένα να
ξεχάσεις**.

Και υπάρχει ένας προορισμός που δεν είναι καν οθόνη — μέχρι να γίνει. Το
`daemon.py:677-680` γράφει `manufacturer`/`product`/`serial` στο JSON log. Αν
καθαρίσουμε μόνο κατά την εμφάνιση, ένα `cat cerberus.jsonl` τρεις μέρες μετά
ξαναπυροδοτεί την επίθεση — σε άλλο terminal, χωρίς κανείς να το περιμένει,
πιθανώς σε άλλο μηχάνημα αν το αρχείο σταλεί κάπου.

Άρα το σημείο είναι **ένα**: εκεί όπου τα bytes του descriptor γίνονται
Python string.

---

## 1. `cerberus/descriptors.py` — το μοναδικό chokepoint

Εκεί όπου διαβάζονται τα `manufacturer` / `product` / `serial`:

```python
from . import textsafe

# ... μέσα στην κατασκευή της συσκευής:
raw_manufacturer = _read("manufacturer")
raw_product = _read("product")
raw_serial = _read("serial")

manufacturer = textsafe.sanitize(raw_manufacturer)
product = textsafe.sanitize(raw_product)
serial = textsafe.sanitize(raw_serial)

dev.manufacturer = manufacturer.text
dev.product = product.text
dev.serial = serial.text

# The notes are evidence, not bookkeeping. No legitimate device puts an
# escape character in its manufacturer string, so a cleaned string with
# nothing recording WHY it needed cleaning would throw away the single
# strongest indicator that a descriptor was crafted rather than filled in.
dev.string_notes = sorted({
    note
    for field_name, result in (("iManufacturer", manufacturer),
                               ("iProduct", product),
                               ("iSerialNumber", serial))
    for note in result.notes
})
dev.string_note_fields = {
    "iManufacturer": manufacturer.notes,
    "iProduct": product.notes,
    "iSerialNumber": serial.notes,
}
```

Τίποτα δεν χάνεται: τα ωμά bytes παραμένουν στο `raw_descriptors`, που είναι
αυτό που κατακερματίζει το ledger. Η ανίχνευση drift μένει ανέπαφη και το
forensic αρχείο πλήρες.

**Στείλε μου το `descriptors_safe.py`** πριν το εφαρμόσεις. Το review λέει ότι
υπάρχει και δεν εισάγεται από πουθενά (F16) — αν κάνει ήδη μέρος αυτής της
δουλειάς, τα ενώνουμε αντί να έχουμε δύο μηχανισμούς που ο ένας δεν ξέρει τον
άλλο.

---

## 2. `cerberus/rules.py` — τα notes γίνονται finding

Νέος κανόνας. Η διατύπωση μιμείται το στιλ των υπαρχόντων:

```python
def rule_crafted_strings(dev):
    """
    A device string that had to be sanitised is testimony about the device.

    Severity is split because the categories are not equally suspicious.
    A control character in a product name has no benign explanation: no
    toolchain puts ESC there by accident, and the reason to put one there is
    to write on the screen of whoever is deciding. A zero-width character
    might be sloppiness in a manufacturer's build process, so it is a notice
    rather than a warning -- but it is still worth a line, because two trust
    entries that differ only by one are a way to look like an approved device.
    """
    notes = set(getattr(dev, "string_notes", ()))
    if textsafe.NOTE_CONTROL in notes or textsafe.NOTE_BIDI in notes:
        return Finding(
            Severity.WARNING,
            "This device's name contains characters that can rewrite what "
            "you see on screen. Nothing legitimate needs them, and their "
            "purpose is to change what this report looks like.",
            evidence=_which_fields(dev))
    if textsafe.NOTE_INVISIBLE in notes:
        return Finding(
            Severity.NOTICE,
            "This device's name contains invisible characters. Two devices "
            "whose names look identical to you may not be the same device.",
            evidence=_which_fields(dev))
    return None
```

**Θέλω να δω το `rules.py`** για την ακριβή υπογραφή του `Finding` και για το
πώς δηλώνονται οι κανόνες, ώστε να μη μαντέψω το API.

Ερώτημα σχεδιασμού για σένα: πρέπει το `NOTE_CONTROL` να είναι **CRITICAL**;
Επιχείρημα υπέρ — είναι ένδειξη σκόπιμης κατασκευής, όχι απλής ασυνέπειας, και
το CRITICAL απαιτεί πληκτρολόγηση της λέξης `authorize` αντί για κλικ. Κατά —
το CRITICAL στο υπόλοιπο εργαλείο σημαίνει «ταιριάζει με γνωστό μοτίβο
επίθεσης», και η διεύρυνσή του αποδυναμώνει τη λέξη. Κλίνω προς WARNING, με το
CRITICAL να μένει για τον συνδυασμό `control-characters` **και** HID interface.

---

## 3. `cerberus/report.py` — πλάτος οθόνης αντί για `len()`

### 3α. Το `_line()` (γραμμή ~40)

**Πριν:**

```python
def _line(text: str = "") -> str:
    # Border(1) + space(1) + padded text(WIDTH-1) + border(1) == WIDTH + 2,
    # which is exactly the width of the ─ rules above and below.
    return f"│ {text:<{WIDTH - 1}}│"
```

**Μετά:**

```python
def _line(text: str = "") -> str:
    # Border(1) + space(1) + padded text(WIDTH-1) + border(1) == WIDTH + 2,
    # which is exactly the width of the ─ rules above and below.
    #
    # Padded by COLUMNS, not by len(). The two differ in both directions and
    # only one of them is an attack: a combining accent is a character with no
    # column, an ideograph is one character in two columns. A Chinese product
    # name is legitimate and used to push the right-hand border off the line
    # all by itself.
    return f"│ {textsafe.pad(text, WIDTH - 1)}│"
```

### 3β. Το `_wrap()` (γραμμή ~48)

Η υπάρχουσα σπάει μόνο σε κενά, οπότε ένα όνομα 300 χαρακτήρων χωρίς κενό δεν
τυλίγεται καθόλου. Πρόσθεσε σκληρό σπάσιμο για λέξεις που δεν χωράνε μόνες
τους, και μέτρα σε στήλες:

```python
def _wrap(text: str, width: int) -> List[str]:
    """Naive word wrap. Explanations are prose and must not run off the box."""
    lines, current = [], ""
    for word in text.split():
        # A single "word" wider than the box has no whitespace to break at.
        # Device strings have no obligation to contain spaces, so this is not
        # a hypothetical: without it one long token runs past the border and
        # takes the rest of the report's layout with it.
        while textsafe.display_width(word) > width:
            if current:
                lines.append(current)
                current = ""
            head = textsafe.fit(word, width)[:-3]   # fit() appends "..."
            lines.append(head)
            word = word[len(head):]
        candidate = f"{current} {word}".strip()
        if textsafe.display_width(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines
```

### 3γ. Import

```python
from . import rules, sysfs, textsafe, usbclass
```

Οι γραμμές 106-108 και 114 και 155 **δεν χρειάζονται αλλαγή** — τα strings
φτάνουν εκεί ήδη καθαρά από το βήμα 1. Αυτό είναι το νόημα του chokepoint.

---

## 4. Ένα ξεχωριστό ζήτημα: markup στους διαλόγους

Το `zenity --text` και το `KMessageBox` του kdialog **ερμηνεύουν markup**
(Pango / rich text) όταν το κείμενο μοιάζει με HTML. Το ίδιο και το body μιας
freedesktop notification, που υποστηρίζει `<b>`, `<i>`, `<u>` και `<a href>`.

Ο καθαριστής **δεν** το καλύπτει αυτό, και σκόπιμα: το `<` είναι νόμιμος
χαρακτήρας και η διαφυγή του θα χάλαγε ένα όνομα σαν `A<B Electronics`. Η
σωστή θέση είναι στους ίδιους τους διαλόγους — είτε απενεργοποίηση του markup
όπου γίνεται, είτε escape του `&`, `<`, `>` τη στιγμή της κλήσης.

**Στείλε μου το `dialogs.py`** και το κοιτάμε ξεχωριστά. Δεν είναι το ίδιο
πρόβλημα με το F3 παρότι έχει την ίδια αιτία, και συγχέοντάς τα θα κατέληγε ο
ένας μηχανισμός να μισο-καλύπτει το πεδίο του άλλου.

---

## Τι θέλω για την επόμενη παρτίδα

```bash
cat cerberus/descriptors_safe.py
sed -n '60,170p' cerberus/report.py
grep -n "manufacturer\|product\|serial\|def \|Finding(" cerberus/rules.py | head -50
sed -n '1,80p' cerberus/dialogs.py
```
