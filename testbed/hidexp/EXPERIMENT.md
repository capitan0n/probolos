# Πείραμα διαρροής: μετράμε πόσα keystrokes φτάνουν στη συνεδρία

Στόχος: αριθμημένο, ασφαλές πριν/μετά. Πόσα key events ενός BadUSB payload
διαρρέουν στη συνεδρία **με** deferred bind vs **χωρίς**.

Τρία αρχεία, όλα στο ίδιο σημείο (π.χ. `~/Lab/personal/probolos/testbed/hidexp/`):

```bash
mkdir -p ~/Lab/personal/probolos/testbed/hidexp
\cp -f ~/Downloads/hid_gadget_up.sh ~/Downloads/hid_gadget_down.sh \
       ~/Downloads/hid_attack.py ~/Lab/personal/probolos/testbed/hidexp/
chmod +x ~/Lab/personal/probolos/testbed/hidexp/*.sh
```

---

## Βήμα 0 — Smoke test (ΧΩΡΙΣ Probolos, δες ότι δουλεύει το gadget)

Πρώτα βεβαιώσου ότι το gadget στήνεται και παράγει `/dev/hidg0`:

```bash
cd ~/Lab/personal/probolos/testbed/hidexp
sudo ./hid_gadget_up.sh
```

Πρέπει να δεις `[+] HID keyboard gadget live` και ένα `/dev/hidg0`. Επίσης
θα εμφανιστεί ένα ΝΕΟ evdev node — το «πληκτρολόγιο» υπάρχει τώρα στο
σύστημά σου. Επιβεβαίωσε:

```bash
ls /dev/hidg*
sudo dmesg | tail -5        # θα δεις "hid-generic ... Keyboard"
```

**ΠΡΟΣΟΧΗ:** αυτή τη στιγμή το gadget είναι πραγματικό πληκτρολόγιο δεμένο
στη συνεδρία σου. Αν τρέξεις το attack ΤΩΡΑ (χωρίς Probolos), τα markers
ΘΑ πληκτρολογηθούν όπου έχεις focus. Άνοιξε έναν κενό editor και δες:

```bash
# Σε κενό αρχείο/editor με focus:
sudo python3 hid_attack.py --markers 2
# Θα δεις χαρακτήρες να εμφανίζονται. Αυτό είναι το "χωρίς προστασία".
```

Καθάρισε πριν συνεχίσεις:

```bash
sudo ./hid_gadget_down.sh
```

---

## Βήμα 1 — ΜΕ Probolos, deferred bind ON (η κανονική κατάσταση)

Δύο terminals.

**Terminal A** — ο Probolos, με capture ώστε να μετρήσει keystrokes:

```bash
cd ~/Lab/personal/probolos
sudo python -m probolos --observe 3 --capture-payload
```

Άφησέ τον να ακούει.

**Terminal B** — στήσε το gadget (ο Probolos θα το πιάσει ως νέα συσκευή)
και μετά επίθεση:

```bash
cd ~/Lab/personal/probolos/testbed/hidexp
sudo ./hid_gadget_up.sh
# Ο Probolos στο Α τυπώνει τώρα "NEW USB DEVICE — keyboard".
# Μόλις μπει σε καραντίνα (DO NOT TOUCH), τρέξε ΑΜΕΣΩΣ:
sudo python3 hid_attack.py --markers 8
```

**Τι να κοιτάξεις στο report του Probolos (Terminal A):**

- `Keystrokes captured : 41` (ή όσα έστειλες) — τα έπιασε ΟΛΑ
- Finding: `machine-generated-keystrokes` (CRITICAL) — αναγνώρισε τον ρυθμό
- Finding: `immediate-activity` (WARNING) — χτύπησε αμέσως
- Το exposure: `actual exposure 0 ms` — δεν πρόλαβαν να διαρρεύσουν

**ΤΟ ΚΡΙΣΙΜΟ:** στο Terminal B, ΚΑΝΕΝΑΣ χαρακτήρας δεν πρέπει να εμφανιστεί.
Ο Probolos κρατά το grab· τα markers πάνε σε αυτόν, όχι στη συνεδρία.
Αυτό είναι το «0 keystrokes leaked».

Καθάρισε:

```bash
sudo ./hid_gadget_down.sh
# Ctrl-C στον Probolos (Terminal A)
```

---

## Βήμα 2 — ΜΕ Probolos, deferred bind OFF (το control πείραμα)

Για να δείξεις τη ΔΙΑΦΟΡΑ, χρειάζεσαι το ίδιο σενάριο χωρίς το deferred
bind. Πρόσθεσε προσωρινό flag ή, πιο απλά, force το fallback:

```bash
# Πρόχειρος τρόπος: πες στο daemon να μη χρησιμοποιεί deferred bind.
# Αν δεν έχεις flag, σχολίασε προσωρινά το supported() check ή
# ρύθμισε ένα env var. Πες μου να προσθέσω --no-deferred-bind flag.
```

Στο fallback, ο driver δένει αμέσως στο authorize. Στα ~50 ms πριν το grab,
τα πρώτα markers ΔΙΑΡΡΕΟΥΝ. Θα δεις:

- Στο Terminal B: μερικοί χαρακτήρες ΕΜΦΑΝΙΖΟΝΤΑΙ (η διαρροή)
- Keystrokes captured: λιγότερα από όσα στάλθηκαν
- exposure: `~50 ms` αντί για 0

---

## Ο πίνακας που παράγεις για τη διπλωματική

| Συνθήκη | enumeration | exposure | keystrokes leaked |
|---|---|---|---|
| Χωρίς Probolos | — | ∞ | ΟΛΑ (41/41) |
| Probolos, deferred OFF | ~50 ms | ~50 ms | μερικά (π.χ. 3-8) |
| Probolos, deferred ON | ~50 ms | ~0 ms | 0 |

Αυτός ο πίνακας είναι το αποτέλεσμα. Δείχνει μετρημένη, όχι θεωρητική,
βελτίωση — και μάλιστα με πραγματικό kernel gadget, όχι mock.

**Επανάλαβε κάθε γραμμή 10+ φορές** και ανάφερε median/p95, όχι μία τιμή.
Το «leaked 0/41 σε 10/10 δοκιμές» είναι πολύ ισχυρότερο από ένα single run.

---

## Troubleshooting

**Δεν δημιουργείται `/dev/hidg0`:** το `usb_f_hid` ίσως δεν φορτώθηκε.
`sudo modprobe usb_f_hid` χειροκίνητα, μετά ξανά το up script.

**`echo dummy_udc.0 > UDC` δίνει "Device or resource busy":** κάτι άλλο
κρατά τον UDC. `cat /sys/class/udc/dummy_udc.0/state` — αν λέει
"configured", τρέξε πρώτα το down script.

**Ο Probolos δεν βλέπει το gadget:** το `dummy_hcd` δημιουργεί συσκευές
στο bus 5 (`usb5`). Βεβαιώσου ότι ο Probolos δεν φιλτράρει το bus 5 —
στο baseline output πρέπει να δεις `usb5: closed`.

**Το down script αφήνει σκουπίδια:** `find /sys/kernel/config/usb_gadget/probolos_test`
δείχνει τι έμεινε. Σχεδόν πάντα είναι το UDC ακόμη δεμένο — 
`echo "" > .../probolos_test/UDC` και ξανά.
