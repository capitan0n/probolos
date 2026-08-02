# F3, δεύτερο μισό — markup escaping στο `dialogs.py`

Ίδια αιτία με το F3 (device-controlled text σε επιφάνεια που το ερμηνεύει),
**διαφορετικός μηχανισμός**, γι' αυτό ξεχωριστά. Το `textsafe` καθάρισε τα
control chars· αυτό καθαρίζει το markup.

---

## Γιατί ΔΕΝ μπαίνει στο textsafe

Το `<` είναι νόμιμος χαρακτήρας. Ένα όνομα σαν `A<B & C>D Electronics` πρέπει
να εμφανίζεται **αυτούσιο** στο terminal και στο tkinter — αυτά δεν ερμηνεύουν
markup. Αν το `textsafe` έκανε escape το `<`, θα χάλαγε κάθε τέτοιο όνομα σε
τρεις από τις τέσσερις επιφάνειες για να προστατέψει τη μία.

Μόνο δύο backends ερμηνεύουν markup:

| backend | επιφάνεια | ερμηνεύει |
|---|---|---|
| kdialog | `KMessageBox`, Qt rich text | `<b>`, `<a href>`, HTML subset |
| zenity | Pango markup | `<b>`, `<i>`, `<a href>` |
| tkinter | `messagebox`, plain | τίποτα |
| terminal | plain | τίποτα |

Άρα το escape μπαίνει στα δύο πρώτα, τη στιγμή που χτίζεται το `subprocess.run`
args — όχι νωρίτερα.

## Γιατί ΟΧΙ μέσω flag

Το `zenity --no-markup` δεν υπάρχει σε παλιές εκδόσεις, και το kdialog δεν έχει
καθόλου αντίστοιχο flag. Το escape στο περιεχόμενο δουλεύει σε κάθε έκδοση και
δεν εξαρτάται από feature detection. `html.escape` καλύπτει `& < >` που είναι
ό,τι χρειάζονται και τα δύο markup συστήματα — επαληθευμένο ότι αφήνει το
νόμιμο `A<B & C>D` να εμφανιστεί σωστά ως `A&lt;B &amp; C&gt;D`.

---

## Ο κώδικας

### 1. Βοηθητικό, σε module level στο `dialogs.py`

```python
import html


def _markup_safe(text: str) -> str:
    """
    Escape text going to a backend that renders markup.

    kdialog (Qt rich text) and zenity (Pango) both treat a string that looks
    like HTML as HTML: a device named "<a href='file:///...'>Kingston</a>"
    would render as a clickable link in the security prompt, or "<b>Verified
    by Cerberus</b>" as words this tool never wrote. Neither has a portable
    flag to turn markup off -- zenity --no-markup is recent, kdialog has none
    -- so the text itself is made inert.

    The terminal and tkinter backends do NOT call this: < and & are ordinary
    characters there, and a legitimate name like "A<B & C>D" must show as
    typed. This is why the escaping lives per-backend and not in textsafe.
    """
    return html.escape(text, quote=False)
```

`quote=False`: το `"` και το `'` δεν χρειάζονται escape εκτός attribute, και
το να τα κρατήσουμε αυτούσια κρατά τα ονόματα ευανάγνωστα.

### 2. `KDialogBackend` — escape του `text` σε `confirm` και `choose`

Και στις δύο μεθόδους, η μόνη αλλαγή είναι το `text` που πάει στα args:

**confirm** — πριν:

```python
        args = [self._binary, "--title", title,
                "--yes-label", yes_label, "--no-label", no_label,
                "--warningyesno", text]
```

μετά:

```python
        args = [self._binary, "--title", title,
                "--yes-label", yes_label, "--no-label", no_label,
                "--warningyesno", _markup_safe(text)]
```

**choose** — πριν:

```python
                "--warningyesnocancel", text]
```

μετά:

```python
                "--warningyesnocancel", _markup_safe(text)]
```

Ο `title` δεν χρειάζεται escape: τον θέτει το Cerberus, δεν προέρχεται από τη
συσκευή. Αλλά αν ποτέ μπει device string στον τίτλο, θα πρέπει κι αυτός.

### 3. `ZenityBackend` — το ίδιο, στο `--text`

**confirm** — πριν:

```python
        args = [self._binary, "--question", "--title", title,
                "--text", text,
```

μετά:

```python
        args = [self._binary, "--question", "--title", title,
                "--text", _markup_safe(text),
```

**choose** — πριν:

```python
        args = [self._binary, "--question", "--title", title,
                "--text", text,
```

μετά:

```python
        args = [self._binary, "--question", "--title", title,
                "--text", _markup_safe(text),
```

### 4. `TkinterBackend` — καμία αλλαγή

Το `messagebox` δείχνει plain text. Μια σημείωση αξίζει, ώστε να μην «διορθώσει»
κάποιος τη μη-συνέπεια αργότερα:

```python
    # No _markup_safe here on purpose: tkinter's messagebox renders plain text,
    # so escaping would show a literal "&lt;" to the user. The asymmetry with
    # the kdialog/zenity backends is correct -- it mirrors which surfaces
    # interpret markup and which do not.
```

---

## Πού μπαίνει το evidence: markup vs control chars

Προσοχή στη σειρά. Το `text` που φτάνει στους διαλόγους έχει **ήδη** περάσει
από το `textsafe` (τα strings καθαρίστηκαν στην πηγή, βήμα 1 του F3). Άρα:

- Ένα `\x1b[2J` έχει ήδη γίνει `\x1b[2J` ορατό κείμενο πριν φτάσει εδώ.
- Το `_markup_safe` ασχολείται μόνο με το `< > &` που είναι **νόμιμοι**
  χαρακτήρες τους οποίους το textsafe σωστά άφησε να περάσουν.

Οι δύο άμυνες δεν επικαλύπτονται και δεν συγκρούονται: η πρώτη ουδετεροποιεί
χαρακτήρες που καμία συσκευή δεν έχει λόγο να στέλνει, η δεύτερη κάνει inert
χαρακτήρες που νόμιμες συσκευές στέλνουν αλλά μια επιφάνεια παρερμηνεύει.

---

## Ερώτηση για σένα

Το `text` που χτίζεται από το `report.py` / `daemon.py` και περνιέται στο
`dialog.choose()` — περιέχει **μόνο** device strings, ή και δομή που θέλεις να
μείνει; Αν π.χ. βάζεις ο ίδιος `<b>` για έμφαση κάπου στο prompt, το
`_markup_safe` θα το εξουδετερώσει κι αυτό. Στείλε μου το σημείο που συνθέτει
το `text`:

```bash
grep -n "\.choose(\|\.confirm(\|def.*prompt\|dialog\." cerberus/daemon.py cerberus/agent.py | head -20
```

Αν δεν βάζεις markup ο ίδιος — που είναι το πιθανό — τότε τίποτα δεν χάνεται
και το patch μπαίνει ως έχει.
