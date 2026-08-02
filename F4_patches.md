# F4 — patches για αρχεία που δεν στάλθηκαν ολόκληρα

Το `safety.py` και το `tests/test_safety_panic.py` έρχονται ως πλήρη αρχεία.
Εδώ είναι οι υπόλοιπες αλλαγές, ως ακριβή before/after.

---

## 1. `cerberus/privsep.py`

### 1α. Πρόσθεσε πάνω από την `prepare_state_dir`

```python
# Directories the launcher is willing to hand to the analyzer.
#
# prepare_state_dir takes a path from --ledger (or --trust-store) and chowns
# its PARENT to the unprivileged uid, then chmods it 0700. With no bound on
# which parent, `sudo cerberus --ledger /etc/x.json` makes /etc owned by
# nobody and mode 0700 -- which takes sudo, ssh and PAM with it, on a running
# system, irreversibly. That needs no attacker: a typo in a flag is enough.
#
# So the launcher refuses instead of chowning. The cost of refusing is that
# the analyzer keeps no history; the cost of not refusing is the machine.
STATE_ROOTS = ("/var/lib/cerberus", "/run/cerberus")


def _within_allowed_root(directory: str) -> bool:
    """
    True if `directory` is one of STATE_ROOTS or lies beneath one.

    realpath first, so that --ledger /var/lib/cerberus/../../etc/x.json is
    judged as /etc rather than as something under /var/lib/cerberus. The
    separator is appended before the prefix comparison so that a sibling
    named /var/lib/cerberus-evil does not match a root it merely starts with.
    """
    resolved = os.path.realpath(directory)
    for root in STATE_ROOTS:
        root = os.path.realpath(root)
        if resolved == root or resolved.startswith(root + os.sep):
            return True
    return False
```

### 1β. Αντικατάστησε την αρχή του σώματος της `prepare_state_dir`

**Πριν** (γραμμές 101–104):

```python
    import os as _os
    directory = _os.path.dirname(_os.path.abspath(str(path)))
    try:
        _os.makedirs(directory, exist_ok=True)
```

**Μετά:**

```python
    directory = os.path.dirname(os.path.abspath(str(path)))

    if not _within_allowed_root(directory):
        log(f"[privsep] REFUSING to hand {directory} to uid {uid}: state "
            f"files must live under one of {', '.join(STATE_ROOTS)}.\n"
            f"[privsep] chowning it would give an unprivileged account "
            f"ownership of a directory the system depends on. Continuing "
            f"without device history.")
        return

    try:
        os.makedirs(directory, exist_ok=True)
```

Και μέσα στο υπόλοιπο `try`, άλλαξε κάθε `_os.` σε `os.` — το `import os as _os`
ήταν περιττό, το `os` υπάρχει ήδη σε επίπεδο module (το χρησιμοποιεί η `start`).

Επαληθευμένη συμπεριφορά:

| `--ledger` | αποτέλεσμα |
|---|---|
| `/var/lib/cerberus/ledger.json` | ALLOW |
| `/run/cerberus/x.json` | ALLOW |
| `/etc/x.json` | refuse — το `/etc` μένει `root 0755` |
| `/var/lib/x.json` | refuse |
| `/var/lib/cerberus-evil/x.json` | refuse (δεν αρκεί το κοινό πρόθεμα) |
| `/var/lib/cerberus/../../../etc/x.json` | refuse (λύνεται πρώτα το realpath) |

Το allowlist ισχύει μόνο υπό privsep — η `start()` πετάει `PrivsepError` αν δεν
είσαι root, οπότε η rootless διαδρομή του `ledger.default_path()` προς το
`XDG_STATE_HOME` δεν το αγγίζει καθόλου.

---

## 2. `cerberus/daemon.py`

### 2α. Ο έλεγχος εκκίνησης (~γραμμή 749)

**Πριν:**

```python
    if policy.panic_file.exists() and not dry_run:
        raise SystemExit(
            f"A panic file already exists at {policy.panic_file}.\n"
            f"It would force the gate open immediately. Remove it first:\n"
            f"    rm {policy.panic_file}")
```

**Μετά:**

```python
    if not dry_run and policy.panic_requested():
        raise SystemExit(
            f"A valid panic file already exists at {policy.panic_file}.\n"
            f"It would force the gate open immediately. Remove it first:\n"
            f"    sudo rm {policy.panic_file}")
```

Δύο πράγματα αλλάζουν. Το `exists()` γινόταν **άρνηση εκκίνησης** από
οποιονδήποτε μπορούσε να γράψει στο `/tmp` — δηλαδή ένα denial of service πάνω
στο ίδιο το εργαλείο ασφαλείας, που χειρότερα *μοιάζει με bug*. Και το `rm`
γίνεται `sudo rm`, γιατί το αρχείο είναι πλέον του root.

Ένα **άκυρο** αρχείο στην εκκίνηση δεν σταματά τίποτα: η `panic_requested()`
καταγράφει την άρνηση και επιστρέφει `False`, οπότε ο daemon ξεκινά και ο
χρήστης βλέπει γιατί αγνοήθηκε.

### 2β. Το μήνυμα του ledger (~γραμμή 740)

**Πριν:**

```python
        if store.load_error:
            print(f"[!] ledger unreadable ({store.load_error}); "
                  f"continuing without history")
```

**Μετά:**

```python
        if store.load_error:
            print(f"[!] ledger: {store.load_error}")
            if not store.entries:
                print("    continuing with no device history at all")
```

Μετά τη διόρθωση του F7 η συνηθισμένη περίπτωση είναι **μερική** απώλεια: το
αρχείο διαβάστηκε, οι περισσότερες εγγραφές φορτώθηκαν, μερικές πετάχτηκαν. Το
«unreadable / continuing without history» θα ήταν και τα δύο λάθος και θα
έκρυβε το μόνο που έχει σημασία — ποιες συσκευές έχασαν το ιστορικό τους.

### 2γ. Το banner (~γραμμή 766) — μικρή βελτίωση UX

**Πριν:**

```python
            print(f"  - watchdog armed ({watchdog_timeout:.0f}s), "
                  f"panic file: {policy.panic_file}")
```

**Μετά:**

```python
            print(f"  - watchdog armed ({watchdog_timeout:.0f}s); "
                  f"escape hatch:  sudo touch {policy.panic_file}")
```

Κάποιος κλειδωμένος έξω χρειάζεται την **εντολή**, όχι τη διαδρομή. Είναι
ακριβώς το στιλ που ήδη κάνει καλά το `[!!] COULD NOT DEAUTHORIZE`.

---

## 3. `systemd/cerberus.service`

Δεν χρειάζεται λειτουργική αλλαγή, αλλά δύο σχόλια:

```ini
# The panic file lives at /run/cerberus.panic -- BESIDE this directory, not
# inside it. RuntimeDirectoryMode below is not what ends up on disk:
# agentlink.prepare_socket_dir() chowns /run/cerberus to the analyzer's uid
# and chmods it 2770 so the desktop agent can open the socket. Anything
# inside it is therefore reachable by `nobody` and by the desktop user's
# group, which is not where an off switch for this tool belongs.
RuntimeDirectory=cerberus
RuntimeDirectoryMode=0750
```

**Το `PrivateTmp=yes` (γραμμή 82) μπορεί να μείνει ως έχει.** Ήταν πρόβλημα
μόνο επειδή το panic file ζούσε στο `/tmp`: η υπηρεσία έβλεπε δικό της ιδιωτικό
`/tmp`, οπότε ένα `touch /tmp/cerberus-panic` από το terminal σου δεν έφτανε
ποτέ στον daemon — η διαδρομή ανάκτησης ήταν σπασμένη σιωπηλά. Με το αρχείο στο
`/run` η απομόνωση του `/tmp` γίνεται καθαρό κέρδος χωρίς παρενέργεια.

Το ίδιο ισχύει και για το `cerberus-agent.service:22`.

---

## Τι μένει ανοιχτό

Το `allowed_uids` του `AgentLink` δεν το περνάει ακόμα κανείς — το
`daemon.py:716` κατασκευάζει `agentlink.AgentLink(agent_socket)` σκέτο. Για να
συνδεθεί χρειάζομαι το σημείο όπου το `__main__.py` υπολογίζει το uid που
δίνει στην `prepare_socket_dir`:

```bash
sed -n '262,278p' cerberus/__main__.py     # ο ορισμός του --agent-socket
sed -n '362,382p' cerberus/__main__.py     # η κλήση prepare_socket_dir
cat systemd/cerberus-agent.service
```
