# Leakage experiment: how many keystrokes reach the session

The measurable question, before and after: with deferred bind **on** vs
**off**, how many key events of a BadUSB payload actually reach the user's
session? Everything else in the quarantine documentation is theory; this is
the number.

Three files, all in the same place (e.g. `~/Lab/personal/probolos/testbed/hidexp/`):

```bash
mkdir -p ~/Lab/personal/probolos/testbed/hidexp
cp -f ~/Downloads/hid_gadget_up.sh ~/Downloads/hid_gadget_down.sh \
      ~/Downloads/hid_attack.py ~/Lab/personal/probolos/testbed/hidexp/
chmod +x ~/Lab/personal/probolos/testbed/hidexp/*.sh
```

---

## Step 0 — Smoke test (WITHOUT Probolos, confirm the gadget works)

First make sure the gadget assembles and produces `/dev/hidg0`:

```bash
cd ~/Lab/personal/probolos/testbed/hidexp
sudo ./hid_gadget_up.sh
```

You should see `[+] HID keyboard gadget live` and a `/dev/hidg0`. A NEW
evdev node also appears — the "keyboard" now exists on your system.
Confirm:

```bash
ls /dev/hidg*
sudo dmesg | tail -5        # will show "hid-generic ... Keyboard"
```

**WARNING:** at this point the gadget is a real keyboard attached to your
session. If you run the attack NOW (without Probolos), the markers WILL be
typed wherever focus is. Open an empty editor and see for yourself:

```bash
# With focus on an empty file/editor:
sudo python3 hid_attack.py --markers 2
# You will see characters appear. That is the "no protection" case.
```

Clean up before continuing:

```bash
sudo ./hid_gadget_down.sh
```

---

## Step 1 — WITH Probolos, deferred bind ON (the normal case)

Two terminals.

**Terminal A** — Probolos, with capture so it counts keystrokes:

```bash
cd ~/Lab/personal/probolos
sudo python -m probolos --observe 3 --capture-payload --close-race-window
```

Let it listen.

**Terminal B** — bring up the gadget (Probolos will see it as a new device)
and then attack:

```bash
cd ~/Lab/personal/probolos/testbed/hidexp
sudo ./hid_gadget_up.sh
# Probolos in A now prints "NEW USB DEVICE — keyboard".
# The moment it enters quarantine (DO NOT TOUCH), run immediately:
sudo python3 hid_attack.py --markers 8
```

**What to look for in the Probolos report (Terminal A):**

- `Keystrokes captured : 41` (or however many you sent) — it caught them all
- Finding: `machine-generated-keystrokes` (CRITICAL) — recognised the rhythm
- Finding: `immediate-activity` (WARNING) — hit straight away
- Exposure: `actual exposure 0 ms` — nothing had time to leak

**THE CRITICAL PART:** in Terminal B, NO character should appear. Probolos
holds the grab; the markers go to it, not to your session. That is the
"0 keystrokes leaked" result.

Clean up:

```bash
sudo ./hid_gadget_down.sh
# Ctrl-C on Probolos (Terminal A)
```

---

## Step 2 — WITH Probolos, deferred bind OFF (the control run)

The control experiment is the same setup **without** `--close-race-window`:
its absence IS the control, its presence IS the treatment. No code change is
needed.

**Terminal A** — same as Step 1 but drop the flag:

```bash
sudo python -m probolos --observe 3 --capture-payload
```

**Terminal B** — identical to Step 1:

```bash
sudo ./hid_gadget_up.sh
sudo python3 hid_attack.py --markers 8
```

In the fallback path the driver binds immediately at authorize. For the ~50
ms before the grab succeeds, the first markers LEAK. You will see:

- In Terminal B: a few characters APPEAR (the leak)
- Keystrokes captured: fewer than were sent
- Exposure: `~50 ms` instead of 0

---

## The table you produce for the thesis

| Condition                | enumeration | exposure | keystrokes leaked |
|--------------------------|-------------|----------|-------------------|
| No Probolos              | —           | ∞        | ALL (41/41)       |
| Probolos, deferred OFF   | ~50 ms      | ~50 ms   | some (e.g. 3–8)   |
| Probolos, deferred ON    | ~50 ms      | ~0 ms    | 0                 |

That table is the result. It shows a measured — not theoretical — improvement,
against a real kernel gadget rather than a mock.

**Repeat each row 10+ times** and report median and p95, not a single value.
"leaked 0/41 in 10/10 trials" reads much stronger than a single run.

---

## Troubleshooting

**`/dev/hidg0` does not appear:** `usb_f_hid` may not have loaded. Run
`sudo modprobe usb_f_hid` by hand, then the up script again.

**`echo dummy_udc.0 > UDC` reports "Device or resource busy":** something
else is holding the UDC. `cat /sys/class/udc/dummy_udc.0/state` — if it
reads "configured", run the down script first.

**Probolos does not see the gadget:** `dummy_hcd` creates devices on
bus 5 (`usb5`). Make sure Probolos is not filtering bus 5 — you should see
`usb5: closed` in the baseline output.

**The down script leaves debris:** `find /sys/kernel/config/usb_gadget/probolos_test`
shows what remains. It is almost always the UDC still bound —
`echo "" > .../probolos_test/UDC` then try again.
