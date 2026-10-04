# Leakage experiment: how many keystrokes reach the session

The measurable question: when a keystroke-injection device is plugged in, how
many of its key events reach the user's session before Probolos captures it?
CAPABILITIES.md §1.4 states the design's answer only qualitatively -- input can
escape before a grab succeeds, and `--close-race-window` does not eliminate that
race. Whether the flag shortens the window at all is part of what this
experiment measures. It puts a number on the leak, against a real kernel gadget
rather than a mock (ROADMAP 2.4, "keystrokes that escape before the
grab").

Measure; do not assume a result. The table at the end starts empty.

The three files live here, in the repository; run everything from this
directory:

```bash
cd testbed/hidexp          # from the repository root
```

- `hid_gadget_up.sh` / `hid_gadget_down.sh` build and remove a USB HID
  keyboard gadget through configfs, on the `dummy_udc.0` loopback controller.
- `hid_attack.py` types a harmless payload through it: GUI+r, then
  `--markers` repetitions of the five keys `c e r b s`, then Enter. It sends
  **5 × markers + 2** key presses (42 with `--markers 8`) at 8 ms intervals,
  and prints the number it sent. GUI+r reaches Probolos as two key-downs
  (Meta and r), so a run in which everything is captured reports
  `keystrokes captured:` 5 × markers + 3 (43 with `--markers 8`).

Prerequisite (once per boot): `sudo modprobe -a dummy_hcd libcomposite`.

---

## Step 0 — Smoke test, without Probolos

Make sure the gadget assembles and produces `/dev/hidg0`:

```bash
sudo ./hid_gadget_up.sh
ls /dev/hidg*
sudo dmesg | tail -5        # shows "hid-generic ... Keyboard"
```

**Warning:** the gadget is now a real keyboard attached to your session. GUI+r
opens your desktop's run dialog and the final Enter submits what was typed
there; the payload is only the letters above, but keep focus on an empty
editor. This run is the "no protection" baseline:

```bash
sudo python3 hid_attack.py --markers 2      # 12 keys; you will see them typed
sudo ./hid_gadget_down.sh
```

---

## Step 1 — Control: Probolos, default path

Two terminals, and an empty editor window that has the focus while the attack
runs. The leak is every payload key that reaches the session. The first one,
GUI+r, can open the run dialog and take the focus, so look there as well as in
the editor.

**Terminal A** — Probolos (the `keystrokes captured` count is printed with or
without `--capture-payload`; the flag adds the `payload-captured` finding):

```bash
cd ../..                    # the repository root
sudo python -m probolos --observe 3 --capture-payload
```

**Terminal B** — bring up the gadget, then attack the moment Probolos reports
the device and starts observing it:

```bash
sudo ./hid_gadget_up.sh
sudo python3 hid_attack.py --markers 8
```

Record, per run:

- **sent:** printed by `hid_attack.py` (`[+] Sent N keystrokes ...`);
- **captured:** `keystrokes captured: N` in the report's BEHAVIOUR UNDER
  QUARANTINE block;
- **leaked:** keys that reached the session, counted wherever they landed and
  not computed from the other two (a key can also be lost to both): GUI+r if
  the run dialog opened, the letters in the run dialog or the editor, and Enter
  if it submitted the dialog or added a line in the editor. Leaked keys are
  always the first ones sent, because the leak ends when the grab lands;
- **exposure gap:** the `exposure gap: ...` line, when the report prints one;
- **findings:** which of `machine-generated-keystrokes`, `unprompted-typing`
  and `immediate-activity` fired.

Then clean up: `sudo ./hid_gadget_down.sh`, and Ctrl-C in Terminal A.

---

## Step 2 — Treatment: `--close-race-window`

Identical, with the flag on Probolos. It defers driver binding (bus-wide
`drivers_autoprobe`), so the keyboard's driver is not bound at the instant the
device is switched on; Probolos binds it itself just before grabbing. The
race between that bind and the grab remains (CAPABILITIES §1.4, §1.12). The
flag is **experimental and outside the 1.0 guarantees** (§2.2, §3.0), and it
cannot be combined with `--privsep`.

```bash
sudo python -m probolos --observe 3 --capture-payload --close-race-window
```

Record the same five values.

---

## The table you produce for the thesis

Repeat each condition 10 or more times and report the median and p95, not a
single value.

| Condition                         | runs | sent | captured (median / p95) | leaked at the session (median / p95) | exposure gap |
|-----------------------------------|------|------|-------------------------|--------------------------------------|--------------|
| No Probolos (Step 0)              |      |      | —                       |                                      | —            |
| Probolos, default (Step 1)        |      |      |                         |                                      |              |
| Probolos, `--close-race-window`   |      |      |                         |                                      |              |

Keep the raw per-run values with the results (TESTING.md, ROADMAP 2.2), so the
medians can be recomputed.

---

## Troubleshooting

**`/dev/hidg0` does not appear:** `usb_f_hid` may not have loaded. Run
`sudo modprobe usb_f_hid` by hand, then the up script again.

**`echo dummy_udc.0 > UDC` reports "Device or resource busy":** something
else is holding the UDC. `cat /sys/class/udc/dummy_udc.0/state` -- if it
reads "configured", run the down script first.

**Probolos does not see the gadget:** `dummy_hcd` adds its own root hub,
`usbN`, whose number depends on the machine
(`grep -il dummy /sys/bus/usb/devices/usb*/product` finds it). Probolos's
startup output must list that hub as `usbN: closed`; if it does not, the
gadget is on a bus Probolos is not gating.

**The down script leaves debris:** `find /sys/kernel/config/usb_gadget/probolos_test`
shows what remains. It is almost always the UDC still bound --
`echo "" > .../probolos_test/UDC` then try again.
