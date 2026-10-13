# Leakage experiment: how many keystrokes get through

**The question:** when a keystroke-injection device is plugged in, how many of
its keys reach the session before Probolos captures it? CAPABILITIES.md §1.4
only says that some can, and that `--close-race-window` does not remove the
race. This experiment puts a number on it, with a real kernel gadget instead
of a mock (ROADMAP 2.4). Measure; do not assume a result.

Run everything from this directory (`cd testbed/hidexp` from the repository
root). Once per boot: `sudo modprobe -a dummy_hcd libcomposite`.

- `hid_gadget_up.sh` and `hid_gadget_down.sh` create and remove a USB keyboard
  gadget (configfs, on the `dummy_udc.0` loopback controller).
- `hid_attack.py --markers N` types a harmless payload: GUI+r, then N times
  the keys `c e r b s`, then Enter, at 8 ms intervals. That is **5 × N + 2**
  key presses (42 with `--markers 8`), and it prints how many it sent.
  Probolos counts GUI+r as two keys (Meta and r), so a fully captured run
  reports `keystrokes captured:` 5 × N + 3 (43 with `--markers 8`).

> **Warning:** the gadget is a real keyboard in your session. GUI+r opens your
> desktop's run dialog and the final Enter submits it. The payload is only
> those letters, but keep the focus on an empty editor.

## Step 0: baseline, without Probolos

```bash
sudo ./hid_gadget_up.sh
ls /dev/hidg*                               # the gadget exists
sudo python3 hid_attack.py --markers 2      # 12 keys; you see them typed
sudo ./hid_gadget_down.sh
```

## Step 1: Probolos, default (the control)

Terminal A, from the repository root (`keystrokes captured` is printed either
way; `--capture-payload` adds the `payload-captured` finding):

```bash
sudo python -m probolos --observe 3 --capture-payload
```

Terminal B, here: bring the gadget up, then attack the moment Probolos reports
the device and starts observing it.

```bash
sudo ./hid_gadget_up.sh
sudo python3 hid_attack.py --markers 8
```

Record for each run:

- **sent:** printed by `hid_attack.py` (`[+] Sent N keystrokes ...`);
- **captured:** `keystrokes captured: N` in the report's behaviour block;
- **leaked:** keys that reached the session, counted where they landed (the
  run dialog, the editor, an Enter that submitted something), not computed
  from the other two. Leaked keys are always the first ones sent;
- **exposure gap:** the report's `exposure gap: ...` line, if it prints one;
- **findings:** which of `machine-generated-keystrokes`, `unprompted-typing`
  and `immediate-activity` fired.

Clean up with `sudo ./hid_gadget_down.sh` and Ctrl-C in terminal A.

## Step 2: `--close-race-window` (the treatment)

The same, with the flag:

```bash
sudo python -m probolos --observe 3 --capture-payload --close-race-window
```

It defers driver binding (the system-wide `drivers_autoprobe`) until Probolos
binds the driver itself, just before grabbing; the race between that bind and
the grab remains (CAPABILITIES §1.4). The flag is experimental, outside the
1.0 guarantees (§2.2, §3.0), and cannot be combined with `--privsep`.

## Results

Repeat each condition 10 or more times and report the median and p95, not a
single value. Keep the raw values per run (for `TESTING.md`, ROADMAP 2.2), so
the medians can be recomputed.

| Condition | runs | sent | captured (median / p95) | leaked at the session (median / p95) | exposure gap |
|---|---|---|---|---|---|
| No Probolos (Step 0) | | | — | | — |
| Probolos, default (Step 1) | | | | | |
| Probolos, `--close-race-window` (Step 2) | | | | | |

## Troubleshooting

- **`/dev/hidg0` does not appear:** `usb_f_hid` may not have loaded. Run
  `sudo modprobe usb_f_hid`, then the up script again.
- **`echo dummy_udc.0 > UDC` says "Device or resource busy":** something holds
  the UDC. If `cat /sys/class/udc/dummy_udc.0/state` reads `configured`, run
  the down script first.
- **Probolos does not see the gadget:** `dummy_hcd` adds its own root hub
  (`grep -il dummy /sys/bus/usb/devices/usb*/product` finds it). Probolos's
  startup output must list that hub as `usbN: closed`; otherwise the gadget is
  on a bus Probolos is not gating.
- **The down script leaves debris:**
  `find /sys/kernel/config/usb_gadget/probolos_test` shows what remains;
  usually the UDC is still bound: `echo "" > .../probolos_test/UDC`, then try
  again.
