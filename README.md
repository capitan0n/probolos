# Probolos

> ⚠️ **Alpha — under active development.** This is an early, research-stage
> project. The core mechanism works in software emulation and has automated regression coverage, but **validation on real, physical hardware is still pending** —
> the tool has not yet been proven to behave correctly against a broad range of
> genuine USB devices and attack fixtures (e.g. BadUSB via ATmega32u4 / Raspberry
> Pi Zero). Interfaces, flags and on-disk formats may change without notice.
> **Do not rely on it as a security control on a machine you care about.** Treat
> everything here as experimental and report anything that surprises you.

**A deny-by-default USB admission gate for Linux.**

*Probolos* (πρόβολος) — Greek for a jutting barrier: the thing set in front that
must be got past first.

New USB devices are held for a decision. Identity checks run while blocked;
optional behavioural and storage inspection temporarily activate the device.
Remembered devices and configured safety exemptions may be admitted automatically.

```
identity · consistency · behaviour
```

---

## The idea

Every USB defence has the same problem: the kernel binds a driver the moment a
device is enumerated. By the time anything notices a keyboard is a BadUSB, it
has already typed.

Probolos sets `authorized_default=0` on every root hub, so a new device arrives
*inert*. It is then examined across four stages, and only a human decision
authorizes it.

| Stage | What it asks | Device state |
|---|---|---|
| 1 · Identity | What does it claim to be? | blocked |
| 2 · Consistency | Do its own claims agree with each other? | blocked |
| 3 · Behaviour | What does it do when switched on and gagged? | live, input grabbed |
| 4 · Contents | What is on the medium? | live, read-only, never mounted |

Stage 3 grabs evdev input after drivers bind, observes it, then re-blocks the
device **before releasing the grabs**. Keystrokes may escape before a grab
succeeds, including with `--close-race-window`: that legacy flag enables
experimental deferred binding, not race-free isolation. Newly discovered input
nodes are checked throughout observation; this still requires userspace to react.

Stage 4 also temporarily activates the device. Probolos itself never mounts the
medium, but another service may do so. It is skipped if any parsed configuration
or alternate setting declares HID input, or if descriptors are incomplete.

The research subject is an admission gate combining descriptor, behavioural,
and storage metadata evidence. Comparative claims about other tools require
independent measurements of their actual configurations; the previous table
asserting that other tools invariably decide after driver binding was removed.

---

## Quick start

```bash
git clone https://github.com/capitan0n/probolos
cd probolos
sudo python3 -m probolos --observe 3
```

Plug in a device. You will get a report and a prompt.

> **Keep a second way in while testing** — SSH, or your built-in keyboard.
> Internal (`removable=fixed`) ports are never gated, so a laptop keyboard on
> the PS/2 controller is unaffected, but check before you rely on it.

Stop with `Ctrl-C`; the gate reopens on every exit path.

### Recommended: privilege separation

```bash
sudo python3 -m probolos --privsep --agent --agent-user "$USER"
python3 -m probolos.agent          # in your graphical session
```

`--privsep` runs the analyzer as `nobody` and routes privileged operations
through a separate gate. The trusted code also includes startup preparation,
protocol handling and cleanup; it is not a 150-line security boundary.
`--agent` moves the prompt into a desktop dialog.

### Stop automount racing the scan

Stage 4 activates the device temporarily and udisks2 may automount it. If the
following inhibitor exists in your full checkout, install it before experiments
with stage 4. It was not present in the review ZIP. Otherwise disable stage 4
with `--no-storage-scan` until automounting has been controlled:

```bash
sudo cp systemd/60-probolos-inhibit-automount.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=block
```

Verify the inhibitor's effect on your system: a udisks rule does not constrain
other mount services. Probolos itself reads a raw device without mounting it.

---

## Common options

| Flag | Effect |
|---|---|
| `--observe SEC` | length of the behavioural quarantine (`0` disables stage 3) |
| `--privsep` | run the analyzer as `nobody` behind a minimal root gate |
| `--agent` | ask via a desktop dialog instead of the terminal |
| `--dry-run` | report everything, change nothing |
| `--list` | read-only inventory of attached devices; never closes the gate |
| `--trusted` / `--forget N` | list and revoke remembered devices |
| `--no-storage-scan` | skip stage 4 entirely |
| `--allow-port PORT` | keep a rescue port always open |
| `--capture-payload` | reconstruct what a quarantined device typed (opt-in) |
| `--release` | reopen the gate after a crash |

---

## If something goes wrong

The gate restores on exit, on signals, and via `atexit`. If a device is still
blocked:

```bash
sudo python3 -m probolos --release
```

If Probolos itself is wedged, the panic file forces the gate open from another
TTY or over SSH:

```bash
sudo touch /run/probolos.panic
```

It must be **root-owned** — a panic file anyone could create would be a way for
any local account to switch the tool off. Last resort, one line:

```bash
echo 1 | sudo tee /sys/bus/usb/devices/usb1/authorized_default
```

---

## Running as a service

See [`systemd/README.md`](systemd/README.md) for the two units (a system
service for the gate, a user service for the agent) and what the sandboxing
does.

---

## Requirements

- Linux with sysfs USB authorization (`/sys/bus/usb/devices/*/authorized`)
- Python 3.10+
- `pyudev` for the event loop
- Optional: `kdialog`, `zenity`, or `tkinter` for the desktop agent

No `python-evdev`: the quarantine talks to the kernel directly through one
`EVIOCGRAB` ioctl.

---

## Development

```bash
python3 -m tests.run_all  # unittest classes plus standalone descriptor tests
python3 -m unittest discover -b -s tests -t .  # unittest classes only
```

`testbed/` emulates USB devices in software via `dummy_hcd` + `raw_gadget`,
with presets for BadUSB, descriptor drift and overpowered devices — so the
CRITICAL paths can be exercised with no hardware.

---

## Scope

[`CAPABILITIES.md`](CAPABILITIES.md) is the authoritative list of what Probolos
does, what it does not do, and what may be built later. Read it first — it
distinguishes between code that runs and code that merely exists in the tree.

[`SECURITY.md`](SECURITY.md) covers the threat model and is explicit about what
Probolos does **not** stop: USB stack vulnerabilities, a patient attacker,
descriptor forgery, Thunderbolt/DMA, and wireless gateways.

Short version:

- **Does** — deny-by-default admission, descriptor consistency rules,
  pre-authorization quarantine with `EVIOCGRAB` and timing analysis, unmounted
  storage-metadata inspection, cross-session ledger and trust store, privilege
  separation with kernel-derived scope, lockout safety.
- **Does not** — anything before the kernel finishes enumerating, anything after
  you approve the device, Thunderbolt/DMA, USB-PD, wireless, or file contents.
- **Off by default** — `--close-race-window` experiments with deferred binding
  using a bus-wide switch. It does not remove the input race. See `SECURITY.md`.
- **No early activation** — use `--observe 0 --no-storage-scan` when holding
  unknown devices blocked is more important than behavioural/storage evidence.
- **Not yet** — no HID report descriptor analysis: the parser for it is written
  and hardened, but the report descriptor is not in the sysfs blob and has no
  source wired to it. `CAPABILITIES.md` §2.2 and §3.2.

Status: **alpha — under active development.** The supplied ZIP contained tests
for fixes missing from its implementation. See `AUDIT_REPORT_EL.md` for this
review's fixes, test results and limitations. A passing mock test does not prove
USB isolation on a real kernel. **Real-hardware validation is the main open work item**:
until Probolos has been tested against a range of genuine devices and BadUSB
fixtures, treat every real-world result as data rather than a guarantee, and
report anything that surprises you. Known open items are tracked in
[`CHANGELOG.md`](CHANGELOG.md).

---

## License

GPLv3 — see [`LICENSE`](LICENSE).

Note the warranty disclaimer in particular: this is alpha, security-relevant
software provided as-is. You are responsible for what you run it on.
