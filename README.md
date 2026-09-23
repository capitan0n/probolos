# Probolos

> ⚠️ **Alpha — under active development.** This is an early, research-stage
> project. The admission path has been exercised on real hardware and has
> automated regression coverage, but **it has never been run against an actual
> attack**: no BadUSB fixture (ATmega32u4, Raspberry Pi Zero, O.MG cable) has
> been put through the behavioural quarantine, so the claim that matters most
> is the one with the least evidence behind it. Interfaces, flags and on-disk
> formats may change without notice.
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
medium, but another service may do so. It is skipped unless every parsed
configuration and alternate setting declares mass storage only (no HID, network,
serial or vendor function), or if descriptors are incomplete.

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

Stage 4 must briefly authorize the device for its block node to appear, and
udisks2 may automount the medium inside that window. Probolos itself only ever
reads raw sectors and never mounts anything, but a desktop session will.

The simplest answer is `--no-storage-scan`, which skips stage 4 entirely and
removes the window. If you want stage 4, tell udisks not to automount USB block
devices:

```bash
sudo tee /etc/udev/rules.d/60-probolos-inhibit-automount.rules <<'EOF'
# Probolos stage 4 authorizes a storage device just long enough to read its
# partition table. udisks2 will automount it in that window unless told not to.
SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_AUTO}="0"
EOF
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=block
```

**Know what this costs.** The rule is system-wide and permanent: *every* USB
block device stops automounting, including ones Probolos has approved and ones
plugged in while it is not running. You mount them by hand afterwards. Remove
the file and reload to undo it.

It also only constrains **udisks**. Any other automounter on the machine is
unaffected, so verify the behaviour on your own system rather than assuming the
window is closed.

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
python3 -m unittest discover -b -s tests -t .   # the whole suite
python3 -m tests.run_all                        # same, with AF_UNIX skips
```

Both collect the same tests. `run_all` exists only to skip the handful that
need a listening AF_UNIX socket, which some restricted containers refuse; use
it there and the plain command everywhere else. If the two ever report
different totals, that difference is a bug — it was one before, when the
defensive-parsing checks were bare module-level functions that unittest
discovery does not collect and only `run_all` picked up.

`tests/` holds one module per subject — `test_gate.py`, `test_ledger.py`,
`test_rules.py` and so on. `tests/audit/` holds the regression tests from each
security review, named by what that review found rather than by its number: a
round number stops meaning anything past the third one, while a theme keeps
working however many passes the project accumulates.

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

Status: **alpha — under active development.** The tree has been through six
security review passes; each finding has a regression test named after the
defect, under `tests/audit/`.

**Verified on real hardware.** Closing and restoring `authorized_default` on
all five root hubs of the reference laptop. A Kingston DataTraveler 3.0 through
stage 1 and stage 4 — identity, MBR parse, filesystem signature — with the
device re-blocked before the prompt. Descriptor drift across visits, including
the false positive that the same stick produces when moved between a USB 2 and
a USB 3 controller, which is why the ledger fingerprint ignores bus-negotiated
fields. Both prompt paths, both answers, and gate restoration on `SIGINT`.

**Not verified on real hardware.** Stage 3: no BadUSB or HID fixture has been
run against the quarantine, so the `EVIOCGRAB` path and the exposure-window
measurement rest on emulation only. Nor has `--privsep`, `--close-race-window`,
or either systemd unit. A passing test does not prove USB isolation on a real
kernel, and these are the claims most worth distrusting until somebody plugs an
ATmega32u4 in and watches what happens.

Treat every real-world result as data rather than a guarantee, and report
anything that surprises you. Known open items are tracked in
[`CHANGELOG.md`](CHANGELOG.md).

---

## License

GPLv3 — see [`LICENSE`](LICENSE).

Note the warranty disclaimer in particular: this is alpha, security-relevant
software provided as-is. You are responsible for what you run it on.
