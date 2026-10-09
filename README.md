# Probolos

> **Beta — feature-complete, still being tested.** This is a research-stage
> project. The admission path has been exercised on real hardware and has
> automated regression coverage, but **it has never been run against an actual
> attack**: no BadUSB fixture (ATmega32u4, Raspberry Pi Zero, O.MG cable) has
> been put through the behavioural quarantine, so the claim that matters most
> is the one with the least evidence behind it. The feature set is frozen at
> 0.11.0 on the way to 1.0: until then only fixes, tests and documentation go
> in ([`ROADMAP.md`][roadmap]). Known open weaknesses are listed in
> [`SECURITY.md`][security], "Known weaknesses".
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
sudo pacman -S python-pyudev     # or your distro's package (python3-pyudev)
sudo python3 -m probolos --observe 3
```

Plug in a device. You will get a report and a prompt.

> **Keep a second way in while testing** — SSH, or your built-in keyboard.
> A laptop keyboard on the PS/2 (i8042) controller is not USB and is never
> affected. Devices on internal (`removable=fixed`) USB ports are not gated
> unless you pass `--gate-fixed-ports`; check before you rely on either.

Stop with `Ctrl-C`; the gate reopens on every exit path.

### Recommended: privilege separation

```bash
sudo python3 -m probolos --privsep --agent --agent-user "$USER"
python3 -m probolos.agent          # in your graphical session
```

`--privsep` runs the analyzer as `nobody` and routes privileged operations
through a separate gate. The trusted code also includes startup preparation,
protocol handling and cleanup; it is not a 150-line security boundary.
`nobody` is shared: any other process running as `nobody` can kill the
analyzer, and the gate then reopens (`SECURITY.md`, "Known weaknesses").
`--privsep-user` takes a dedicated account instead: the service runs the
analyzer as `probolos`, a system account `install.sh` creates, and a run by
hand can pass `--privsep-user probolos` once it exists.
`--agent` moves the prompt into a desktop dialog: one dialog for a plain
storage device, a second confirmation for anything that can type or carry
traffic or showed a warning, and a 10-second countdown before "Allow anyway"
for a critical finding (a refused device returning, a changed identity).

### Run it in the background

```bash
sudo ./install.sh              # install and start; re-run after pulling to update
sudo ./install.sh --uninstall  # stop and remove (history is kept)
```

This installs the code to `/opt/probolos` (root-owned), a `probolos` command
(`sudo probolos --history`), the gate as a system service with `--privsep`, and
the desktop prompt as a user service for the account that ran `sudo`.

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

### Card readers: the card is not gated

A card reader is the USB device; the card is a medium inside it. Inserting,
removing or swapping a card causes no USB re-enumeration, so once a reader is
admitted every later card enters without passing the gate. Stage 4 only sees a
card that was already in the reader when it was plugged in.

`--watch-media` adds a separate detection layer for that: it listens for the
block-layer `change` on admitted storage hosts (and ones present at startup),
reads each new medium the same way stage 4 does — raw, read-only, never
mounted — and reports its layout, EFI system or hidden partitions, and drift
from the first medium seen in that slot. It **does not gate the card**: there
is no per-medium `authorized` switch. The only enforcement is
`--media-policy deauthorize`, which switches the **whole reader** off on a
CRITICAL finding.

Two things decide how much a report is worth, and each one says which case
applied:

- **Automount.** udisks2 mounts on the same event. Without the udev rule
  above, the card may already be mounted when it is read, and the report is
  post-hoc alerting, not prevention.
- **Latency.** Media detection rides on the kernel's disk-event polling,
  typically 1–2 s. Some readers do not report media changes at all; such a
  slot is flagged when first seen.

Under `--privsep` this widens the gate: the analyzer may open the whole disks
of watched readers read-only and switch those readers off. See `SECURITY.md`.

---

## Common options

| Flag | Effect |
|---|---|
| `--observe SEC` | length of the behavioural quarantine (`0` disables stage 3) |
| `--privsep` | run the analyzer as `nobody` behind a separate root gate |
| `--privsep-user USER` | the analyzer's account instead of `nobody` (the service: `probolos`) |
| `--agent` | ask via a desktop dialog instead of the terminal |
| `--dry-run` | report everything, change nothing |
| `--list` | read-only inventory of attached devices; never closes the gate |
| `--trusted` / `--remove-trusted N\|all` | list and revoke remembered devices (history is kept) |
| `--history [-v]` | every device seen, its decisions and descriptor drift |
| `--remove-all` | clear remembered devices **and** history; asks first, refuses while the daemon runs |
| `--no-storage-scan` | skip stage 4 entirely |
| `--watch-media` | inspect and alert on cards inserted into admitted readers (detection only) |
| `--media-policy log\|deauthorize` | with `--watch-media`: on a CRITICAL media finding, log (default) or drop the whole reader |
| `--allow-port PORT` | keep a rescue port always open |
| `--capture-payload` | reconstruct what a quarantined device typed (opt-in) |
| `--release` | reopen the gate after a crash |

---

## If something goes wrong

The gate restores on exit, on signals, and via `atexit`. If a device is still
blocked:

```bash
sudo python3 -m probolos --release      # from the checkout
sudo probolos --release                 # after install.sh
```

`--release` refuses while a gate is still running. If Probolos itself is
wedged, the panic file forces the gate open from another TTY or over SSH:

```bash
sudo touch /run/probolos.panic
```

It must be **root-owned** — a panic file anyone could create would be a way for
any local account to switch the tool off. Last resort, one line:

```bash
for hub in /sys/bus/usb/devices/usb*/authorized_default; do echo 1 | sudo tee "$hub"; done
```

That only affects devices attached from then on: replug anything still
blocked, or authorize it with `echo 1 | sudo tee /sys/bus/usb/devices/<name>/authorized`.

---

## Running as a service

`sudo ./install.sh` does all of it. See [`systemd/README.md`][systemd]
for what it sets up by hand: the two units (a system
service for the gate, a user service for the agent) and what the sandboxing
does.

---

## Requirements

- Linux with sysfs USB authorization (`/sys/bus/usb/devices/*/authorized`)
- Python 3.10+
- `pyudev` for the event loop
- Optional: `PyYAML`, only for `--rules FILE`
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

```bash
ruff check .                                    # lint (config in pyproject.toml)
python3 -m mypy                                 # types, root side (config in pyproject.toml)
```

CI runs these tools at exact versions, pinned in `.github/requirements-*.txt`
(`pip install -r .github/requirements-ci.txt -r .github/requirements-typecheck.txt`
gets the same ones locally), and
holds coverage of the root-side code to a floor (`.github/workflows/coverage.yml`).

The suite needs only the standard library: no root, no USB hardware and no
`pyudev` (a few tests skip themselves when an optional piece such as PyYAML
is missing).

`tests/` holds one module per area of the code, and each file's docstring
names the modules it covers: a bug in `probolos/trust.py` gets its regression
test in `tests/test_trust.py`, `probolos/storage.py` in `test_storage.py`, and
so on. The regression tests from the security reviews live there too, as
classes named after the defect they pin (`AnalyzerHasNoControllingTerminal`,
`TheDecoyFromTheReport`) rather than after the review that found it.
Builders and fixtures used by more than one file are in `tests/_support.py`.

| File | Covers |
|---|---|
| `test_agent.py` | `agent`, `agentlink`, `dialogs` |
| `test_boundary.py` | the refusal and error paths of `privsep`, `gate_client`, `gate_server` |
| `test_cli.py` | `__main__` |
| `test_daemon.py` | `daemon`, `session` |
| `test_descriptors.py` | `descriptors`, `descriptors_safe`, `usbclass` |
| `test_gate.py` | `gate`, `safety` |
| `test_interrogate.py` | `interrogate`, the study's offline half (probe order, `--gentle`, CSV rows) |
| `test_ledger.py` | `ledger`, `history` |
| `test_privsep.py` | `privsep`, `gate_server`, `gate_client`, `protocol` |
| `test_properties.py` | property-based (Hypothesis), across modules: descriptor, medium and protocol parsing, `textsafe`, the state files, the agent socket |
| `test_quarantine.py` | `quarantine`, `payload`, `deferred_bind` |
| `test_rules.py` | `rules`, `analyzers`, `report` |
| `test_service.py` | the shipped service: `systemd/probolos.service`, `systemd/probolos.sysusers`, `install.sh` |
| `test_storage.py` | `storage`, `storage_hardening`, `mediawatch` |
| `test_sysfs.py` | `sysfs` |
| `test_testbed.py` | `testbed.spawn`, `testbed.emulate`: every preset builds and raises what `testbed/README.md` promises (for the drift pair: same identity, different fingerprint) |
| `test_textsafe.py` | `textsafe` |
| `test_trust.py` | `trust`, `atomicio` |

`testbed/` emulates USB devices in software via `dummy_hcd` + `raw_gadget`,
with presets for BadUSB, descriptor drift and overpowered devices — so the
CRITICAL paths can be exercised with no hardware.

---

## Scope

[`CAPABILITIES.md`][capabilities] is the authoritative list of what Probolos
does, what it does not do, and what may be built later. Read it first — it
distinguishes between code that runs and code that merely exists in the tree.

[`SECURITY.md`][security] covers the threat model and is explicit about what
Probolos does **not** stop: USB stack vulnerabilities, a patient attacker,
descriptor forgery, Thunderbolt/DMA, and wireless gateways.

Short version:

- **Does** — deny-by-default admission, descriptor consistency rules,
  pre-authorization quarantine with `EVIOCGRAB` and timing analysis, unmounted
  storage-metadata inspection, cross-session ledger and trust store, privilege
  separation with kernel-derived scope, lockout safety.
- **Does not** — anything before the kernel finishes enumerating, anything after
  you approve the device, Thunderbolt/DMA, USB-PD, wireless, or file contents.
  A card inserted into an admitted reader is not gated; `--watch-media` only
  inspects and alerts on it.
- **Off by default** — `--close-race-window` experiments with deferred binding
  using a bus-wide switch. It does not remove the input race. See `SECURITY.md`.
- **No early activation** — use `--observe 0 --no-storage-scan` when holding
  unknown devices blocked is more important than behavioural/storage evidence.
- **Not yet** — no HID report descriptor analysis: the parser for it is written
  and hardened, but the report descriptor is not in the sysfs blob and has no
  source wired to it. `CAPABILITIES.md` §2.2 and §3.2.

Status: **beta, 1.0.0b1**, feature-frozen since 0.11.0 on the way to 1.0
([`ROADMAP.md`][roadmap]). The tree has been through several security
review passes, the latest on 2026-10-04 ([`docs/QA-LOG.md`][qa-log]);
each fixed finding has a regression test named after the defect, under
`tests/`, and the ones still open are listed in `SECURITY.md`.

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
anything that surprises you. What is not done is listed in
[`CAPABILITIES.md`][capabilities] §2.2 and §3, the plan to 1.0 is
[`ROADMAP.md`][roadmap], and defects found since the freeze are logged in
[`docs/QA-LOG.md`][qa-log].

---

## License

GPL-3.0-or-later: Probolos is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version. See [`LICENSE`][license].

Note the warranty disclaimer in particular: this is beta, security-relevant
software provided as-is. You are responsible for what you run it on.

<!-- Absolute links: this file is also the project page on PyPI, where a
     relative link points nowhere (tests/test_cli.py checks it). -->

[capabilities]: https://github.com/capitan0n/probolos/blob/main/CAPABILITIES.md
[license]: https://github.com/capitan0n/probolos/blob/main/LICENSE
[qa-log]: https://github.com/capitan0n/probolos/blob/main/docs/QA-LOG.md
[roadmap]: https://github.com/capitan0n/probolos/blob/main/ROADMAP.md
[security]: https://github.com/capitan0n/probolos/blob/main/SECURITY.md
[systemd]: https://github.com/capitan0n/probolos/blob/main/systemd/README.md
