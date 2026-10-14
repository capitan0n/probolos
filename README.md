# Probolos

**A deny-by-default USB gate for Linux.** New USB devices stay switched off
until you decide. While a device waits, Probolos checks what it claims to be,
whether those claims add up and, optionally, what it does and what its storage
holds.

*Probolos* (πρόβολος) is Greek for a barrier set in front: the thing you must
get past first.

> **Beta (1.0.0b1).** It runs on real hardware, but it has **never been tested
> against a real attack device** (Rubber Ducky, O.MG cable). Do not make it
> your only protection. Its known weak spots are listed in
> [SECURITY.md][security].

## How it works

Linux binds a driver as soon as a USB device appears, so a fake keyboard can
type before anything notices. Probolos sets `authorized_default=0` on every
USB root hub, so a new device arrives **switched off**. It is checked in up to
four stages, and only your answer switches it on.

| Stage | Question | The device is |
|---|---|---|
| 1 · Identity | What does it claim to be? | off |
| 2 · Consistency | Do its claims agree? (a "USB stick" that is also a keyboard?) | off |
| 3 · Behaviour | Does it type by itself? | on for a few seconds, input captured |
| 4 · Storage | What partitions does it carry? | on briefly, read-only, never mounted |

Stages 3 and 4 switch the device on for a moment, and keys it sends before its
input is captured can still get through. `--observe 0 --no-storage-scan` keeps
unknown devices fully off until you answer.

Devices you allowed with "always" get in without a question, unless something
CRITICAL turns up.

## Quick start

```bash
git clone https://github.com/capitan0n/probolos
cd probolos
sudo pacman -S python-pyudev        # Debian/Ubuntu: sudo apt install python3-pyudev
sudo python3 -m probolos
```

Plug in a device: you get a report and a question. `Ctrl-C` stops Probolos and
reopens the gate.

> **Keep a way back in while testing**: SSH, or the laptop's built-in
> keyboard (often PS/2, which Probolos never touches). Internal USB ports
> (`removable=fixed`) are not gated unless you add `--gate-fixed-ports`, and
> neither is a port given to `--allow-port`, even while the screen is locked
> (see [SECURITY.md][security]).

### Desktop prompts and privilege separation (recommended)

```bash
sudo python3 -m probolos --privsep --agent --agent-user "$USER"
python3 -m probolos.agent           # in your desktop session
```

- `--privsep` splits Probolos in two: a small root "gate" that flips the USB
  switches, and an unprivileged analyzer that does everything else. The
  analyzer runs as `nobody` by default; once `install.sh` has created the
  `probolos` account, add `--privsep-user probolos` (safer, see
  [SECURITY.md][security]).
- `--agent` asks through desktop dialogs, with more friction for riskier
  devices:
  - **one dialog** for a plain storage device with no warnings;
  - **two dialogs** for anything that can type or carry network traffic, or
    that raised a warning;
  - **a 10-second countdown** before "Allow anyway" for a CRITICAL finding.

### Install as a service

```bash
sudo ./install.sh              # install and start; re-run after `git pull` to update
sudo ./install.sh --uninstall  # remove (device history is kept)
```

This copies the code to `/opt/probolos` (owned by root), adds a `probolos`
command (`sudo probolos --history`), runs the gate as a system service (with
`--privsep`, analyzer as the `probolos` account) and the desktop prompt as a
user service for the account that ran `sudo`. Details:
[systemd/README.md][systemd].

When there is no desktop to ask (login screen, logout), new devices are
**held** switched off and asked about once the prompt is back. Remembered
devices still get in.

## Card readers

A card reader is the USB device; the card inside it is not. Swapping cards does
not re-plug anything, so **once a reader is allowed, every card you insert
later gets in without a question.**

`--watch-media` adds a watcher for that. When a card goes into an allowed
reader (or one already plugged in when Probolos started), it reads the card's
layout (raw, read-only, never mounted) and reports:

- an EFI system or hidden partition (CRITICAL);
- a card inserted while the screen is locked (WARNING);
- a layout different from the first card seen in that slot;
- a card the reader cannot read (`UNREADABLE CARD`, after 15 s).

The same card rules apply at the plug-in prompt to a card that is already in
the reader. The card you approved there is not judged again, and a card the
reader announces twice is reported once.

It **detects; it does not block**. On a CRITICAL card:

- `--media-policy log` (default): it is reported, nothing more. Your desktop
  may still mount it.
- `--media-policy deauthorize`: the **whole reader** is switched off, every
  slot. Replug the reader to get it back; the card inside is checked again (at
  the plug-in prompt, or by the watcher for a reader you allowed with
  "always").

Under `--privsep` this also lets the analyzer read every USB storage device it
watches (card readers, but also sticks and USB disks) and switch it off, never
on.

## Stop automount (recommended for stage 4 and `--watch-media`)

Probolos never mounts anything, but your desktop may mount a stick or card
while it is being checked. Either skip the storage check (`--no-storage-scan`)
or stop desktop automount for USB storage:

```bash
sudo tee /etc/udev/rules.d/60-probolos-inhibit-automount.rules <<'EOF'
# Probolos reads USB storage before anything mounts it.
SUBSYSTEM=="block", ENV{ID_BUS}=="usb", ENV{UDISKS_IGNORE}="1"
EOF
sudo udevadm control --reload      # then replug the device
```

- Works on **KDE Plasma** and **GNOME**. `UDISKS_AUTO="0"` is **not** enough on
  KDE, which ignores it. On KDE you can instead turn off System Settings →
  Disks & Cameras → Device Auto-Mount.
- It applies to **every** USB drive, also when Probolos is not running, and
  hides them from the file manager. Mount by hand with
  `udisksctl mount -b /dev/sdX1`. Delete the file and reload to undo.
- It only stops udisks-based automount. Each card report says whether automount
  was off.

## Common options

| Option | What it does |
|---|---|
| `--observe SEC` | length of the behaviour check (default 3; `0` skips stage 3) |
| `--no-storage-scan` | skip stage 4 |
| `--privsep`, `--privsep-user USER` | privilege separation, and the analyzer's account (default `nobody`) |
| `--agent` | ask through desktop dialogs |
| `--timeout SEC` | deny after SEC seconds without an answer (default 0: the terminal waits; a desktop dialog gives up after 60 s) |
| `--lock-policy queue\|deny\|ignore` | devices plugged in while the screen is locked (default `queue`: ask on unlock) |
| `--watch-media`, `--media-policy log\|deauthorize` | watch cards in allowed readers, and what to do with a CRITICAL card |
| `--allow-port PORT` | never gate this port, even while the screen is locked (keep a rescue keyboard there) |
| `--dry-run` | report only; never block or allow anything |
| `--list [-v]` | show attached devices (read-only) |
| `--history [-v]` | every device seen: its type, decisions and changes |
| `--trusted`, `--remove-trusted N\|PATTERN\|all` | list or forget remembered devices (history is kept) |
| `--remove-all` | forget remembered devices **and** all history (asks first) |
| `--capture-payload` | record what a quarantined device typed (off by default) |
| `--log FILE` | append every decision to FILE as JSON lines |
| `--release` | recovery: switch blocked devices on and reopen the gate |

`python3 -m probolos --help` lists them all.

## If something goes wrong

The gate reopens whenever Probolos exits, crashes or is stopped; only
`kill -9` or a kernel panic can prevent that. If devices stay blocked:

```bash
sudo probolos --release                 # after install.sh
sudo python3 -m probolos --release      # from the source folder
```

`--release` refuses while Probolos is still running. If Probolos hangs, force
the gate open from another terminal or over SSH. The file must be created by
root, and the watchdog must be on (the default; `--watchdog 0` turns off
both):

```bash
sudo touch /run/probolos.panic
```

Last resort, without Probolos:

```bash
for hub in /sys/bus/usb/devices/usb*/authorized_default; do echo 1 | sudo tee "$hub"; done
```

Then replug anything still dead, or switch it on with
`echo 1 | sudo tee /sys/bus/usb/devices/<name>/authorized`.

## What it does not protect against

- bugs in the kernel's own USB code (reached before Probolos sees the device);
- a device that behaves for days and attacks later;
- a perfect copy of a real device (such as an O.MG cable) that stays quiet
  while it is checked;
- Thunderbolt/DMA, USB-C power delivery, Bluetooth and other wireless devices;
- anything after you allow a device (except cards, with `--watch-media`);
- malware inside files: it reads partition tables, not files.

The full list is in [SECURITY.md][security]; the exact feature list is in
[CAPABILITIES.md][capabilities].

## Status

- **Tested on real hardware:** closing and restoring the gate on all five root
  hubs of a laptop; USB sticks through stages 1 and 4; descriptor-change
  detection, including the harmless change of a stick moved between USB 2 and
  USB 3 ports; both prompt types; `--watch-media` with a USB card reader on KDE
  Plasma. The service runs on the author's own machine.
- **Not yet tested on real hardware:** stage 3 against a real attack device,
  `--close-race-window`, and the planned matrix of devices and desktops
  (ROADMAP 2.2).

The feature set is frozen since 0.11.0: until 1.0 only fixes, tests and
documentation go in ([ROADMAP.md][roadmap]). Defects found since the freeze are
logged in [docs/QA-LOG.md][qa-log]; what changed is in
[CHANGELOG.md][changelog].

## Requirements

- Linux with USB authorization in sysfs (`/sys/bus/usb/devices/*/authorized`)
- Python 3.10+ and `pyudev` (no `python-evdev` needed)
- Optional: `PyYAML` for `--rules FILE`; `kdialog`, `zenity` or `tkinter` for
  desktop prompts

## Development

```bash
python3 -m unittest discover -b -s tests -t .   # the whole test suite
python3 -m tests.run_all                        # the same tests; skips the few that need AF_UNIX sockets
ruff check .                                    # lint
python3 -m mypy                                 # type check of the root-side code
```

Both test commands collect the same tests: if their totals ever differ, that is
a bug. The suite needs no root, no USB hardware and no `pyudev`. CI pins the
tool versions in `.github/requirements-*.txt` and keeps a coverage floor on the
root-side code.

`tests/` has one file per area of the code. `testbed/` emulates USB devices in
software (BadUSB, descriptor drift, ...) so the CRITICAL paths can be tried
without hardware ([testbed/README.md][testbed]). Internals and the map of the
tests: [docs/TECHNICAL-REFERENCE.md][techref].

## License

GPL-3.0-or-later; see [LICENSE][license]. This is beta, security-relevant
software, provided as is, without warranty.

<!-- Absolute links: this file is also the project page on PyPI, where a
     relative link points nowhere (tests/test_cli.py checks it). -->

[capabilities]: https://github.com/capitan0n/probolos/blob/main/CAPABILITIES.md
[changelog]: https://github.com/capitan0n/probolos/blob/main/CHANGELOG.md
[license]: https://github.com/capitan0n/probolos/blob/main/LICENSE
[qa-log]: https://github.com/capitan0n/probolos/blob/main/docs/QA-LOG.md
[roadmap]: https://github.com/capitan0n/probolos/blob/main/ROADMAP.md
[security]: https://github.com/capitan0n/probolos/blob/main/SECURITY.md
[systemd]: https://github.com/capitan0n/probolos/blob/main/systemd/README.md
[techref]: https://github.com/capitan0n/probolos/blob/main/docs/TECHNICAL-REFERENCE.md
[testbed]: https://github.com/capitan0n/probolos/blob/main/testbed/README.md
