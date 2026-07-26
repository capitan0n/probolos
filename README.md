# Cerberus

A USB authorization gate for Linux that holds newly attached devices in the
kernel's unauthorized state, reports **what they claim to be** in plain
language, and lets a human decide — using an input device the new one cannot
impersonate.

> **Status: stages 1-2 of 4.** The authorization core, identity reporting and
> semantic consistency rules work. Behavioural and content inspection are not
> implemented yet.

## Why not just use USBGuard?

USBGuard does policy enforcement, and does it well. Cerberus is not a
replacement and does not try to be one. The distinction is deliberate:

| | USBGuard | Cerberus |
|---|---|---|
| Decides on | VID/PID/class rules | claimed identity, then *behaviour* and *content* |
| Asks the user | before anything is known | after inspection, with findings |
| Trusts device self-report | yes | treats it as a claim to be checked |

The gap Cerberus targets: **a device's descriptors are its own testimony.** A
BadUSB stick declaring itself a Logitech keyboard passes any rule written about
Logitech keyboards. Cerberus is built around not taking that testimony at face
value.

If you want hardened, mature policy enforcement today, run USBGuard.

## How it works

When a USB device is attached, the kernel enumerates it, reads and caches its
descriptors, and only then binds a driver. Setting

```
/sys/bus/usb/devices/usbN/authorized_default = 0
```

splits that sequence: descriptors are read, no configuration is set, no driver
is bound. The device exists in sysfs and can be inspected, but it cannot act.
That window is where Cerberus lives.

One consequence drives the whole design: while a device is unauthorized, its
interface directories (`1-4:1.0/`) are never created, so `bInterfaceClass`
cannot be read the usual way — and `bDeviceClass` is `0x00` on most real
hardware. Cerberus therefore parses the raw
`/sys/bus/usb/devices/<dev>/descriptors` blob itself, which *is* populated for
blocked devices. See `cerberus/descriptors.py`.

The confirmation prompt appears on the terminal you already control. A
malicious HID that has just been plugged in is still unauthorized, so it
cannot press its own "yes". **The device is never allowed to answer the
question that is about itself.**

## Install

Manjaro / Arch:

```bash
sudo pacman -S python-pyudev
git clone <repo> && cd cerberus
```

No other dependencies. Nothing to build.

## Usage

```bash
python -m cerberus --list        # inventory, read-only, no root needed
python -m cerberus --dry-run     # watch attachments, never block anything
sudo python -m cerberus          # run the gate
sudo python -m cerberus --timeout 30 --log /var/log/cerberus.jsonl
sudo python -m cerberus --release   # recovery: unblock everything, reopen gate
```

Start with `--dry-run`. It shows exactly what the gate would report without
changing a single kernel flag.

### Before you run it for real

`authorized_default=0` is global per root hub and it persists. If Cerberus is
killed while the gate is closed, USB devices attached afterwards stay dead.
Restoration is wired into four independent paths (context manager, signal
handlers, `atexit`, and an explicit error message), but `SIGKILL` defeats all
of them.

Manual recovery, as root:

```bash
echo 1 > /sys/bus/usb/devices/usb1/authorized_default   # repeat per root hub
echo 1 > /sys/bus/usb/devices/1-4/authorized            # per stranded device
```

or simply `sudo python -m cerberus --release`.

While testing, keep a second way in: a built-in laptop keyboard, or an SSH
session from another machine.

## What this does not protect against

Stated plainly, because a security tool that oversells itself is worse than
none:

- **Exploits in the USB stack itself.** The gate acts *after* the kernel has
  parsed descriptors. A bug in that parsing code is reached before Cerberus
  ever sees the device. Cerberus defends against malicious device
  *functionality*, not against vulnerabilities in the enumeration path.
- **A patient attacker.** Nothing here defeats a device that behaves perfectly
  and attacks later.
- **Descriptor forgery.** A device can copy a legitimate device's VID/PID,
  strings, and interface layout exactly. Identity checking has a hard ceiling —
  which is precisely why stages 3 and 4 exist.
- **DMA-capable interfaces.** Thunderbolt/PCIe attacks bypass this entirely;
  that is what IOMMU and `boltctl` are for.

## Roadmap

- [x] **Stage 1 — authorization core.** Gate lifecycle with guaranteed
      restore, udev event loop, raw descriptor parsing, identity report,
      deny-by-default prompt, JSONL audit log.
- [x] **Stage 2 — semantic consistency rules.** Graded findings over
      functional coherence: storage + keyboard, keyboard + network, self
      contradictory identity, structural anomalies. Benign-pattern suppression
      validated against real hardware. Optional YAML tuning.
- [ ] **Stage 3 — behavioural quarantine for input devices.** Authorize while
      immediately `EVIOCGRAB`-ing the input node so events reach only the
      daemon, then classify inter-keystroke timing as human or machine.
- [ ] **Stage 4 — read-only storage inspection.** Raw `blkid -p` / `dumpe2fs`
      examination of the block device without ever mounting it.

## Tests

```bash
python -m unittest discover -s tests -t .
```

The descriptor parser is tested against synthesised device blobs, including a
composite storage + keyboard BadUSB layout, alternate settings that must not be
miscounted, and hostile inputs such as a zero-length descriptor. No hardware
required — the parser is the one component that can be fully tested in CI, so
it is.

## Licence

GPL-3.0.

## Known blind spots discovered during development

**Wireless controllers are gateways.** A Bluetooth adapter (class `0xE0`)
passes every check here, and then admits a keyboard over the air with no USB
event at all. Cerberus never sees that device. This is not a bug that can be
fixed at the USB layer; it is a boundary of the approach.

**Serial numbers are not identity.** On real hardware a Realtek Bluetooth radio
reported serial `00e04c000001` — a factory placeholder built from Realtek's
OUI, shared across countless units — and a Chicony camera reported `0001`.
Allowlists keyed on serial numbers will collide between different devices.

**Cross-branded strings are normal.** A Microsoft-branded mouse reports
manufacturer `PixArt`, the company that makes its optical sensor. Any rule that
cross-checks manufacturer strings against VID ownership will flag ordinary
hardware. See `tests/test_rules.py`, where three real devices are asserted to
produce zero findings.
