# Cerberus

**A deny-by-default USB admission gate for Linux.**

New USB devices do not work until a human approves them. While a device waits,
Cerberus inspects it — and the device is dead the whole time.

```
identity · consistency · behaviour
```

---

## The idea

Every USB defence has the same problem: the kernel binds a driver the moment a
device is enumerated. By the time anything notices a keyboard is a BadUSB, it
has already typed.

Cerberus sets `authorized_default=0` on every root hub, so a new device arrives
*inert*. It is then examined across four stages, and only a human decision
authorizes it.

| Stage | What it asks | Device state |
|---|---|---|
| 1 · Identity | What does it claim to be? | blocked |
| 2 · Consistency | Do its own claims agree with each other? | blocked |
| 3 · Behaviour | What does it do when switched on and gagged? | live, input grabbed |
| 4 · Contents | What is on the medium? | live, read-only, never mounted |

The stage-3 window is the only moment the device is live before approval, and
its input is held under `EVIOCGRAB` throughout — nothing it sends reaches your
session. It is re-blocked the instant observation ends, *before* you are asked.

**The contribution is the pre-authorization quarantine window**: observation
time is decoupled from attack success. Existing tools (USBGuard, usbauth, ukip)
decide from descriptors alone, or watch a device that is already live.

---

## Quick start

```bash
git clone https://github.com/capitan0n/cerberus
cd cerberus
sudo python3 -m cerberus --observe 3
```

Plug in a device. You will get a report and a prompt.

> **Keep a second way in while testing** — SSH, or your built-in keyboard.
> Internal (`removable=fixed`) ports are never gated, so a laptop keyboard on
> the PS/2 controller is unaffected, but check before you rely on it.

Stop with `Ctrl-C`; the gate reopens on every exit path.

### Recommended: privilege separation

```bash
sudo python3 -m cerberus --privsep --agent --agent-user "$USER"
python3 -m cerberus.agent          # in your graphical session
```

`--privsep` keeps root to a ~150-line gate; everything else runs as `nobody`.
`--agent` moves the prompt into a desktop dialog.

### Stop automount racing the scan

Stage 4 authorizes the device briefly to read its partition table, and udisks2
may automount the medium in that window — the exact kernel-filesystem exposure
stage 4 exists to avoid. Install the inhibitor:

```bash
sudo cp systemd/60-cerberus-inhibit-automount.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=block
```

USB storage will no longer auto-mount. Cerberus reads the raw node itself, so
it loses nothing; you mount approved devices deliberately afterwards.

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
sudo python3 -m cerberus --release
```

If Cerberus itself is wedged, the panic file forces the gate open from another
TTY or over SSH:

```bash
sudo touch /run/cerberus.panic
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
python3 -m unittest discover -s tests        # 328 tests
python3 -m unittest discover -b -s tests -t . # quieter: suppresses daemon output
```

`testbed/` emulates USB devices in software via `dummy_hcd` + `raw_gadget`,
with presets for BadUSB, descriptor drift and overpowered devices — so the
CRITICAL paths can be exercised with no hardware.

---

## Scope

Read [`SECURITY.md`](SECURITY.md) before trusting this with anything. It is
explicit about what Cerberus does **not** stop: USB stack vulnerabilities, a
patient attacker, descriptor forgery, Thunderbolt/DMA, and wireless gateways.

Status: **beta.** All four critical findings from the security audit are fixed
and covered by regression tests, but the tool has been exercised on a limited
range of hardware. Treat real-world results as data, and report anything that
surprises you.
