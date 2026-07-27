# Cerberus

A USB authorization gate for Linux that holds newly attached devices in the
kernel's unauthorized state, reports **what they claim to be** in plain
language, and lets a human decide — using an input device the new one cannot
impersonate.

> **Status: working prototype, pre-1.0.** Authorization gate, identity
> reporting, semantic rules, behavioural quarantine, payload extraction and a
> descriptor ledger all work. Privilege separation and interface-level
> authorization — both required before this should be installed anywhere real
> — do not exist yet. See `SECURITY.md` for the honest list.

## Prior art, stated honestly

**Asking the user what they expected is not a new idea.** GoodUSB (ACSAC 2015)
established exactly that: translate low-level interface classes into
descriptions a person can answer, compare the answer to what the device
requests, and block the interfaces that do not match. If you thought that was
the novel part of this project, it was published eleven years ago.

Two gaps in that work are what Cerberus is actually for:

**It compared expectation against the device's *claims*.** An O.MG cable
declares precisely what a real cable declares, so it defeats any check built on
declarations. Comparing expectation against *behaviour* — and, eventually,
against an active firmware fingerprint — is a different question that
descriptors cannot answer.

**It required a patched kernel and never became installable software.** GoodUSB
needed kernel modifications, a userspace daemon and a honeypot KVM. It does not
run on any current machine. The idea was right and nobody made it work.

USBGuard, by contrast, is mature, maintained and does policy enforcement well.
It decides on VID/PID/class rules and trusts the device's self-report, because
that is what a policy engine is for. **If you want hardened enforcement today,
run USBGuard.** Cerberus is asking a different question: what if you do not
believe the device?

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
sudo pacman -S python-pyudev python-evdev
```

`python-pyudev` is required. `python-evdev` is required only for stage 3;
without it Cerberus still runs and says plainly that behaviour could not be
observed, rather than silently skipping the check. `python-yaml` is optional
and only needed to override rule severities from a file.

## Usage

```bash
python -m cerberus --list           # inventory, read-only, no root needed
python -m cerberus --dry-run        # watch attachments, never block anything
sudo python -m cerberus --privsep   # run the gate WITH privilege separation
sudo python -m cerberus             # run as a single root process (simpler)
sudo python -m cerberus --privsep --timeout 30 --log /var/log/cerberus.jsonl
sudo python -m cerberus --release   # recovery: unblock everything, reopen gate
sudo python -m cerberus --observe 0 # disable behavioural quarantine
```

`--privsep` is recommended: it runs the clever, larger, more exposed code as an
unprivileged user, keeping only a small audited gate as root. See `SECURITY.md`.

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

## Behavioural quarantine (stage 3)

Stages 1-2 judge what a device CLAIMS. A well-made BadUSB claims to be an
ordinary keyboard and passes both. The only remaining evidence is what it DOES.

`EVIOCGRAB` gives one process exclusive access to an input node: events reach
the grabbing process and nowhere else — not the terminal, not X, not Wayland,
not the focused window. So Cerberus authorizes the device, grabs its input
nodes immediately, and watches it in isolation for a few seconds while you are
told not to touch it. A device that types anyway is doing something it was not
asked to do.

Two judgements are made from that:

- **Anything at all.** If nobody touched it, every keystroke is unsolicited.
  This catches payloads deliberately throttled to human typing speed, which
  defeat timing analysis entirely.
- **Regularity, not speed.** The discriminating statistic is the coefficient of
  variation of inter-keystroke gaps. A fast typist is fast but irregular; no
  human sustains a near-constant interval, while a script does so by default.

Mouse movement and button clicks are explicitly not keystrokes. `BTN_*` codes
are separated from `KEY_*` codes, because otherwise a click on an ordinary
mouse would be reported as typing.

### The race, stated plainly

Between writing `authorized=1` and completing the grab there is a window in
which keystrokes can reach your session. The kernel must probe the device, bind
`usbhid` and create `/dev/input/eventN` before anything can be grabbed at all.

Cerberus starts its udev listener *before* authorizing so it is already waiting
when the node appears, and it **measures and prints the actual gap** in every
report. Typical values are 10-20 ms. Most off-the-shelf payloads wait several
hundred milliseconds before typing, because firing earlier loses keystrokes to
an incomplete enumeration; against those, the grab wins. Against a payload
tuned to fire at the earliest possible instant, it may not.

A grab is held by an open file descriptor, so if Cerberus dies the kernel
releases it automatically. There is no way to leave a keyboard captured.

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

## Declared power

Configurations declare how much bus current they intend to draw. Cerberus
checks that declaration against the specification and against the device's own
other claims: more than the bus may legally supply, storage that expects to
cost nothing to run, a self-powered device demanding half an amp anyway.

Two things to understand about these checks.

**`bMaxPower` is not one unit.** It counts 2 mA steps on USB 2.0 and 8 mA steps
on SuperSpeed. Scaling everything by 2 — which this project did until v0.4.1 —
under-reports every USB 3 device by a factor of four. The multiplier is now
selected from `bcdUSB` and pinned by tests, and the report prints the raw byte
next to the milliamps so the two can be checked against each other.

One rule was written here and deleted three days later, after it fired on an
ordinary internal Bluetooth radio that declares both the self-powered flag and
a 500 mA maximum. The premise turned out to be wrong on re-reading the
specification. The deletion is recorded in a comment in `rules.py` and pinned
by a test named after the device, so the idea does not get reinvented.

**These are declarations, not measurements.** A computer cannot measure what a
USB device actually draws: there is no current sensor on the port, and the
battery gauge is swamped by CPU frequency changes. Anyone who clones a
descriptor set clones `bMaxPower` with it, so these rules catch only the
careless and are all NOTICE or WARNING. Measuring real consumption needs
external hardware such as an INA219, and is well covered in the literature —
see PowerID (INFOCOM 2023) and subsequent work.

## The ledger: identity across time

Every other check judges one connection in isolation. The ledger remembers a
SHA-256 of each device's raw descriptor blob against the identity it claimed,
so a device that was an innocent flash drive last week and has grown a keyboard
interface this week is a CRITICAL finding regardless of how ordinary it looks
right now.

Raw bytes are hashed rather than the parsed view, because a field the parser
ignores is exactly where a device wanting to change quietly would put the
change. A first sighting is never a finding — novelty is not guilt.

## Payload extraction

Since keystrokes never reach the session, there is no reason to cut a payload
off early. `--capture-payload` lets it type itself out in full inside the
quarantine and reconstructs the transcript, so the outcome is not "a suspicious
device was blocked" but "the device attempted to run `curl … | bash`".

This records key content and is therefore **off by default**. Read the privacy
section of `SECURITY.md` before enabling it; the constraints there are
structural and tested, not promises.

## Active interrogation (research, not yet a detector)

`interrogation_study.py` is an offline experiment, deliberately not wired into
the daemon. It issues control transfers to a held device and measures the
answers: latency distributions, behaviour on undefined requests, handling of an
invalid string index, response to a HID LED output report.

The reasoning: a payload can imitate human typing rhythm, and a descriptor set
can be cloned, because both are software the attacker controls. Firmware and
silicon behaviour are not. A Pico running TinyUSB cannot cheaply pretend to be
a Cypress keyboard controller at the control-transfer layer.

Whether that is actually true is an empirical question, and the study exists to
answer it with data **before** anything is built on the assumption. Collect
consumer peripherals and general-purpose microcontroller boards, label them
honestly, and see whether the distributions separate.

## Roadmap

- [x] **Stage 1 — authorization core.** Gate lifecycle with guaranteed
      restore, udev event loop, raw descriptor parsing, identity report,
      deny-by-default prompt, JSONL audit log.
- [x] **Stage 2 — semantic consistency rules.** Graded findings over
      functional coherence: storage + keyboard, keyboard + network, self
      contradictory identity, structural anomalies. Benign-pattern suppression
      validated against real hardware. Optional YAML tuning.
- [x] **Stage 3 — behavioural quarantine for input devices.** Authorize while
      immediately `EVIOCGRAB`-ing the input nodes so events reach only the
      daemon, then judge what arrives. The exposure gap is measured and
      reported, never glossed over.
- [x] **Descriptor ledger.** Drift detection across sightings.
- [x] **Payload extraction.** Opt-in DuckyScript reconstruction.
- [x] **Lockout safety layer.** Protected ports, watchdog, panic file, all as
      tested invariants.
- [x] **Analyzer plugin layer.** One contract, `analyze(ctx) -> [Finding]`,
      with failures contained so a broken heuristic cannot block a keyboard.
- [x] **Privilege separation** (`--privsep`). A minimal root gate
      (`gate_server.py`) passes file descriptors over `SCM_RIGHTS` to an
      unprivileged analyzer running as `nobody`; the privilege drop is
      verified. systemd sandboxing of the two units is the remaining step.
- [ ] **Interface-level authorization + `drivers_autoprobe=0` + libusb.**
      Eliminates the quarantine race instead of measuring it, and is the
      precondition for both active interrogation and QEMU passthrough.
- [ ] **`dummy_hcd` / `raw-gadget` testbed in CI.** Synthetic malicious devices
      on every commit, so the rules face negative samples and not only three
      clean fixtures.
- [ ] **Stage 4 — read-only storage inspection.** Raw `blkid -p` / `dumpe2fs`
      examination of the block device without ever mounting it.
- [ ] **Sandbox as a third answer.** Deny / open in an ephemeral VM /
      authorize, with the VM's observations feeding back into the prompt.

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
