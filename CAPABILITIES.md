# Capabilities and scope

This document is the authoritative answer to "what does Probolos actually do?".
It exists because a security tool that is vague about its own boundary is worse
than one with a narrow but honest one: a user who overestimates the tool makes
decisions the tool cannot support.

Three lists follow: **what is implemented and active**, **what is deliberately
or currently not done**, and **what is under consideration**. Every entry in the
first list corresponds to code on an execution path that actually runs. Anything
that exists in the tree but is not reachable is in the second list, not the
first — that distinction is the point of this document.

Status: **alpha**. Validated largely under software emulation
(`dummy_hcd`/`raw_gadget`); real-hardware coverage is limited.

---

## 1. What Probolos does

### 1.1 Admission control

| Capability | Mechanism |
|---|---|
| Deny-by-default for newly attached USB devices | `authorized_default=0` written per USB bus (`gate.py`) |
| Per-device hold and release | `/sys/bus/usb/devices/<dev>/authorized` |
| Human decision required before a device becomes live | terminal prompt, or desktop agent |
| Original bus state restored on exit, crash, or signal | `atexit` + signal handlers in `gate.py`; `--release` recovers manually |
| Devices already attached at start are left alone | the gate governs *new* attachments only |

The prompt is served on an already-trusted terminal or an already-authenticated
agent socket. A device that has just been plugged in is still unauthorized, so
it cannot press its own "yes". This is the core invariant.

### 1.2 Stage 1 — Identity

Descriptor parsing from sysfs and the raw `descriptors` blob (`descriptors.py`,
`sysfs.py`): device / configuration / interface descriptors, string descriptors,
speed, and per-configuration power.

`bMaxPower` is scaled by the correct unit — 2 mA below USB 3.0, 8 mA at
SuperSpeed — selected from `bcdUSB`, and the bus limit is 500 mA / 900 mA
accordingly.

### 1.3 Stage 2 — Consistency rules

Static rules over the declared identity (`rules.evaluate`). Severities are
defaults and are overridable per rule in a YAML config (`--rules`).

**CRITICAL**
- `storage-with-keyboard` — a mass-storage device that also declares HID input
- `network-with-keyboard` — a network interface that also declares HID input
- `crafted-strings-hid` — text-manipulation characters in the strings of an input device

**WARNING**
- `keyboard-with-unrelated-function`
- `self-contradictory-identity`
- `unreadable-descriptors`
- `interface-count-mismatch` — declared `bNumInterfaces` vs. interfaces present
- `crafted-strings`
- `power-exceeds-bus-limit` — declares more than the specification permits

**NOTICE**
- `multiple-distinct-functions`
- `no-interfaces`
- `keyboard-at-high-speed`
- `invisible-string-characters`
- `storage-declares-negligible-power`
- `power-varies-across-configurations`

### 1.4 Stage 3 — Pre-authorization quarantine

The distinguishing capability. The device is switched on **with its input
captured** (`EVIOCGRAB` on every `/dev/input/event*` node belonging to that USB
device), observed for a bounded window, and then returned to `authorized=0`
*before* the human is asked. Observation time is therefore decoupled from attack
success: waiting longer does not increase exposure, because the device is dark
again before any decision is made.

Behavioural rules (`rules.behaviour_findings`):

- `machine-generated-keystrokes` (CRITICAL) — inter-keystroke coefficient of variation below human range
- `unprompted-typing` (CRITICAL) — input while the user was told not to touch it
- `unexpected-keystrokes` (WARNING)
- `immediate-activity` (WARNING)
- `incomplete-isolation` (WARNING) — a node could not be grabbed
- `quarantine-unavailable` (NOTICE)

The residual exposure window between `authorized=1` and the grab completing is
**measured and printed per device** rather than assumed constant (41–85 ms on
the hardware tested so far). Optional raw keystroke capture (`--capture-payload`,
off by default) feeds a payload analyzer.

### 1.5 Stage 4 — Storage inspection without mounting

Read-only inspection of the first sectors of a USB block device (`storage.py`):
MBR and GPT partition tables, filesystem identification by magic signature. No
mount, no write, no filesystem driver involved.

- `partition-beyond-end-of-device` (WARNING)
- `overlapping-partitions` (WARNING)
- `filesystem-type-mismatch` (NOTICE)
- `large-unallocated-gap` (NOTICE)
- `gpt-without-protective-mbr` (NOTICE)

The scan runs in a forked worker with a hard timeout, so a device that stalls
its reads cannot wedge the daemon. Storage inspection is **refused** on a
composite storage+input device, because authorizing it to look would switch the
input half on without a grab.

### 1.6 Memory across sessions

- **Ledger** (`ledger.py`) — append-only record of every device seen, with a
  SHA-256 hash of its descriptor set. A device that changes its descriptors
  between visits is detectable.
- **Trust store** (`trust.py`) — devices pinned by identity *and* descriptor
  hash. Trust never overrides a CRITICAL finding. Both files are written
  atomically at mode `0600`; an unreadable trust store fails **closed**
  (nothing trusted, everything asked).

### 1.7 Session awareness

Screen-lock handling (`session.py`): devices arriving while the session is
locked are queued or denied per `--lock-policy`, and a queued device is re-asked
on unlock. Deferral never becomes silent approval.

### 1.8 Privilege separation (`--privsep`)

A minimal root gate (`gate_server.py`) performs the only privileged operations —
writing `authorized`, opening input and block nodes read-only — and passes file
descriptors over a `SEQPACKET` socket with `SCM_RIGHTS` to an analyzer running
as `nobody`. The privilege drop is verified, including that `setuid(0)` fails
afterwards.

Scope is derived from the **kernel**, not from the request: the gate acts only
on a USB device whose `authorized` flag currently reads `0`, and on input or
block nodes whose USB parent is such a device. Consequences: the built-in
PS/2 keyboard has no USB parent and can never be in scope; a non-USB disk is
refused; a device you are actively using reads `authorized=1` and cannot be
disturbed. A compromised analyzer cannot widen its own scope by lying.

### 1.9 Lockout safety

Watchdog with configurable timeout, panic file, `--release` recovery,
`--allow-port` to exempt known ports, `--dry-run`, and full restoration of bus
state on any exit path. On the reference laptop the built-in keyboard is on the
i8042 PS/2 controller and is unaffected by USB authorization entirely.

### 1.10 Hostile-text handling

All device-supplied strings pass through `textsafe.py` before display:
bidirectional overrides, control characters, and invisible characters are
neutralized and reported as findings. A device cannot forge or reorder the
report about itself.

### 1.12 Notes on what changed

Four capabilities in the lists above were, until recently, code that existed
without being reachable. They are called out because the failure mode is worth
recognising rather than just repairing:

| Was | Now |
|---|---|
| `deferred_bind` decided it was supported by counting interface directories on a device held at `authorized=0`, where none exist. It returned `False` on every device and the daemon silently took the racy path. | Rewritten around bus-wide `drivers_autoprobe`, which is the only kernel control acting at the instant interfaces are created. Opt-in via `--close-race-window`. |
| `descriptors_safe` was imported by nothing, so its bounds on descriptor count and its `bLength` checks protected nothing. | `descriptors.parse()` walks through it. Truncation is now recorded and surfaced instead of discarded. |
| `storage_hardening` had one of four functions called. A partition with a legal start and an absurd length was read anyway. | All three bounds are wired, and `MediumReport.suspicious` — previously written and read by nobody — is now a finding. |
| `TrustStore.load()` parsed an admission list without checking who owned it or who could write it. | Ownership, mode, and symlink checks before the JSON is believed. Fails closed. |

Each has a regression test that was verified to go red when the fix is reverted.

### 1.11 Non-product tooling

- `testbed/` — `dummy_hcd` / `raw_gadget` software emulation and a HID attack fixture
- `interrogation_study.py` + `interrogate.py` — **research instrument only.**
  Active control-transfer fingerprinting for data collection. It classifies
  nothing and is not wired into the daemon.

---

## 2. What Probolos does not do

### 2.1 Out of scope by design

These are not deficiencies; they are boundaries. Each belongs to a different
subsystem or threat model.

- **Vulnerabilities in the kernel USB stack.** The gate acts *after* the kernel
  has parsed descriptors. Memory corruption during enumeration is reached before
  Probolos sees anything. Only a sacrificial host (`usbip`) removes this.
- **Thunderbolt / PCIe DMA.** A different subsystem entirely — that is what the
  IOMMU and `boltctl` are for.
- **USB Power Delivery.** PD negotiation happens in the Type-C port manager, not
  in USB device authorization.
- **Wireless gateways.** A Bluetooth adapter passes every check and then admits
  a keyboard over the air, with no USB event at all.
- **A patient attacker.** A device that behaves for a week and attacks afterwards
  passes everything here.
- **Descriptor forgery.** An O.MG cable declares exactly what a real cable
  declares. No identity-based check can separate them — which is precisely why
  stages 3 and 4 exist.
- **Malicious hub or controller silicon.** Trust in the bus topology is assumed.
- **Post-authorization monitoring.** Once a device is approved, Probolos stops
  watching it.
- **Content scanning.** No file inspection, no signatures, no anti-malware. The
  storage stage reads partition metadata, nothing else.
- **Non-Linux platforms.** The entire mechanism is Linux sysfs USB authorization.

### 2.2 Present in the tree but not on any execution path

Listed separately because reading the source could suggest otherwise. The four
entries that used to head this list — an inert `deferred_bind`, an orphaned
`descriptors_safe`, a half-wired `storage_hardening`, and an unverified trust
store — have been fixed; see §1.12.

- **HID report descriptor analysis.** `descriptors_safe.walk_hid_items()`
  exists, is hardened, and is tested — but the sysfs `descriptors` blob does not
  contain report descriptors, only the HID descriptor (`0x21`) that announces
  their length. Reaching the report descriptor itself requires the device to be
  authorized and `usbhid` bound, i.e. the quarantine stage. Not yet wired to
  anything; see §3.2.
- **`--close-race-window` is unvalidated on hardware.** The mechanism is
  implemented, unit-tested against a synthetic sysfs tree, and off by default.
  It has not yet been run against a real device on a real kernel. Until it has,
  treat the exposure window as open unless you have measured otherwise on your
  own machine.
- **systemd units ship but should not be enabled yet.** Enabling them commits
  the machine to whatever the defaults are, unattended, before
  `--close-race-window` has hardware validation.

---

## 3. What may be built

Nothing here is promised. Ordering is by "closes a real gap and is achievable"
first, research second.

### 3.1 Validate the race-window fix on hardware

The mechanism is written; what is missing is evidence that it works outside a
synthetic sysfs tree. In order:

1. Confirm the premise on your kernel — with the gate active and a device held,
   this should print nothing, because interfaces do not exist before
   authorization:
   ```sh
   ls -d /sys/bus/usb/devices/<dev>:*
   ```
2. Run `--close-race-window` against a HID device on the emulated testbed
   (`dummy_hcd`), where a lockout costs nothing.
3. Only then a real keyboard, with a second machine or an SSH session available.
4. Measure the window with and without the flag, on the same device, several
   times. That before/after pair is the strongest experimental result the
   project can produce, and it is worth collecting carefully.

The one alternative still worth keeping in view is **`usbip` to a sacrificial
host**, which removes both the race and the kernel-parsing exposure of §2.1 at
the cost of a second machine.

### 3.2 Reach the HID report descriptors

`walk_hid_items()` is written, hardened against push/pop imbalance, collection
depth, and absurd report sizes — and has nothing to read. The report descriptor
is not in the sysfs blob. Getting to it means either reading
`/sys/bus/hid/devices/*/report_descriptor` during the quarantine window, once
`usbhid` has bound, or fetching it over a control transfer with the device
authorized but no driver attached — which `--close-race-window` now makes
possible for the first time.

The rule it unlocks is a strong one with no equivalent in the current set: a
device whose interface descriptor says *mouse* while its report descriptor
claims the keyboard usage page. Identity-level checks cannot see that at all.

### 3.3 Other connected work

- An HMAC over the trust store, keyed by a root-only file, would extend §1.6
  from "nobody else could write this" to "nobody else did write this".
- Enable systemd once §3.1 has hardware validation.

### 3.4 Research directions

- **Population-scale false-positive measurement of the two new rules**
  (`descriptor-chain-truncated`, `descriptor-length-overstated`). Both are
  reasoned from the specification rather than observed in the wild, which is
  the profile of a rule that turns out to fire on some ordinary vendor's
  firmware.
- **Active interrogation as a detector** — promote `interrogate.py` from study
  to rule, *if and only if* the collected distributions actually separate
  consumer USB stacks from general-purpose microcontrollers.
- **Post-authorization monitoring via HID-BPF** — addresses §2.1's blind spot
  after approval. Requires C and clang.
- **Port and topology watch** — a device appearing on a port that is physically
  internal is worth a finding on its own.
- **Differential analysis across visits** — beyond descriptor hash equality, to
  *what* changed and whether the change is plausible.
- **Vendor plausibility** — a VID assigned to one company whose strings name
  another.
- **Population-scale false-positive measurement** — the rule set is only as
  good as its false-positive rate across ordinary hardware, which is currently
  unmeasured.

### 3.5 Explicitly not planned

Thunderbolt/DMA, USB-PD, wireless attack surfaces, content scanning, and
non-Linux platforms. They are listed here so their absence reads as a decision
rather than an omission.
