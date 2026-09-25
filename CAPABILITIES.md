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
| Final admission policy | terminal/agent decision, remembered trust, or safety exemption; inspection can activate earlier |
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
- `unreadable-descriptors`, `descriptor-chain-truncated`, `configurations-missing`
  — part of what the device declared was never examined (parse failure, a chain
  cut short, or fewer configurations read than declared), so no rule above can
  vouch for it

**WARNING**
- `keyboard-with-unrelated-function`
- `self-contradictory-identity`
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

The device is temporarily activated and evdev nodes are grabbed as they appear.
It is re-blocked before those grabs are released, including on exceptions.
Input can escape before a grab succeeds. Late nodes are checked throughout the
window, and failed grabs stop it. Event buffers are bounded; timing comes from
kernel input-event timestamps rather than Python's batch-read times.

Behavioural rules (`rules.behaviour_findings`):

- `machine-generated-keystrokes` (CRITICAL) — inter-keystroke coefficient of variation below human range
- `unprompted-typing` (CRITICAL) — input while the user was told not to touch it
- `unexpected-keystrokes` (WARNING)
- `immediate-activity` (WARNING)
- `incomplete-isolation` (WARNING) — a node could not be grabbed
- `quarantine-unavailable` (NOTICE)

Authorization-to-first-grab latency is reported. It is not a measurement of
all escaped input, and `--close-race-window` does not eliminate the race.
Optional raw keystroke capture (`--capture-payload`, off by default) feeds a
payload analyzer.

### 1.5 Stage 4 — Storage inspection without mounting

Read-only inspection of the first sectors of a USB block device (`storage.py`):
MBR entries and GPT header/protective-MBR detection, with limited filesystem
signatures. ISO 9660 and UDF are reported only when their volume structure
checks out (ISO 9660: descriptor set, PVD both-byte-order fields, root
directory record, size; UDF: the recognition sequence), not on the magic
alone; the other signatures are still magic-only. GPT entries are not parsed. Probolos does not mount or write the
medium; other services can still mount it during activation.

- `partition-beyond-end-of-device` (WARNING)
- `overlapping-partitions` (WARNING)
- `filesystem-type-mismatch` (NOTICE)
- `filesystem-signature-without-structure` (NOTICE)
- `large-unallocated-gap` (NOTICE)
- `gpt-without-protective-mbr` (NOTICE)

The read/parse phase runs in a forked worker with a timeout. Authorization,
gate-provided descriptor acquisition and cleanup are outside that deadline. Storage inspection is **refused** on a
composite storage+input device, because authorizing it to look would switch the
input half on without a grab, and on any other composite (storage+network,
serial or vendor), because it would switch those functions on before a
decision. This guard includes every parsed configuration and alternate setting. Incomplete descriptors disable early activation entirely.

### 1.6 Memory across sessions

- **Ledger** (`ledger.py`) — bounded per-identity history, with a
  **normalized** SHA-256 fingerprint of the parsed descriptor set: VID/PID,
  `bcdDevice`, top-level class triple, and per-interface
  class/subclass/protocol. Bus-negotiated fields (`bcdUSB`, `bMaxPower`,
  endpoint descriptors, SuperSpeed companion descriptors) are excluded, so
  the same physical stick on a USB 2 vs. a USB 3 controller does not produce
  a spurious drift alarm. The raw-byte hash is stored beside it (`raw_hash`)
  for forensics but never fed to the CRITICAL rule.
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

The gate distinguishes temporary activation from final admission. Read scope
follows the USB device ancestor, skipping interface nodes, and requires blocked
state or an unexpired temporary permission for the same device instance. Final
admission gives no continued read/deauthorization permission. Whole-device
requests cannot target interfaces. See `SECURITY.md` for the limits of this
boundary; the analyzer still controls admission policy.

### 1.9 Lockout safety

Watchdog with configurable timeout, panic file, `--release` recovery,
`--allow-port` to exempt known ports, `--dry-run`, and best-effort restoration of bus
state, including partial startup failures and analyzer disconnects. On the reference laptop the built-in keyboard is on the
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
| `deferred_bind` decided it was supported by counting interface directories on a device held at `authorized=0`, where none exist. It returned `False` on every device and the daemon silently took the racy path. | Uses bus-wide `drivers_autoprobe` to defer binding, opt-in via the legacy `--close-race-window` flag. The input race remains. |
| `descriptors_safe` was imported by nothing, so its bounds on descriptor count and its `bLength` checks protected nothing. | `descriptors.parse()` walks through it. Truncation is now recorded and surfaced instead of discarded. |
| `storage_hardening` had one of four functions called. A partition with a legal start and an absurd length was read anyway. | All three bounds are wired, and `MediumReport.suspicious` — previously written and read by nobody — is now a finding. |
| `TrustStore.load()` parsed an admission list without checking who owned it or who could write it. | Ownership, mode, and symlink checks before the JSON is believed. Fails closed. |
| `_write_attr_pinned()` opened the pinned directory with `O_DIRECTORY \| O_NOFOLLOW` on the path as given, but `/sys/bus/usb/devices/<name>` entries are symlinks — so the direct backend failed with ENOTDIR on every write except `admit()`, which lacked the flag. The gate could not close in the default (non-privsep) mode. | `realpath()` before the open, symlink refusal preserved on the attribute. `admit()` uses the same discipline. Measured on real hardware: five root hubs, all closed cleanly. |
| `SafetyPolicy.is_protected()` accepted `removable=fixed` on any device. For a device behind an EXTERNAL hub that value comes from the hub's own `DeviceRemovable` bitmap, so one hostile hub silently disabled every check on everything behind it. | The chain from the device to the controller is walked; every ancestor must itself be `fixed` and the walk must reach a root hub before the exemption is granted. |
| `Ledger.record()` overwrote `descriptor_hash` on every decision, and `LedgerAnalyzer` compared against that field. A refusal, a timeout-denial, or merely queueing a device via `_hold_until_unlocked` adopted the attacker's blob as the reference. | A dedicated `baseline_hash` moved only by an explicit approval (`Ledger.record(..., approved=True)`). Old ledgers migrate via `known_hashes[0]`. |
| `descriptor_fingerprint()` hashed the raw descriptor blob, so the same physical stick on a USB 2 vs. a USB 3 controller produced a different digest — measured false positive on a Kingston DataTraveler. | Normalized fingerprint over the parsed device/interface identity, dropping bus-negotiated fields. The raw hash is kept beside it in `raw_hash` for forensics. Ledgers written by earlier versions clear their baseline on load and re-learn from the next sighting. |
| `report._line()` padded with Python character count, so a long ASCII name, a CJK product name, or a product string containing box-drawing characters broke the report box. `textsafe.pad`/`fit`/`display_width` were written for exactly this and had no callers. | `_line()` uses `textsafe.pad()`; `_wrap()` measures in terminal columns; a new `_field()` wraps identity rows and quotes device-supplied strings so they read as testimony, not as verdict text. |
| The shipped systemd unit ran `--privsep --agent --timeout 0` with no `--agent-user`. At boot there is no graphical session, so `_resolve_agent_identity()` called `sys.exit()` and `Restart=on-failure` looped forever with the gate never closing. | Auto-detection failure logs and continues without the agent (explicit unknown `--agent-user` still exits). The unit gained `Environment=PROBOLOS_AGENT_USER` and a drop-in note. |

This audit adds regression scenarios and records the actual run in
`AUDIT_REPORT_EL.md`; hardware claims are not inferred from mock tests.

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
- **Deferred binding remains experimental.** It does not guarantee a zero
  exposure window. The systemd unit needs live integration testing too.

---

## 3. What may be built

### 3.1 Validate the existing scope before adding features

For a thesis, prioritize hardware experiments: escaped keystrokes at the trusted
host, detection/miss rates, false positives on ordinary devices, stage latency,
and recovery after failures. Measure actual effects, not just discovery-to-grab
time. A clear, limited contribution with reproducible evidence is sufficient;
new detectors, kernel components or a second machine are separate research work.

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
