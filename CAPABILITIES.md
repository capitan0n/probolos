# Capabilities and scope

> **Feature freeze.** §1 below, as of the `v0.11.0` tag, is the feature
> contract for 1.0.0. Until 1.0.0 nothing new goes in: every change is a fix,
> a security fix, testing, documentation or release work (`ROADMAP.md`). A
> change that makes documented behaviour true is a fix; one that adds
> behaviour goes on the post-1.0 list (§3.0).

This document is the authoritative answer to "what does Probolos actually do?".
It exists because a security tool that is vague about its own boundary is worse
than one with a narrow but honest one: a user who overestimates the tool makes
decisions the tool cannot support.

Three lists follow: **what is implemented and active**, **what is deliberately
or currently not done**, and **what is under consideration**. Every entry in the
first list corresponds to code on an execution path that actually runs. Anything
that exists in the tree but is not reachable is in the second list, not the
first — that distinction is the point of this document.

Status: **beta**. Validated largely under software emulation
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

The desktop agent asks with as much friction as the device earns
(`daemon._prompt_steps`): **one dialog** for a device that can neither type
nor carry traffic and showed nothing suspicious; **two** (a second "switch it
on?") for keyboards/HID, network, radio, vendor-specific or unknown functions,
or any warning; and for a CRITICAL finding the **countdown**: "Allow anyway"
stays disabled for 10 s, "always" is never offered, and the daemon itself
refuses an approval that arrives sooner. A dialog that closes without a
button (killed, timed out, no display) is no decision, never a refusal. On a
terminal a CRITICAL device needs the typed word `authorize`.

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
- `storage-with-undeclared-hid` — a mass-storage device that also declares an
  input interface whose shape the descriptors do not show (HID subclass 0, or a
  declared mouse whose report descriptor was not read)
- `unreadable-descriptors`, `descriptor-chain-truncated`, `configurations-missing`
  — part of what the device declared was never examined (parse failure, a chain
  cut short, or fewer configurations read than declared), so no rule above can
  vouch for it

**WARNING**
- `keyboard-with-unrelated-function`
- `self-contradictory-identity`
- `interface-count-mismatch` — declared `bNumInterfaces` vs. interfaces present
- `crafted-strings`
- `network-with-undeclared-hid` — a network interface beside an input interface
  of unclear shape (as `storage-with-undeclared-hid`)
- `stacked-combining-marks` — more combining marks on one character than any
  writing system uses, which can draw over the report
- `power-exceeds-bus-limit` — declares more than the specification permits

**NOTICE**
- `multiple-distinct-functions`
- `no-interfaces`
- `keyboard-at-high-speed`
- `invisible-string-characters`
- `storage-declares-negligible-power`
- `power-varies-across-configurations`
- `descriptor-length-overstated` — `wTotalLength` claims more configuration data
  than was delivered

A check that raises is reported, never skipped: `analyzer-failed:<check>` is
CRITICAL when that check is the one that decides its stage, and NOTICE
otherwise.

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
- `quarantine-not-restored` (CRITICAL) — `authorized=0` could not be written
  back after observation, so the device may still be live

Payload rule (`analyzers.PayloadAnalyzer`, only with `--capture-payload`):

- `payload-captured` (CRITICAL) — the device typed at least one key during
  quarantine; its keystrokes are rebuilt as a DuckyScript-style transcript,
  assuming a US QWERTY layout and capped at about 4096 characters (keystrokes
  past the cap are counted, not transcribed)

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
alone; the other signatures are still magic-only. GPT entries are read only
for their type GUID and attributes, only from the standard location inside
the header read (LBA 2, 128-byte entries), and only the media-change rules
(§1.13) use them; the geometry rules still judge the protective MBR. Probolos does not mount or write the
medium; other services can still mount it during activation.

Recognised filesystems are a fixed internal set (NTFS, exFAT, FAT12/16/32,
ext2/3/4, btrfs, ISO 9660, UDF); detection does not delegate to libblkid.
f2fs, minix and squashfs, among others, read as "no known filesystem" — the
same string a medium with no structure at all produces. The stage 4 result is
**contextual, not a gate criterion**: a device can also force the
identity-only path by delaying its block node past the poll window. Admission
rests on stages 1–2.

Every inspection failure (switch-on refused, no block node, node never ready,
unreadable or stalled read, removal mid-scan, re-block refused) is reported the
same way: `not inspected: <reason>` in the MEDIUM block plus the
`storage-unreadable` notice. The reason shown is from a fixed vocabulary; the
raw error text and paths go to the JSON audit log (`medium.detail`) only.

- `partition-beyond-end-of-device` (WARNING)
- `overlapping-partitions` (WARNING)
- `impossible-partition-geometry` (WARNING) — entries that cannot exist on this
  medium (`storage_hardening`); they are not read
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
  atomically. The ledger is `0600`. The trust store is `0600` unless
  `--privsep` is used: there the launcher makes an existing store `0644` and
  the gate creates a new one `0644`, so the analyzer can read it back, and any
  later rewrite keeps the read bits the file already has. An unreadable trust
  store fails **closed** (nothing trusted, everything asked).

History rules (`analyzers.LedgerAnalyzer`):

- `descriptor-drift` (CRITICAL) — the normalized descriptor set differs from
  this identity's baseline: the first readable set recorded for it, whatever
  that sighting's decision, or the set most recently approved
- `previously-rejected` (CRITICAL) — this identity was refused before; the
  prompt is the countdown
- `ledger-unavailable` (NOTICE) — the history could not be read, so the device
  is judged without it

### 1.7 Session awareness

Screen-lock handling (`session.py`): devices arriving while the session is
locked are queued or denied per `--lock-policy`, and a queued device is re-asked
on unlock. Deferral never becomes silent approval.

With no one to ask at all -- the service has no terminal, and no desktop agent
is connected (login screen, logout, agent restart) -- a device is **held**
blocked before stages 3 and 4, and asked about when an agent connects. A
replayed udev "add" for a held device is ignored. A device whose question was
lost to a departing agent three times is refused as unanswered. A question
that was shown and not answered is recorded as "no answer", not re-queued,
and the agent shows a display-only "still blocked, replug it" notice
(critical urgency for a CRITICAL device).

### 1.8 Privilege separation (`--privsep`)

A separate root gate (`gate_server.py`) performs the only privileged operations —
writing `authorized`, opening input and block nodes read-only — and passes file
descriptors over a `SEQPACKET` socket with `SCM_RIGHTS` to an analyzer running
as `nobody`, or the account `--privsep-user` names (the systemd service: its
own `probolos` system account). The privilege drop is verified, including
that `setuid(0)` fails afterwards.

The gate distinguishes temporary activation from final admission. Read scope
follows the USB device ancestor, skipping interface nodes, and requires blocked
state or an unexpired temporary permission for the same device instance. Final
admission gives no continued read/deauthorization permission. Whole-device
requests cannot target interfaces. See `SECURITY.md` for the limits of this
boundary; the analyzer still controls admission policy.

"Always" under `--privsep` is written by the gate (`REQ_TRUST`), never by the
analyzer: only for a device the gate admitted on this connection, within
60 s, once, and only under the fingerprint the gate took itself before first
switching the device on. The trust file's path comes from the root side's
command line.

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

### 1.11 Non-product tooling

- `testbed/` — `dummy_hcd` / `raw_gadget` software emulation and a HID attack fixture
- `interrogation_study.py` + `interrogate.py` — **research instrument only.**
  Active control-transfer fingerprinting for data collection. It classifies
  nothing and is not wired into the daemon.

### 1.12 Notes on what changed

Several capabilities in the lists above were, until recently, code that
existed without being reachable or that did not do what it said. They are
called out because the failure mode is worth recognising rather than just
repairing:

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
| `report._line()` padded with Python character count, so a long ASCII name, a CJK product name, or a product string containing box-drawing characters broke the report box. `textsafe.pad`/`fit`/`display_width` were written for exactly this and had no callers. | The box is gone: the report is indented text, `_wrap()` measures in terminal columns (`textsafe.display_width`, `split_width`), and `_quote()` quotes device-supplied strings so they read as testimony, not as verdict text. `pad`/`fit` lost their callers with the box (§2.2). |
| The shipped systemd unit ran `--privsep --agent --timeout 0` with no `--agent-user`. At boot there is no graphical session, so `_resolve_agent_identity()` called `sys.exit()` and `Restart=on-failure` looped forever with the gate never closing. | Auto-detection failure logs and continues without the agent (explicit unknown `--agent-user` still exits). The unit gained `Environment=PROBOLOS_AGENT_USER` and a drop-in note. |

Each row has regression tests under `tests/`. Hardware claims are not
inferred from mock tests.

### 1.13 Media changes in admitted card readers (`--watch-media`, off by default)

**A separate detection layer, not part of the admission gate.** A card is a
SCSI medium inside a reader, not a USB device: inserting one is a unit
attention in the bound `usb-storage`/`uas` driver, with no re-enumeration and
no `authorized` decision point. The pre-authorization quarantine therefore
does not extend to cards, and nothing here claims it does.

| Piece | Mechanism |
|---|---|
| Which hosts | storage-only devices admitted by this run (prompt, trust, safety exemption) and storage-only devices present at startup (`mediawatch.MediaWatch.register`) |
| Event | udev `block`/`disk` `change` (and `add`) on a disk whose sysfs path is under a watched host, same kernel directory instance (`daemon._dispatch`) |
| Read | stage 4's own `storage.inspect_safely` on `/dev/sdX`: raw, read-only, never mounted, bounded, watchdog paused |
| Drift | ledger `media` section keyed on reader identity + SCSI LUN; the first layout is the baseline and never moves |
| Privsep | the gate, started with the same flag, records admitted/baseline storage-only hosts and allows whole-disk read-only opens and switch-**off** for them (`gate_server._media_host`) |
| Enforcement | `--media-policy log` (default) or `deauthorize`: drop the **whole reader** on a CRITICAL finding; nothing finer exists |

Rules (`rules.media_findings`), added to the stage 4 structural findings:

- `media-efi-system-partition` (CRITICAL) — MBR type `0xEF` or the GPT ESP GUID
- `media-hidden-partition` (CRITICAL) — hidden MBR types, or GPT attribute bit 62
- `media-inserted-while-locked` (WARNING)
- `media-layout-drift` (WARNING for a layout never seen in the slot, NOTICE for one seen before)

Every report states whether automount was inhibited for the disk
(`UDISKS_IGNORE`/`UDISKS_AUTO` from udev) or the medium was already mounted
when read, in which case it is post-hoc alerting. Latency follows the kernel's
disk-event polling (typically 1–2 s); a slot whose `events` does not include
`media_change`, or that nobody polls, is flagged when first seen.

Not covered: SD/MMC readers that are not USB mass storage (`mmcblk`, e.g.
SDHCI or `rtsx`), composite readers, and filesystem-parser exploits (§2.1).

### 1.14 The background service

`sudo ./install.sh` installs the code root-owned in `/opt/probolos` and enables
two systemd units (`systemd/`): `probolos.service`, the gate as a system
service with `--privsep --agent` and a sandboxed unit, and
`probolos-agent.service`, the desktop agent as a user service. Without an
agent the service holds devices (§1.7); with one, it asks through the desktop
prompt (§1.1). The units are checked in CI (`systemd-analyze verify`); their
behaviour on real hardware is part of the hardware matrix (ROADMAP 2.2).

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
  watching it. The one exception is `--watch-media` (§1.13), which watches
  the *media* of admitted storage hosts and still does not gate them.
- **Admission control for removable media.** A card has no `authorized`
  switch of its own. `--watch-media` observes and alerts; at most it drops the
  whole reader.
- **Filesystem-parser exploits.** A crafted exFAT/NTFS/FAT that attacks the
  kernel's filesystem driver on mount looks like an ordinary filesystem in a
  partition table. Kernel fs-driver bugs are the same class as kernel USB-stack
  bugs above.
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
- **`textsafe.pad()` and `textsafe.fit()`.** Tested, and correct for
  double-width and combining characters, but the boxed report they were
  written for is gone (§1.12): nothing outside the tests calls them. They stay
  until after 1.0.
- **Deferred binding remains experimental** (`--close-race-window`). It does
  not guarantee a zero exposure window, it is not available under
  `--privsep`, and it is outside the 1.0 guarantees (§3.0).

---

## 3. What may be built

### 3.0 Deferred past 1.0

Decided at the feature freeze (`v0.11.0`), so the absence reads as a decision.
None of these is in 1.0.0; each is a post-1.0 candidate.

| Deferred | Note |
|---|---|
| A GUI for history and trust | `--history`, `--trusted` and `--remove-*` stay command-line |
| `--remove-history N\|PATTERN`, numbered `--history` | |
| A configurable dialog timeout | 60 s stays the default |
| HID report-descriptor analysis | §3.2 |
| `--close-race-window` (deferred binding) | Stays in the tree, **experimental, outside the 1.0 guarantees** (§2.2) |

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
- Validate the systemd service (§1.14) on real hardware (§3.1, ROADMAP 2.2).

### 3.4 Research directions

- **Population-scale false-positive measurement of two specification-derived rules**
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
