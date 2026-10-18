# Capabilities and scope

What Probolos does (§1), what it does not do (§2), and what may come later
(§3). §1 lists only code that actually runs; code that exists in the tree but
is not used is in §2.2.

> **Feature freeze.** §1, as of the `v0.11.0` tag, is the feature list for
> 1.0.0. Until then only fixes, tests, documentation and release work go in
> ([ROADMAP.md](ROADMAP.md)); anything new waits for after 1.0 (§3.0).

Status: beta. Tested mostly with emulated devices (`dummy_hcd`/`raw_gadget`);
real-hardware testing is limited (README, "Status").

**Severities.** CRITICAL means the device matches an attack pattern: allowing
it takes a 10-second countdown in the dialog or the typed word `authorize` in
the terminal, "always" is never offered, and trust never overrides it. WARNING
is suspicious; NOTICE is worth knowing. A YAML file (`--rules FILE`) can turn
off or re-grade the rules of stages 2 to 4 and the card rules; the history and
payload rules (§1.6, `payload-captured`) cannot be changed.

---

## 1. What Probolos does

### 1.1 Admission control

- Every USB root hub gets `authorized_default=0`, so new devices arrive
  switched off. Devices already attached at start are left alone.
- A device is switched on for good only by your answer (terminal or desktop
  agent), a remembered "always", or a safety exemption (internal port,
  `--allow-port`). Stages 3 and 4 switch it on briefly before that.
- A new device cannot answer its own prompt: it is still off while the
  question is shown.
- The original state is restored on every exit, crash or signal; `--release`
  recovers by hand.

The desktop agent asks with as much friction as the device earns: **one
dialog** for a device that can neither type nor carry traffic and showed no
warning; **two dialogs** for keyboards and other HID, network, radio,
vendor-specific or unknown functions, or any warning; and for a CRITICAL
finding a **countdown**, where "Allow anyway" stays disabled for 10 s and an
earlier approval is refused. A dialog that times out or crashes is "no
answer", never a refusal; closing its window counts as "Keep blocked".

### 1.2 Stage 1 — Identity

Reads what the device declares: device, configuration, interface and string
descriptors, speed, and power (in the right units for USB 2 and USB 3).

### 1.3 Stage 2 — Consistency rules

| Rule | Severity | Fires when the device |
|---|---|---|
| `storage-with-keyboard` | CRITICAL | is storage and also declares a keyboard |
| `network-with-keyboard` | CRITICAL | is a network or radio device and also declares a keyboard |
| `crafted-strings-hid` | CRITICAL | can type and hides control or bidi characters in its name |
| `storage-with-undeclared-hid` | CRITICAL | is storage plus an input interface of unclear kind (a mouse, or HID that does not say) |
| `unreadable-descriptors` | CRITICAL | has descriptors that could not be parsed |
| `descriptor-chain-truncated` | CRITICAL | cut its descriptor chain short |
| `configurations-missing` | CRITICAL | delivered fewer configurations than it declared |
| `keyboard-with-unrelated-function` | WARNING | is a keyboard bundled with an unrelated function |
| `self-contradictory-identity` | WARNING | names itself storage but presents an input interface |
| `interface-count-mismatch` | WARNING | declares a different number of interfaces than it has |
| `crafted-strings` | WARNING | has control or bidi characters in its strings |
| `network-with-undeclared-hid` | WARNING | is a network device plus an input interface of unclear kind |
| `stacked-combining-marks` | WARNING | piles up combining marks that can draw over the report |
| `power-exceeds-bus-limit` | WARNING | asks for more power than USB allows |
| `multiple-distinct-functions` | NOTICE | combines functions in an unusual way |
| `no-interfaces` | NOTICE | declares no interfaces at all |
| `keyboard-at-high-speed` | NOTICE | is a keyboard on a high-speed link |
| `invisible-string-characters` | NOTICE | has invisible characters in its strings |
| `storage-declares-negligible-power` | NOTICE | is storage that claims to need almost no power |
| `power-varies-across-configurations` | NOTICE | declares very different power per configuration |
| `descriptor-length-overstated` | NOTICE | claims more descriptor data than it delivered |

A check that crashes is reported, never skipped: `analyzer-failed:<check>` is
CRITICAL when that check decides its stage, NOTICE otherwise.

### 1.4 Stage 3 — Behavioural quarantine

The device is switched on for `--observe` seconds (default 3) with its input
captured (`EVIOCGRAB`), and switched off again *before* the capture is
released, also on errors. Keys sent before the capture takes hold can escape,
and `--close-race-window` does not change that. Timing comes from kernel
timestamps.

| Rule | Severity | Fires when |
|---|---|---|
| `unprompted-typing` | CRITICAL | it typed while you were told not to touch it |
| `machine-generated-keystrokes` | CRITICAL | its typing rhythm is too regular for a human |
| `quarantine-not-restored` | CRITICAL | it could not be switched off again afterwards |
| `payload-captured` | CRITICAL | it typed, with `--capture-payload`: the keys are shown as a transcript (US layout, about 4096 characters at most) |
| `unexpected-keystrokes` | WARNING | a few unexplained keys arrived |
| `immediate-activity` | WARNING | it started typing the instant it was switched on |
| `incomplete-isolation` | WARNING | an input channel could not be captured |
| `quarantine-unavailable` | NOTICE | the behaviour could not be observed |

The report shows the delay between switch-on and capture. That delay is not a
count of the keys that escaped.

### 1.5 Stage 4 — Storage inspection, never mounted

For storage-only devices, Probolos reads the first sectors raw and read-only:
the MBR or GPT, and filesystem signatures (NTFS, exFAT, FAT, ext2/3/4, btrfs,
ISO 9660, UDF; the last two only when their structure checks out). Anything
else (f2fs, squashfs, ...) reads as "no known filesystem". An installer image
written with `dd` (ISO 9660 behind an MBR) is shown as such. The read runs in
a separate process with a time limit. Media with 512-byte logical blocks only:
one with 4096-byte blocks is reported as not inspected.

Stage 4 is skipped for composite devices (storage plus anything else) and for
devices with incomplete descriptors, because switching them on would switch
their other functions on too. Its result is context: decisions rest on stages
1 and 2.

| Rule | Severity | Fires when |
|---|---|---|
| `partition-beyond-end-of-device` | WARNING | a partition ends past the end of the medium |
| `overlapping-partitions` | WARNING | partitions overlap |
| `impossible-partition-geometry` | WARNING | a partition entry cannot exist on this medium |
| `filesystem-type-mismatch` | NOTICE | a partition holds something other than its declared type |
| `filesystem-signature-without-structure` | NOTICE | a filesystem signature has no valid structure behind it |
| `large-unallocated-gap` | NOTICE | a large area before the first partition is described by nothing |
| `gpt-without-protective-mbr` | NOTICE | a GPT has no protective MBR |
| `storage-unreadable` | NOTICE | the medium could not be read (the reason is shown) |

### 1.6 History and trust

- **History (the ledger):** every device seen, with its type (from its
  interface classes, never from its own name), the decisions about it, and a
  fingerprint of its descriptors. The fingerprint ignores what legitimately
  changes between USB 2 and USB 3 ports. `--history [-v]` shows it.
- **Trust store:** devices allowed "always", pinned by identity *and* the
  exact descriptor bytes, so a remembered device moved between a USB 2 and a
  USB 3 port may be asked about again. A trust store that cannot be read, or
  that holds a malformed entry, trusts nothing.

| Rule | Severity | Fires when |
|---|---|---|
| `descriptor-drift` | CRITICAL | a known device now presents different descriptors |
| `previously-rejected` | CRITICAL | you refused this device before |
| `ledger-unavailable` | NOTICE | the history could not be read |

### 1.7 When nobody can answer

- **Screen locked:** a new device is held and asked about on unlock
  (`--lock-policy queue`, the default) or denied (`deny`). Either way nothing
  gets in while the screen is locked, not even a remembered device, except on
  an internal port or an `--allow-port` port (§1.9). (`ignore` takes no
  notice of the lock.)
- **Desktop prompt set up but not there** (the service at the login screen,
  during a logout, or while the agent restarts): a new device is **held**
  switched off, before stages 3 and 4, and asked about when the prompt is
  back. Remembered devices still get in.
- A question that was shown and not answered is recorded as "no answer", not
  as a refusal, and you are told to replug the device. A device whose question
  is lost three times is refused as unanswered.

### 1.8 Privilege separation (`--privsep`)

A root gate does the privileged work (writing `authorized`, opening the input
and disk nodes of devices under inspection) and hands open files to an analyzer
that runs as `nobody`, or as `--privsep-user` (the service: `probolos`). The
privilege drop is verified. The gate's scope comes from the kernel's view of
the device, not from the analyzer's request. "Always" is written by the gate
itself, only for a device it admitted in the last 60 s, under a fingerprint it
measured. Limits: [SECURITY.md](SECURITY.md).

### 1.9 Lockout safety

A watchdog (`--watchdog`), the panic file (`/run/probolos.panic`, checked by
the watchdog), `--release`, `--allow-port`, `--dry-run`, internal ports left
ungated, and the bus state restored on every exit path, including a failed
start and a lost analyzer. Internal ports and `--allow-port` stay ungated
while the screen is locked, so a rescue keyboard can type the password.

### 1.10 Hostile device text

Names and serials are cleaned where they enter the program: control
characters, bidi overrides and invisible characters are shown escaped, never
acted on, and reported (§1.3). A device cannot rewrite the report about
itself. The dialogs also escape markup.

### 1.11 Research tooling (not part of the product)

- `testbed/`: software-emulated USB devices and a HID keystroke experiment.
- `interrogation_study.py` and `interrogate.py`: active probing for data
  collection. It classifies nothing and the daemon does not use it.

### 1.12 Card readers (`--watch-media`, off by default)

A **detection layer**, not part of the gate: a card is a medium inside an
allowed reader, not a USB device, so it cannot be held.

- Watched: storage-only devices this run allowed, and ones present at start.
- When a card changes, it is read like stage 4 and judged by the rules below.
  At the plug-in prompt, the same rules apply to a card already in the reader.
- `--media-policy log` (default) only reports; `deauthorize` switches the
  whole reader off on a CRITICAL card. Nothing finer exists.
- Each report says whether automount was off (`UDISKS_IGNORE=1`), only hinted
  off (`UDISKS_AUTO=0`, which KDE Plasma ignores), or the card was already
  mounted.
- A card left at 0 bytes is re-checked for 15 s, then reported as unreadable.
- The card approved with its reader is not judged again, and a card the reader
  announces twice is reported once (not while the screen is locked).
- A card that raised a CRITICAL never becomes the slot's reference layout.
- Under `--privsep`, the gate lets the analyzer read the disks of all
  watched devices (sticks and USB disks too, not only readers) and switch
  them off, never on.

| Rule | Severity | Fires when the card |
|---|---|---|
| `media-efi-system-partition` | CRITICAL | has an EFI system partition |
| `media-hidden-partition` | CRITICAL | has a hidden partition |
| `media-inserted-while-locked` | WARNING | went in while the screen was locked |
| `media-layout-drift` | WARNING or NOTICE | differs from the slot's first card (NOTICE if its layout was seen in that slot since) |

Not covered: card readers that are not USB storage (`mmcblk`, such as SDHCI or
`rtsx`), composite readers, and malicious filesystems (§2.1).

### 1.13 Background service

`sudo ./install.sh` installs the code in `/opt/probolos` and two systemd units:
the gate as a sandboxed system service (`--privsep --agent`, analyzer as
`probolos`) and the desktop prompt as a user service
([systemd/README.md](systemd/README.md)). CI checks the units; testing them on
real hardware is ROADMAP 2.2.

---

## 2. What Probolos does not do

### 2.1 Out of scope by design

- Bugs in the kernel's USB code (reached before Probolos sees the device)
- Thunderbolt / PCIe DMA (the IOMMU and `boltctl` cover that)
- USB Power Delivery
- Bluetooth and other wireless devices
- A patient device that attacks later
- A perfect copy of a real device that stays quiet while it is checked
- Malicious hubs or controller chips
- Anything after a device is allowed (except card watching, §1.12)
- Blocking a single card: there is no per-card switch, only the whole reader
- Malicious filesystems (bugs in the kernel's filesystem drivers)
- Scanning file contents
- Systems other than Linux

### 2.2 In the tree but not used

- **HID report descriptor analysis.** The parser
  (`descriptors_safe.walk_hid_items()`) is written and tested, but nothing
  feeds it: the report descriptor is not in sysfs while the device is off
  (§3.2).
- **`textsafe.pad()` and `fit()`.** Tested, but without a caller since the
  boxed report was removed. They stay until after 1.0.
- **`--close-race-window`.** Experimental deferred driver binding: it does not
  close the input race, it uses a system-wide switch, it cannot be combined
  with `--privsep`, and it is outside the 1.0 guarantees.

---

## 3. What may come later

### 3.0 Deferred past 1.0

Decided at the feature freeze, so their absence reads as a decision:

| Deferred | Note |
|---|---|
| A GUI for history and trust | stays command-line |
| `--remove-history N\|PATTERN`, numbered `--history` | |
| A configurable dialog timeout | dialogs use `--timeout` (10–600 s), or 60 s when it is 0 |
| HID report-descriptor analysis | §3.2 |
| `--close-race-window` | stays in the tree, experimental (§2.2) |

### 3.1 Validate before adding

Measure what exists on real hardware first: keystrokes that escape before the
capture, detection and miss rates, false positives on ordinary devices, how
long each stage takes, and recovery after failures (ROADMAP 2.4).

### 3.2 HID report descriptors

Reading them, from `/sys/bus/hid/devices/*/report_descriptor` during
quarantine or with a control transfer while no driver is bound, would allow a
strong new rule: a device that says *mouse* while its report descriptor
describes a keyboard.

### 3.3 Research ideas

- An HMAC over the trust store, keyed by a root-only file.
- Active interrogation as a detector, if the collected data separates
  ordinary devices from general-purpose microcontrollers.
- Watching devices after approval, with HID-BPF.
- A finding for a device that appears on an internal port.
- Explaining *what* changed between visits, and whether it is plausible.
- Vendor plausibility: a vendor ID whose strings name another company.
- False-positive rates on ordinary hardware, starting with
  `descriptor-chain-truncated` and `descriptor-length-overstated`, which come
  from the specification rather than from devices seen in the wild.

### 3.4 Not planned

Thunderbolt/DMA, USB-PD, wireless attack surfaces, content scanning and
platforms other than Linux.
