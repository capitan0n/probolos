# Changelog

All notable changes to Cerberus. Versioning is semantic.

## [0.8.0] — approving from the desktop

### Added
- **Desktop notification agent** (`python -m cerberus.agent`). A third process
  runs in the user's session, shows a notification when a device is waiting and
  sends the answer back over a group-restricted Unix socket. Clicking the body
  means allow; a second, differently worded notification must also be clicked
  to confirm. Every other ending — dismissal, expiry, a closed session — is a
  refusal.
- A CRITICAL device is never offered as a clickable question. The agent shows a
  warning with no way to allow anything and the decision stays in the terminal,
  where the whole word `authorize` is required.
- An agent that cannot answer is distinguished from one that answered "no": a
  missing answer falls back to the terminal rather than refusing a device the
  user never saw.
- `--agent`, `--agent-socket`, `--agent-user`. The socket directory is prepared
  by the root launcher with the setgid bit set, so a socket created by the
  unprivileged analyzer is reachable by exactly the desktop user and nobody
  else — a world-writable socket would let any local account approve hardware.
- `python -m cerberus.agent --test` checks that notifications and body-clicks
  work on a given desktop before relying on them.

### Notes
- The security property that makes a clickable prompt safe is that the device is
  still unauthorized when the notification appears, so it cannot click its own
  approval. This depends on the device being re-blocked after observation, which
  is a tested invariant.
- Run the suite with `-b` (`python -m unittest discover -b -s tests -t .`) to
  keep daemon output from interleaving with test results.

## [0.7.2] — the deferred question

### Fixed
- **A remembered device held while the screen was locked was admitted silently
  when the queue drained.** The stated policy — nothing is admitted while you
  are away, including remembered devices — was undone by the deferral itself:
  the trust shortcut applied when the question was finally put, so the policy
  degraded to "nothing until you get back, then everything". Anything that
  spent time in the queue is now always asked about, with a note explaining
  why a remembered device is being questioned. *Found by a user asking why a
  held device came back as TRUSTED.*

## [0.7.1] — found in use

### Fixed
- **A device held when Cerberus exited was stranded.** It stayed at
  `authorized=0` — dead — and on the next run was counted as part of the
  baseline, so it was never asked about. The only way to get a question was to
  unplug and replug the hardware, which is precisely what the hold queue exists
  to avoid. A device at `authorized=0` is no longer treated as "already working,
  leave it alone"; it is queued for decision at startup.
- Exiting with undecided devices now says which ones are being left blocked and
  how to release them. Cerberus will not authorize something nobody approved,
  but leaving hardware dead in silence is how a tool earns a reputation for
  breaking things.
- Approving with `always` now counts as the first admission, and the state
  directory hand-over is announced once rather than per file.

## [0.7.0] — usable every day

### Added
- **Remembered devices.** Approving with `a` (always) admits a device silently
  next time. Trust is pinned to identity AND a hash of the raw descriptors, so
  a cloned VID/PID is not the trusted device; it never overrides a CRITICAL
  finding, and the `always` option is not offered for one. `--trusted` lists
  what is remembered, `--forget` revokes it.
- **Stage 4: read-only storage inspection.** The partition table and filesystem
  signatures are parsed directly from the raw block device, opened read-only
  and never mounted, so the kernel's filesystem drivers never see the medium.
  Detects partitions past the end of the device, overlapping partitions,
  declared types that disagree with content, and large unallocated gaps.
  Deliberately does not walk directories — that would reintroduce the attack
  surface this stage exists to avoid.
- **Screen-lock policy.** While the screen is locked nothing is admitted, not
  even remembered devices, and the device is never powered up — so neither
  quarantine nor the storage scan runs with nobody present. Held devices are
  queued and asked about the moment the screen unlocks, with no need to unplug
  and replug. State comes from logind; if it cannot be determined, Cerberus
  says so rather than silently disabling the protection.
- `OPEN_BLOCK` in the gate protocol, so the unprivileged analyzer can read a
  whole disk read-only through the privileged gate. Restricted to whole
  `/dev/sdX` nodes — never a partition, never a mapper device.


## [0.6.0] — privilege separation

Five defects in this release were found by running the tool on real hardware,
not by review or by the test suite. They are listed explicitly because that
pattern is the most useful thing this project has produced.

### Fixed (found in use)
- **Quarantine never worked on a real device.** `find_input_nodes` compared the
  bus-view USB path against udev's already-resolved `sys_path`; they never
  match. Every real quarantine reported "no input nodes appeared" — an absence
  of evidence that read as evidence of absence, the worst failure mode for a
  security tool. Now both sides are resolved before comparison.
- **The device stayed live between observation and decision.** The grab was
  released when the observation window ended, but the device remained
  authorized while the human read the report. A malicious device could stay
  silent for the window and then act freely during the prompt, defeating
  quarantine by waiting; a composite device's storage half was exposed to
  automount for the same period. The device is now re-blocked the instant
  observation ends. *Reported by a user noticing their mouse still worked.*
- **A crashed run left the gate closed permanently.** On startup, an
  `authorized_default` already at 0 was recorded as "the original value" and
  faithfully restored on exit, so each run politely preserved the previous
  run's lockout. 0 is now treated as "no valid previous state" and 1 restored.
- **The gate died with the analyzer on Ctrl-C.** SIGINT reaches the whole
  process group, so the privileged gate tore down its socket while the
  analyzer was still sending its final restore requests — producing a cascade
  of "FAILED to restore". The gate now ignores terminal signals and exits when
  the analyzer closes the connection.
- **Path validation rejected legitimate devices.** USB nodes are reachable both
  as bus-view symlinks and as resolved device-tree paths, depending on whether
  they came from sysfs or from pyudev. The gate now accepts either, proving USB
  membership structurally rather than by prefix.

### Changed
- **`python-evdev` is no longer a dependency.** Behavioural quarantine talks to
  the kernel directly (one `EVIOCGRAB` ioctl, one fixed-size struct). evdev
  opens the node from a path, which is impossible for the unprivileged analyzer
  that receives an already-open descriptor — so removing it also collapsed two
  diverging code paths into one.
- Measured exposure gap on real hardware is 41–85 ms, not the 10–20 ms
  previously estimated in the README. The figure is measured and printed per
  device precisely because it is not a constant.

### Added
- **Privilege separation (`--privsep`).** A minimal root gate
  (`gate_server.py`) is now the only code that runs privileged: it writes
  `authorized`/`authorized_default` and opens input nodes read-only, passing
  the descriptors to an unprivileged analyzer over a `SEQPACKET` socketpair
  using `SCM_RIGHTS`. The analyzer — rules, quarantine, ledger, payload — runs
  as `nobody`. The privilege drop is verified, including that regaining root
  fails afterwards.
- `protocol.py`: the complete, auditable message contract between the two
  halves. The gate refuses any path outside `/sys/bus/usb/devices` and
  `/dev/input`, and only ever performs four operations.
- Pluggable privileged-write backend in `sysfs.py`, so the entire existing
  daemon moved behind the split with no change to its logic.
- 20 new tests covering the protocol, gate path validation (including `../`
  traversal), fd passing over `SCM_RIGHTS`, and the privilege-drop guards.

### Notes
- `--privsep` is opt-in for now and will become the default after more
  real-world testing. Without it, behaviour is unchanged.

## [0.5.2] — testbed

### Added
- **Software USB device emulation** (`testbed/`) using `dummy_hcd` +
  `raw_gadget`. Presets for BadUSB, descriptor drift, overpowered devices and
  honest controls. Enables the CRITICAL and drift paths to be demonstrated and
  tested with no hardware.
- `--wait` on the spawn tool to hold an emulated device present until Enter,
  so there is time to answer the prompt.

### Fixed
- raw-gadget ABI: corrected ioctl sizes for the flexible-array event and ep0
  structs, and the control-transfer status-stage handling for no-data
  requests. Five successive fixes, each documented in the source.
- Ledger decisions are recorded before the sysfs write, so history survives a
  device removed mid-decision (which drift detection depends on).

## [0.5.0] — power, field fixes

### Fixed
- **`bMaxPower` unit bug**: 2 mA units on USB 2.0 but 8 mA on SuperSpeed. Every
  USB 3 device had been under-reported fourfold.
- Removed a power rule that fired on an ordinary self-powered Bluetooth radio;
  the premise was wrong on re-reading the spec. Recorded, with a test.

### Added
- Four power-declaration consistency rules, all NOTICE/WARNING.
- Ledger default path is now XDG-friendly for non-root use.

## [0.4.0] — analyzers, ledger, payload, safety

### Added
- Analyzer plugin layer (`analyze(ctx) -> [Finding]`), with failures contained.
- Descriptor ledger with drift detection across sightings.
- Opt-in payload reconstruction (`--capture-payload`).
- Lockout-safety layer: protected ports, watchdog, panic file — as tested
  invariants.

## [0.3.0] — behavioural quarantine

### Added
- Stage 3: authorize an input device while immediately `EVIOCGRAB`-ing it, then
  judge what arrives. Timing analysis plus the stronger "typed while untouched"
  signal. The exposure race is measured and reported.

## [0.2.0] — semantic rules

### Added
- Stage 2 consistency rules over functional coherence, validated against real
  hardware to avoid false positives.

## [0.1.0] — the gate

### Added
- Authorization gate with guaranteed restore, udev loop, raw descriptor parser,
  identity report, deny-by-default prompt, JSONL audit log.
