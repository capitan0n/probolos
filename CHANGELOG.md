# Changelog

All notable changes to Cerberus. Versioning is semantic.

## [0.9.0] — the audit

An external security review of the whole codebase produced four critical
findings and a dozen smaller ones. All four are fixed, each with a regression
test that was *proven* to fail against the original defect before being kept.
The suite went from 282 tests to 328.

One theme runs through almost every finding, and it is worth naming: **correct
work that was never connected to the path it was written for.** A sanitiser
imported by nothing, a uid check that nothing passed a uid to, a hardening
patch documented but never applied, an inventory command parsed but never
dispatched. The bugs were rarely bad code; they were unwired code.

### Fixed — critical

- **A composite storage+keyboard device was live and ungrabbed for up to ~3.5
  seconds.** Stage 4 ran *before* stage 3, and stage 4 authorizes the whole
  device to make its block node appear — so on a Rubber Ducky in a flash-drive
  body, the keyboard half was typing into the session for the entire scan, with
  no `EVIOCGRAB` anywhere. That is 40–80× longer than the race the documentation
  treated as the main weakness, and it landed on exactly the threat model
  SECURITY.md names as canonical. The stages are reordered, and a device that
  declares both storage and input is no longer inspected at all: it has already
  earned a CRITICAL "storage device that can also type", and its partition table
  cannot make that verdict safer.
- **Anything that could open the agent socket could answer on your behalf.**
  `allowed_uids` was never passed from `serve()`, so the entire `SO_PEERCRED`
  check in `AgentLink._admit()` was dead code. The desktop user's identity is
  now resolved once, before the privsep branch, so the socket's group and the
  uid the gate enforces cannot drift apart — a mismatch there fails quietly, as
  an agent that connects, shows a dialog, and has its answer silently refused.
- **State writes followed symlinks.** `TrustStore.save()` and `Ledger.save()`
  used `write_text()`, which follows a symlink at the staging path. A process
  running as `nobody` could pre-plant `trusted.tmp` pointing anywhere, and the
  next root-run save — `sudo … --forget N`, which the tool's own output tells
  you to run — would write through it. All state writes now use
  `O_NOFOLLOW | O_CREAT | O_EXCL` (`atomicio.py`) and are created `0600`.
- **The root gate enforced none of the policies the design depended on.** It
  checked that a path *was* a USB, input or block node, never that it was the
  device under quarantine — so a compromised analyzer could open
  `/dev/input/event0` (the built-in keyboard) as a system-wide keylogger, read
  `/dev/sda`, or deauthorize hardware you were using. Scope is now derived from
  the kernel: the gate acts only on a device whose `authorized` flag reads 0,
  and on nodes whose USB parent is such a device. A PS/2 keyboard has no USB
  parent and can never be in scope. Because the check reads the kernel rather
  than the request, the analyzer cannot widen its own scope by lying.

### Fixed — high

- **`--privsep` crashed on the deferred-bind path.** `GateBackend` had no
  `authorize_interface`, so `sysfs.set_interface_authorized()` raised
  `AttributeError` in the mode the systemd unit mandates. Added, with a new
  protocol request kind, scoped like every other gate operation: the
  interface's parent device must be under quarantine.
- **`--list` closed the gate.** The flag parsed but was never dispatched, so
  the documented read-only inventory command fell through to `require_root()`
  and disabled every USB port. `cmd_list()` had existed, unreferenced, all
  along.
- **A machine with no dialog backend silently denied every device.** The agent
  returned `ANSWER_NO` when it had no way to ask — indistinguishable from the
  user refusing, and invisible. It now returns a sentinel the analyzer reads as
  "no answer", falling back to the terminal.
- **`--agent` without `--privsep` never worked.** `prepare_socket_dir()` was
  only called on the privsep branch, so the socket stayed `root:root` mode 0660
  and the agent — running as you — got `EACCES` on connect. `AgentLink` now
  chowns the socket to the desktop user when it bound it as root; under privsep
  the launcher still prepares the directory and the chown is skipped, so one
  code path serves both. *Found by running it and looking at `ls -l`.*
- **`nobody` could write valid trust entries.** The trust store and the ledger
  shared a directory, and that directory was chowned to the analyzer. Directory
  write permission allows replacing any file inside it whatever the file's own
  owner, so trust was handed over with it. The ledger moved to
  `/var/lib/cerberus/state/`; `/var/lib/cerberus/` stays root-owned. The
  launcher now refuses outright to hand over a directory holding a trust store.
- **`--ledger /etc/x.json` would chown `/etc` to `nobody` at mode 0700**,
  taking sudo, ssh and PAM with it on a running system — no attacker needed, a
  typo was enough. State directories are restricted to a fixed allowlist,
  resolved with `realpath` first so `../` cannot escape and a sibling like
  `/var/lib/cerberus-evil` does not match on prefix.
- **A stalled storage read opened the gate system-wide.** A device that stalls
  its own security scan froze the daemon; with the watchdog running, that freeze
  became the watchdog reopening `authorized_default` for every port. The read
  now runs in a forked child under a hard time limit, with the watchdog paused
  for the duration. Both are needed: pausing alone converts the fail-open into a
  permanent freeze, which is the obvious and wrong fix.
- **`textsafe.py` was imported by nothing.** 237 lines of Trojan Source and
  control-character defence, orphaned, while a crafted `iProduct` reached the
  terminal, the JSON log and the trust store intact — able to scroll the report
  and overwrite the CRITICAL line the operator was reading. Sanitisation now
  happens at the single point where sysfs bytes become Python strings, and *why*
  a string had to be cleaned is recorded and becomes a finding.
- **Trust entries were built with `TrustedDevice(**raw)`** — no validation at
  all, while the far less security-critical ledger validated carefully.
  `from_raw()` now rejects wrong types, empty fingerprints, and entries whose
  key disagrees with the name they are filed under. That last case is also what
  used to make trust *un-revocable*: `forget_index()` raised `KeyError` and the
  entry could never be removed.

### Added

- **`crafted-strings` rules.** A device that hides control characters or bidi
  overrides in its own identity strings earns a WARNING; one that *also*
  declares a keyboard earns CRITICAL (`crafted-strings-hid`). A real keyboard
  has no reason to obfuscate its name, and combined with the ability to inject
  keystrokes that is intent, not sloppiness.
- **Markup escaping in the dialog backends.** `kdialog` renders Qt rich text
  and `zenity` renders Pango, so a device named
  `<a href="…">Kingston</a>` drew a live link — or a reassuring verdict this
  tool never wrote — next to the Allow button, the one surface where the
  decision is actually made. Escaped for those two backends only: the terminal
  and tkinter render plain text, where a legitimate `A<B & C>D` must show as
  typed.
- **`systemd/60-cerberus-inhibit-automount.rules`.** Stage 4 must briefly
  authorize the device for its block node to appear, and udisks2 would automount
  the medium in that window — the exact kernel-filesystem exposure stage 4
  exists to avoid. The rule sets `UDISKS_IGNORE=1` on USB block devices;
  Cerberus reads the raw node itself and loses nothing. *Found in use: the
  operator was able to mount the stick by hand while the scan was running.*
- **`atomicio.py`** — symlink-safe atomic JSON writes, shared by the trust
  store and the ledger.
- 46 new tests, including a synthetic sysfs tree that exercises the gate's
  kernel-derived scoping with no root and no hardware.

### Changed

- The ledger moved from `/var/lib/cerberus/ledger.json` to
  `/var/lib/cerberus/state/ledger.json`. To keep existing history:
  `sudo mkdir -p /var/lib/cerberus/state && sudo mv /var/lib/cerberus/ledger.json /var/lib/cerberus/state/`
- Storage inspection uses an explicit `fork` start method. The default is
  `spawn` on some configurations, which re-imports the whole package per
  inspection — seconds of latency, and worse, a longer window in which the
  device is authorized.
- `__init__.py` declared `0.5.1` while the changelog was at `0.8.1`. Reconciled.
- The top-level `README.md` was a byte-identical copy of `systemd/README.md`.
  Rewritten as an actual project README.

### Notes

- SECURITY.md previously stated the quarantine race as "typically 10–20 ms".
  The measured figure on real hardware is 41–85 ms, as the 0.6.0 notes already
  recorded. Corrected.
- The panic file moved to `/run/cerberus.panic` and must be root-owned;
  SECURITY.md still documented `/tmp/cerberus-panic`. Corrected.
- `descriptors_safe.py` remains orphaned — 816 lines of hardening reachable
  from no running code path. It is a known outstanding item, not dead weight to
  be deleted casually; either wire it in or remove it deliberately.

## [0.8.1] — three choices, and a service

### Fixed
- **The graphical path was more permissive than the terminal one.** The agent
  offered only Allow/Cancel, so "allow" had to mean "remember forever" — anyone
  glancing at an unfamiliar stick once acquired a permanent trust entry they
  never asked for. The second dialog now offers the same three outcomes as the
  terminal: just this once, always, or cancel. A security tool whose convenient
  path grants more than its inconvenient path is training its users badly.
  *Found by reading the output of a successful run.*

### Added
- **systemd units** (`systemd/`): a system service for the gate and a user
  service for the agent, since a dialog can only appear inside a graphical
  session. Sandboxed with `ProtectSystem=strict`, `PrivateNetwork=yes`,
  `DevicePolicy=closed` restricted to input and block devices,
  `MemoryDenyWriteExecute=yes`, a `SystemCallFilter` denying module loading and
  raw I/O, and a `CapabilityBoundingSet` of only the five capabilities the
  privilege drop needs. `ProtectKernelTunables` is deliberately off and the
  reason is documented: writing sysfs `authorized` is the mechanism itself.

### Changed
- Notification actions were abandoned in favour of dialogs. Plasma advertises
  the `actions` capability and renders no button for it, and the specification
  permits servers not to support interaction at all — a security decision cannot
  rest on an optional mechanism. This also matches what polkit, USBGuard's
  applet, Windows driver prompts and macOS 13's "Allow accessory to connect?"
  all do.

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
