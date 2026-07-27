# Changelog

All notable changes to Cerberus. Versioning is semantic.

## [0.6.0] — privilege separation

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
