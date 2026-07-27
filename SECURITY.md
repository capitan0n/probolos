# Security policy and threat model

## Reporting

Open a GitHub issue for anything that is already public. For anything else,
contact the maintainer directly before disclosing.

## What Cerberus is trying to stop

An attacker with brief physical access who leaves behind, or persuades someone
to plug in, a USB device whose declared function differs from its real one.
The canonical case is a keystroke-injection device in the body of a flash
drive.

## What it assumes

- The machine and its kernel are trustworthy at the moment Cerberus starts.
- The operator can answer a prompt using an input device that was already
  present and already trusted.
- Root is not already compromised. Cerberus is not a rootkit detector.

## What it does not stop

**Vulnerabilities in the USB stack itself.** The gate acts *after* the kernel
has parsed descriptors. A bug in that parsing is reached before Cerberus sees
anything. This defends against malicious device *functionality*, not against
memory corruption during enumeration. Only a separate physical machine
(`usbip` to a sacrificial host) removes this exposure.

**A patient attacker.** A device that behaves perfectly for a week and attacks
afterwards passes every check here. The ledger narrows this by detecting a
device that changes its descriptors between visits, but a device that changes
only its *behaviour* leaves nothing to compare.

**Descriptor forgery.** An O.MG cable declares exactly what a real cable
declares. No identity-based check can separate them — which is the entire
reason stages 3 and 4 exist, and why active interrogation is being
investigated.

**DMA-capable interfaces.** Thunderbolt and PCIe attacks bypass this entirely.
That is what the IOMMU and `boltctl` are for.

**Wireless gateways.** A Bluetooth adapter (class `0xE0`) passes every check
and then admits a keyboard over the air, with no USB event at all.

## Known weaknesses in the current implementation

These are real and are not hidden:

**The daemon runs as root and reads keystrokes.** This is the wrong shape. The
privileged operations are small — writes to `sysfs`, opening input nodes — and
belong in a minimal process that passes file descriptors to an unprivileged
analyzer over `SCM_RIGHTS`. Until that split exists, a bug in any analyzer is a
bug in a root process.

**The quarantine has a race.** Between `authorized=1` and the `EVIOCGRAB`
completing, keystrokes can reach the session. The window is measured and
printed in every report, typically 10–20 ms. It is eliminated, not merely
narrowed, by moving to `drivers_autoprobe=0` plus interface-level
authorization plus `libusb`, so that no `/dev/input` node is ever created. That
is the intended architecture; the current one is a stopgap.

**Active interrogation can be a trigger.** The probes in `interrogate.py`
deliberately send requests outside ordinary enumeration. A sophisticated
implant can use exactly that as a wake-up signal. Probes are ordered so benign
ones run first, but probing a device believed hostile is an active choice.

## Behavioural analysis and mimicry

Malboard (Farhi et al., *Computers & Security*, 2019) demonstrated a malicious
USB keyboard that imitates a specific user's typing characteristics in order to
defeat continuous keystroke-dynamics verification, evading the detection tools
tested in 83–100% of cases.

Cerberus's timing statistics are vulnerable to exactly that technique, and the
`machine-generated-keystrokes` rule should be assumed defeated by a
sufficiently careful attacker.

The quarantine is what survives it. Continuous-verification systems must
separate an attacker's typing from the legitimate user's *while the user is
present*, which is what makes imitation effective. During quarantine the ground
truth is that nobody is touching the device, so a perfectly human rhythm buys
the attacker nothing: `unprompted-typing` fires on the fact of typing, not on
its cadence. That rule, not the timing analysis, is the one carrying the weight.

## Keystroke capture and privacy

Cerberus can reconstruct what a quarantined device typed. That capability is
constrained structurally, not by policy:

1. **Devices attached before startup are recorded in a baseline and never
   inspected.** Your own keyboard is never a candidate.
2. **Quarantine runs strictly before the human decision.** Once a device is
   authorized the grab is released and never retaken.
3. **Key identity is discarded unless `--capture-payload` is passed.** By
   default a `KeyPress` carries a timestamp and nothing else, so the default
   configuration cannot reconstruct text even in memory. Timing analysis works
   without it.

Points 1–3 are asserted in `tests/test_payload.py` and `tests/test_safety.py`.

There is therefore no configuration in which Cerberus records a device that
somebody has approved and is using. If you find one, that is a security bug and
should be reported as one.

Operators in the EU should note that capturing input from a device attached to
a corporate machine may still engage GDPR obligations even under these
constraints, and that `--capture-payload` should be enabled deliberately.

## Lockout safety

A tool that can leave someone without a keyboard does not get installed. Four
independent layers:

| Layer | Covers |
|---|---|
| Protected devices | internal (`removable=fixed`) ports are never gated |
| Port allowlist | `--allow-port` keeps a rescue port always open |
| Watchdog | daemon alive but stuck; reopens the gate |
| Panic file | `touch /tmp/cerberus-panic` from another TTY or over SSH |

Plus the gate's own restore paths (context manager, signal handlers, `atexit`)
which cover a daemon that dies, and `--release` for manual recovery.

Only `SIGKILL` combined with a full lockout defeats all of these, and the manual
recovery is one line:

```bash
echo 1 > /sys/bus/usb/devices/usb1/authorized_default
```
