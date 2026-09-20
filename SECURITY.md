# Security policy and threat model

## Reporting

Open a GitHub issue for anything that is already public. For anything else,
contact the maintainer directly before disclosing.

## Scope of this document

This file describes the **threat model**: what is being defended against and
under what assumptions. For the feature-by-feature boundary — which capabilities
are implemented and reachable, which exist in the tree but are not on any
execution path, and which are merely under consideration — see
[`CAPABILITIES.md`](CAPABILITIES.md). Where the two disagree, `CAPABILITIES.md`
is the one kept current against the code.

## What Probolos is trying to stop

An attacker with brief physical access who leaves behind, or persuades someone
to plug in, a USB device whose declared function differs from its real one.
The canonical case is a keystroke-injection device in the body of a flash
drive.

## What it assumes

- The machine and its kernel are trustworthy at the moment Probolos starts.
- The operator can answer a prompt using an input device that was already
  present and already trusted.
- Root is not already compromised. Probolos is not a rootkit detector.

## What it does not stop

**Vulnerabilities in the USB stack itself.** The gate acts *after* the kernel
has parsed descriptors. A bug in that parsing is reached before Probolos sees
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

**Privilege separation is optional.** With `--privsep`, the analyzer runs as
`nobody`; the root gate handles sysfs writes and read-only device descriptors.
Startup preparation and protocol/cleanup code also belong to the privileged
boundary. A dedicated service account is preferable to shared `nobody`.

**Temporary activation and admission are different operations.** The gate can
open input/block nodes belonging to a blocked peripheral or to the same device
instance it temporarily activated. Temporary open permission expires after
30 seconds. Re-blocking clears it. Final `admit` activates the inspected instance
without retaining read/deauthorization permission. An already-open descriptor
is not revoked by a lease timer; the normal workflow revokes the device by
re-blocking it before final admission. Baseline devices, non-USB disks and PS/2
keyboards remain outside scope. An interface cannot be passed to the whole-device
operation to bypass its parent-device checks.

The analyzer still decides whether unknown hardware is admitted; this is not
independent verification of a human decision by the gate. An analyzer compromise
can also cause a denial of service or trigger the deliberate exit-time reopening
policy. Privilege separation is not a guarantee that protection survives a
compromised policy process.

**Observation temporarily activates the whole device.** Grabs protect only input
channels successfully captured by Probolos. Storage/network functions of a
composite device are live too. The cleanup path now re-blocks before releasing
any grab and runs on exceptions as well. A grab failure aborts observation;
late nodes continue to be discovered, but discovery is asynchronous.

**The input race remains, including with `--close-race-window`.** Deferred
binding delays driver attachment; it does not stop a driver from delivering
input between attachment and the eventual `EVIOCGRAB`. Starting a udev monitor
first cannot make the following operations atomic. The reported duration is
authorization-to-first-grab latency. Time between Python discovering a node and
grabbing it is not the true exposure interval, and a small displayed number
cannot demonstrate that no keys escaped.

The legacy flag remains experimental and incompatible with `--privsep`. It
changes the bus-wide `drivers_autoprobe` switch and can leave it disabled after
`SIGKILL` or a kernel failure. Use `--observe 0 --no-storage-scan` to avoid these
pre-decision activation windows. That intentionally forgoes behavioural and
storage evidence; it does not protect the earlier kernel enumeration phase.

**Active interrogation can be a trigger.** The probes in `interrogate.py`
deliberately send requests outside ordinary enumeration. A sophisticated
implant can use exactly that as a wake-up signal. Probes are ordered so benign
ones run first, but probing a device believed hostile is an active choice.

## Behavioural analysis and mimicry

Malboard (Farhi et al., *Computers & Security*, 2019) demonstrated a malicious
USB keyboard that imitates a specific user's typing characteristics in order to
defeat continuous keystroke-dynamics verification, evading the detection tools
tested in 83–100% of cases.

Probolos's timing statistics are vulnerable to exactly that technique, and the
`machine-generated-keystrokes` rule should be assumed defeated by a
sufficiently careful attacker.

The quarantine is what survives it. Continuous-verification systems must
separate an attacker's typing from the legitimate user's *while the user is
present*, which is what makes imitation effective. During quarantine the ground
truth is that nobody is touching the device, so a perfectly human rhythm buys
the attacker nothing: `unprompted-typing` fires on the fact of typing, not on
its cadence. That rule, not the timing analysis, is the one carrying the weight.

## Keystroke capture and privacy

Probolos can reconstruct what a quarantined device typed. That capability is
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

There is therefore no configuration in which Probolos records a device that
somebody has approved and is using. If you find one, that is a security bug and
should be reported as one.

Operators in the EU should note that capturing input from a device attached to
a corporate machine may still engage GDPR obligations even under these
constraints, and that `--capture-payload` should be enabled deliberately.

## State files: trust, ledger, and who may write them

The trust store decides whether a device is admitted **without asking**, so
whoever can write it can admit hardware. Under `--privsep` the analyzer runs as
`nobody` — a *shared* account — and that shapes the whole design here.

**The two stores are deliberately separated.** Directory write permission is
stronger than it looks: it allows unlinking and replacing any file in that
directory regardless of the file's own owner. So while the ledger and the trust
store shared one directory, handing it to `nobody` handed over trust as well.
The ledger now lives in `/var/lib/probolos/state/`, which is the only directory
given to the analyzer; `/var/lib/probolos/` itself stays root-owned and holds
`trusted.json`. The analyzer reads trust and can neither rewrite nor replace it.

**Writes never follow a symlink.** State files are written with
`O_NOFOLLOW | O_CREAT | O_EXCL` and renamed into place. Previously a `nobody`
process could pre-plant `trusted.tmp` as a symlink to, say, a file under
`/etc/cron.d`, and the next root-run save (`sudo … --forget N`) would write the
store's JSON through it. Stores are created mode `0600`.

**The launcher refuses to chown anything outside a fixed allowlist.**
`--ledger /etc/x.json` would otherwise make `/etc` owned by an unprivileged
account at mode `0700`, taking sudo, ssh and PAM with it on a running system.
That needs no attacker; a typo is enough. Allowed ledger directories are
`/var/lib/probolos/state` and `/run/probolos/state`, including descendants.
The allowlist is lexical and every directory component is opened with
`O_NOFOLLOW`; resolving an allowlisted symlink must not redefine the allowlist.
Files must be regular and have one link. Ownership and mode changes use pinned
file descriptors. Agent directory preparation is limited to `/run/probolos`.
A root-run agent listener requires trusted ancestor directories and keeps its
directory root-owned, so a desktop user cannot replace a socket with a symlink
before a privileged chmod/chown on restart.

**Trust entries are validated on load,** with the same discipline the ledger
already used — the security-critical store was previously the unvalidated one.
An entry whose fields are the wrong type, whose fingerprint is empty, or whose
key disagrees with the name it is filed under is ignored and counted, not
trusted. State readers reject non-object JSON, invalid encodings, non-finite
timestamps, special files and inputs over 8 MiB. Reload clears previous entries
before parsing. Trust checks apply to the opened inode and its directory chain.

## Device strings are treated as hostile input

A device chooses its own manufacturer, product and serial strings, and those
strings reach the terminal, the approval dialog, the JSON log, the trust store
and the ledger. They are sanitised at the single point where sysfs bytes become
Python strings, not at each display site — a `cat probolos.jsonl` three days
later would otherwise replay an escape-sequence attack in a terminal nobody was
guarding.

Control characters and bidi overrides are made visible rather than executed, so
a device cannot scroll the report and overwrite the CRITICAL line the operator
is reading. *Why* a string had to be cleaned is recorded and becomes a finding
in its own right: `crafted-strings` (WARNING), escalating to `crafted-strings-hid`
(CRITICAL) when a device that can type also disguises its own name — two things
no honest keyboard does.

Markup is escaped separately, in the dialog backends only. `kdialog` renders Qt
rich text and `zenity` renders Pango, so an `iProduct` of
`<a href="…">Kingston</a>` would otherwise draw a live link, or a reassuring
verdict this tool never wrote, next to the Allow button. The terminal and
tkinter backends deliberately do **not** escape: `<` and `&` are ordinary
characters there, and a legitimate name like `A<B & C>D` must display as typed.

## Storage read deadlines and remaining limits

Stage 4 reads the raw medium, and a device can stall a read indefinitely —
ordinary for failing USB, deliberate for a hostile one. Unbounded, that freeze
would trip the watchdog, and the watchdog's job is to reopen the gate: a stall
in the security scan would become a system-wide fail-open.

The read therefore runs in a child process under a hard time limit and is
killed if it overruns, while the watchdog is paused for the duration. Both are
required. A timeout alone leaves the watchdog counting legitimate work as a
stall; pausing alone converts the fail-open into a permanent freeze. A device
that will not let itself be inspected produces a finding — the silence is the
result. This deadline covers the worker read/parse phase. Device authorization,
opening a gate-provided block descriptor, and deauthorization occur outside that
worker; a kernel operation stuck in uninterruptible sleep cannot be bounded or
reliably killed by Python. The watchdog is not proof against every USB stall.

Stage 4 must briefly authorize the device for its block node to appear, and
udisks2 may automount the medium in that window. The window is kept as short as
the kernel allows and the device is re-blocked the instant the read returns, but
the race is real. A udisks-specific inhibitor can suppress udisks automounting,
but not every other program capable of mounting a device. Holding the storage
interface at 0 also prevents the block node needed by the current scanner; it
is not a drop-in fix. The inhibitor file referenced in the original README was
not present in the supplied ZIP; it was not reconstructed as part of this audit.

## Lockout safety

A tool that can leave someone without a keyboard does not get installed. Five
independent layers:

| Layer | Covers |
|---|---|
| Protected devices | internal (`removable=fixed`) ports are never gated |
| Port allowlist | `--allow-port` keeps a rescue port always open |
| Watchdog | daemon alive but stuck; reopens the gate |
| Panic file | `sudo touch /run/probolos.panic` from another TTY or over SSH |
| Privilege separation | analyzer compromise cannot escalate to root |

Plus the gate's own restore paths (context manager, signal handlers, `atexit`)
which cover a daemon that dies, and `--release` for manual recovery.

Cleanup is best effort. The root gate now restores state if its analyzer
disconnects, including after an analyzer crash. Killing the root gate too,
kernel failures, or failed sysfs writes still require manual recovery:

```bash
echo 1 | sudo tee /sys/bus/usb/devices/usb1/authorized_default
```

The panic file must be **root-owned, in a root-owned directory**, and is checked
with `lstat` so a symlink or hardlink planted at that path is refused. An off
switch any local account could throw is not an off switch; it is a way to
disable the tool. It lives in `/run` (tmpfs) so a forgotten one cannot survive a
reboot.

## Controller hotplug and deployment

Only root hubs discovered when the gate starts are closed by the current
implementation. New host controllers/root hubs require separate boot/udev
policy; do not assume their first devices are blocked by this daemon. The
supplied systemd unit was corrected to allow AF_NETLINK and to remain in the
host network namespace for udev events. Live systemd/USB validation remains
necessary; a static unit edit is not an integration test.

Kernel authorization semantics: https://docs.kernel.org/usb/authorization.html
