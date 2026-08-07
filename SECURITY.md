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

**Privilege separation exists (`--privsep`), but is not yet the default.**
With `--privsep`, a small root gate (`gate_server.py`, the only privileged
code) does nothing but write `authorized`/`authorized_default` and open input
nodes read-only, passing the file descriptors to an unprivileged analyzer over
`SCM_RIGHTS`. The analyzer — all rules, timing, ledger, payload work — runs as
`nobody` and can regain no privilege; the drop is verified, including that
`setuid(0)` fails afterwards. A bug in any analyzer is then a bug in an
unprivileged process, not a root compromise.

What this does and does not buy: it bounds the blast radius of a compromised
analyzer to the analyzer's own (minimal) privileges. It does NOT stop the
analyzer from reading keystrokes it is entitled to read during quarantine —
that is bounded instead by the "never on an authorized device" invariant.

**That invariant is now enforced by the gate, not asserted by the analyzer.**
It used to live on the untrusted side, which meant a compromised analyzer could
simply ignore it: the gate would open any `/dev/input/event*` (including the
built-in keyboard), read any `/dev/sd*` (including the system disk), and
authorize any USB device. The gate now derives scope from the kernel — it acts
only on a device whose `authorized` flag reads 0, and on input or block nodes
whose USB parent is such a device. A PS/2 keyboard has no USB parent and can
never be in scope; a disk that is not USB-attached is refused; a device you are
using reads authorized=1 and cannot be disturbed. Because the check reads the
kernel rather than the request, a compromised analyzer cannot widen its own
scope by lying.

Without `--privsep` the daemon still runs entirely as root, which is why the
flag is recommended in the README and will become the default once it has more
real-world testing.

**Observation requires briefly authorizing the device.** During the observation
window the device is live, with its input captured. It is returned to
`authorized=0` the instant observation ends, before the human is asked, so
there is no window in which it is both live and unwatched. A composite device's
non-input functions (storage, network) are nonetheless live for the duration of
the window, which is a real exposure and the reason the window is short and
configurable (`--observe`, `0` disables it).

**The quarantine has a race.** Between `authorized=1` and the `EVIOCGRAB`
completing, keystrokes can reach the session. The window is measured and
printed in every report. Measured on real hardware it is 41–85 ms, not the
10–20 ms this document previously estimated; the figure is printed per device
precisely because it is not a constant. It is eliminated, not merely
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

## State files: trust, ledger, and who may write them

The trust store decides whether a device is admitted **without asking**, so
whoever can write it can admit hardware. Under `--privsep` the analyzer runs as
`nobody` — a *shared* account — and that shapes the whole design here.

**The two stores are deliberately separated.** Directory write permission is
stronger than it looks: it allows unlinking and replacing any file in that
directory regardless of the file's own owner. So while the ledger and the trust
store shared one directory, handing it to `nobody` handed over trust as well.
The ledger now lives in `/var/lib/cerberus/state/`, which is the only directory
given to the analyzer; `/var/lib/cerberus/` itself stays root-owned and holds
`trusted.json`. The analyzer reads trust and can neither rewrite nor replace it.

**Writes never follow a symlink.** State files are written with
`O_NOFOLLOW | O_CREAT | O_EXCL` and renamed into place. Previously a `nobody`
process could pre-plant `trusted.tmp` as a symlink to, say, a file under
`/etc/cron.d`, and the next root-run save (`sudo … --forget N`) would write the
store's JSON through it. Stores are created mode `0600`.

**The launcher refuses to chown anything outside a fixed allowlist.**
`--ledger /etc/x.json` would otherwise make `/etc` owned by an unprivileged
account at mode `0700`, taking sudo, ssh and PAM with it on a running system.
That needs no attacker; a typo is enough. Paths are resolved with `realpath`
first, so `../` cannot smuggle a path back out, and a sibling such as
`/var/lib/cerberus-evil` does not match on prefix alone.

**Trust entries are validated on load,** with the same discipline the ledger
already used — the security-critical store was previously the unvalidated one.
An entry whose fields are the wrong type, whose fingerprint is empty, or whose
key disagrees with the name it is filed under is ignored and counted, not
trusted.

## Device strings are treated as hostile input

A device chooses its own manufacturer, product and serial strings, and those
strings reach the terminal, the approval dialog, the JSON log, the trust store
and the ledger. They are sanitised at the single point where sysfs bytes become
Python strings, not at each display site — a `cat cerberus.jsonl` three days
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

## Storage inspection cannot wedge the daemon

Stage 4 reads the raw medium, and a device can stall a read indefinitely —
ordinary for failing USB, deliberate for a hostile one. Unbounded, that freeze
would trip the watchdog, and the watchdog's job is to reopen the gate: a stall
in the security scan would become a system-wide fail-open.

The read therefore runs in a child process under a hard time limit and is
killed if it overruns, while the watchdog is paused for the duration. Both are
required. A timeout alone leaves the watchdog counting legitimate work as a
stall; pausing alone converts the fail-open into a permanent freeze. A device
that will not let itself be inspected produces a finding — the silence is the
result.

Stage 4 must briefly authorize the device for its block node to appear, and
udisks2 may automount the medium in that window. The window is kept as short as
the kernel allows and the device is re-blocked the instant the read returns, but
the race is real; ship `systemd/60-cerberus-inhibit-automount.rules` to close
it. The structural fix is interface-level authorization — authorize the device
while holding the mass-storage interface at 0, so no block node is ever created
— and that work is not finished.

## Lockout safety

A tool that can leave someone without a keyboard does not get installed. Five
independent layers:

| Layer | Covers |
|---|---|
| Protected devices | internal (`removable=fixed`) ports are never gated |
| Port allowlist | `--allow-port` keeps a rescue port always open |
| Watchdog | daemon alive but stuck; reopens the gate |
| Panic file | `sudo touch /run/cerberus.panic` from another TTY or over SSH |
| Privilege separation | analyzer compromise cannot escalate to root |

Plus the gate's own restore paths (context manager, signal handlers, `atexit`)
which cover a daemon that dies, and `--release` for manual recovery.

Only `SIGKILL` combined with a full lockout defeats all of these, and the manual
recovery is one line:

```bash
echo 1 | sudo tee /sys/bus/usb/devices/usb1/authorized_default
```

The panic file must be **root-owned, in a root-owned directory**, and is checked
with `lstat` so a symlink or hardlink planted at that path is refused. An off
switch any local account could throw is not an off switch; it is a way to
disable the tool. It lives in `/run` (tmpfs) so a forgotten one cannot survive a
reboot.
