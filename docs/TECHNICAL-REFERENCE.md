# Technical reference

The details behind [README.md](../README.md), [SECURITY.md](../SECURITY.md)
and [CAPABILITIES.md](../CAPABILITIES.md): how the privileged parts are
bounded, where state lives, and the exact behaviour of the stages and the card
watcher. You do not need any of it to use Probolos.

Contents: [privilege separation](#privilege-separation) ·
["always" under `--privsep`](#always-under---privsep-req_trust) ·
[state files](#state-files) · [agent socket](#the-agent-socket) ·
[holding and answers](#holding-and-answers-that-are-not-decisions) ·
[device text](#device-text-is-hostile-input) · [stage 3](#stage-3-details) ·
[stage 4](#stage-4-details) · [card watcher](#card-watcher-details) ·
[lockout](#lockout-safety-details) · [tests](#the-test-suite)

---

## Privilege separation

With `--privsep` a root **gate** (`gate_server.py`) and an unprivileged
**analyzer** (rules, quarantine, history, prompts) are separate processes. They
talk over a private `SEQPACKET` socketpair made before `fork()`; the gate
passes open file descriptors with `SCM_RIGHTS`. The trusted code is the gate
plus startup preparation, the protocol (`protocol.py`) and cleanup: well over
a thousand lines, not a tiny kernel.

**What the gate does:** writes `authorized` and `authorized_default`,
authorizes or deauthorizes interfaces, opens `/dev/input/eventN` and whole
`/dev/sdX` nodes read-only, and writes trust entries (next section).

**Scope comes from the kernel, not from the request:**

- It acts only on a USB device that reads `authorized=0`, or on one it
  switched on itself for inspection (its nodes may be opened for 30 s after
  that; re-blocking ends it), and only on the kernel directory instance the
  checks read. A device that re-enumerated at the same port is a different
  instance and is refused.
- Input and block nodes must belong to such a device (the USB ancestor,
  interface nodes skipped). Devices present at start, non-USB disks and PS/2
  keyboards are never in scope.
- Final admission leaves the analyzer no further read or deauthorization
  permission. An interface cannot be passed where a whole device is expected.
- Node checks, in both modes (`--privsep` and plain root): only
  `/dev/input/eventN` or a whole `/dev/sdX`; it must be the right kind of
  special file; it is opened `O_NOFOLLOW`. "Whole disk" is decided from
  `/sys/dev/block` (no `partition` attribute, matching kernel name), not from
  the node's name.

**The privilege drop is verified:** supplementary groups are dropped and
checked (a surviving `input` or `disk` group would bypass the gate entirely),
then the gid and uid, and `setuid(0)` must fail afterwards. The analyzer calls
`setsid()` first, so it has no controlling terminal to inject keystrokes into.
It does not inherit the one-gate lock.

**When the analyzer goes away** the gate restores interfaces it turned off,
re-blocks devices it switched on for inspection, and reopens the root hubs.
Nothing is restored on a path whose kernel instance has changed (a recycled
port). Devices you allowed stay on.

**Why a killed analyzer reopens the gate.** Keeping the hubs closed when the
analyzer is killed was considered and not done. The analyzer's own `SIGTERM`
handler reopens the hubs and exits 0, so a `SIGTERM` from another process with
its uid looks exactly like `systemctl stop`; and for the signals that can be
told apart, it would trade a gate left open for dead ports, which ROADMAP §4
ranks the same (P0); the OOM killer would lock a USB-keyboard machine out. The
fix taken instead: the service runs the analyzer as its own `probolos` account,
which nothing else runs as (`systemd/probolos.sysusers`).

**`--watch-media` widens the gate, only when asked.** The flag reaches the gate
from the root side of the fork. The gate then records storage-only devices it
admitted and those live at its start (card readers, sticks and USB disks
alike), and allows them whole-disk read-only opens and a switch **off** (never
on), while the instance is unchanged and every interface is still mass
storage. Cost: a compromised analyzer can read those disks and cards, and
switch the devices off.

## "Always" under `--privsep` (`REQ_TRUST`)

The trust store admits devices without asking, so under `--privsep` only the
gate writes it, and only on terms it can check itself:

- **Only the gate can write.** The request travels on the private socketpair,
  which no other process can reach. Which file is written comes from the root
  side's command line, never from the socket.
- **Only a device it admitted.** The gate records each final admission. A
  trust request must name that device's instance within 60 s
  (`TRUST_WINDOW`), and the record is spent by the first request that names
  it, whether it succeeds or not. The device must still be the same instance
  and still be authorized.
- **Only a fingerprint it measured.** Just before it first writes
  `authorized=1` for an instance, the gate hashes the descriptors and reads the
  vendor, product and serial through a pinned directory descriptor, and
  computes the key with the same `trust.key_for` the analyzer uses. The
  analyzer's key must match it exactly. The label is the only value taken from
  the request, and it is sanitised.
- **Persistence is all a compromised analyzer gains**, for devices it could
  admit anyway. The gate refuses to rewrite a store that fails its integrity
  checks and caps it at 1024 entries (`MAX_TRUSTED`). A CRITICAL device is
  never offered "always".

## State files

| Path | What | Owner and mode |
|---|---|---|
| `/var/lib/probolos/trusted.json` | remembered devices | root; `0600`, or `0644` under `--privsep` so the analyzer can read it |
| `/var/lib/probolos/state/ledger.json` | device history | the analyzer's account under `--privsep`; `0600` |
| `/var/lib/probolos/instance.lock` | one gate at a time | root |
| `/run/probolos/agent.sock` | desktop prompt socket | see below |
| `/run/probolos.panic` | panic switch | must be created by root |

Run by hand without root, the history defaults to the XDG state directory.

- **Trust and history are in different directories on purpose.** Write access
  to a directory lets you replace any file in it, whatever the file's own
  owner. Only `state/` is handed to the analyzer; `/var/lib/probolos/` stays
  root-owned, and the launcher refuses to hand over a directory that holds a
  trust store.
- **Writes never follow a symlink:** files are created
  `O_NOFOLLOW | O_CREAT | O_EXCL` and renamed into place. A rewrite keeps the
  read bits the file already has.
- **The launcher hands over only allowlisted directories**
  (`/var/lib/probolos/state`, `/run/probolos/state` and below). The check is
  lexical, every component is opened `O_NOFOLLOW`, files must be regular with
  one link, and ownership changes use pinned descriptors. Without it,
  `--ledger /etc/x.json` would have given `/etc` to `nobody`.
- **Everything is validated on load.** Trust entries with wrong types, an
  empty fingerprint or a key that disagrees with their name are ignored and
  counted. Non-object JSON, bad encodings, non-finite timestamps, special files
  and files over 8 MiB are rejected. The trust checks apply to the opened file
  and its directory chain; a store that fails them trusts nothing.
- The trust store is re-read whenever it changes, so `--remove-trusted`
  reaches a running daemon. The history is not; `--remove-all` refuses while a
  daemon runs.

**Fingerprints.** The history's drift check compares a normalized SHA-256
over the parsed descriptors: vendor and product IDs, `bcdDevice`, the device
class triple, and for every configuration and interface the counts and the
class/subclass/protocol triple. It leaves out `bcdUSB`, `bMaxPacketSize0`,
`bMaxPower`, endpoint and SuperSpeed companion descriptors, which change when a
device moves between a USB 2 and a USB 3 port. The raw-bytes hash is stored
beside it (`raw_hash`, shown by `--history -v`) for forensics.
`descriptor-drift` compares against the first readable fingerprint recorded for
the identity, or the one most recently approved. The trust store is stricter:
its key is the identity plus a SHA-256 of the **raw** descriptor bytes
(`trust.key_for`), so a remembered device that moves between a USB 2 and a
USB 3 port no longer matches and is asked about again.

## The agent socket

`/run/probolos/` is mode `2750`: owned by the analyzer's account, group-owned
by the desktop user's group. The socket is `0660`, and the analyzer checks the
connecting uid with `SO_PEERCRED`. `connect()` needs write permission on the
socket, not on the directory, so the group has no write permission there:
otherwise any member could unlink the socket and listen in its place.

The directory's *owner* can still do that. While the owner was the shared
`nobody`, any `nobody` process could put its own listener there and show the
agent its own questions (answers to them admit nothing, but the real analyzer
loses its prompt and holds devices meanwhile). The service's `probolos`
account closes this; a hand run as `nobody` does not (ROADMAP 1.13).

The socket's mode is set relative to the held directory descriptor after
`lstat` confirms it is still the socket, and shutdown removes only a socket. A
process running as the desktop user can still occupy the prompt and never
answer; that times out into "no answer", the safe direction.

## Holding, and answers that are not decisions

A missing answer must never become an approval, and should not become a
refusal either: a recorded refusal makes the next plug CRITICAL
(`previously-rejected`).

- **No agent, device held.** The service has no terminal (stdin is
  `/dev/null`). With a desktop agent configured but not connected, a new
  device is held blocked before stages 3 and 4, and asked about when an agent
  connects. With no agent configured at all (the unit's placeholder agent
  user), nothing is held: the stages run and the terminal prompt reads
  end-of-file, so the device is refused as "no answer". Holding
  again records nothing new, so it cannot push a real refusal out of the
  bounded history.
- **Re-ask cap.** An agent that leaves mid-question holds the device again;
  each round may switch it on for inspection, so on the third lost question
  (`MAX_UNSEEN_ASKS`) it is refused as unanswered.
- **Replayed "add" events are ignored.** udev replays `add` for held devices
  (`udevadm trigger`, a settle, a rescan). Only a different kernel instance at
  the port replaces the queued entry, so a replay cannot ask twice or skip the
  forced question after an unlock.
- **Only the dialog's own answers count.** A button, or closing the window
  (which kdialog, zenity and Tk report as the "Keep blocked" button), is an
  answer. kdialog killed by a signal (Qt aborts when the display goes away),
  kdialog's own failures (254/255), zenity's error exit (255), a crashed Tk
  window and a timeout are "no answer". A question shown and not answered is
  recorded as such, not re-queued, and the agent shows a display-only "still
  blocked, replug it" notice (critical urgency for a CRITICAL device).
  Remaining gap: GTK exits 1 when it loses the display, which zenity reports
  like Cancel.
- **Dialog timeout.** A dialog closes after `--timeout` seconds, clamped to
  10–600 s, or after 60 s when `--timeout` is 0 (only the terminal can wait
  without limit). The device then stays blocked as "no answer".
- **The countdown is enforced by the daemon:** an approval that arrives within
  10 s of the question is refused, whatever sent it.
- **tkinter asks twice.** A Tk message box labels its buttons Yes/No/Cancel
  whatever the question, so it asks "Allow it?" (No keeps it blocked) and then
  "Remember this device?" (No, the default, allows it once).
- **The terminal prompt flushes pending input first** and says how many bytes
  it discarded, so keys a device typed during stage 3 cannot answer for you.

## Device text is hostile input

A device chooses its own manufacturer, product and serial strings, and they
reach the terminal, the dialogs, the JSON log, the trust store and the ledger.

- They are cleaned at one point, where sysfs bytes become Python strings
  (`textsafe.py`), not at each display, so a later `cat probolos.jsonl` cannot
  replay an escape-sequence attack either.
- Control characters, bidi overrides and invisible characters are shown
  escaped, and *why* a string was cleaned becomes a finding (`crafted-strings`,
  `crafted-strings-hid`, `invisible-string-characters`,
  `stacked-combining-marks`).
- A string over its length limit is cut as a prefix: nothing after the first
  token that does not fit is appended. Scanning continues past the cut, so a
  control character hidden behind harmless ones is still reported.
- Markup is escaped for kdialog (Qt rich text) and zenity (Pango) only, and
  backslashes are doubled because both decode escapes. The terminal and Tk show
  plain text, where `A<B & C>D` must display as typed. Notification arguments
  go to `gdbus` as quoted GVariant literals.

## Stage 3 details

- The device is switched on by instance; input nodes are grabbed as they
  appear, and late nodes are looked for during the whole window. A failed grab
  ends the observation. The device is re-blocked before any grab is released,
  also on exceptions.
- Event buffers are bounded. Timing uses the kernel's input-event timestamps,
  not the times Python read them.
- The "exposure gap" in the report is the delay from authorization to the
  first grab. On real hardware it measured 41–85 ms; it is not the true
  exposure and cannot prove that no key escaped.
- `--close-race-window` sets `/sys/bus/usb/drivers_autoprobe` to 0 so drivers
  do not bind on their own, and binds the device's drivers itself just before
  grabbing. The race between that bind and the grab remains. A `SIGKILL` or
  kernel failure can leave autoprobe off for the whole system.
- `--capture-payload` keeps key identities and rebuilds a DuckyScript-style
  transcript (US QWERTY, capped near 4096 characters; keys past the cap are
  counted). Without it a key press carries only a timestamp.

## Stage 4 details

- **Reading.** The first sectors of the whole disk: the MBR, or the GPT header
  and protective MBR. GPT entries are read only from the standard place (LBA 2,
  128-byte entries) for their type GUID and attributes, and only the card rules
  use them; the geometry rules judge the protective MBR. A medium with no
  partition table is read up to `0x10200` bytes, past the ISO 9660/UDF
  descriptors at sector 16.
- **Filesystems.** A fixed set, not libblkid: NTFS, exFAT, FAT12/16/32,
  ext2/3/4, btrfs, ISO 9660, UDF. ISO 9660 counts only when the descriptor set,
  the primary volume descriptor's both-byte-order fields, the root directory
  record and the size check out; UDF needs the BEA01 → NSR → TEA01 sequence.
  The rest are magic-only. A signature with nothing behind it raises
  `filesystem-signature-without-structure`.
- **Isohybrid images.** An ISO 9660 volume at sector 0 behind an MBR is
  reported as what a desktop mounts. It explains a large gap before the first
  partition only if the volume actually reaches that partition; a tiny ISO
  does not explain away hidden space.
- **Failures** (switch-on refused, no block node, node never ready, unreadable
  or stalled read, removal mid-scan, re-block refused) all show as
  `not inspected: <reason>` from a fixed vocabulary, plus `storage-unreadable`.
  The raw error goes to the JSON log only (`medium.detail`).
- **Deadline.** The read runs in a forked child with a hard time limit while
  the watchdog is paused. Both are needed: a timeout alone counts the read as a
  stall, a pause alone turns a stall into a permanent freeze. The child resets
  the inherited signal handlers, and only the process that closed the gate may
  reopen it, so a killed child cannot open the gate. Kernel operations stuck in
  uninterruptible sleep cannot be bounded from Python.
- **Why it is only context.** A device decides when its block node appears: in
  testing, a replug fell back to identity-only at a 1 s poll and was read at
  3 s. A hostile device can force that fallback.
- **The automount window.** The device must be authorized for its block node
  to exist, so a desktop automounter can mount it meanwhile. `UDISKS_IGNORE=1`
  stops udisks only; holding the storage interface at 0 would also stop the
  block node the scan needs.

## Card watcher details

`mediawatch.py`, enabled by `--watch-media`.

- **Hosts.** Storage-only devices admitted by this run (prompt, trust, safety
  exemption) and storage-only devices present at start. A host is tied to its
  kernel instance: after an unplug it is dropped silently; a different device
  at the same path is dropped with a warning.
- **Events.** udev `block` `add`/`change`/`remove` for whole disks under a
  watched host. Disk events left over from stage 4 are ignored by their
  `SEQNUM` (the kernel's event counter is read just before admission).
- **Slots.** Surveyed when the host is registered; a slot settling to empty
  within 5 s of attach stays silent. Slots whose `events` lack `media_change`
  (nobody will report changes) are flagged at once. Latency follows the
  kernel's disk-event polling, typically 1–2 s.
- **Unreadable cards.** A media change that leaves the slot at 0 bytes is
  re-checked for 15 s. A capacity must be seen for 1.5 s before it is treated
  as the card (udev's own event usually arrives first, with its udisks hints);
  otherwise `UNREADABLE CARD` is printed.
- **Approval.** The layout shown at the plug-in prompt is accepted for 30 s
  from the reader's first disk event after admission, and stays accepted until
  that card is removed.
- **Reported once.** A media change with the same layout and the same findings
  as the card already in the slot, with no removal seen, prints one line and
  writes a `re-announced` audit entry, unless the screen is locked or a
  `deauthorize` switch-off is still due (a failed switch-off is retried). A
  swap faster than the reader reports the slot empty, to a card with the same
  layout and findings, cannot be told apart.
- **Reference layout.** The ledger's `media` section is keyed on the reader's
  identity plus the SCSI LUN. The first card recorded in a slot is its
  reference for `media-layout-drift`; a card that raised a CRITICAL is never
  recorded.
- **Automount report.** "inhibited" means udev set `UDISKS_IGNORE=1`;
  "hinted" means only `UDISKS_AUTO=0` (KDE Plasma ignores it); "already
  mounted" means the report is after the fact. Under `--media-policy log` a
  CRITICAL report says the card is not blocked.

## Lockout safety details

- **Restore paths:** the context manager, handlers for `SIGTERM`, `SIGINT` and
  `SIGHUP`, and `atexit`. Only `SIGKILL` and a kernel panic defeat them, hence
  the manual one-liner in the README.
- **Startup:** an `authorized_default` already at 0 (a crashed run) is not
  taken as the original value; 1 is restored. A device found at
  `authorized=0` is queued for a decision rather than taken as baseline.
- **Watchdog:** if the daemon stops making progress for `--watchdog` seconds,
  it reopens the gate and exits with a failure status, so systemd restarts it.
- **One gate at a time:** a root-only lock (`instance.lock`); `--release`
  refuses while a gate holds it, and `--dry-run` never takes it.
- **Panic file:** must be root-owned, in a root-owned directory, and is
  checked with `lstat`, so a planted symlink or hardlink is refused. The
  watchdog thread is what checks for it, so `--watchdog 0` disables it too.
- **The screen lock comes first.** The lock check runs before the exemptions
  for internal ports and `--allow-port`, so while the screen is locked a
  device on those ports is held (or denied) like any other: an open lockout
  risk for a machine whose only keyboard is USB.
- **Root hubs** that appear after start (a new controller) are not closed.

## The test suite

One file per area of the code; each file's docstring names the modules it
covers. Regression tests from security reviews are classes named after the
defect they pin (`AnalyzerHasNoControllingTerminal`, `TheDecoyFromTheReport`).
Shared builders are in `tests/_support.py`.

| File | Covers |
|---|---|
| `test_agent.py` | `agent`, `agentlink`, `dialogs` |
| `test_boundary.py` | refusal and error paths of `privsep`, `gate_client`, `gate_server` |
| `test_cli.py` | `__main__` |
| `test_daemon.py` | `daemon`, `session` |
| `test_descriptors.py` | `descriptors`, `descriptors_safe`, `usbclass` |
| `test_gate.py` | `gate`, `safety` |
| `test_interrogate.py` | `interrogate`, the offline half of the interrogation study |
| `test_ledger.py` | `ledger`, `history` |
| `test_privsep.py` | `privsep`, `gate_server`, `gate_client`, `protocol` |
| `test_properties.py` | property-based tests (Hypothesis) across modules |
| `test_quarantine.py` | `quarantine`, `payload`, `deferred_bind` |
| `test_rules.py` | `rules`, `analyzers`, `report` |
| `test_service.py` | `systemd/probolos.service`, `systemd/probolos.sysusers`, `install.sh` |
| `test_storage.py` | `storage`, `storage_hardening`, `mediawatch` |
| `test_sysfs.py` | `sysfs` |
| `test_testbed.py` | `testbed.spawn`, `testbed.emulate`: every preset does what `testbed/README.md` promises |
| `test_textsafe.py` | `textsafe` |
| `test_trust.py` | `trust`, `atomicio` |

`HYPOTHESIS_PROFILE=deep` runs the property tests at length (before each
beta). Coverage of the root-side code has a floor in
`.github/workflows/coverage.yml`.

Kernel documentation of USB authorization:
<https://docs.kernel.org/usb/authorization.html>
