# Changelog

Notable changes to Probolos. Versions follow PEP 440 (`1.0.0b1` < `1.0.0rc1` <
`1.0.0`). Every defect found since the 0.11.0 freeze, and how it was found, is
in [docs/QA-LOG.md](docs/QA-LOG.md).

## Unreleased

### Added

- **`--history` shows what each device is:** a TYPE column (`mouse`,
  `storage+keyboard`, `camera+network+vendor`) built from the interface
  classes, never from the device's own name. `-v` adds the type and a
  `! type changed` line when a device has claimed more than one, aligned and
  wrapped to 80 columns.

### Security

- **A storage reader could reopen the gate.** The forked process that reads a
  medium inherited the armed gate and its signal handlers; killed with
  `SIGTERM` after a stall, it set `authorized_default=1` on every root hub
  while the daemon believed the gate closed. Only the process that closed the
  gate may reopen it now, and the reader drops the inherited handlers.
- **Nothing the analyzer starts outlives it** (ROADMAP 1.12). The root side is
  a child subreaper: on a run from a terminal, a process a compromised
  analyzer forked kept that terminal after the gate stopped, and one holding
  the analyzer's socket kept the gate serving it after the analyzer had
  exited. The analyzer's exit now ends the gate, and everything it left
  behind is killed and reaped; an analyzer still running after it closed its
  socket is killed after 10 s.
- **The agent socket cannot be replaced by the analyzer's account**
  (ROADMAP 1.13). Under `--privsep` root binds it before the privilege drop, in
  a directory root owns, and the analyzer inherits the listener. A hand run as
  `nobody` let any other `nobody` process listen in its place.
- **A refusal can no longer be washed out of a device's history.** The last 20
  decisions were kept, so twenty unanswered plug-ins removed the refusal and
  the `previously-rejected` countdown with it. A refusal is kept at the front.

### Fixed

- **Lockout: the rescue port works at the lock screen.** Internal ports and
  `--allow-port` were held while the screen was locked, so a USB keyboard on
  the rescue port could not type the password. They are admitted before the
  lock is checked, and one found blocked at a locked start is admitted at once.
- **Desktop prompt timeouts:** the analyzer stopped listening after
  `--timeout` as given while the dialog stayed up at least 10 s, so under
  `--timeout 5` an answer could be lost, and a CRITICAL device under about
  12 s could not be approved at all. The question now lasts as long as the
  dialog, and a CRITICAL one at least 10 s past its countdown.
- **`--lock-policy deny`** asks about devices found blocked at a locked start
  when the screen unlocks; with no desktop prompt they were never asked about.
- **`--agent` with a socket that could not be opened** holds devices that no
  terminal can answer; under the service they were denied as unanswered.
- **zenity without a display:** GTK's exit when it cannot open or loses the
  display was read as "Keep blocked" and recorded as a refusal; it is "no
  answer" now.
- **Card readers (`--watch-media`):**
  - a card the reader cannot read (0 bytes after a media change) is re-checked
    for 15 s and reported as `UNREADABLE CARD`; it used to be dropped silently;
  - a card that raises a CRITICAL never becomes the slot's reference layout;
  - the plug-in prompt applies the card rules, and the card approved there is
    not judged again (under `deauthorize` it used to switch the reader off
    seconds after approval); the approval lasts 30 s from the reader's first
    disk event, then until the card is taken out;
  - a card the reader announces again (same layout and findings, no removal,
    screen unlocked) gets one line instead of a full report; a failed
    switch-off is retried; disk events left over from stage 4 are ignored;
  - an ordinary unplug no longer reads as a replaced reader;
  - `UDISKS_AUTO=0` is no longer reported as "inhibited", since KDE Plasma
    ignores it; the README's udev rule uses `UDISKS_IGNORE=1`. Under
    `--media-policy log` a CRITICAL report says the card is not blocked;
  - "first card seen in this slot" follows the history, not the current run,
    and slots that cannot report media changes are flagged at once.
- **Devices left switched off at exit** (refused, switched off by the media
  policy, or with their question cut short) are listed, with how to switch
  them back on.
- **`--history`:** every recorded reason has its own word (`READER OFF`,
  `HELD`, `NO ANSWER`, `FAILED`, `DENIED`); an allow-listed device no longer
  reads as AUTHORIZED, and a screen-lock denial is not counted as a refusal.
  Serials show their distinguishing end (`…000001532`, not `00000000`).
- **Isohybrid images** (ISO 9660 at sector 0 behind an MBR, as `dd` writes
  installers) are reported as such. That explains a large gap before the first
  partition only when the ISO volume actually covers it, and a planted ISO
  signature behind an MBR raises the same notice as without one.

### Documentation

- README, SECURITY.md and CAPABILITIES.md rewritten shorter and plainer; the
  details moved to the new `docs/TECHNICAL-REFERENCE.md`. The other documents
  are shorter too.
- Statements that did not match the code are corrected: with `--timeout 0` a
  desktop dialog still closes after 60 s; the unit's placeholder agent user
  makes devices refused, not held; closing a dialog window counts as "Keep
  blocked"; the panic file works only while the watchdog runs;
  `network-with-keyboard` needs a declared keyboard.
- SECURITY.md lists a newly found weakness: while the screen is locked, the
  internal-port and `--allow-port` exemptions do not apply.

## [1.0.0b1] — 2026-10-09 · first beta

The features of 0.13.0, released a new way.

- **On PyPI.** `release.yml` uploads each tag by trusted publishing (no stored
  token): to TestPyPI at once, to PyPI once the maintainer approves. Only the
  files the build hashed and attested go up, each with a PEP 740 attestation.
  The one-time setup is in `docs/GITHUB-SETUP.md`.
- Package metadata says Beta. The README's links are absolute, since it is
  also the PyPI page, and a test checks them.
- Deep property run on the 1.0.0b1 tree: clean.
- Still open: the analyzer's descendants can outlive the gate on a terminal
  run (ROADMAP 1.12); a run by hand without `--privsep-user probolos` uses the
  shared `nobody` account (1.11, 1.13).

## [0.13.0] — 2026-10-05 · the analyzer's own account

- **Security:** the service's analyzer runs as its own `probolos` system
  account (`systemd/probolos.sysusers`, created by `install.sh`) instead of the
  shared `nobody`, which any other `nobody` process could use to kill it
  (reopening the gate) or to take over the agent socket. Keeping the hubs
  closed when the analyzer is killed was considered and rejected.
- The unit's placeholder agent user is `probolos`, which the gate refuses as
  a desktop account, so an unconfigured unit runs with the prompt off instead
  of handing it to every `nobody` process.
- Tests for the account, the sysusers file and `install.sh`.

## [0.12.0] — 2026-10-05 · Phase 1 hardening

Fixes from the security audit of 2026-10-04, each with a regression test that
fails on 0.11.0.

### Security

- The tkinter fallback's "No" meant "Always allow"; it now asks two separate
  questions.
- Stages 3 and 4 switch on the inspected device instance, never a device that
  re-enumerated in its place.
- Device strings decode as UTF-8 under every locale (a non-UTF-8 locale could
  crash the start and reopen the gate).
- The `--privsep` analyzer no longer inherits the one-gate lock, and trusts
  only a root-owned trust store.
- `install.sh` copies regular files only and runs Python isolated (`-I`).
- `release.yml` releases only commits on `main`, after the checks, with
  PEP 440 versions.

### Fixed

- A watchdog stall exits with a failure status, so systemd restarts the
  service.
- `--release` refuses while a gate runs, reports failed writes, and reopens the
  hubs even when nothing is blocked.
- One command per run, and `--dry-run` changes nothing.
- "Always" is not offered over a trust store that failed to load, and a second
  failed save says so.
- A countdown window that crashed is no decision; the agent survives deeply
  nested JSON; `--history` on an unreadable ledger says so; several
  `install.sh` edge cases.
- The CRITICAL "still blocked" notice is true and is sent; the `overpowered`
  testbed preset builds; `modprobe -a` for the testbed modules.

### QA, documentation, licensing, release

- Tests for the privilege boundary's refusal paths (coverage 80% → 95%),
  mypy on the root-side modules, a test that every rule is documented and that
  every testbed preset works, and `docs/QA-LOG.md`. A structure audit; all of
  its findings fixed.
- SECURITY.md covers the gate-side trust write, holding, the text cut, dialog
  exit codes and the open weaknesses.
- The license is stated as GPL-3.0-or-later (SPDX metadata; `LICENSE` in the
  wheel; building needs setuptools 77+).
- `release.yml` drafts a release with the sdist, wheel, `SHA256SUMS` and a
  provenance attestation; the wheel is reproducible. The sdist carries the
  tests, testbed, systemd files and docs. `CITATION.cff` added.

## [0.11.0] — 2026-10-03 · feature freeze

The feature set of 1.0 (`CAPABILITIES.md` §1). From here on, only fixes,
tests, documentation and release work.

### Added

- **"Always allow" under `--privsep`**, written by the root gate on terms it
  checks itself (`REQ_TRUST`).
- **Devices are held, not refused, when nobody can be asked** (the service
  with no desktop agent), with a cap of three lost questions.
- "Still blocked, replug it" notices; an unanswered question is recorded as
  "no answer".
- CI: tests as root, ShellCheck, systemd unit checks, actionlint and zizmor,
  Arch Linux, coverage; pinned actions and Dependabot. ruff with bugbear and
  bandit rules, Hypothesis property tests.
- `ROADMAP.md`, private vulnerability reporting, issue templates.

### Fixed

- A dialog that died is no decision; it used to count as a refusal.
- A replayed udev "add" for a held device is ignored.
- Holding a device again writes nothing new to the history.
- The trust store fails closed when its directory cannot be read, and a store
  the gate creates is readable by the analyzer.
- The `textsafe` cut could drop an escape and show its neighbour (found by the
  property tests).

## [0.10.0] — 2026-10-01 · prompts, service install, card readers

### Added

- **Prompts that match the risk:** one dialog, two dialogs, or a 10 s
  countdown, which makes CRITICAL devices approvable from the desktop. A
  refused device that returns is CRITICAL.
- **`sudo ./install.sh`** sets up the service in one step.
- `--remove-trusted N|PATTERN|all` (replaces `--forget`) and `--remove-all`.
- **`--watch-media` and `--media-policy`:** detection for cards in admitted
  readers, also under `--privsep`; GPT entry types are read for its rules.

### Security

- A keyboard could answer the terminal prompt about itself; the prompt now
  flushes pending input.
- The `--privsep` analyzer could type into the shell that started it
  (`TIOCSTI`); it no longer has a controlling terminal.
- gdbus, zenity and kdialog decoded escapes in device strings back into
  markup; the strings are now quoted for each.
- Without `--privsep`, any device node was opened as handed over; nodes are now
  validated as the gate does.
- The agent socket's directory was group-writable (now `2750`) and its mode was
  set through a path; interfaces turned off through the gate are restored; the
  privilege drop verifies supplementary groups.
- Every stage 4 failure is reported the same way, raw details in the log only.

### Fixed

- A crashed tkinter dialog could answer for the user; unanswered prompts were
  recorded as refusals; two gates could run at once (now an instance lock);
  "always" was offered where it could not be kept; the service crash-looped
  with the gate open; revoked trust did not reach a running daemon; the
  journal stayed empty until exit.
- Bad `--rules` files and invalid durations are rejected cleanly; a missing
  `pyudev` is reported before the gate closes; startup signals are handled
  under `--privsep`.
- The agent's receive buffer is bounded and a malformed message cannot stop
  it; ordinary webcams no longer exceed the descriptor limit.
- Stage 4 recognises `dd`-written live images (ISO 9660, UDF, btrfs without a
  partition table), no longer refuses healthy whole disks, and needs a valid
  structure for ISO 9660 and UDF (new `filesystem-signature-without-structure`).

### Tests

- The suite is organised by module, runs on Python 3.10 to 3.14, and is clean
  under ruff.

## [0.9.0] — the audit

An external review found four critical defects and a dozen smaller ones,
mostly correct code that was never wired in. All fixed, each with a regression
test (282 → 328 tests).

- A storage+keyboard device was live and ungrabbed for seconds during stage 4;
  the stages were reordered and such devices are no longer inspected.
- The agent socket's peer check was dead code, so anything that could open the
  socket could answer.
- State writes followed symlinks; they are now `O_NOFOLLOW` atomic writes.
- The root gate checked the kind of path, not that it belonged to the device
  in quarantine; its scope now comes from the kernel.
- Also fixed: `--list` closed the gate; no dialog backend silently denied
  everything; `--agent` without `--privsep` never worked; `nobody` could write
  trust entries (the ledger moved to `/var/lib/probolos/state/`); `--ledger`
  could hand `/etc` to `nobody`; a stalled storage read reopened the gate;
  device strings were not sanitised; trust entries were not validated.
- Added: the `crafted-strings` rules, markup escaping in dialogs, the
  automount-inhibit udev rule, `atomicio.py`.
- The panic file is `/run/probolos.panic` and must be root-owned.

## [0.8.1] — three choices, and a service

- The desktop prompt offers once / always / cancel, like the terminal.
- systemd units: a sandboxed system service for the gate, a user service for
  the agent.
- Dialogs instead of notification actions, which desktops do not reliably
  support.

## [0.8.0] — approving from the desktop

- The desktop agent (`python -m probolos.agent`, `--test` to check it) and
  `--agent`, `--agent-socket`, `--agent-user`.

## [0.7.2] — the deferred question

- A remembered device held behind a locked screen was admitted silently on
  unlock; it is now always asked about.

## [0.7.1] — found in use

- A device held when Probolos exited was stranded and later taken as baseline;
  it is now queued at startup, and the exit lists devices left blocked.

## [0.7.0] — usable every day

- Remembered devices ("always"), pinned by identity and descriptors, never
  over a CRITICAL finding.
- Stage 4: read-only partition and filesystem inspection, never mounted.
- Screen-lock policy: nothing is admitted while locked; held devices are asked
  about on unlock.

## [0.6.0] — privilege separation

- `--privsep`: a root gate and an unprivileged analyzer, passing open file
  descriptors over `SCM_RIGHTS`.
- Five defects found on real hardware: quarantine never matched real input
  nodes; the device stayed live between observation and decision; a crashed
  run left the gate closed for good; Ctrl-C killed the gate before the
  analyzer; valid device paths were refused.
- No more `python-evdev`; the measured exposure gap is 41–85 ms.

## [0.5.2] — testbed

- Software USB emulation (`dummy_hcd` + `raw_gadget`) with attack and control
  presets.

## [0.5.0] — power

- `bMaxPower` units fixed (8 mA on SuperSpeed); power-consistency rules.

## [0.4.0] — analyzers, ledger, payload, safety

- Analyzer plugins, the descriptor ledger with drift detection,
  `--capture-payload`, and lockout safety (protected ports, watchdog, panic
  file).

## [0.3.0] — behavioural quarantine

- Stage 3: switch input devices on under `EVIOCGRAB` and judge what arrives.

## [0.2.0] — semantic rules

- Stage 2 consistency rules, checked against real hardware for false
  positives.

## [0.1.0] — the gate

- The authorization gate with guaranteed restore, the udev loop, the
  descriptor parser, the report, the prompt and a JSON audit log.
