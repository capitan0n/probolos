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

- **The panic file could leave no USB driver binding under
  `--close-race-window`.** The watchdog and the panic file reopened the hubs
  but not `drivers_autoprobe`, which that flag holds at 0 around one
  authorize write a hostile device can stall: new devices then enumerated
  with no driver, the rescue keyboard included. The gate's restore now puts
  the bus switch back first, under a lock shared with the code that set it.
- **Blank letters in device names went unreported.** The Hangul fillers and
  the default-ignorable combining marks (variation selectors and the like)
  are now escaped and reported like zero-width spaces. A trust entry or
  history for a device whose serial holds one is keyed differently and asks
  again once.
- **A trust store with one malformed entry still admitted the others
  without asking.** The broken entry was skipped and reported, startup said
  "nothing will be treated as trusted" and `--trusted` refused to list the
  store, but every entry it could read went on admitting its device without
  a question. A store that does not load cleanly now trusts nothing until it
  does, and a corrected file counts again without a restart. Nothing
  rewrites it but `--remove-trusted`, which repairs it and says what is
  trusted afterwards (with nothing readable left, `all` used to answer "No
  remembered devices." and leave the file broken). An "always" answered
  after the store broke used to be saved over it, keeping only the readable
  entries, so a restart trusted them all again. Only a writer of the
  root-owned store could cause any of this, and a broken entry means
  corruption or tampering.
- **The 2026-10-13 batch was never in the code.** Its fixes (the storage
  reader below, the card-reader watch fixes, isohybrid images, `--history`
  serials) were committed as `probolos-fixes.patch` and deleted again
  unapplied, while this changelog listed them. They are applied now, with
  their tests.
- **The service could not end an analyzer that outlived its socket.** The
  unit's bounding set has no `CAP_KILL`, and root without it may not signal
  another uid: the 10 s `SIGKILL` failed unnoticed and root waited for as long
  as the analyzer lived, the gate stopped and the unit still "active". When it
  did exit, its status 0 was passed on, so `Restart=on-failure` never ran. The
  gate now exits with a failure, and systemd ends what is left.
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

- **`--log` under `--privsep` logged nothing.** The analyzer writes it, and
  could not create it in a root-owned directory such as `/var/log`: every
  decision printed "could not write log". The problem is now named once at
  startup, a log under `/var/lib/probolos/state/` has its directory handed to
  the analyzer (also with `--no-ledger`), and the README says so.
- **kdialog showed escape codes instead of characters.** The confirm window
  read "its maker&#x27;s software" for "its maker's software". kdialog lets
  Qt guess rich or plain text from the first line only, and escaped text
  usually looked plain, so the escapes were shown as typed; an escaped `<` on
  the first line flipped the guess and ran every line together. kdialog text
  now always opens with `<qt>`, so Qt reads it as rich text and shows exactly
  what was sent, line breaks and spacing included. Device names stay inert.
  Quotes are no longer escaped either: the text only goes between tags, so
  only `&`, `<` and `>` need it, and an apostrophe now reads correctly even
  where the text is shown as plain (a notification server without markup).
- **Stage 4's UDF check could raise instead of answering.** The walk over the
  volume recognition sequence checked a descriptor's identifier and then read
  its version byte, one past what it had checked; a buffer ending between
  the two raised `IndexError`. The reader process contained it, and a block
  device returns whole sectors, so no real medium could end there; the parser
  no longer relies on either. Found by fuzzing.
- **The unused-area notice trusted a refused ISO 9660 half, and gave a UDF
  volume 0.0 MiB.** Behind an MBR, a UDF/ISO 9660 bridge whose ISO 9660 half
  stage 4 refused (one claiming 8 TB on a 100 MB stick, say) is reported as
  plain UDF. The refused half's size still decided how far the volume reached,
  so `large-unallocated-gap` called the gap "an isohybrid image, as written by
  every Linux installer" in the same report that refused it. Only a half that
  passed the check is measured now. A UDF volume, whose size stage 4 does not
  measure, was said to cover "only the first 0.0 MiB"; the notice now says its
  size was not measured. The finding and its severity are unchanged.
- **An overstated `wTotalLength` was missed in every configuration but the
  last.** Each configuration was measured from its own descriptor to the end
  of the blob, so the configurations after it counted as its own data, and an
  overstatement showed only by however much it exceeded them. A first
  configuration of two that declared 60 bytes and delivered 18, followed by
  one of 54 bytes, raised no `descriptor-length-overstated`, and early
  activation (stages 3 and 4) was not switched off; followed by one of 18
  bytes, it read as 24 bytes instead of 42. Each configuration is now measured
  up to the next one. Real hardware can produce this, since the kernel accepts
  a short read of a configuration. Nothing was hidden from the interface
  checks, which see the same bytes as the kernel.
- **One line on the agent socket could end the desktop agent.** An integer of
  more than 4300 digits (`json` raises a plain `ValueError` there, not the
  `JSONDecodeError` the agent caught), an integer countdown past 1.8e308
  (`OverflowError`), or a NUL or lone surrogate in a question's title, body,
  capabilities or countdown note (`ValueError` or `UnicodeEncodeError` from
  the dialog tool's argv) went uncaught, and the agent exited; so did a lone
  surrogate in a notice, on its way to gdbus. The desktop prompt was gone and
  the gate failed closed. Such a line is now ignored like any other that is
  not JSON, the countdown falls back to 10 s, and the two characters are shown
  written out as textsafe writes them (`\x00`, `\ud800`); any other text is
  shown unchanged. Only whatever occupies the agent socket can send these; the
  daemon never does.
- **An overlong count in a state file could stop the ledger saving and turn a
  drift alarm into a notice.** The ledger kept any integer as a device's
  sighting count. A count of 4300 nines, the largest `json.loads` accepts,
  became 4301 digits at the next sighting, and Python will not write that out.
  `save()` then raised instead of returning the error, as it promises to.
  Until a restart, no decision reached the ledger and none reached the audit
  log (`--log`). The ledger analyzer raised too, so a reflashed device's later
  sightings came out as `analyzer-failed:ledger` (NOTICE) instead of
  `descriptor-drift` (CRITICAL). The trust store's admission count had the
  same flaw: a trusted device was admitted, but its decision went unrecorded.
  Both counts are now capped at 2**53 when loaded, which no device reaches. A
  value `json.dumps` refuses is now a save error like any other. Only a writer
  of the state file could set such a count: root, or for the ledger the
  analyzer's account (`probolos` under the service, `nobody` by default on a
  hand run). Such a writer could already rewrite the baseline directly. Found
  in review after fuzzing.
- **An impossible date in a state file could turn a drift alarm into a
  notice.** The ledger keeps any finite number as a time. One past the year
  9999 (or before the year 1) made the drift finding's own text raise, so
  `descriptor-drift` (CRITICAL) came out as `analyzer-failed:ledger` (NOTICE);
  `--trusted` stopped with a traceback at such an entry. Such a date now reads
  "an unknown date". Only a writer of the state file could set one.
- **What the state files hold could stop `--trusted`, or write to the
  terminal.** Any JSON string loads as a trust entry's label, identity or
  port: a lone surrogate in one ended the listing with a traceback, and an
  escape sequence reached the terminal raw. So did the schema a trust store
  or ledger claims, printed in the "unreadable" warnings and the
  `ledger-unavailable` finding, and a refused device's ports from the
  ledger, printed in `previously-rejected`. All of them are written out
  through textsafe now; an ordinary device name is shown as it was stored.
  Only a writer of the state file could set them (root for the trust store;
  for the ledger also the analyzer's account).
- **A disk with 4096-byte sectors got a clean stage 4 report for a layout
  that was never read.** Stage 4 reads partition tables in 512-byte blocks.
  On a 4Kn medium the GPT header sits at byte 4096, so it was not found: the
  disk read as MBR, the EFI-system-partition and hidden-partition checks did
  not run, and nothing said so. Such a medium is now reported as not
  inspected (`storage-unreadable`, "its sectors are not 512 bytes"), and the
  block size goes to the log. Reading 4Kn layouts is for after 1.0.
- `tests/test_cli.py` called `unittest.main()` before its last 15 tests, so
  running the file directly skipped them (the suite itself ran them all). A
  test now checks that every test file ends with its guard.
- **Ctrl-C under `--privsep` could do nothing.** The root gate passes Ctrl-C
  and hangup on to the analyzer, but a signal that landed just before the
  gate's blocking `recv()` did not interrupt it, so the gate passed it on
  only at the analyzer's next request, on an idle machine never. The gate
  now waits on its socket and a signal wakeup pipe together. Once the
  analyzer is reaped, nothing is passed on to its pid any more (it may
  belong to another process by then). The test that caught this,
  `test_ctrl_c_at_the_terminal_still_reaches_the_analyzer`, failed about one
  run in thirty under load; it also had a race of its own (its "ready"
  was written outside its `try`), fixed with it.
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

### Tests

- **`fuzzing/`, a coverage-guided fuzzer** for everything Probolos parses
  before a decision (descriptors, HID report descriptors, the medium, the gate
  protocol, the agent socket, the state files) and for the whole analysis
  path. Standard library only, with an optional atheris engine; not part of
  the suite or the sdist (`fuzzing/README.md`, and a paragraph in
  `docs/TECHNICAL-REFERENCE.md`). It found the UDF defect above, and the
  review that followed it found the other fixes of this batch.
- New property tests: storage with any HID interface is at least a WARNING
  and one HID interface alone never is (also checked once over all 65 536
  subclass/protocol pairs); a partition past the end of the medium is always
  reported; and stage 4's reads, observed, start inside a device whose size
  was believed.

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
