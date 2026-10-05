# Changelog

All notable changes to Probolos. Versions follow PEP 440
(`1.0.0b1` < `1.0.0rc1` < `1.0.0`).

## [0.13.0] — 2026-10-05 · the analyzer's own account

Still alpha, still frozen at the 0.11.0 feature set (`CAPABILITIES.md` §1).
This release closes ROADMAP 1.11, the P1 left open by the 0.12.0 security
audit, and with it 1.13 for the service.

### Security

- **The service's analyzer runs as its own account, not the shared
  `nobody`.** Any other process running as `nobody` could kill the
  `--privsep` analyzer; every analyzer exit reopens every hub, and the
  devices attached before the service restarted became the next run's
  untouched baseline. The same processes could take over the agent socket,
  whose directory the analyzer's account owns. `probolos.service` now passes
  `--privsep-user probolos`, a system account with no login that nothing else
  runs as, declared in the new `systemd/probolos.sysusers`; `install.sh`
  creates it with `systemd-sysusers` and refuses an existing `probolos` that
  is not a system account of its own. The other option, keeping the hubs
  closed when the analyzer is killed, was not taken: the analyzer's `SIGTERM`
  handler reopens them itself, so it could not tell a kill from
  `systemctl stop`, and it would turn an OOM kill into dead ports
  (`SECURITY.md`).
- **The unit's agent placeholder stays harmless.** `PROBOLOS_AGENT_USER`
  shipped as `nobody`, which the gate refused only because it was also the
  analyzer's account. With the analyzer on `probolos` it would have handed
  the prompt to every `nobody` process; the placeholder is now `probolos`,
  so an unconfigured unit still runs without the agent and holds devices.

### QA

- `tests/test_service.py`: the unit's analyzer account is not `nobody`, the
  sysusers file declares it, `install.sh` creates it before starting the
  service, the placeholder agent user is that account, and the unit's own
  command line drops to it with the agent off. As root with
  `systemd-sysusers`, the file is applied to a scratch root and must give a
  system uid, no login shell and a locked password. The account, sysusers,
  install and drop checks fail on 0.12.0; the two placeholder checks pass on
  it and guard the regression this change would otherwise have brought.

### Documentation

- `SECURITY.md`, `README.md`, `CAPABILITIES.md` and `systemd/README.md` say
  which account the analyzer runs as, how a manual install creates it, and
  what is still open: a run by hand defaults to `nobody` unless it passes
  `--privsep-user probolos`, and the analyzer's descendants can still outlive
  the gate on a terminal run (1.12).

## [0.12.0] — 2026-10-05 · Phase 1 hardening

Still alpha, still frozen at the 0.11.0 feature set (`CAPABILITIES.md` §1):
everything below is a fix, a security fix, testing, documentation or release
work. It is not the first beta. The security audit of 2026-10-04 found the
defects marked "review (security audit)" in `docs/QA-LOG.md`; the ones fixed
here have regression tests that fail on 0.11.0, and the ones still open are
listed under "Known open issues" below and in `SECURITY.md`.

### Security

- **The tkinter fallback no longer turns "No" into "Always allow".** On a
  desktop with only tkinter, the one-step prompt asked "Allow it?" with
  Yes/No/Cancel, and No meant "Always allow": the button that reads as a
  refusal admitted the device and trusted it for good. The Tk backend now
  asks twice, as the base class allows: "Allow it?" (No keeps it blocked),
  then "Remember this device?" (No, the default, allows it once).
- **Stage 3 and 4 switch on the inspected device, never its replacement.**
  Temporary activation went by path. A device that re-enumerated at the same
  port between the identity checks and the switch-on -- a different device,
  judged by nothing -- was switched on in its place, for stage 4 with no input
  grab. `sysfs.activate_device` now writes only to the inspected kernel
  directory instance, in both modes, as final admission already did.
- **Device strings decode the same way under every locale.** `read_attr`
  used the locale's codec and let `UnicodeDecodeError` out: under a non-UTF-8
  locale an honest non-ASCII product name, or bytes that are not UTF-8,
  stopped `snapshot()` at startup and the gate reopened as the process
  exited. Strings are decoded as UTF-8 with replacement on both sides of the
  boundary, so the trust keys still agree, and an undecodable one is the
  existing `crafted-strings` finding. (A serial holding a carriage return now
  keeps it, so such a remembered device is asked about once more.)
- **The analyzer no longer inherits the one-gate lock.** `O_CLOEXEC` acts at
  exec, not fork, so the `--privsep` analyzer held the instance lock and could
  release it, letting a second gate start beside the first. It is closed in
  the child before the analyzer runs.
- **Under `--privsep` the analyzer trusts only a root-owned store**, as the
  gate does. It accepted a store owned by its own uid -- the shared `nobody`
  -- which any `nobody` process could write, given a `--trust-file` in such a
  directory.
- **`install.sh` copies regular files only, and runs Python isolated.** A
  symlink in the checkout (or the package directory being one) was copied as
  a symlink into root-owned `/opt/probolos`, leaving the root service running
  code its owner could still edit; it is now refused. The `pyudev` check and
  `compileall` ran as root without `-I`, so a module in the directory `sudo`
  was run from was imported as root; the script now runs from `/`, with `-I`.
- **`release.yml` releases only a commit of main, after the checks.** Any
  `v*` tag on any commit built and attested a draft release. A check job now
  requires the tagged commit to be on `main` and runs ruff and the suite
  first; the version must be in PEP 440 normal form (`1.0.0-beta.1` matched
  its tag and built `1.0.0b1` files), and pre-release status comes from
  PEP 440 (a/b/rc/dev) instead of a pattern on the tag, which missed
  `.devN`. A 0.x final stays a normal release, as v0.9.0 to v0.11.0 were,
  so it can be "Latest".

### Fixed

- **A watchdog stall ends in a failure exit status.** After the watchdog
  reopened the gate the process exited 0, so `Restart=on-failure` never
  started it again and the unit read "inactive (dead)" while nothing was
  gated. The panic file, the operator's own off switch, still exits 0.
- **`--release` refuses while a gate is running,** where it admitted every
  device the gate was holding or had refused and reopened the hubs under it.
  It also exits 1 when a write fails, and reopens the hubs when no device is
  blocked: it returned at "Nothing stranded" before the hub loop, so a gate
  left closed by a `SIGKILL` with nothing plugged in stayed closed.
- **One command per run; `--dry-run` changes nothing.** `--remove-trusted ""`
  fell through every command and started the gate; `--list --release` ran the
  first and dropped the second; `--dry-run` with `--release`,
  `--remove-trusted` or `--remove-all` changed state anyway, and
  `--dry-run --privsep` made the trust store readable and handed the ledger
  directory to the analyzer. Each is now refused or skipped.
- **"Always" is not offered over a trust store that failed to load** (direct
  mode), where saving kept only what had been read -- after one stray comma,
  nothing -- plus the new entry. The gate already refused this under
  `--privsep`.
- **A second failed "always" says so.** `TrustStore.save` returned success
  for a failure that repeated the previous one, so the message read
  "remembered for future admissions" with nothing on disk.
- **A countdown window that died is no decision.** kdialog's and zenity's
  notice read every exit as "closed", so a first window that crashed at once
  ended the countdown as a refusal nobody made, which arms
  `previously-rejected` for the next plug.
- **The agent survives deeply nested JSON** (`RecursionError` in `_handle`).
- **`--history` on an unreadable ledger says so** instead of "History is
  empty".
- **`install.sh`**: `--user 0` passed the check for root and left the service
  restarting forever; a trailing `--user` exited silently; uninstalling
  removed an administrator's `override.conf` with the drop-in directory; the
  code is swapped by two renames instead of delete-then-move.

### QA

- New regression tests for each fix above, each shown to fail on 0.11.0, and
  for contracts that mutation testing showed nothing pinned down: trust never
  admits past a CRITICAL finding, `y` does not pass a CRITICAL terminal prompt,
  stage 4 always ends with the device re-blocked, and `--dry-run` writes
  nothing even for a protected device. The tkinter tests now run the
  backend's real dialog scripts against a stub tkinter, so what each button
  press produces is tested, not only the exit codes.
- The suite no longer leaves temporary directories behind (33 per run), and
  `unittest.main()` sits at the end of `test_trust.py` and `test_ledger.py`,
  where running either file directly skipped the classes after it.
- Deep property run (`HYPOTHESIS_PROFILE=deep`) on `ed0ad1a` and on the
  0.12.0 tree: clean both times.

### Documentation

- `SECURITY.md` lists the weaknesses still open (below), corrects the agent
  socket section (the `2750` directory stopped the desktop group, not other
  `nobody` processes), and no longer says an analyzer compromise "cannot
  escalate to root" as a lockout-safety layer. The last-resort recovery
  command resets every root hub, not only `usb1`, and says that blocked
  devices then need a replug.
- `README.md`: no emoji; the recovery commands for an installed copy; the
  shared-`nobody` caveat under `--privsep`; `--gate-fixed-ports` in the
  internal-port note; no `pip install pyudev` before `sudo python3`.
- `systemd/README.md`, the unit's comment and `testbed/README.md` match what
  the code does (held, not denied; no system package yet; the report's
  CRITICAL line).

### Licensing

- **GPL-3.0-or-later, stated.** "GPLv3" did not say whether later versions
  of the GPL apply; they do, at the licensee's option. The package metadata is
  now the SPDX expression (PEP 639) with `license-files`, so the wheel carries
  `LICENSE`; the deprecated `license` table and the license classifier, which
  setuptools would stop accepting after 2027-02-18, are gone. Building needs
  setuptools 77 or newer. `README.md` and `CITATION.cff` say the same.

### Known open issues

Found by the same audit and not fixed here; each is a beta blocker or is
listed in `ROADMAP.md` Phase 1.

- Any process running as `nobody` can kill the `--privsep` analyzer, and the
  gate then reopens every hub until the service restarts (`SECURITY.md`).
- The analyzer's descendants can outlive the gate on a terminal run.
- Any `nobody` process can take over the agent socket path and show its own
  questions (it cannot approve anything).
- `--timeout` under about 12 s and the agent's 10 s floor disagree; the
  ledger's decision history is capped, so many replugs can push an old
  refusal out of it; `--lock-policy deny` never asks about devices stranded
  at a locked startup; with `--agent` requested but the socket failing, the
  service denies instead of holding.

### Before the audit

The feature set is frozen at 0.11.0 (`CAPABILITIES.md` §1). Everything below
is a fix, a security fix, testing, documentation or release work, and ships
in 0.12.0.

#### Fixed

- **The CRITICAL notice says what is true, and is sent.** The agent's
  `MSG_CRITICAL` handler still said "cannot be approved from here. Use the
  terminal" -- untrue since CRITICAL devices became approvable with the
  countdown, and the service has no terminal -- and `AgentLink.notify_critical`
  had no caller. When a CRITICAL device's countdown question goes unanswered
  (or an approval arrives inside the countdown and is ignored), the "still
  blocked, replug it to be asked" notice now goes out as `MSG_CRITICAL`, which
  the agent shows at critical urgency so it stays on screen until dismissed.
  It is display-only like every notice: no id, nothing to answer, and it
  falls back to the one-button window on a desktop with no notification
  server. Ordinary devices keep the normal-urgency notice.
- **`install.sh` no longer skips its already-running check on an unusual
  path.** It put the checkout path into the Python program it ran, so a path
  with a quote in it made a syntax error, which read as "not running". The
  path is now an argument.
- **testbed: the `overpowered` preset builds.** It declared 800 mA, which does
  not fit `bMaxPower` (one byte, 2 mA units), so it crashed before presenting
  anything; it now declares 510 mA, the most a configuration can, still over
  the 500 mA limit. `modprobe dummy_hcd raw_gadget`, in the testbed README, the
  spawn docstring and an error hint, loaded only `dummy_hcd`; it is
  `modprobe -a` now.

#### QA

- **The privilege boundary's refusal paths are tested**
  (`tests/test_boundary.py`): every failed step of the privilege drop (euid,
  egid, regained root), every way the analyzer child can end (Ctrl-C,
  `SystemExit` with a message, a crash), `privsep.start()`'s child branch
  (session, drop, exit status, signal dispositions put back) and parent branch
  (a gate that raises, a child already reaped, signal forwarding and the
  pre-fork window), every refused `GateClient` operation and broken exchange,
  and the gate's refusal and error paths for paths, interfaces, root hubs,
  input and block opens, fingerprints and its serve loop. `privsep.start()` is
  driven in-process with fork and `_exit` mocked, because its pty-forked
  children report no coverage. Boundary coverage went from 80% to 95%
  (`privsep.py` 67% → 98%, `gate_client.py` 71% → 94%, `gate_server.py` 81% →
  95%).
- **Coverage leaves out what no unit test can reach**: `interrogate.py` (a
  research instrument, not on the daemon's path) and `countdown_dialog.py` (a
  Tk window in its own interpreter), with the reason next to the setting in
  `pyproject.toml`. Floors re-baselined: boundary 93%, total 83%.
- **mypy on the root side** (`mypy.yml`): the six boundary modules, with
  `check_untyped_defs`, configured in `[tool.mypy]` so `python -m mypy` checks
  the same thing locally. Clean after annotation-only changes in
  `protocol.py`, `gate_server.py`, `privsep.py` and `trust.py` (an implicit
  `Optional`); no behaviour changed.
- **`docs/QA-LOG.md`**: one row per defect found from the freeze on, with how
  it was found, plus the boundary coverage table and static-analysis triage
  (CodeQL: two alerts, both false positives).
- **A structure audit** of the repository on 2026-10-04 (six independent
  reviewers, each finding re-checked by a skeptic) found the defects
  `docs/QA-LOG.md` marks "review (structure audit)", one row each, and the
  same method run over the fixes found two more ("review (fix verification)").
  All of them are fixed here. The CRITICAL notice and the two `SECURITY.md`
  statements above were found earlier, by review.
- **New tests:** every rule id the code emits must appear in `CAPABILITIES.md`
  (`EveryRuleIsInTheContract`); every testbed preset builds and raises the rule
  it exists for (`tests/test_testbed.py`); the offline half of the
  interrogation study (`tests/test_interrogate.py`: benign probes first,
  `--gentle` sends nothing intrusive, failures classified, CSV rows match the
  header). `tests/run_all.py` refuses module-level test functions instead of
  wrapping them, so it and `unittest discover` count the same tests. The
  report-width tests check every rendered line again: they matched only box
  borders, and with the box gone they checked nothing.
- **CI:** a build job in `tests.yml` builds with the release pins on every push,
  checks the wheel holds the package alone, and runs the suite from the
  unpacked sdist. Every workflow runs on `ubuntu-24.04`, not `ubuntu-latest`,
  which moves to a new Ubuntu on its own; every job has a timeout.
  `coverage[toml]` (and `tomli` on Python 3.10) in `requirements-ci.txt`.

#### Documentation

- **`SECURITY.md`**: the threat model of the gate-side trust write
  (`REQ_TRUST`); holding with no agent, the re-ask cap and replayed "add"
  events; the `textsafe` cut; dialog exit codes that are no decision. Two
  statements that were no longer true are corrected: an unanswered agent
  question does not fall back to a terminal the service does not have, and a
  trust store the gate creates is `0644`, not `0600`.
- **`CAPABILITIES.md` §1 names every rule 0.11.0 emits.** It left out nine
  rules, five of them CRITICAL (`storage-with-undeclared-hid`,
  `quarantine-not-restored`, `payload-captured`, `descriptor-drift`,
  `previously-rejected`), and listed a tenth only in §3.4. They are documented
  now, with `analyzer-failed:<check>` and the systemd service (§1.14); nothing
  changed in the code. §1.6 (and `SECURITY.md`) say when the trust store is
  `0644` under `--privsep`; §1.11 sits in order; §1.12 describes the report as
  it is; §2.2 lists `textsafe.pad`/`fit` as tested but unreachable; a pointer
  to an audit report that is not in the repository is gone. §1.7 names the
  critical-urgency notice.
- **`systemd/README.md` "By hand"** gives the drop-in settings `install.sh`
  writes (`PYTHONPATH`, `PROBOLOS_AGENT_USER`, and the agent's
  `WorkingDirectory=/`; not `ConditionUser=`, which a per-user unit does not
  need).
  Without them the agent could not import `probolos`, and with the shipped
  `PROBOLOS_AGENT_USER=nobody` the gate turned the agent off and denied every
  device.
- **`testbed/hidexp/EXPERIMENT.md`** runs from the repository, makes the default
  path the control and `--close-race-window` the treatment (outside the 1.0
  guarantees), counts leaked keystrokes at the session, and leaves the results
  table to be measured; it predicted zero leaks, which CAPABILITIES §1.4 rules
  out. Linked from `testbed/README.md` and ROADMAP 2.4.
- **No `probolos --version` in the docs.** The bug form and `SECURITY.md` asked
  for it and the CLI has no such flag; they ask for the release or
  `git describe` instead.
- **README.md:** the freeze status, the two test files its table missed and
  the two new ones, the pinned tools and mypy, and pointers to CAPABILITIES,
  ROADMAP and QA-LOG instead of "open items in CHANGELOG".
- **`CITATION.cff`** for GitHub's "Cite this repository" and the Zenodo DOI
  (ROADMAP 4.2), author `capitan0n`, also in `pyproject.toml`.
- **`docs/GITHUB-SETUP.md`**: the labels, milestones, repository settings and
  Phase 1 issues to apply by hand; the settings applied so far; Zenodo
  (switched on before 1.0.0) and Software Heritage (after it). ROADMAP ticks
  what is done.

#### Release engineering

- **`release.yml`**: on a `v*` tag, checks the tag against `pyproject.toml`
  and the `__init__.py` fallback, builds the sdist and wheel with a pinned
  `build`, writes `SHA256SUMS`, attests build provenance, and opens a
  **draft** release (a pre-release for a/b/rc tags) for the maintainer to
  publish. Nothing goes to PyPI. It builds with `setuptools` pinned too
  (`--no-isolation`) and `SOURCE_DATE_EPOCH` at the commit time, so a tag
  gives a byte-identical wheel; the sdist is not byte-reproducible.
- **`MANIFEST.in`**: the sdist carries the tests with their helpers (they
  could not run from it before), `testbed/`, `systemd/`, `install.sh`, `docs/`
  and the documents the code cites. The wheel is unchanged.

## [0.11.0] — 2026-10-03 · feature freeze

The feature-complete snapshot: what 1.0 will ship, and what the thesis
describes. From here to 1.0.0 only fixes, tests, documentation and release
work go in (`ROADMAP.md`).

### The freeze

- **`CAPABILITIES.md` §1 is the 1.0 feature contract.** It opens with the
  freeze note, and §3.0 lists what is deferred past 1.0: a GUI for history
  and trust, `--remove-history`, a configurable dialog timeout, HID
  report-descriptor analysis, and `--close-race-window`, which stays in the
  tree as experimental and outside the 1.0 guarantees. §1 now also states
  what this release added without describing it there: the three prompt
  levels, the hold when nobody can be asked, and the gate-side "always".
- **`ROADMAP.md`**: the plan from here to 1.0.0.
- **Reporting.** `SECURITY.md` points to GitHub's private vulnerability
  reporting. Issue templates: a bug report form asking for the distribution,
  kernel, `probolos --version`, desktop and `journalctl -u probolos`; security
  reports are routed to private reporting; blank issues are off.

### Added

- **"Always allow" under `--privsep`, written by the gate.** The analyzer runs
  as `nobody` and cannot write the root-owned trust store, so "always" was
  never offered under the service. The root gate now writes the entry itself
  (`REQ_TRUST`), and only for a device it admitted on this connection, within
  60 s, once, under a fingerprint it took itself from the device's
  descriptors before it first switched it on. The analyzer's key must equal
  the gate's exactly; the label is the only value taken from the request, and
  the gate cleans it. The trust file's path comes from the root side's
  command line, never from the socket. A compromised analyzer gains
  persistence for devices it could already admit, and nothing else.
- **Devices are held, not refused, when nobody can be asked.** Under the
  service (stdin is `/dev/null`) a device plugged in with no desktop agent
  connected -- at the login screen, after a logout, while the agent restarts
  -- used to be "asked" on a terminal that reads EOF, and denied. It is now
  held blocked, before stages 3 and 4 switch it on, and asked about when an
  agent connects. A remembered device is still admitted on trust. An agent
  that leaves mid-question holds the device again; on the third lost question
  for the same device instance it is refused as unanswered instead, so an
  agent that crashes on the question cannot have the same unknown hardware
  switched on for inspection again and again.
- **"Still blocked" notices.** A question the agent showed but nobody
  answered is recorded as "no answer" (never as a refusal, so the replug does
  not get the previously-rejected countdown), the device is not re-queued,
  and the agent shows a display-only notice: "Unplug it and plug it in again
  to be asked." With no notification server, a one-button window, one at a
  time and off the agent's receive loop; tkinter-only desktops got a
  `notice()` they lacked.
- **CI.** Workflows for the suite as root, ShellCheck on every tracked shell
  script, the systemd units (they parse, and the service's sandboxing has not
  weakened), actionlint and zizmor on the workflows, the suite on Arch Linux,
  and coverage. Every action is
  pinned to a commit; Dependabot proposes updates.
- **QA tooling.** ruff with flake8-bugbear (`B`) and flake8-bandit (`S`) on
  top of the defaults, each exception justified in `pyproject.toml`;
  Hypothesis property tests (`tests/test_properties.py`) over the parsers,
  the protocol, `textsafe`, the state files and the agent's message loop, with
  `ci` and `deep` profiles; branch coverage that follows forked children, with
  a floor on the privilege boundary (`coverage.yml`); exact tool versions in
  `.github/requirements-ci.txt`.

### Fixed

- **A dialog that died is no decision.** kdialog killed by a signal (Qt
  aborts when the display goes away, as at logout) or failing on its own
  (254/255), and zenity's error exit, used to read as "Keep blocked": the
  device was recorded as "user rejected" and the next plug got the
  previously-rejected countdown for a refusal nobody made. Only the buttons
  are answers now; anything else is no decision, like a timeout.
- **A replayed "add" for a held device is ignored.** udev replays `add`
  (`udevadm trigger`, a settle, a rescan) for queued devices too. Gating the
  replay asked about the device now and again at the drain, and for one held
  behind a locked screen skipped the forced question after unlock -- a
  remembered device would have been admitted on trust. Only a different
  device instance at the port replaces the queue entry.
- **Holding a device again writes nothing new.** Each repeated "held" record
  cost one of the ledger's bounded decision slots, and enough of them could
  push a real "user rejected" out of the history.
- **The trust store fails closed when it cannot be reached.** `EACCES` on its
  directory raised out of `TrustStore`'s constructor and ended the analyzer at
  startup, taking the gate with it. It is now a `load_error`: nothing is
  trusted, and the reason is reported.
- **A store the gate creates is readable by the analyzer** (0644 on
  creation); an existing file keeps its mode. A 0600 file written by root
  would have been remembered on disk and asked about anyway.
- **No pointless trust bookkeeping under `--privsep`**: the analyzer no
  longer tries to update `last_seen` in a store it cannot write, which only
  printed "could not update trust store" once per run.
- **`textsafe` cut.** Once one token did not fit, the cut skipped only that
  token and kept appending what still fitted, so a long escape was dropped
  and its neighbour shown in its place (`'\x1f0'` at a limit of 1 came out
  as `0...`), and the combining-mark count reset. Nothing is appended after
  the first token that does not fit. Found by the property tests.
- **`interrogation_study.py`** reports a driver it could not detach instead
  of swallowing the error; `interrogate.py` binds each probe rather than
  closing over the loop variable (both found by ruff `B`).

## [0.10.0] — 2026-10-01 · quality pass

### Added

- **The desktop prompt asks with as much friction as the device earns.**
  One dialog for a device that can neither type nor carry traffic and showed
  nothing suspicious; a second "switch it on?" when it can (keyboard/HID,
  network, radio, vendor-specific, or anything unknown) or when a warning was
  found. The dialogs now say what the device is in plain words and which port
  it is on, list every finding (most severe first; "...and 1 more" hid
  warnings), and name what THIS device will be able to do. The notification
  is one line instead of a copy of the dialog.
- **Critical devices can be approved from the desktop, after a 10 s
  countdown.** They used to be approvable only by typing `authorize` in the
  terminal, which the service does not have -- so under the service a known
  device after a firmware update could not be approved at all. "Allow anyway"
  now stays disabled for 10 seconds (a real countdown button with tkinter; a
  read-first window before the question with kdialog/zenity), "always" is
  never offered, and the daemon refuses an approval that arrives sooner,
  whatever sent it. A previously refused device is now CRITICAL too, so it
  gets the countdown. The window's warning fits the finding ("allow it only
  if refusing it was a mistake" rather than "matches an attack pattern" for a
  refused stick), and with tkinter it is drawn in the desktop's own colours
  and font from `~/.config/kdeglobals`. Every refusal button reads "Keep
  blocked".

- **`sudo ./install.sh`** runs Probolos as a background service in one step:
  root-owned code in `/opt/probolos`, a `probolos` command (run with `-I`, so
  a `probolos/` folder in the current directory is never executed as root),
  both systemd units with drop-ins for the local settings, and the prompt
  enabled only for the account that ran `sudo`. Re-run to update;
  `--uninstall` removes it and keeps `/var/lib/probolos`.
- **`--remove-trusted N|PATTERN|all`** replaces `--forget` (still accepted).
  It says plainly that device history is kept, which is what the old
  "Forgot all 0 device(s)" left users wondering about. `all` asks first.
- **`--remove-all`** clears remembered devices and the device history
  together. It always asks, lists the devices whose descriptor-drift
  evidence would be erased, refuses while a daemon holds the history, and
  takes `-y/--yes` for scripts. Without a terminal and without `--yes` it
  refuses rather than guess.

### Fixed

- **A crashed tkinter dialog answered for the user.** Python exits 1 on any
  uncaught exception, and the tkinter dialogs used exit 1 for an answer:
  "no" from confirm(), and "Always allow" from choose() -- reached after the
  person had clicked Allow once, so a crash there trusted the device for
  good. Answers now use their own exit codes and anything else is "no
  decision". tkinter also counts as available only when it can open a
  window, not merely import, so a service with no `$DISPLAY` falls back to
  kdialog/zenity instead of refusing every critical device unseen.
- **The journal showed nothing until a service exited.** Python
  block-buffers a pipe; both units now set `PYTHONUNBUFFERED=1`, so events
  are logged when they happen.
- **Unanswered prompts were recorded as refusals.** A dialog left to time out
  came back as "Keep blocked", and under the service a question nobody
  answered fell through to the terminal, read EOF from `/dev/null`, and was
  logged as `user rejected` -- so the next plug warned "You have refused this
  device before" about a refusal nobody made. The device is still denied,
  but recorded as `no answer`; only a real click or keystroke counts as a
  refusal.
- **Two gates could run at once, and the second reopened the ports.** A
  probolos started by hand beside the service took the closed gate for a
  crashed run, asked about the same devices, and set `authorized_default=1`
  on exit while the service still believed it was guarding. A gate now takes
  a root-only lock (`/var/lib/probolos/instance.lock`) before touching
  anything, and a second one refuses to start. `--dry-run` never takes it.
- **"Always allow" was offered where it could not be kept.** Under
  `--privsep` the analyzer can read the trust store but never write it, so
  the answer admitted the device once and lost the trust entry. "Always" is
  now offered (and accepted) only when the trust store is writable, in the
  dialog and the terminal alike, and startup says so.
- The partition warnings blamed the device ("how a device lies about its own
  capacity"). A genuine drive holding an image made for a larger disk trips
  them too, so they now name both causes and point to a capacity test.
- **The shipped service crash-looped with the gate open.** `probolos.service`
  sets `RestrictSUIDSGID=yes`, which refuses any chmod carrying the setgid
  bit, and the launcher chmodded `/run/probolos` to `2750` on every start:
  `could not prepare the agent socket directory: [Errno 1] Operation not
  permitted`, a restart every five seconds, and USB devices admitted with no
  prompt. systemd now creates the directory `2750` itself
  (`RuntimeDirectoryMode`), and the launcher chmods only when the mode is not
  already right, so the hardening stays on.
- **Revoking trust did not reach a running daemon.** The daemon read the
  trust store once at startup, so a device removed with `--forget` stayed
  admitted without a prompt until a restart, and the next admission of any
  remembered device wrote the revoked entry back to disk. The store is now
  re-read whenever the file changes (including a chmod that makes it
  untrustworthy, which fails closed), and saves keep the file's read bits
  so a root-run edit no longer locks a `--privsep` analyzer out of it. The
  ledger is deliberately not reloaded the same way: its directory belongs to
  `nobody` under `--privsep`, so `--remove-all` waits for the daemon to stop
  instead.

- **A malformed `--rules` file ended in a traceback.** `yaml.YAMLError` is not
  a `ValueError`, so a YAML syntax error escaped the entry point's handler; it
  is now reported as the one-line `rule config: ...` error like every other
  bad rule file.
- **Duration flags accepted values that silently meant "off".** `--timeout`,
  `--observe` and `--watchdog` took negative numbers, NaN and infinity, which
  fell through the daemon's `> 0` tests — `--watchdog -1` disabled a safety
  layer without a word. They now require a finite number of seconds, 0 or
  more.
- `--force-locked` and `--force-unlocked` are mutually exclusive; together,
  the first used to win silently.
- A missing `pyudev` is reported before the gate closes. It was discovered
  only in the event loop, after every root hub had been closed and reopened,
  and ended in a traceback.
- **The `--privsep` analyzer child could exit by unwinding.** It caught
  `KeyboardInterrupt` and `Exception`, but not `SystemExit`, which `serve()`
  raises for a leftover panic file (and now a missing `pyudev`) and the
  gate's signal handler raises too. The exit then escaped `os._exit()` and
  unwound through the parent's stack in the forked child, running its
  inherited atexit handlers. It now becomes an exit status like the rest.
- **A Ctrl-C at `--privsep` startup could kill the root gate.** The gate
  installed its signal handlers after `fork()`; a SIGINT in between met
  Python's default handler, raised KeyboardInterrupt in the root process, and
  left the analyzer running with nobody behind its socket. The handlers are
  now in place before `fork()`, and the child restores what it inherited. The
  root-only test that presses Ctrl-C was failing about one run in five for
  this reason.
- `interrogation_study.py` cleans device strings with `textsafe` before
  printing them. The fix had landed in a second copy under `probolos/`, which
  could not import the package when run as a script; that copy is removed.

### Removed

- `probolos/_media.py`, a test fixture shipped inside the runtime package. The
  entry below that "moved it back" to `tests/_media.py` added the new copy but
  left this one; nothing imported it.

### Tests and tooling

- The whole-disk guard tests pass on Python 3.10, the declared minimum. The
  harness patched `os.stat`, which 3.10's `pathlib` does not route through.
- The late-input-node test asserts that discovery ran more than once.
- New `tests/test_cli_validation.py`; a YAML-syntax case in
  `test_parser_and_display_limits.py`.
- `ruff check .` is clean and configured in `pyproject.toml`; redundant
  re-imports left over from merging test modules, unused imports and dead
  locals are removed.
- `.github/workflows/tests.yml` runs ruff and the suite on 3.10, 3.12 and
  3.14.
- The suite no longer depends on where it is run. `report.py` turns colour on
  when stdout is a terminal, so three tests that look for a phrase in the
  rendered report failed at a developer's prompt and passed in CI;
  `tests/__init__.py` now sets `NO_COLOR`. On Python 3.14, argparse asks
  stdout whether it is a terminal, which a test that replaced stdout with a
  bare `Mock` could not answer; it uses a `StringIO`.
- **The test suite is organised by module: 28 files became 13.** Half the
  files were named after the security review that produced them, so the
  tests for one module were spread over up to eleven files. Each file now
  covers named modules (see the table in README.md); the review regressions
  are classes named after the defect they pin. Builders shared between files
  moved to `tests/_support.py`, and seven helpers that shared a name with a
  different one elsewhere were renamed for what they build. Same 798 tests,
  same class and method names, and each file also passes on its own.
- README: the install step for `pyudev`, PyYAML as an optional requirement,
  and `tests/audit/` references corrected — that directory no longer exists.

## [0.10.0] · input that crossed a boundary

Four findings, each reproduced against the unpatched tree before it was fixed.
Regression tests are in `tests/test_escape_and_terminal_boundaries.py`.

### Security

- **A keyboard could answer the terminal prompt about itself.** Stage 3 turns
  the device on before `EVIOCGRAB` takes it, and keystrokes sent in that
  window reach the focused window, usually the terminal running Probolos.
  `y⏎` queued there, or `authorize⏎` on a CRITICAL prompt, was then read as
  the operator's answer. The prompt now flushes the terminal's input queue
  first and says how many bytes it discarded.
- **The `--privsep` analyzer could type into the shell that started it.** It
  kept the terminal as its controlling tty, so `ioctl(TIOCSTI)` could queue a
  command for the root shell (or one with a cached sudo ticket) to run when
  Probolos exited. The analyzer now calls `setsid()` before dropping
  privilege; the gate forwards Ctrl-C, Ctrl-\ and hangup to it, and ignores
  Ctrl-Z, since suspending the gate alone would leave the analyzer reading
  the terminal alongside the shell.
- **gdbus undid the sanitising of the notification body.** gdbus parses its
  arguments as GVariant text and decodes backslash escapes, so plain ASCII in
  a device string reached the notification server as live markup, and the
  visible `\u202e` that textsafe writes came out as a real bidi override.
  Every string argument is now passed as a quoted GVariant literal.
- **zenity and kdialog did the same to the decision dialog.** zenity
  `g_strcompress()`es the text before rendering it as Pango markup, so octal
  escapes became tags after `_markup_safe` had run. kdialog decodes `\n`,
  which let a device add lines to the prompt. Backslashes in the dialog text
  are now doubled, which both tools decode back to one.

## [0.10.0] · the sixth review

A pass over the privilege boundary, the agent socket and the parsers. Every
finding below has a regression test under `tests/audit/`, each proven to fail
against the original defect before being kept.

The theme this time is **a rule enforced on one side of a pair and not the
other**: the gate validated device nodes and the direct backend did not, the
chown was pinned to a directory descriptor and the chmod beside it was not, the
gate restored devices and hubs but not interfaces, the drop verified uid and gid
but not groups.

### Added — media changes in admitted card readers

- **`--watch-media`: a detection layer for the card-reader gap.** A card is
  a SCSI medium inside a reader, not a USB device; inserting one causes no
  re-enumeration, so a trusted reader admitted every later card unexamined.
  The watcher listens for block-layer `change` events on admitted storage
  hosts (and ones present at startup), reads the new medium with stage 4's
  own inspection (raw, read-only, never mounted, bounded), and reports
  EFI system partitions and hidden partitions (CRITICAL), insertion while the
  session is locked (WARNING), and layout drift against the first medium seen
  in that reader's slot (ledger `media` section, keyed on reader identity +
  LUN). It does **not** gate the card. `--media-policy deauthorize` switches
  the whole reader off on a CRITICAL finding; the default only logs.
- **Every media report says how much it is worth**: whether udisks automount
  was inhibited for the disk or the medium was already mounted when read
  (post-hoc alerting), and, when a slot is first seen, whether it reports
  media changes to the kernel at all.
- **Wired under `--privsep`, where it would otherwise have been dead.** Final
  admission grants the analyzer no further read or deauthorization
  permission, so the watcher's reads and its one enforcement action would
  both have been refused. The gate now takes `watch_media` from the root side
  and scopes it to storage-only hosts it admitted or found live at start,
  same kernel directory instance, read-only opens and switch-off only.
- **GPT entry types are read** from the standard location inside the header
  read, for the ESP and hidden-partition rules only.

### Fixed — tests

- `tests/_media.py` had been committed as `probolos/_media.py`, so three test
  modules (`test_forged_signatures`, `test_partitionless_filesystems`,
  `test_whole_disk_guard`) failed to import and none of their tests ran. Moved
  back; the suite collects them again.

### Fixed — security

- **A medium that could not be switched on was never reported as unexamined.**
  If the sysfs write that activates a storage device for stage 4 failed —
  typically a device re-enumerating or pulled mid-inspection — the raw
  exception, errno text and full sysfs path included, was printed at the
  decision prompt and the stage returned nothing: no MEDIUM block, no
  "judged on its declared identity alone" notice. The same root cause arriving
  one step later (no block node) produced the correct notice. Every stage 4
  failure now goes through one handler (`Probolos._medium_not_examined`): the
  operator sees a fixed-vocabulary reason and the identity-only warning, a
  device that has vanished is reported as removed whichever step noticed, and
  the raw detail is written to the JSON audit log only.
- **The direct backend opened any device node it was handed.** `gate_server`
  refuses anything that is not `/dev/input/eventN` or a whole `/dev/sdX`,
  proves the node is the right kind of special file, and opens it
  `O_NOFOLLOW`. `sysfs._DirectBackend` — the DEFAULT, used by the documented
  `sudo python -m probolos`, running with real root rather than behind a gate —
  did none of the three: `os.open()` on the string it was given, following
  symlinks at every component. The same asymmetry `_write_attr_pinned` was
  written to remove on the other half of the privileged surface, and the one
  `storage._WHOLE_DISK_NAME` already names for block devices.
- **The agent socket lived in a group-writable directory.** `/run/probolos`
  was `2770`, so every member of the desktop user's group and every process
  running as the shared `nobody` account that owns it could unlink `agent.sock`
  and bind its own listener at that path — and `SO_PEERCRED` cannot see an
  attacker who is not a client at all. `connect()` needs traverse on the path
  and write on the socket inode, never write on the directory, so the
  directory is now `2750`.
- **The socket's mode was set by name, as root.** `os.chmod` follows symlinks,
  the path comes from `--agent-socket`, and `_chown_for_owner` two lines below
  was hardened against exactly this and carries the reasoning. The chmod now
  runs relative to the held directory descriptor after `lstat` confirms the
  name is still the socket that was bound, and the bind itself runs under an
  explicit umask so the socket is never momentarily more permissive than
  intended. `stop()` no longer unlinks whatever happens to sit at that path.
- **Interfaces deauthorized through the gate were never restored.** Devices
  the gate authorized are re-blocked and hubs it closed are reopened when the
  analyzer disconnects; `authorize_interface(intf, 0)` had no entry in that
  ledger, so it survived the analyzer's death — a device configured with one
  function permanently driverless, looking healthy in sysfs. Restoration
  checks the kernel directory instance, so a recycled port is not
  re-authorized under an entry belonging to different hardware.
- **The privilege drop did not verify that supplementary groups were gone.**
  `drop_privileges` asserted the uid and the gid and not the step its own
  docstring calls "a classic source of silent security holes". A surviving
  `input` or `disk` membership would let the analyzer open every evdev node
  and every raw disk directly, bypassing the gate's whole scoping rule while
  every check that *was* made still passed.

### Fixed — robustness

- **The agent's receive buffer was unbounded.** `MAX_MESSAGE` bounded each
  `recv()` and not their sum, so anything able to occupy the socket path could
  grow it without limit. `AgentLink.ask()` has carried this bound since the
  same bug was found on the server side; the agent — the half running in the
  user's session, with the user's privileges — was the one still without it.
- **`float(message["timeout"])` took the agent down.** A string, a list or a
  null raised out of the recv loop, which is a way to remove the desktop
  prompt by sending one malformed message. The value is now validated and
  clamped, and the display fields are type-checked rather than assumed.
- **256 descriptors per blob was reachable by ordinary hardware.** The flood
  guard counted every descriptor of every configuration, and a UVC webcam with
  its usual run of alternate settings exceeds it — as a NON-recoverable error,
  so the whole descriptor set was refused: `parse_error`, no behavioural or
  storage stage, and a WARNING on somebody's own camera. This project treats a
  false alarm on your own hardware as a defect in its own right. The ceiling is
  4096, the blob is now bounded where it is read, and the walk was already
  bounded by advancing at least two bytes per item.
- **An astral escape decoded to the wrong character.** `textsafe._escape` wrote
  `\u1f600` for U+1F600, which reads as U+1F60 followed by `0`. The escape
  exists so the operator sees exactly what the device sent.
- **A malformed rule file produced a traceback, not a config error.**
  `load_config` assumed a mapping of the expected shape throughout, and
  `__main__` catches only `RuntimeError`, `ValueError` and `OSError` around it,
  so the gate never closed.

### Fixed — detection

- **A dd-written live image was reported as a blank medium.** With no
  partition table, stage 4 sniffed only its 17 KiB header read, which ends
  before the ISO 9660 / UDF volume descriptors at sector 16 (0x8000). A
  bootable Slax stick — a whole operating system, kernel modules included —
  was shown as `contains no known filesystem`, the description an operator is
  most likely to approve. A partitionless medium is now read over the same
  descriptor for as far as a partition is (0x10200 bytes), and
  `sniff_filesystem` recognises ISO 9660 (`CD001`) and UDF (an `NSR02`/`NSR03`
  descriptor in the recognition sequence). btrfs without a partition table had
  the same cause and is recognised too. LBA-0 signatures still win, so a FAT
  superfloppy is unchanged. **This changes what stage 4 reports to the
  operator**: partitionless image filesystems now read as
  `whole-device <fs> filesystem (no partition table)`; `contains no known
  filesystem` is emitted only when no signature matches. Detection only — no
  rule, verdict or authorization path changed.
- **Stage 4 refused healthy whole disks as "not a whole-disk block device".**
  The whole-disk guard (`sysfs._safe_block_node`, mirrored by
  `gate_server._safe_block_path`) answered `None` for every failure and folded
  an `os.stat()` error into it, while the daemon's 1.5 s poll waited only for
  the sysfs `block/sdX` entry — which the kernel creates before `/dev/sdX`. A
  node opened in that gap was refused with a reason that was false about the
  device, and the medium was "judged on its declared identity alone": stage 4
  skipped for every mass-storage device that hit it. **The whole-disk guard is
  now sysfs-based**: the node's own device number is looked up under
  `/sys/dev/block`, a `partition` attribute there refuses it, and the kernel's
  name for that number must be the node's name — no name suffix or minor-number
  rule decides it. The `sdX` name check remains as scope (USB mass storage is
  always a SCSI disk), not as the whole-disk test. Every refusal now states its
  reason, a node that has not appeared yet is reported as exactly that, and the
  daemon polls until the node is ready (`sysfs.block_node_pending`) rather than
  until sysfs is. Genuinely unreadable media still take the transparent
  "could not be read" notice. Detection only — no rule, verdict or
  authorization path changed.

- **A forged ISO 9660 magic was reported as a filesystem.** Six bytes —
  `01 "CD001" 01` at 0x8000 on a blank device — made stage 4 show
  `whole-device ISO 9660 filesystem`, so an attacker-controlled medium chose
  the label the operator saw. ISO 9660 is now reported only when the volume
  structure checks out (ECMA-119): the descriptor set from sector 16 carries
  defined types and versions and ends in a terminator within 16 descriptors; a
  Primary Volume Descriptor is present and its both-byte-order fields agree
  with themselves (volume space size, volume set size and sequence, logical
  block size of 512–2048, path table size); its root directory record is a
  directory inside the volume; the file structure version is 1; and the volume
  fits on the device. UDF, the same bug class, now needs a BEA01 → NSR → TEA01
  recognition sequence rather than a bare NSR identifier. Checked against
  images from xorriso, genisoimage, pycdlib and mkudffs, all still recognised.
  A signature with nothing behind it is not dropped silently: it raises the
  new `filesystem-signature-without-structure` NOTICE. FAT, exFAT, NTFS, ext
  and btrfs are unchanged and remain magic-only.

### Tests

- `tests/test_payload.py` now exists. SECURITY.md said the three keystroke
  privacy invariants were "asserted in `tests/test_payload.py` and
  `tests/test_safety.py`"; only the second file was in the tree, so the
  invariants that decide whether this tool can record what somebody typed were
  asserted nowhere.
- `tests/audit/` now exists, as README.md describes it.
- `tests/run_all.py` walks subdirectories. It globbed only the top level, so
  the two documented ways of running the suite reported different totals —
  which README.md says is itself a bug, and was one before for the same reason.
- `tests/test_partitionless_filesystems.py` covers the raw ISO 9660 regression
  and the acceptance cases around it: UDF, superfloppy FAT32/exFAT, MBR and GPT
  unchanged, a blank medium, and media too short to hold a descriptor.
- `tests/test_whole_disk_guard.py` covers the whole-disk guard on a synthetic
  `/dev` and `/sys/dev/block`: a whole disk on any device number is accepted
  and opened, partitions are refused with the same notice, a late node is
  reported as late and waited for, both halves of the privilege split give the
  same verdicts, and stage 4 reaches the medium end to end. The earlier suite
  only ever asserted refusals, so a guard that refused everything passed it.
- `tests/test_forged_signatures.py` covers the forged-magic decoy from the
  report, one test per structural check, UDF sequence order, partitions, and
  real images from whichever of xorriso, genisoimage and mkudffs is installed
  (skipped when none is). Fixtures that meant "a real ISO 9660 / UDF volume"
  planted the bare magic — the forgery itself — and now build a valid header
  with `tests/_media.py`.

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
  `/var/lib/probolos/state/`; `/var/lib/probolos/` stays root-owned. The
  launcher now refuses outright to hand over a directory holding a trust store.
- **`--ledger /etc/x.json` would chown `/etc` to `nobody` at mode 0700**,
  taking sudo, ssh and PAM with it on a running system — no attacker needed, a
  typo was enough. State directories are restricted to a fixed allowlist,
  resolved with `realpath` first so `../` cannot escape and a sibling like
  `/var/lib/probolos-evil` does not match on prefix.
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
- **`systemd/60-probolos-inhibit-automount.rules`.** Stage 4 must briefly
  authorize the device for its block node to appear, and udisks2 would automount
  the medium in that window — the exact kernel-filesystem exposure stage 4
  exists to avoid. The rule sets `UDISKS_IGNORE=1` on USB block devices;
  Probolos reads the raw node itself and loses nothing. *Found in use: the
  operator was able to mount the stick by hand while the scan was running.*
- **`atomicio.py`** — symlink-safe atomic JSON writes, shared by the trust
  store and the ledger.
- 46 new tests, including a synthetic sysfs tree that exercises the gate's
  kernel-derived scoping with no root and no hardware.

### Changed

- The ledger moved from `/var/lib/probolos/ledger.json` to
  `/var/lib/probolos/state/ledger.json`. To keep existing history:
  `sudo mkdir -p /var/lib/probolos/state && sudo mv /var/lib/probolos/ledger.json /var/lib/probolos/state/`
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
- The panic file moved to `/run/probolos.panic` and must be root-owned;
  SECURITY.md still documented `/tmp/probolos-panic`. Corrected.
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
- **Desktop notification agent** (`python -m probolos.agent`). A third process
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
- `python -m probolos.agent --test` checks that notifications and body-clicks
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
- **A device held when Probolos exited was stranded.** It stayed at
  `authorized=0` — dead — and on the next run was counted as part of the
  baseline, so it was never asked about. The only way to get a question was to
  unplug and replug the hardware, which is precisely what the hold queue exists
  to avoid. A device at `authorized=0` is no longer treated as "already working,
  leave it alone"; it is queued for decision at startup.
- Exiting with undecided devices now says which ones are being left blocked and
  how to release them. Probolos will not authorize something nobody approved,
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
  and replug. State comes from logind; if it cannot be determined, Probolos
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
