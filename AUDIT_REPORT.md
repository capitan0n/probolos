# Probolos audit report

- **Project:** Probolos 1.0.0b1 (deny-by-default USB gate for Linux, Python)
- **Base commit:** `436045f` (branch `ccr-c8f6f4b1-w1i5o0`), working tree clean before the audit
- **Date:** 2026-10-23
- **Scope:** the whole repository: `probolos/` (root gate, privilege separation, analyzer, agent, parsers), `tests/`, `testbed/`, `fuzzing/`, `install.sh`, `systemd/`, `.github/workflows/`, packaging and documentation
- **Nothing was committed, pushed or published.** The fixes exist only in the working tree and in this archive.

## 1. Executive summary

The privilege boundary is the strongest part of the code. That covers the root gate (`gate_server.py`), the wire protocol, the privilege drop and the descriptor-pinned filesystem helpers. I traced every request kind a compromised analyzer can send: path validation, kernel-instance pinning, scope (blocked / owned / leased / media host), `authorized_default` restore rules and the `TRUST` fingerprint check. I found **no exploitable boundary defect**. The project's own QA log shows several earlier review rounds, and most classic issues (TOCTOU on sysfs, symlink writes, fd leaks, fail-open on crashes, terminal and markup injection) are already fixed and tested.

This audit found and fixed **three defects**, none of them a fail-open:

| ID | Severity | Summary |
|---|---|---|
| F1 | **Medium** (project scale P2) | The watchdog and the panic file reopened the hubs but left the bus-wide `drivers_autoprobe` at 0 under `--close-race-window`. New devices, a rescue keyboard included, then got no driver: a lockout in exactly the situation the escape hatch is for. |
| F2 | Low (P3) | The text sanitizer let Unicode "blank" characters through: Hangul fillers, variation selectors and other default-ignorable marks. A device name could hide invisible characters without the `invisible-string-characters` finding. |
| F3 | Low (P2) | `--log FILE` under `--privsep` is written by the unprivileged analyzer. Any root-owned location (such as `/var/log`) failed on every decision and logged nothing, and no documentation said where the file could go. |

Every fix has regression tests that fail on the original code. The full suite passes (**1362 tests, 0 failures**), as do ruff, mypy, the CI coverage floors, the release build, the suite run from the built sdist, and about 894k fuzzer executions on the affected targets.

## 2. Findings by severity

### F1 (Medium): the escape hatch can leave USB driver binding switched off

- **Files:** `probolos/gate.py:119` (`_restore_locked`), `probolos/deferred_bind.py:187` (`emergency_restore`) and `:242` (`DeferredBind.__enter__`), `probolos/daemon.py:1885` (`on_stall`). Line numbers refer to the original commit.
- **Confirmed:** yes. A test reproduced it on the original code (`tests/test_quarantine.py::DeferredBindTests::test_the_gate_restore_puts_autoprobe_back_too`).
- **Root cause.** `--close-race-window` (direct mode only) writes `drivers_autoprobe=0` for the whole USB bus around one `authorized=1` write. A hostile device can stall that write with slow control transfers, and a kernel hang can wedge it. The watchdog and the panic file are the documented ways out of a wedged daemon. They call `AuthorizationGate.restore()` from the watchdog thread, which reopened the root hubs only. `deferred_bind`'s docstring claimed "gate.py's recovery path calls it [`emergency_restore`]", but nothing did. Only the main thread's own `finally` and `atexit` restored the switch, and neither runs while the main thread is stuck.
- **Impact.** After `sudo touch /run/probolos.panic`, every new device enumerates with no driver bound, so the USB keyboard the operator plugs in to recover does nothing. This is the lockout `gate.py` was written to prevent. Exploiting it needs the experimental flag, root without `--privsep`, and a wedged or stalled authorize write. That makes it rare, but it defeats a safety guarantee.
- **Secondary race, found while fixing.** Once `emergency_restore()` can run from another thread, a restore landing between "record the original value" and "write 0" in `__enter__` clears the record and then lets the 0 stick, with nothing left to undo it. A test with a forced interleaving reproduces it.
- **Remediation.** `_restore_locked()` now calls `deferred_bind.emergency_restore()` first, after the forked-child check and before the hubs. It is a no-op unless the bus switch is held. A module-level `threading.RLock` now guards the record-and-write in `__enter__` and the restore. It is re-entrant because signal handlers run on the main thread, which may already hold it. Lock order is always gate lock, then autoprobe lock; `DeferredBind` never takes the gate lock, so there is no inversion.

### F2 (Low): invisible "blank" characters in device strings were not flagged

- **File:** `probolos/textsafe.py:69` (`_INVISIBLE`, original line).
- **Confirmed:** yes (`tests/test_textsafe.py::DangerousStrings::test_blank_letters_are_made_visible`, `test_invisible_selectors_are_made_visible`).
- **Root cause.** The sanitizer escapes characters by Unicode category (Cc, Cf, Cs, Co, Cn, Zl, Zp) plus fixed bidi and zero-width sets. Two kinds of default-ignorable code points fall outside those rules:
  - the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, which are category Lo (letters) but draw as blank space;
  - combining marks that draw nothing (U+034F, U+17B4/5, U+180B–U+180D, U+180F, U+FE00–U+FE0F, U+E0100–U+E01EF). Up to three of these in a row passed as ordinary accents.
- **Impact.** A device could put look-alike blanks or invisible characters in its manufacturer, product or serial string. They reached the terminal and dialogs unescaped, and no `invisible-string-characters` finding fired. This is a display and reporting gap only: no admission decision reads these strings, and the trust key compares exact bytes.
- **Remediation.** Added these code points to `_INVISIBLE`, so they are escaped (`ㅤ`) and reported. Real scripts were checked and stay unflagged: Latin with accents, Vietnamese, Thai, Hindi, Greek, Cyrillic, CJK, Hangul and emoji. The property tests and fuzz invariants import `_INVISIBLE`, so they enforce the wider set automatically.
- **Compatibility.** A device whose serial contains one of these characters now gets a different trust key and history identity. That device is asked about once more. This fails in the safe direction and is expected to affect no real hardware.

### F3 (Low): `--log` does not work under `--privsep`

- **Files:** `probolos/daemon.py` (`_record`, `serve`), `probolos/__main__.py:783` (`state_paths`), `README.md` (options table).
- **Confirmed:** yes. Under `--privsep`, `daemon._record()` runs in the analyzer (`nobody` or `probolos`), and `securefs.append_json_line()` then has to create the file in the given directory and own it. A `fork` + `setuid(nobody)` probe got `PermissionError`. The CLI wiring test fails on the original code (`tests/test_cli.py::...test_a_log_in_the_state_directory_is_handed_to_the_analyzer`).
- **Impact.** With `--privsep --log /var/log/probolos.jsonl`, the setup an operator would naturally choose, every decision printed `could not write log: [Errno 13]` and no audit line was written. Under the shipped unit, `ProtectSystem=strict` also makes such paths read-only. No documentation said where the log could go. Decisions still reach the ledger and journal; only the JSON audit trail is lost.
- **Remediation.** Kept minimal and inside the existing safety design:
  1. New `securefs.append_problem()` checks, writing nothing, what `append_json_line` would refuse. `serve()` calls it once at startup as the process that will actually write, and prints a clear reason plus where to put the file.
  2. Under `--privsep`, a `--log` path inside the vetted `STATE_ROOTS` gets its directory handed to the analyzer like the ledger's, also with `--no-ledger`. Paths outside those roots are never chowned; this is the guard that prevents handing `/var/log` or `/etc` to `nobody`.
  3. The README options table now says to use `/var/lib/probolos/state/`.

## 3. Areas reviewed with no defect found

- **Root gate and protocol** (`gate_server.py`, `protocol.py`, `gate_client.py`). Checked: `realpath` plus bus-view proof for every USB path; `O_NOFOLLOW` and directory-fd pinning for every read and write; kernel-instance checks; the scoping of `OPEN_INPUT` and `OPEN_BLOCK` (blocked / owned + 30 s lease / media host, whole `sdX` disks only, kind re-checked on the opened descriptor); `SET_DEFAULT` restore limited to the recorded value; `TRUST` limited to a fingerprint taken before the first switch-on, one use within 60 s; bounded and validated JSON; fd closed in `finally`; handler exceptions contained.
- **Privilege drop** (`privsep.py`): order and verification of setgroups/setgid/setuid, refusal of a surviving supplementary group, setsid against TIOCSTI, subreaper and descendant reaping, closing the instance lock in the child, `prepare_state_dir` limited to `STATE_ROOTS` and pinned.
- **Filesystem helpers** (`securefs.py`, `atomicio.py`, `instance.py`, `trust.py`, `ledger.py`): no symlink following, regular file with one link, owner and mode checks, unguessable `O_EXCL` staging names, a trust store that fails closed.
- **Decision flow** (`daemon.py`, `agentlink.py`, `agent.py`, `dialogs.py`): the device is blocked while asked; typeahead is discarded; the countdown is enforced on the daemon side; "always" is never accepted when not offered; SO_PEERCRED uid check; ids are unguessable and buffered data is discarded; dialog escaping covers Qt rich text, Pango and gdbus GVariant; exit codes are mapped so that only a real button press is an answer.
- **Untrusted parsers** (`descriptors*.py`, `storage*.py`, `payload.py`, `rules.py`): bounded reads; the reader runs in a forked child under a time limit, with the inherited gate handlers neutralised; a crash in a decisive analyzer becomes CRITICAL.
- **Install and service** (`install.sh`, `systemd/*`): root-owned copy with symlinks refused, `-I` wrappers, account checks, sandboxing directives.
- **CI** (`.github/workflows/*`): untrusted values passed through `env:`, permissions scoped per job, actions pinned by hash.

## 4. Changes made

| File | Change | Why |
|---|---|---|
| `probolos/gate.py` | `_restore_locked()` restores `drivers_autoprobe` first (never in a forked child) | F1 |
| `probolos/deferred_bind.py` | `_autoprobe_lock` (RLock) around record-and-write and around restore | F1, and the race the fix exposed |
| `probolos/textsafe.py` | `_INVISIBLE` extended with default-ignorable fillers and selectors | F2 |
| `probolos/securefs.py` | New `append_problem()` (read-only check) | F3 |
| `probolos/daemon.py` | One startup diagnostic for an unwritable `--log` | F3 |
| `probolos/__main__.py` | Under `--privsep`, a `--log` inside `STATE_ROOTS` is added to `state_paths` | F3 |
| `README.md` | `--log` row says where to put it under `--privsep` | F3 |
| `CHANGELOG.md`, `docs/QA-LOG.md` | Entries in the project's own format | Project convention: every post-freeze defect is logged |
| `tests/test_quarantine.py` | +3 tests: gate restore puts autoprobe back; cross-thread restore cannot strand it; a forked child never touches it | F1 |
| `tests/test_textsafe.py` | +3 tests: Hangul fillers, invisible selectors, ordinary Hangul untouched | F2 |
| `tests/test_privsep.py` | +4 tests for `append_problem` (writable, cannot create, existing file, refused shapes) | F3 |
| `tests/test_cli.py` | +2 tests: a log in the state roots is handed over; one outside is never chowned | F3 |
| `tests/test_daemon.py` | +2 tests: unwritable log reported exactly once; writable log quiet | F3 |

No API, protocol or file format changed. No dependency was added. No existing test was modified or removed.

## 5. Tests executed (actual results)

Environment: Linux container (no `/sys/bus/usb`, so no real hardware was touched), Python 3.13.17, running as root. The project's pinned CI tools (Hypothesis 6.168.5, PyYAML 6.0.3, ruff 0.17.0, coverage 7.16.2) were installed in a scratch venv.

| Check | Baseline (before) | Final (after) |
|---|---|---|
| `python -m tests.run_all` with CI deps, `HYPOTHESIS_PROFILE=ci` | 1348 passed, 5 skipped | **1362 passed, 5 skipped** |
| `python -m unittest discover -b -s tests -t .` with CI deps | n/a | **1362 passed, 5 skipped** (same total, as the README requires) |
| Same, system Python without Hypothesis/PyYAML | 1320 passed, 6 skipped | **1334 passed, 6 skipped** |
| `ruff check .` | clean | **clean** |
| `mypy` (root-side modules per `pyproject.toml`) | clean (6 files) | **clean** |
| Coverage floors from `coverage.yml` (boundary ≥ 93%, total ≥ 83%) | n/a | **boundary 96%, total 88%: pass**; `securefs.py` 90% (QA log: 87%) |
| Release build (`requirements-release.txt` installed with `--require-hashes`, `python -m build --no-isolation`) | n/a | **wheel and sdist built**; wheel holds only `probolos/` |
| Test suite run from the unpacked sdist | n/a | **1362 passed, 5 skipped** |
| `fuzzing/heavy_fuzz.py` on `textsafe,analysis,trust,ledger`, 3 min, 4 workers | n/a | **894,208 executions, 0 crashes** |
| Regression tests against the original code | | F1 and the race test **fail**, F2 tests **fail**, F3 CLI test **fails**; all pass with the fixes |

Skipped tests need tools absent here: PySide6, and ISO/UDF mastering tools (`genisoimage`, `mkudffs`, `xorriso`).

## 6. Known limitations, unresolved items, follow-ups

These are not fixed. Each is a design-level heuristic, a documented limitation, or not reproducible here.

1. **Keyboard plus a vendor-class function raises nothing.** `rules.py` deliberately excludes class 0xFF from "unrelated function" to avoid false positives on gaming keyboards. A device pairing a boot keyboard with a network adapter that binds by VID:PID (an ASIX-style class-0xFF NIC) is therefore not flagged at stage 2; stage 3 still observes it. A narrower rule would need hardware data (ROADMAP 3.1). *Decision needed from the maintainer.*
2. **The storage reader is forked from a multi-threaded analyzer** (watchdog and agent accept threads). Python 3.12+ warns about this. If another thread held an interpreter lock at fork time (stdout, say), the child could hang until the 10 s limit. The device would then be reported as "did not respond", a misleading finding but never a fail-open. Not reproduced; a `forkserver` helper or checking for a result before declaring a timeout would remove it.
3. **Under the shipped unit, `end_descendants()` cannot see or kill analyzer children** (`ProtectProc=invisible`, no `CAP_KILL`). The code relies, as documented, on systemd ending the unit's cgroup. This is correct, but the in-process reaping is effectively terminal-only.
4. **A crash in the ledger analyzer is reported at NOTICE** even though it produces CRITICAL findings (`descriptor-drift`, `previously-rejected`). This is deliberate (`analyzers.run`). Drift also changes the trust key, so trust cannot wave a drifted device through, but `previously-rejected` would lose its countdown. Its inputs are bounded.
5. **Not verifiable here:** real USB hardware, the systemd unit under real systemd, desktop dialogs (kdialog/zenity/tk), and `--close-race-window` against a stalling device. F1's fix is verified against a faithful sysfs fake, not a real bus.
6. **Existing known weaknesses** are already listed in `SECURITY.md` (the stage-3 input race, automount, cards not gated, root hubs added after start). They were confirmed by reading and are not re-reported.

Recommended next steps: run F1's scenario on a test machine with `dummy_hcd` (see `testbed/`); decide on item 1; consider moving the storage reader to a `forkserver` (item 2).

## 7. Files modified or added

Modified, source: `probolos/gate.py`, `probolos/deferred_bind.py`, `probolos/textsafe.py`, `probolos/securefs.py`, `probolos/daemon.py`, `probolos/__main__.py`
Modified, tests: `tests/test_quarantine.py`, `tests/test_textsafe.py`, `tests/test_privsep.py`, `tests/test_cli.py`, `tests/test_daemon.py`
Modified, docs: `README.md`, `CHANGELOG.md`, `docs/QA-LOG.md`
Added: `AUDIT_REPORT.md` (this file, archive only)

Total: 14 files changed, 301 insertions and 24 deletions, plus this report.
